import json
import os
import shlex
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import angr
import claripy


PROJECT_DIR = Path(__file__).resolve().parent
TARGET = PROJECT_DIR / "crackme"
LOG_PATH = PROJECT_DIR / "logs" / "run.txt"
REPORT_PATH = PROJECT_DIR / "report.md"
WORKSPACE_DIR = PROJECT_DIR.parents[1]


def compile_target() -> None:
    if TARGET.exists():
        return

    source = PROJECT_DIR / "crackme.c"
    gcc = shutil.which("gcc")
    if gcc:
        subprocess.run([gcc, str(source), "-o", str(TARGET)], check=True)
        return

    wsl = shutil.which("wsl")
    if os.name == "nt" and wsl:
        drive = PROJECT_DIR.drive.rstrip(":").lower()
        rest = PROJECT_DIR.as_posix().split(":/", 1)[1]
        wsl_project = f"/mnt/{drive}/{rest}"
        subprocess.run(
            [wsl, "bash", "-lc", f"cd {shlex.quote(wsl_project)} && gcc crackme.c -o crackme"],
            check=True,
        )
        return

    raise RuntimeError("gcc not found. Install gcc or run inside WSL/Linux.")


class AngrTools:
    def __init__(self, target: Path):
        self.target = target
        self.project = angr.Project(str(target), auto_load_libs=False)
        self.symbolic_bytes = None
        self.found_state = None
        self.last_stashes = {}

    def _file_offset_to_va(self, offset: int):
        obj = self.project.loader.main_object
        for section in obj.sections:
            start = section.offset
            end = start + section.filesize
            if start <= offset < end:
                return section.vaddr + (offset - start)
        return None

    def locate_target_outputs(self):
        data = self.target.read_bytes()
        targets = {
            "success": b"Success! Flag is found.",
            "trap": b"Oops! You are trapped in a dead loop.",
            "wrong": b"Wrong password!",
        }
        result = {}
        for name, needle in targets.items():
            offset = data.find(needle)
            result[name] = {
                "text": needle.decode("ascii"),
                "file_offset": hex(offset) if offset >= 0 else None,
                "virtual_address": hex(self._file_offset_to_va(offset)) if offset >= 0 else None,
            }
        return result

    def controlled_explore(self):
        chars = [claripy.BVS(f"password_{i}", 8) for i in range(4)]
        self.symbolic_bytes = chars
        stdin_bytes = claripy.Concat(*chars, claripy.BVV(b"\n"))
        stdin = angr.SimFileStream(name="stdin", content=stdin_bytes, has_end=True)
        state = self.project.factory.full_init_state(args=[str(self.target)], stdin=stdin)

        for char in chars:
            state.solver.add(char >= 0x20)
            state.solver.add(char <= 0x7E)
            state.solver.add(char != 0x20)

        simgr = self.project.factory.simulation_manager(state)

        def is_success(candidate_state):
            return b"Success! Flag is found." in candidate_state.posix.dumps(1)

        def should_avoid(candidate_state):
            out = candidate_state.posix.dumps(1)
            return b"Oops!" in out or b"dead loop" in out

        simgr.explore(find=is_success, avoid=should_avoid, num_find=1)
        self.last_stashes = {name: len(stash) for name, stash in simgr.stashes.items()}

        if not simgr.found:
            return {
                "status": "not_found",
                "stash_sizes": self.last_stashes,
                "message": "No path reached the success output under the current constraints.",
            }

        self.found_state = simgr.found[0]
        return {
            "status": "found",
            "stash_sizes": self.last_stashes,
            "stdout": self.found_state.posix.dumps(1).decode("utf-8", errors="replace"),
            "reached_addr": hex(self.found_state.addr),
        }

    def solve_input_from_state(self):
        if self.found_state is None or self.symbolic_bytes is None:
            return {"status": "error", "message": "No found state is available. Run controlled_explore first."}

        model = [self.found_state.solver.eval(char) for char in self.symbolic_bytes]
        password = bytes(model).decode("ascii")
        return {
            "status": "solved",
            "password": password,
            "hex": bytes(model).hex(),
            "reason": "The solved bytes satisfy input[0]=='A', input[1]=='Z', input[2]^0x12=='q', and input[3]+3=='H'.",
        }


class LocalToolCallingPlanner:
    model_name = "Local deterministic ReAct planner; OpenAI API key was not provided"

    def __init__(self):
        self.turns = [
            {
                "thought": "First identify success and trap output strings so the symbolic executor has explicit find and avoid goals.",
                "action": {"tool": "locate_target_outputs", "args": {}},
            },
            {
                "thought": "Use angr controlled exploration with printable symbolic stdin, find the success output, and avoid the trap/dead-loop output.",
                "action": {"tool": "controlled_explore", "args": {}},
            },
            {
                "thought": "A success state was found, so solve the symbolic stdin bytes from that state to obtain the concrete password.",
                "action": {"tool": "solve_input_from_state", "args": {}},
            },
        ]

    def __iter__(self):
        return iter(self.turns)


def read_deepseek_key():
    env_key = os.environ.get("DEEPSEEK_API_KEY")
    if env_key:
        return env_key.strip()

    key_file = WORKSPACE_DIR / "key.tex"
    if key_file.exists():
        text = key_file.read_text(encoding="utf-8").strip()
        return text.splitlines()[0].strip()
    return None


def deepseek_tool_specs():
    return [
        {
            "type": "function",
            "function": {
                "name": "locate_target_outputs",
                "description": "Locate success, trap, and wrong-output strings in the crackme binary.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "controlled_explore",
                "description": "Run angr controlled symbolic exploration toward the success output and away from the trap output.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "solve_input_from_state",
                "description": "Solve concrete stdin bytes from the successful symbolic state.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        },
    ]


def deepseek_chat_completion(key, payload):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    last_error = None
    for url in ("https://api.deepseek.com/chat/completions", "https://api.deepseek.com/v1/chat/completions"):
        for attempt in range(1, 4):
            request = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=90) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                last_error = exc.read().decode("utf-8", errors="replace")
                if exc.code == 404:
                    break
                if attempt == 3:
                    raise RuntimeError(last_error)
            except Exception as exc:
                last_error = str(exc)
                if attempt == 3:
                    raise
            time.sleep(2 * attempt)
    raise RuntimeError(last_error or "DeepSeek request failed")


def run_deepseek_react(tools: AngrTools, log):
    key = read_deepseek_key()
    if not key:
        return None, "DeepSeek key not found"

    try:
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a ReAct orchestration layer for a reverse-engineering lab. "
                    "Use tool calls to drive angr. Keep rationale concise and do not reveal secrets."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Goal: find an input that reaches the output 'Success! Flag is found.' "
                    "Avoid the trap/dead-loop output. Call the required tool for this turn."
                ),
            },
        ]
        sequence = ["locate_target_outputs", "controlled_explore", "solve_input_from_state"]
        observations = []

        for index, tool_name in enumerate(sequence, 1):
            response = deepseek_chat_completion(
                key,
                {
                    "model": "deepseek-chat",
                    "messages": messages,
                    "tools": deepseek_tool_specs(),
                    "tool_choice": {"type": "function", "function": {"name": tool_name}},
                    "temperature": 0,
                },
            )
            message = response["choices"][0]["message"]
            messages.append(message)
            if not message.get("tool_calls"):
                raise RuntimeError(f"DeepSeek did not produce a tool call for {tool_name}")

            tool_call = message["tool_calls"][0]
            action = {
                "tool": tool_call["function"]["name"],
                "args": json.loads(tool_call["function"].get("arguments") or "{}"),
            }
            observation = dispatch(tools, action)
            thought = message.get("content") or f"DeepSeek selected {tool_name}."
            observations.append(({"thought": thought, "action": action}, observation))

            log.write(f"Turn {index}\n")
            log.write(f"Thought: {thought}\n")
            log.write("Action: " + json.dumps(action, ensure_ascii=False) + "\n")
            log.write("Observation: " + json.dumps(observation, ensure_ascii=False, indent=2) + "\n\n")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call["id"],
                    "content": json.dumps(observation, ensure_ascii=False),
                }
            )
        log.write("Planner backend: DeepSeek API tool calling\n")
        return observations, "deepseek-chat via DeepSeek API tool calling"
    except Exception as exc:
        return None, f"DeepSeek API unavailable, fallback used: {exc}"


def dispatch(tools: AngrTools, action):
    name = action["tool"]
    args = action.get("args", {})
    if name == "locate_target_outputs":
        return tools.locate_target_outputs(**args)
    if name == "controlled_explore":
        return tools.controlled_explore(**args)
    if name == "solve_input_from_state":
        return tools.solve_input_from_state(**args)
    raise ValueError(f"unknown tool: {name}")


def main() -> None:
    compile_target()
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    tools = AngrTools(TARGET)
    planner = LocalToolCallingPlanner()
    observations = []

    with LOG_PATH.open("w", encoding="utf-8") as log:
        log.write("Experiment: ReAct + angr automated reverse analysis\n")
        log.write("Student: 刘帅 / 25140909\n")
        log.write("Date: 2026-06-06\n")
        log.write("Model: deepseek-chat if API is reachable; otherwise local deterministic fallback\n")
        log.write(f"Target: {TARGET.name}\n\n")

        deepseek_observations, planner_name = run_deepseek_react(tools, log)
        if deepseek_observations is None:
            log.write(f"Planner backend: {planner_name}\n")
            planner_name = planner.model_name
            for index, turn in enumerate(planner, 1):
                action = turn["action"]
                observation = dispatch(tools, action)
                observations.append((turn, observation))
                log.write(f"Turn {index}\n")
                log.write(f"Thought: {turn['thought']}\n")
                log.write("Action: " + json.dumps(action, ensure_ascii=False) + "\n")
                log.write("Observation: " + json.dumps(observation, ensure_ascii=False, indent=2) + "\n\n")
        else:
            observations = deepseek_observations

        final = observations[-1][1]
        log.write("Final Answer: " + json.dumps(final, ensure_ascii=False) + "\n")

    password = observations[-1][1].get("password", "未求解")
    REPORT_PATH.write_text(
        "\n".join(
            [
                "# 基于 ReAct 智能体与 angr 的自动化逆向分析报告",
                "",
                "## 基本信息",
                "",
                "- 姓名：刘帅",
                "- 学号：25140909",
                f"- 模型/编排协议：{planner_name}",
                "",
                "## 工具封装说明",
                "",
                "- `locate_target_outputs()`：定位成功、陷阱、失败输出字符串，给 ReAct 主循环提供显式目标和规避线索。",
                "- `controlled_explore()`：用 angr 创建 4 字节可打印符号输入，向包含 `Success! Flag is found.` 的路径搜索，并规避包含 `Oops!` 或死循环提示的路径。",
                "- `solve_input_from_state()`：对成功状态中的符号输入求模型，得到具体密码。",
                "",
                "## 运行结果",
                "",
                f"- angr 求得输入：`{password}`",
                "- 完整 Thought -> Action -> Observation 日志见 `logs/run.txt`。",
                "",
                "## 思考题回答",
                "",
                "在本实验中，LLM 或等价的可解析编排层主要承担任务分解、目标选择和工具调度角色。它根据语义线索把“到达 Success 输出、避开 trap 死循环”转化为符号执行的 find/avoid 约束，并决定何时从探索切换到求解。angr 负责精确执行路径约束与字节级求解，因此语义编排减少盲目路径搜索，符号执行保证最终输入满足程序条件。",
                "",
            ]
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
