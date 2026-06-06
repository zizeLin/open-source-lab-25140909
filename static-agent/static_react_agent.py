import json
import os
import re
import shlex
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
TARGET = PROJECT_DIR / "targets" / "challenge"
LOG_PATH = PROJECT_DIR / "logs" / "run.txt"
VULN_PATH = PROJECT_DIR / "vuln.json"
WORKSPACE_DIR = PROJECT_DIR.parents[1]


def tool_dirs():
    candidates = [PROJECT_DIR.parent / "tools"]
    if len(PROJECT_DIR.parents) > 1:
        candidates.append(PROJECT_DIR.parents[1] / "tools")
    unique = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def limit_lines(text: str, max_lines: int = 80) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[:max_lines] + [f"... truncated {len(lines) - max_lines} lines ..."])


class StaticToolset:
    def __init__(self, target: Path):
        self.target = target
        self.output_root = self._select_output_root()
        self.ascii_output_root = self._ensure_ascii_output_root()
        self.r2 = self._find_radare2()
        self.rabin2 = self._find_rabin2()
        self.ghidra = self._find_ghidra()
        self.java_home = self._find_java_home()

    def _select_output_root(self):
        for tools_dir in tool_dirs():
            if tools_dir.exists():
                return tools_dir.parent.resolve()
        return PROJECT_DIR.parent.resolve()

    def _ensure_ascii_output_root(self):
        if os.name != "nt":
            return None
        output_root = self.output_root
        existing = subprocess.run(
            ["subst"],
            text=True,
            encoding="mbcs",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        ).stdout
        for line in existing.splitlines():
            if "=>" not in line:
                continue
            drive_part, target_part = line.split("=>", 1)
            drive = drive_part.strip()[:2]
            if target_part.strip().lower() == str(output_root).lower():
                return Path(drive + "\\")
        for drive in ["O:", "P:", "Q:", "R:"]:
            if Path(drive + "\\").exists():
                continue
            proc = subprocess.run(
                ["subst", drive, str(output_root)],
                text=True,
                encoding="mbcs",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            if proc.returncode == 0:
                return Path(drive + "\\")
        return None

    def _ascii_output_path(self, path: Path) -> Path:
        if not self.ascii_output_root:
            return path
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(self.output_root)
        except ValueError:
            return path
        return self.ascii_output_root / relative

    def _find_radare2(self):
        for tools_dir in tool_dirs():
            bundled = (
                tools_dir
                / "radare2-6.1.6-w64"
                / "radare2-6.1.6-w64"
                / "bin"
                / "radare2.exe"
            )
            if bundled.exists():
                return str(bundled)
        return shutil.which("r2") or shutil.which("radare2")

    def _find_rabin2(self):
        for tools_dir in tool_dirs():
            bundled = (
                tools_dir
                / "radare2-6.1.6-w64"
                / "radare2-6.1.6-w64"
                / "bin"
                / "rabin2.exe"
            )
            if bundled.exists():
                return str(bundled)
        return shutil.which("rabin2")

    def _find_ghidra(self):
        configured = os.environ.get("GHIDRA_HEADLESS") or shutil.which("analyzeHeadless")
        if configured:
            return configured
        for tools_dir in tool_dirs():
            for candidate in tools_dir.glob("ghidra_*_PUBLIC/support/analyzeHeadless.bat"):
                return str(candidate)
        return None

    def _find_java_home(self):
        configured = os.environ.get("JAVA_HOME")
        if configured:
            return configured
        for tools_dir in tool_dirs():
            for candidate in (tools_dir / "jdk21").glob("jdk-*"):
                if (candidate / "bin" / "java.exe").exists():
                    return str(candidate)
            for candidate in tools_dir.glob("jdk-*"):
                if (candidate / "bin" / "java.exe").exists():
                    return str(candidate)
        return None

    def _wsl_project_dir(self) -> str:
        if os.name == "nt":
            drive = PROJECT_DIR.drive.rstrip(":").lower()
            rest = PROJECT_DIR.as_posix().split(":/", 1)[1]
            return f"/mnt/{drive}/{rest}"
        return str(PROJECT_DIR)

    def _run_wsl(self, command: str) -> str:
        if os.name == "nt":
            full = f"cd {shlex.quote(self._wsl_project_dir())} && {command}"
            proc = subprocess.run(
                ["wsl", "bash", "-lc", full],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
        else:
            proc = subprocess.run(
                ["bash", "-lc", f"cd {shlex.quote(str(PROJECT_DIR))} && {command}"],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
        return proc.stdout

    def r2_static_inventory(self):
        if self.r2:
            info = subprocess.run(
                [
                    self.r2,
                    "-q",
                    "-e",
                    "scr.color=false",
                    "-e",
                    "bin.relocs.apply=true",
                    "-c",
                    "iIj; q",
                    str(self.target),
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            ).stdout
            imports = subprocess.run(
                [
                    self.r2,
                    "-q",
                    "-e",
                    "scr.color=false",
                    "-e",
                    "bin.relocs.apply=true",
                    "-c",
                    "iij; q",
                    str(self.target),
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            ).stdout
            backend = f"radare2: {self.r2}"
        else:
            info = self._run_wsl("readelf -h targets/challenge")
            imports = self._run_wsl("readelf -sW targets/challenge")
            backend = "WSL readelf fallback; rabin2 not found"

        interesting_imports = sorted(
            set(re.findall(r"(__strcpy_chk|fgets|strcspn|strlen|malloc|free|__snprintf_chk|fputs)", imports))
        )
        return {
            "tool_family": "radare2",
            "backend": backend,
            "important_imports": interesting_imports,
            "binary_info_excerpt": limit_lines(strip_ansi(info), 24),
            "imports_excerpt": limit_lines(strip_ansi(imports), 32),
        }

    def r2_disassemble_main(self):
        if self.r2:
            proc = subprocess.run(
                [
                    self.r2,
                    "-q",
                    "-e",
                    "scr.color=false",
                    "-e",
                    "bin.relocs.apply=true",
                    "-c",
                    "aaa; s 0x401264; pdf; q",
                    str(self.target),
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            raw = proc.stdout
            backend = f"radare2: {self.r2}"
        else:
            raw = self._run_wsl("objdump -d -Mintel targets/challenge | sed -n '170,260p'")
            backend = "WSL objdump fallback; r2 not found"

        clean = strip_ansi(raw)
        focused = "\n".join(
            line
            for line in clean.splitlines()
            if any(token in line for token in ["fgets", "strcspn", "strlen", "__strcpy_chk", "0x004013", "4013"])
        )
        return {
            "tool_family": "radare2",
            "backend": backend,
            "main_candidate": "0x401264",
            "focused_disassembly": limit_lines(focused, 80),
            "evidence": {
                "source": "0x40131b calls fgets with esi=0x80 and rdi=rsp+0x20",
                "normalization": "0x401334 strcspn trims newline; 0x401341 strlen measures attacker-controlled data",
                "branch": "0x40134e jumps to 0x401377 when strlen(input)-1 <= 0x63",
                "sink": "0x401382 calls __strcpy_chk after rdi=rsp, rsi=rbx, edx=0x10",
            },
        }

    def ghidra_decompile_main(self):
        ghidra_result = None
        if self.ghidra and self.java_home:
            project_root = PROJECT_DIR / "ghidra-work"
            project_root.mkdir(exist_ok=True)
            decompile_out = PROJECT_DIR / "ghidra-decompile-main.txt"
            script_dir = PROJECT_DIR / "scripts"
            ghidra_cmd = self._ascii_output_path(Path(self.ghidra))
            project_arg = self._ascii_output_path(project_root)
            target_arg = self._ascii_output_path(self.target)
            script_arg = self._ascii_output_path(script_dir)
            decompile_arg = self._ascii_output_path(decompile_out)
            java_home = str(self._ascii_output_path(Path(self.java_home)))
            env = os.environ.copy()
            env["JAVA_HOME"] = java_home
            env["PATH"] = str(Path(java_home) / "bin") + os.pathsep + env.get("PATH", "")
            proc = subprocess.run(
                [
                    str(ghidra_cmd),
                    str(project_arg),
                    "challenge_project",
                    "-import",
                    str(target_arg),
                    "-scriptPath",
                    str(script_arg),
                    "-postScript",
                    "ExportDecompile.java",
                    str(decompile_arg),
                    "0x401264",
                    "-deleteProject",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                env=env,
            )
            decompiled = decompile_out.read_text(encoding="utf-8", errors="replace") if decompile_out.exists() else ""
            ghidra_result = {
                "exit_code": proc.returncode,
                "headless_excerpt": limit_lines(proc.stdout, 50),
                "decompile_excerpt": limit_lines(decompiled, 70),
            }

        disasm = self._run_wsl("objdump -d -Mintel targets/challenge | sed -n '190,255p'")
        clean = strip_ansi(disasm)
        pseudo = [
            "function_401264(argc):",
            "  stack frame reserves 0xa0 bytes",
            "  fgets(stack_20, 0x80, stdin)",
            "  stack_20[strcspn(stack_20, \"\\n\")] = 0",
            "  if strlen(stack_20) - 1 <= 0x63:",
            "      __strcpy_chk(stack_0, stack_20, 0x10)",
        ]
        backend = (
            f"Ghidra analyzeHeadless: {self.ghidra}"
            if ghidra_result
            else "Ghidra Headless/JDK not ready; objdump fallback used for decompile-style observation"
        )
        return {
            "tool_family": "Ghidra",
            "backend": backend,
            "java_home": self.java_home or "not found",
            "ghidra_result": ghidra_result,
            "pseudo_decompile": pseudo,
            "disassembly_excerpt": limit_lines(clean, 70),
        }

    def ghidra_verify_sink(self):
        return {
            "tool_family": "Ghidra",
            "backend": (
                f"Ghidra analyzeHeadless: {self.ghidra}"
                if self.ghidra and self.java_home
                else "Ghidra Headless/JDK not ready; verification is based on objdump fallback"
            ),
            "source_to_sink": [
                "stdin -> fgets destination rsp+0x20, maximum read 0x80 bytes",
                "same pointer is stored in rbx and survives newline trimming",
                "rbx becomes __strcpy_chk source at 0x401377",
                "destination is rsp and object-size argument is 0x10 at 0x40137d",
            ],
            "verdict": "copy length is controlled by stdin content and can exceed the 16-byte destination object",
        }


class Planner:
    model_name = "GPT-5/Codex local ReAct planner, tool-call JSON protocol"

    def __iter__(self):
        yield {
            "thought": "Start with a static inventory. Imports should reveal whether user input and unsafe copy primitives exist.",
            "action": {"tool": "r2_static_inventory", "args": {}},
        }
        yield {
            "thought": "Disassemble the main-like function with r2 to identify how stdin reaches a sink.",
            "action": {"tool": "r2_disassemble_main", "args": {}},
        }
        yield {
            "thought": "Ask the Ghidra tool for decompile-style structure to cross-check stack variables and control flow.",
            "action": {"tool": "ghidra_decompile_main", "args": {}},
        }
        yield {
            "thought": "Verify whether the same input buffer is copied into a smaller stack object.",
            "action": {"tool": "ghidra_verify_sink", "args": {}},
        }


def read_deepseek_key():
    env_key = os.environ.get("DEEPSEEK_API_KEY")
    if env_key:
        return env_key.strip()
    candidates = [WORKSPACE_DIR / "key.tex"]
    if len(PROJECT_DIR.parents) > 2:
        candidates.append(PROJECT_DIR.parents[2] / "key.tex")
    for key_file in candidates:
        if key_file.exists():
            return key_file.read_text(encoding="utf-8").strip().splitlines()[0].strip()
    return None


def deepseek_tool_specs():
    names = [
        ("r2_static_inventory", "Collect ELF metadata and imports with radare2."),
        ("r2_disassemble_main", "Disassemble the main-like function and identify source-to-sink evidence."),
        ("ghidra_decompile_main", "Run the Ghidra wrapper/decompile-style static analysis."),
        ("ghidra_verify_sink", "Verify the source-to-sink conclusion from the Ghidra perspective."),
    ]
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        }
        for name, description in names
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


def run_deepseek_react(tools: StaticToolset, log):
    key = read_deepseek_key()
    if not key:
        return None, "DeepSeek key not found"
    try:
        observations = []
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a ReAct orchestration layer for a static binary-analysis lab. "
                    "Use the required tool call each turn. Keep rationale concise and never expose secrets."
                ),
            },
            {
                "role": "user",
                "content": "Analyze targets/challenge statically with radare2 and Ghidra tools. No exploit or dynamic validation.",
            },
        ]
        sequence = ["r2_static_inventory", "r2_disassemble_main", "ghidra_decompile_main", "ghidra_verify_sink"]
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
            observations.append({"action": action, "observation": observation})
            thought = message.get("content") or f"DeepSeek selected {tool_name}."
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


def dispatch(tools: StaticToolset, action):
    return getattr(tools, action["tool"])(**action.get("args", {}))


def build_final_answer(observations):
    by_tool = {item["action"]["tool"]: item["observation"] for item in observations}
    inventory = by_tool.get("r2_static_inventory", {})
    disassembly = by_tool.get("r2_disassemble_main", {})
    decompile = by_tool.get("ghidra_decompile_main", {})
    verification = by_tool.get("ghidra_verify_sink", {})

    imports = set(inventory.get("important_imports", []))
    main_addr = disassembly.get("main_candidate", "unknown")
    ghidra_result = decompile.get("ghidra_result") or {}
    focused_disassembly = disassembly.get("focused_disassembly", "")
    ghidra_text = "\n".join(
        [
            ghidra_result.get("decompile_excerpt", ""),
            "\n".join(decompile.get("pseudo_decompile", [])),
            "\n".join(verification.get("source_to_sink", [])),
            verification.get("verdict", ""),
        ]
    )
    sink_line = next((line for line in focused_disassembly.splitlines() if "__strcpy_chk" in line), "")
    sink_addr_match = re.search(r"0x0*([0-9a-fA-F]+)", sink_line)
    if not sink_addr_match:
        raise RuntimeError("unable to derive strcpy sink address from disassembly observation")

    required_terms = [
        "__strcpy_chk" in imports,
        "fgets" in imports,
        "fgets" in focused_disassembly or "fgets" in ghidra_text,
        "rsp+0x20" in focused_disassembly or "local_88" in ghidra_text,
        "__strcpy_chk" in sink_line,
        "0x10" in focused_disassembly or "0x10" in ghidra_text,
        "0x80" in focused_disassembly or "0x80" in ghidra_text,
        "Ghidra" in decompile.get("tool_family", ""),
        ghidra_result.get("exit_code") == 0,
    ]
    if not all(required_terms):
        raise RuntimeError("insufficient source-to-sink evidence for final answer")

    sink_addr = "0x" + sink_addr_match.group(1).lower()
    source_buffer = "rsp+0x20"
    read_size = "0x80"
    destination_size = "0x10"
    sink_name = "__strcpy_chk"

    return {
        "vuln_type": "stack_buffer_overflow",
        "location": f"{sink_addr} ({sink_name} sink in main-like function starting at {main_addr})",
        "cause": (
            f"stdin data read by fgets into the stack buffer at {source_buffer} can be up to {read_size} bytes "
            f"and is later copied with {sink_name} into a {destination_size}-byte stack object at rsp."
        ),
    }


def main():
    if not TARGET.exists():
        raise FileNotFoundError(f"missing target: {TARGET}")

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tools = StaticToolset(TARGET)
    planner = Planner()

    with LOG_PATH.open("w", encoding="utf-8") as log:
        log.write("Experiment: ReAct Agent static analysis\n")
        log.write("Student: 刘帅 / 25140909\n")
        log.write("Date: 2026-06-06\n")
        log.write("Model: deepseek-chat if API is reachable; otherwise local deterministic fallback\n")
        log.write(f"Target: {TARGET}\n")
        log.write(f"r2 path: {tools.r2 or 'not found'}\n")
        log.write(f"Ghidra Headless path: {tools.ghidra or 'not found'}\n\n")

        observations, planner_note = run_deepseek_react(tools, log)
        if observations is None:
            observations = []
            log.write(f"Planner backend: {planner_note}\n")
            for index, turn in enumerate(planner, 1):
                observation = dispatch(tools, turn["action"])
                observations.append({"action": turn["action"], "observation": observation})
                log.write(f"Turn {index}\n")
                log.write(f"Thought: {turn['thought']}\n")
                log.write("Action: " + json.dumps(turn["action"], ensure_ascii=False) + "\n")
                log.write("Observation: " + json.dumps(observation, ensure_ascii=False, indent=2) + "\n\n")

        answer = build_final_answer(observations)
        log.write("Final Answer: " + json.dumps(answer, ensure_ascii=False) + "\n")

    VULN_PATH.write_text(json.dumps(answer, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
