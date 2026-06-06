# 基于 ReAct 智能体与 angr 的自动化逆向分析报告

## 基本信息

- 姓名：刘帅
- 学号：25140909
- 模型/编排协议：deepseek-chat via DeepSeek API tool calling

## 工具封装说明

- `locate_target_outputs()`：定位成功、陷阱、失败输出字符串，给 ReAct 主循环提供显式目标和规避线索。
- `controlled_explore()`：用 angr 创建 4 字节可打印符号输入，向包含 `Success! Flag is found.` 的路径搜索，并规避包含 `Oops!` 或死循环提示的路径。
- `solve_input_from_state()`：对成功状态中的符号输入求模型，得到具体密码。

## 运行结果

- angr 求得输入：`AZcE`
- 完整 Thought -> Action -> Observation 日志见 `logs/run.txt`。

## 思考题回答

在本实验中，LLM 或等价的可解析编排层主要承担任务分解、目标选择和工具调度角色。它根据语义线索把“到达 Success 输出、避开 trap 死循环”转化为符号执行的 find/avoid 约束，并决定何时从探索切换到求解。angr 负责精确执行路径约束与字节级求解，因此语义编排减少盲目路径搜索，符号执行保证最终输入满足程序条件。
