# 工具路径说明

## radare2

本地运行使用：

`output/tools/radare2-6.1.6-w64/radare2-6.1.6-w64/bin/radare2.exe`

Agent 会优先查找这个路径；如果不存在，再查找 `PATH` 中的 `r2` 或 `radare2`。

## Ghidra 与 JDK

本地运行使用：

`output/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless.bat`

`output/tools/jdk21/jdk-21.0.11+10/bin/java.exe`

Windows 中文路径下，脚本会把 `output` 映射到 ASCII 盘符后再调用 Ghidra。最终运行日志中 `ghidra_result.exit_code` 为 `0`。
