# 公开版测试范围

原工程全部 Python 测试文件及 React/浏览器测试源文件按原字节复制，没有删除、skip、修改断言或弱化原工程测试。新增公开版入口与检查不改原业务源码。这里的结果只指本次实际执行的公开副本。

## 普通回归

`python scripts/run_public_tests.py` 按现有发现规则加载测试；使用合成夹具和Fake Gemini。移除进程密钥、禁用LangSmith追踪，阻止非本机socket连接。外部网络尝试导致失败，不伪造服务返回。脚本明确输出 executed/passed/failures/errors/skipped，以及没有选入本轮范围的完整测试ID。

本轮不执行但原文件保留：

- `test_m2b_models`：内含合成模型fit测试。没有私有数据依赖，但因本轮不训练模型，整个组未执行。
- `test_m6_gemini.GeminiTests.test_frontend_child_never_receives_backend_secrets`：已有测试依赖批准runtime及安装的前端，运行包缺失时会先退出，不能测到它期望的子进程分支。
- `test_m7a_release.ModelConfigTests.test_port_conflict_before_spawning`：同样需批准runtime，且要存在构建好的前端。

未执行不计为通过，也不是原测试上的skip装饰器。其他临时SQLite和合成PCAP由测试自行创建，不含真实流量。TF-IDF知识检索的索引构建仍是测试功能，不是IDS训练。

## 私有资产集成测试

`frontend/e2e/` 为保留的浏览器集成测试，需实际运行的服务、对应告警/调查或历史checkpoint；具体环境变量见 `frontend/playwright.config.ts`。部分测试会创建调查或提交审核，不能对不可更改的历史原件直接运行。本次未执行这些测试，不声称通过原项目全量验收。旧smoke/evaluation/demo脚本保留为历史代码依赖，不属于普通回归入口，也不自动运行。

公开版前端验证是 `pnpm --dir frontend typecheck`、`test`、`build`。Pages页面另外在 `/NetSentry-Copilot/` 下验证，不用业务服务与真实LLM。

本次实际结果见 [PUBLIC_CHECKS.md](PUBLIC_CHECKS.md)。机器日志和安装环境保存在导出目录旁的私有verification目录，不随源码提交。
