# 公开文件范围

本目录独立导出，没有原工程.git历史。白名单包含 netsentry Python/JSON、全部原Python测试、frontend源文件/测试/配置/锁文件、必要脚本及其导入依赖、明确标记synthetic的小型sample_data、项目知识笔记、既有许可证、精简文档及site静态资料。

site只含已精简的当前Gemini 3.1展示材料，不链接内部日志或历史失败资料。保留html案例入口和来源说明；未复制Sites站点身份、托管凭据或专用配置。所有资源相对引用，适用于仓库子路径。_headers和_redirects并非GitHub Pages配置，因此没有导出。

未包含：真实CSV、真实PCAP、运行SQLite、历史checkpoint、joblib/pickle权重、私有ZIP、原Git历史、work/outputs、内部delivery日志、.env秘密值、虚拟环境、node_modules、缓存。sample_data/*.csv例外：明确为synthetic合成测试夹具，绝不是官方数据样本。

历史模型ID及协议兼容逻辑可以出现在业务源码/测试中；不会恢复到作品集正文。少量原演示/归档脚本因现有测试的模块导入依赖而保留，它们引用的历史资产不存在，也不属于公开版一键演示入口。

原工程保持不变；导出副本新增README、公开启动预检、测试范围入口和Pages配置。实际复制摘要与检查摘要见 SOURCE_MANIFEST.json 和 PUBLIC_CHECKS.md。公开仓库可阅读源码、看静态作品集、执行合成审计/查询与无需私有资产的测试；完整告警调查必须自行提供批准运行包。
