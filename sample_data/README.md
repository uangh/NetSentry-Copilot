# 合成测试数据声明

本目录全部 CSV 均为本次人工构造的 synthetic 测试夹具，**不是 CIC-IDS2018 原始数据**。
其中的 IP、时间、标签、数值只是程序输入样例，不代表检测结果或安全事件。
EXAMPLE_ATTACK 不是任何公开数据集的权威类别映射。

- features_only.csv：合法特征数据，有标签/时间/端口，没有源目标 IP；应成功审计并提示能力缺失。
- with_network_metadata.csv：包含源/目标 IP 的合成数据；字段存在不代表有认证日志。
- broken_numeric.csv：包含 Infinity、空值和 bad，必须如实统计、不静默删除。
- duplicate_headers.csv：清理空格后标题重复，应拒绝。
- empty.csv：空文件，应拒绝。
- manifest.json：用于追溯夹具字节的 SHA256，不是模型性能报告。

所有样本只能用于软件单元/契约测试，不可用来宣称检测精度、误报率或真实用户收益。
