# 运行资产准备

公开源码不包含模型或任何真实数据库，不能直接复现截图中的告警与历史调查。GitHub Pages 只展示静态资料。

`NETSENTRY_RUNTIME_DIR` 指向可信的批准运行包（推荐放在忽略的 `runtime/approved/`）。必须包含：

```text
runtime_manifest.json
events.sqlite
inference.sqlite
inference_store.json
development_ids.json
models/F2_logistic.json
models/F2_logistic.joblib
models/F2_rf100.json
models/F2_rf100.joblib
```

契约由 `netsentry/services/prediction_service.py` 的 ASSETS 与 verify_runtime 实际执行：运行版本 `netsentry.api.runtime.v1`、范围 `Week1 B Train+Validation only`、默认模型 `F2_logistic`，manifest 对上述8个资产提供 SHA256。模型状态保持 DEV_ONLY。当前实现同时加载 logistic 与 rf100，因此不能只放一个权重文件。

events.sqlite 仅有获准事件元数据，不能含真实Label；inference.sqlite 是无标签推理特征。离线标签库、原CSV、测试集和Week2不得冒充该运行包。预测、检测和查询需要有效的批准资产；历史回放另需兼容的历史checkpoint、对应告警库与来源记录，本仓库不提供这些资产。

来源：CIDDS 官方公开版本见 [数据页面](https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/)。公开CSV可以用于单独审计或导入，但下载CSV并不能自动得到已有模型、批准划分或运行包。获得批准运行包需自行解决数据/权重的许可与可信来源；本公开发布没有提供可下载运行包或声称能一键重建它。本轮不进行训练。

先执行 `python scripts/check_runtime.py`。它只检查清单、固定范围与摘要，不反序列化权重；SHA匹配不能代替可信来源核验。失败时必须补齐真正的资产，不能新建空库或Fake模型来绕过启动条件。

新调查的告警写库与checkpoint由本地程序创建，放在忽略的 outputs/；不要放入只读运行目录。`NETSENTRY_API_TOKEN` 是本地写操作令牌，和只传给后端的 `GEMINI_API_KEY` 不同。原历史演示脚本保留用于代码/测试兼容，其私有包路径不构成公开版运行承诺。
