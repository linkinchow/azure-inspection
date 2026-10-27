# 样例报告（虚构客户）

`sample-output/Contoso_Azure巡检报告_2026年10月/` 是一套完整的交付样例：00 汇总、01 月度成本、02 虚拟机规格、03 可靠性与安全、04 卓越运营与性能效率、05 同类资源配置对比，以及报告引用的图表。

**这是虚构数据生成的样例。** 客户“示例客户”、订阅、资源、费用和问题全部是编的，与任何真实客户无关；看它是为了了解报告长什么样、各节写什么、Excel 有哪些列。

样例由 `make_sample.py` 离线生成，用的是插件真实的分析、生成、交叉核对和打包代码，不连接 Azure，不取令牌，也不运行 `az`：

- 01：用一份编造的每日账单回答 Cost Management 的查询，费用采集和补充分析走插件原有代码；数据库、存储、日志用量直接写成采集结果的格式。
- 02：编造的虚拟机清单、7 天指标、规格能力和官网价格缓存，然后运行插件的规格分析。
- 03/04：直接写成各支柱的问题文件；另外生成了 8 月的问题，用来展示“与上月相比”（新增、已解决、严重程度变化、新增检查项）。
- 05：编造的存储账户、MySQL、PostgreSQL 配置，然后运行插件的同类对比。
- 说明文字（前十大问题、根本原因、处理计划等）按 `references/narrative-format.md` 的格式写在脚本里，相当于 agent 写的部分。

重新生成（需要 Python 依赖，见 `plugins/azure-inspection/skills/azure-monthly-inspection/scripts/requirements.txt`；Windows 装有 Excel 时会做公式复算）：

```bash
python examples/make_sample.py
```

脚本在临时目录里建工作目录，完成后把打包好的文件夹复制到 `sample-output/`；加 `--keep` 可保留临时工作目录，`--workspace <目录>` 可指定工作目录。
