# 说明文件格式（narrative）

脚本负责采集、计算、判断和排版；**报告里的说明文字由你（agent）根据数据撰写**，写进 `<工作目录>/<月份>/narrative/<报告>.json`。生成报告的脚本读取这些文件，并核对其中引用的问题编号和资源名都真实存在。

> 实现进度：01–04 的说明文件已由 build 命令读取；05、00 从 M4 起读取。

## 写作素材

分析命令会为每份报告生成 `findings/<报告>-digest.json`，包含：
- 各检查项的问题数和涉及资源数
- 每条问题的编号、严重程度、资源、发现、建议
- 同类对比的偏差
- 费用变化的主要来源
- 上月仍未处理的问题

先读素材，再写说明。不要凭记忆或其他客户的情况写。

01、02 目前还没有单独的 digest 文件，直接读以下数据：
- 01：`findings/cost/model.json`（订阅、业务组、服务、资源组、资源费用和变化），`raw/cost/supplement/drivers.json`（每个主要变化按资源和计量拆解，含 `topResources`、`topMeters`），`raw/cost/resources/*.json`（数据库、存储、日志），`findings/cost/actions.json`（自动生成的建议）。
- 02：`findings/vm/summary.json`、`recommendations.json`、`candidate-checks.json`。

## 通用字段

```json
{
  "report": "03",
  "topIssues": [
    {
      "title": "db-orders-prod 没有高可用，也没有异地备份",
      "detail": "单可用区部署，备份只保留在本区域……",
      "impact": "可用区或区域故障时数据库不可用，可能丢失数据……",
      "recommendation": {
        "rootCause": "该库在门户手工创建，没有使用其他生产库共用的 IaC 模块……",
        "fix": "按标准模块修改配置，与其他生产库保持一致",
        "shortTerm": "先在门户开启区域冗余高可用和异地备份"
      },
      "findingIds": ["R5-xxxx", "R5-yyyy"]
    }
  ],
  "checkNotes": {"R1": "一句话主要发现", "R2": "……"},
  "actionPlan": {"week": ["……"], "month": ["……"], "quarter": ["……"]},
  "severityOverrides": [
    {"findingId": "R9-xxxx", "severity": "中", "reason": "客户确认该入口只用于内部测试，计划本月下线"}
  ],
  "findingTextOverrides": [
    {"findingId": "R9-xxxx", "finding": "……", "needsConfirmation": "……"}
  ],
  "limitations": ["……"]
}
```

- `topIssues`：最多 10 条，按影响排序；`findingIds` 必须存在。没有根本原因的问题，`recommendation` 可以直接写成字符串。
- `checkNotes`：每个有问题的检查项写一句话，用于汇总表的“主要发现”列；缺省时脚本根据数据生成默认文字。
- `severityOverrides`：只在有外部证据时使用，必须写 `reason`，脚本会把理由写进问题清单。
- `findingTextOverrides`：修正某条问题的描述，例如补充证据，不能改动数字含义。可改 `finding`、`recommendation`、`needsConfirmation`、`acceptance`（验收标准）。
- `landingZoneNote`（03）：Landing Zone 对照一节表格下的解读，例如哪些不符合项是客户有意的设计选择、哪些值得规划调整。
- `sectionNotes`：加在“可靠性”“安全”“卓越运营”“性能效率”各节表格下的说明，键为节名，值为一句话或句子列表。
- `limitations`：补充到“检查范围与限制”的条目；未启用订阅、离线判断端口等通用限制由脚本自动写。
- 问题编号可用 `findings/waf/<支柱>.json` 里的 `id`（如 `R1-3f2a9c`，每月稳定）。
- `topIssues` 每条的 `impact` 可省略；所有条目都没有 `impact` 时，表格不显示“影响”列。

## 各报告特有字段

- **01 成本**（全部可选，缺省时用数据生成默认文字）：
  - `driverNotes`：每个主要变化写一句原因，键为“订阅|服务”，用于第 3 节表格和 Excel“变化原因拆解”。写清是新增资源、用量变化还是单价变化，引用具体资源和计量。
  - `highlights`：“需要优先关注的变化”下的 3–7 条要点，每条以粗体短句开头。
  - `forecastSummary`：替换费用总览中“下月预计”那一条，可补充上半月实际与预测的对比。
  - `chartNotes`：图下说明，键为 `daily`、`forecast`、`services`、`regions`、`databases`。写图里看得到的规律（如工作日与周末、节假日低谷），不要重复表格数字。
  - `growthRecommendations`：费用增长建议的“建议怎么做”，键为“订阅|服务”。
  - `notableDatabases`：除自动筛选（CPU 和内存都低于 20% 且费用 USD 300 以上）外，还要列入“费用较高的低使用率资源”表的数据库或缓存名称。
  - `storageTableNote`：存储表下的一句说明；`storageNotes`、`logNotes`、`networkNotes`：存储、日志、网络各节的要点列表。
  - `downsizeExclusions`：交叉核对 X4 后，不宜降档的数据库或缓存，格式 `[{"name": "...", "reason": "内存持续增长，按当前速度约 N 天达到 80%"}]`；01 会把它们移出低使用率候选表并写明原因。
  - `actions`：补充到建议清单的项目，字段为 `topic`、`scope`、`finding`、`recommendation`、`saving`（不估算时为 null）、`owner`、`status`、`evidencePeriod`。数据库、缓存、存储、日志的具体建议写在这里。
- **02 虚拟机**：
  - `crossCheckNotes`：交叉核对后加在逐台建议“说明”列的提醒，格式为 `[{"subscription": "...", "namePrefix": "...", "note": "..."}]`。
  - `crossCheckParagraph`：报告中“与卓越运营与性能效率巡检对照”一段。
- **05 同类对比**（全部可选，缺省时用数据生成默认文字）：
  - 写作素材：`findings/peer/baseline.json`。每类资源的标准做法、采用率、逐资源偏差（差异、原因证据、可行性），以及按创建方式、业务线、月份的规律。
  - `checkDate`：报告开头的检查时间写法（缺省用配置读取日期）。
  - `conclusions`：结论要点列表，每条以粗体短句开头；写清偏差主要来自哪里（创建方式、业务线、模板参数、供应商）。
  - `chartNotes`：两张图下的说明，键为 `method`（按创建方式）、`line`（按业务线）。
  - `topDeviations`：最重要的 10 项偏差，每项 `resource`、`difference`、`cause`、`alignment`、`shortTerm`；写清根本原因、能否原地修改，以及短期措施。
  - `typeSummaries`：键为类型（aks、mysql、postgres、redis、mongo、storage、keyvault、acr、ai、appgw、frontdoor、vm、vnet、loganalytics、dbdiag），值为 `standard`、`exceptions`、`alignment`、`cause`、`note`。
  - `moduleFixes`：需要修正的模板默认值，每项 `module`、`current`、`target`、`resources`；`moduleNote`：表后的一段说明，例如门户直接修改 IaC 管理的资源造成的漂移。
  - `vendorNote`：“供应商创建的资源”一节的文字，可为一段或列表。
  - `resourceNotes`：逐资源的原因补充，键为“类型|资源名”或资源名，值为句子列表；会追加到 Excel“偏差明细”的“原因”列。
  - `limitations`：补充的局限。
  - 05 的 03/04 联动：分析时写 `findings/peer/links.json`，生成 03/04 时自动填问题清单的“与同类资源的差异”“根本原因”“对齐标准的做法”三列（问题自带的内容优先）。需要改写某条 03/04 问题的建议时，用 03/04 说明文件的 `findingTextOverrides`。
- **00 汇总**（最后写，先读 01–05 的结果和交叉核对）：
  - `conclusion`：总体结论表下的几段话（列表，每项一段），讲最主要的规律，例如问题集中在哪类资源、哪种创建方式。
  - `immediate`：需要立即处理的问题，最多 10 条，格式同 03 的 `topIssues`；缺省时取 03、04 说明文件 `topIssues` 的前 5 条。
  - `costNotes`：成本一节的要点；缺省用 01 的 `highlights`。
  - `extraSavings`：节省表中 VM 以外的方案，`[{"item","current","after","saving"}]`（官网列表价，金额来自 01 或其他已核对的数据）。
  - `savingsPending`：需要客户确认后才能估算节省的项目，`[{"item","status"}]`。
  - `pillarNotes`：各支柱 3–5 个要点，键为“可靠性”“安全”“卓越运营”“性能效率”；缺省取 03、04 的 `checkNotes`。
  - `actionPlan`：本周内、一个月内、一个季度内（同 03 格式，可用分号分隔多项）；缺省合并 03、04 的处理顺序。
  - `customerQuestions`：需要客户确认或提供的信息（列表）。
  - `followUp`：后续一节的文字。
  - 数字不写在说明里，由脚本从各报告取数，避免两处不一致；交叉核对 X6 会检查。

## 写作检查

写完后运行 build 命令，它会检查：
- 引用的编号是否存在
- 说明里出现的资源名是否在数据中
- 内部用语
- 粗体标点

有错误时修改说明文件，不要改脚本。
