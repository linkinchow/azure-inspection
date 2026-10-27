---
name: azure-monthly-inspection
description: Read-only monthly Azure inspection for a customer tenant, producing Chinese customer reports (cost review, VM rightsizing, reliability, security, operational excellence, performance, peer comparison, summary). Use when the user asks to run or prepare an Azure 月度巡检/成本巡检/WAF 巡检/健康检查 for a customer, set up a new customer for inspection, check read-only access, or quality-check inspection reports before delivery.
metadata:
  version: 0.6.0
---

# Azure 月度巡检（只读）

用客户提供的只读账号读取 Azure 配置、指标和费用，生成给客户的中文巡检报告。每月一次，可与上月对比。

| 编号 | 报告 | 内容 |
|---|---|---|
| 00 | 汇总报告 | 总体结论、需要立即处理的问题、处理计划 |
| 01 | 月度成本巡检 | 费用、变化原因、闲置资源、存储和日志、建议与跟踪 |
| 02 | 虚拟机利用率与规格优化 | 每台机器的建议、调整前后价格、预计节省 |
| 03 | 可靠性与安全巡检 | 问题清单（Excel）和报告 |
| 04 | 卓越运营与性能效率巡检 | 问题清单（Excel）和报告 |
| 05 | 同类资源配置对比 | 找根本原因，给出对齐客户标准做法的建议 |

## 当前版本能做什么

版本 0.6.0 可以：

- 准备：环境检查、建客户工作目录、核对只读访问
- 生成全部 6 份报告：**00 汇总**、**01 月度成本**、**02 虚拟机规格**、**03 可靠性与安全**、**04 卓越运营与性能效率**、**05 同类资源配置对比**（采集、分析、生成、核对）
- 跨报告交叉核对（X1–X9）和打包
- RI/SP：分摊费用中的覆盖比例、现有预留和节省计划的使用率与到期、Azure 购买建议；02 标出已被 RI/SP 覆盖、降配节省不能直接实现的机器
- 跨月跟踪：03/04 自动与上月比，分出新增问题、新增检查项发现、仍未处理、已解决、本月未检查
- 检查 Markdown 报告

- 并入微软公开规则库：APRL（可靠性）、Defender/Policy（安全）、孤立资源（01）、AMBA 告警基线（04）、Landing Zone 清单（03 架构对照）（见文末“开发进度”）。**还没有提供的命令，不要自己写脚本去访问客户环境代替**；告诉用户这部分尚未提供。

## 必须遵守的规则

完整规则见 `references/safety.md`，下面是要点：

1. **只读**：
   - 只通过本 skill 的脚本访问 Azure。脚本只允许读取，会拦截写操作和取密钥的操作。
   - 不用 kubectl，不取 AKS 凭据，不扫描端口。
2. **不动用户的登录状态**：
   - 永远不执行 `az login`、`az logout`、`az account set`。
   - 需要登录只读账号时，请用户自己执行。
   - 脚本会核对令牌属于 `customer.yaml` 里的只读账号和租户，不一致就停止。
3. **读不到就如实记录**：遇到 401/403/404 记录后继续，不绕过权限。缺数据不当 0：读不到的费用不是 0 元，读不到的指标不是“利用率低”。
4. **客户数据只放在客户工作目录**，不放进 skill 目录，不上传。报告中不出现邮箱。
5. **降配、删除、购买 RI/SP 等建议都写成“需客户确认后执行”。**

## 运行脚本

下文 `<skill>` 指本 SKILL.md 所在的目录。在 Claude Code 中它显示为本 skill 的 Base directory；在其他 agent 中，用 SKILL.md 的路径去掉文件名得到。所有命令都这样运行：

```bash
python "<skill>/scripts/azinspect_cli.py" <命令> [参数]
```

命令输出是中文，直接转述给用户即可。

## 第一步：准备（每个新客户做一次）

1. **检查环境**：

   ```bash
   python "<skill>/scripts/azinspect_cli.py" doctor
   ```

   缺依赖时，告诉用户输出里的安装命令，经同意后再执行。缺中文字体会导致图表乱码。

2. **建客户工作目录**：问用户目录放在哪里。工作目录在 skill 目录之外，每个客户一个，例如 `~/inspections/<客户>`。

   ```bash
   python "<skill>/scripts/azinspect_cli.py" init --workspace "<工作目录>"
   ```

3. **填写 `customer.yaml`**：向用户要以下信息，其余字段按模板注释和用户说明填写：
   - 客户名称
   - 文件名前缀
   - 租户 ID
   - 只读账号的 UPN（或服务主体 appId）
   - 一个只读账号能访问的订阅 ID（用来取令牌）
   - 订阅范围
   - 环境命名规则
   - 业务线规则

   不要猜租户和账号。

4. **请用户用只读账号登录 Azure CLI**（用户自己执行 `az login`）。之后核对访问：

   ```bash
   python "<skill>/scripts/azinspect_cli.py" access-check --workspace "<工作目录>"
   ```

   向用户说明以下几项，并请用户确认范围：
   - 能看到多少订阅：纳入、已停用、被排除各多少
   - 资源能否读取
   - 费用能否读取

   只读账号建议的权限（都只读）：

   | 权限 | 范围 | 用于 |
   |---|---|---|
   | 读者（Reader） | 各订阅或根管理组 | 配置、指标、活动日志 |
   | 成本管理读者（Cost Management Reader） | 各订阅 | 01 费用、按资源的 RI/SP 覆盖、Azure 购买建议 |
   | Log Analytics 读者 | 日志工作区 | 日志摄取来源、AKS 调度事件 |
   | 安全读者（Security Reader） | 各订阅 | Defender 建议 |
   | 预留读取者（Reservations Reader） | 租户 | 现有 RI/SP 的使用率和到期（可选） |
   | Microsoft Graph 目录读取 | 租户 | 高权限账号、来宾、凭据到期（可选） |

   缺少可选权限时，对应检查如实写“未能核对”，不影响其他报告。

## 第二步：月度巡检

`--month` 是巡检的月份（已结束的完整月），例如 10 月上旬巡检 9 月就写 `2026-09`；不写时默认上一个完整月。`--part` 可选 `cost`（01）、`vm`（02）、`waf`（03、04）、`peer`（05）、`summary`（00，只用于 build）或 `all`。

1. **采集**（只读，访问客户环境，约 10–30 分钟）：

   ```bash
   python "<skill>/scripts/azinspect_cli.py" collect --workspace "<工作目录>" --month <YYYY-MM> --part all
   ```

   `all` 依次采集虚拟机、费用、四个支柱（可靠性、网络安全、身份安全、性能效率、卓越运营）。01 的“本月虚拟机使用情况”需要虚拟机清单；卓越运营会复用费用巡检的存储和日志数据，所以建议用 `all`。指标和活动日志看采集当天之前 30 天。输出里的读取失败、无权限要转告用户，不要重试绕过。

2. **分析**（离线，查询官网公开价格）：

   ```bash
   python "<skill>/scripts/azinspect_cli.py" analyze --workspace "<工作目录>" --month <YYYY-MM> --part all
   ```

3. **撰写说明**：按 `references/narrative-format.md` 读数据，写 `narrative/01.json` 至 `narrative/05.json`，最后写 `narrative/00.json`；写法见 `references/writing-style.md`。01 的重点是费用变化原因（`driverNotes`）、要点（`highlights`）和具体建议（`actions`）；03、04 的重点是前十大问题（`topIssues`，含根本原因）、各检查项的主要发现（`checkNotes`）和处理顺序（`actionPlan`）。有外部证据需要调整严重程度时用 `severityOverrides`，必须写理由。不写也能生成，但只有默认文字。

4. **生成并核对**：

   ```bash
   python "<skill>/scripts/azinspect_cli.py" build --workspace "<工作目录>" --month <YYYY-MM> --part all
   ```

   生成 `reports/` 下的 Markdown、Excel 和图表，并自动核对：Excel 公式复算、合计与原始数据一致、读取失败未按 0 处理。核对失败时按提示修改说明文件或补数据，不要改核对脚本。

5. **交叉核对**：

   ```bash
   python "<skill>/scripts/azinspect_cli.py" crosscheck --workspace "<工作目录>" --month <YYYY-MM>
   ```

   逐条处理“需要处理”的规则（明细在 `findings/crosscheck.json`，每条带建议做法），见 `references/cross-checks.md`：降配冲突写进 `narrative/02.json` 的 `crossCheckNotes`；不宜降档的数据库或缓存写进 `narrative/01.json` 的 `downsizeExclusions`。改完重新 build 再跑 crosscheck，直到没有“需要处理”。“需人工确认”的逐条看一遍，必要时改说明文件。

6. **质量检查**：

   ```bash
   python "<skill>/scripts/azinspect_cli.py" quality-check --path "<工作目录>/<YYYY-MM>/reports"
   ```

   有问题就修改再检查，直到通过。

7. **打包**：

   ```bash
   python "<skill>/scripts/azinspect_cli.py" package --workspace "<工作目录>" --month <YYYY-MM>
   ```

   生成 `package/<客户>_Azure巡检报告_<出具月份>/` 和同名压缩包，逐字节核对。交叉核对还有“需要处理”时会拒绝打包；只加了提醒、决定保留建议的，用 `--allow-open`，并在交付时告诉用户。

只重跑部分支柱时用 `--pillars`（逗号分隔），例如某个支柱采集失败后：`collect --part waf --pillars operations,amba`。可选：reliability、aprl、security_network、security_identity、defender、performance、operations、amba、landing_zone。

采集输出里出现“采集失败”时，不要用其他方式绕过；把错误原文告诉用户。被只读白名单拦截（BlockedRequest）说明脚本要发出的请求不在允许范围内，需要修改脚本，而不是放宽规则。

完整流程与进度：

| 阶段 | 做什么 | 命令 | 状态 |
|---|---|---|---|
| 1 采集 | 只读采集费用、资源配置、指标；保存去敏感信息后的原始数据 | `collect` | 01–04 可用 |
| 2 分析 | 按 `references/check-catalog.md` 判断问题，生成问题清单 | `analyze` | 01–04 可用；新增检查项开发中（M3） |
| 3 同类对比 | 对有问题的资源找标准做法和偏差 | `--part peer` | 可用 |
| 4 撰写说明 | **由你根据数据写**，格式见 `references/narrative-format.md` | — | 01–04 可用 |
| 5 生成报告 | 生成 Markdown、Excel、图表并核对 | `build` | 00–05 可用 |
| 6 交叉核对 | 检查报告之间的矛盾 | `crosscheck` | 可用 |
| 7 质量检查 | 星号、图片、表格列数、内部用语、邮箱 | `quality-check` | 可用 |
| 8 打包 | 中文文件夹和压缩包，逐字节核对 | `package` | 可用 |
| 9 跨月跟踪 | 与上月比：新增、已解决、仍未处理 | build 时自动 | 可用 |

## 跨月跟踪

每次 build 生成 03/04 时，自动把当月问题（稳定编号）存到 `<工作目录>/state/months/<月份>.json`，并与最近一个更早的月份比较，结果写入 `findings/tracking.json`：

- **新增问题**：上月已执行这项检查，本月才出现。
- **新增检查项发现**：本月起新增或首次成功执行的检查发现的问题。不代表情况变差，报告会写明是哪些检查。
- **仍未处理**、**已解决**；对应检查本月读取失败的，算“本月未检查”，不算已解决。

03/04 报告开头会有一句与上月的对比，Excel 问题清单有“与上月相比”列，另有“上月问题处理情况”页；00 汇总的总体结论表多一行。第一次巡检没有对比。撰写 00、03、04 说明时，引用这些数字，不要另行统计。

## 写报告时

- **先读写法规范**：`references/writing-style.md`。要点：
  - 先说建议、费用和预计节省，再简短说明依据和限制。
  - 用直白中文，不写内部过程。
  - 公开价格标注“Azure 官网公开列表价”。
  - 区分问题条数和涉及资源数。
- **每个问题都与同类资源对比**：说明根本原因和对齐标准的做法（`references/peer-comparison.md`）。
- **严重程度按 `references/check-catalog.md`**：有外部证据时可以调整，但要写明理由。

## 交付给用户时

告诉用户以下几项，然后给出交付文件夹和压缩包的路径：

- 各报告的关键数字
- 需要客户确认的事项
- 交叉核对发现的冲突和处理方式：只加了提醒、没改建议的，要说明
- 无法读取的范围

## 参考文件

按需读取，不必一次全读：

| 文件 | 什么时候读 |
|---|---|
| `references/safety.md` | 第一次使用、遇到权限问题、不确定某个操作是否允许时 |
| `references/writing-style.md` | 写或改任何给客户的文字之前 |
| `references/check-catalog.md` | 分析问题、定严重程度时 |
| `references/cost-review.md` | 成本巡检和虚拟机规格判断 |
| `references/peer-comparison.md` | 写根本原因和对齐建议时 |
| `references/cross-checks.md` | 打包前 |
| `references/report-structure.md` | 生成或检查报告结构、Excel 列、打包时 |
| `references/narrative-format.md` | 撰写说明文件时 |
| `references/external-rules.md` | 使用 APRL 等微软规则库时 |
| `templates/customer.example.yaml` | 填写客户配置时 |

## 开发进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| M1 | 安全底层、客户配置、准备命令、质量检查、参考文档 | 已完成（0.1.0） |
| M2 | 01 月度成本、02 虚拟机规格 | 已完成（0.2.0） |
| M3 | 03/04 四个支柱、说明文件机制、新增检查、APRL 等规则库 | 已完成（0.3.0） |
| M4 | 05 同类对比、00 汇总、交叉核对、打包 | 已完成（0.4.0） |
| M5 | 跨月跟踪、最终验证（含 GitHub Copilot CLI 加载测试） | 已完成（0.5.0） |
