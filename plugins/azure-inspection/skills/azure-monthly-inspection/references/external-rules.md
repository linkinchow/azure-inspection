# 微软公开规则库的使用方法

除了我们自己的检查项，巡检还使用微软公开的规则库，扩大覆盖面。统一做法：

1. **取规则库里的只读查询或清单**，放进 `vendor/`，固定版本，记录提交号和日期。
2. **用本 skill 的只读客户端执行**（`core/http.py`），不运行规则库自带的工具。
3. **结果转成统一的问题格式**，用中文写说明，并标注出处（规则编号和官方链接）。
4. **白名单**：只自动列出审核过的规则，按我们的严重程度规则重新定级。其余规则或者放进“需要客户确认”，或者忽略。
5. **与我们自己的检查项去重**：同一问题只出现一次，在说明中加上规则库编号。
6. **规则库更新版本时，重新审核新增和修改的规则。**

> 实现进度（M3）：APRL、Defender/Policy、孤立资源、AMBA、Landing Zone 清单已接入，固定版本在 `vendor/` 下（各目录有 LICENSE 和版本号）：
>
> | 规则库 | 代码 | 用在哪里 |
> |---|---|---|
> | APRL（20 条白名单） | `waf/aprl/` | 03：R3、R13–R21、S-N9；04：O11 |
> | Defender / Policy | `waf/defender/` | 03：S-I11 |
> | Azure Orphan Resources（19 类） | `cost/orphan.py` | 01：当前闲置资源待确认 |
> | AMBA（15 类资源的核心告警） | `waf/amba/` | 04：O2 与推荐告警对比、“推荐告警（AMBA）”页 |
> | Azure Review Checklists ALZ（40 条可自动核对；2 条上游查询有错误，已跳过） | `waf/landing_zone/` | 03：Landing Zone 对照（不计入问题数） |

## 各规则库

| 规则库 | 支柱 | 内容 | 用法 | 许可证 |
|---|---|---|---|---|
| [APRL](https://github.com/Azure/Azure-Proactive-Resiliency-Library-v2)（Azure Proactive Resiliency Library v2） | 可靠性 | 按资源类型整理的可靠性建议，每条有固定编号、影响等级、官方链接；约一半附带 Resource Graph 查询 | 执行白名单内的查询；无查询的建议列为需要确认 | MIT |
| Defender for Cloud 建议、Azure Policy 合规结果 | 安全 | Resource Graph 的 `securityresources`、`policyresources` 表，逐资源给出建议和合规状态 | 直接查询，按建议严重程度汇总 | 客户自己的数据，无需许可 |
| [Azure Orphan Resources](https://github.com/dolevshor/azure-orphan-resources) | 成本 | 找闲置和孤立资源的 Resource Graph 查询 | 并入 01 的闲置资源 | 加入前核对 |
| [AMBA](https://github.com/Azure/azure-monitor-baseline-alerts)（Azure Monitor Baseline Alerts） | 卓越运营 | 按资源类型推荐的告警指标和阈值 | O2 告警检查与推荐告警逐项对比 | 加入前核对 |
| [Azure Review Checklists](https://github.com/Azure/review-checklists) | 架构 | Landing Zone 等检查清单，部分条目带 Resource Graph 查询 | 支撑“架构总览与 Landing Zone 对照” | 加入前核对 |
| [azqr](https://github.com/Azure/azqr)（Azure Quick Review） | 全部 | 汇总上述多个来源的命令行工具 | **只作参考**：用 `azqr rules --json` 对照我们的覆盖缺口；不作为依赖，因为它用 CLI 默认账号认证，可能用错账号 | MIT |
| [PSRule for Azure](https://github.com/Azure/PSRule.Rules.Azure) | 全部 | 500 多条按支柱分类的规则 | **只作参考**；依赖 PowerShell | MIT |

## APRL 试跑经验

- 当前版本 372 条建议，其中约 160 条有可执行的 Resource Graph 查询；其余标记为“无法用 Resource Graph 验证”或“开发中”。
- 命中结果大致分三类，比例相近：
  - 与我们已有检查重复。
  - 有价值的新发现，例如数据库存储自动增长关闭、负载均衡后端只有 1 台、专线只连一个对接点。
  - 查询过宽或取决于业务的建议，不宜直接列为问题。
- 发现过的误报：
  - “AKS 持久卷使用旧驱动”的查询只要有一个 CSI 驱动未开就报。Blob 驱动默认关闭，所以所有集群都会被标出。
  - “所有虚拟机都应跨可用区或用 ZRS 磁盘、都应配置 Site Recovery”这类建议，需要按业务要求判断。
- 因此必须用白名单，并在报告中按我们的严重程度规则定级。
