# Azure 月度巡检插件（只读）

用客户提供的只读账号读取 Azure 配置、指标和费用，生成给客户的中文巡检报告：

| 编号 | 报告 |
|---|---|
| 00 | 汇总报告 |
| 01 | 月度成本巡检 |
| 02 | 虚拟机利用率与规格优化 |
| 03 | 可靠性与安全巡检 |
| 04 | 卓越运营与性能效率巡检 |
| 05 | 同类资源配置对比 |

全部检查只读。脚本只允许读取，会拦截写操作和取密钥；令牌必须属于客户配置里的只读账号，否则停止。不会切换你的 Azure CLI 默认账号。

> **当前版本 0.10.5**：全部 6 份报告（00 汇总、01 月度成本、02 虚拟机规格、03 可靠性与安全、04 卓越运营与性能效率、05 同类资源配置对比），01–05 可按客户选择只做一部分（`customer.yaml` 的 `report.include`，00 只汇总所选），也可只查客户指定的订阅，并入 APRL、Defender/Policy、孤立资源、AMBA、Landing Zone 清单等微软公开规则库；RI/SP 覆盖、使用率和购买建议；跨报告交叉核对、质量检查和打包。跨月跟踪（自动与上月比：新增、已解决、仍未处理）按资源判断；读取失败、不在本月范围或范围不完整的问题记为“本月未检查”并写明原因，不算作已解决。进度见 SKILL.md 文末。
>
> **0.10.5 修复**（措辞和显示类）：
> - 01 增减图：很小的变化显示“0”而不是“-0”；全是增加或全是减少时不再空出半边；四舍五入为 0 的变化不列为“增减最大”。
> - 月初 1–2 天内查询费用时，01 的“数据范围与限制”提醒上月最后一天的费用可能还没全部入账。
> - 00 附件表里的报告文件名不再被加空格（如“01_9 月”）；只做 02 时，范围说明不再写“预留和节省计划订单按全租户检查”（02 不读订单）。
> - 截断的发现保留数字后面隔了空格的中文单位（“30 天”）。
> - 交叉核对 X10 按完整数字比较，四舍五入来的百分比算一致。
> - 检查项汇总表写明是哪一条问题可能多报；跟踪说明里写明“新增检查项发现”也包括已有检查新增的规则。
> - 说明文件里的重点问题只有部分编号失效时，build 提醒核对文字；05 不再出现内部路径。
> - 改选报告后，build 把本月没选的报告的旧文件和图表移到 `reports/未选报告_旧版/`，不再和本月报告混在一起。
> - 检查覆盖页的接口报错先用中文说明是什么情况，原文放在括号里。
> - 01 分别写费用、区域和变化原因、预测各自实际读取的时间（用 `--resume` 续采时不再都写成本次运行时间）。
> - 费用采集多读一项上月按计价模式的费用；预留或节省计划的购买费用占某月费用 5% 以上时，01 另给出不含这部分时的日均变化。
> - R9：价格调整通知不再当作退役公告；和已列出的版本问题是同一件事的公告并入那一条；未关联到资源的公告先用中文写产品和要做什么，英文原文放在括号里。
> - X10 也检查不带小数的金额（和表格数字四舍五入后比较）。
> - 01 的区域表和区域增减图把 Cost Management 的地区名（如“EU West”）译成中文；增减图的颜色说明移到图上方，不再压住横轴刻度。
>
> **0.10.4 修复**：
> - 04 卓越运营的 AKS 操作记录（O4）以前每次都返回 400（查询开始时间超过活动日志的 90 天保留期），从来没读到；现在限定在保留期内。接口报错改为记录原始的错误代码和说明，不再是“None: None”。
> - 只查部分订阅时，04 的范围说明写明管理组按全租户检查；治理检查（O8）只点名所选的订阅。
> - 说明文件引用的问题编号本月不存在时（升级后变了，或属于没选的支柱），跳过并提醒，不再中断 03/04 的生成。
> - 某个支柱分析失败时，保留它上次的结果，其他支柱照常分析，并在重新分析成功前不能打包。
> - Excel 复算失败时重试一次；大文件保存后关闭出错，不再算作复算失败。
> - 调用记录增加每次请求的重试次数、等待时间和限流次数。
> - 用户目录和临时目录都不可写时（如 Codex 在 Windows 的沙箱里），图表的 matplotlib 缓存自动放到工作目录的 `.cache/matplotlib`，不用另外设置环境变量。
> - SKILL.md：只运行本 skill 的命令，命令被拒时停下告诉用户，不设置 `AZINSPECT_NO_EXCEL`，不结束不是自己启动的进程。
>
> **0.10.3 修复**：
> - 下个月费用预测只读到部分订阅时，不再当作全部订阅的预测：只和有预测的订阅自己的本月费用比较；有预测的订阅不到本月费用的 95% 时，01 和 00 写“预测不完整”，不给出全部订阅的预计；一个都没读到时不再显示 −100%；Excel“说明”列改为中文。新增交叉核对 X11 检查这一点。
> - 只做部分报告时，没选 01、02 的 00 结论不再要求写金额，写了金额（包括“金额待确认”）会被质量检查挡住；说明文件是按另一次报告选择写的、之后没改过时，build 会停下并列出这些文件。
> - 下个月有特别大的单日费用（一次性购买预留，或 Azure 预测里的大额单日）时，01 写出这几天并按去掉它们后的日均比较，预测里的大额单日单独提示核对，00 的预计费用后面也加提示。
> - README 补充三个 agent 的运行方式和测试情况（Codex 在 Windows 上的前提、任务说明的写法）。
> - 上月记录由 0.10.0 以前的版本生成时，03 和 00 的“与上月相比”会说明部分“新增问题”来自之后新增或调整的检查规则。
>
> **0.10.2 改进**：费用预测被接口限流（429）时，不再每个订阅等 2 分钟后放弃：每个订阅先试一次，被限流的不等待，等其他费用查询做完后轮流补读，补读最多 20 分钟，仍读不到的订阅记为读取失败；用 --resume 续采时，已读到的预测直接复用。不再查询下下个月的预测，01 Excel 预测表去掉“下下月预测USD”一列。新增交叉核对 X10：00 结论里的金额和带小数的百分比，如果第 1 节表格里没有，就列出来请人工确认（不阻止打包）。
>
> **0.10.1 修复提醒**：0.10.0 及以前，全订阅巡检时 03 的“Defender 与 Policy 逐项结果”（S-I11）可能只列出部分订阅的 Defender 建议（Resource Graph 只返回了部分订阅，而程序只有在它完全不返回时才改为按订阅读取）。订阅多的租户请升级到 0.10.1 后重新分析和生成 03；安全检查的身份部分已经采集过的，不用重新采集。升级后的第一个月，跨月跟踪会把补上的订阅里的 Defender 建议记为“新增问题”，它们大多早就存在：03 和 00 的“与上月相比”会写明 Defender 建议覆盖的订阅从几个增加到几个，持续时间见问题清单。
>
> **0.9.0 修复提醒**：0.8.3 及以前，03 里微软退役公告（R9）的退役日期显示成一串数字或写成“退役日期未取得”，严重程度因此可能偏低，标题里的“&”显示成“&amp;amp;”。只影响分析和报告，不用重新采集：升级到 0.9.0 后重新分析和生成 03 即可。
>
> **0.8.3 修复提醒**：0.8.0–0.8.2 采集时，身份安全的虚拟机清单读取失败（查询返回 400），报告缺少虚拟机安全基线检查（S-I8：SSH 密码登录、公网暴露、补丁评估、受信任启动等），05 同类资源配置对比里的虚拟机类也缺数据；其他检查不受影响。用这几个版本采集并交付过报告的，请升级到 0.8.3 后补采身份安全（`collect --part waf --pillars security_identity`），再重新分析和生成（做了 05 的也要重新生成 05）；用了跨月跟踪的，这期间被记为“已解决”的 S-I8 问题需要更正。

## 使用前提

- **Python 3.10+**，依赖装一次：

  ```bash
  python -m pip install --user -r plugins/azure-inspection/skills/azure-monthly-inspection/scripts/requirements.txt
  ```

- **Azure CLI**，并用客户的只读账号执行过 `az login`。
- **中文字体**（图表用）：Windows 自带微软雅黑；Mac 自带苹方；Linux 安装 Noto Sans CJK。
- **可选**：Windows 上装了 Excel 时，可用 pywin32 复算 Excel 公式。

## 安装

skill 本身是一个自包含的文件夹：`plugins/azure-inspection/skills/azure-monthly-inspection/`。它遵循公开的 [Agent Skills 规范](https://agentskills.io)，Claude Code、GitHub Copilot、OpenAI Codex 都能使用。

### Claude Code（终端、Claude Desktop 的 Code 页签、VS Code 扩展）

把本仓库作为插件市场添加，然后安装：

```bash
claude plugin marketplace add <仓库地址或本地路径>
```

```bash
claude plugin install azure-inspection@azure-inspection
```

在会话里输入 `/azure-inspection:azure-monthly-inspection`，或直接说“给某客户做月度巡检”。仓库更新后执行 `claude plugin marketplace update azure-inspection` 获取新版本。

非交互运行（`claude -p`）时，同样建议限定工具，并停用 MCP 服务器，例如：

```
claude -p "<任务说明>" --strict-mcp-config --allowedTools "Skill Read Glob Grep Write Edit Bash(python:*)" --disallowedTools "Bash(az:*) Bash(curl:*) WebFetch WebSearch"
```

从 Claude Desktop 的会话里调用终端版 `claude` 时，先清掉继承的 `CLAUDE*`、`ANTHROPIC*` 环境变量，否则会提示未登录。

### GitHub Copilot（Copilot CLI、VS Code/Visual Studio/JetBrains 的 agent 模式）

把 skill 文件夹复制或链接到以下任一位置：
- 个人目录：`~/.copilot/skills/`
- 项目内：`.github/skills/` 或 `.agents/skills/`

Copilot CLI 中执行 `/skills reload` 后，用 `/azure-monthly-inspection` 调用。

非交互运行（`copilot -p`）时，建议只放行 python 和读文件命令，禁止 Copilot 直接调用 Azure CLI 等工具，例如：

```
copilot -p "<任务说明>" --no-ask-user --allow-tool "shell(python)" --allow-tool "shell(python:*)" --allow-tool write --deny-tool "shell(az)" --deny-tool "shell(az:*)" --deny-tool "shell(curl)" --deny-tool "shell(Invoke-RestMethod)" --deny-tool "shell(Invoke-WebRequest)" --deny-tool "shell(pwsh)" --deny-tool "shell(powershell)" --deny-tool "shell(Remove-Item)"
```

如果 Copilot 配置了能操作 Azure 的 MCP 服务器，巡检时先停用它（`--disable-builtin-mcps --disable-mcp-server <名称>`；插件要用 `copilot plugin disable <插件>`，用完再 `enable`）；账号最好只有只读角色（`access-check` 会提示可写角色）。

注意：`shell(python:*)` 放行的是任意 Python 代码，不是沙箱；只读由脚本自身的检查和只读账号保证。

### OpenAI Codex（CLI、IDE 扩展、Codex 应用）

把 skill 文件夹复制或链接到以下任一位置：
- 个人目录：`~/.agents/skills/`
- 项目内：`.agents/skills/`

重启 Codex 后，用 `$azure-monthly-inspection` 调用，或直接描述任务。

在 Windows 上运行 Codex CLI 有两个前提，否则一条命令都执行不了：
- 沙箱设为 `windows.sandbox="unelevated"`（写在 `~/.codex/config.toml`，或每次用 `-c` 指定）；
- 使用 python.org 或 uv 安装的 Python，不能用 Microsoft Store 版的 Python 和 PowerShell。

沙箱里不能用 Excel 复算公式，报告会退回结构核对。非交互运行的参考命令：

```
codex exec -s workspace-write -c windows.sandbox="unelevated" -c mcp_servers.<名称>.enabled=false "<任务说明>"
```

## 样例

`examples/sample-output/` 是用虚构的“示例客户”数据生成的全部 6 份报告，数字和问题都是编的，供第一次使用前了解报告的样子。重新生成方法见 `examples/README.md`。

> 本插件主要在 Claude Code 上测试；GitHub Copilot CLI 1.0.104 已在一个真实客户环境中从准备到打包完整跑通 6 份报告，Azure 请求全部为只读。另外，Claude Code 终端版 2.1.201、GitHub Copilot CLI 1.0.105、OpenAI Codex CLI 0.164.0 都已用虚构数据离线跑通全流程和“只做部分报告”的流程（Codex 需满足上面的 Windows 前提）；Codex 尚未在真实客户环境测试。安全规则由脚本强制执行，与 agent 无关；报告文字质量取决于所用模型，建议首次使用时先试跑一次。
>
> 让其他 agent 运行时，任务说明里建议写明：“每条命令单独运行，只写 python 命令本身，不要在前后加其他命令或环境变量；命令被拒绝时停下来告诉我，不要自己写脚本代替”。否则命令可能被上面的放行规则拦下，agent 会放弃或自己写包装脚本。

## 使用流程

1. 对 agent 说：“给 <客户> 做 Azure 月度巡检”。
2. agent 会依次：
   - 检查环境
   - 在你指定的目录建客户工作目录
   - 向你要租户、只读账号和订阅信息，填写 `customer.yaml`
   - 请你用只读账号登录
   - 核对能读取哪些订阅
3. 月度巡检：采集（collect）、分析（analyze）、撰写说明（agent 写 narrative）、生成并核对（build）、质量检查（quality-check）。之后交叉核对（crosscheck）和打包（package）。全部可用。

### 只做部分报告或部分订阅

01–05 可以按客户需要只做一部分，00 汇总报告总是生成，只汇总所选报告；也可以只查客户指定的关键订阅。对 agent 说就行，例如：

- “这个客户以后只做 03、04、05”
- “只做可靠性巡检”（03 只做可靠性部分，报告为 `03_可靠性巡检报告`）
- “这个月只做 01 和 03，做完改回全部”
- “只巡检 pay-prod 和 shop-prod 两个订阅”

agent 会先复述要做哪几份报告、查哪些订阅，请你确认，再改客户工作目录里 `customer.yaml` 的这两项（也可以自己改）：

```yaml
scope:
  includeSubscriptions: ['pay-prod', 'shop-prod']   # 不写或为空等于全部；支持 * 通配或订阅 ID
report:
  include: ['01', '03']                             # 不写等于全部；03/04 也可写支柱名，如 ['可靠性', '性能效率']
```

- 这是长期设置，之后每个月都按它执行；只想某个月例外，做完要改回。
- 报告文件保留原来的编号（例如只做 01 和 03 时，交付的是 00、01、03 三份），00 汇总报告里的附件按所选顺序编为附件一、二……
- 只选一部分时，采集会自动补上所选报告要用的数据（例如只选 02 时只读 RI/SP 覆盖，不做费用巡检）。没选的报告在交叉核对中显示“不适用”，打包时不包含。
- 只查部分订阅时，报告写明“按贵司选择，本次只检查 N 个订阅”；Entra ID 账号与凭据、管理组、预留和节省计划订单不按订阅划分，仍按全租户检查。跨月跟踪不会把没检查的订阅里的问题算作“已解决”。依赖其他订阅资源的检查（例如专线网关连接的专线线路常在另一个订阅）在报告里写明可能漏报，跨月跟踪记为“本月未检查（范围不完整）”；维护配置、备份、活动日志告警建在其他订阅时可能多报，报告里也会写明。订阅少，采集也快很多。

客户数据（`customer.yaml`、原始数据、报告）都放在客户工作目录，不要提交到本仓库。

## 开发

运行单元测试（安全底层：账号核对、只读拦截、去敏感信息、格式检查）：

```bash
python -m unittest discover -s plugins/azure-inspection/skills/azure-monthly-inspection/scripts/tests
```

校验插件结构：

```bash
claude plugin validate .
```

目录说明：

```
.claude-plugin/marketplace.json                 插件市场清单
plugins/azure-inspection/.claude-plugin/plugin.json
plugins/azure-inspection/skills/azure-monthly-inspection/
  SKILL.md                                      主说明
  references/                                   规则和写法（按需加载）
  scripts/azinspect/                            Python 脚本（core：只读访问、配置、格式、质量检查）
  scripts/azinspect_cli.py                      命令入口
  templates/customer.example.yaml               客户配置模板
```

## 许可证

MIT，见 [LICENSE](LICENSE)。`vendor/` 下的微软规则库各自保留原 MIT 许可证。
