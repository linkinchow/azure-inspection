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

> **当前版本 0.6.1**：全部 6 份报告（00 汇总、01 月度成本、02 虚拟机规格、03 可靠性与安全、04 卓越运营与性能效率、05 同类资源配置对比），并入 APRL、Defender/Policy、孤立资源、AMBA、Landing Zone 清单等微软公开规则库；RI/SP 覆盖、使用率和购买建议；跨报告交叉核对、质量检查和打包。跨月跟踪（自动与上月比：新增、已解决、仍未处理）。进度见 SKILL.md 文末。

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

### GitHub Copilot（Copilot CLI、VS Code/Visual Studio/JetBrains 的 agent 模式）

把 skill 文件夹复制或链接到以下任一位置：
- 个人目录：`~/.copilot/skills/`
- 项目内：`.github/skills/` 或 `.agents/skills/`

Copilot CLI 中执行 `/skills reload` 后，用 `/azure-monthly-inspection` 调用。

非交互运行（`copilot -p`）时，建议只放行 python 和读文件命令，禁止 Copilot 直接调用 Azure CLI 等工具，例如：

```
copilot -p "<任务说明>" --no-ask-user --allow-tool "shell(python)" --allow-tool "shell(python:*)" --allow-tool write --deny-tool "shell(az)" --deny-tool "shell(az:*)" --deny-tool "shell(curl)" --deny-tool "shell(Invoke-RestMethod)" --deny-tool "shell(Invoke-WebRequest)" --deny-tool "shell(pwsh)" --deny-tool "shell(powershell)" --deny-tool "shell(Remove-Item)"
```

如果 Copilot 配置了能操作 Azure 的 MCP 服务器，巡检时先停用它；账号最好只有只读角色（`access-check` 会提示可写角色）。

### OpenAI Codex（CLI、IDE 扩展、Codex 应用）

把 skill 文件夹复制或链接到以下任一位置：
- 个人目录：`~/.agents/skills/`
- 项目内：`.agents/skills/`

重启 Codex 后，用 `$azure-monthly-inspection` 调用，或直接描述任务。

## 样例

`examples/sample-output/` 是用虚构的“示例客户”数据生成的全部 6 份报告，数字和问题都是编的，供第一次使用前了解报告的样子。重新生成方法见 `examples/README.md`。

> 本插件主要在 Claude Code 上测试；GitHub Copilot CLI 1.0.104 已在一个真实客户环境中从准备到打包完整跑通 6 份报告，Azure 请求全部为只读。Codex 读取 skill 的方式（`.agents/skills/`）相同，尚未实测。安全规则由脚本强制执行，与 agent 无关；报告文字质量取决于所用模型，建议首次使用时先试跑一次。

## 使用流程

1. 对 agent 说：“给 <客户> 做 Azure 月度巡检”。
2. agent 会依次：
   - 检查环境
   - 在你指定的目录建客户工作目录
   - 向你要租户、只读账号和订阅信息，填写 `customer.yaml`
   - 请你用只读账号登录
   - 核对能读取哪些订阅
3. 月度巡检：采集（collect）、分析（analyze）、撰写说明（agent 写 narrative）、生成并核对（build）、质量检查（quality-check）。之后交叉核对（crosscheck）和打包（package）。全部可用。

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
