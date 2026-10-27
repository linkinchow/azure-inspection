# 安全与只读规则

巡检是只读的：不修改客户环境里的任何东西，不取任何密钥。下面的规则大部分已经写进脚本（`scripts/azinspect/core/auth.py`、`http.py`、`io.py`），违反时脚本会直接停止；没写进脚本的，执行时必须自己遵守。

## 账号

- **只用客户提供的只读账号。**账号、租户和取令牌用的订阅写在 `customer.yaml` 的 `access` 下。
- **不切换用户的默认账号。**永远不要执行 `az login`、`az logout`、`az account set`、`az account clear`，也不要改 Azure CLI 配置。需要登录只读账号时，请用户自己执行 `az login`。
- 脚本只用 `az account get-access-token --subscription <订阅> --resource <服务>` 取令牌，并核对令牌里的账号、租户、受众和有效期；不一致就停止。
- 令牌只在内存里使用，不打印、不写入文件、不放进命令行参数。

## 只读

- 只允许读取：
  - **GET**：Azure 资源管理、Microsoft Graph v1.0、Azure 公开价格接口。
  - **POST，只限只读查询**：Resource Graph、Cost Management 的 query 和 forecast、Azure Monitor metrics:getBatch、Log Analytics query、Graph getByIds、Azure Policy 合规状态汇总（policyStates/latest/summarize）。
- 唯一例外：Front Door 的证书引用（`Microsoft.Cdn/profiles/<名称>/secrets/<名称>`）允许 GET，用于读取证书到期时间；它只返回到期时间、主题和 Key Vault 引用，证书和私钥仍在 Key Vault 中，不会读到。其他路径含 secrets 的请求一律拦截。
- 禁止 PUT、PATCH、DELETE，以及任何会修改资源或执行动作的 POST（启动、停止、重启、扩缩容等）。
- 禁止取密钥：listKeys、list*Credentials、listAccountSas、listConnectionStrings、Key Vault 机密、AKS 集群凭据（因此不用 kubectl）。
- 不访问数据面：存储账户内容、数据库连接、Key Vault 数据面、Redis 数据等。
- 不做端口扫描，不连接客户的任何服务端口。公网是否开放只根据 NSG、公网 IP 和负载均衡规则离线判断。
- 公网 DNS 解析可以做（例如核对证书域名指向哪里），但不发请求到客户业务地址。

## 读取失败

- 401、403、404 和超时都记录下来（脚本会写入 `raw/_calls/`），然后继续，不重试权限、不想办法绕过。
- 报告的“检查覆盖”里写明：哪些订阅或资源无法读取，原因是什么。
- **缺数据不等于 0。**读不到的费用不算 0 元，读不到的指标不算“利用率低”，读不到配置不算“未开启”。

## 数据处理

- 保存原始数据前去掉密钥、令牌、邮箱和电话（`io.sanitize`）。
- 客户报告里不出现邮箱地址；人员用角色描述（例如“1 个用户账号”），必要时只写显示名。
- 客户数据只放在客户工作目录，不放进插件仓库，不上传到任何外部服务。
- 发给客户前，按 `report-structure.md` 的打包检查确认没有遗留内部文件。

## 需要用户确认后才能做的事

- 第一次对某个客户执行采集前，确认 `customer.yaml` 里的账号和订阅范围。
- 任何会产生费用或对外发布的动作（本 skill 本身不需要这类动作）。
