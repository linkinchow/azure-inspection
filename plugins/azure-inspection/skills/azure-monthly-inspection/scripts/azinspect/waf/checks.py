"""Check names, report grouping, default acceptance criteria and resource type labels (customer independent)."""
from __future__ import annotations

CHECKS = {
    'R1': 'AKS 网络容量', 'R2': '系统节点池', 'R3': '可用区', 'R4': 'AKS 控制面服务等级', 'R5': '数据库高可用与备份',
    'R6': '存储冗余与恢复', 'R7': '虚拟机备份', 'R8': '出站连接', 'R9': '版本与组件退役', 'R10': '配额', 'R11': '资源健康',
    'R12': '近期失败操作', 'R13': '数据库存储自动增长', 'R14': '数据库维护窗口', 'R15': '负载均衡后端单实例',
    'R16': '专线与 VPN 冗余', 'R17': 'Event Hubs', 'R18': '应用网关健康探测', 'R19': '镜像仓库可用性', 'R20': 'AKS 备份与扩缩容',
    'R21': '其他可靠性建议（APRL）',
    'S-N1': '子网未关联 NSG', 'S-N2': 'NSG 对公网开放端口', 'S-N3': '公网 IP 暴露', 'S-N4': '数据服务公网访问', 'S-N5': '存储账户安全',
    'S-N6': '入口防护（WAF、负载均衡）', 'S-N7': '传输加密（TLS）', 'S-N8': '私有终结点连接状态', 'S-N9': '路由与 IP 转发',
    'S-I1': 'AKS API Server 访问', 'S-I2': 'AKS 身份认证', 'S-I3': 'AKS 安全功能与补丁', 'S-I4': 'Defender for Cloud', 'S-I5': '高权限角色',
    'S-I6': '凭据有效期', 'S-I7': '审计日志', 'S-I8': '虚拟机安全基线', 'S-I9': 'Key Vault', 'S-I10': '镜像仓库与 AI 服务认证', 'S-I11': 'Defender 与 Policy 逐项结果',
    'O1': '监控覆盖', 'O2': '告警', 'O3': '日志保留与诊断', 'O4': '升级与维护', 'O5': '配置一致性与 IaC', 'O6': '失败或卡住的操作',
    'O7': '标签与负责人', 'O8': '治理（策略、资源锁）', 'O9': '预算与费用告警', 'O10': 'Advisor 运营建议', 'O11': '变更告警',
    'P1': '计算负载', 'P2': 'AKS 节点负载与调度', 'P3': '出站 SNAT', 'P4': '磁盘与 IO', 'P5': '数据库与缓存', 'P6': 'AI 服务限流与配额',
    'P7': '存储性能', 'P8': '部署位置与跨区域流量', 'P9': '入口与负载均衡健康', 'P10': 'Advisor 性能建议',
}

# What "done" looks like for each check; a finding can override with its own 'acceptance'.
ACCEPTANCE = {
    'R1': '节点子网的可用 IP 足够所有节点池扩到上限并完成一次版本升级；近 7 天没有因子网已满导致的创建节点失败',
    'R2': '系统节点池至少 2 个节点（生产建议 3 个、跨可用区），且只运行系统组件',
    'R3': '生产节点池、应用网关、NAT 网关和关键虚拟机部署在至少 2 个可用区',
    'R4': '生产集群使用 Standard 层（有 SLA）',
    'R5': '生产数据库开启区域冗余高可用和异地备份；缓存开启持久化；做过一次恢复演练',
    'R6': '存放重要数据的存储账户使用 ZRS/GRS，并开启软删除和版本控制',
    'R7': '保存不可重建数据的虚拟机已配置 Azure Backup，并完成一次恢复测试',
    'R8': '出站使用 NAT 网关或足够的 SNAT 端口；近 30 天没有 SNAT 连接失败',
    'R9': '集群版本在标准支持期内并开启自动升级；节点镜像 30 天内更新过；即将退役的组件有迁移计划',
    'R10': '各区域关键配额使用率低于 80%，或已申请提高配额',
    'R11': '资源健康为“可用”，异常事件已有处理记录',
    'R12': '失败操作的原因已确认并修复，近 7 天没有同类失败',
    'R13': '生产数据库开启存储自动增长，并有存储使用率告警',
    'R14': '生产数据库设置了业务低峰的自定义维护窗口',
    'R15': '生产负载均衡后端池至少 2 台实例并跨可用区',
    'R16': '专线来自至少两个对接点或有 VPN 备份；网关设置了维护窗口',
    'R17': 'Event Hubs 开启自动扩容并有吞吐量告警',
    'R18': '应用网关每个后端都有自定义健康探测',
    'R19': '生产镜像仓库为 Premium 层，开启区域冗余和软删除',
    'R20': '生产节点池开启自动扩缩容且至少 2 个节点；有状态集群配置了备份',
    'R21': 'APRL 建议已处理或确认不适用',
    'S-N1': '所有业务子网关联 NSG，入站默认拒绝',
    'S-N2': 'NSG 不再允许 Internet 任意来源访问管理端口和数据、中间件端口',
    'S-N3': '虚拟机不直接绑定公网 IP，管理访问经 Bastion 或 VPN；Linux 只允许密钥登录',
    'S-N4': '数据服务关闭公网访问或只允许必要来源，优先使用私有终结点',
    'S-N5': '存储账户禁止匿名访问、只允许 HTTPS 和 TLS 1.2，并按需限制网络访问',
    'S-N6': '对外入口启用 WAF 且为阻止模式；负载均衡不暴露管理端口',
    'S-N7': '数据服务强制加密连接，最低 TLS 1.2',
    'S-N8': '已删除目标资源的私有终结点已清理，没有处于断开或拒绝状态的连接',
    'S-N9': '只有网络设备开启 IP 转发；默认路由指向预期的防火墙或网关',
    'S-I1': 'API Server 限制来源 IP 或为私有集群',
    'S-I2': '集群集成 Entra ID 并禁用本地账号',
    'S-I3': '集群开启需要的安全功能（Defender、Workload Identity、镜像清理等），网络策略组件在支持期内',
    'S-I4': '生产订阅开启对应资源的 Defender 计划，并配置安全告警联系人；高严重性建议有处理计划',
    'S-I5': '高权限角色按人分配并有审批，没有共享账号和长期的临时提权',
    'S-I6': '没有已过期或 90 天内到期且无人负责的凭据',
    'S-I7': '活动日志导出到日志工作区或存储，保留期满足审计要求；关键网络开启流日志',
    'S-I8': '虚拟机定期做补丁评估，公网可达的 Linux 禁用密码登录',
    'S-I9': '生产 Key Vault 开启清除保护和软删除，并使用 RBAC 授权',
    'S-I10': '镜像仓库禁用管理员账号；AI 服务禁用 API 密钥认证，改用 Entra ID',
    'S-I11': '超过 30 天的高严重性 Defender 建议已处理或有记录的豁免；已分配策略的不合规资源已修正或豁免',
    'O1': '生产集群、虚拟机和关键资源都接入 Azure Monitor 或已确认的其他监控平台',
    'O2': '生产资源有 CPU、内存、存储、连接数和可用性告警，告警发送到值班组且有人处理',
    'O3': '日志保留期满足审计和排障要求，关键资源已开启诊断日志',
    'O4': '集群开启自动升级并设置维护窗口',
    'O5': '生产变更统一走 IaC，同类资源配置一致',
    'O6': '处于失败状态的资源已修复或删除',
    'O7': '生产资源有环境、负责人和成本中心标签',
    'O8': '关键数据资源有删除锁；订阅按管理组组织并有基础策略',
    'O9': '有费用的订阅都配置了预算和费用告警',
    'O10': 'Advisor 运营建议已处理或确认不适用',
    'O11': '路由表、NSG 等关键网络配置的变更有活动日志告警并发送到值班组',
    'P1': '30 天平均负载低于 80%，每日最高值打满的天数明显减少',
    'P2': '没有长期无法调度的 Pod；节点内存使用低于可分配量的 80%',
    'P3': '近 30 天没有 SNAT 连接失败',
    'P4': '磁盘 IOPS 和吞吐不再每天打满',
    'P5': '数据库和缓存的 CPU、内存、连接数保持在上限的 80% 以内并有余量',
    'P6': '限流（429）比例低于 1%，配额有余量',
    'P7': '存储账户没有限流，端到端延迟与服务端延迟接近',
    'P8': '计算与数据在同一区域，跨区域流量有明确原因',
    'P9': '入口后端健康，5xx 比例低于 1%；不用的入口已删除',
    'P10': 'Advisor 性能建议已处理或确认不适用',
}

# ARM resource type (lower case) -> Chinese noun used in "涉及资源数"
TYPE_LABELS = {
    'microsoft.network/virtualnetworks/subnets': '子网', 'microsoft.network/virtualnetworks': '虚拟网络',
    'microsoft.network/networksecuritygroups': 'NSG', 'microsoft.network/publicipaddresses': '公网 IP',
    'microsoft.network/loadbalancers': '负载均衡', 'microsoft.network/applicationgateways': '应用网关',
    'microsoft.network/natgateways': 'NAT 网关', 'microsoft.network/networkinterfaces': '网卡', 'microsoft.network/privateendpoints': '私有终结点',
    'microsoft.network/privatelinkservices': '私有链接服务', 'microsoft.network/frontdoors': 'Front Door',
    'microsoft.cdn/profiles': 'Front Door', 'microsoft.network/frontdoorwebapplicationfirewallpolicies': 'WAF 策略',
    'microsoft.network/virtualnetworkgateways': '虚拟网络网关', 'microsoft.network/azurefirewalls': '防火墙',
    'microsoft.containerservice/managedclusters': '集群', 'microsoft.containerservice/managedclusters/agentpools': '节点池',
    'microsoft.compute/virtualmachines': '虚拟机', 'microsoft.compute/virtualmachinescalesets': '虚拟机规模集',
    'microsoft.compute/disks': '磁盘', 'microsoft.compute/snapshots': '快照',
    'microsoft.dbformysql/flexibleservers': 'MySQL', 'microsoft.dbforpostgresql/flexibleservers': 'PostgreSQL',
    'microsoft.cache/redis': 'Redis', 'microsoft.cache/redisenterprise': 'Redis',
    'microsoft.documentdb/mongoclusters': 'MongoDB', 'microsoft.documentdb/databaseaccounts': 'Cosmos DB',
    'microsoft.storage/storageaccounts': '存储账户', 'microsoft.keyvault/vaults': 'Key Vault',
    'microsoft.containerregistry/registries': '镜像仓库', 'microsoft.cognitiveservices/accounts': 'AI 账户',
    'microsoft.operationalinsights/workspaces': '日志工作区', 'microsoft.insights/actiongroups': '操作组',
    'microsoft.recoveryservices/vaults': '备份保管库', 'microsoft.eventhub/namespaces': 'Event Hubs 命名空间', 'microsoft.network/routetables': '路由表', 'microsoft.resources/subscriptions': '订阅',
    'microsoft.management/managementgroups': '管理组', 'microsoft.authorization/roleassignments': '角色分配',
    'microsoft.resources/deployments': '部署', 'microsoft.network/publicipprefixes': '公网 IP 前缀',
    'microsoft.graph/serviceprincipals': '服务主体', 'microsoft.graph/users#guest': '来宾账号', 'microsoft.graph/users': '用户账号',
    'microsoft.cognitiveservices/locations/usages': '模型配额', 'microsoft.alertsmanagement/prometheusrulegroups': '告警规则组',
    'microsoft.insights/metricalerts': '告警规则', 'microsoft.insights/scheduledqueryrules': '告警规则',
    'microsoft.insights/datacollectionrules': '数据收集规则', 'datacollectionrule': '数据收集规则',
    'microsoft.insights/datacollectionendpoints': '数据收集终结点', 'datacollectionendpoint': '数据收集终结点',
}
MEASURE = {'虚拟机': '台', '磁盘': '块', '模型配额': '项', '告警规则': '条', '告警规则组': '组'}


def report_of(check: str) -> str:
    return '03' if check.startswith(('R', 'S-')) else '04'


def group_of(check: str) -> str:
    if check.startswith('R'):
        return '可靠性'
    if check.startswith('S-'):
        return '安全'
    return '卓越运营' if check.startswith('O') else '性能效率'


def check_number(check: str) -> tuple:
    head = check.rstrip('0123456789')
    return head, int(check[len(head):] or 0)


def type_label(resource_type: str | None) -> str:
    if not resource_type:
        return '资源'
    t = resource_type.lower()
    return TYPE_LABELS.get(t) or TYPE_LABELS.get('/'.join(t.split('/')[:2])) or '资源'


def count_text(n: int, label: str) -> str:
    """'5 台虚拟机', '3 个 NAT 网关'."""
    space = ' ' if label[:1].isascii() else ''
    return f'{n} {MEASURE.get(label, "个")}{space}{label}'
