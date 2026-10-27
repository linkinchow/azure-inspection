"""Reviewed APRL whitelist: which APRL queries become findings, under which check, at which severity, in which words.

Severity is for production resources; test and development resources go one level down. APRL rules that report
every resource regardless of need (Site Recovery for all VMs, zone-redundant disks everywhere, ...) or that duplicate
our own checks are deliberately not listed. Review again when vendor/aprl is updated to a new APRL commit.
"""
from __future__ import annotations

RULES = {
    '6293a3cc-6b4a-4c0f-9ea7-b8ae8d7dd3d5': {
        'check': 'R13', 'severity': '高', 'type': 'Microsoft.DBforPostgreSQL/flexibleServers',
        'finding': 'PostgreSQL 关闭了存储自动增长，磁盘写满后数据库会变为只读',
        'recommendation': '开启存储自动增长，并为存储使用率配置告警'},
    'b2bad57d-7e03-4c0f-9024-597c9eb295bb': {
        'check': 'R14', 'severity': '中', 'type': 'Microsoft.DBforPostgreSQL/flexibleServers',
        'finding': 'PostgreSQL 未设置自定义维护时间窗口，平台维护可能落在业务高峰',
        'recommendation': '设置在业务低峰的自定义维护窗口，并提前通知相关团队'},
    '6d82d042-6d61-ad49-86f0-6a5455398081': {
        'check': 'R15', 'severity': '高', 'type': 'Microsoft.Network/loadBalancers',
        'finding': '负载均衡后端池只有 1 台实例，这台实例故障时服务中断',
        'recommendation': '后端池至少放 2 台实例并分布在不同可用区；确实只需要 1 台的，请说明原因'},
    '621dbc78-3745-4d32-8eac-9e65b27b7512': {
        'check': 'R3', 'severity': '中', 'type': 'Microsoft.Network/loadBalancers',
        'finding': '标准负载均衡的前端 IP 未跨可用区',
        'recommendation': '新建区域冗余的前端 IP 并切换（前端的可用区设置创建后不能修改）'},
    '5a44bd30-ae6a-4b81-9b68-dc3a8ffca4d8': {
        'check': 'R3', 'severity': '中', 'type': 'Microsoft.Cache/Redis',
        'finding': '旧版 Azure Cache for Redis 未开启区域冗余',
        'recommendation': '开启区域冗余，或与迁移到 Azure Managed Redis 一起规划'},
    'd37db635-157f-584d-9bce-4f6fc8c65ce5': {
        'check': 'R16', 'severity': '中', 'type': 'Microsoft.Network/virtualNetworkGateways',
        'finding': '专线网关只连接了同一对接点的线路，该对接点故障时专线全部中断',
        'recommendation': '增加来自不同对接点的专线线路，或配置 VPN 作为备用连接'},
    '3e115044-a3aa-433e-be01-ce17d67e50da': {
        'check': 'R16', 'severity': '低', 'type': 'Microsoft.Network/virtualNetworkGateways',
        'finding': '专线网关未设置客户控制的维护窗口',
        'recommendation': '设置在业务低峰的网关维护窗口'},
    'f8c2e6d9-4b3a-45d6-b9e2-8e7f3a1c2d04': {
        'check': 'R16', 'severity': '低', 'type': 'Microsoft.Network/virtualNetworkGateways',
        'finding': 'VPN 网关未设置客户控制的维护窗口',
        'recommendation': '设置在业务低峰的网关维护窗口'},
    'fbfef3df-04a5-41b2-a8fd-b8541eb04956': {
        'check': 'R17', 'severity': '中', 'type': 'Microsoft.EventHub/namespaces',
        'finding': 'Event Hubs 标准层未开启自动扩容，吞吐单元用满后会被限流',
        'recommendation': '开启自动扩容并设置上限，同时为吞吐量配置告警'},
    '847a8d88-21c4-bc48-a94e-562206edd767': {
        'check': 'R18', 'severity': '中', 'type': 'Microsoft.Network/applicationGateways',
        'finding': '应用网关未配置自定义健康探测，后端异常时可能继续转发请求',
        'recommendation': '为每个后端配置指向健康检查地址的自定义探测'},
    'eb005943-40a8-194b-9db2-474d430046b7': {
        'check': 'R19', 'severity': '中', 'type': 'Microsoft.ContainerRegistry/registries',
        'finding': '镜像仓库不是 Premium 层，不支持异地复制和区域冗余，限流也更低',
        'recommendation': '生产镜像仓库改为 Premium 层，并按需开启异地复制'},
    '63491f70-22e4-3b4a-8b0c-845450e46fac': {
        'check': 'R19', 'severity': '低', 'type': 'Microsoft.ContainerRegistry/registries',
        'finding': '镜像仓库未开启区域冗余',
        'recommendation': '改为 Premium 层后开启区域冗余'},
    'e7f0fd54-fba0-054e-9ab8-e676f2851f88': {
        'check': 'R19', 'severity': '低', 'type': 'Microsoft.ContainerRegistry/registries',
        'finding': '镜像仓库未开启软删除，误删的镜像无法恢复',
        'recommendation': '开启软删除并设置保留天数'},
    '902c82ff-4910-4b61-942d-0d6ef7f39b67': {
        'check': 'R20', 'severity': '中', 'type': 'Microsoft.ContainerService/managedClusters',
        'finding': 'AKS 集群有节点池未开启自动扩缩容，负载增加时不能自动加节点',
        'recommendation': '为业务节点池开启自动扩缩容，并按子网 IP 容量设置上限'},
    '005ccbbd-aeab-46ef-80bd-9bd4479412ec': {
        'check': 'R20', 'severity': '中', 'type': 'Microsoft.ContainerService/managedClusters',
        'finding': 'AKS 用户节点池的节点数（或自动扩缩容下限）少于 2 个，节点故障或升级时业务会中断',
        'recommendation': '生产用户节点池至少保持 2 个节点（跨可用区）'},
    '269a9f1a-6675-460a-831e-b05a887a8c4b': {
        'check': 'R20', 'severity': '低', 'type': 'Microsoft.ContainerService/managedClusters',
        'finding': 'AKS 集群没有配置备份，集群配置和持久卷误删后难以恢复',
        'recommendation': '为有状态工作负载的集群配置 AKS 备份，或确认已有其他备份方式'},
    '23b2dfc7-7e5d-9443-9f62-980ca621b561': {
        'check': 'O11', 'severity': '低', 'type': 'Microsoft.Network/routeTables',
        'finding': '路由表变更没有配置活动日志告警，路由被误改时无人知道',
        'recommendation': '为路由表的写入和删除操作配置活动日志告警，发送到值班组'},
    '41a22a5e-5e08-9647-92d0-2ffe9ef1bdad': {
        'check': 'S-N9', 'severity': '低', 'type': 'Microsoft.Compute/virtualMachines',
        'finding': '虚拟机网卡开启了 IP 转发（只有防火墙、路由器等网络设备需要）',
        'recommendation': '确认该机是否是网络设备；不是的关闭 IP 转发'},
    '3201dba8-d1da-4826-98a4-104066545170': {
        'check': 'R21', 'severity': '低', 'type': 'Microsoft.Compute/virtualMachines',
        'finding': '使用 B 系列（突发型）虚拟机，CPU 积分用完后性能会被限制，不适合持续高负载的业务',
        'recommendation': '持续高负载的业务改用 D 或 E 系列等通用规格'},
    'df0ff862-814d-45a3-95e4-4fad5a244ba6': {
        'check': 'R21', 'severity': '中', 'type': 'Microsoft.Compute/virtualMachines',
        'finding': '虚拟机使用标准硬盘，单台虚拟机的可用性 SLA 要求所有磁盘为高级 SSD 或更高',
        'recommendation': '关键单实例虚拟机的系统盘和数据盘改用高级 SSD'},
}

LOWER = {'高': '中', '中': '低', '低': '低'}
