"""S-I1 API Server access, S-I2 identity, S-I3 security features and patching for AKS clusters."""
from __future__ import annotations

import re

from .collect import safe_name
from .context import is_prod, is_test, parse_dt

RT = 'Microsoft.ContainerService/managedClusters'
NO_CHANGE = '本次未做任何更改。'


def node_image_date(version):
    m = re.search(r'-(\d{4})(\d{2})\.(\d{2})\.', version or '')
    if not m:
        return None
    return parse_dt(f'{m.group(1)}-{m.group(2)}-{m.group(3)}T00:00:00Z')


def _diag(detail):
    body = (detail.get('diagnosticSettings') or {}).get('body')
    http = (detail.get('diagnosticSettings') or {}).get('http')
    categories, destinations = set(), []
    for s in (body or {}).get('value', []):
        props = s.get('properties', {})
        destinations.append({k: bool(props.get(k)) for k in ('workspaceId', 'storageAccountId', 'eventHubAuthorizationRuleId')})
        for log in props.get('logs', []):
            if log.get('enabled'):
                categories.add(log.get('category') or log.get('categoryGroup'))
    audit = None if http != 200 else bool(categories & {'kube-audit', 'kube-audit-admin', 'allLogs', 'audit'})
    return body, http, categories, destinations, audit


def _support(ctx, sid, location, version):
    minor = '.'.join((version or '').split('.')[:2])
    kv = ((ctx.raw.load('aks/_kubernetesVersions.json') or {}).get(f'{sid}|{location}') or {}).get('body') or {}
    plans, latest = None, None
    for v in kv.get('values', []):
        if v.get('version') == minor:
            plans = (v.get('capabilities') or {}).get('supportPlan')
            patches = sorted((v.get('patchVersions') or {}).keys(), key=lambda x: [int(y) for y in x.split('.')])
            latest = patches[-1] if patches else None
    return kv, plans, latest


def _pools(ctx, pools):
    info, oldest = [], None
    for pl in pools:
        built = node_image_date(pl.get('nodeImageVersion'))
        age = (ctx.today - built).days if built else None
        sec = pl.get('securityProfile') or {}
        info.append({'name': pl.get('name'), 'mode': pl.get('mode'), 'osSKU': pl.get('osSKU'), 'count': pl.get('count'),
                     'nodeImageVersion': pl.get('nodeImageVersion'), 'nodeImageAgeDays': age, 'enableNodePublicIP': pl.get('enableNodePublicIP'),
                     'secureBoot': sec.get('enableSecureBoot'), 'vTPM': sec.get('enableVTPM'), 'sshAccess': sec.get('sshAccess'),
                     'encryptionAtHost': pl.get('enableEncryptionAtHost')})
        if age is not None and (oldest is None or age > oldest):
            oldest = age
    return info, oldest


def run(ctx):
    inventory = []
    maintenance = ctx.raw.load('aks/_maintenanceConfigurations.json') or {}
    for r in ctx.rows('aks'):
        detail = ctx.raw.load(f'aks/{safe_name(r["name"])}.json') or {}
        cluster = (detail.get('cluster') or {}).get('body') or {}
        if cluster:
            inventory.append(_cluster(ctx, r, detail, cluster, maintenance))
    ctx.inventory['aks'] = inventory
    ctx.notes['S-I1'].append(f'通过 Resource Graph 发现 {len(inventory)} 个 AKS 集群，逐个 ARM GET 刷新（api 2025-07-01）。')
    ctx.notes['S-I2'].append('与 S-I1 共用集群 GET 数据；未获取任何集群凭据，未执行 kubectl，集群内 RoleBinding 未检查。')
    ctx.notes['S-I3'].append('诊断设置、upgradeProfile、kubernetesVersions 均为 ARM GET；Defender 传感器状态取自 securityProfile.defender。')


def _cluster(ctx, r, detail, cl, maintenance):
    p, sid = cl.get('properties', {}), r['subscriptionId']
    e = ctx.env(ctx.name_of(sid), r['name'], r.get('tags'))
    ap, sp = p.get('apiServerAccessProfile') or {}, p.get('securityProfile') or {}
    # a non-dict value means the add-on block could not be read (e.g. redacted): unknown, not "off"
    addons = {k: bool(v.get('enabled')) if isinstance(v, dict) else None for k, v in (p.get('addonProfiles') or {}).items()}
    net, aup = p.get('networkProfile') or {}, p.get('autoUpgradeProfile') or {}
    diag_body, diag_http, categories, destinations, kube_audit = _diag(detail)
    version = p.get('currentKubernetesVersion') or p.get('kubernetesVersion')
    kv, plans, latest = _support(ctx, sid, r['location'], version)
    support_plan = p.get('supportPlan')
    std_support = (None if not kv else False) if plans is None else (support_plan in plans)
    pool_info, oldest = _pools(ctx, p.get('agentPoolProfiles') or [])
    ident = cl.get('identity') or {}
    inv = {'name': r['name'], 'subscription': ctx.name_of(sid), 'resourceGroup': r['resourceGroup'], 'location': r['location'],
           'environment': e, 'kubernetesVersion': version, 'latestPatchInMinor': latest, 'supportPlan': support_plan,
           'minorAvailablePlans': plans, 'inStandardSupport': std_support, 'privateCluster': bool(ap.get('enablePrivateCluster')),
           'authorizedIPRanges': ap.get('authorizedIPRanges'), 'privateClusterPublicFQDN': ap.get('enablePrivateClusterPublicFQDN'),
           'disableRunCommand': ap.get('disableRunCommand'), 'aadProfile': p.get('aadProfile'),
           'enableAzureRBAC': (p.get('aadProfile') or {}).get('enableAzureRBAC'), 'enableRBAC': p.get('enableRBAC'),
           'disableLocalAccounts': p.get('disableLocalAccounts'), 'oidcIssuer': (p.get('oidcIssuerProfile') or {}).get('enabled'),
           'workloadIdentity': (sp.get('workloadIdentity') or {}).get('enabled'), 'clusterIdentityType': ident.get('type'),
           'kubeletIdentity': 'UserAssigned' if (p.get('identityProfile') or {}).get('kubeletidentity') else None,
           'defenderProfile': bool(sp.get('defender')), 'imageCleaner': (sp.get('imageCleaner') or {}).get('enabled'),
           'azurePolicyAddon': addons.get('azurepolicy', False), 'keyVaultSecretsProvider': addons.get('azureKeyvaultSecretsProvider', False),
           'networkPlugin': net.get('networkPlugin'), 'networkPolicy': net.get('networkPolicy'), 'networkDataplane': net.get('networkDataplane'),
           'upgradeChannel': aup.get('upgradeChannel'), 'nodeOSUpgradeChannel': aup.get('nodeOSUpgradeChannel'),
           'oldestNodeImageAgeDays': oldest, 'pools': pool_info, 'diagnosticSettingsHttp': diag_http,
           'diagnosticDestinations': destinations, 'enabledLogCategories': sorted(x for x in categories if x), 'kubeAuditEnabled': kube_audit,
           'containersDefenderPlan': ctx.plan_tier(sid, 'Containers')}
    common = dict(sub=sid, rg=r['resourceGroup'], name=r['name'], rtype=RT, environment=e, rid=r['id'])
    local_on = p.get('disableLocalAccounts') is not True

    if not ap.get('enablePrivateCluster') and not ap.get('authorizedIPRanges'):
        sev = '高' if (is_prod(e) and local_on) else ('低' if is_test(e) else '中')
        local = '，同时本地账户（证书管理员凭据）未禁用' if local_on else ''
        ctx.add('S-I1', sev, finding=f'AKS 集群 {r["name"]} 的 API Server 对公网开放且未配置授权 IP 范围{local}，拿到 kubeconfig 的人可从任意互联网地址管理集群。',
                evidence={'enablePrivateCluster': ap.get('enablePrivateCluster'), 'authorizedIPRanges': ap.get('authorizedIPRanges'),
                          'disableLocalAccounts': p.get('disableLocalAccounts'), 'aadProfile': p.get('aadProfile')},
                recommendation='为 API Server 配置授权 IP 范围（仅放行办公出口、CI/CD 出口和跳板机 IP），或改为私有集群 / API Server VNet 集成；'
                               '同时按 S-I2 启用 Entra ID 集成并禁用本地账户。' + NO_CHANGE,
                confirm='确认需要访问 API Server 的来源 IP（办公出口、CI/CD、跳板机）。', key='api-server', **common)
    if not p.get('aadProfile') or local_on:
        ctx.add('S-I2', '低' if is_test(e) else '中',
                finding=f'AKS 集群 {r["name"]} 未启用 Microsoft Entra ID 集成和 Azure RBAC，且本地账户未禁用，集群访问只能依赖共享证书凭据，无法按人审计和及时吊销。',
                evidence={'aadProfile': p.get('aadProfile'), 'enableAzureRBAC': inv['enableAzureRBAC'], 'disableLocalAccounts': p.get('disableLocalAccounts'),
                          'enableRBAC(Kubernetes RBAC)': p.get('enableRBAC'), 'disableRunCommand': ap.get('disableRunCommand'),
                          'oidcIssuer': inv['oidcIssuer'], 'workloadIdentity': inv['workloadIdentity'],
                          'clusterIdentityType': ident.get('type'), 'kubeletIdentity': inv['kubeletIdentity']},
                recommendation='启用 AKS 托管 Entra ID 集成并指定管理员组，开启 Azure RBAC for Kubernetes 授权；确认所有使用者和流水线都已改用 Entra 登录后再禁用本地账户，'
                               '并轮换集群证书。' + NO_CHANGE,
                confirm='确认所有使用者和流水线能改用 Entra ID 登录后再禁用本地账户。', key='entra-id', **common)
    if net.get('networkPolicy') == 'azure':
        ctx.add('S-I3', '低' if is_test(e) else '中',
                finding=f'AKS 集群 {r["name"]} 使用 Azure 网络策略管理器（Azure NPM），Linux 版 Azure NPM 将于 2028-09-30 停止支持，且新订阅已无法再启用。',
                evidence={'networkPlugin': net.get('networkPlugin'), 'networkPolicy': 'azure', 'networkDataplane': net.get('networkDataplane')},
                recommendation='规划迁移到 Cilium（Azure CNI Powered by Cilium）或 Calico 网络策略；迁移前导出并验证现有 NetworkPolicy，先在测试集群演练。' + NO_CHANGE,
                key='network-policy-manager', **common)
    channel = aup.get('nodeOSUpgradeChannel')
    if channel in (None, 'None', 'Unmanaged') or (oldest is not None and oldest > 90):
        ctx.add('S-I3', '低' if is_test(e) else '中',
                finding=f'AKS 集群 {r["name"]} 的节点 OS 升级通道为 {channel}，最旧节点镜像已 {oldest} 天未更新，节点安全补丁可能长期未应用。',
                evidence={'nodeOSUpgradeChannel': channel, 'upgradeChannel': aup.get('upgradeChannel'), 'oldestNodeImageAgeDays': oldest,
                          'maintenanceConfigurations': [x.get('name') for x in (maintenance.get(r['id'].lower(), {}).get('value') or [])],
                          'pools': [{k: x[k] for k in ('name', 'nodeImageVersion', 'nodeImageAgeDays')} for x in pool_info]},
                recommendation='将节点 OS 升级通道设为 NodeImage（或 SecurityPatch）并配置计划维护窗口；对镜像超过 90 天的节点池先手动做一次节点镜像升级。'
                               '若通道已是 NodeImage 但镜像仍很旧，需检查维护窗口或升级是否失败。' + NO_CHANGE,
                confirm='升级通道已是 NodeImage 但镜像仍旧，请确认维护窗口设置或节点镜像升级是否失败。' if channel == 'NodeImage' else None,
                key='node-os-patching', **common)
    if std_support is False or (latest and version and version != latest):
        out_of_support = std_support is False
        sev = ('低' if is_test(e) else '中') if out_of_support else '低'
        if out_of_support:
            text = f'AKS 集群 {r["name"]} 运行 Kubernetes {version}，该小版本在本区域只剩 LTS 支持计划，而集群支持计划为 {support_plan}，已不在 AKS 标准支持范围内，不再获得安全补丁。'
            rec = '尽快将集群升级到受标准支持的小版本（逐个小版本升级，先测试集群），并将控制面自动升级通道设为 patch。'
        else:
            text = f'AKS 集群 {r["name"]} 运行 Kubernetes {version}，落后于同小版本最新补丁 {latest}，控制面自动升级通道为 {aup.get("upgradeChannel")}。'
            rec = '将控制面自动升级通道设为 patch 并配置维护窗口，使补丁版本自动跟进。'
        ctx.add('S-I3', sev, finding=text, recommendation=rec + NO_CHANGE, key='kubernetes-version',
                evidence={'kubernetesVersion': version, 'supportPlan': support_plan, 'minorAvailablePlans': plans, 'latestPatchInMinor': latest,
                          'upgradeChannel': aup.get('upgradeChannel')}, **common)
    gaps = []
    if not sp.get('defender'):
        gaps.append('未启用 Defender for Containers 传感器')
    if not addons.get('azurepolicy'):
        gaps.append('未启用 Azure Policy 加载项')
    if kube_audit is False:
        gaps.append('未导出 kube-audit / kube-audit-admin 审计日志')
    if not (sp.get('imageCleaner') or {}).get('enabled'):
        gaps.append('未启用 Image Cleaner')
    if gaps:
        sev = '低' if is_test(e) else ('中' if kube_audit is False else '低')
        ctx.add('S-I3', sev, finding=f'AKS 集群 {r["name"]} 安全监控与治理能力缺失：{"；".join(gaps)}。', key='security-monitoring',
                evidence={'defenderProfile': bool(sp.get('defender')), 'containersDefenderPlan': inv['containersDefenderPlan'],
                          'azurePolicyAddon': addons.get('azurepolicy', False), 'kubeAuditEnabled': kube_audit,
                          'diagnosticSettingsCount': len((diag_body or {}).get('value', [])) if diag_body is not None else None,
                          'imageCleaner': inv['imageCleaner'], 'keyVaultSecretsProvider': inv['keyVaultSecretsProvider']},
                recommendation='为集群添加诊断设置，至少将 kube-audit-admin 和 guard 日志发送到 Log Analytics（比完整 kube-audit 便宜）；'
                               '按需启用 Defender for Containers 和 Azure Policy 加载项（先审计模式）；启用 Image Cleaner 清理残留的有漏洞镜像。' + NO_CHANGE,
                **common)
    return inv
