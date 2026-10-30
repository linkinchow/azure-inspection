"""S-I7 audit logs, S-I8 VM baseline and patching, S-I9 Key Vault, S-I10 container registries and AI service authentication."""
from __future__ import annotations

from collections import defaultdict

from ...core import appliance
from ..common import mixed_env
from ..pipeline import SSH_PENDING
from .context import is_prod, is_test, member, subscription_members

NO_CHANGE = '本次未做任何更改。'
VM_TYPE = 'Microsoft.Compute/virtualMachines'
KV_TYPE = 'Microsoft.KeyVault/vaults'
ACR_TYPE = 'Microsoft.ContainerRegistry/registries'
AI_TYPE = 'Microsoft.CognitiveServices/accounts'


def _many(n):
    return f'多个订阅（{n} 个）'


def _vm_members(items):
    return [member(x['name'], VM_TYPE, x['subscription']) for x in items]


# ---------------------------------------------------------------------------------------------- S-I7
def audit(ctx):
    no_export, exports = [], []
    for s in ctx.enabled:
        c = ctx.subcalls[s['id']].get('activityLogDiag') or {}
        values = (c.get('body') or {}).get('value', []) if c.get('http') == 200 else None
        exports.append({'subscription': s['name'], 'http': c.get('http'), 'exported': (len(values) > 0) if values is not None else None})
        if values is not None and not values:
            no_export.append(s['name'])
    if no_export:
        envs = [ctx.sub_env(x) for x in no_export]
        ctx.add('S-I7', '中', _many(len(no_export)), None, None, 'Microsoft.Insights/diagnosticSettings', mixed_env(envs),
                finding=f'{len(no_export)} 个已启用订阅（含 {sum(is_prod(e) for e in envs)} 个生产订阅）都没有把活动日志导出到 Log Analytics、存储或事件中心，'
                        '平台只保留 90 天，超过后无法追溯谁在何时修改或删除了资源。',
                evidence={'subscriptionsWithoutExport': no_export},
                recommendation='用 Azure Policy（“Configure Azure Activity logs to stream to specified Log Analytics workspace”）在根管理组统一导出活动日志到'
                               '中心 Log Analytics 工作区，并按合规要求设置保留期（如 365 天或归档到存储）。' + NO_CHANGE,
                key='activity-log-export', members=subscription_members(no_export))
    vaults = ctx.rows('keyvaults')
    diag = ctx.raw.load('keyvault/diagnosticSettings.json') or {}
    no_audit = []
    for r in vaults:
        d = diag.get(r['id'].lower()) or {}
        if d.get('http') != 200:
            continue
        ok = any(log.get('enabled') and (log.get('category') == 'AuditEvent' or log.get('categoryGroup') in ('audit', 'allLogs'))
                 for s in (d.get('body') or {}).get('value', []) for log in s.get('properties', {}).get('logs', []))
        if not ok:
            no_audit.append({'name': r['name'], 'subscription': ctx.name_of(r['subscriptionId'])})
    if no_audit:
        ctx.add('S-I7', '低', '多个订阅', None, f'{len(no_audit)} 个 Key Vault', KV_TYPE, None,
                finding=f'{len(no_audit)} 个 Key Vault（共 {len(vaults)} 个）没有配置诊断设置，AuditEvent 审计日志未导出，无法追溯谁读取了机密或证书。',
                evidence={'vaults': no_audit},
                recommendation='为每个 Key Vault 启用诊断设置，把 audit 类别日志发送到中心 Log Analytics 工作区。' + NO_CHANGE,
                key='keyvault-audit', members=[member(x['name'], KV_TYPE, x['subscription']) for x in no_audit])
    flow, vnets, nsgs = ctx.rows('flowlogs'), ctx.rows('vnets'), ctx.rows('nsgs')
    if not flow:
        ctx.add('S-I7', '低', '多个订阅', None, None, 'Microsoft.Network/networkWatchers/flowLogs', None,
                finding=f'已启用订阅中共有 {len(vnets)} 个虚拟网络和 {len(nsgs)} 个 NSG，均未配置 NSG/VNet 流日志，发生入侵时无法回溯网络连接记录。',
                evidence={'vnets': len(vnets), 'nsgs': len(nsgs), 'flowLogs': 0},
                recommendation='至少为生产 VNet 启用 VNet 流日志（NSG 流日志将于 2027-09-30 退役，新建请直接用 VNet 流日志），存储保留 30-90 天，按需开启流量分析。' + NO_CHANGE,
                key='flow-logs', members=[member(v['name'], 'Microsoft.Network/virtualNetworks', ctx.name_of(v['subscriptionId'])) for v in vnets])
    workspaces = ctx.rows('workspaces')
    ctx.inventory.update(activityLogExport=exports, flowLogs=len(flow),
                         logAnalyticsWorkspaces=[{'name': w['name'], 'retentionInDays': w.get('retentionInDays')} for w in workspaces])
    retention = sorted({w.get('retentionInDays') for w in workspaces if w.get('retentionInDays') is not None})
    ctx.notes['S-I7'].append(f'Log Analytics 工作区保留期来自 Resource Graph（{len(workspaces)} 个工作区，保留期取值 {retention} 天）。')


# ---------------------------------------------------------------------------------------------- S-I8
def _vm_item(ctx, v, has_pip, extensions, instance):
    sid, sp = v['subscriptionId'], v.get('securityProfile') or {}
    summary = (instance.get('patchStatus') or {}).get('availablePatchSummary') or {}
    patch = v.get('linuxPatchSettings') or v.get('windowsPatchSettings') or {}
    uefi = sp.get('uefiSettings') or {}
    return {'name': v['name'], 'subscription': ctx.name_of(sid), 'subscriptionId': sid, 'resourceGroup': v['resourceGroup'], 'osType': v['osType'],
            'powerState': v.get('powerState'), 'environment': ctx.env(ctx.name_of(sid), v['name'], v.get('tags')),
            'disablePasswordAuthentication': v.get('disablePasswordAuthentication'), 'publicIpAttached': has_pip,
            'securityType': sp.get('securityType'), 'secureBoot': uefi.get('secureBootEnabled'), 'vTPM': uefi.get('vTpmEnabled'),
            'encryptionAtHost': sp.get('encryptionAtHost'), 'patchMode': patch.get('patchMode'), 'assessmentMode': patch.get('assessmentMode'),
            'lastPatchAssessment': summary.get('lastModifiedTime'), 'criticalAndSecurityPatchCount': summary.get('criticalAndSecurityPatchCount'),
            'otherPatchCount': summary.get('otherPatchCount'), 'identityType': (v.get('identity') or {}).get('type'),
            'amaInstalled': any('AzureMonitor' in x for x in extensions), 'mdeInstalled': any('MDE' in x or 'Defender' in x for x in extensions),
            'aadSshLogin': any('AADSSHLogin' in x for x in extensions), 'vmAccessExtension': any('VMAccess' in x for x in extensions),
            '_patchSummary': bool(summary)}


def vms(ctx):
    ips = {p['id']: p for p in ctx.rows('public_ips')}
    vm_pip = defaultdict(list)
    for n in ctx.rows('vm_nics'):
        if n.get('vmId') and n.get('publicIpId'):
            vm_pip[n['vmId']].append(bool((ips.get(n['publicIpId'].lower()) or {}).get('ip')))
    vm_ext = defaultdict(list)
    for x in ctx.rows('vm_extensions'):
        vm_ext[x['id'].lower().split('/extensions/')[0]].append(f'{x["publisher"]}/{x["extType"]}')
    views = ctx.raw.load('vm/instanceView_patchStatus.json') or {}
    inventory = []
    pw_pub, pw_priv, unknown, no_patch, pending, devices = (defaultdict(list) for _ in range(6))
    names = ctx.cfg.appliance_names() if getattr(ctx, 'cfg', None) else None
    rel = ctx.raw.other('reliability')
    known = appliance.index(((rel.load('arg/vms.json') or {}).get('rows') or []), names)
    for v in ctx.rows('vms'):
        if v['resourceGroup'].lower().startswith('mc_'):
            continue
        vid, sid = v['id'].lower(), v['subscriptionId']
        item = _vm_item(ctx, v, any(vm_pip.get(vid, [])), vm_ext.get(vid, []), views.get(vid) or {})
        item['appliance'] = known.get(vid) or appliance.of(v, names)
        inventory.append(item)
        if item['appliance'] and v.get('disablePasswordAuthentication') is not True:
            devices[sid].append(item)     # appliance administrators log in with passwords: access to the management port matters
        elif v['osType'] == 'Linux':
            if v.get('disablePasswordAuthentication') is False:
                (pw_pub if item['publicIpAttached'] else pw_priv)[sid].append(item)
            elif v.get('disablePasswordAuthentication') is None:
                unknown[sid].append(item)
        if not item['_patchSummary']:
            no_patch[sid].append(item)
        elif (item['criticalAndSecurityPatchCount'] or 0) > 0:
            pending[sid].append(item)
    _password_findings(ctx, pw_pub, pw_priv, unknown)
    _appliance_findings(ctx, devices)
    _patch_findings(ctx, no_patch, pending)
    if inventory:
        not_trusted = [x for x in inventory if x['securityType'] != 'TrustedLaunch']
        no_eah = [x for x in inventory if not x['encryptionAtHost']]
        ctx.add('S-I8', '低', '多个订阅', None, f'{len(inventory)} 台虚拟机', VM_TYPE, mixed_env([x['environment'] for x in inventory]),
                finding=f'{len(inventory)} 台非 AKS 虚拟机中 {len(not_trusted)} 台未使用受信任启动（安全启动/vTPM），{len(no_eah)} 台未启用主机加密；'
                        f'只有 {sum(x["amaInstalled"] for x in inventory)} 台装了 Azure Monitor 代理，{sum(x["mdeInstalled"] for x in inventory)} 台有 Defender for Endpoint 扩展。',
                evidence={'nonTrustedLaunch': len(not_trusted), 'noEncryptionAtHost': len(no_eah), 'ama': sum(x['amaInstalled'] for x in inventory),
                          'mde': sum(x['mdeInstalled'] for x in inventory), 'withManagedIdentity': sum(1 for x in inventory if x['identityType']),
                          'withVMAccessExtension': sum(x['vmAccessExtension'] for x in inventory)},
                recommendation='新建虚拟机默认使用受信任启动并启用主机加密，现有虚拟机在重建时迁移；启用 Defender for Servers 后会自动部署 MDE。' + NO_CHANGE,
                key='vm-security-baseline', members=_vm_members(inventory))
    for x in inventory:
        x.pop('_patchSummary', None)
    ctx.inventory['vms'] = inventory
    assessed = len(ctx.rows('patch_assessment'))
    ctx.notes['S-I8'].append(f'Resource Graph patchassessmentresources 返回 {assessed} 行；补丁状态以逐台 instanceView 的 patchStatus 为准，'
                             f'{sum(len(v) for v in no_patch.values())} 台没有任何补丁评估记录。AKS 节点（MC_ 资源组）已排除。')


def _appliance_findings(ctx, devices):
    for sid, items in devices.items():
        e = ctx.sub_env(ctx.name_of(sid))
        public = [x for x in items if x['publicIpAttached']]
        running = [x for x in public if (x['powerState'] or '').endswith('running')]
        sev = '高' if (is_prod(e) and running) else ('中' if public else '低')
        shown = '、'.join(x['name'] for x in items[:5]) + (f' 等 {len(items)} 台' if len(items) > 5 else '')
        ctx.add('S-I8', sev, sid, None, f'{len(items)} 台网络设备', VM_TYPE, e,
                finding=f'订阅 {ctx.name_of(sid)} 有 {len(items)} 台网络设备（{shown}）允许管理员用密码登录'
                        + (f'，其中 {len(public)} 台绑定了公网 IP' if public else '')
                        + '。网络设备的管理员通常使用密码，关闭密码登录不适用，重点是限制管理口的访问'
                        + (SSH_PENDING if public else '。'),
                evidence={'vms': [{k: x[k] for k in ('name', 'resourceGroup', 'powerState', 'publicIpAttached', 'appliance')} for x in items]},
                recommendation='管理口（SSH、HTTPS）只允许受信地址访问、不对公网开放（用 NSG 或设备自身的可信主机设置），管理员账号启用多因素认证并定期更换密码；'
                               '按厂商建议及时升级设备系统。' + NO_CHANGE,
                key='appliance-admin-login', members=_vm_members(items))


def _password_findings(ctx, pw_pub, pw_priv, unknown):
    for sid, items in pw_pub.items():
        e = ctx.sub_env(ctx.name_of(sid))
        running = [x for x in items if (x['powerState'] or '').endswith('running')]
        sev = '高' if (is_prod(e) and running) else ('中' if running and not is_test(e) else '低')
        ctx.add('S-I8', sev, sid, None, f'{len(items)} 台虚拟机', VM_TYPE, e,
                finding=f'订阅 {ctx.name_of(sid)} 有 {len(items)} 台 Linux 虚拟机允许 SSH 密码登录且绑定了公网 IP（其中 {len(running)} 台在运行），有被暴力破解的风险'
                        '（NSG 是否放行 22 端口以网络检查结果为准）。',
                evidence={'vms': [{k: x[k] for k in ('name', 'resourceGroup', 'powerState', 'securityType', 'aadSshLogin')} for x in items]},
                recommendation='在这些虚拟机上关闭密码认证，只允许 SSH 密钥或 Entra ID 登录（AADSSHLoginForLinux），并用 Azure Bastion / JIT 访问替代公网 22 端口；'
                               '可用 Azure Policy 审计“Linux 计算机应仅使用 SSH 密钥”。' + NO_CHANGE,
                confirm='确认这些虚拟机是否仍需要密码登录。', key='ssh-password-public', members=_vm_members(items))
    for sid, items in pw_priv.items():
        ctx.add('S-I8', '低', sid, None, f'{len(items)} 台虚拟机', VM_TYPE, ctx.sub_env(ctx.name_of(sid)),
                finding=f'订阅 {ctx.name_of(sid)} 有 {len(items)} 台 Linux 虚拟机允许 SSH 密码登录（未绑定公网 IP）。',
                evidence={'vms': [{k: x[k] for k in ('name', 'resourceGroup', 'powerState')} for x in items]},
                recommendation='关闭密码认证，只使用 SSH 密钥或 Entra ID 登录。' + NO_CHANGE,
                key='ssh-password-private', members=_vm_members(items))
    if unknown:
        items = [x for v in unknown.values() for x in v]
        ctx.add('S-I8', '低', _many(len(unknown)), None, f'{len(items)} 台虚拟机', VM_TYPE, mixed_env([x['environment'] for x in items]),
                finding=f'{len(items)} 台 Linux 虚拟机在管理面没有 osProfile（通常由已有磁盘创建或迁移而来），无法从 Azure 判断是否允许密码登录，'
                        f'其中 {sum(x["publicIpAttached"] for x in items)} 台绑定了公网 IP。',
                evidence={'bySubscription': {ctx.name_of(k): [x['name'] for x in v] for k, v in unknown.items()}},
                recommendation='登录这些虚拟机检查 sshd_config 中的 PasswordAuthentication 设置，或用 Azure Policy 来宾配置审计。' + NO_CHANGE,
                confirm='登录这些虚拟机检查 PasswordAuthentication 设置。', key='ssh-auth-unknown', members=_vm_members(items))


def _patch_findings(ctx, no_patch, pending):
    if no_patch:
        items = [x for v in no_patch.values() for x in v]
        prod_count = sum(len(v) for k, v in no_patch.items() if is_prod(ctx.sub_env(ctx.name_of(k))))
        ctx.add('S-I8', '中', _many(len(no_patch)), None, f'{len(items)} 台虚拟机', VM_TYPE, mixed_env([x['environment'] for x in items]),
                finding=f'{len(items)} 台非 AKS 虚拟机（其中 {prod_count} 台在生产订阅）都没有 Azure Update Manager 补丁评估记录，补丁模式为镜像默认，'
                        '无法知道缺多少关键/安全更新。',
                evidence={'bySubscription': {ctx.name_of(k): len(v) for k, v in no_patch.items()},
                          'patchModes': sorted({f'{x["patchMode"]}/{x["assessmentMode"]}' for x in items}),
                          'defenderRecommendationUnhealthy': 'Machines should be configured to periodically check for missing system updates'},
                recommendation='通过 Azure Policy 为虚拟机开启定期评估（assessmentMode=AutomaticByPlatform，评估本身免费），再用 Update Manager 维护配置分批安装关键和安全更新。' + NO_CHANGE,
                key='patch-assessment-missing', members=_vm_members(items))
    for sid, items in pending.items():
        ctx.add('S-I8', '中', sid, None, f'{len(items)} 台虚拟机', VM_TYPE, ctx.sub_env(ctx.name_of(sid)),
                finding=f'订阅 {ctx.name_of(sid)} 有 {len(items)} 台虚拟机存在待安装的关键/安全更新。',
                evidence={'vms': [{k: x[k] for k in ('name', 'criticalAndSecurityPatchCount', 'lastPatchAssessment')} for x in items]},
                recommendation='用 Update Manager 尽快安装关键和安全更新。' + NO_CHANGE,
                key='pending-patches', members=_vm_members(items))


# ---------------------------------------------------------------------------------------------- S-I9
def keyvaults(ctx):
    inventory, unjudged = [], []
    for r in ctx.rows('keyvaults'):
        policies = r.get('accessPolicies') or []
        full = unknown = 0
        for a in policies:
            perms = a.get('permissions') or {}
            secrets, keys = perms.get('secrets') or [], perms.get('keys') or []
            # Raw files saved before 0.6.5 may hold a redaction marker instead of the permission list: not judged, never "no full access".
            if not isinstance(secrets, list) or not isinstance(keys, list):
                unknown += 1
            elif any(x.lower() == 'all' for x in secrets + keys) or len(secrets) >= 7:
                full += 1
        if unknown:
            unjudged.append(r['name'])
        sid = r['subscriptionId']
        e = ctx.env(ctx.name_of(sid), r['name'], r.get('tags'))
        item = {'name': r['name'], 'subscription': ctx.name_of(sid), 'environment': e, 'softDelete': r.get('enableSoftDelete'),
                'softDeleteRetentionDays': r.get('softDeleteRetentionInDays'), 'purgeProtection': r.get('enablePurgeProtection'),
                'rbacAuthorization': r.get('enableRbacAuthorization'), 'accessPolicyCount': len(policies),
                'fullSecretKeyPolicies': None if unknown else full, 'unjudgedAccessPolicies': unknown,
                'publicNetworkAccess': r.get('publicNetworkAccess'), 'networkAclsDefaultAction': r.get('networkAclsDefault') or None}
        inventory.append(item)
        common = dict(sub=sid, rg=r['resourceGroup'], name=r['name'], rtype=KV_TYPE, environment=e, rid=r['id'])
        if not r.get('enablePurgeProtection'):
            ctx.add('S-I9', '中' if is_prod(e) else '低',
                    finding=f'Key Vault {r["name"]} 未启用清除保护，有权限的账户可在软删除后立即永久清除密钥库及其中的机密/证书。',
                    evidence={k: item[k] for k in ('softDelete', 'softDeleteRetentionDays', 'purgeProtection', 'rbacAuthorization',
                                                   'accessPolicyCount', 'publicNetworkAccess', 'networkAclsDefaultAction')},
                    recommendation='启用清除保护（启用后不可关闭，先确认没有需要立即清除并重建同名密钥库的自动化流程）。' + NO_CHANGE,
                    confirm=None if is_prod(e) else '确认该 Key Vault 是否为生产环境。', key='purge-protection', **common)
        if r.get('enableSoftDelete') is False or (not r.get('enableRbacAuthorization') and full):
            ctx.add('S-I9', '中', finding=f'Key Vault {r["name"]} 使用访问策略模式且有 {full} 条完全密钥/机密权限策略（或未启用软删除）。', evidence=item,
                    recommendation='迁移到 Azure RBAC 授权模型，按最小权限授予 Key Vault Secrets User 等角色。' + NO_CHANGE, key='access-policy', **common)
    ctx.inventory['keyVaults'] = inventory
    ctx.notes['S-I9'].append('仅管理面属性，未访问 Key Vault 数据面；访问策略只统计数量和权限范围。')
    if unjudged:
        ctx.notes['S-I9'].append(f"{len(unjudged)} 个 Key Vault 的访问策略权限在保存的数据中已被脱敏，是否授予完全权限无法判断：{'、'.join(unjudged)}。")


# ---------------------------------------------------------------------------------------------- S-I10
def registries_and_ai(ctx):
    inventory = []
    for r in ctx.rows('acr'):
        sid = r['subscriptionId']
        e = ctx.env(ctx.name_of(sid), r['name'], r.get('tags'))
        item = {'name': r['name'], 'subscription': ctx.name_of(sid), 'sku': r.get('sku'), 'environment': e,
                'adminUserEnabled': r.get('adminUserEnabled'), 'anonymousPullEnabled': r.get('anonymousPullEnabled'),
                'publicNetworkAccess': r.get('publicNetworkAccess'), 'retentionPolicy': (r.get('retentionPolicy') or {}).get('status'),
                'retentionNote': '保留策略仅 Premium SKU 支持' if r.get('sku') != 'Premium' else None,
                'containersDefenderPlan': ctx.plan_tier(sid, 'Containers')}
        inventory.append(item)
        common = dict(sub=sid, rg=r['resourceGroup'], name=r['name'], rtype=ACR_TYPE, environment=e, rid=r['id'])
        if r.get('adminUserEnabled'):
            public = '，且允许公网访问' if str(r.get('publicNetworkAccess') or '').lower() != 'disabled' else ''
            ctx.add('S-I10', '低' if is_test(e) else '中',
                    finding=f'容器镜像仓库 {r["name"]} 启用了管理员用户（共享用户名+密码，拥有推送和拉取全部权限）{public}。',
                    evidence={k: item[k] for k in ('sku', 'adminUserEnabled', 'anonymousPullEnabled', 'publicNetworkAccess', 'containersDefenderPlan')},
                    recommendation='确认没有流水线或集群依赖管理员密码后禁用管理员用户；AKS 用 kubelet 托管身份授予 AcrPull，CI/CD 用服务主体/工作负载身份授予 AcrPush。' + NO_CHANGE,
                    confirm='确认是否有流水线或集群依赖管理员密码。', key='admin-user', **common)
        if r.get('anonymousPullEnabled'):
            ctx.add('S-I10', '中', finding=f'容器镜像仓库 {r["name"]} 允许匿名拉取。', evidence=item, recommendation='关闭匿名拉取。' + NO_CHANGE,
                    confirm='确认是否确实需要匿名拉取。', key='anonymous-pull', **common)
    no_scan = [x for x in inventory if x['containersDefenderPlan'] != 'Standard']
    if no_scan:
        ctx.add('S-I10', '低', '多个订阅', None, f'{len(no_scan)} 个镜像仓库', ACR_TYPE, mixed_env([x['environment'] for x in no_scan]),
                finding=f'{len(no_scan)} 个容器镜像仓库所在订阅都未启用 Defender for Containers，镜像没有漏洞扫描。',
                evidence={'registries': [{k: x[k] for k in ('name', 'subscription', 'sku', 'containersDefenderPlan')} for x in no_scan]},
                recommendation='在承载生产镜像仓库的订阅启用 Defender for Containers（含无代理镜像漏洞扫描），或接入其他镜像扫描工具。' + NO_CHANGE,
                key='registry-scanning', members=[member(x['name'], ACR_TYPE, x['subscription']) for x in no_scan])
    accounts = ctx.rows('cognitive')
    by_sub, local = {}, []
    for r in accounts:
        name = ctx.name_of(r['subscriptionId'])
        entry = by_sub.setdefault(name, {'accounts': 0, 'localAuthEnabled': 0, 'kinds': {}})
        entry['accounts'] += 1
        entry['kinds'][r.get('kind')] = entry['kinds'].get(r.get('kind'), 0) + 1
        if r.get('disableLocalAuth') is not True:
            entry['localAuthEnabled'] += 1
            local.append(r)
    if local:
        ctx.add('S-I10', '中', _many(len(by_sub)), None, f'{len(local)} 个 AI 服务账户', AI_TYPE,
                mixed_env([ctx.env(ctx.name_of(r['subscriptionId']), r['name'], r.get('tags')) for r in local]),
                finding=f'{len(accounts)} 个 AI / OpenAI / Foundry 账户中有 {len(local)} 个仍允许 API 密钥认证（disableLocalAuth 未设为 true），'
                        '密钥一旦泄露即可被直接调用并产生费用，且调用无法追溯到具体身份。',
                evidence={'bySubscription': by_sub},
                recommendation='排查应用是否仍在用 API 密钥；改用托管身份/Entra ID（Cognitive Services OpenAI User 等角色）后设置 disableLocalAuth=true，'
                               '过渡期定期轮换密钥并存入 Key Vault。' + NO_CHANGE,
                confirm='确认应用是否仍在使用 API 密钥。', key='ai-local-auth',
                members=[member(r['name'], AI_TYPE, ctx.name_of(r['subscriptionId'])) for r in local])
    ctx.inventory.update(containerRegistries=inventory, cognitiveAccounts=by_sub)
    ctx.notes['S-I10'].append('镜像漏洞扫描以所在订阅的 Containers 计划判断；网络暴露由网络检查负责。')
