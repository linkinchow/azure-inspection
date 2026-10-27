"""Peer comparison for storage accounts, Key Vault, container registries, AI accounts and Log Analytics workspaces."""
from __future__ import annotations

from .engine import TypeReport, std_root_cause
from .types_platform import SN, _vendor_confirm


def storage_type(ctx):
    T = TypeReport(ctx, 'storage', '存储账户')
    blob = {x['id'].lower(): x for x in ctx.load('reliability/storage/blobservices.json', []) or []}
    cap = {x['id'].lower(): x.get('lastUsedCapacityBytes') for x in ctx.load('reliability/storage/used-capacity.json', []) or []}
    excluded = []
    for r in ctx.rows(f'{SN}/arg/storage.json'):
        if str(r.get('resourceGroup') or '').lower().startswith('mc_'):
            excluded.append(r['name'])
            continue
        it = T.basic(r)
        p = r.get('properties') or {}
        acl = p.get('networkAcls') or {}
        b = (blob.get(r['id'].lower()) or {}).get('blobService') or {}
        bp = b.get('properties', b) if isinstance(b, dict) else {}
        it.update({'pna': p.get('publicNetworkAccess') or '未设置（默认开启）', 'def': acl.get('defaultAction'),
                   'ipRules': len(acl.get('ipRules') or []), 'vnetRules': len(acl.get('virtualNetworkRules') or []),
                   'pe': len(p.get('privateEndpointConnections') or []), 'blobPub': p.get('allowBlobPublicAccess'),
                   'shared': p.get('allowSharedKeyAccess'), 'tls': p.get('minimumTlsVersion'), 'sku': (r.get('sku') or {}).get('name'),
                   'soft': (bp.get('deleteRetentionPolicy') or {}).get('enabled'),
                   'created': (p.get('creationTime') or '')[:10] or it['created'],
                   'gib': round((cap.get(r['id'].lower()) or 0) / 2**30, 1),
                   'publicDist': bool(ctx.public_storage and ctx.public_storage.search(r['name'])),
                   'tfstate': 'tfstate' in r['name'].lower()})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}
    if excluded:
        T.population_note = f'不含 AKS 自动创建的 {len(excluded)} 个账户（{", ".join(excluded)}）'

    def net_dev(r):
        return not (r['pna'] == 'Disabled' or r['def'] == 'Deny')
    closed = [r['name'] for r in T.items if not net_dev(r)]
    n12 = sum(1 for r in T.items if r['tls'] == 'TLS1_2')
    T.baseline_rationale = (f'以已按推荐做法配置的账户为标准：关闭公网或默认拒绝 + 私有终结点（{len(closed)}/{n} 个）、TLS1_2（{n12}/{n}）、'
                            '开启 Blob 软删除、禁止匿名 Blob 访问。')

    def conf(r):
        if r['vendor']:
            return _vendor_confirm(r)
        if r['publicDist']:
            return '客户登记为对外分发用的公开账户，可能有意允许匿名下载；请确认其中没有敏感文件，并考虑改为通过 Front Door/CDN 分发'
        return None
    T.attr('network', '网络访问', '关闭公网或默认拒绝 + 私有终结点',
           lambda r: f'公网={r["pna"]}，默认动作={r["def"]}，IP/VNet 规则 {r["ipRules"]}/{r["vnetRules"]}，私有终结点 {r["pe"]} 个',
           net_dev, rec=lambda r: '先加私有终结点、切换内部访问后关闭公网' if r['pe'] == 0 else '已有私有终结点，确认内部访问走私网后把默认动作改为 Deny 或关闭公网',
           feas='原地修改（需维护窗口或应用配合）', short=lambda r: '至少把默认动作改为 Deny 并只放行确需的出口 IP' if not r['publicDist'] else None,
           confirm=conf, major=lambda r: not r['publicDist'] and not r['vendor'])
    T.attr('tls', '最低 TLS 版本', f'TLS1_2（{n12}/{n} 个账户）', lambda r: r['tls'], lambda r: r['tls'] != 'TLS1_2',
           rec='把最低 TLS 版本改为 1.2（Azure 存储已停止支持 TLS 1.0/1.1）', feas='原地修改', major=True)
    T.attr('softDelete', 'Blob 软删除', '开启', lambda r: '开启' if r['soft'] else '未开启', lambda r: not r['soft'],
           rec='开启 Blob 与容器软删除（建议 7~14 天）', feas='原地修改', confirm=conf)
    T.attr('blobPublic', '允许匿名 Blob 访问', '禁止（allowBlobPublicAccess=false）', lambda r: str(r['blobPub']),
           lambda r: r['blobPub'] is True and not r['publicDist'], rec='关闭账户级匿名访问开关（当前没有匿名容器的账户可直接关闭）',
           feas='原地修改', confirm=conf)

    def rc(r):
        notes = []
        if r['tls'] == 'TLS1_0':
            notes.append('最低 TLS 为 1.0，通常是旧版接口或迁移工具建账户时的默认值（门户新建默认是 TLS1.2）')
        if r['vendor']:
            notes.append(f'供应商 {r["vendor"]} 创建的账户')
        if r['tfstate']:
            notes.append('IaC 状态存储账户：状态文件中通常含有资源敏感信息，应优先收紧网络和共享密钥访问')
        if r['tf'] and net_dev(r):
            notes.append(f'按 {ctx.standard_name} 创建但仍对全网开放：存储账户模板没有统一设置网络规则')
        return std_root_cause(ctx, r, notes)
    T.run(rc)
    shared = sum(1 for r in T.items if r['shared'] is False)
    if shared * 2 < n:
        T.uniform_gaps.append({'attribute': '共享密钥访问', 'followedBy': shared, 'of': n,
                               'note': f'{n - shared}/{n} 个账户允许共享密钥访问，没有统一改为只用 Entra ID；建议先从 IaC 状态和备份账户开始关闭共享密钥。'})
    return T, {'network': '关闭公网/默认拒绝 + 私有终结点', 'tls': 'TLS1_2', 'softDelete': '开启', 'allowBlobPublicAccess': 'false'}


def kv_type(ctx):
    T = TypeReport(ctx, 'keyvault', 'Key Vault')
    for r in ctx.rows(f'{SN}/arg/keyvaults.json'):
        it = T.basic(r)
        p = r.get('properties') or {}
        it.update({'pna': p.get('publicNetworkAccess'), 'def': (p.get('networkAcls') or {}).get('defaultAction'),
                   'pe': len(p.get('privateEndpointConnections') or []), 'purge': bool(p.get('enablePurgeProtection')),
                   'rbac': p.get('enableRbacAuthorization')})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}
    purge = sum(r['purge'] for r in T.items)
    net = sum(1 for r in T.items if r['pna'] == 'Disabled' or r['def'] == 'Deny')
    if purge and purge < n:
        T.attr('purge', '清除保护', f'开启（{purge}/{n} 个）', lambda r: '开启' if r['purge'] else '未开启', lambda r: not r['purge'],
               rec='开启清除保护（开启后不能关闭）', feas='原地修改')
    if net and net < n:
        T.attr('network', '网络访问', f'私有终结点或默认拒绝（{net}/{n} 个）', lambda r: f'公网={r["pna"]}，默认动作={r["def"]}',
               lambda r: not (r['pna'] == 'Disabled' or r['def'] == 'Deny'), rec='加私有终结点或把默认动作改为拒绝（允许受信任的微软服务）',
               feas='原地修改（需维护窗口或应用配合）')
    T.baseline_rationale = ('有内部范例的项目以已配置的 Key Vault 为标准；全部一样的项目没有内部范例，按微软推荐（清除保护 + 私有终结点或防火墙）作为目标，'
                            '属于“全体一致的缺口”。')
    T.run(lambda r: std_root_cause(ctx, r))
    if purge == 0:
        T.uniform_gaps.append({'attribute': '清除保护', 'followedBy': 0, 'of': n, 'note': '全部未开启，可原地开启，但开启后不可关闭。'})
    if net == 0:
        T.uniform_gaps.append({'attribute': '网络访问', 'followedBy': 0, 'of': n,
                               'note': '全部对全网开放；存放 Front Door 证书的需允许 Front Door 访问（开启“允许受信任的 Microsoft 服务”后可设默认拒绝）。'})
    return T, {'purgeProtection': '开启', 'network': '私有终结点或默认拒绝'}


def acr_type(ctx):
    T = TypeReport(ctx, 'acr', '容器镜像仓库（ACR）')
    for r in ctx.rows(f'{SN}/arg/registries.json'):
        it = T.basic(r)
        p = r.get('properties') or {}
        it.update({'sku': (r.get('sku') or {}).get('name'), 'admin': p.get('adminUserEnabled'), 'pna': p.get('publicNetworkAccess'),
                   'created': (p.get('creationDate') or '')[:10] or it['created']})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}
    off = sum(1 for r in T.items if not r['admin'])
    T.baseline_rationale = f'{off}/{n} 个仓库关闭了管理员账号，AKS 通过托管身份拉取镜像；以此为标准。'
    T.attr('admin', '管理员账号', f'关闭（{off}/{n}）', lambda r: '开启' if r['admin'] else '关闭', lambda r: bool(r['admin']),
           rec='改用 AKS 托管身份或 Entra 令牌推送与拉取镜像后关闭管理员账号', feas='原地修改（需维护窗口或应用配合）',
           confirm='请确认 CI/CD 是否仍在用管理员用户名密码推送', major=True)
    T.run(lambda r: std_root_cause(ctx, r))
    closed = sum(1 for r in T.items if r['pna'] == 'Disabled')
    if closed == 0:
        T.uniform_gaps.append({'attribute': '网络访问', 'followedBy': 0, 'of': n,
                               'note': f'{n} 个仓库都对全网开放；Basic/Standard 不支持私有终结点，私网化需先升级到 Premium（原地升级）。'})
    return T, {'adminUser': '关闭'}


def ai_type(ctx):
    T = TypeReport(ctx, 'ai', 'AI Foundry / OpenAI / 认知服务账户')
    for r in ctx.rows(f'{SN}/arg/cognitive.json'):
        it = T.basic(r)
        p = r.get('properties') or {}
        it.update({'pna': p.get('publicNetworkAccess'), 'def': (p.get('networkAcls') or {}).get('defaultAction'),
                   'local': not p.get('disableLocalAuth'), 'kind': r.get('kind')})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}
    keyless = sum(1 for r in T.items if not r['local'])
    net = sum(1 for r in T.items if r['pna'] == 'Disabled' or r['def'] == 'Deny')
    if keyless and keyless < n:
        T.attr('localAuth', 'API 密钥认证', f'禁用（{keyless}/{n} 个）', lambda r: '允许' if r['local'] else '禁用', lambda r: r['local'],
               rec='调用方改用 Entra ID 令牌后设置 disableLocalAuth=true', feas='原地修改（需维护窗口或应用配合）')
    T.baseline_rationale = '按微软推荐（禁用本地密钥认证，改用 Entra ID；按需加网络限制）作为目标；全部一样的项目属于全体一致的缺口。'
    T.run(lambda r: std_root_cause(ctx, r))
    if keyless == 0:
        T.uniform_gaps.append({'attribute': 'API 密钥认证', 'followedBy': 0, 'of': n,
                               'note': '全部允许 API 密钥；可原地设置 disableLocalAuth=true，前提是调用方改用 Entra ID 令牌。'})
    if net == 0:
        T.uniform_gaps.append({'attribute': '网络访问', 'followedBy': 0, 'of': n, 'note': '全部对全网开放。'})
    return T, {'disableLocalAuth': 'true', 'network': '受限'}


def la_type(ctx):
    T = TypeReport(ctx, 'loganalytics', 'Log Analytics 工作区')
    ret = {x['id'].lower(): x.get('retention') for x in ctx.rows('performance/arg/workspaces.json')}
    for r in ctx.rows(f'{SN}/arg/loganalytics.json'):
        it = T.basic(r)
        it.update({'retention': ret.get(r['id'].lower()), 'cap': ((r.get('properties') or {}).get('workspaceCapping') or {}).get('dailyQuotaGb')})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}
    retentions = sorted({r['retention'] for r in T.items if r['retention'] is not None})
    T.baseline_rationale = (f'{n} 个工作区的保留期为 ' + '、'.join(f'{x} 天' for x in retentions) + '；'
                            + ('配置一致，没有偏差，' if len(retentions) <= 1 else '') + '主要问题在于工作区是否分散。')
    T.run(lambda r: std_root_cause(ctx, r))
    capped = sum(1 for r in T.items if r['cap'] not in (None, -1, -1.0))
    T.uniform_gaps.append({'attribute': '每日数据上限/数据量告警', 'followedBy': capped, 'of': n,
                           'note': f'{n - capped}/{n} 个工作区没有设置每日上限。'})
    auto = [r['name'] for r in T.items if r['name'].startswith('DefaultWorkspace-')]
    if auto:
        T.insights.append(f'{len(auto)} 个 DefaultWorkspace-* 工作区由门户在启用监控时自动创建，不是规划出来的工作区；建议按业务线或区域收敛到少数几个工作区。')
    return T, {'retentionInDays': retentions[0] if len(retentions) == 1 else '、'.join(map(str, retentions))}
