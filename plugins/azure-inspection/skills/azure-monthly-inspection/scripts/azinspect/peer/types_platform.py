"""Peer comparison for AKS, MySQL, PostgreSQL, Redis and MongoDB (vCore). Baselines come from the customer's own resources."""
from __future__ import annotations

import ipaddress
import re
from collections import Counter

from .engine import TypeReport, most_common, std_root_cause

SN = 'security_network/raw'


def _vendor_confirm(r):
    if r.get('vendor'):
        return (f'该资源由供应商 {r["vendor"]} 创建和管理，修改前请先与供应商确认其模板是否支持，'
                '避免被供应商的自动化改回或失去支持')
    return None


def _minor(version):
    m = re.match(r'(\d+)\.(\d+)', str(version or ''))
    return (int(m.group(1)), int(m.group(2))) if m else None


# ---------------------------------------------------------------------------------------------- AKS

def _node_vmss(ctx):
    """Cluster name -> {pool name: VMSS capacity}, from the reliability pillar's node VMSS reads."""
    out = {}
    for entry in ctx.load('reliability/aks/clusters.json', []) or []:
        name = (entry.get('cluster') or {}).get('name')
        items = ((entry.get('nodeVmss') or {}).get('items') or []) if isinstance(entry.get('nodeVmss'), dict) else []
        pools = {}
        for v in items:
            pool = (v.get('tags') or {}).get('aks-managed-poolName')
            if pool:
                pools[pool] = pools.get(pool, 0) + int((v.get('sku') or {}).get('capacity') or 0)
        if name:
            out[name] = pools
    return out


def _free_pod_subnet(vnet):
    """An empty subnet in the node VNet whose name says it is meant for pods (reserved but unused)."""
    for s in ((vnet or {}).get('properties') or {}).get('subnets') or []:
        sp = s.get('properties') or {}
        if 'pod' in s['name'].lower() and not sp.get('ipConfigurations'):
            return f'{s["name"]}（{sp.get("addressPrefix") or (sp.get("addressPrefixes") or [""])[0]}）'
    return None


def aks_type(ctx):
    T = TypeReport(ctx, 'aks', 'AKS 集群')
    vnets = {v['id'].lower(): v for v in ctx.rows(f'{SN}/arg/vnets.json')}
    capacity = _node_vmss(ctx)
    folder = ctx.raw / 'security_identity' / 'aks'
    for f in sorted(folder.glob('*.json')) if folder.exists() else []:
        if f.name.startswith('_'):
            continue
        b = ((ctx.load(f'security_identity/aks/{f.name}') or {}).get('cluster') or {}).get('body')
        if not b:
            continue
        parts = b['id'].split('/')
        it = T.basic({'id': b['id'], 'name': b['name'], 'subscriptionId': parts[2], 'resourceGroup': parts[4], 'tags': b.get('tags'),
                      'type': 'Microsoft.ContainerService/managedClusters', 'location': b.get('location')})
        p = b.get('properties') or {}
        pools = p.get('agentPoolProfiles') or []
        net = p.get('networkProfile') or {}
        addons = p.get('addonProfiles') or {}
        system_pools = [x['name'] for x in pools if x.get('mode') == 'System']
        actual = capacity.get(b['name'])
        it.update({
            'podSubnet': all(bool(x.get('podSubnetID')) for x in pools) if pools else False,
            'overlay': str(net.get('networkPluginMode') or '').lower() == 'overlay',
            'maxPods': sorted({x.get('maxPods') for x in pools if x.get('maxPods')}),
            'nodeSubnets': sorted({(x.get('vnetSubnetID') or '').split('/')[-1] for x in pools}),
            'nodeVnet': '/'.join((pools[0].get('vnetSubnetID') or '').split('/')[:9]).lower() if pools else '',
            'private': bool((p.get('apiServerAccessProfile') or {}).get('enablePrivateCluster')),
            'authIPs': (p.get('apiServerAccessProfile') or {}).get('authorizedIPRanges'),
            'tier': (b.get('sku') or {}).get('tier'),
            'nodeOS': (p.get('autoUpgradeProfile') or {}).get('nodeOSUpgradeChannel'),
            'upgrade': (p.get('autoUpgradeProfile') or {}).get('upgradeChannel'),
            'poolsNoZones': [x['name'] for x in pools if not x.get('availabilityZones')],
            'sysCount': sum(x.get('count') or 0 for x in pools if x.get('mode') == 'System'),
            'sysActual': sum(actual.get(n, 0) for n in system_pools) if actual else None,
            'version': p.get('kubernetesVersion'),
            'ci': bool((addons.get('omsagent') or {}).get('enabled')) if isinstance(addons.get('omsagent'), dict) else False,
            'prom': bool(((p.get('azureMonitorProfile') or {}).get('metrics') or {}).get('enabled')),
            'netpol': net.get('networkPolicy'), 'dataplane': net.get('networkDataplane'), 'outbound': net.get('outboundType'),
            'serviceCidr': net.get('serviceCidr'), 'dnsPrefix': p.get('dnsPrefix'), 'nodeRG': p.get('nodeResourceGroup'),
            'aad': bool(p.get('aadProfile')), 'localDisabled': p.get('disableLocalAccounts'),
            'addons': sorted(k for k, v in addons.items() if isinstance(v, dict) and v.get('enabled')),
            'freePodSubnet': _free_pod_subnet(vnets.get('/'.join((pools[0].get('vnetSubnetID') or '').split('/')[:9]).lower())) if pools else None})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}
    c = Counter
    n_pod = sum(1 for r in T.items if r['podSubnet'] or r['overlay'])
    n_private = sum(1 for r in T.items if r['private'])
    n_std = sum(1 for r in T.items if r['tier'] == 'Standard')
    n_img = sum(1 for r in T.items if r['nodeOS'] == 'NodeImage')
    n_mon = sum(1 for r in T.items if r['ci'] and r['prom'])
    common = most_common(['.'.join(map(str, _minor(r['version']))) for r in T.items if _minor(r['version'])])
    n_ver = sum(1 for r in T.items if _minor(r['version']) and '.'.join(map(str, _minor(r['version']))) == common)
    max_pods = most_common([m for r in T.items if r['podSubnet'] for m in r['maxPods']])
    peers_dates = {r['name']: r['created'] for r in T.items if r['tf'] and not r['vendor']}
    T.baseline_rationale = (f'以客户自己集群中已在使用、且符合微软推荐的做法为标准：独立 Pod 子网或 Overlay（{n_pod}/{n} 个集群）、'
                            f'私有 API Server（{n_private}/{n}）、Standard 层（{n_std}/{n}）、节点镜像自动更新（{n_img}/{n}）、'
                            f'Azure 监控（{n_mon}/{n}），版本取多数集群的 {common}（{n_ver}/{n}）。')

    def ipam_rec(r):
        if r['vendor']:
            return f'与供应商 {r["vendor"]} 确认模板能否改用独立 Pod 子网或 Azure CNI Overlay；在此之前至少确保节点子网留有扩容余量'
        reserved = f'（同一 VNet 中已预留且空闲的 {r["freePodSubnet"]} 可直接使用）' if r['freePodSubnet'] else ''
        return f'按标准做法新建一个使用独立 Pod 子网的集群{reserved}，把工作负载分批迁过去后下线旧集群'

    T.attr('ipam', 'Pod IP 分配方式', '独立 Pod 子网（动态分配 IP）或 Azure CNI Overlay' + (f'，maxPods {max_pods}' if max_pods else ''),
           lambda r: f'传统 Azure CNI：Pod 直接占用节点子网 {",".join(r["nodeSubnets"])} 的 IP，maxPods {"/".join(map(str, r["maxPods"]))}',
           lambda r: not (r['podSubnet'] or r['overlay']), rec=ipam_rec,
           feas=lambda r: '需供应商确认' if r['vendor'] else '需重建并迁移',
           short=lambda r: ('先在同一 VNet 新建一个足够大的节点子网，在其上新建节点池（按实际需要设置较小的 maxPods），'
                            '把现有业务节点池的负载迁过去以释放原节点子网的 IP；也可评估原地升级为 Azure CNI Overlay'
                            '（无需新集群，但不可回退，需先在测试集群演练）' if not r['vendor'] else '监控节点子网剩余 IP；必要时请供应商把节点池扩到新的节点子网'),
           confirm=_vendor_confirm, major=True)
    T.attr('apiServer', 'API Server 访问方式', f'私有集群（{n_private}/{n} 个集群）',
           lambda r: '公网可访问，未配置授权 IP 范围' if not r['authIPs'] else f'公网 + 授权 IP {len(r["authIPs"])} 条',
           lambda r: not r['private'],
           rec='为 API Server 配置授权 IP 范围（办公网出口、CI/CD 出口），再改为私有访问（可通过 API Server VNet 集成在现有集群上开启）',
           feas='原地修改（需维护窗口或应用配合）', short='先配置授权 IP 范围（原地生效，几分钟）', confirm=_vendor_confirm, major=True)
    T.attr('tier', '控制面层级', f'Standard（{n_std}/{n} 个集群，提供 SLA）', lambda r: r['tier'],
           lambda r: r['tier'] != 'Standard' and r['prod'], rec='把控制面层级改为 Standard', feas='原地修改', confirm=_vendor_confirm)
    T.attr('nodeOS', '节点系统镜像自动更新', f'NodeImage（{n_img}/{n} 个集群）', lambda r: r['nodeOS'],
           lambda r: r['nodeOS'] in (None, 'None', 'Unmanaged'), rec='把节点系统自动更新通道设为 NodeImage 并配置维护窗口', feas='原地修改')
    T.attr('zones', '节点池可用区', '所有节点池跨可用区', lambda r: '未跨可用区的节点池：' + ', '.join(r['poolsNoZones']),
           lambda r: bool(r['poolsNoZones']),
           rec='按标准做法新建跨可用区的节点池，迁移负载后删除旧池（可用区不能在现有节点池上修改）', feas='新建节点池/新实例替换（不重建整体）')
    T.attr('systemPool', '系统节点池节点数', '≥2 台',
           lambda r: f'{r["sysCount"]} 台' + (f'（实际 VMSS 为 {r["sysActual"]} 台）' if r['sysActual'] is not None and r['sysActual'] < r['sysCount'] else ''),
           lambda r: r['sysCount'] < 2 or r['sysActual'] == 0,
           rec=lambda r: '把系统节点池扩到至少 2 台' + ('（需先解决节点子网 IP 不足，否则扩容会继续失败）'
                                                   if r['sysActual'] == 0 and not (r['podSubnet'] or r['overlay']) else ''),
           feas='原地修改', confirm=lambda r: _vendor_confirm(r) or (None if r['prod'] else '非生产集群，可视成本决定是否调整'))
    if common:
        T.attr('version', 'Kubernetes 版本', f'{common}（{n_ver}/{n} 个集群）', lambda r: r['version'],
               lambda r: (_minor(r['version']) or (0, 0)) < tuple(map(int, common.split('.'))),
               rec=f'逐个小版本升级到 {common}（先升控制面再升节点池，先在测试集群演练）', feas='原地修改（需维护窗口或应用配合）',
               confirm=_vendor_confirm)
    T.attr('monitoring', 'Azure 监控', f'Container Insights + 托管 Prometheus（{n_mon}/{n} 个集群）',
           lambda r: f'Container Insights={"开" if r["ci"] else "关"}，托管 Prometheus={"开" if r["prom"] else "关"}',
           lambda r: not (r['ci'] and r['prom']),
           rec='启用 Container Insights（只采集 ContainerLogV2/KubeEvents 控制费用）和托管 Prometheus，并套用 AKS 推荐告警规则',
           feas='原地修改', follower_note='多数集群未启用时，以已启用的集群为目标做法' if n_mon * 2 < n else '', confirm=_vendor_confirm)

    def rc(r):
        return std_root_cause(ctx, r, [], peers_dates if not r['vendor'] else None)

    def extra(r, d):
        d['observedConfig'] = {k: r[k] for k in ('dnsPrefix', 'serviceCidr', 'nodeRG', 'netpol', 'dataplane', 'outbound', 'addons', 'upgrade')}
    T.run(rc, extra)
    entra = sum(1 for r in T.items if r['aad'] and r['localDisabled'])
    engines = c(str(r['netpol'] or '无') for r in T.items)
    auto = sum(1 for r in T.items if r['upgrade'] not in (None, 'none', 'None'))
    if entra == 0:
        T.uniform_gaps.append({'attribute': 'Entra ID 集成 + 禁用本地账户', 'followedBy': 0, 'of': n,
                               'note': f'{n} 个集群都未启用 Entra ID 集成并禁用本地账户，本地管理员证书仍可用；没有内部范例，按微软推荐统一补齐（原地修改，需先准备 Entra 组与 kubeconfig 切换）。'})
    if len(engines) > 1:
        T.uniform_gaps.append({'attribute': '网络策略引擎', 'note': '集群之间不统一：' + '、'.join(f'{k} {v} 个' for k, v in engines.most_common())
                               + '。Azure NPM 将于 2028-09-30 停止支持；建议每条业务线确定一个引擎（推荐 Cilium）写进模板。'})
    if auto * 2 < n:
        T.uniform_gaps.append({'attribute': 'Kubernetes 自动升级', 'followedBy': auto, 'of': n,
                               'note': f'{n - auto}/{n} 个集群关闭自动升级，需要统一的升级流程。'})
    base = {'ipam': '独立 Pod 子网（动态分配 IP）或 Azure CNI Overlay', 'apiServer': '私有集群', 'tier': 'Standard',
            'nodeOSUpgradeChannel': 'NodeImage', 'zones': '所有节点池跨可用区', 'systemPool': '≥2 台', 'version': common,
            'monitoring': 'Container Insights + 托管 Prometheus'}
    return T, base


# ---------------------------------------------------------------------------------------------- MySQL / PostgreSQL

PORTAL_RULE = re.compile(r'^(ClientIPAddress_|AllowAll_|AllowAllAzureServicesAndResourcesWithinAzureIps_|ClientIp)', re.I)


def _fw_summary(rules):
    pub, allow_all, big, azure, portal_named = [], [], [], 0, 0
    for x in rules or []:
        p = x.get('properties') or {}
        s, e, nm = p.get('startIpAddress'), p.get('endIpAddress'), x.get('name') or ''
        if PORTAL_RULE.match(nm):
            portal_named += 1
        if s == '0.0.0.0' and e == '0.0.0.0':
            azure += 1
            continue
        try:
            n = int(ipaddress.ip_address(e)) - int(ipaddress.ip_address(s)) + 1
        except ValueError:
            n = 1
        pub.append(nm)
        if s == '0.0.0.0' and e == '255.255.255.255':
            allow_all.append(nm)
        elif n >= 65536:
            big.append(f'{nm}({s}-{e})')
    return {'publicRules': len(pub), 'allowAll': allow_all, 'largeRanges': big, 'allowAzureServices': azure, 'portalStyleNames': portal_named}


def _diag_counts(ctx):
    return {x['id'].lower(): len((x.get('self') or {}).get('value') or []) for x in ctx.load('operations/diagnostic-settings.json', []) or []}


def db_type(ctx, kind):
    is_my = kind == 'mysql'
    T = TypeReport(ctx, kind, 'MySQL 灵活服务器' if is_my else 'PostgreSQL 灵活服务器')
    cfgs = ctx.load(f"{SN}/arm/{'mysql_cfg' if is_my else 'pg_cfg'}.json", {}) or {}
    fws = ctx.load(f"{SN}/arm/{'mysql_fw' if is_my else 'pg_fw'}.json", {}) or {}
    diag = _diag_counts(ctx)
    for r in ctx.rows(f'{SN}/arg/{kind}.json'):
        it = T.basic(r)
        p = r.get('properties') or {}
        net = p.get('network') or {}
        rst = ((((cfgs.get(r['id'] + '|require_secure_transport') or {}).get('data') or {}).get('properties') or {}).get('value'))
        role = p.get('replicationRole')
        it.update({'pna': net.get('publicNetworkAccess'), 'vnetInt': bool(net.get('delegatedSubnetResourceId')),
                   'pe': len(p.get('privateEndpointConnections') or []), 'fw': _fw_summary((fws.get(r['id']) or {}).get('data')),
                   'rst': (rst or '').upper() or None, 'ha': (p.get('highAvailability') or {}).get('mode'),
                   'geo': (p.get('backup') or {}).get('geoRedundantBackup'), 'ret': (p.get('backup') or {}).get('backupRetentionDays'),
                   'replica': role in ('Replica', 'AsyncReplica') or r['name'].endswith('-readonly'),
                   'tier': (r.get('sku') or {}).get('tier'), 'diag': diag.get(r['id'].lower(), 0)})
        it['primaryProd'] = it['prod'] and not it['replica']
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}

    def exposure(r):
        f = r['fw']
        if r['vnetInt']:
            return '私有访问（VNet 集成）'
        parts = [f'公网开关={r["pna"]}', f'私有终结点 {r["pe"]} 个', f'公网防火墙规则 {f["publicRules"]} 条']
        if f['allowAll']:
            parts.append('含全网放行规则 ' + ','.join(f['allowAll']))
        if f['largeRanges']:
            parts.append('含超大地址段 ' + ','.join(f['largeRanges'][:3]))
        if f['allowAzureServices']:
            parts.append('含“允许所有 Azure 服务”')
        return '，'.join(parts)

    def exposed(r):
        if r['vnetInt'] or r['pna'] == 'Disabled':
            return False
        return r['fw']['publicRules'] > 0 or r['fw']['allowAzureServices'] > 0 or r['pe'] == 0

    private = [r for r in T.items if not exposed(r)]
    tls_on = sum(1 for r in T.items if r['rst'] in ('ON',))
    zr = [r for r in T.items if r['primaryProd']]
    n_zr = sum(1 for r in zr if r['ha'] == 'ZoneRedundant')
    ret_peers = [r['ret'] for r in T.items if r['primaryProd'] and r['tf'] and r['ret']] or [r['ret'] for r in T.items if r['primaryProd'] and r['ret']]
    ret = most_common(ret_peers)
    T.baseline_rationale = (f'以已按微软推荐配置的库为标准：私有访问、没有公网防火墙规则（{len(private)}/{n} 台）；强制 TLS（{tls_on}/{n}）；'
                            f'生产主库跨可用区高可用（{n_zr}/{len(zr)}）' + (f'；备份保留 {ret} 天（按标准方式创建的生产库最常见的设置）' if ret else '') + '。')
    portal_rule_note = (lambda r: '请确认哪些外部客户端（办公网、第三方）仍需直连，改为经 VPN、跳板机或私有终结点访问'
                        if r['fw']['publicRules'] else None)
    if is_my:
        T.attr('network', '网络访问', '仅私有终结点，无公网防火墙规则（最好再关闭公网开关）', exposure, exposed,
               rec='为服务器创建私有终结点（或复用已有终结点），把应用连接串切到私有地址后删除全部公网防火墙规则并关闭公网访问',
               feas='原地修改（需维护窗口或应用配合）',
               short=lambda r: ('立即删除全网放行规则 ' + ','.join(r['fw']['allowAll'])) if r['fw']['allowAll'] else
               ('先删除超大地址段规则，只保留确需的固定出口 IP' if r['fw']['largeRanges'] else None),
               confirm=portal_rule_note, major=lambda r: r['fw']['publicRules'] > 0 or r['pe'] == 0)
        T.attr('tls', '强制 TLS（require_secure_transport）', 'ON', lambda r: r['rst'], lambda r: r['rst'] == 'OFF',
               rec='把 require_secure_transport 改为 ON（动态参数，无需重启）', feas='原地修改（需维护窗口或应用配合）',
               confirm='同一应用的库都关闭此项时，说明该应用客户端未启用 TLS，需应用侧先改再打开')
        T.attr('ha', '高可用', 'ZoneRedundant（跨可用区）', lambda r: r['ha'], lambda r: r['primaryProd'] and r['ha'] != 'ZoneRedundant',
               rec=lambda r: ('先把服务器从可突发（Burstable）升级到通用型，再开启跨可用区高可用' if r['tier'] == 'Burstable'
                              else '把高可用改为跨可用区（先关闭同可用区 HA 再按跨可用区重新开启，确认区域支持）'),
               feas='原地修改（需维护窗口或应用配合）')
        if ret:
            T.attr('retention', '备份保留天数', f'{ret} 天（按标准方式创建的生产库做法）', lambda r: f'{r["ret"]} 天',
                   lambda r: r['primaryProd'] and (r['ret'] or 0) < ret, rec=f'把备份保留期调到 {ret} 天', feas='原地修改')
    else:
        T.attr('network', '网络访问', '私有访问（私有终结点或 VNet 集成），无公网防火墙规则', exposure, exposed,
               rec='为每台服务器创建私有终结点（公网访问模式的服务器支持后加私有终结点），切换连接串后删除公网规则并关闭公网访问；网络模式本身创建后不能互换，不需要重建',
               feas='原地修改（需维护窗口或应用配合）',
               short=lambda r: '先删除“允许所有 Azure 服务”和不再使用的客户端 IP 规则' if r['fw']['publicRules'] or r['fw']['allowAzureServices'] else None,
               confirm=portal_rule_note, major=lambda r: r['fw']['publicRules'] > 0 or r['pe'] == 0)
        T.attr('tls', '强制 TLS（require_secure_transport）', 'on', lambda r: r['rst'], lambda r: r['rst'] == 'OFF',
               rec='把 require_secure_transport 改为 on', feas='原地修改（需维护窗口或应用配合）', confirm='请确认应用连接已启用 TLS')
        T.attr('ha', '高可用', 'ZoneRedundant（跨可用区）', lambda r: r['ha'], lambda r: r['primaryProd'] and r['ha'] != 'ZoneRedundant',
               rec=lambda r: '先升级到通用型再开启跨可用区高可用' if r['tier'] == 'Burstable' else '开启跨可用区高可用',
               feas='原地修改（需维护窗口或应用配合）')

    def rc(r):
        notes, f = [], r['fw']
        if f['portalStyleNames']:
            notes.append(f'{f["portalStyleNames"]} 条防火墙规则名称为门户按钮自动生成格式（ClientIPAddress_日期 / AllowAll_日期），'
                         '说明是在门户里点“添加当前客户端 IP / 允许全部”加上的')
        if r['tf'] and exposed(r):
            notes.append(f'带 {ctx.standard_name} 标签，但' + ('公网规则是在门户上加的（见上条规则命名），属于代码之外的配置漂移'
                                                            if f['portalStyleNames'] else '仍开着公网访问，可能是模板默认值问题'))
        return std_root_cause(ctx, r, notes)

    T.run(rc)
    geo = sum(1 for r in T.items if r['geo'] == 'Enabled')
    if geo * 2 < n:
        T.uniform_gaps.append({'attribute': '异地冗余备份', 'followedBy': geo, 'of': n,
                               'note': f'{n - geo}/{n} 台没开异地冗余备份；该设置只能在创建时选择，补齐需要“时间点还原到开启异地备份的新服务器”后切换，建议放到下次重建或大版本升级时一并处理。'})
    alert_note = '见“数据库与缓存的日志与告警”。'
    T.uniform_gaps.append({'attribute': 'Azure 告警规则', 'followedBy': None, 'of': n, 'note': alert_note})
    return T, None


# ---------------------------------------------------------------------------------------------- Redis

def redis_type(ctx):
    T = TypeReport(ctx, 'redis', 'Redis（Azure Managed Redis 与 Azure Cache for Redis）')
    dbs = ctx.load(f'{SN}/arm/redisent_db.json', {}) or {}
    for r in ctx.rows(f'{SN}/arg/redisenterprise.json'):
        it = T.basic(r)
        p = r.get('properties') or {}
        d = ((((dbs.get(r['id']) or {}).get('data') or [{}])[0]) or {}).get('properties') or {}
        pers = d.get('persistence') or {}
        it.update({'kind': 'AMR', 'sku': (r.get('sku') or {}).get('name'), 'pna': p.get('publicNetworkAccess'),
                   'pe': len(p.get('privateEndpointConnections') or []), 'vnetInj': False, 'proto': d.get('clientProtocol'),
                   'persist': bool(pers.get('rdbEnabled') or pers.get('aofEnabled')), 'ha': p.get('highAvailability') != 'Disabled'})
        T.items.append(it)
    for r in ctx.rows(f'{SN}/arg/redis.json'):
        it = T.basic(r)
        p = r.get('properties') or {}
        it.update({'kind': '经典', 'sku': (p.get('sku') or {}).get('name'), 'pna': p.get('publicNetworkAccess'),
                   'pe': len(p.get('privateEndpointConnections') or []), 'vnetInj': bool(p.get('subnetId')),
                   'proto': 'Encrypted' if not p.get('enableNonSslPort') else 'Plaintext', 'persist': None, 'ha': True})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}

    def net_dev(r):
        return not r['vnetInj'] and r['pna'] != 'Disabled'
    closed = sum(1 for r in T.items if not net_dev(r))
    enc = sum(1 for r in T.items if r['proto'] != 'Plaintext')
    T.baseline_rationale = (f'以已按推荐做法配置的缓存为标准：关闭公网 + 私有终结点或 VNet 注入（{closed}/{n} 个）、加密协议（{enc}/{n}）、'
                            '生产开启持久化和高可用。Azure Managed Redis 不支持 IP 防火墙，公网开关一开就是对全网开放，因此关闭公网是唯一可接受的做法。')
    T.attr('network', '网络访问', '关闭公网 + 私有终结点（或 VNet 注入）',
           lambda r: 'VNet 注入（私有）' if r['vnetInj'] else f'公网开关={r["pna"]}，私有终结点 {r["pe"]} 个', net_dev,
           rec=lambda r: '先创建私有终结点并把应用切到私有地址，再关闭公网访问' if r['pe'] == 0 else '已有私有终结点，确认应用都走私有地址后直接关闭公网访问',
           feas='原地修改（需维护窗口或应用配合）',
           short=lambda r: '在关闭公网前，至少轮换访问密钥并确认没有外部客户端' if r['pe'] == 0 else None,
           major=lambda r: r['pe'] == 0 and not r['vnetInj'])
    T.attr('protocol', '客户端协议', 'Encrypted（TLS）', lambda r: r['proto'], lambda r: r['proto'] == 'Plaintext',
           rec='把客户端协议改为 Encrypted，应用连接改用 TLS（端口不变）', feas='原地修改（需维护窗口或应用配合）',
           confirm='需应用侧同步启用 TLS，否则切换后连接会失败', major=True)
    T.attr('persistence', '持久化（生产）', '开启 RDB', lambda r: '未开启' if r['persist'] is False else '开启',
           lambda r: r['kind'] == 'AMR' and r['prod'] and r['persist'] is False, rec='为生产缓存开启 RDB 持久化（原地修改）', feas='原地修改',
           confirm='若该缓存只存可重建的数据，可不开启持久化')
    T.attr('ha', '高可用', '开启', lambda r: '关闭' if not r['ha'] else '开启', lambda r: not r['ha'],
           rec='开启高可用', feas='原地修改（需维护窗口或应用配合）', confirm='测试实例可接受关闭高可用')

    def rc(r):
        notes = []
        if r['tf'] and r['pna'] != 'Disabled' and not r['vnetInj']:
            notes.append(f'按标准方式（{ctx.standard_name}）创建' + ('并有私有终结点，' if r['pe'] else '，') + '但公网开关没有关闭，属于模板默认值问题')
        if r['proto'] == 'Plaintext':
            notes.append('明文协议通常按应用分布，说明该应用客户端未启用 TLS')
        return std_root_cause(ctx, r, notes)
    T.run(rc)
    return T, {'network': '关闭公网 + 私有终结点', 'protocol': 'Encrypted', 'persistence': '生产开启 RDB', 'ha': '开启'}


# ---------------------------------------------------------------------------------------------- MongoDB vCore

def mongo_type(ctx):
    T = TypeReport(ctx, 'mongo', 'Azure Cosmos DB for MongoDB（vCore）')
    fws = ctx.load(f'{SN}/arm/mongo_fw.json', {}) or {}
    for r in ctx.rows(f'{SN}/arg/mongoclusters.json'):
        it = T.basic(r)
        p = r.get('properties') or {}
        groups = p.get('nodeGroupSpecs') or []
        it.update({'pna': p.get('publicNetworkAccess'), 'pe': len(p.get('privateEndpointConnections') or []),
                   'fwRules': len((fws.get(r['id']) or {}).get('data') or []),
                   'ha': any(g.get('enableHa') for g in groups) or str((p.get('highAvailability') or {}).get('targetMode') or '').lower() not in ('', 'disabled'),
                   'sku': ','.join(g.get('sku') or '' for g in groups)})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}
    closed = sum(1 for r in T.items if r['pna'] == 'Disabled')
    T.baseline_rationale = f'以已按推荐做法配置的实例为标准：私有终结点访问、关闭公网（{closed}/{n} 个）、生产开启高可用。'
    T.attr('network', '公网开关', f'关闭（{closed}/{n} 个）', lambda r: f'{r["pna"]}（防火墙规则 {r["fwRules"]} 条，私有终结点 {r["pe"]} 个）',
           lambda r: r['pna'] != 'Disabled', rec='确认应用走私有终结点后关闭公网访问', feas='原地修改')
    T.attr('ha', '高可用（生产）', '开启', lambda r: '开启' if r['ha'] else '关闭', lambda r: r['prod'] and not r['ha'],
           rec='开启高可用（原地修改，会增加一套备用节点费用）', feas='原地修改（需维护窗口或应用配合）')
    T.run(lambda r: std_root_cause(ctx, r))
    return T, {'network': '私有终结点 + 关闭公网', 'ha': '生产开启'}
