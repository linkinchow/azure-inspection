"""Offline analysis for S-N1..S-N8: reads raw/waf/security_network only, writes findings/waf/security_network.json."""
from __future__ import annotations

from ..common import Findings, Raw, load_scope, mixed_env
from . import private_endpoints
from .checks import (Draft, check_amr, check_db_servers, check_edge, check_misc_paas, check_mongo, check_nsg, check_public_ips,
                     check_redis, check_storage, check_subnets)
from .collect import ARG_TYPES, PILLAR
from .network import ADMIN_PORTS, Ctx, evaluate_exposures, lid, public_paths

# (check, resourceType substring, finding substring, key, summary): per-resource rows merged per subscription
GROUP_RULES = [
    ('S-N1', 'subnets', '未关联 NSG', 'sn1', '子网未关联 NSG'),
    ('S-N4', 'flexibleServers', '按 IP 白名单限制', 'db-iplist', '数据库开启公网访问、仅按 IP 白名单限制'),
    ('S-N4', 'flexibleServers', '公网实际无法连接', 'db-norule', '数据库公网开关开启但无防火墙规则（实际不可连）'),
    ('S-N7', 'flexibleServers', 'require_secure_transport=OFF', 'db-rst', '数据库 require_secure_transport=OFF（允许不加密连接）'),
    ('S-N4', 'redisEnterprise', '开启了公网访问', 'amr-public', 'Azure Managed Redis 开启公网访问（不支持 IP 防火墙，等于对全网开放）'),
    ('S-N7', 'redisEnterprise', 'Plaintext', 'amr-plain', 'Azure Managed Redis 数据库使用明文协议'),
    ('S-N4', 'storageAccounts', '允许从所有网络访问', 'st-open', '存储账户允许从所有网络访问'),
    ('S-N4', 'KeyVault', '允许从所有网络访问', 'kv-open', 'Key Vault 允许从所有网络访问'),
    ('S-N4', 'mongoClusters', '公网实际无法连接', 'mongo-norule', 'MongoDB(vCore) 公网开关开启但无防火墙规则（实际不可连）'),
    ('S-N6', 'Cdn/profiles', '模式', 'afd-detect', 'Front Door WAF 处于 Detection（只记录不拦截）'),
    ('S-N6', 'applicationGateways', '不带 WAF', 'agw-nowaf', '公网应用网关不带 WAF'),
    ('S-N7', 'applicationGateways', '明文 HTTP 监听', 'agw-http', '应用网关有明文 HTTP 监听且未跳转 HTTPS'),
    ('S-N7', 'applicationGateways', '未显式配置 SSL 策略', 'agw-ssl', '应用网关未显式配置 SSL 策略'),
]

CHECK_SOURCES = {
    'S-N1': ['vnets', 'nics', 'vmss', 'vms'],
    'S-N2': ['nsgs', 'nics', 'vmss', 'loadbalancers', 'publicips'],
    'S-N3': ['publicips', 'publicipprefixes', 'vms', 'vmss', 'nics', 'natgateways', 'bastions', 'firewalls', 'vngateways'],
    'S-N4': ['mysql', 'mysql_single', 'postgres', 'postgres_single', 'redis', 'redisenterprise', 'cosmos', 'mongoclusters', 'storage',
             'keyvaults', 'registries', 'cognitive', 'loganalytics', 'sqlservers', 'eventhubs', 'servicebus', 'webapps',
             'privateendpoints', 'mysql_fw', 'pg_fw', 'redis_fw', 'redisent_db', 'mongo_fw', 'sql_fw'],
    'S-N5': ['storage', 'containers'],
    'S-N6': ['appgateways', 'appgw_wafpolicies', 'fd_wafpolicies', 'frontdoors_classic', 'cdn_profiles', 'loadbalancers', 'pls',
             'afd_secpol', 'afd_endpoints'],
    'S-N7': ['mysql_cfg', 'pg_cfg', 'redis', 'redisenterprise', 'redisent_db', 'storage', 'appgateways'],
}
RANK = {'高': 0, '中': 1, '低': 2}


def consolidate(items):
    """Merge repetitive per-resource rows into one per (subscription, check, severity, pattern)."""
    groups, out = {}, []
    for f in items:
        key = None
        for chk, rt, txt, k, summary in GROUP_RULES:
            if f['check'] == chk and rt in (f['resourceType'] or '') and txt in f['finding']:
                key = (f['subscriptionId'], chk, f['severity'], k, summary)
                break
        if key is None:
            out.append(f)
        else:
            groups.setdefault(key, []).append(f)
    for (_sub, _chk, _sev, k, summary), rows in groups.items():
        if len(rows) == 1:
            out.append(rows[0])
            continue
        f0 = rows[0]
        rgs = sorted({i['resourceGroup'] for i in rows})
        out.append({**f0, 'resourceName': f'{len(rows)} 个：' + ', '.join(i['resourceName'] for i in rows), 'resourceId': None,
                    'resourceGroup': rgs[0] if len(rgs) == 1 else '(多个)',
                    'environment': mixed_env([i['environment'] for i in rows]),
                    'finding': f'该订阅有 {len(rows)} 个资源{summary}：' + '；'.join(i['finding'].rstrip('。') for i in rows[:6])
                               + ('；…（其余见证据）' if len(rows) > 6 else '') + '。',
                    'evidence': {'consolidatedFrom': len(rows),
                                 'items': [{'resourceName': i['resourceName'], 'resourceGroup': i['resourceGroup'], 'environment': i['environment'],
                                            'finding': i['finding'], 'evidence': i['evidence']} for i in rows]},
                    'needsConfirmation': any(i['needsConfirmation'] for i in rows),
                    'members': [m for i in rows for m in i['members']], 'key': k})
    return out


def _missing(c, pairs):
    """Resource types that were looked for but do not exist, e.g. '经典 Front Door、Azure 防火墙'."""
    return '、'.join(label for key, label in pairs if not c.rows(key))


def _coverage(index, c, pe_coverage):
    basic = any((p.get('sku') or {}).get('name') == 'Basic' for p in c.pip.values())
    n4 = _missing(c, [('cosmos', 'Cosmos DB'), ('sqlservers', 'Azure SQL'), ('webapps', 'App Service')])
    n6 = _missing(c, [('frontdoors_classic', '经典 Front Door'), ('firewalls', 'Azure 防火墙')])
    notes = {
        'S-N1': '子网 ipConfigurations 来自 Resource Graph；平台托管实例（VNet 注入的 Redis、应用网关 v2、AGC、VPN 网关、Bastion 等）在微软托管订阅中，只能按 ID 归类。'
                'GatewaySubnet/AzureFirewallSubnet/AzureBastionSubnet/RouteServerSubnet 按要求排除。',
        'S-N2': '“公网是否可达”为离线评估：子网与网卡两层 NSG 按优先级首个匹配（来源仅把 Any/Internet/0.0.0.0/0 视为全网），结合直连公网 IP 与公网 LB 规则；'
                '未调用 Network Watcher 有效安全规则，ASG 目标按可匹配保守处理。',
        'S-N3': ('' if basic else '未发现 Basic SKU 公网 IP；') + 'VMSS 实例级公网 IP 按模型 publicIPAddressConfiguration 判断。',
        'S-N4': (f'未发现 {n4}；' if n4 else '') + 'Azure Managed Redis 不支持 IP 防火墙；VNet 注入的经典 Redis 仅 VNet 内可达，不按公网判定。'
                'Elasticsearch 类自建服务只能通过 NSG 规则判断（见 S-N2）。',
        'S-N5': '仅对 allowBlobPublicAccess 不为 false 的账户列出容器（管理面 GET，只取 publicAccess 属性，未读取任何数据）；未检查文件共享/队列/表。',
        'S-N6': (f'未发现 {n6}；' if n6 else '') + '公网 LB 暴露端口取自 LB 规则配置，未连接任何端点。',
        'S-N7': 'MySQL 只读取 require_secure_transport、tls_version；PG 只读取 require_secure_transport、ssl_min_protocol_version。',
    }
    coverage = {}
    for chk, keys in CHECK_SOURCES.items():
        rel = [x for x in index if (x['check'] == 'ARG' and x['target'].split(':', 1)[1] in keys) or x['check'] in keys]
        coverage[chk] = {'attempted': len(rel), 'succeeded': sum(1 for x in rel if x['http'] == 200),
                         'denied': sum(1 for x in rel if x['http'] in (401, 403)),
                         'notFound': sum(1 for x in rel if x['http'] == 404),
                         'otherErrors': sum(1 for x in rel if x['http'] not in (200, 401, 403, 404)),
                         'notes': [notes[chk]]}
    if pe_coverage:
        coverage['S-N8'] = pe_coverage
    return coverage


def _month_label(ws):
    return f'{int(ws.month[5:7])} 月' if ws.month else '本月'


def analyze(ws, cfg, log=print):
    # customer-specific management/middleware ports (customer.yaml rules.extraRiskyPorts) join the shared table
    ADMIN_PORTS.update(getattr(cfg, 'extra_risky_ports', {}) or {})
    raw = Raw(ws, PILLAR)
    subs = load_scope(ws)
    subname = {s['id'].lower(): s['name'] for s in subs}
    c = Ctx(lambda key: raw.load(f'raw/arg/{key}.json'), subname)
    arm_cache = {}

    def arm(kind):
        if kind not in arm_cache:
            arm_cache[kind] = raw.load(f'raw/arm/{kind}.json', {})
        return arm_cache[kind]

    targets = {}
    for pe in c.rows('privateendpoints'):
        pp = pe.get('properties') or {}
        for conn in (pp.get('privateLinkServiceConnections') or []) + (pp.get('manualPrivateLinkServiceConnections') or []):
            targets.setdefault(lid((conn.get('properties') or {}).get('privateLinkServiceId')), []).append(pe['name'])

    def pecount(r):
        return max(len((r.get('properties') or {}).get('privateEndpointConnections') or []), len(targets.get(lid(r['id']), [])))

    F = Draft(c, cfg)
    paths = public_paths(c)
    exposures = evaluate_exposures(c, paths)
    subnet_inv = check_subnets(c, F)
    nsg_inv, mgmt_direct = check_nsg(c, F, exposures)
    pip_inv, vm_direct = check_public_ips(c, F, paths, exposures, mgmt_direct)
    paas = {
        'mysqlFlexible': check_db_servers(c, F, arm, pecount, 'MySQL 灵活服务器', 'mysql', 'mysql_fw', 'mysql_cfg',
                                          'require_secure_transport', 'tls_version', 'Microsoft.DBforMySQL/flexibleServers'),
        'postgresFlexible': check_db_servers(c, F, arm, pecount, 'PostgreSQL 灵活服务器', 'postgres', 'pg_fw', 'pg_cfg',
                                             'require_secure_transport', 'ssl_min_protocol_version', 'Microsoft.DBforPostgreSQL/flexibleServers'),
        'redisClassic': check_redis(c, F, arm, pecount),
        'azureManagedRedis': check_amr(c, F, arm, pecount),
        'mongoClusters': check_mongo(c, F, arm, pecount),
        'storage': check_storage(c, F, arm, pecount),
    }
    paas.update(check_misc_paas(c, F, pecount))
    edge = check_edge(c, F, arm, paths)

    drafts = consolidate(F.items)
    drafts.sort(key=lambda f: (RANK[f['severity']], f['check'], f['subscriptionName'] or '', f['resourceName'] or ''))
    findings = Findings(PILLAR)
    for i, f in enumerate(drafts, 1):
        findings.add(f['check'], f['severity'], f['finding'], f['recommendation'], subscription=f['subscriptionName'],
                     resource_group=f['resourceGroup'], resource_name=f['resourceName'], resource_type=f['resourceType'],
                     resource_id=f['resourceId'], environment=f['environment'], evidence=f['evidence'],
                     needs_confirmation='是' if f['needsConfirmation'] else None, members=f['members'], key=f['key'],
                     legacy_id=f'SN-{i:03d}')
    pe_coverage, pe_summary = private_endpoints.analyze(raw, ws, cfg, subname, _month_label(ws), findings.add)

    meta = raw.load('raw/meta.json', {})
    index = raw.load('index.json', {}).get('calls', [])
    disabled = [s for s in subs if s.get('state') != 'Enabled']
    manifest = raw.load('manifest.json', {})
    by_check = {}
    for f in findings.items:
        by_check.setdefault(f['check'], {'高': 0, '中': 0, '低': 0})[f['severity']] += 1
    scope = {'subscriptionsTotal': len(subs), 'inspected': len(subs) - len(disabled),
             'notInspected': [{'name': s['name'], 'id': s['id'], 'reason': f'订阅状态为 {s.get("state")}，无法读取，未检查'} for s in disabled],
             'environmentNote': '生产/测试环境按客户配置的命名和标签规则推断，均标注“推断”，需客户确认。',
             'method': '只读：ARM GET 与 Azure Resource Graph 查询；未调用 listKeys/连接串/数据面；未做端口扫描或连接测试；未修改任何配置。'}
    inventory = {'subnets': subnet_inv, 'nsgs': nsg_inv, 'publicIps': pip_inv, 'vmDirectPublicIps': vm_direct, **edge, 'paas': paas,
                 'counts': {k: len(c.rows(k)) for k in ARG_TYPES if k != 'subscriptions_visible'},
                 'privateEndpoints': pe_summary}
    summary = {'total': len(findings.items), 'perResourceFindingsBeforeConsolidation': len(F.items),
               'bySeverity': {s: sum(1 for f in findings.items if f['severity'] == s) for s in ('高', '中', '低')},
               'byCheck': dict(sorted(by_check.items()))}
    data = findings.write(ws, window=manifest.get('window'), coverage=_coverage(index, c, pe_coverage), scope=scope, inventory=inventory,
                          limitations=['端口可达性为按 NSG、公网 IP 和负载均衡规则的离线判断，未做端口扫描或连接测试。'],
                          extra={'collectedAt': manifest.get('collectedAt') or meta.get('collectedAt'), 'summary': summary,
                                 'argErrors': meta.get('argErrors') or {}})
    log(f'安全-网络：{summary["total"]} 条问题（高 {summary["bySeverity"]["高"]}、中 {summary["bySeverity"]["中"]}、低 {summary["bySeverity"]["低"]}）')
    return data
