"""Architecture overview for report 03: subscriptions, regions, network and main workloads, built from the
resource inventory the operations pillar already reads (no extra calls). narrative/03.json `architecture`
(paragraphs) adds the agent's description of how the business runs on these components."""
from __future__ import annotations

from collections import Counter, defaultdict

from ..core.io import read_json
from .common import load_scope

COMPONENTS = [
    ('AKS 集群', ('microsoft.containerservice/managedclusters',)),
    ('虚拟机', ('microsoft.compute/virtualmachines',)),
    ('应用服务', ('microsoft.web/sites',)),
    ('数据库', ('microsoft.dbforpostgresql/flexibleservers', 'microsoft.dbforpostgresql/servers', 'microsoft.dbformysql/flexibleservers',
              'microsoft.dbformysql/servers', 'microsoft.sql/servers/databases', 'microsoft.sql/managedinstances',
              'microsoft.documentdb/databaseaccounts')),
    ('缓存', ('microsoft.cache/redis', 'microsoft.cache/redisenterprise')),
    ('存储账户', ('microsoft.storage/storageaccounts',)),
    ('消息服务', ('microsoft.eventhub/namespaces', 'microsoft.servicebus/namespaces')),
    ('AI 服务', ('microsoft.cognitiveservices/accounts', 'microsoft.machinelearningservices/workspaces')),
    ('应用网关', ('microsoft.network/applicationgateways',)),
    ('Front Door/CDN', ('microsoft.cdn/profiles', 'microsoft.network/frontdoors')),
]
NETWORK = [
    ('虚拟网络', ('microsoft.network/virtualnetworks',)),
    ('专线', ('microsoft.network/expressroutecircuits',)),
    ('VPN 或专线网关', ('microsoft.network/virtualnetworkgateways',)),
    ('Virtual WAN 中心', ('microsoft.network/virtualhubs',)),
    ('Azure Firewall', ('microsoft.network/azurefirewalls',)),
    ('NAT 网关', ('microsoft.network/natgateways',)),
    ('私有终结点', ('microsoft.network/privateendpoints',)),
]


def _rows(ws, rel):
    path = ws.raw(rel)
    if not path.exists():
        return None
    data = read_json(path)
    if data.get('error'):
        return None
    return data.get('rows') or []


def summary(ws, cfg) -> dict | None:
    resources = _rows(ws, 'waf/operations/arg/resources.json')
    if resources is None:
        return None
    names = {s['id'].lower(): s['name'] for s in load_scope(ws)}
    by_sub = defaultdict(list)
    for r in resources:
        by_sub[(r.get('subscriptionId') or '').lower()].append(r)
    subs = []
    for sid, rs in sorted(by_sub.items(), key=lambda kv: -len(kv[1])):
        types = Counter(r['type'] for r in rs)
        regions = Counter(r['location'] for r in rs if r.get('location') and r['location'] != 'global')
        comps = [(label, sum(types[t] for t in ts)) for label, ts in COMPONENTS]
        subs.append({'subscription': names.get(sid, sid), 'resources': len(rs),
                     'regions': [cfg.region(loc) for loc, _ in regions.most_common(3)],
                     'components': [(label, n) for label, n in comps if n]})
    types = Counter(r['type'] for r in resources)
    network = [(label, sum(types[t] for t in ts)) for label, ts in NETWORK]
    peerings = _rows(ws, 'waf/performance/arg/peerings.json')
    cross_region = None
    if peerings is not None:
        loc = {r['id'].lower(): r.get('location') for r in resources if r['type'] == 'microsoft.network/virtualnetworks'}
        cross_region = sum(1 for p in peerings if loc.get((p.get('remote') or '').lower()) not in (None, p.get('location')))
    return {'subscriptions': subs, 'network': network, 'peerings': None if peerings is None else len(peerings),
            'crossRegionPeerings': cross_region}


def section(arch: dict | None, narrative: dict) -> list[str]:
    paragraphs = narrative.get('architecture') or []
    if isinstance(paragraphs, str):
        paragraphs = [paragraphs]
    if not arch and not paragraphs:
        return []
    lines = []
    if arch:
        lines += ['|订阅|资源数|主要区域|主要组件|', '|---|---:|---|---|']
        for s in arch['subscriptions']:
            comps = '、'.join(f'{label} {n} 个' for label, n in s['components']) or '没有上述主要组件'
            lines.append(f'|{s["subscription"]}|{s["resources"]}|{"、".join(s["regions"]) or "-"}|{comps}|')
        net = arch['network']
        have = [f'{label} {n} 个' for label, n in net if n]
        missing = [label for label, n in net if not n and label in ('专线', 'VPN 或专线网关', 'Virtual WAN 中心', 'Azure Firewall')]
        text = '网络：' + ('、'.join(have) if have else '没有读到虚拟网络')
        if arch['peerings'] == 0:
            text += '；虚拟网络之间没有对等连接'
        elif arch['peerings']:
            text += f'；虚拟网络对等 {arch["peerings"]} 个' + (f'，其中跨区域 {arch["crossRegionPeerings"]} 个' if arch['crossRegionPeerings'] else '')
        if missing:
            text += f'。Azure 中没有{"、".join(missing)}；Azure 之外是否有专线、VPN 或第三方防火墙，需要客户确认'
        lines += ['', text + '。']
    for p in paragraphs:
        lines += ['', p]
    return lines[1:] if lines[:1] == [''] else lines
