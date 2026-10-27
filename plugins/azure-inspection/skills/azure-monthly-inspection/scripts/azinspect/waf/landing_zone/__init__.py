"""Landing Zone comparison: Azure Review Checklists ALZ items that carry a Resource Graph query (MIT, fixed commit in
<skill>/vendor/landing_zone). Read-only Resource Graph.

Result is an architecture comparison for the 03 report (section + Excel sheet), not findings: our own checks already
cover the important gaps, and many ALZ items are design choices to discuss with the customer.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..common import Findings, Raw, enabled, load_scope, now

VENDOR = Path(__file__).resolve().parents[4] / 'vendor' / 'landing_zone' / 'checklist.json'
CATEGORIES = {'Identity and Access Management': '身份与访问', 'Resource Organization': '资源组织', 'Security': '安全',
              'Network Topology and Connectivity': '网络拓扑与连接', 'Management': '管理'}
SEVERITY = {'High': '高', 'Medium': '中', 'Low': '低'}
# Items whose upstream query does not run in Resource Graph (re-check when vendor/landing_zone is updated).
SKIP = {'4b69bad3-3aad-45e8-a68e-1d76667313b4': 'cross-table join (resourcecontainers x authorizationresources) returns HTTP 400; '
                                                'role assignments are covered by S-I5',
        '3f630472-2dd6-49c5-a5c2-622f54b69bad': 'RFC 1918 regex is written with \\. inside a verbatim string, so every '
                                                'address is reported as non-compliant'}
TITLES = {
    '4b69bad3': '用 Entra 组分配权限，而不是直接分配给个人',
    '1559ab91': '域控制器跨可用区部署至少两台',
    'f5664b5e': '为平台、网络、安全等关键角色使用自定义 RBAC 角色',
    '9cf5418b': '身份服务放在独立虚拟网络并与中心网络对等',
    '0ce74f19': '尽量减少订阅 Owner 数量',
    '2df27ee4': '管理组层级不超过四层',
    '33b6b780': '订阅不直接放在根管理组下',
    '5de32c19': '用标签支持计费和成本管理',
    '91b9d7d5': 'Route Server 子网使用 /27',
    '0e7c28ec': '单区域分支网络超过 400 个时增加中心网络',
    '3d457936': '每个路由表不超过 400 条路由',
    'c76cb5a2': 'VNet 对等启用“允许流量到远程虚拟网络”',
    '3f630472': '使用 RFC 1918 私有地址段',
    '33aad5e8': '不创建过大的虚拟网络（如 /16），避免浪费地址空间',
    '6eab9eb6': 'Bastion 子网使用 /26 或更大',
    'd4cd21b0': '按带宽需求选择专线/VPN 网关规格',
    '7025b442': '只有带宽足够大时才使用不限流量的专线',
    'f4e7926a': '对接点支持时使用 Local 类型专线降低费用',
    '2447ec66': '专线网关使用区域冗余规格',
    '4d873974': 'VPN 网关使用区域冗余规格',
    'e0d5973c': '专线来自不同对接点以实现冗余',
    '72105cc8': 'GatewaySubnet 上的路由表开启网关路由传播',
    '14d99880': '用防火墙应用规则按域名过滤出站流量',
    'c10d51ef': '使用 Azure Firewall 高级版',
    'e9c8f584': '防火墙威胁情报设为“告警并拒绝”',
    'b9d0dff5': '防火墙入侵检测（IDPS）设为“拒绝”',
    'a3784907': '子网关联路由表，使出站流量经过防火墙',
    '22d6419e': '防火墙子网使用 /26',
    '94f3eede': '开启防火墙 DNS 代理',
    'e8143efa': '防火墙所在虚拟网络开启 DDoS 防护',
    '4704489a': '不要在所有子网默认开启服务终结点',
    'f2aad7e3': 'GatewaySubnet 至少 /27',
    '11deb39d': '不要依赖 NSG 默认的 VirtualNetwork 入站规则限制连通性',
    '872e52e3': '用 NSG 保护子网之间和着陆区之间的流量',
    'dfe237de': '开启虚拟网络流日志和流量分析',
    '0390417d': '每个 NSG 不超过 900 条规则',
    '7d5d1e4e': '在安全中心网络部署防火墙过滤出站流量',
    '727c77e1': 'Virtual WAN 不要关闭分支到分支的流量（除非需要）',
    'd49ac006': 'Virtual WAN 中心路由优先级使用 AS-Path',
    '9c75dfef': 'Virtual WAN 中心至少分配 /23',
    'a0477a20': '不同应用、环境、区域使用不同的 Key Vault',
    'a56888b2': '把安全日志集中到一个地方关联分析',
}


def checklist():
    return json.loads(VENDOR.read_text(encoding='utf-8'))


def collect(ws, cfg, client, window, log=print):
    raw = Raw(ws, 'landing_zone')
    subs = [s['id'] for s in enabled(load_scope(ws))]
    data, results = checklist(), []
    for item in [i for i in data['items'] if i['guid'] not in SKIP]:
        rows, status, error = client.arg(item['graph'], subs, 'landing-zone', item['guid'])
        # queries name their columns differently (name, subnetName, vnetName, ...): keep the short scalar fields
        keep = [{k: v for k, v in r.items() if isinstance(v, (str, int, float, bool)) and len(str(v)) <= 300} for r in rows or []]
        results.append({'guid': item['guid'], 'status': status, 'error': error, 'rows': keep})
    raw.save('results.json', {'collectedAt': now(), 'commit': data['commit'], 'results': results})
    raw.save('manifest.json', {'collectedAt': now(), 'window': window})
    log(f'Landing Zone 对照：执行 {len(results)} 条清单查询，{sum(1 for r in results if r["status"] != 200)} 条失败')


def _label(row):
    """Readable name of a checked item: a *name column, else the last part of an id, else the first text value."""
    for key in sorted(row, key=lambda k: (k.lower() != 'name', not k.lower().endswith('name'))):
        if key.lower().endswith('name') and row[key]:
            return str(row[key])
    for key in ('id', 'resourceId', 'subnetId', 'vnetId'):
        if row.get(key):
            return str(row[key]).rstrip('/').split('/')[-1]
    texts = [v for k, v in row.items() if isinstance(v, str) and v and k != 'compliant' and not v.lower().startswith('/subscriptions/')]
    return texts[0] if texts else '（未命名）'


def _is_compliant(value):
    return str(value).lower() in ('1', 'true')


def analyze(ws, cfg, log=print):
    raw = Raw(ws, 'landing_zone')
    data, manifest, meta = raw.load('results.json'), raw.load('manifest.json') or {}, checklist()
    items = {i['guid']: i for i in meta['items']}
    rows = []
    for r in data['results']:
        item = items.get(r['guid'])
        if not item or r['guid'] in SKIP:
            continue
        ok = [x for x in r['rows'] if _is_compliant(x.get('compliant'))]
        bad = [x for x in r['rows'] if not _is_compliant(x.get('compliant'))]
        rows.append({'guid': r['guid'], 'category': CATEGORIES.get(item['category'], item['category']),
                     'title': TITLES.get(r['guid'][:8], item['text']), 'severity': SEVERITY.get(item['severity'], item['severity']),
                     'status': ('读取失败' if r['status'] != 200 else '不适用（没有相关资源）' if not r['rows']
                                else '全部符合' if not bad else '有不符合项'),
                     'compliant': len(ok) if r['status'] == 200 else None, 'nonCompliant': len(bad) if r['status'] == 200 else None,
                     'examples': sorted({_label(x) for x in bad})[:10], 'link': item.get('link'), 'text': item['text']})
    order = {'有不符合项': 0, '全部符合': 1, '不适用（没有相关资源）': 2, '读取失败': 3}
    rows.sort(key=lambda x: (order[x['status']], {'高': 0, '中': 1, '低': 2}.get(x['severity'], 3), x['category']))
    out = Findings('landing_zone').write(ws, window=manifest.get('window'), coverage={}, scope={'items': len(rows)},
                                         inventory={'landingZone': rows}, extra={'checklistCommit': meta['commit']})
    log(f'Landing Zone 对照：{len(rows)} 条，其中 {sum(1 for x in rows if x["status"] == "有不符合项")} 条有不符合项')
    return out
