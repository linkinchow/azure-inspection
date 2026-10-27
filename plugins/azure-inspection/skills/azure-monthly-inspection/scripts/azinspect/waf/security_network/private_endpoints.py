"""S-N8: private endpoints whose connection is Disconnected because the target resource was deleted.

Reads raw/pe-disconnected (collected with the other network data) and, when present, the monthly cost
data of the same workspace month for each endpoint's actual cost.
"""
from __future__ import annotations

from collections import defaultdict

from ...core.io import read_json
from ..common import env as env_of
from ..common import mixed_env

PE = 'raw/pe-disconnected/'
TYPE = 'Microsoft.Network/privateEndpoints'
KIND = {'microsoft.cache/redisenterprise': 'Redis', 'microsoft.cache/redis': 'Redis', 'microsoft.storage/storageaccounts': '存储账户',
        'microsoft.dbformysql/flexibleservers': 'MySQL', 'microsoft.dbforpostgresql/flexibleservers': 'PostgreSQL',
        'microsoft.keyvault/vaults': 'Key Vault', 'microsoft.documentdb/databaseaccounts': 'Cosmos DB',
        'microsoft.documentdb/mongoclusters': 'MongoDB', 'microsoft.containerregistry/registries': '镜像仓库',
        'microsoft.cognitiveservices/accounts': 'AI 服务', 'microsoft.sql/servers': 'SQL Server'}
RECOMMEND = '确认没有应用、脚本或配置仍引用这些终结点的名称或 IP 后删除；以后删除 Redis、存储账户、数据库时同时删除它们的私有终结点。'
STANDARD_NOTE = '带标准部署标签的终结点请在部署模板（如 Terraform）中一并删除，避免配置与实际环境不一致。'


def _kind(target):
    for k, v in KIND.items():
        if f'/providers/{k}/' in target:
            return v
    return '资源'


def _deleted_on(activity, target):
    events = ((activity.get(target) or {}).get('data') or {}).get('value', [])
    done = sorted(e['eventTimestamp'][:10] for e in events
                  if e['operationName']['value'].lower().endswith('/delete') and e['status']['value'] == 'Succeeded')
    return done[-1] if done else None


def _month_cost(ws, ids):
    """Actual cost of the workspace month per resource id from the cost review; None when not collected."""
    path = ws.raw('cost/cost-data.json')
    if not path.exists():
        return None
    total = defaultdict(float)
    for r in read_json(path)['rows'].get('curResources', []):
        rid = str(r.get('resourceId') or '').lower()
        if rid in ids:
            total[rid] += r['cost']
    return total


def _target_text(by_target, activity):
    parts = []
    for target, names in sorted(by_target.items(), key=lambda kv: (_deleted_on(activity, kv[0]) or '0', kv[0])):
        when = _deleted_on(activity, target)
        when = f'{int(when[5:7])} 月 {int(when[8:10])} 日删除' if when else '删除时间早于 90 天，活动日志已查不到'
        parts.append(f'{"、".join(sorted(names))}（目标：{_kind(target)} {target.rsplit("/", 1)[-1]}，{when}）')
    return '；'.join(parts)


def analyze(raw, ws, cfg, subname, month_label, add):
    """Adds S-N8 findings through add(...); returns (coverage entry, summary) or (None, None) when not collected."""
    pes_rec = raw.load(PE + 'pe-all.json')
    if pes_rec is None:
        return None, None
    pes = pes_rec.get('rows') or []
    exists, activity = raw.load(PE + 'targets-exist.json', {}), raw.load(PE + 'target-activity.json', {})
    dns, nics_rec = raw.load(PE + 'dns-a-records.json', {}), raw.load(PE + 'nics.json', {})
    nics = {n['id']: [c['properties'].get('privateIPAddress') for c in n['ips']] for n in nics_rec.get('rows') or []}
    still_there = {r['id'] for r in exists.get('rows') or []}
    disc = [r for r in pes if r['status'] == 'Disconnected']
    gone = [r for r in disc if r['target'] not in still_there]
    ips = {ip for r in gone for n in r.get('nics') or [] for ip in nics.get(n['id'].lower(), [])}
    dns_hits = {a['ipv4Address'] for z in dns.values() for rec in (z.get('data') or {}).get('value', [])
                for a in rec['properties'].get('aRecords', []) if a['ipv4Address'] in ips}
    dns_ok = all(z.get('http') == 200 for z in dns.values())
    cost = _month_cost(ws, {r['id'].lower() for r in gone})
    groups = defaultdict(list)
    for r in gone:
        groups[subname.get(r['subscriptionId'].lower(), r['subscriptionId'])].append(r)
    for i, (sub, rows) in enumerate(sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])), 1):
        _add_group(add, cfg, sub, rows, i, pes, disc, activity, nics, dns_hits, dns_ok, cost, month_label)
    notes = (f'读取全部 {len(pes)} 个私有终结点的连接状态；对 {len(disc)} 个已断开的，核对目标资源是否存在、私有 DNS 记录和近 90 天删除记录。'
             + (f'其中 {len(disc) - len(gone)} 个的目标资源仍存在，未列为问题。' if len(disc) > len(gone) else ''))
    coverage = {'attempted': len(pes), 'succeeded': len(pes) if pes_rec.get('http') == 200 else 0,
                'denied': 0 if pes_rec.get('http') != 403 else 1, 'otherErrors': 0, 'notes': [notes]}
    summary = {'privateEndpoints': len(pes), 'disconnected': len(disc), 'targetsDeleted': len({r['target'] for r in gone}),
               'monthCostUSD': round(sum(cost.values()), 2) if cost is not None else None}
    return coverage, summary


def _add_group(add, cfg, sub, rows, i, pes, disc, activity, nics, dns_hits, dns_ok, cost, month_label):
    by_target = defaultdict(list)
    for r in rows:
        by_target[r['target']].append(r['name'])
    many = len(rows) > 1
    standard = [r['name'] for r in rows if cfg.created_by_standard(r.get('tags'))]
    lead = (f'{sub} 有 {len(rows)} 个私有终结点的连接状态为“已断开”，它们连接的目标资源都已删除：' if many
            else f'{sub} 有 1 个私有终结点的连接状态为“已断开”，它连接的目标资源已删除：')
    this, that = ('这些终结点', '这些终结点') if many else ('该终结点', '它')
    row_ips = {ip for r in rows for n in r.get('nics') or [] for ip in nics.get(n['id'].lower(), [])}
    if not dns_ok:
        dns_text = '私有 DNS 记录未能全部读取'
    elif row_ips & dns_hits:
        dns_text = f'私有 DNS 中仍有记录指向{this}'
    else:
        dns_text = f'私有 DNS 中已没有指向{this}的记录'
    if cost is None:
        cost_text = '按小时计费'
    else:
        month_cost = sum(cost.get(r['id'].lower(), 0) for r in rows)
        cost_text = f'按小时计费（{month_label}实际费用 USD {month_cost:,.2f}）'
    finding = lead + _target_text(by_target, activity) + f'。{dns_text}，但{that}仍占用子网 IP 并{cost_text}。'
    rec = RECOMMEND
    if standard:
        tag = f'{cfg.standard_tag.get("key")}={cfg.standard_tag.get("value")}'
        finding += f'其中 {"、".join(standard)} 带有 {tag} 标签。' if many else f'该终结点带有 {tag} 标签。'
        rec += STANDARD_NOTE
    envs = [env_of(cfg, sub, r['name'], r.get('tags')) for r in rows]
    item = add('S-N8', '低', finding, rec, subscription=sub, resource_group='、'.join(sorted({r['resourceGroup'] for r in rows})),
               resource_name=f'{len(rows)} 个私有终结点' if many else rows[0]['name'], resource_type=TYPE,
               resource_id=None if many else rows[0]['id'], environment=mixed_env(envs),
               evidence={'items': [{'resourceName': r['name'], 'target': r['target'],
                                    'createdIp': [ip for n in r.get('nics') or [] for ip in nics.get(n['id'].lower(), [])],
                                    'monthCostUSD': round(cost.get(r['id'].lower(), 0), 2) if cost is not None else None}
                                   for r in sorted(rows, key=lambda r: r['name'])]},
               needs_confirmation='请确认这些终结点是否还有用途（例如准备重建同名资源）；没有用途即可删除。',
               members=[{'name': r['name'], 'type': TYPE, 'subscription': sub} for r in rows],
               key='disconnected-private-endpoints', legacy_id=f'SN-PE-{i:02d}')
    item['difference'] = f'全部 {len(pes)} 个私有终结点中，{len(pes) - len(disc)} 个连接正常（已批准）；这 {len(disc)} 个的目标资源已删除。'
    item['rootCause'] = ('删除目标资源时没有一并删除私有终结点；目标资源删除后，Azure 不会自动删除指向它的终结点，只会把连接标为“已断开”。'
                         + ('终结点由部署模板管理，目标资源删除后模板未同步清理。' if standard else ''))
    item['alignment'] = '删除 Redis、存储账户、数据库时同时删除其私有终结点；用部署模板（如 Terraform）管理的，把终结点和目标资源放在同一模块，随目标一起删除。'
