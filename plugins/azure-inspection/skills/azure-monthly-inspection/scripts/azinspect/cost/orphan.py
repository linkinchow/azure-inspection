"""Orphaned resources (Azure Orphan Resources queries, MIT, fixed commit in <skill>/vendor/orphan): read-only Resource Graph.

The KQL is sent as a Resource Graph query through the read-only client. Unattached disks, unassociated public IPs and
NICs are already found by review.waste_review, disconnected private endpoints by the S-N8 check, so they are skipped.
Results are listed as "待确认用途" (never deleted, no saving claimed); they merge into the 01 idle-resource sheet.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..core.io import read_json, write_json

VENDOR = Path(__file__).resolve().parents[3] / 'vendor' / 'orphan' / 'queries.json'
SKIP = {'managed-disks', 'public-ips', 'network-interfaces', 'private-endpoints'}
LABELS = {
    'app-service-plans': '没有应用的应用服务计划', 'availability-set': '没有虚拟机的可用性集', 'sql-elastic-pool': '没有数据库的 SQL 弹性池',
    'network-security-groups': '未关联子网或网卡的 NSG', 'route-tables': '未关联子网的路由表',
    'load-balancers': '没有后端池和入站 NAT 规则的负载均衡', 'front-door-waf-policy': '未关联 Front Door 的 WAF 策略',
    'traffic-manager-profiles': '没有终结点的流量管理器', 'application-gateways': '后端池没有目标的应用网关',
    'virtual-networks': '没有子网的虚拟网络', 'subnets': '没有连接设备的空子网', 'nat-gateways': '未关联子网的 NAT 网关',
    'ip-groups': '未被防火墙使用的 IP 组', 'private-dns-zones': '没有关联虚拟网络的私有 DNS 区域',
    'virtual-network-gateways': '没有连接的虚拟网络网关', 'ddos-protections': '没有保护任何虚拟网络的 DDoS 防护计划',
    'resource-groups': '空资源组', 'api-connections': '未被逻辑应用使用的 API 连接', 'certificates': '已过期的证书',
}
# Resources that still cost money while idle (others are free or nearly free; listed for tidiness only).
CHARGED = {'app-service-plans', 'sql-elastic-pool', 'load-balancers', 'application-gateways', 'nat-gateways',
           'virtual-network-gateways', 'ddos-protections', 'traffic-manager-profiles'}


def queries():
    data = json.loads(VENDOR.read_text(encoding='utf-8'))
    return data, [q for q in data['queries'] if q['key'] not in SKIP and q['key'] in LABELS]


def collect(ws, client, subscription_ids, log=print):
    meta, todo = queries()
    results = []
    for q in todo:
        # drop the pack_all() Details column: it repeats every property and is not needed
        rows, status, error = client.arg(q['kql'] + '\n| project-away Details', subscription_ids, 'orphan', q['key'])
        if status == 400 and rows is None:   # queries without a Details column
            rows, status, error = client.arg(q['kql'], subscription_ids, 'orphan', q['key'])
        keep = [{k: r.get(k) for k in ('subscriptionId', 'Resource', 'id', 'name', 'resourceGroup', 'location', 'Sku', 'Tier') if k in r}
                for r in rows or []]
        results.append({'key': q['key'], 'status': status, 'error': error, 'rows': keep})
    out = {'collectedAt': datetime.now(timezone.utc).isoformat(), 'commit': meta['commit'], 'results': results}
    write_json(ws.raw('cost/orphan.json'), out)
    hits = sum(len(r['rows']) for r in results)
    failed = [r['key'] for r in results if r['status'] != 200]
    log(f'孤立资源查询：{len(results)} 类，发现 {hits} 个待确认资源' + (f'；{len(failed)} 类查询失败' if failed else ''))
    return out


def findings(ws, subscription_names):
    """Rows in the format of review.waste_review, plus counts by category."""
    path = ws.raw('cost/orphan.json')
    if not path.exists():
        return [], Counter(), None
    data = read_json(path)
    rows, counts = [], Counter()
    for r in data['results']:
        if r['status'] != 200:
            continue
        for x in r['rows']:
            rid = x.get('Resource') or x.get('id') or ''
            name = x.get('name') or rid.rstrip('/').split('/')[-1]
            category = f'orphan:{r["key"]}'
            counts[category] += 1
            rows.append({'category': category, 'resourceId': rid, 'name': name,
                         'subscriptionName': subscription_names.get(str(x.get('subscriptionId') or '').lower()),
                         'resourceGroup': x.get('resourceGroup'), 'region': x.get('location'), 'charged': r['key'] in CHARGED})
    return rows, counts, data


def label(category):
    key = category.split(':', 1)[1] if category.startswith('orphan:') else category
    return LABELS.get(key)
