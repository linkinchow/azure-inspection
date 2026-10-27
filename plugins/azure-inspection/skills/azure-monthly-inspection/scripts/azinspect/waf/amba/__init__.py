"""O2 against the Azure Monitor Baseline Alerts (AMBA, MIT, fixed commit in <skill>/vendor/amba).

Offline only: reads the operations pillar's resource list and alert rules (raw/waf/operations/arg/*.json).
- inventory.recommendedAlerts: the core AMBA metric alerts per resource type, with AMBA's thresholds (Excel sheet in 04).
- findings (O2, 低): production resources that already have some metric alerts but miss core recommended metrics.
  Resources with no alerts at all are reported by the operations pillar's O2 check, so they are not repeated here.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from ..checks import type_label
from ..common import Findings, Raw, env, load_scope

VENDOR = Path(__file__).resolve().parents[4] / 'vendor' / 'amba' / 'alerts.json'
# Core metrics per type (chosen from AMBA for availability, saturation and errors); thresholds come from AMBA.
CORE = {
    'microsoft.containerservice/managedclusters': ['node_cpu_usage_percentage', 'node_memory_working_set_percentage', 'node_disk_usage_percentage',
                                                   'kube_node_status_condition', 'kube_pod_status_ready'],
    'microsoft.dbformysql/flexibleservers': ['cpu_percent', 'memory_percent', 'storage_percent', 'io_consumption_percent', 'active_connections',
                                             'replication_lag'],
    'microsoft.dbforpostgresql/flexibleservers': ['cpu_percent', 'memory_percent', 'storage_percent', 'active_connections', 'is_db_alive',
                                                  'disk_iops_consumed_percentage'],
    'microsoft.cache/redis': ['serverLoad', 'usedmemorypercentage', 'connectedclients', 'errors'],
    'microsoft.network/applicationgateways': ['UnhealthyHostCount', 'FailedRequests', 'BackendLastByteResponseTime', 'CapacityUnits'],
    'microsoft.cdn/profiles': ['OriginHealthPercentage', 'Percentage5XX', 'TotalLatency'],
    'microsoft.keyvault/vaults': ['Availability', 'SaturationShoebox', 'ServiceApiLatency'],
    'microsoft.storage/storageaccounts': ['Availability', 'UsedCapacity'],
    'microsoft.compute/virtualmachines': ['Percentage CPU', 'Available Memory Bytes', 'VmAvailabilityMetric', 'OS Disk IOPS Consumed Percentage',
                                          'Data Disk IOPS Consumed Percentage'],
    'microsoft.network/loadbalancers': ['VipAvailability', 'DipAvailability', 'UsedSNATPorts'],
    'microsoft.network/virtualnetworkgateways': ['ExpressRouteGatewayCpuUtilization', 'ExpressRouteGatewayBitsPerSecond', 'TunnelEgressPacketDropCount'],
    'microsoft.eventhub/namespaces': ['ThrottledRequests', 'ServerErrors', 'QuotaExceededErrors'],
    'microsoft.network/natgateways': ['DatapathAvailability', 'PacketDropCount'],
    'microsoft.network/azurefirewalls': ['FirewallHealth', 'SNATPortUtilization'],
    'microsoft.cognitiveservices/accounts': ['AzureOpenAITimeToResponse', 'AzureOpenAIProvisionedManagedUtilizationV2'],
}
OPERATORS = {'GreaterThan': '>', 'GreaterThanOrEqual': '≥', 'LessThan': '<', 'LessThanOrEqual': '≤'}


def baseline():
    data = json.loads(VENDOR.read_text(encoding='utf-8'))
    out = {}
    for rtype, metrics in CORE.items():
        rows = {}
        for a in data['alerts'].get(rtype, []):
            if a['metricName'] in metrics and a['metricName'] not in rows:
                rows[a['metricName']] = a
        out[rtype] = [rows[m] for m in metrics if m in rows]
    return data, out


def collect(ws, cfg, client, window, log=print):
    """Nothing to read: the operations pillar already collected resources and alert rules."""
    Raw(ws, 'amba').save('manifest.json', {'window': window, 'source': 'raw/waf/operations/arg'})


def _rows(raw, name):
    data = raw.load(f'arg/{name}.json') or raw.load(f'raw/arg/{name}.json') or {}
    return data.get('rows') if isinstance(data, dict) else data


def analyze(ws, cfg, log=print):
    meta, core = baseline()
    ops = Raw(ws, 'operations')
    resources, rules = _rows(ops, 'resources') or [], _rows(ops, 'alertrules') or []
    subs = {s['id'].lower(): s['name'] for s in load_scope(ws)}
    covered = defaultdict(set)   # resource id -> metric names with an enabled metric alert
    for r in rules:
        p = r.get('properties') or {}
        if str(r.get('type')).lower() != 'microsoft.insights/metricalerts' or not p.get('enabled'):
            continue
        metrics = {c.get('metricName') for c in ((p.get('criteria') or {}).get('allOf') or [])}
        target = (p.get('targetResourceType') or '').lower()
        for scope in (x.lower() for x in p.get('scopes') or []):
            for res in resources:
                rid = res['id'].lower()
                if rid == scope or ((rid.startswith(scope + '/')) and res['type'].lower() == target):
                    covered[rid] |= metrics
    findings = Findings('amba')
    gaps = defaultdict(list)
    for res in resources:
        rtype, rid = res['type'].lower(), res['id'].lower()
        if rtype not in core or rid not in covered:
            continue
        sub = subs.get(str(res['subscriptionId']).lower(), res['subscriptionId'])
        e = env(cfg, sub, res['name'], res.get('tags') if isinstance(res.get('tags'), dict) else None)
        if e['value'] != 'prod':
            continue
        missing = [a['metricName'] for a in core[rtype] if a['metricName'] not in covered[rid]]
        if missing:
            gaps[(rtype, sub)].append((res, missing, e))
    for (rtype, sub), items in sorted(gaps.items()):
        label = type_label(rtype)
        detail = '；'.join(f'{res["name"]} 缺少 {"、".join(m)}' for res, m, _ in items[:5]) + (f' 等 {len(items)} 个' if len(items) > 5 else '')
        findings.add('O2', '低', f'{len(items)} 个生产{label}已有部分指标告警，但缺少 AMBA 推荐的核心告警：{detail}',
                     '按 Excel“推荐告警（AMBA）”补齐核心告警，阈值可先用推荐值，运行一段时间后按实际情况调整',
                     subscription=sub, resource_name=items[0][0]['name'] if len(items) == 1 else f'{len(items)} 个{label}',
                     resource_type=items[0][0]['type'], environment=items[0][2],
                     evidence={'missing': {res['name']: m for res, m, _ in items}, 'ambaCommit': meta['commit']},
                     members=[{'name': res['name'], 'type': res['type'], 'subscription': sub} for res, _, _ in items], key=f'amba|{rtype}')
    recommended = [{'resourceType': rtype, 'label': type_label(rtype), 'metric': a['metricName'], 'description': a.get('description'),
                    'condition': f'{a.get("aggregation") or ""} {OPERATORS.get(a.get("operator"), a.get("operator") or "")} {a.get("threshold")}'.strip()
                    if a.get('criterion') != 'DynamicThresholdCriterion' else '动态阈值',
                    'window': a.get('windowSize'), 'severity': a.get('severity')}
                   for rtype, alerts in core.items() for a in alerts]
    manifest = Raw(ws, 'amba').load('manifest.json') or {}
    out = findings.write(ws, window=manifest.get('window'), coverage={'O2': {'attempted': 1, 'succeeded': 1 if resources else 0, 'denied': 0,
                                                                              'otherErrors': 0 if resources else 1,
                                                                              'notes': [f'与 AMBA 推荐告警对比（提交 {meta["commit"][:12]}）；只看已有部分告警的生产资源']}},
                         scope={'subscriptions': len(subs)}, inventory={'recommendedAlerts': recommended}, extra={'ambaCommit': meta['commit']})
    log(f'AMBA：{len(out["findings"])} 项问题，推荐告警 {len(recommended)} 条')
    return out
