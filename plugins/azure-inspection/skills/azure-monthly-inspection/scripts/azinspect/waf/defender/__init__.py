"""S-I11: Defender for Cloud recommendations and Azure Policy compliance, resource by resource (Resource Graph, read-only).

S-I4 already counts open high-severity recommendations per subscription; here each high-severity recommendation that has
been unhealthy for more than STALE_DAYS becomes one finding listing its resources, so the customer can assign it.
Policy: one finding per assignment with non-compliant resources (deny/audit effects only show what the customer decided
to enforce, so these are the customer's own rules).
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone

from ..common import Findings, Raw, coverage_entry, enabled, env, load_scope, mixed_env, now

STALE_DAYS = 30
SEVERITY = {'High': '中', 'Medium': '低'}   # our level for long-open Defender recommendations
ASSESSMENTS = """securityresources
| where type == 'microsoft.security/assessments'
| where tostring(properties.status.code) == 'Unhealthy'
| extend severity = tostring(properties.metadata.severity)
| where severity in ('High', 'Medium')
| project subscriptionId, assessmentKey = name, displayName = tostring(properties.displayName), severity,
          resourceId = tostring(properties.resourceDetails.Id), firstUnhealthy = tostring(properties.status.firstEvaluationDate),
          statusChange = tostring(properties.status.statusChangeDate), link = tostring(properties.links.azurePortal)"""
POLICY = """policyresources
| where type == 'microsoft.policyinsights/policystates'
| where tostring(properties.complianceState) == 'NonCompliant'
| project subscriptionId, resourceId = tostring(properties.resourceId), assignment = tostring(properties.policyAssignmentName),
          assignmentScope = tostring(properties.policyAssignmentScope), definition = tostring(properties.policyDefinitionName),
          effect = tostring(properties.policyDefinitionAction)"""
ASSIGNMENTS = """policyresources
| where type == 'microsoft.authorization/policyassignments'
| project id, name, displayName = tostring(properties.displayName), scope = tostring(properties.scope)"""


def collect(ws, cfg, client, window, log=print):
    raw = Raw(ws, 'defender')
    subs = [s['id'] for s in enabled(load_scope(ws))]
    out = {}
    for key, query in (('assessments', ASSESSMENTS), ('policyStates', POLICY), ('policyAssignments', ASSIGNMENTS)):
        rows, status, error = client.arg(query, subs, 'S-I11', key)
        out[key] = {'status': status, 'error': error, 'rows': rows or []}
    raw.save('results.json', {'collectedAt': now(), **out})
    raw.save('manifest.json', {'collectedAt': now(), 'window': window})
    log(f'Defender/Policy：未处理的高、中严重性建议 {len(out["assessments"]["rows"])} 条记录，不合规的策略状态 {len(out["policyStates"]["rows"])} 条')


def _name(resource_id):
    return str(resource_id or '').rstrip('/').split('/')[-1]


def _type(resource_id):
    parts = str(resource_id or '').split('/')
    lower = [p.lower() for p in parts]
    if 'providers' not in lower:
        return 'Microsoft.Resources/subscriptions'
    i = len(lower) - 1 - lower[::-1].index('providers')
    return '/'.join(parts[i + 1:i + 3])


def _from_identity(ws):
    """Unhealthy High/Medium assessments from the security_identity pillar (Defender assessments API, per subscription).

    Used when Resource Graph's securityresources table returns nothing for this account (seen in practice: the query
    succeeds with 0 rows while the per-subscription API returns hundreds of recommendations).
    """
    rows, files = [], sorted(Raw(ws, 'security_identity').path('defender').glob('assessments_*.json'))
    for path in files:
        data = json.loads(path.read_text(encoding='utf-8'))
        for a in data.get('assessments') or []:
            if a.get('status') == 'Unhealthy' and a.get('severity') in ('High', 'Medium'):
                rows.append({'subscriptionId': data['subscriptionId'], 'displayName': a.get('displayName'), 'severity': a['severity'],
                             'resourceId': a.get('resourceId'), 'firstUnhealthy': a.get('firstEvaluationDate'),
                             'statusChange': a.get('statusChangeDate'), 'link': None})
    return rows, len(files)


def _days(value, end):
    try:
        return (end - datetime.fromisoformat(str(value).replace('Z', '+00:00'))).days
    except ValueError:
        return None


def analyze(ws, cfg, log=print):
    raw = Raw(ws, 'defender')
    data, manifest = raw.load('results.json'), raw.load('manifest.json') or {}
    subs = {s['id'].lower(): s['name'] for s in load_scope(ws)}
    end = datetime.fromisoformat(str((manifest.get('window') or {}).get('end') or data['collectedAt']).replace('Z', '+00:00'))
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    findings, cov = Findings('defender'), {'S-I11': coverage_entry()}
    c = cov['S-I11']
    for key in ('assessments', 'policyStates'):
        c['attempted'] += 1
        status = data[key]['status']
        if status == 200:
            c['succeeded'] += 1
        else:
            c['denied' if status in (401, 403) else 'otherErrors'] += 1
            c['notes'].append(f'{key} 读取失败：{data[key].get("error")}')

    assessments = data['assessments']['rows']
    if not assessments:
        assessments, files = _from_identity(ws)
        if files:
            c['notes'].append(f'Resource Graph 的 securityresources 表没有返回 Defender 建议，改用按订阅读取的 Defender 评估接口（与 S-I4 同一来源，{files} 个订阅）')
    undated = not any(r.get('firstUnhealthy') for r in assessments)
    if undated and assessments:
        c['notes'].append('未取得建议的首次发现时间，无法判断已持续多久：只列出高严重性建议')
    stale = defaultdict(list)
    for r in assessments:
        age = _days(r.get('firstUnhealthy'), end)
        if (age is not None and age > STALE_DAYS) or (undated and r['severity'] == 'High'):
            stale[(r['displayName'], r['severity'])].append({**r, 'age': age})
    for (title, sev), rows in sorted(stale.items(), key=lambda kv: (kv[0][1] != 'High', -len(kv[1]), kv[0][0])):
        names = sorted({_name(r['resourceId']) for r in rows})
        subs_hit = sorted({subs.get(str(r['subscriptionId']).lower(), r['subscriptionId']) for r in rows})
        envs = [env(cfg, subs.get(str(r['subscriptionId']).lower(), ''), _name(r['resourceId'])) for r in rows]
        if all(e['value'] in ('test', 'dev') for e in envs) and sev == 'Medium':
            continue
        ages = [r['age'] for r in rows if r['age'] is not None]
        how_long = f'已超过 {STALE_DAYS} 天未处理（最长 {max(ages)} 天）' if ages else '未处理'
        oldest = max(ages) if ages else None
        findings.add('S-I11', SEVERITY[sev],
                     f'Defender for Cloud {"高" if sev == "High" else "中"}严重性建议“{title}”{how_long}，'
                     f'涉及 {len(names)} 个资源，分布在 {len(subs_hit)} 个订阅',
                     '在 Defender for Cloud 中按建议的修复步骤处理；确实不适用的设为豁免并写明原因，避免长期挂在未处理列表中',
                     subscription=subs_hit[0] if len(subs_hit) == 1 else f'多个订阅（{len(subs_hit)} 个）',
                     resource_name=names[0] if len(names) == 1 else f'{len(names)} 个资源', environment=mixed_env(envs),
                     evidence={'recommendation': title, 'severity': sev, 'oldestDays': oldest, 'subscriptions': subs_hit,
                               'portalLink': rows[0].get('link')},
                     members=[{'name': _name(r['resourceId']), 'type': _type(r['resourceId']),
                               'subscription': subs.get(str(r['subscriptionId']).lower())} for r in rows],
                     key=f'defender|{title}')
    if assessments and not stale:
        c['notes'].append(f'未处理的建议都在 {STALE_DAYS} 天以内')

    names = {a['name']: a.get('displayName') or a['name'] for a in data['policyAssignments']['rows']}
    by_assignment = defaultdict(list)
    for r in data['policyStates']['rows']:
        by_assignment[r['assignment']].append(r)
    for assignment, rows in sorted(by_assignment.items(), key=lambda kv: -len(kv[1])):
        resources = sorted({r['resourceId'] for r in rows})
        subs_hit = sorted({subs.get(str(r['subscriptionId']).lower(), r['subscriptionId']) for r in rows})
        effects = sorted({str(r.get('effect') or '') for r in rows} - {''})
        findings.add('S-I11', '低',
                     f'Azure Policy 分配“{names.get(assignment, assignment)}”有 {len(resources)} 个不合规资源，分布在 {len(subs_hit)} 个订阅'
                     + (f'（效果：{"、".join(effects)}）' if effects else ''),
                     '确认这条策略是否仍是要执行的标准：是则按策略修正这些资源，否则调整策略范围或设为豁免',
                     subscription=subs_hit[0] if len(subs_hit) == 1 else f'多个订阅（{len(subs_hit)} 个）',
                     resource_name=f'{len(resources)} 个资源', environment={'value': 'mixed', 'label': '多个环境', 'basis': '见涉及资源'},
                     evidence={'assignment': assignment, 'definitions': sorted({r['definition'] for r in rows})[:20]},
                     members=[{'name': _name(rid), 'type': _type(rid), 'subscription': None} for rid in resources],
                     key=f'policy|{assignment}')
    c['notes'].insert(0, f'Defender 建议只列出超过 {STALE_DAYS} 天未处理的高、中严重性建议（中严重性只看生产）；'
                         f'Policy 只列出客户已分配策略的不合规资源。')
    out = findings.write(ws, window=manifest.get('window'), coverage=cov, scope={'subscriptions': len(subs)})
    log(f'Defender/Policy：{len(out["findings"])} 项问题')
    return out
