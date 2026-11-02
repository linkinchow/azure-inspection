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


def _member(resource_id, subs):
    """A resource with its subscription's name; a subscription itself is named, not shown as its ID."""
    parts = str(resource_id or '').split('/')
    sub = subs.get(parts[2].lower()) if len(parts) > 2 and parts[1].lower() == 'subscriptions' else None
    rtype = _type(resource_id)
    name = sub if rtype == 'Microsoft.Resources/subscriptions' and sub else _name(resource_id)
    return {'name': name, 'type': rtype, 'subscription': sub}


def _type(resource_id):
    parts = str(resource_id or '').split('/')
    lower = [p.lower() for p in parts]
    if 'providers' not in lower:
        return 'Microsoft.Resources/subscriptions'
    i = len(lower) - 1 - lower[::-1].index('providers')
    return '/'.join(parts[i + 1:i + 3])


def _from_identity(ws, skip=()):
    """Unhealthy High/Medium assessments from the security_identity pillar (Defender assessments API, per subscription),
    for the subscriptions not in `skip`.

    Used for the subscriptions Resource Graph's securityresources table returned nothing for (seen in practice: 0 rows
    for an account while the per-subscription API returns hundreds of recommendations; and on a large tenant, rows for a
    few subscriptions only).
    """
    rows, files = [], []
    for path in sorted(Raw(ws, 'security_identity').path('defender').glob('assessments_*.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        if str(data.get('subscriptionId')).lower() in skip:
            continue
        files.append(path)
        for a in data.get('assessments') or []:
            if a.get('status') == 'Unhealthy' and a.get('severity') in ('High', 'Medium'):
                rows.append({'subscriptionId': data['subscriptionId'], 'displayName': a.get('displayName'), 'severity': a['severity'],
                             'resourceId': a.get('resourceId'), 'firstUnhealthy': a.get('firstEvaluationDate'),
                             'statusChange': a.get('statusChangeDate'), 'link': None})
    return rows, files


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
    got = {str(r.get('subscriptionId')).lower() for r in assessments}
    # Resource Graph may answer for some subscriptions only: the others come from the per-subscription Defender API
    left_out = [s for s in enabled(load_scope(ws)) if s['id'].lower() not in got]
    if left_out:
        extra, files = _from_identity(ws, skip=got)
        assessments = assessments + extra
        filled = {path.stem.split('_', 1)[1].lower() for path in files}
        missing = [s['name'] for s in left_out if s['id'].lower() not in filled]
        if files and not got:
            c['notes'].append(f'Resource Graph 的 securityresources 表没有返回 Defender 建议，改用按订阅读取的 Defender 评估接口（与 S-I4 同一来源，{len(files)} 个订阅）')
        elif files:
            c['filled'] = {'resourceGraph': len(got), 'perSubscription': len(files)}
            c['notes'].append(f'Resource Graph 只返回了 {len(got)} 个订阅的 Defender 建议，其余 {len(files)} 个订阅改用按订阅读取的 Defender 评估接口补上'
                              '（与 S-I4 同一来源）')
        if missing and data['assessments']['status'] == 200:
            c['otherErrors'] += 1   # what was not read is not resolved (tracking reads this as a failed read)
            shown = '、'.join(missing[:5]) + (f' 等 {len(missing)} 个' if len(missing) > 5 else '')
            c['notes'].append(f'订阅 {shown} 的 Defender 建议 Resource Graph 没有返回，也没有按订阅读取的数据（安全检查的身份部分没有采集），可能有遗漏')
    undated = not any(r.get('firstUnhealthy') for r in assessments)
    if undated and assessments:
        c['notes'].append('未取得建议的首次发现时间，无法判断已持续多久：只列出高严重性建议')
    stale = defaultdict(list)
    for r in assessments:
        age = _days(r.get('firstUnhealthy'), end)
        if (age is not None and age > STALE_DAYS) or (undated and r['severity'] == 'High'):
            stale[(r['displayName'], r['severity'])].append({**r, 'age': age})
    for (title, sev), rows in sorted(stale.items(), key=lambda kv: (kv[0][1] != 'High', -len(kv[1]), kv[0][0])):
        names = sorted({_member(r['resourceId'], subs)['name'] for r in rows})
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
                     members=[_member(r['resourceId'], subs) for r in rows],
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
                     members=[_member(rid, subs) for rid in resources],
                     key=f'policy|{assignment}')
    c['notes'].insert(0, f'Defender 建议只列出超过 {STALE_DAYS} 天未处理的高、中严重性建议（中严重性只看生产）；'
                         f'Policy 只列出客户已分配策略的不合规资源。')
    out = findings.write(ws, window=manifest.get('window'), coverage=cov, scope={'subscriptions': len(subs)})
    log(f'Defender/Policy：{len(out["findings"])} 项问题')
    return out
