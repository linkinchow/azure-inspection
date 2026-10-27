"""APRL (Azure Proactive Resiliency Library) whitelist: run the reviewed Resource Graph queries read-only.

The queries are data files in <skill>/vendor/aprl/kql (MIT, fixed commit in VERSION.json); they are sent as Resource
Graph queries through the read-only client and never executed any other way. Rows become findings under our own
check codes (rules.py), one finding per rule and subscription.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ..common import Findings, Raw, coverage_entry, enabled, env, load_scope, now
from .rules import LOWER, RULES

VENDOR = Path(__file__).resolve().parents[4] / 'vendor' / 'aprl'
KEEP = ('id', 'name', 'tags', 'param1', 'param2', 'param3', 'param4', 'param5')


def version() -> dict:
    import json
    return json.loads((VENDOR / 'VERSION.json').read_text(encoding='utf-8'))


def collect(ws, cfg, client, window, log=print):
    raw = Raw(ws, 'aprl')
    subs = [s['id'] for s in enabled(load_scope(ws))]
    meta, results = version(), []
    for guid in RULES:
        query = (VENDOR / 'kql' / f'{guid}.kql').read_text(encoding='utf-8')
        rows, status, error = client.arg(query, subs, 'aprl', guid)
        results.append({'aprlGuid': guid, 'status': status, 'error': error,
                        'rows': [{k: r.get(k) for k in KEEP if k in r} for r in rows or []]})
    raw.save('results.json', {'collectedAt': now(), 'aprlCommit': meta['commit'], 'results': results})
    raw.save('manifest.json', {'collectedAt': now(), 'window': window})
    failed = [r['aprlGuid'][:8] for r in results if r['status'] != 200]
    log(f'APRL：执行 {len(results)} 条白名单查询，命中 {sum(1 for r in results if r["rows"])} 条' + (f'；{len(failed)} 条失败' if failed else ''))


def _sub_of(resource_id: str) -> str:
    parts = str(resource_id or '').split('/')
    return parts[2].lower() if len(parts) > 2 and parts[1].lower() == 'subscriptions' else ''


def _rg_of(resource_id: str):
    parts = str(resource_id or '').split('/')
    lower = [p.lower() for p in parts]
    return parts[lower.index('resourcegroups') + 1] if 'resourcegroups' in lower else None


def _label(row, guid):
    """Display name; node pool rules name the pool."""
    name = row.get('name') or ''
    detail = str(row.get('param1') or '')
    if guid in ('902c82ff-4910-4b61-942d-0d6ef7f39b67', '005ccbbd-aeab-46ef-80bd-9bd4479412ec') and ': ' in detail:
        return f'{name}/{detail.split(": ", 1)[1]}'
    return name


def analyze(ws, cfg, log=print):
    raw = Raw(ws, 'aprl')
    data = raw.load('results.json')
    manifest = raw.load('manifest.json') or {}
    subs = {s['id'].lower(): s['name'] for s in load_scope(ws)}
    meta = version()
    links = {r['aprlGuid']: r['learnMoreLink'] for r in meta['rules']}
    findings, coverage = Findings('aprl'), {}
    for result in data['results']:
        guid, rule = result['aprlGuid'], RULES.get(result['aprlGuid'])
        if not rule:
            continue
        c = coverage.setdefault(rule['check'], coverage_entry())
        c['attempted'] += 1
        if result['status'] == 200:
            c['succeeded'] += 1
        else:
            c['denied' if result['status'] in (401, 403) else 'otherErrors'] += 1
            c['notes'].append(f'APRL {guid[:8]} 查询失败：{result.get("error")}')
            continue
        groups = defaultdict(list)
        for row in result['rows']:
            groups[_sub_of(row.get('id'))].append(row)
        for sid, rows in sorted(groups.items(), key=lambda kv: subs.get(kv[0], kv[0])):
            sub = subs.get(sid, sid)
            envs = [env(cfg, sub, r.get('name'), r.get('tags') if isinstance(r.get('tags'), dict) else None) for r in rows]
            nonprod = all(e['value'] in ('test', 'dev') for e in envs)
            severity = LOWER[rule['severity']] if nonprod else rule['severity']
            names = sorted({_label(r, guid) for r in rows})
            shown = '、'.join(names[:3]) + (f' 等 {len(names)} 个' if len(names) > 3 else '')
            environment = envs[0] if len({e['value'] for e in envs}) == 1 else {'value': 'mixed', 'label': '多个环境', 'basis': '见涉及资源'}
            findings.add(rule['check'], severity, f'{rule["finding"]}：{shown}。（APRL 建议 {guid[:8]}）',
                         f'{rule["recommendation"]}。参考：{links.get(guid)}',
                         subscription=sub, resource_group=_rg_of(rows[0].get('id')) if len(rows) == 1 else None,
                         resource_name=names[0] if len(names) == 1 else f'{len(names)} 个资源', resource_type=rule['type'],
                         resource_id=rows[0].get('id') if len(rows) == 1 else None, environment=environment,
                         evidence={'aprlGuid': guid, 'learnMoreLink': links.get(guid), 'aprlCommit': data.get('aprlCommit'),
                                   'rows': [{k: v for k, v in r.items() if k != 'tags'} for r in rows]},
                         members=[{'name': n, 'type': rule['type'], 'subscription': sub} for n in names], key=guid)
    for c in coverage.values():
        c['notes'].insert(0, f'APRL 白名单查询（提交 {meta["commit"][:12]}，{meta["commitDate"]}）；测试和开发资源降一级。')
    out = findings.write(ws, window=manifest.get('window'), coverage=coverage,
                         scope={'subscriptions': len(subs)}, extra={'aprlCommit': meta['commit']})
    log(f'APRL：{len(out["findings"])} 项问题')
    return out
