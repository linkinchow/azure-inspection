"""Month-over-month tracking of 03/04 findings.

Each build stores this month's findings (stable ids) in state/months/<YYYY-MM>.json, overwriting a rerun of the same
month, and compares with the latest earlier month:
- 新增问题: id not seen last month and its check already ran last month (the problem is new);
- 新增检查项发现: the check did not exist or did not run last month (new coverage, not a new problem);
- 仍未处理: id in both months (severity changes are listed);
- 已解决: id last month, absent now, and its check ran successfully this month;
- 本月未检查: id last month, absent now, but its check failed or was not run this month (never counted as resolved).
Customer decisions (负责人、客户决定、处理状态) come from the customer's Excel and are not read here.
"""
from __future__ import annotations

from .core.io import read_json, write_json
from .waf.checks import CHECKS, report_of
from .waf.common import PILLARS


def current(ws):
    findings, ran = {}, set()
    base = ws.month_dir('findings') / 'waf'
    for pillar in PILLARS:
        path = base / f'{pillar}.json'
        if not path.exists():
            continue
        data = read_json(path)
        # a check is identified by its source module too: APRL rows under R3 or AMBA rows under O2 are new coverage
        for check, c in (data.get('coverage') or {}).items():
            if (c.get('succeeded') or 0) > 0:
                ran.add(f'{pillar}:{check}')
        for f in data['findings']:
            findings[f['id']] = {'check': f['check'], 'source': pillar, 'severity': f['severity'], 'subscription': f.get('subscriptionName'),
                                 'resource': f.get('resourceName'), 'finding': f['finding'][:200]}
            ran.add(f'{pillar}:{f["check"]}')
    return findings, ran


def _key(f):
    return f'{f.get("source")}:{f["check"]}'


def previous_month(ws):
    months = sorted(p.stem for p in (ws.state_dir / 'months').glob('*.json') if p.stem < ws.month)
    return months[-1] if months else None


def update(ws, log=print):
    findings, ran = current(ws)
    write_json(ws.state_dir / 'months' / f'{ws.month}.json', {'month': ws.month, 'findings': findings, 'checksRun': sorted(ran)})
    prev_month = previous_month(ws)
    if not prev_month:
        out = {'month': ws.month, 'previous': None, 'first': True}
        write_json(ws.month_dir('findings') / 'tracking.json', out)
        log('跨月跟踪：这是第一次记录，下个月起与本月对比')
        return out
    prev = read_json(ws.state_dir / 'months' / f'{prev_month}.json')
    before, ran_before = prev['findings'], set(prev.get('checksRun') or [])
    rows = []
    for fid, f in findings.items():
        if fid in before:
            old = before[fid]['severity']
            rows.append({**f, 'id': fid, 'status': '仍未处理', 'previousSeverity': old if old != f['severity'] else None})
        else:
            rows.append({**f, 'id': fid, 'status': '新增问题' if _key(f) in ran_before else '新增检查项发现'})
    for fid, f in before.items():
        if fid not in findings:
            rows.append({**f, 'id': fid, 'status': '已解决' if _key(f) in ran else '本月未检查'})
    out = {'month': ws.month, 'previous': prev_month, 'first': False, 'rows': rows}
    write_json(ws.month_dir('findings') / 'tracking.json', out)
    counts = summary(out)
    log('跨月跟踪（对比 ' + prev_month + '）：' + '，'.join(f'{k} {v}' for k, v in counts['all'].items()))
    return out


def summary(tracking, report=None):
    """Counts by status (and by status x severity) for one report or all."""
    from collections import Counter
    rows = [r for r in tracking.get('rows') or [] if report is None or report_of(r['check']) == report]
    order = ['新增问题', '新增检查项发现', '仍未处理', '已解决', '本月未检查']
    c = Counter(r['status'] for r in rows)
    sev = {s: Counter(r['severity'] for r in rows if r['status'] == s) for s in order}
    return {'all': {k: c[k] for k in order if c[k]}, 'bySeverity': sev,
            'severityChanged': [r for r in rows if r.get('previousSeverity')],
            'newChecks': sorted({(r['check'], r.get('source')) for r in rows if r['status'] == '新增检查项发现'},
                                key=lambda k: list(CHECKS).index(k[0]) if k[0] in CHECKS else 99)}


SOURCE_LABELS = {'aprl': 'APRL', 'amba': 'AMBA', 'defender': 'Defender/Policy'}


def check_label(check, source):
    return CHECKS.get(check, check) + (f'（{SOURCE_LABELS[source]}）' if source in SOURCE_LABELS else '')


def load(ws):
    path = ws.month_dir('findings') / 'tracking.json'
    return read_json(path) if path.exists() else None
