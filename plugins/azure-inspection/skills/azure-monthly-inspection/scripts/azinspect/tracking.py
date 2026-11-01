"""Month-over-month tracking of 03/04 findings.

Each build stores this month's findings (stable ids) in state/months/<YYYY-MM>.json, overwriting a rerun of the same
month, and compares with the latest earlier month:
- 新增问题: id not seen last month and its check already ran last month (the problem is new);
- 新增检查项发现: the check did not exist or did not run last month, or the rule that found it (coverage 'rules', e.g. R9
  retirement notices, APRL rules) was added to the check this month (new coverage, not a new problem);
- 仍未处理: id in both months (severity changes are listed);
- 已解决: id last month, absent now, and its check ran this month without a failed read;
- 本月未检查: id last month, absent now, but its check failed (any read: what it did not see may still be there) or was
  not run this month, or its pillar or one of its
  resources' subscriptions was left out this month (customer.yaml) — never counted as resolved.
A problem in a subscription that was left out last month is new coverage (新增检查项发现), not a new problem.
Ids depend on how rows are merged (a row across subscriptions becomes one row per subscription when the scope narrows):
a new row sharing resources with a row of the same check that is gone is the same problem regrouped (仍未处理).
Customer decisions (负责人、客户决定、处理状态) come from the customer's Excel and are not read here.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .core.io import Workspace, read_json, write_json
from .waf.checks import CHECKS, group_of, report_of
from .waf.common import PILLARS, is_aggregate_subscription, is_tenant_label, load_scope

GUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)


def current(ws):
    """This month's findings and the checks that ran, for the pillars of 03/04 done this month (customer.yaml report.include):
    a pillar left out never counts as run, so its problems from last month are 本月未检查."""
    from .selection import load_groups
    groups = load_groups(ws)
    findings, ran, failed, partial, rules = {}, set(), set(), {}, set()
    base = ws.month_dir('findings') / 'waf'
    for pillar in PILLARS:
        path = base / f'{pillar}.json'
        if not path.exists():
            continue
        data = read_json(path)
        # a check is identified by its source module too: APRL rows under R3 or AMBA rows under O2 are new coverage
        for check, c in (data.get('coverage') or {}).items():
            if (c.get('succeeded') or 0) > 0 and group_of(check) in groups:
                ran.add(f'{pillar}:{check}')
                rules.update(f'{pillar}:{check}:{r}' for r in c.get('rules') or [])
            if (c.get('denied') or 0) + (c.get('otherErrors') or 0) > 0:
                failed.add(f'{pillar}:{check}')
            if c.get('incomplete'):   # rules that could not see resources in subscriptions left out (APRL ids)
                partial.setdefault(f'{pillar}:{check}', set()).update(c['incomplete'])
        for f in data['findings']:
            if group_of(f['check']) not in groups:
                continue
            findings[f['id']] = {'check': f['check'], 'source': pillar, 'severity': f['severity'], 'subscription': f.get('subscriptionName'),
                                 'resource': f.get('resourceName'), 'finding': f['finding'][:200], 'members': _members(f),
                                 **({'rule': f['rule']} if f.get('rule') else {})}
            ran.add(f'{pillar}:{f["check"]}')
    return findings, ran, failed, partial, rules


def _key(f):
    return f'{f.get("source")}:{f["check"]}'


def _members(f):
    """[[subscription, resource name]] of a finding (a merged row lists every resource it covers)."""
    return [[str(m.get('subscription') or ''), str(m['name'])] for m in f.get('members') or [] if m.get('name')]


def _subs(f):
    """Subscriptions a row covers: its resources', else its own when it names one (merged-row labels such as
    '(多个订阅)', '多个订阅（4 个）', '全部 3 个可读订阅' do not)."""
    single = lambda s: bool(s) and not is_aggregate_subscription(s) and not is_tenant_label(s)  # noqa: E731
    subs = {s for s, _ in f.get('members') or [] if single(s)}
    return subs or ({f['subscription']} if single(f.get('subscription')) else set())


def _fill_members(ws, month, before):
    """Months recorded before members were kept: take them from that month's findings files when they are still there."""
    if all('members' in f for f in before.values()):
        return
    for path in (Workspace(ws.root, month).month_dir('findings') / 'waf').glob('*.json'):
        data = read_json(path)
        for f in data.get('findings') or [] if isinstance(data, dict) else []:
            if f.get('id') in before and 'members' not in before[f['id']]:
                before[f['id']]['members'] = _members(f)


def inspected(ws):
    """Names of the subscriptions read this month, or None when not recorded."""
    try:
        return sorted(s['name'] for s in load_scope(ws) if s.get('state') == 'Enabled')
    except FileNotFoundError:
        return None


def previous_month(ws):
    months = sorted(p.stem for p in (ws.state_dir / 'months').glob('*.json') if p.stem < ws.month)
    return months[-1] if months else None


def update(ws, log=print):
    findings, ran, failed, partial, rules = current(ws)
    subs = inspected(ws)
    write_json(ws.state_dir / 'months' / f'{ws.month}.json', {'month': ws.month, 'findings': findings, 'checksRun': sorted(ran),
                                                             'rulesRun': sorted(rules), 'subscriptions': subs})
    prev_month = previous_month(ws)
    if not prev_month:
        out = {'month': ws.month, 'previous': None, 'first': True}
        write_json(ws.month_dir('findings') / 'tracking.json', out)
        log('跨月跟踪：这是第一次记录，下个月起与本月对比')
        return out
    prev = read_json(ws.state_dir / 'months' / f'{prev_month}.json')
    before, ran_before, rules_before = prev['findings'], set(prev.get('checksRun') or []), set(prev.get('rulesRun') or [])
    _fill_members(ws, prev_month, before)
    subs_before = prev.get('subscriptions')
    # this month reads fewer subscriptions than last month covered (also when last month did not record its scope)
    narrowed = subs is not None and bool((set(subs_before or []) | {s for f in before.values() for s in _subs(f)}) - set(subs))

    def left_out(f, scope, unknown=False):
        """A row some of whose subscriptions were not read; a merged row without resources is judged by `unknown`."""
        if scope is None or is_tenant_label(f.get('subscription')):   # tenant rows do not follow the subscription scope
            return False
        covered = _subs(f)
        return bool(covered - set(scope)) if covered else unknown

    gone = {fid: f for fid, f in before.items() if fid not in findings}
    by_key = defaultdict(list)
    for fid, f in gone.items():
        by_key[_key(f)].append(fid)
    # a subscription listed as a resource is named by its ID in months before 0.9.0 and by its name since: the same resource
    try:
        alias = {s['id'].lower(): s['name'] for s in load_scope(ws)}
    except FileNotFoundError:
        alias = {}
    names = lambda f: {alias.get(n.lower(), n) for _, n in f.get('members') or []}  # noqa: E731
    # rows of one check can share a resource (several Defender recommendations on one subscription). A Defender/Policy row
    # is the same problem only under the same title (the quoted recommendation or assignment, IDs left out);
    # otherwise prefer the gone rows with the same opening clause, else any that share a resource
    def title(f):
        quoted = re.search(r'“([^”]+)”', str(f.get('finding') or ''))
        return GUID.sub('', quoted.group(1)) if quoted else None

    def head(f):
        return str(f.get('finding') or '').split('，')[0].split('：')[0]

    def olds(f):
        shared = [g for g in by_key[_key(f)] if names(f) & names(gone[g])]
        if f.get('source') == 'defender' and title(f) is not None:
            return [g for g in shared if title(gone[g]) == title(f)]
        return [g for g in shared if head(gone[g]) == head(f)] or shared
    regrouped = {fid: olds(f) for fid, f in findings.items() if fid not in before}
    regrouped = {fid: olds for fid, olds in regrouped.items() if olds}
    consumed = {g for olds in regrouped.values() for g in olds}
    plain = lambda f: {k: v for k, v in f.items() if k != 'members'}  # noqa: E731
    rows = []
    for fid, f in findings.items():
        if fid in before or fid in regrouped:
            old = before[fid]['severity'] if fid in before else before[regrouped[fid][0]]['severity']
            rows.append({**plain(f), 'id': fid, 'status': '仍未处理', 'previousSeverity': old if old != f['severity'] else None,
                         **({'previousIds': regrouped[fid]} if fid in regrouped else {})})
        else:
            new_problem = _key(f) in ran_before and not left_out(f, subs_before)
            known = {r for r in rules_before if r.startswith(_key(f) + ':')}   # none in months recorded before rules were kept
            if new_problem and f.get('rule') and known and f'{_key(f)}:{f["rule"]}' not in known:
                new_problem = False     # a rule added to the check this month: new coverage
            rows.append({**plain(f), 'id': fid, 'status': '新增问题' if new_problem else '新增检查项发现'})
    from .selection import load_groups
    groups = load_groups(ws)
    for fid, f in gone.items():
        if fid in consumed:
            continue
        outside = group_of(f['check']) not in groups or left_out(f, subs, narrowed)   # not in this month's pillars or subscriptions
        incomplete = any(rule in (f.get('finding') or '') for rule in partial.get(_key(f), ()))
        if _key(f) in ran and _key(f) not in failed and not outside and not incomplete:
            rows.append({**plain(f), 'id': fid, 'status': '已解决'})
        else:
            why = '不在本月范围' if outside else '读取失败' if _key(f) in failed or _key(f) not in ran else '范围不完整'
            rows.append({**plain(f), 'id': fid, 'status': '本月未检查', 'notChecked': why})
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
