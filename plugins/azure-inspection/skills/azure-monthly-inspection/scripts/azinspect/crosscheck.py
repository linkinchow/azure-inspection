"""Cross-report checks X1-X12 (references/cross-checks.md). Read-only over the month's findings and reports.

Writes findings/crosscheck.json. Each rule returns status '通过', '需要处理' (items listed with a suggested action),
'需人工确认', '未检查' (inputs missing) or '不适用' (a report it compares was not chosen this month). Nothing here changes a report: the agent decides, writes notes into the
narrative files (e.g. narrative/02.json crossCheckNotes) and rebuilds.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .core.config import GROUPS, REPORTS
from .core.io import read_json, write_json
from .selection import load as load_selection, load_groups
from .waf.checks import group_of

RECOMMENDED = '建议试点调整'


def _load(path):
    return read_json(path) if path.exists() else None


def _findings(ws, pillar):
    data = _load(ws.month_dir('findings') / 'waf' / f'{pillar}.json')
    return data['findings'] if data else None


def _names(f):
    return {str(m['name']).lower() for m in f.get('members') or [] if m.get('name')} or {str(f.get('resourceName') or '').lower()}


def _pool_of(vmss):
    """AKS pool name from a VMSS name or resource id: .../aks-nodepool1-12345678-vmss -> nodepool1."""
    m = re.match(r'^aks-(.+?)-\d+-vmss$', str(vmss or '').rstrip('/').split('/')[-1], re.I)
    return m.group(1).lower() if m else None


def _result(rule, title, items, missing=None, manual=False):
    if missing:
        return {'rule': rule, 'title': title, 'status': '未检查', 'reason': missing, 'items': []}
    open_items = [i for i in items if not i.get('handled')]
    status = '通过' if not items else ('已处理' if not open_items else '需人工确认' if manual else '需要处理')
    return {'rule': rule, 'title': title, 'status': status, 'items': items}


def _note(ws, subscription, names, rule=None, kind=None):
    """The narrative/02.json crossCheckNotes entry covering this VM or pool (same matching as the 02 report), or None.
    A note with `rules` and/or `kinds` covers only those rules and conflict kinds; without them it covers every rule."""
    notes = (_load(ws.month_dir('narrative') / '02.json') or {}).get('crossCheckNotes') or []
    for n in notes:
        if n.get('subscription') == subscription and n.get('namePrefix') and any(str(x).startswith(n['namePrefix']) for x in names) \
                and (not n.get('rules') or rule in n['rules']) and (not n.get('kinds') or kind in n['kinds']):
            return n
    return None


def _noted(ws, subscription, names, rule=None, kind=None):
    return _note(ws, subscription, names, rule, kind) is not None


# 02 directions and what they reduce; a conflict is direct when 02 reduces what 04 found saturated
REDUCES = {'CPU与内存减半': {'CPU', '内存', 'IO'}, '只减CPU，内存保留': {'CPU', 'IO'}, '只减内存，CPU保留': {'内存', 'IO'}}


def _conflict(ws, r, f, rule, kind):
    """One X1/X2 item: kind (CPU/内存/IO), level, the note that covers it."""
    direction = (r.get('candidate') or {}).get('direction')
    direct = direction is None or kind in REDUCES.get(direction, {'CPU', '内存', 'IO'})
    note = _note(ws, r['subscriptionName'], [r['name']], rule, kind)
    suggestion = ('直接冲突：02 要减少的正是 04 报满的资源，建议改为不更换，或在 crossCheckNotes 写明可以减少的理由（由用户决定）'
                  if direct else f'方向不同：02 不减少{kind}，但 04 建议增加；在 crossCheckNotes 写一句说明，让客户知道两份报告都已考虑')
    return {'resource': r['name'], 'subscription': r['subscriptionName'], 'from': r['currentSKU'], 'to': r.get('targetSKU'),
            'kind': kind, 'conflict': '直接冲突' if direct else '方向不同', 'direction': direction,
            'handled': note is not None, 'handledBy': f"{note['namePrefix']}：{str(note.get('note'))[:60]}" if note else None,
            'evidence': f'{f["id"]}（{f["severity"]}）：{f["finding"][:120]}', 'suggestion': suggestion}


def x1_x2_x3(ws):
    recs, perf = _load(ws.month_dir('findings') / 'vm' / 'recommendations.json'), _findings(ws, 'performance')
    titles = ('降配建议 vs 性能峰值', '降配建议 vs 磁盘吞吐', '节点池降配 vs 内存压力')
    if recs is None or perf is None:
        reason = '缺少 02 建议或 04 性能结果'
        return [_result(r, t, [], reason) for r, t in zip(('X1', 'X2', 'X3'), titles)]
    downsized = [r for r in recs if r.get('status') == RECOMMENDED]
    by_name = {str(r['name']).lower(): r for r in downsized}
    x1, x2, x3 = [], [], []
    for f in perf:
        hit = sorted(n for n in _names(f) if n in by_name)
        if f['check'] == 'P1' and hit:
            # the kind comes from 04 itself, not the text: 04 may append the 02 recommendation, which mentions CPU and memory
            kind = (f.get('evidence') or {}).get('kind') or ('内存' if '平均内存使用' in f['finding'] else 'CPU')
            kind = 'CPU' if kind == 'CPU峰值' else kind
            x1 += [_conflict(ws, by_name[n], f, 'X1', kind) for n in hit]
        if f['check'] == 'P4' and hit:
            for n in hit:
                item = _conflict(ws, by_name[n], f, 'X2', 'IO')
                item['suggestion'] += '；查官方规格表比较新规格的磁盘吞吐上限与已挂数据盘上限'
                x2.append(item)
    pools = defaultdict(list)
    for r in downsized:
        pool = _pool_of(r.get('pool'))
        if pool:
            pools[(str(r['subscriptionName']).lower(), pool)].append(r)
    for f in perf:
        if f['check'] != 'P2':
            continue
        items = (f.get('evidence') or {}).get('items') or [f.get('evidence') or {}]
        for it in items:
            pool = str(it.get('pool') or '').lower() or str(it.get('resourceName') or '').split('/')[-1].lower()
            sub = str(it.get('subscriptionName') or f.get('subscriptionName') or '').lower()
            cluster = str(it.get('cluster') or str(it.get('resourceName') or '').split('/')[0]).lower()
            # same pool name can exist in several clusters of one subscription: the node resource group names the cluster
            same = [r for r in pools.get((sub, pool), []) if f'_{cluster}_' in str(r.get('pool') or '').lower()]
            for r in same[:1]:
                names = [x['name'] for x in pools[(sub, pool)] if x.get('pool') == r.get('pool')]
                x3.append({'resource': f'{it.get("cluster") or ""}/{pool}', 'subscription': r['subscriptionName'], 'from': r['currentSKU'],
                           'handled': _noted(ws, r['subscriptionName'], names, 'X3', '内存'), 'names': names,
                           'to': r.get('targetSKU'), 'evidence': f'{f["id"]}（{f["severity"]}）：{f["finding"][:120]}',
                           'suggestion': '在 02 加提醒：先解决内存压力，不宜只降 CPU'})
    return [_result('X1', titles[0], x1), _result('X2', titles[1], x2), _result('X3', titles[2], x3)]


def x4(ws):
    dbs, perf = _load(ws.raw('cost/resources/databases.json')), _findings(ws, 'performance')
    if dbs is None or perf is None:
        return _result('X4', '缓存或数据库降档 vs 增长趋势', [], '缺少 01 数据库用量或 04 性能结果')
    low = {r['name'].lower(): r for r in dbs['resources'] if any(str(x).startswith('LOW') for x in r.get('flags') or [])}
    excluded = {x['name'].lower() for x in (_load(ws.month_dir('narrative') / '01.json') or {}).get('downsizeExclusions') or []}
    items = []
    for f in perf:
        if f['check'] in ('P4', 'P5'):
            for n in sorted(_names(f) & set(low)):
                items.append({'resource': low[n]['name'], 'subscription': low[n]['subscriptionName'], 'handled': n in excluded,
                              'evidence': f'01 列为低利用率；04 {f["id"]}（{f["severity"]}）：{f["finding"][:120]}',
                              'suggestion': '在 narrative/01.json 的 downsizeExclusions 加入 {"name", "reason"}：01 会移出降档候选并写明原因'})
    return _result('X4', '缓存或数据库降档 vs 增长趋势', items)


EXPOSED_TYPES = {'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'}


def x5(ws, chosen=REPORTS, groups=None):
    review = _load(ws.raw('cost/review/results.json'))
    if review is None:
        return _result('X5', '闲置资源 vs 仍在使用', [], '缺少 01 资源复查结果')
    from .cost.orphan import findings as orphan_findings
    rows, _, _ = orphan_findings(ws, {})
    idle = {str(r.get('name')).lower(): r for r in (review.get('wasteFindings') or []) + rows if r.get('name')}
    items = []
    for pillar in ('performance', 'operations', 'reliability', 'security_network'):
        for f in _findings(ws, pillar) or []:
            if groups is not None and group_of(f['check']) not in groups:
                continue
            names = _names(f)
            if pillar == 'security_network':
                # only network interfaces and public IPs listed as exposed; idle NSGs are already a latent risk there
                names = {str(m['name']).lower() for m in f.get('members') or []
                         if str(m.get('type') or '').lower() in EXPOSED_TYPES and m.get('name')}
            for n in sorted(names & set(idle)):
                items.append({'resource': idle[n]['name'], 'subscription': idle[n].get('subscriptionName'),
                              'evidence': f'01 列为闲置（{idle[n].get("category")}）；{f["id"]}：{f["finding"][:100]}',
                              'suggestion': '确认是否仍在使用；在用的从闲置清单说明中改为“需要确认用途”'
                                            + ('；确是残留的，03 的建议改为直接清理' if pillar == 'security_network' else '')})
    return _result('X5', '闲置资源 vs 仍在使用', items, manual=True)


def x6_x7(ws, chosen=REPORTS):
    """Numbers and subscription counts. X6 compares 00 against the chosen reports when 00 exists."""
    reports = ws.month_dir('reports')
    pick = lambda code, rel: _load(ws.month_dir('findings') / rel) if code in chosen else None  # noqa: E731
    model, vm = pick('01', 'cost/model.json'), pick('02', 'vm/summary.json')
    r03, r04, peer = pick('03', 'waf/report-03.json'), pick('04', 'waf/report-04.json'), pick('05', 'peer/baseline.json')
    expected = {}
    if model:
        expected['01 本月费用'] = f'{model["comparableTotals"]["cur"]:,.2f}'
    if vm:
        expected['02 预计每月节省'] = f'{vm["monthlySavingsUSD"]:,.2f}' if 'monthlySavingsUSD' in vm else f'{vm["monthlyPotentialSavingsUSD"]:,.2f}'
        expected['02 建议调整台数'] = str(vm['recommendedVMCount'])
    for code, meta in (('03', r03), ('04', r04)):
        if meta:
            expected[f'{code} 问题数'] = str(meta['total'])
    if peer:
        total = peer.get('summary', {}).get('deviations') or peer.get('totalDeviations')
        if total:
            expected['05 偏差数'] = str(total)
    summary = sorted(reports.glob('00_*.md'))
    if not summary:
        x6 = _result('X6', '汇总报告数字与明细一致', [], '还没有 00 汇总报告')
    else:
        text = re.sub(r'\s+', '', summary[0].read_text(encoding='utf-8'))
        missing = [{'resource': k, 'evidence': f'00 中找不到 {v}', 'suggestion': '以明细报告为准修改汇总（重新生成 00）'}
                   for k, v in expected.items() if v.replace(' ', '') not in text]
        x6 = _result('X6', '汇总报告数字与明细一致', missing)
    counts = {}
    if model:
        counts['01'] = model['totals']['comparableSubscriptionCount']
    if vm:
        counts['02'] = vm.get('subscriptionCount')
    from .waf.common import load_scope
    try:
        if {'03', '04'} & set(chosen):
            counts['03/04'] = sum(1 for s in load_scope(ws) if s.get('state') == 'Enabled')
    except FileNotFoundError:
        pass
    values = {v for v in counts.values() if v is not None}
    x7 = _result('X7', '各报告订阅数一致', [] if len(values) <= 1 else
                 [{'resource': '订阅数', 'evidence': '；'.join(f'{k}：{v}' for k, v in counts.items()),
                   'suggestion': '统一写法；不同的原因（如 01 只比较两个月都能读取的订阅）在报告中写明'}], manual=True)
    return [x6, x7], expected


def x8(ws, chosen=REPORTS, groups=None):
    """Same resource with different severities across 03/04 (high vs low): review that the advice agrees."""
    seen = defaultdict(list)
    for pillar in ('reliability', 'aprl', 'security_network', 'security_identity', 'performance', 'operations'):
        for f in _findings(ws, pillar) or []:
            if groups is not None and group_of(f['check']) not in groups:
                continue
            for n in _names(f):
                seen[n].append(f)
    items = []
    for name, fs in sorted(seen.items()):
        sev = {f['severity'] for f in fs}
        if '高' in sev and '低' in sev and len(fs) <= 6:
            items.append({'resource': name, 'evidence': '；'.join(f'{f["id"]}（{f["severity"]}）' for f in fs),
                          'suggestion': '确认各报告对这个资源的建议一致；以同类对比得出的根本原因为准'})
    return _result('X8', '同一资源的严重程度和建议一致', items[:30], manual=True)


CHART_SOURCES = {'01': ('cost',), '02': ('vm',), '03': ('waf',), '04': ('waf',), '05': ('peer',)}
CHART_SKIP = ('report', 'verification', 'audit', 'expected-formulas', 'actions')   # written by build itself


def _sha(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def chart_sources(ws, code):
    """Fingerprint of the analysis results a report's charts are drawn from (build records it; X9 compares)."""
    import hashlib
    findings = ws.month_dir('findings')
    files = sorted(f for d in CHART_SOURCES.get(code, ()) for f in (findings / d).glob('*.json') if not f.name.startswith(CHART_SKIP))
    h = hashlib.sha256()
    for f in files:
        h.update(f'{f.parent.name}/{f.name}'.encode('utf-8'))
        h.update(f.read_bytes())
    return h.hexdigest() if files else None


def x9(ws, chosen=REPORTS):
    reports, findings = ws.month_dir('reports'), ws.month_dir('findings')
    charts = [p for p in (reports / 'charts').glob('*.png') if p.name[:2] in chosen or p.name[:2] == '00']
    if not charts:
        return _result('X9', '图表与数据一致', [], '还没有图表')
    path = findings / 'build-hashes.json'
    drawn = (read_json(path) if path.exists() else {}).get('_charts') or {}
    stale = []
    for p in charts:
        dirs = CHART_SOURCES.get(p.name[:2])
        if not dirs:
            continue
        # drawn by a build from the results still there: fresh, whatever the file times say (a save can leave them older)
        if drawn.get(p.name) == [_sha(p), chart_sources(ws, p.name[:2])]:
            continue
        data = [f.stat().st_mtime for d in dirs for f in (findings / d).glob('*.json') if not f.name.startswith(CHART_SKIP)]
        if data and p.stat().st_mtime + 1 < max(data):
            stale.append({'resource': p.name, 'evidence': '图表早于对应的分析结果', 'suggestion': '重新运行 build 生成图表'})
    return _result('X9', '图表与数据一致', stale)


# amounts (with or without cents) and percentages with decimals; rounded ones (约 44%, 约 USD 1.2 万) are left alone
FIGURE = re.compile(r'USD\s*\d[\d,]*(?:\.\d{2})?(?![\d.,]*\d)(?!\s*[万亿])|\d+\.\d+%')


def _same_figure(said, shown):
    """Whole figures only (2.5% is not in 12.5%); a percentage rounded from the shown one counts (14.8% for 14.82%)."""
    if said == shown:
        return True
    if said.endswith('%') and shown.endswith('%'):
        decimals = len(said[:-1].split('.')[1]) if '.' in said else 0
        return f'{float(shown[:-1]):.{decimals}f}' == said[:-1]
    if said.startswith('USD') and shown.startswith('USD') and '.' not in said:   # a whole amount rounded from the shown one
        return round(float(shown[3:].replace(',', ''))) == int(said[3:].replace(',', ''))
    return False


def x10(ws, chosen=REPORTS):
    """Amounts and percentages in 00's conclusion (agent text) that 00's own table, drawn from 01-05, does not show. X6 cannot see these:
    the table always has the right numbers. A conclusion may quote other figures from a detailed report, so a person confirms."""
    reports = ws.month_dir('reports')
    summary = sorted(reports.glob('00_*.md'))
    if not summary:
        return _result('X10', '汇总结论数字与表格一致', [], '还没有 00 汇总报告')
    section = summary[0].read_text(encoding='utf-8').split('\n## 1. ', 1)[-1].split('\n## ', 1)[0]   # 1. 总体结论: table, then conclusion
    lines = section.splitlines()
    table = re.sub(r'\s+', '', ''.join(x for x in lines if x.startswith('|')))
    details = {p.name[:2]: re.sub(r'\s+', '', p.read_text(encoding='utf-8')) for p in sorted(reports.glob('0[1-5]_*.md')) if p.name[:2] in chosen}
    shown = [re.sub(r'\s+', '', f) for f in FIGURE.findall(table)]
    items = []
    for figure in dict.fromkeys(FIGURE.findall('\n'.join(x for x in lines if not x.startswith('|')))):
        key = re.sub(r'\s+', '', figure)
        if any(_same_figure(key, s) for s in shown):
            continue
        found = [code for code, text in details.items() if any(_same_figure(key, s) for s in FIGURE.findall(text))]
        items.append({'resource': figure, 'evidence': '00 结论写了此数字，第 1 节表格中没有' + (f'；{"、".join(found)} 报告中有' if found else '；01–05 报告中也没有'),
                      'suggestion': '金额以表格为准改写 narrative/00.json 的 conclusion 并重新生成 00；引用的是明细报告里的其他数字的，核对无误即可'})
    return _result('X10', '汇总结论数字与表格一致', items, manual=True)


INCOMPLETE = ('预测不完整', '预测没有读到')


def x11(ws, chosen=REPORTS):
    """A next-month forecast that misses subscriptions with a large share of this month's costs: 01 and 00 must call it
    incomplete. Their own text does; a narrative forecastSummary or 00 conclusion stating a tenant-wide figure does not."""
    from .cost import forecast_scope
    title = '预测覆盖不全时如实说明'
    model, forecast = _load(ws.month_dir('findings') / 'cost/model.json'), _load(ws.raw('cost/supplement/forecast.json'))
    if not model or not forecast:
        return _result('X11', title, [], '缺少 01 费用或预测数据')
    fc = forecast_scope.coverage(forecast, model, 1, 1)
    if fc['complete'] or (fc['estimate'] is None and not fc['missed']):
        return _result('X11', title, [])
    # the agent's own text only: the generated 01 bullet and 00 table already say 预测不完整
    nxt = str((forecast.get('months') or {}).get('next') or '')
    month = int(nxt[5:7]) if len(nxt) >= 7 else None
    mention = re.compile(rf'(?<!\d){month}\s*月[^。；，]{{0,6}}?(预计|预测)' if month else r'下个?月[^。；，]{0,6}?(预计|预测)')
    summary = (_load(ws.month_dir('narrative') / '01.json') or {}).get('forecastSummary') or '' if '01' in chosen else ''
    conclusion = ''.join((_load(ws.month_dir('narrative') / '00.json') or {}).get('conclusion') or [])
    items = []
    for code, text, field in (('01', summary, 'forecastSummary'), ('00', conclusion if mention.search(conclusion) else '', 'conclusion')):
        if text and not any(w in text for w in INCOMPLETE):
            items.append({'resource': code, 'evidence': f'只读到 {fc["subscriptions"]} 个订阅的预测（占本月费用的 {fc["share"] or 0:.1%}），'
                                                        f'说明文件的 {field} 写了预计却没有写“预测不完整”',
                          'suggestion': f'改写 narrative/{code}.json 的 {field}：写明预测不完整，或去掉全部订阅预计的说法，重新生成'})
    return _result('X11', title, items)


def _minor_key(v):
    return tuple(int(x) for x in str(v).split('.')[:2])


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


AKS_TARGET = re.compile(r'(?:升级到|升级至|升到)\s*(?:至少\s*)?(?:Kubernetes\s*)?(1\.\d{2})(?!\d)')   # two-digit minors: not TLS 1.2


def x12(ws, chosen=REPORTS):
    """AKS upgrade targets in 05 (standard version, deviations), its links into the 03/04 issue lists and the narratives
    (05, 03/04 topIssues and text overrides, 00 immediate) must not be below the lowest minor version in AKS standard
    support in the clusters' regions: the same version table 03's R9/S-I3 use to call a cluster past support."""
    title = 'AKS 升级目标不低于标准支持版本'
    versions = _load(ws.raw('waf/reliability/aks/k8s-versions.json'))
    if versions is None:
        return _result('X12', title, [], '缺少 03 可靠性采集的 AKS 版本表（raw/waf/reliability/aks/k8s-versions.json）')
    lowest = []
    for v in versions.values():
        official = [x['version'] for x in ((v or {}).get('data') or {}).get('values') or []
                    if 'KubernetesOfficial' in ((x.get('capabilities') or {}).get('supportPlan') or []) and not x.get('isPreview')]
        if official:
            lowest.append(min(official, key=_minor_key))
    if not lowest:
        return _result('X12', title, [])
    floor = max(lowest, key=_minor_key)   # supported in every region with clusters
    findings, narrative = ws.month_dir('findings'), ws.month_dir('narrative')
    peer = _load(findings / 'peer' / 'baseline.json') or {}
    aks = [x for x in peer.get('types') or [] if x.get('typeKey') == 'aks']
    sources = [('05 同类对比结果（findings/peer/baseline.json）', aks,
                '用 0.10.7 或更新版本重新运行 analyze（05 的标准版本会取标准支持版本），再 build'),
               ('05 联动到 03/04 问题清单“对齐标准的做法”（findings/peer/links.json）', _load(findings / 'peer' / 'links.json'),
                '用 0.10.7 或更新版本重新运行 analyze，再 build'),
               ('narrative/05.json', _load(narrative / '05.json'), '改写说明文件中的版本号，再 build')]
    for code in ('03', '04'):
        n = _load(narrative / f'{code}.json') or {}
        sources.append((f'narrative/{code}.json', [n.get('topIssues'), n.get('findingTextOverrides')], '改写说明文件中的版本号，再 build'))
    sources.append(('narrative/00.json', (_load(narrative / '00.json') or {}).get('immediate'), '改写说明文件中的版本号，再生成 00'))
    items, seen = [], set()
    for where, data, fix in sources:
        found = {m for s in _strings(data) for m in AKS_TARGET.findall(s)}
        found |= {str(a['baseline']['attributes'].get('version')) for a in aks if data is aks and (a.get('baseline') or {}).get('attributes', {}).get('version')}
        for v in sorted(found, key=_minor_key):
            if _minor_key(v) < _minor_key(floor) and (where, v) not in seen:
                seen.add((where, v))
                items.append({'resource': where, 'evidence': f'写的 AKS 升级目标或标准版本是 {v}，低于集群所在区域最低的标准支持版本 {floor}'
                                                             '（03 的 R9/S-I3 会把它判为已超出标准支持）',
                              'suggestion': f'{fix}；目标版本至少 {floor}'})
    return _result('X12', title, items)


# reports a rule compares; a rule is not applicable when a report it needs was not chosen this month
# (reports or pillars of 03/04): X1-X4 compare the performance pillar of 04 (P1, P2, P4, P5)
PILLARS_ALL = {'可靠性', '安全', '卓越运营', '性能效率'}
NEEDS = {'X1': [{'02'}, {'性能效率'}], 'X2': [{'02'}, {'性能效率'}], 'X3': [{'02'}, {'性能效率'}], 'X4': [{'01'}, {'性能效率'}],
         'X5': [{'01'}, PILLARS_ALL], 'X8': [PILLARS_ALL], 'X11': [{'01'}], 'X12': [{'可靠性'}]}


def _applicable(rule, chosen):
    """The rule as computed, or 不适用 naming what was left out (each set needs one of its reports or pillars)."""
    label = lambda need: '03 或 04' if need == PILLARS_ALL else '或'.join(  # noqa: E731
        x if x in REPORTS else f'{GROUPS[x]} {x}' for x in sorted(need))
    left_out = [label(need) for need in NEEDS.get(rule['rule'], []) if not need & set(chosen)]
    if not left_out:
        return rule
    return {'rule': rule['rule'], 'title': rule['title'], 'status': '不适用', 'items': [],
            'reason': '本月未选择 ' + '、'.join(left_out)}


def run(ws, log=print):
    chosen, groups = load_selection(ws), load_groups(ws)
    rules = x1_x2_x3(ws) + [x4(ws), x5(ws, chosen, groups)]
    x67, expected = x6_x7(ws, chosen)
    rules += x67 + [x8(ws, chosen, groups), x9(ws, chosen), x10(ws, chosen), x11(ws, chosen), x12(ws, chosen)]
    rules = [_applicable(r, chosen + groups) for r in rules]
    out = {'rules': rules, 'expectedNumbers': expected}
    write_json(ws.month_dir('findings') / 'crosscheck.json', out)
    for r in rules:
        handled = sum(1 for i in r['items'] if i.get('handled'))
        detail = r.get('reason') or (f'{len(r["items"])} 处' + (f'，其中 {handled} 处已处理' if 0 < handled < len(r['items']) else '') if r['items'] else '')
        log(f'{r["rule"]} {r["title"]}：{r["status"]}' + (f'（{detail}）' if detail else ''))
    log(f'结果已保存：{ws.month_dir("findings") / "crosscheck.json"}')
    return out
