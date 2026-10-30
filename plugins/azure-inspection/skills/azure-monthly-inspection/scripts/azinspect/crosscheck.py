"""Cross-report checks X1-X9 (references/cross-checks.md). Read-only over the month's findings and reports.

Writes findings/crosscheck.json. Each rule returns status '通过', '需要处理' (items listed with a suggested action),
'需人工确认' or '未检查' (inputs missing). Nothing here changes a report: the agent decides, writes notes into the
narrative files (e.g. narrative/02.json crossCheckNotes) and rebuilds.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .core.io import read_json, write_json

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
                           'handled': _noted(ws, r['subscriptionName'], names), 'names': names,
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


def x5(ws):
    review = _load(ws.raw('cost/review/results.json'))
    if review is None:
        return _result('X5', '闲置资源 vs 仍在使用', [], '缺少 01 资源复查结果')
    from .cost.orphan import findings as orphan_findings
    rows, _, _ = orphan_findings(ws, {})
    idle = {str(r.get('name')).lower(): r for r in (review.get('wasteFindings') or []) + rows if r.get('name')}
    items = []
    for pillar in ('performance', 'operations', 'reliability'):
        for f in _findings(ws, pillar) or []:
            for n in sorted(_names(f) & set(idle)):
                items.append({'resource': idle[n]['name'], 'subscription': idle[n].get('subscriptionName'),
                              'evidence': f'01 列为闲置（{idle[n].get("category")}）；{f["id"]}：{f["finding"][:100]}',
                              'suggestion': '确认是否仍在使用；在用的从闲置清单说明中改为“需要确认用途”'})
    return _result('X5', '闲置资源 vs 仍在使用', items, manual=True)


def x6_x7(ws):
    """Numbers and subscription counts. X6 compares 00 against 01-05 when 00 exists."""
    reports = ws.month_dir('reports')
    model = _load(ws.month_dir('findings') / 'cost' / 'model.json')
    vm = _load(ws.month_dir('findings') / 'vm' / 'summary.json')
    r03 = _load(ws.month_dir('findings') / 'waf' / 'report-03.json')
    r04 = _load(ws.month_dir('findings') / 'waf' / 'report-04.json')
    peer = _load(ws.month_dir('findings') / 'peer' / 'baseline.json')
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
        counts['03/04'] = sum(1 for s in load_scope(ws) if s.get('state') == 'Enabled')
    except FileNotFoundError:
        pass
    values = {v for v in counts.values() if v is not None}
    x7 = _result('X7', '各报告订阅数一致', [] if len(values) <= 1 else
                 [{'resource': '订阅数', 'evidence': '；'.join(f'{k}：{v}' for k, v in counts.items()),
                   'suggestion': '统一写法；不同的原因（如 01 只比较两个月都能读取的订阅）在报告中写明'}], manual=True)
    return [x6, x7], expected


def x8(ws):
    """Same resource with different severities across 03/04 (high vs low): review that the advice agrees."""
    seen = defaultdict(list)
    for pillar in ('reliability', 'aprl', 'security_network', 'security_identity', 'performance', 'operations'):
        for f in _findings(ws, pillar) or []:
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


def x9(ws):
    reports, findings = ws.month_dir('reports'), ws.month_dir('findings')
    charts = list((reports / 'charts').glob('*.png'))
    if not charts:
        return _result('X9', '图表与数据一致', [], '还没有图表')
    stale = []
    for p in charts:
        dirs = CHART_SOURCES.get(p.name[:2])
        if not dirs:
            continue
        data = [f.stat().st_mtime for d in dirs for f in (findings / d).glob('*.json') if not f.name.startswith(CHART_SKIP)]
        if data and p.stat().st_mtime + 1 < max(data):
            stale.append({'resource': p.name, 'evidence': '图表早于对应的分析结果', 'suggestion': '重新运行 build 生成图表'})
    return _result('X9', '图表与数据一致', stale)


def run(ws, log=print):
    rules = x1_x2_x3(ws) + [x4(ws), x5(ws)]
    x67, expected = x6_x7(ws)
    rules += x67 + [x8(ws), x9(ws)]
    out = {'rules': rules, 'expectedNumbers': expected}
    write_json(ws.month_dir('findings') / 'crosscheck.json', out)
    for r in rules:
        handled = sum(1 for i in r['items'] if i.get('handled'))
        detail = r.get('reason') or (f'{len(r["items"])} 处' + (f'，其中 {handled} 处已处理' if 0 < handled < len(r['items']) else '') if r['items'] else '')
        log(f'{r["rule"]} {r["title"]}：{r["status"]}' + (f'（{detail}）' if detail else ''))
    log(f'结果已保存：{ws.month_dir("findings") / "crosscheck.json"}')
    return out
