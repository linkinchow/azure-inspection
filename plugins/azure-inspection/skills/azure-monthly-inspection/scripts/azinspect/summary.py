"""00 汇总报告: numbers from 01-05, explanations from narrative/00.json (agent), defaults from the 03/04 narratives and data.

Numbers are never written by hand here: every amount and count is read from the other reports' outputs, so the
summary cannot disagree with them (crosscheck X6 verifies this again).
"""
from __future__ import annotations

from collections import Counter

from .core import charts as cs
from .core.charts import clear as clear_charts
from .core.fmt_md import format_and_check
from .core.io import read_json, write_json
from .waf.checks import CHECKS
from .waf.report import default_top_issues, recommendation_text

GROUPS = ['可靠性', '安全', '卓越运营', '性能效率']
SEVERITY_ORDER = ('高', '中', '低')


def _load(path):
    return read_json(path) if path.exists() else None


def stem(period):
    return f'00_Azure巡检汇总报告_{period.following.label}'


def money(x):
    return f'{x:,.2f}'


def ws_of(d):
    return d['ws']


def gather(ws, period):
    f = ws.month_dir('findings')
    d = {'model': _load(f / 'cost' / 'model.json'), 'vm': _load(f / 'vm' / 'summary.json'), 'prices': _load(f / 'vm' / 'price-summary.json'),
         'forecast': _load(ws.raw('cost/supplement/forecast.json')), 'r03': _load(f / 'waf' / 'report-03.json'),
         'r04': _load(f / 'waf' / 'report-04.json'), 'peer': _load(f / 'peer' / 'baseline.json'), 'peerReport': _load(f / 'peer' / 'report.json'), 'actions': _load(f / 'cost' / 'actions.json')}
    d['narrative'] = {code: _load(ws.month_dir('narrative') / f'{code}.json') or {} for code in ('01', '03', '04', '05')}
    waf = []
    for p in sorted((f / 'waf').glob('*.json')):
        data = read_json(p)
        if isinstance(data, dict) and 'findings' in data and data.get('pillar'):
            waf += data['findings']
    d['waf'] = waf
    d['ws'] = ws
    return d


def pillar_counts(d):
    counts = {g: Counter() for g in GROUPS}
    for meta in (d['r03'], d['r04']):
        for key, n in ((meta or {}).get('byGroup') or {}).items():
            g, s = key.split('-')
            counts[g][s] += n
    return counts


def chart(counts, path):
    rows = [(g, counts[g]) for g in GROUPS if sum(counts[g].values())]
    if not rows:
        return None
    fig, ax = cs.figure(10, 0.5 * len(rows) + 1.4)
    cs.style(ax, 'x')
    top = max(sum(c.values()) for _, c in rows)
    for i, (g, c) in enumerate(reversed(rows)):
        left = 0
        for s in SEVERITY_ORDER:
            if c[s]:
                ax.barh(i, c[s], left=left, height=0.56, color=cs.SEVERITY[s], edgecolor=cs.SURFACE, linewidth=2)
                if c[s] >= top * 0.06:
                    ax.text(left + c[s] / 2, i, str(c[s]), ha='center', va='center', fontsize=8, color='white' if s != '低' else cs.INK)
            left += c[s]
        ax.text(left + top * 0.01, i, f'{left}（高 {c["高"]}）', va='center', fontsize=9, color=cs.INK)
    ax.set_yticks(range(len(rows)), [g for g, _ in reversed(rows)], fontsize=10, color=cs.INK)
    ax.set_xlim(0, top * 1.2)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=cs.SEVERITY[s], label=s) for s in SEVERITY_ORDER], title='严重程度', loc='lower right', frameon=False,
              fontsize=8.5, title_fontsize=8.5, ncol=3, labelcolor=cs.INK2)
    ax.set_title('各支柱发现的问题数量', loc='left', fontsize=11, color=cs.INK, pad=10)
    cs.save(fig, path)
    return f'charts/{path.name}'


def default_immediate(d):
    issues = []
    for code in ('03', '04'):
        issues += (d['narrative'][code].get('topIssues') or [])[:5]
    if not issues:
        high = sorted([f for f in d['waf'] if f['severity'] == '高'], key=lambda f: f['check'])
        issues = default_top_issues([{**f, 'checkName': CHECKS.get(f['check'], f['check'])} for f in high])
    return issues[:10]


def default_pillar_notes(d):
    notes = {}
    for code in ('03', '04'):
        for check, text in (d['narrative'][code].get('checkNotes') or {}).items():
            group = '可靠性' if check.startswith('R') else '安全' if check.startswith('S-') else '卓越运营' if check.startswith('O') else '性能效率'
            if text and text != '未发现问题':
                notes.setdefault(group, []).append(text)
    return {g: v[:5] for g, v in notes.items()}


def default_plan(d):
    plan = {}
    for code in ('03', '04'):
        for key, items in (d['narrative'][code].get('actionPlan') or {}).items():
            plan.setdefault(key, []).extend(items)
    return plan


def table(header, rows, align):
    out = ['|' + '|'.join(header) + '|', '|' + '|'.join(align) + '|']
    out += ['|' + '|'.join(str(c).replace('|', '/').replace('\n', ' ') for c in r) + '|' for r in rows]
    return out


def markdown(cfg, period, d, n, pngs, scope):
    model, vm, prices = d['model'], d['vm'], d['prices']
    counts = pillar_counts(d)
    cur, prev, nxt = period.current, period.previous, period.following
    lines = [f'# {cfg.name} Azure 巡检汇总报告（{nxt.label}）', '',
             f'**范围**：{cfg.name} {scope["readable"]} 个 Azure 订阅。' + (f'{scope["note"]}。' if scope['note'] else ''), '',
             '**方式**：使用贵司提供的账号，以只读方式读取费用、配置、监控指标和日志，没有修改任何资源，也没有做端口扫描。', '',
             '**时间**：', '',
             f'- 费用：对比 {cur.label}与{prev.short_label if cur.year == prev.year else prev.label}两个完整自然月。'] + ([f'- 配置：{scope["snapshot"]}读取。'] if scope.get('snapshot') else []) + \
            ([f'- 性能：{scope["window"]}的数据。'] if scope.get('window') else []) + [
             '', '本报告按 Microsoft Azure Well-Architected Framework（WAF）的五个支柱汇总结论：成本优化、可靠性、安全、卓越运营、性能效率。每项问题的资源明细见附件。', '',
             '## 1. 总体结论', '']
    rows = []
    if model:
        t = model['comparableTotals']
        rows.append([f'{cur.short_label}费用', f'USD {money(t["cur"])}，比{prev.short_label}{"增加" if t["delta"] >= 0 else "减少"} {abs(t["changeRate"] or 0):.2%}'
                     + (f'；日均费用{"上升" if t["dailyChangeRate"] >= 0 else "下降"} {abs(t["dailyChangeRate"]):.2%}' if cur.days != prev.days and t['dailyChangeRate'] is not None else '')])
    fc = ((d['forecast'] or {}).get('overall') or {}).get('next') or {}
    if fc.get('fullMonthEstimate'):
        rows.append([f'{nxt.short_label}预计费用', f'约 USD {money(fc["fullMonthEstimate"])}（Azure 预测）'])
    if vm:
        rows.append(['VM 规格调整', f'{vm["recommendedVMCount"]} 台建议降配，**每月约节省 USD {money(vm["monthlyPotentialSavingsUSD"])}**（官网列表价）'])
    plan_by = {p['key']: p for p in (prices or {}).get('plans', [])}
    if 'ri1' in plan_by:
        rows.append(['VM 降配后再购买 1 年 RI', f'VM 计算费用每月从 USD {money(prices["currentMonthly"])} 降到 USD {money(plan_by["ri1"]["monthlyCost"])}，'
                                            f'**每月约节省 USD {money(plan_by["ri1"]["monthlySaving"])}**（官网列表价）'])
    for code, title in (('r03', '可靠性与安全'), ('r04', '卓越运营与性能效率')):
        if d[code]:
            rows.append([title, f'发现 {d[code]["total"]} 项问题，其中高风险 {d[code]["bySeverity"].get("高", 0)} 项'])
    from .tracking import load as load_tracking, summary as tracking_summary
    tracked = load_tracking(ws_of(d))
    if tracked and not tracked.get('first'):
        c = tracking_summary(tracked)['all']
        rows.append([f'与 {tracked["previous"]} 相比', '，'.join(f'{k} {c[k]} 项' for k in c)])
    peer = d['peerReport'] or {}
    if peer.get('deviations'):
        rows.append(['同类资源配置对比', f'{peer["deviations"]} 处配置偏差，其中高风险 {peer.get("highImpact", 0)} 处'])
    lines += table(['项目', '结果'], rows, ['---', '---'])
    if pngs.get('pillars'):
        lines += ['', f'![各支柱发现的问题数量]({pngs["pillars"]})']
    lines += [''] + [x for p in (n.get('conclusion') or []) for x in (p, '')]
    lines += ['费用和预计费用来自 Azure 账单和 Azure 预测；规格调整和 RI/SP 的节省按 Azure 官网公开列表价计算，不是贵司的合同价。' if vm else '', '',
              '## 2. 需要立即处理的问题', '']
    issues = n.get('immediate') or default_immediate(d)
    impact = any(i.get('impact') for i in issues)
    rows = []
    for i, t in enumerate(issues, 1):
        detail = t.get('detail') or ''
        problem = f'**{t["title"].rstrip("。")}' + ('**' if detail[:1] in '，；、' else '。**') + detail
        rows.append([i, problem] + ([t.get('impact') or ''] if impact else []) + [recommendation_text(t.get('recommendation'))])
    lines += table(['#', '问题'] + (['影响'] if impact else []) + ['建议'], rows, ['---'] * (4 if impact else 3))
    lines += ['', '## 3. 成本优化', '']
    if model:
        lines += [f'### {cur.short_label}费用', ''] + [f'- {x}' for x in (n.get('costNotes') or d['narrative']['01'].get('highlights') or [])]
        if pngs.get('daily'):
            lines += ['', f'![{prev.short_label}与{cur.short_label}每日费用]({pngs["daily"]})']
    if prices and prices.get('plans'):
        lines += ['', '### 可量化的节省机会（官网列表价）', '']
        rows = [[p['label'].replace('调整后：', f'VM 降配（{vm["recommendedVMCount"]} 台）后，'), money(prices['currentMonthly']), money(p['monthlyCost']),
                 money(p['monthlySaving'])] for p in prices['plans'] if p['key'] in ('payg', 'ri1', 'sp1')]
        rows += [[r['item'], r.get('current', ''), r.get('after', ''), r.get('saving', '')] for r in n.get('extraSavings') or []]
        lines += table(['方案', '当前每月 USD', '调整后每月 USD', '每月节省 USD'], rows, ['---', '---:', '---:', '---:'])
        notes = [p['note'] for p in prices['plans'] if p['key'] in ('ri1', 'sp1') and p.get('fallbackCount')]
        lines += ['', '- 各 VM 方案需要选择一种，节省不能相加。'] + [f'- {x}。' for x in sorted(set(notes))] + \
                 ['- VM 的 3 年 RI 和 SP 价格见附件二。', '- 建议先降配并观察稳定后，再按实际长期用量确定 RI 或 SP 的数量和期限。']
    if n.get('savingsPending'):
        lines += ['', '### 需要贵司确认后才能估算节省的项目', ''] + table(['项目', '现状'], [[r['item'], r['status']] for r in n['savingsPending']], ['---', '---'])
    notes = n.get('pillarNotes') or default_pillar_notes(d)
    for i, g in enumerate(GROUPS, 4):
        c = counts[g]
        if not sum(c.values()):
            continue
        lines += ['', f'## {i}. {g}', '', f'共 {sum(c.values())} 项问题：高 {c["高"]} 项、中 {c["中"]} 项、低 {c["低"]} 项。', '']
        lines += [f'- {x}' for x in notes.get(g, [])]
    plan = n.get('actionPlan') or default_plan(d)
    lines += ['', '## 8. 建议处理计划', '']
    for key, label in (('week', '本周内'), ('month', '一个月内'), ('quarter', '一个季度内')):
        if plan.get(key):
            lines += [f'**{label}**', ''] + [f'- {x}' for item in plan[key] for x in item.split('；') if x.strip()] + ['']
    lines += ['## 9. 需要贵司确认或提供的信息', ''] + [f'- {x}' for x in (n.get('customerQuestions') or [
        '生产和测试环境的划分：本次按订阅、资源名称和标签判断。', 'RI/SP 现有订单和预算目标，以及各资源的负责人。'])]
    lines += ['', '## 10. 后续', '', n.get('followUp') or
              f'建议每月做一次巡检，覆盖费用变化、资源利用率、闲置资源和 RI/SP 使用情况，并跟踪本报告中各项问题的处理结果。下一次可在 {nxt.short_label}账单完整后开始。',
              '', '## 附件', '']
    att = []
    if model:
        att.append(['一', f'01_{cur.short_label}月度成本巡检报告（Markdown、Excel）', f'{cur.short_label}费用对比、变化原因、数据库与存储日志用量、闲置资源、建议跟踪表'])
    if vm:
        att.append(['二', '02_虚拟机利用率与规格优化（Markdown、Excel）', '逐台 VM 的利用率、建议规格及按需、1 年和 3 年 RI、SP 价格'])
    if d['r03']:
        att.append(['三', '03_可靠性与安全巡检报告、03_可靠性与安全巡检问题清单', f'{d["r03"]["total"]} 项问题的明细、建议、验收标准和跟踪列'])
    if d['r04']:
        att.append(['四', '04_卓越运营与性能效率巡检报告、04_卓越运营与性能效率巡检问题清单', f'{d["r04"]["total"]} 项问题的明细、建议、验收标准和跟踪列'])
    if d['peer']:
        att.append(['五', '05_同类资源配置对比报告、05_同类资源配置对比明细', '各类资源的标准做法、不符合的资源及原因、需要修正的模板默认值'])
    lines += table(['编号', '文件', '内容'], att, ['---', '---', '---'])
    return format_and_check('\n'.join(x for x in lines if x is not None) + '\n')


def build(ws, cfg, period, narrative=None, log=print):
    from .waf.report import scope_text, window_of, cn_date, cn_span
    d = gather(ws, period)
    n = narrative or {}
    out = ws.month_dir('reports')
    clear_charts(out / 'charts', '00')
    pngs = {'pillars': chart(pillar_counts(d), out / 'charts' / '00_1_各支柱问题数量.png')}
    daily = sorted((out / 'charts').glob('01_1_*.png'))
    if daily:
        pngs['daily'] = f'charts/{daily[0].name}'
    scope = {'readable': None, 'note': ''}
    try:
        scope['readable'], scope['note'] = scope_text(ws)
    except FileNotFoundError:
        scope['readable'] = (d['model'] or {}).get('totals', {}).get('comparableSubscriptionCount')
    datasets = {}
    for name in ('reliability', 'performance'):
        p = ws.month_dir('findings') / 'waf' / f'{name}.json'
        if p.exists():
            datasets[name] = read_json(p)
    snapshot, _ = window_of({k: v for k, v in datasets.items() if k == 'reliability'})
    _, perf_window = window_of({k: v for k, v in datasets.items() if k == 'performance'})
    scope['snapshot'] = cn_date(snapshot) if snapshot else None
    scope['window'] = cn_span(*perf_window) if perf_window else None
    md = markdown(cfg, period, d, n, pngs, scope)
    path = out / f'{stem(period)}.md'
    path.write_text(md, encoding='utf-8')
    write_json(ws.month_dir('findings') / 'summary.json', {'file': path.name, 'pillarCounts': {g: dict(c) for g, c in pillar_counts(d).items()}})
    log(f'00 汇总报告：{path.name}')
    return path
