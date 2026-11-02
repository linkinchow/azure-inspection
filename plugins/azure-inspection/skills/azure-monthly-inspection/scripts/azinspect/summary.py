"""00 汇总报告: numbers from 01-05, explanations from narrative/00.json (agent), defaults from the 03/04 narratives and data.

Numbers are never written by hand here: every amount and count is read from the other reports' outputs, so the
summary cannot disagree with them (crosscheck X6 verifies this again).
"""
from __future__ import annotations

import re
from collections import Counter

from .core import charts as cs
from .core.charts import clear as clear_charts
from .core.fmt_md import format_and_check
from .core.config import REPORTS
from .core.io import read_json, write_json
from .selection import TITLES, load as load_selection, load_groups, subscription_scope, title as report_title
from .vm.collect import WINDOW_DAYS as VM_WINDOW_DAYS
from .waf.checks import CHECKS, group_of
from .waf.report import PLAN_PERIODS, action_plan, default_top_issues, recommendation_text, stems

GROUPS = ['可靠性', '安全', '卓越运营', '性能效率']
SEVERITY_ORDER = ('高', '中', '低')
NUMERALS = '一二三四五六'


def _load(path):
    return read_json(path) if path.exists() else None


def stem(period):
    return f'00_Azure巡检汇总报告_{period.following.label}'


def money(x):
    return f'{x:,.2f}'


def ws_of(d):
    return d['ws']


def gather(ws, period):
    """The chosen reports' results only: a report left out this month may still have older results in the month folder."""
    f = ws.month_dir('findings')
    chosen = load_selection(ws)
    pick = lambda code, path: _load(path) if code in chosen else None  # noqa: E731
    d = {'model': pick('01', f / 'cost' / 'model.json'), 'vm': pick('02', f / 'vm' / 'summary.json'),
         'prices': pick('02', f / 'vm' / 'price-summary.json'), 'forecast': pick('01', ws.raw('cost/supplement/forecast.json')),
         'r03': pick('03', f / 'waf' / 'report-03.json'), 'r04': pick('04', f / 'waf' / 'report-04.json'),
         'peer': pick('05', f / 'peer' / 'baseline.json'), 'peerReport': pick('05', f / 'peer' / 'report.json'),
         'actions': pick('01', f / 'cost' / 'actions.json'), 'reports': chosen, 'groups': load_groups(ws)}
    d['narrative'] = {code: (_load(ws.month_dir('narrative') / f'{code}.json') or {}) if code in chosen else {} for code in ('01', '03', '04', '05')}
    waf = []
    for p in sorted((f / 'waf').glob('*.json')):
        data = read_json(p)
        if isinstance(data, dict) and 'findings' in data and data.get('pillar'):
            waf += [x for x in data['findings'] if group_of(x['check']) in d['groups']]   # the chosen pillars of 03/04 only
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
            group = group_of(check)
            if text and text != '未发现问题' and group in d['groups']:
                notes.setdefault(group, []).append(text)
    return {g: v[:5] for g, v in notes.items()}


def default_plan(d):
    plan = {}
    for code in ('03', '04'):
        for key, items in action_plan(d['narrative'][code].get('actionPlan')).items():
            plan.setdefault(key, []).extend(items)
    return plan


def plan_lines(plan):
    lines = []
    for key, label in PLAN_PERIODS:
        items = action_plan(plan).get(key)
        if items:
            lines += [f'**{label}**', ''] + [f'- {x}' for x in items] + ['']
    return lines


def month_row(tracked, waf_reports):
    """00's comparison with last month for the chosen 03/04; problems of a report not chosen are counted, not listed."""
    from .tracking import summary as tracking_summary
    c = tracking_summary(tracked, None if len(waf_reports) == 2 else waf_reports[0])['all']
    text = '，'.join(f'{k} {c[k]} 项' for k in c)
    others = sum(tracking_summary(tracked)['all'].values()) - sum(c.values())
    if others:
        text += f'（另有 {others} 项上月问题属于本月没有选择的报告，未列入）'
    from .waf.report import coverage_growth, older_record
    if '03' in waf_reports and coverage_growth(tracked):
        text += f'；{coverage_growth(tracked)}'
    older = older_record(tracked, None if len(waf_reports) == 2 else waf_reports[0])
    if older:
        text += f'；{older}'
    return [f'与 {tracked["previous"]} 相比', text]


def table(header, rows, align):
    out = ['|' + '|'.join(header) + '|', '|' + '|'.join(align) + '|']
    out += ['|' + '|'.join(str(c).replace('|', '/').replace('\n', ' ') for c in r) + '|' for r in rows]
    return out


def markdown(cfg, period, d, n, pngs, scope):
    model, vm, prices, chosen = d['model'], d['vm'], d['prices'], d['reports']
    counts = pillar_counts(d)
    cur, prev, nxt = period.current, period.previous, period.following
    costs = bool({'01', '02'} & set(chosen))
    section = iter(range(1, 20))
    times = ([f'- 费用：对比 {cur.label}与{prev.short_label if cur.year == prev.year else prev.label}两个完整自然月。'] if '01' in chosen else []) + \
            ([f'- 虚拟机利用率：{scope["vmWindow"]}（UTC）的 {VM_WINDOW_DAYS} 天指标。'] if scope.get('vmWindow') else []) + \
            ([f'- 配置：{scope["snapshot"]}读取。'] if scope.get('snapshot') else []) + ([f'- 性能：{scope["window"]}的数据。'] if scope.get('window') else [])
    # what was read: 01 and 02 read costs (02 the RI/SP coverage); 01 (month usage), 02, 03 and 04 read metrics; 03 and 04 read logs
    kinds = (['费用'] if costs else []) + ['配置'] + (['监控指标'] if {'01', '02', '03', '04'} & set(chosen) else []) + \
            (['日志'] if {'03', '04'} & set(chosen) else [])
    reads = '、'.join(kinds[:-1]) + '和' + kinds[-1] if len(kinds) > 1 else kinds[0]
    if tuple(chosen) == REPORTS and len(d['groups']) == 4:
        waf = '本报告按 Microsoft Azure Well-Architected Framework（WAF）的五个支柱汇总结论：成本优化、可靠性、安全、卓越运营、性能效率。每项问题的资源明细见附件。'
        content = []
    else:
        covered = (['成本优化'] if costs else []) + list(d['groups'])
        waf = (f'本报告按 Microsoft Azure Well-Architected Framework（WAF）汇总结论，本次涉及{"、".join(covered)}。' if covered else '') + '明细见附件。'
        names = '、'.join(f'{c} {report_title(c, d["groups"])}' for c in chosen)
        content = [f'**内容**：按贵司选择，本次包含 {names}，本报告只汇总这些内容。', '']
    lines = [f'# {cfg.name} Azure 巡检汇总报告（{nxt.label}）', '',
             f'**范围**：{cfg.name} ' + (f'{scope["readable"]} 个' if scope['readable'] is not None else '的') + ' Azure 订阅。'
             + (f'{scope["note"]}。' if scope['note'] else '') + (f'{scope["chosen"]}。' if scope.get('chosen') else ''), ''] + content + [
             f'**方式**：使用贵司提供的账号，以只读方式读取{reads}，没有修改任何资源，也没有做端口扫描。', ''] + \
            (['**时间**：', ''] + times + [''] if times else []) + [waf, '', f'## {next(section)}. 总体结论', '']
    rows = []
    if model:
        t = model['comparableTotals']
        rows.append([f'{cur.short_label}费用', f'USD {money(t["cur"])}，比{prev.short_label}{"增加" if t["delta"] >= 0 else "减少"} {abs(t["changeRate"] or 0):.2%}'
                     + (f'；日均费用{"上升" if t["dailyChangeRate"] >= 0 else "下降"} {abs(t["dailyChangeRate"]):.2%}' if cur.days != prev.days and t['dailyChangeRate'] is not None else '')])
    if model and d['forecast']:
        from .cost import forecast_scope
        row = forecast_scope.row_00(forecast_scope.coverage(d['forecast'], model, nxt.days, cur.days), nxt.short_label, cur.short_label)
        if row:
            rows.append(row)
    if vm:
        rows.append(['VM 规格调整', f'{vm["recommendedVMCount"]} 台建议降配，**每月约节省 USD {money(vm["monthlyPotentialSavingsUSD"])}**（官网列表价）'])
    plan_by = {p['key']: p for p in (prices or {}).get('plans', [])}
    if 'ri1' in plan_by:
        rows.append(['VM 降配后再购买 1 年 RI', f'VM 计算费用每月从 USD {money(prices["currentMonthly"])} 降到 USD {money(plan_by["ri1"]["monthlyCost"])}，'
                                            f'**每月约节省 USD {money(plan_by["ri1"]["monthlySaving"])}**（官网列表价）'])
    for code, title in (('r03', report_title('03', d['groups'])), ('r04', report_title('04', d['groups']))):
        if d[code]:
            rows.append([title, f'发现 {d[code]["total"]} 项问题，其中高风险 {d[code]["bySeverity"].get("高", 0)} 项'])
    from .tracking import load as load_tracking
    waf_reports = [c for c in ('03', '04') if c in chosen]
    tracked = load_tracking(ws_of(d)) if waf_reports else None
    if tracked and not tracked.get('first'):
        rows.append(month_row(tracked, waf_reports))
    peer = d['peerReport'] or {}
    if d['peerReport'] is not None:
        rows.append(['同类资源配置对比', f'{peer["deviations"]} 处配置偏差，其中高风险 {peer.get("highImpact", 0)} 处'
                     if peer.get('deviations') else '未发现明显的配置偏差'])
    if rows:
        lines += table(['项目', '结果'], rows, ['---', '---'])
    if pngs.get('pillars'):
        lines += ['', f'![各支柱发现的问题数量]({pngs["pillars"]})']
    lines += [''] + [x for p in (n.get('conclusion') or []) for x in (p, '')]
    basis = ''
    if vm:
        basis = ('费用和预计费用来自 Azure 账单和 Azure 预测；' if model else '') + '规格调整和 RI/SP 的节省按 Azure 官网公开列表价计算，不是贵司的合同价。'
    lines += [basis, '']
    issues = n.get('immediate') or default_immediate(d)
    if issues:
        lines += [f'## {next(section)}. 需要立即处理的问题', '']
        impact = any(i.get('impact') for i in issues)
        rows = []
        for i, t in enumerate(issues, 1):
            detail = t.get('detail') or ''
            problem = f'**{t["title"].rstrip("。")}' + ('**' if detail[:1] in '，；、' else '。**') + detail
            rows.append([i, problem] + ([t.get('impact') or ''] if impact else []) + [recommendation_text(t.get('recommendation'))])
        lines += table(['#', '问题'] + (['影响'] if impact else []) + ['建议'], rows, ['---'] * (4 if impact else 3))
        lines += ['']
    if costs:
        lines += [f'## {next(section)}. 成本优化', '']
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
                 [f'- VM 的 3 年 RI 和 SP 价格见附件{attachment_no(chosen, "02")}。', '- 建议先降配并观察稳定后，再按实际长期用量确定 RI 或 SP 的数量和期限。']
    if costs and n.get('savingsPending'):
        lines += ['', '### 需要贵司确认后才能估算节省的项目', ''] + table(['项目', '现状'], [[r['item'], r['status']] for r in n['savingsPending']], ['---', '---'])
    notes = n.get('pillarNotes') or default_pillar_notes(d)
    for g in GROUPS:
        c = counts[g]
        if not sum(c.values()):
            continue
        lines += ['', f'## {next(section)}. {g}', '', f'共 {sum(c.values())} 项问题：高 {c["高"]} 项、中 {c["中"]} 项、低 {c["低"]} 项。', '']
        lines += [f'- {x}' for x in notes.get(g, [])]
    plan = plan_lines(action_plan(n.get('actionPlan')) or default_plan(d))
    if plan:
        lines += ['', f'## {next(section)}. 建议处理计划', ''] + plan
    questions = ['生产和测试环境的划分：本次按订阅、资源名称和标签判断。',
                 'RI/SP 现有订单和预算目标，以及各资源的负责人。' if costs else '各资源的负责人。']
    lines += [f'## {next(section)}. 需要贵司确认或提供的信息', ''] + [f'- {x}' for x in (n.get('customerQuestions') or questions)]
    covers = ['费用变化'] + (['资源利用率'] if {'02', '04'} & set(chosen) else []) + ['闲置资源']
    follow = (f'建议每月做一次巡检，覆盖{"、".join(covers)}和 RI/SP 使用情况，并跟踪本报告中各项问题的处理结果。下一次可在 {nxt.short_label}账单完整后开始。'
              if '01' in chosen else '建议定期巡检，并跟踪本报告中各项问题的处理结果。')
    lines += ['', f'## {next(section)}. 后续', '', n.get('followUp') or follow, '', '## 附件', '']
    att = []
    if model:
        att.append([f'01_{cur.short_label}月度成本巡检报告（Markdown、Excel）', f'{cur.short_label}费用对比、变化原因、数据库与存储日志用量、闲置资源、建议跟踪表'])
    if vm:
        att.append(['02_虚拟机利用率与规格优化（Markdown、Excel）', '逐台 VM 的利用率、建议规格及按需、1 年和 3 年 RI、SP 价格'])
    if d['r03']:
        att.append(['、'.join(stems('03', d['groups'])), f'{d["r03"]["total"]} 项问题的明细、建议、验收标准和跟踪列'])
    if d['r04']:
        att.append(['、'.join(stems('04', d['groups'])), f'{d["r04"]["total"]} 项问题的明细、建议、验收标准和跟踪列'])
    if d['peer'] or d['peerReport'] is not None:
        att.append(['05_同类资源配置对比报告、05_同类资源配置对比明细', '各类资源的标准做法、不符合的资源及原因、需要修正的模板默认值'])
    lines += table(['编号', '文件', '内容'], [[NUMERALS[i]] + a for i, a in enumerate(att)], ['---', '---', '---'])
    return format_and_check(tidy('\n'.join(x for x in lines if x is not None)) + '\n')


SECTION = re.compile(r'^## \d+\. ')


def tidy(text):
    """One blank line between blocks and before every heading; a numbered section with nothing under it (e.g. 成本优化
    when only 02 is chosen and no price plan was computed) is dropped and the sections renumbered."""
    def collapse(lines):
        out = []
        for line in lines:
            if line == '' and (not out or out[-1] == ''):
                continue
            if line.startswith('#') and out and out[-1] != '':
                out.append('')
            out.append(line)
        return out
    lines = collapse(text.split('\n'))
    lines = [x for i, x in enumerate(lines)
             if not (SECTION.match(x) and next((y for y in lines[i + 1:] if y), '').startswith('## '))]
    lines, number = collapse(lines), 0
    for i, x in enumerate(lines):
        if SECTION.match(x):
            number += 1
            lines[i] = SECTION.sub(f'## {number}. ', x)
    return '\n'.join(lines).rstrip('\n')


def attachment_no(chosen, code):
    """Attachments are numbered in the order of the chosen reports: 一 is the first chosen one."""
    return NUMERALS[[c for c in REPORTS if c in chosen].index(code)]


def build(ws, cfg, period, narrative=None, log=print):
    from .waf.report import scope_text, window_of, cn_date, cn_span
    d = gather(ws, period)
    n = narrative or {}
    out = ws.month_dir('reports')
    missing = [c for c in d['reports'] if not any(out.glob(f'{c}_*.md'))]
    if missing:
        raise SystemExit(f'所选报告还没有生成：{"、".join(f"{c} {TITLES[c]}" for c in missing)}。先补采、分析并 build 这些部分，'
                         '或在 customer.yaml 的 report.include 中去掉，再生成 00')
    clear_charts(out / 'charts', '00')
    pngs = {'pillars': chart(pillar_counts(d), out / 'charts' / '00_1_各支柱问题数量.png')}
    daily = sorted((out / 'charts').glob('01_1_*.png'))
    if daily:
        pngs['daily'] = f'charts/{daily[0].name}'
    scope = {'readable': None, 'note': '', 'chosen': subscription_scope(ws, cfg)}
    try:
        scope['readable'], scope['note'] = scope_text(ws)
    except FileNotFoundError:
        scope['readable'] = (d['model'] or {}).get('totals', {}).get('comparableSubscriptionCount') or (d['vm'] or {}).get('subscriptionCount')
    datasets = {}
    for name, group in (('reliability', '可靠性'), ('security_network', '安全'), ('operations', '卓越运营'), ('performance', '性能效率')):
        p = ws.month_dir('findings') / 'waf' / f'{name}.json'
        if p.exists() and group in d['groups']:
            datasets[name] = read_json(p)
    configured = [k for k in ('reliability', 'security_network', 'operations') if k in datasets]
    snapshot, _ = window_of({configured[0]: datasets[configured[0]]} if configured else {})
    _, perf_window = window_of({k: v for k, v in datasets.items() if k == 'performance'})
    if not snapshot and '05' in d['reports'] and ws.raw('waf/scope.json').exists():   # 05 alone: configuration read with the scope
        snapshot = str(read_json(ws.raw('waf/scope.json')).get('collectedAt') or '')[:10] or None
    scope['snapshot'] = cn_date(snapshot) if snapshot else None
    scope['window'] = cn_span(*perf_window) if perf_window else None
    vm_manifest = ws.raw('vm/metrics/manifest.json')
    if '02' in d['reports'] and vm_manifest.exists():
        m = read_json(vm_manifest)
        scope['vmWindow'] = cn_span(str(m['start'])[:10], str(m['end'])[:10])
    md = markdown(cfg, period, d, n, pngs, scope)
    path = out / f'{stem(period)}.md'
    path.write_text(md, encoding='utf-8')
    write_json(ws.month_dir('findings') / 'summary.json', {'file': path.name, 'pillarCounts': {g: dict(c) for g, c in pillar_counts(d).items()}})
    log(f'00 汇总报告：{path.name}')
    return path
