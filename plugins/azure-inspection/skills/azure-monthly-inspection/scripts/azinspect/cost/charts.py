"""Charts for the monthly cost report: PNG for Markdown and native Excel charts. Values come from the model only."""
from __future__ import annotations

from collections import defaultdict
from datetime import date

import matplotlib.dates as mdates
from matplotlib.ticker import FuncFormatter
from openpyxl.chart import BarChart, LineChart, Reference
from openpyxl.chart.marker import DataPoint

from ..core import charts as cs
from .views import REGION_LABELS


def files(labels):
    return {'daily': f'01_1_{labels["prev"]}至{labels["cur"]}每日费用.png', 'forecast': f'01_2_{labels["next"]}每日费用实际与预测.png',
            'groups': f'01_3_各业务组{labels["prev"]}与{labels["cur"]}费用.png', 'services': '01_4_费用增减最大的服务.png', 'regions': '01_5_各区域费用增减.png'}


def _k(x, _=None):
    return f'{x / 1000:,.0f}K' if abs(x) >= 1000 else f'{x:,.0f}'


def chart_data(model, sup, period):
    daily = {r['day']: r for r in model['daily']}
    nxt = defaultdict(lambda: {'actual': 0.0, 'forecast': 0.0})
    for s in sup['forecast']['subscriptions']:
        o = s['next']
        if o.get('fullMonthEstimate') is None:
            continue
        for p in o['daily']:
            nxt[int(p['date'][8:10])]['actual' if str(p['costStatus']).lower() == 'actual' else 'forecast'] += p['cost']
    prev, cur, following = period.previous, period.current, period.following
    services = sorted(model['services'], key=lambda r: -abs(r['delta']))[:10]
    regions = sorted(sup['region']['overall']['byLocation'], key=lambda r: -abs(r['cur'] - r['prev']))[:8]
    return {'timeline': [(date(prev.year, prev.month, d), (daily.get(d) or {}).get('prev')) for d in range(1, prev.days + 1)]
                        + [(date(cur.year, cur.month, d), (daily.get(d) or {}).get('cur')) for d in range(1, cur.days + 1)],
            'prevDailyAverage': model['comparableTotals']['prevDaily'], 'curDailyAverage': model['comparableTotals']['curDaily'],
            'next': [(d, nxt[d]['actual'] if nxt[d]['actual'] else None, nxt[d]['forecast'] if nxt[d]['forecast'] else None) for d in range(1, following.days + 1)],
            'groups': [(r['name'], r['prev'], r['cur']) for r in model['groups']],
            'services': [(r['name'], r['delta']) for r in services],
            'regions': [(REGION_LABELS.get(r['location'], r['location']), r['cur'] - r['prev']) for r in regions]}


def _line(ax, x, y, color, **kw):
    ax.plot(x, y, color=color, lw=2, solid_joinstyle='round', solid_capstyle='round', dash_capstyle='round', **kw)


def make_pngs(data, labels, chart_dir):
    names = files(labels)
    Lp, Lc, Ln = labels['prev'], labels['cur'], labels['next']
    fig, ax = cs.figure(11, 4)
    cs.style(ax)
    prev = [(d, v) for d, v in data['timeline'][:labels['prevDays']] if v is not None]
    cur = [(d, v) for d, v in data['timeline'][labels['prevDays']:] if v is not None]
    _line(ax, [d for d, _ in prev], [v for _, v in prev], cs.GRAY, label=Lp)
    if prev and cur:
        _line(ax, [prev[-1][0]] + [d for d, _ in cur], [prev[-1][1]] + [v for _, v in cur], cs.BLUE, label=Lc)
    peak = max([v for _, v in prev + cur] or [1])
    for rows, avg, color, name in [(prev, data['prevDailyAverage'], cs.GRAY, f'{Lp}日均'), (cur, data['curDailyAverage'], cs.BLUE, f'{Lc}日均')]:
        if rows:
            ax.plot([rows[0][0], rows[-1][0]], [avg, avg], color=color, lw=1, alpha=0.8)
            ax.text(rows[0][0], avg + peak * 0.02, f'{name} {avg:,.0f}', color=cs.INK2, fontsize=8)
    ax.xaxis.set_major_locator(mdates.WeekdayLocator(byweekday=0))
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d'))
    ax.yaxis.set_major_formatter(FuncFormatter(_k))
    ax.set_ylim(0, peak * 1.15)
    ax.set_xlabel('日期（刻度为每周一）', fontsize=9, color=cs.INK2)
    ax.set_title(f'{Lp}与{Lc}每日费用（USD）', loc='left', fontsize=11, color=cs.INK, pad=10)
    ax.legend(loc='lower left', frameon=False, fontsize=9, ncol=2, labelcolor=cs.INK2)
    cs.save(fig, chart_dir / names['daily'])

    fig, ax = cs.figure(10, 4)
    cs.style(ax)
    actual = [(d, a) for d, a, _ in data['next'] if a is not None]
    forecast = [(d, f) for d, _, f in data['next'] if f is not None]
    if actual:
        _line(ax, [d for d, _ in actual], [v for _, v in actual], cs.BLUE, label=f'{Ln}实际')
    if forecast:
        head = [actual[-1]] if actual else []
        _line(ax, [d for d, _ in head + forecast], [v for _, v in head + forecast], cs.BLUE, linestyle=(0, (4, 3)), label=f'{Ln}预测（Azure）')
    peak = max([v for _, v in actual + forecast] or [1])
    ax.axhline(data['curDailyAverage'], color=cs.INK2, lw=1, alpha=0.6)
    ax.text(1, data['curDailyAverage'] + peak * 0.02, f'{Lc}日均 {data["curDailyAverage"]:,.0f}', color=cs.INK2, fontsize=8)
    ax.set_xlim(0.5, len(data['next']) + 0.5)
    ax.set_xlabel(f'{Ln}日期（实线为实际，虚线为 Azure 预测）', fontsize=9, color=cs.INK2)
    ax.yaxis.set_major_formatter(FuncFormatter(_k))
    ax.set_ylim(0, peak * 1.15)
    ax.set_title(f'{Ln}每日费用：实际与预测（USD）', loc='left', fontsize=11, color=cs.INK, pad=10)
    ax.legend(loc='lower left', frameon=False, fontsize=9, ncol=2, labelcolor=cs.INK2)
    cs.save(fig, chart_dir / names['forecast'])

    groups = list(reversed(data['groups']))
    fig, ax = cs.figure(10, 0.5 * len(groups) + 1.4)
    cs.style(ax, 'x')
    y, h = range(len(groups)), 0.34
    ax.barh([i + h / 2 + 0.02 for i in y], [g[1] for g in groups], height=h, color=cs.GRAY, label=Lp)
    ax.barh([i - h / 2 - 0.02 for i in y], [g[2] for g in groups], height=h, color=cs.BLUE, label=Lc)
    for i, g in zip(y, groups):
        change = f'（{(g[2] / g[1] - 1):+.1%}）' if g[1] else ''
        ax.text(g[2], i - h / 2 - 0.02, f'  {_k(g[2])}{change}', va='center', fontsize=9, color=cs.INK)
    ax.set_yticks(list(y), [g[0] for g in groups], fontsize=10, color=cs.INK)
    ax.xaxis.set_major_formatter(FuncFormatter(_k))
    ax.set_xlim(0, max([max(g[1], g[2]) for g in groups] or [1]) * 1.22)
    ax.set_title(f'各业务组{Lp}与{Lc}费用（USD；括号内为月度变化）', loc='left', fontsize=11, color=cs.INK, pad=10)
    ax.legend(loc='lower right', frameon=False, fontsize=9, labelcolor=cs.INK2)
    cs.save(fig, chart_dir / names['groups'])

    for key, rows, title in [('services', data['services'], f'费用增减最大的 {len(data["services"])} 个服务（{Lc}比{Lp}，USD）'),
                             ('regions', data['regions'], f'费用增减最大的 {len(data["regions"])} 个区域（{Lc}比{Lp}，USD）')]:
        rows = list(reversed(rows))
        fig, ax = cs.figure(10, 0.42 * len(rows) + 1.2)
        cs.style(ax, 'x')
        ax.barh(range(len(rows)), [v for _, v in rows], height=0.55, color=[cs.INCREASE if v > 0 else cs.DECREASE for _, v in rows])
        ax.axvline(0, color=cs.INK2, lw=1)
        span = max([abs(v) for _, v in rows] or [1])
        for i, (_, v) in enumerate(rows):
            ax.text(v + (span * 0.015 if v > 0 else -span * 0.015), i, f'{v:+,.0f}', va='center', ha='left' if v > 0 else 'right', fontsize=9, color=cs.INK)
        ax.set_yticks(range(len(rows)), [n for n, _ in rows], fontsize=9, color=cs.INK)
        ax.set_xlim(-span * 1.3, span * 1.3)
        ax.xaxis.set_major_formatter(FuncFormatter(_k))
        ax.set_title(title, loc='left', fontsize=11, color=cs.INK, pad=10)
        ax.text(1, -0.12, '红色：增加    蓝色：减少', transform=ax.transAxes, ha='right', fontsize=8, color=cs.INK2)
        cs.save(fig, chart_dir / names[key])
    return {k: f'charts/{v}' for k, v in names.items()}


def _color(series, color, line=False, dashed=False):
    if line:
        series.graphicalProperties.line.solidFill = color
        series.graphicalProperties.line.width = 22000
        if dashed:
            series.graphicalProperties.line.dashStyle = 'dash'
        series.smooth = False
    else:
        series.graphicalProperties.solidFill = color
        series.graphicalProperties.line.solidFill = color


def add_excel_sheet(sheet, data, labels):
    Lp, Lc, Ln = labels['prev'], labels['cur'], labels['next']
    ws = sheet('图表', f'{Lc}费用图表', '图表数据取自本工作簿各页及 Azure 预测；节省金额不在此页。',
               ['日期', f'{Lp}USD', f'{Lc}USD', '', f'{Ln}日期', f'{Ln}实际USD', f'{Ln}预测USD', f'{Lc}日均USD'])
    for i, (d, v) in enumerate(data['timeline'], 4):
        ws.cell(i, 1, d.strftime('%m-%d'))
        ws.cell(i, 2 if i - 4 < labels['prevDays'] else 3, v)
    for i, (d, a, f) in enumerate(data['next'], 4):
        ws.cell(i, 5, f'{labels["nextMonth"]:02d}-{d:02d}')
        ws.cell(i, 6, a)
        ws.cell(i, 7, f)
        ws.cell(i, 8, data['curDailyAverage'])
    n, on = 3 + len(data['timeline']), 3 + len(data['next'])
    blocks, row = {}, n + 3
    for key, header, rows in [('groups', ['业务组', f'{Lp}USD', f'{Lc}USD'], data['groups']), ('services', ['服务', '增减USD'], data['services']),
                              ('regions', ['区域', '增减USD'], data['regions'])]:
        for c, h in enumerate(header, 1):
            ws.cell(row, c, h)
        for i, values in enumerate(rows, row + 1):
            for c, v in enumerate(values, 1):
                ws.cell(i, c, v)
        blocks[key] = (row, row + len(rows))
        row += len(rows) + 3

    def title(anchor, text):
        col = ''.join(c for c in anchor if c.isalpha())
        ws[f'{col}{int("".join(c for c in anchor if c.isdigit())) - 1}'] = text

    def line_chart(text, cols, colors, anchor, last, category_col, dashed=()):
        ch = LineChart()
        ch.height, ch.width = 7.5, 18
        ch.y_axis.numFmt = '#,##0'
        title(anchor, text)
        for col, color in zip(cols, colors):
            ch.add_data(Reference(ws, min_col=col, min_row=3, max_row=last), titles_from_data=True)
            _color(ch.series[-1], color, line=True, dashed=col in dashed)
        ch.set_categories(Reference(ws, min_col=category_col, min_row=4, max_row=last))
        ch.x_axis.delete = ch.y_axis.delete = False
        ch.legend.position, ch.legend.overlay = 'b', False
        ch.x_axis.tickLblSkip = ch.x_axis.tickMarkSkip = 7 if last - 3 > 31 else 5
        ws.add_chart(ch, anchor)
    line_chart(f'{Lp}与{Lc}每日费用（USD）', [2, 3], ['A09F98', '2A78D6'], 'J5', n, 1)
    line_chart(f'{Ln}每日费用：实际与预测（USD）', [6, 7, 8], ['2A78D6', '2A78D6', '52514E'], 'J22', on, 5, dashed=(7,))

    def bar_chart(text, key, cols, colors, anchor, diverging=False):
        first, last = blocks[key]
        if last == first:
            return
        ch = BarChart()
        ch.type, ch.height, ch.width, ch.gapWidth = 'bar', 7.5, 18, 60
        ch.y_axis.numFmt = '#,##0;-#,##0'
        title(anchor, text)
        for col, color in zip(cols, colors):
            ch.add_data(Reference(ws, min_col=col, min_row=first, max_row=last), titles_from_data=True)
            _color(ch.series[-1], color)
        ch.set_categories(Reference(ws, min_col=1, min_row=first + 1, max_row=last))
        if diverging:
            for idx in range(last - first):
                v = ws.cell(first + 1 + idx, 2).value or 0
                pt = DataPoint(idx=idx, invertIfNegative=False)
                pt.graphicalProperties.solidFill = pt.graphicalProperties.line.solidFill = 'E34948' if v > 0 else '2A78D6'
                ch.series[0].dPt.append(pt)
            ch.series[0].invertIfNegative = False
            ch.x_axis.tickLblPos = 'low'
            ch.legend = None
        else:
            ch.legend.position, ch.legend.overlay = 'b', False
        ch.x_axis.scaling.orientation = 'maxMin'
        ch.x_axis.delete = ch.y_axis.delete = False
        ch.y_axis.crosses = 'max'
        ws.add_chart(ch, anchor)
    bar_chart(f'各业务组{Lp}与{Lc}费用（USD）', 'groups', [2, 3], ['A09F98', '2A78D6'], 'J39')
    bar_chart(f'费用增减最大的 {len(data["services"])} 个服务（红色增加，蓝色减少）', 'services', [2], ['2A78D6'], 'J56', diverging=True)
    bar_chart(f'费用增减最大的 {len(data["regions"])} 个区域（红色增加，蓝色减少）', 'regions', [2], ['2A78D6'], 'J73', diverging=True)
    return ws
