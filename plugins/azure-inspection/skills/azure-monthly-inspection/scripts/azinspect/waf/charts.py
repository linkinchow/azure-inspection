"""Charts for 03/04: problems per check stacked by severity (PNG + native Excel), alert coverage of key resources (PNG)."""
from __future__ import annotations

from collections import Counter

from matplotlib.patches import Patch
from openpyxl.chart import BarChart, Reference
from openpyxl.chart.series import SeriesLabel

from ..core import charts as cs
from .checks import CHECKS, group_of

HAS, MISSING = '#2a78d6', '#d9d8d2'
FILES = {'可靠性': '03_1_可靠性各检查项问题数量.png', '安全': '03_2_安全各检查项问题数量.png',
         '卓越运营': '04_1_卓越运营各检查项问题数量.png', '性能效率': '04_2_性能效率各检查项问题数量.png'}
ALERT_FILE = '04_3_生产资源告警覆盖情况.png'
ALERT_ORDER = ['AKS 集群', 'MySQL 灵活服务器', 'PostgreSQL 灵活服务器', 'Azure Managed Redis', 'Azure Cache for Redis', 'MongoDB (vCore)',
               '应用网关', 'Front Door / CDN 配置文件', 'Key Vault', '存储账户（费用前 10）']


def stacked_by_check(path, title, rows):
    """rows = [(check name, Counter(severity))], drawn top to bottom in the given order."""
    fig, ax = cs.figure(10, 0.36 * len(rows) + 1.3)
    cs.style(ax, 'x')
    total_max = max([sum(c.values()) for _, c in rows] + [1])
    for i, (name, c) in enumerate(reversed(rows)):
        left = 0
        for sev in ('高', '中', '低'):
            v = c[sev]
            if v:
                ax.barh(i, v, left=left, height=0.56, color=cs.SEVERITY[sev], edgecolor=cs.SURFACE, linewidth=2)
                if v >= total_max * 0.06:
                    ax.text(left + v / 2, i, str(v), ha='center', va='center', fontsize=8, color='white' if sev != '低' else cs.INK)
            left += v
        ax.text(left + total_max * 0.01, i, f'{left}' + (f'（高 {c["高"]}）' if c['高'] else ''), va='center', fontsize=8.5, color=cs.INK)
    ax.set_yticks(range(len(rows)), [n for n, _ in reversed(rows)], fontsize=9, color=cs.INK)
    ax.set_xlim(0, total_max * 1.2)
    ax.legend(handles=[Patch(color=color, label=sev) for sev, color in cs.SEVERITY.items()], title='严重程度', loc='lower right',
              frameon=False, fontsize=8.5, title_fontsize=8.5, ncol=3, labelcolor=cs.INK2)
    ax.set_title(title, loc='left', fontsize=11, color=cs.INK, pad=10)
    cs.save(fig, path)


def make_pngs(report, findings, checks, chart_dir):
    out = {}
    for group in dict.fromkeys(group_of(c) for c in checks):
        counts = {code: Counter() for code in checks if group_of(code) == group}
        for f in findings:
            if f['check'] in counts:
                counts[f['check']][f['severity']] += 1
        stacked_by_check(chart_dir / FILES[group], f'{group}：各检查项发现的问题数量', [(CHECKS.get(k, k), v) for k, v in counts.items()])
        out[group] = f'charts/{FILES[group]}'
    return out


def alert_coverage_png(ops_data, chart_dir):
    inv = ((ops_data or {}).get('inventory') or {}).get('monitoringCoverageByType') or {}
    rows = [(name, inv[name].get('withAlert') or 0, inv[name]['total']) for name in ALERT_ORDER if name in inv and inv[name].get('total')]
    if not rows:
        return None
    vm = inv.get('虚拟机（非 AKS）') or {}
    fig, ax = cs.figure(10, 0.36 * len(rows) + 1.5)
    cs.style(ax, 'x')
    for i, (name, has, total) in enumerate(reversed(rows)):
        ax.barh(i, has, height=0.56, color=HAS, edgecolor=cs.SURFACE, linewidth=2)
        ax.barh(i, total - has, left=has, height=0.56, color=MISSING, edgecolor=cs.SURFACE, linewidth=2)
        ax.text(total + 0.4, i, f'{has} / {total}', va='center', fontsize=8.5, color=cs.INK)
    ax.set_yticks(range(len(rows)), [n for n, *_ in reversed(rows)], fontsize=9, color=cs.INK)
    ax.set_xlim(0, max(t for *_, t in rows) * 1.18)
    ax.legend(handles=[Patch(color=HAS, label='有告警'), Patch(color=MISSING, label='没有告警')], loc='lower right', frameon=False,
              fontsize=8.5, ncol=2, labelcolor=cs.INK2)
    ax.set_title('关键资源的告警覆盖情况（有告警的数量 / 总数）', loc='left', fontsize=11, color=cs.INK, pad=10)
    if vm.get('total'):
        ax.text(0, -0.13, f'另有 {vm["total"]} 台非 AKS 虚拟机，有告警的 {vm.get("withAlert") or 0} 台（未画入，避免压缩其他条形）。',
                transform=ax.transAxes, fontsize=8, color=cs.INK2)
    cs.save(fig, chart_dir / ALERT_FILE)
    return f'charts/{ALERT_FILE}'


def add_overview_charts(ws, groups):
    """Stacked severity bars on the 概览 sheet; groups = [(title, first_row, last_row, anchor)] over B (name) and D:F (高/中/低)."""
    for title, first, last, anchor in groups:
        ch = BarChart()
        ch.type, ch.grouping, ch.overlap, ch.gapWidth = 'bar', 'stacked', 100, 50
        ch.height, ch.width = 0.55 * (last - first + 1) + 3, 18
        ch.add_data(Reference(ws, min_col=4, max_col=6, min_row=first, max_row=last), titles_from_data=False)
        for series, sev in zip(ch.series, ('高', '中', '低')):
            series.tx = SeriesLabel(v=sev)
            series.graphicalProperties.solidFill = cs.SEVERITY[sev][1:]
            series.graphicalProperties.line.solidFill = 'FCFCFB'
        ch.set_categories(Reference(ws, min_col=2, min_row=first, max_row=last))
        ch.x_axis.scaling.orientation = 'maxMin'
        ch.x_axis.delete = ch.y_axis.delete = False
        ch.y_axis.crosses = 'max'
        ch.legend.position, ch.legend.overlay = 'b', False
        col = ''.join(c for c in anchor if c.isalpha())
        row = int(''.join(c for c in anchor if c.isdigit()))
        ws[f'{col}{row - 1}'] = title
        ws.add_chart(ch, anchor)
