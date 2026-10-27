"""03 可靠性与安全、04 卓越运营与性能效率: Excel issue list + Markdown report.

Counts, resources covered, coverage and unreadable scope come from the findings files. Explanations (top issues,
per-check notes, action plan, severity changes with reasons) come from narrative/03.json and narrative/04.json,
written by the agent; without them a plain default is generated from the data.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter as L

from ..core.excel import SEVERITY_FILL, verify
from ..core.fmt_md import format_and_check
from ..core.io import write_json
from . import architecture
from . import charts as waf_charts
from .checks import ACCEPTANCE, CHECKS, check_number, count_text, group_of, report_of, type_label
from .common import PILLARS, REPORT_OF, env_text, load_findings, load_scope

ORDER = {'高': 0, '中': 1, '低': 2}
REPORTS = {
    '03': {'title': '可靠性与安全巡检', 'groups': ['可靠性', '安全'],
           'severity': '**高**＝可能直接导致故障、数据丢失或被入侵；**中**＝单点故障或缺少必要防护；**低**＝建议改进。',
           'method': '只读读取配置、指标和日志，未修改任何资源，也未做端口扫描',
           'notes': ['端口是否对公网开放是根据 NSG、公网 IP 和负载均衡规则离线判断，未做端口扫描或连接测试。',
                     '集群内部配置（Pod 副本数、PodDisruptionBudget、健康检查、资源请求）需要 AKS 只读访问，本次未检查。',
                     '只读取了凭据的到期时间等元数据，未读取任何密钥、密码或连接字符串。'],
           'links': [('可靠性检查表', 'https://learn.microsoft.com/en-us/azure/well-architected/reliability/checklist'),
                     ('安全性检查表', 'https://learn.microsoft.com/en-us/azure/well-architected/security/checklist'),
                     ('AKS 的 Well-Architected 服务指南', 'https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-kubernetes-service'),
                     ('AKS API Server 访问控制', 'https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges')]},
    '04': {'title': '卓越运营与性能效率巡检', 'groups': ['卓越运营', '性能效率'],
           'severity': '**高**＝故障可能无人发现，或用户已经受到影响；**中**＝监控覆盖缺口或接近容量上限；**低**＝建议改进。'
                       '性能判断看两点：平均负载是否持续偏高，以及每日最高值打满的天数。',
           'method': '只读读取配置、指标、告警和日志，未修改任何资源',
           'notes': ['没有集群只读访问时，集群内自建的监控只能从节点池和磁盘名称推断。'],
           'links': [('卓越运营检查表', 'https://learn.microsoft.com/en-us/azure/well-architected/operational-excellence/checklist'),
                     ('性能效率检查表', 'https://learn.microsoft.com/en-us/azure/well-architected/performance-efficiency/checklist'),
                     ('AKS 的 Well-Architected 服务指南', 'https://learn.microsoft.com/en-us/azure/well-architected/service-guides/azure-kubernetes-service'),
                     ('Azure Monitor 建议告警规则（AKS）', 'https://learn.microsoft.com/en-us/azure/azure-monitor/containers/kubernetes-metric-alerts')]},
}
COUNT_NOTE = ('表中“高、中、低”是问题条数，即 Excel 问题清单的行数：同类问题按订阅或资源合并为一条，重要问题按资源单独列出。'
              '“涉及资源数”是这些问题涉及的资源数量，同一资源在一个检查项下只算一次。')
LIST_COLUMNS = ['编号', '支柱', '检查项', '严重程度', '订阅', '资源组', '资源', '资源类型', '环境（推断）', '发现', '建议', '验收标准',
                '需要客户确认', '与同类资源的差异', '根本原因', '对齐标准的做法', '涉及资源数', '涉及资源', '与上月相比', '负责人', '客户决定', '处理状态', '完成日期']


class NarrativeError(ValueError):
    pass


def stems(report):
    title = REPORTS[report]['title']
    return f'{report}_{title}报告', f'{report}_{title}问题清单'


# ---------------------------------------------------------------- data

def load(ws, report):
    SUB_NAMES.update({s['id'].lower(): s['name'] for s in load_scope(ws)})
    links_path = ws.month_dir('findings') / 'peer' / 'links.json'
    peer_links = json.loads(links_path.read_text(encoding='utf-8')) if links_path.exists() else {}
    datasets, findings = {}, []
    for p in PILLARS:
        if not (ws.month_dir('findings') / 'waf' / f'{p}.json').exists():
            continue
        data = load_findings(ws, p)
        mine = [f for f in data['findings'] if report_of(f['check']) == report]
        if REPORT_OF[p] != report and not mine:
            continue
        # a pillar can contribute to the other report (APRL O11 goes to 04): keep only this report's rows and coverage
        datasets[p] = {**data, 'findings': mine, 'coverage': {k: v for k, v in data['coverage'].items() if report_of(k) == report}}
        for f in mine:
            peer = {k: v for k, v in (peer_links.get(f['id']) or {}).items() if v and not f.get(k)}   # the finding's own text wins
            findings.append({**f, **peer, 'pillar': p, 'group': group_of(f['check']), 'checkName': CHECKS.get(f['check'], f['check'])})
    return datasets, findings


def resolve(findings, fid):
    for f in findings:
        if fid in (f['id'], f.get('legacyId')):
            return f
    raise NarrativeError(f'说明文件引用的问题编号不存在：{fid}')


def apply_narrative(findings, narrative):
    for o in narrative.get('severityOverrides') or []:
        if o.get('severity') not in ORDER or not str(o.get('reason') or '').strip():
            raise NarrativeError(f'severityOverrides 需要有效的 severity 和 reason：{o}')
        f = resolve(findings, o['findingId'])
        f['originalSeverity'], f['severity'] = f['severity'], o['severity']
        f['severityReason'] = o['reason']
    for o in narrative.get('findingTextOverrides') or []:
        f = resolve(findings, o['findingId'])
        for key in ('finding', 'recommendation', 'needsConfirmation', 'acceptance'):
            if o.get(key):
                f[key] = o[key]
    for issue in narrative.get('topIssues') or []:
        for fid in issue.get('findingIds') or []:
            resolve(findings, fid)


def sort_key(f):
    head, num = check_number(f['check'])
    return ORDER[f['severity']], REPORTS_GROUP_INDEX.get(f['group'], 9), head, num, f.get('subscriptionName') or '', f['id']


REPORTS_GROUP_INDEX = {'可靠性': 0, '安全': 1, '卓越运营': 0, '性能效率': 1}


SUB_NAMES: dict = {}   # subscription id -> name, filled by load() so GUID members read as names


def members(f):
    named = [{**m, 'name': SUB_NAMES.get(str(m['name']).lower(), m['name'])} for m in f.get('members') or [] if m.get('name')]
    return named or ([{'name': f['resourceName'], 'type': f.get('resourceType'),
                                                                      'subscription': f.get('subscriptionName')}] if f.get('resourceName') else [])


def resources_text(findings):
    """'5 个子网、3 个集群' over distinct resources of one check."""
    seen, counts = set(), Counter()
    for f in findings:
        for m in members(f):
            key = ((m.get('subscription') or '').lower(), str(m['name']).lower(), (m.get('type') or '').lower())
            if key not in seen:
                seen.add(key)
                counts[type_label(m.get('type'))] += 1
    return '、'.join(count_text(n, label) for label, n in counts.most_common()) or '—'


def scope_text(ws):
    subs = load_scope(ws)
    disabled = sorted(s['name'] for s in subs if s.get('state') != 'Enabled')
    readable = len(subs) - len(disabled)
    if not disabled:
        return readable, ''
    prefix = os.path.commonprefix(disabled)
    shown = f'{prefix}*' if len(disabled) > 3 and len(prefix) >= 4 else '、'.join(disabled[:3]) + (f' 等 {len(disabled)} 个' if len(disabled) > 3 else '')
    return readable, f'另有 {len(disabled)} 个未启用订阅（{shown}）无法读取，未纳入检查'


def window_of(datasets):
    snapshots, windows = [], []
    for data in datasets.values():
        w = data.get('window') or {}
        snap = w.get('snapshot') or str(w.get('end') or '')[:10]
        if snap:
            snapshots.append(snap)
        if w.get('start') and w.get('end'):
            windows.append((str(w['start'])[:10], str(w['end'])[:10]))
    return (max(snapshots) if snapshots else None), (windows[0] if windows else None)


def cn_span(start, end):
    """'2026 年 9 月 21 日至 10 月 21 日' (year shown once when both dates are in the same year)."""
    tail = cn_date(end)
    return f'{cn_date(start)}至{tail.split(" 年 ", 1)[1] if start[:4] == end[:4] else tail}'


def cn_date(iso):
    return f'{int(iso[:4])} 年 {int(iso[5:7])} 月 {int(iso[8:10])} 日' if iso and len(iso) >= 10 else '未记录'


# ---------------------------------------------------------------- defaults

def first_clause(text, limit=70):
    text = str(text or '')
    for sep in ('。', '；'):
        text = text.split(sep)[0]
    return text if len(text) <= limit else text[:limit].rstrip('，、') + '……'


def default_top_issues(findings):
    picked = [f for f in findings if f['severity'] == '高']
    picked += [f for f in findings if f['severity'] == '中' and f['environment'].get('value') == 'prod']
    return [{'title': f'{f["checkName"]}：{f.get("resourceName") or f.get("subscriptionName") or ""}', 'detail': first_clause(f['finding'], 160),
             'recommendation': first_clause(f['recommendation'], 160), 'findingIds': [f['id']]} for f in picked[:10]]


def default_check_note(fs):
    top = sorted(fs, key=sort_key)[0]
    return first_clause(top['finding'])


def default_action_plan(findings):
    by = defaultdict(list)
    for f in findings:
        if f['checkName'] not in by[f['severity']]:
            by[f['severity']].append(f['checkName'])
    plan = {}
    if by['高']:
        plan['week'] = [f'处理高严重程度问题：{"、".join(by["高"])}。']
    if by['中']:
        plan['month'] = [f'处理中等严重程度问题：{"、".join(by["中"])}。']
    if by['低']:
        plan['quarter'] = [f'按计划改进：{"、".join(by["低"])}。']
    return plan


def recommendation_text(rec):
    if isinstance(rec, dict):
        parts = [('根本原因', rec.get('rootCause')), ('根治', rec.get('fix')), ('短期', rec.get('shortTerm'))]
        return ''.join(f'**{k}：**{v}' for k, v in parts if v)
    return str(rec or '')


# ---------------------------------------------------------------- Excel

def write_excel(path, cfg, report, findings, by_check, datasets, checks, snapshot, scope_note, ssh_rows, tracked=None):
    wb, expected = Workbook(), {}
    ov = wb.active
    ov.title = '概览'
    meta = REPORTS[report]
    ov.append([f'{cfg.name} {meta["title"]}问题清单（{cn_date(snapshot).replace(" ", "")}只读读取）'])
    ov.append([meta['severity'].replace('**', '') + '环境（生产/测试）按名称或标签推断。高、中、低为问题条数（问题清单行数），涉及资源数按资源去重。'])
    ov.append(['支柱', '检查项', '编号', '高', '中', '低', '合计', '涉及资源数'])
    rows_by_group = {}
    for code in checks:
        h, m, lo = (by_check.get((code, s), 0) for s in ('高', '中', '低'))
        ov.append([group_of(code), CHECKS.get(code, code), code, h, m, lo, None, resources_text([f for f in findings if f['check'] == code])])
        r = ov.max_row
        ov.cell(r, 7, f'=SUM(D{r}:F{r})')
        expected[f'概览!G{r}'] = h + m + lo
        rows_by_group.setdefault(group_of(code), []).append(r)
    n = ov.max_row
    ov.append(['合计', '', ''])
    for col in 'DEFG':
        ov[f'{col}{n + 1}'] = f'=SUM({col}4:{col}{n})'
    for col, sev in zip('DEF', ('高', '中', '低')):
        expected[f'概览!{col}{n + 1}'] = sum(1 for f in findings if f['severity'] == sev)
    expected[f'概览!G{n + 1}'] = len(findings)

    fl = wb.create_sheet('问题清单')
    fl.append([f'{meta["title"].replace("巡检", "")}问题清单'])
    fl.append(['每行一个问题；同类问题已按订阅或资源合并，涉及的资源见“涉及资源”。负责人、客户决定、处理状态和完成日期由客户填写。'])
    fl.append(LIST_COLUMNS)
    for f in findings:
        names = list(dict.fromkeys(str(m['name']) for m in members(f)))
        need = f.get('needsConfirmation')
        if f.get('severityReason'):
            need = '；'.join(x for x in [need, f'严重程度由{f["originalSeverity"]}调整为{f["severity"]}：{f["severityReason"]}'] if x)
        fl.append([f['id'], f['group'], f['checkName'], f['severity'], f.get('subscriptionName'), f.get('resourceGroup'), f.get('resourceName'),
                   f.get('resourceType'), env_text(f.get('environment')), f['finding'], f['recommendation'],
                   f.get('acceptance') or ACCEPTANCE.get(f['check']), need, f.get('difference'), f.get('rootCause'), f.get('alignment'),
                   len(names), '；'.join(names)[:2000], month_status(tracked, f['id']), None, None, None, None])
    if ssh_rows:
        sx = wb.create_sheet('公网可登录VM')
        sx.append(['直接绑定公网 IP 且 SSH（22）对 Internet 开放的虚拟机'])
        sx.append(['根据 NSG 规则离线判断，未做任何端口扫描或连接。“允许密码登录”来自虚拟机配置；为空表示未取得。'])
        sx.append(['订阅', '虚拟机', '公网 IP', '运行状态', '对公网开放的端口', '放行规则', '允许 SSH 密码登录'])
        for r in ssh_rows:
            sx.append(r)
    cv = wb.create_sheet('检查覆盖')
    cv.append(['检查覆盖情况'])
    cv.append(['读取失败或未检查的内容不视为没有问题。'])
    cv.append(['编号', '检查项', '尝试', '成功', '失败或无权限', '说明'])
    for data in datasets.values():
        for code, c in data['coverage'].items():
            notes = c.get('notes')
            cv.append([code, CHECKS.get(code, code), c.get('attempted'), c.get('succeeded'), (c.get('denied') or 0) + (c.get('otherErrors') or 0),
                       '；'.join(map(str, notes)) if isinstance(notes, list) else notes])
    if scope_note:
        cv.append(['未检查', '未启用订阅', None, None, None, scope_note])
    lz_rows = ((datasets.get('landing_zone') or {}).get('inventory') or {}).get('landingZone')
    if lz_rows:
        lz = wb.create_sheet('Landing Zone 对照')
        lz.append(['Azure Landing Zone 检查清单对照（可自动核对的条目）'])
        lz.append(['来自微软 Azure Review Checklists；架构设计参考，不计入问题数。“清单原文”为英文原文。'])
        lz.append(['领域', '条目', '清单重要性', '结果', '不符合', '符合', '不符合示例', '清单原文', '链接'])
        for r in lz_rows:
            lz.append([r['category'], r['title'], r['severity'], r['status'], r['nonCompliant'], r['compliant'],
                       '、'.join(r['examples']), r['text'], r.get('link')])
    gone = [r for r in ((tracked or {}).get('rows') or []) if r['status'] in ('已解决', '本月未检查') and report_of(r['check']) == report]
    if gone:
        ht = wb.create_sheet('上月问题处理情况')
        ht.append([f'{tracked["previous"]} 的问题本月的情况'])
        ht.append(['“已解决”：对应检查本月已执行，问题不再出现。“本月未检查”：对应检查本月没有成功执行，不能判断是否解决。'])
        ht.append(['编号', '检查项', '上月严重程度', '订阅', '资源', '上月发现', '本月情况'])
        for r in sorted(gone, key=lambda r: (r['status'], r['check'])):
            ht.append([r['id'], CHECKS.get(r['check'], r['check']), r['severity'], r.get('subscription'), r.get('resource'), r['finding'], r['status']])
    recommended = ((datasets.get('amba') or {}).get('inventory') or {}).get('recommendedAlerts')
    if recommended:
        am = wb.create_sheet('推荐告警（AMBA）')
        am.append(['各类资源建议配置的核心告警（Azure Monitor Baseline Alerts）'])
        am.append(['阈值和时间窗口取自微软 AMBA 推荐值，可先按此配置，运行一段时间后按实际情况调整。“说明”为 AMBA 原文。'])
        am.append(['资源类型', '指标', '说明', '条件', '时间窗口', 'AMBA 严重性（0 最高）'])
        for r in recommended:
            am.append([r['label'], r['metric'], r.get('description'), r.get('condition'), r.get('window'), r.get('severity')])
    for s in wb:
        s.sheet_view.showGridLines = False
        s.freeze_panes = 'A4'
        s.auto_filter.ref = f'A3:{L(s.max_column)}{s.max_row}'
        s.merge_cells(start_row=1, start_column=1, end_row=1, end_column=s.max_column)
        s.merge_cells(start_row=2, start_column=1, end_row=2, end_column=s.max_column)
        for row in s:
            for c in row:
                c.font = Font(name='Arial', size=10)
                c.alignment = Alignment(wrap_text=True, vertical='top')
                if c.row == 1:
                    c.fill = PatternFill('solid', fgColor='17365D')
                    c.font = Font(name='Arial', size=14, bold=True, color='FFFFFF')
                elif c.row == 3:
                    c.fill = PatternFill('solid', fgColor='DCE6F1')
                    c.font = Font(name='Arial', size=10, bold=True)
        s.row_dimensions[2].height = 40
        for i in range(1, s.max_column + 1):
            s.column_dimensions[L(i)].width = 16
    for row in fl.iter_rows(min_row=4):
        row[3].fill = PatternFill('solid', fgColor=SEVERITY_FILL[row[3].value])
    for col, w in {'G': 30, 'J': 80, 'K': 70, 'L': 50, 'M': 50, 'N': 60, 'O': 60, 'P': 60, 'R': 60, 'S': 24}.items():
        fl.column_dimensions[col].width = w
    if gone:
        wb['上月问题处理情况'].column_dimensions['E'].width = 30
        wb['上月问题处理情况'].column_dimensions['F'].width = 80
    groups = []
    anchor_row = 5
    for group in meta['groups']:
        rows = rows_by_group.get(group)
        if rows:
            groups.append((f'{group}：各检查项问题数量', rows[0], rows[-1], f'J{anchor_row}'))
            anchor_row += len(rows) + 8
    waf_charts.add_overview_charts(ov, groups)
    ov.column_dimensions['B'].width = 30
    ov.column_dimensions['H'].width = 45
    cv.column_dimensions['F'].width = 90
    if lz_rows:
        for col, w in {'B': 45, 'G': 50, 'H': 70, 'I': 40}.items():
            wb['Landing Zone 对照'].column_dimensions[col].width = w
    if recommended:
        wb['推荐告警（AMBA）'].column_dimensions['B'].width = 36
        wb['推荐告警（AMBA）'].column_dimensions['C'].width = 50
        wb['推荐告警（AMBA）'].column_dimensions['D'].width = 30
    if ssh_rows:
        wb['公网可登录VM'].column_dimensions['E'].width = 40
        wb['公网可登录VM'].column_dimensions['F'].width = 40
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    return expected


# ---------------------------------------------------------------- 03 extras

def ssh_cross(datasets):
    """VMs with SSH reachable from the Internet (S-N3) that also allow password login (S-I8)."""
    open22, pwd = {}, set()
    for f in (datasets.get('security_network') or {}).get('findings', []):
        if f['check'] != 'S-N3':
            continue
        for v in (f.get('evidence') or {}).get('vmsWithDirectPublicIp') or []:
            if 22 in (v.get('internetReachableMgmtPorts') or []) and str(v.get('endpoint', '')).startswith('VM '):
                open22[(f['subscriptionName'], v['endpoint'][3:].lower())] = v
    for f in (datasets.get('security_identity') or {}).get('findings', []):
        vms = (f.get('evidence') or {}).get('vms')
        if f['check'] == 'S-I8' and isinstance(vms, list):
            pwd |= {(f['subscriptionName'], str(v.get('name', '')).lower()) for v in vms if isinstance(v, dict)}
    rows = [[sub, v['endpoint'][3:], v.get('publicIp'), (v.get('powerState') or '').replace('PowerState/', ''),
             '，'.join(v.get('internetReachablePorts') or []), '，'.join(v.get('allowingNsgRules') or []), '是' if (sub, vm) in pwd else None]
            for (sub, vm), v in sorted(open22.items())]
    return rows, len(open22), len(set(open22) & pwd)


# ---------------------------------------------------------------- Markdown

def month_status(tracked, fid):
    if not tracked:
        return None
    if tracked.get('first'):
        return '首次记录'
    row = next((r for r in tracked['rows'] if r['id'] == fid), None)
    if not row:
        return None
    return row['status'] + (f'（上月为{row["previousSeverity"]}）' if row.get('previousSeverity') else '')


def month_sentence(tracked, report):
    """One paragraph comparing with last month; new checks are named so they do not read as a deterioration."""
    from ..tracking import summary
    if not tracked or tracked.get('first'):
        return None
    s = summary(tracked, report)
    c = s['all']
    parts = [f'{k} {c[k]} 项' for k in ('新增问题', '新增检查项发现', '仍未处理', '已解决', '本月未检查') if c.get(k)]
    if not parts:
        return None
    text = f'与 {tracked["previous"]} 相比：' + '，'.join(parts) + '。'
    if c.get('新增检查项发现'):
        from ..tracking import check_label
        names = '、'.join(dict.fromkeys(check_label(k, src) for k, src in s['newChecks']))
        text += f'“新增检查项发现”来自本月起新增或首次成功执行的检查（{names}），不代表情况变差。'
    if c.get('本月未检查'):
        text += '“本月未检查”是对应检查本月读取失败，不能判断是否已解决。'
    if s['severityChanged']:
        text += f'另有 {len(s["severityChanged"])} 项严重程度有变化，见 Excel“与上月相比”列。'
    return text


def markdown(cfg, report, findings, by_check, checks, narrative, snapshot, perf_window, readable, scope_note, pngs, alert_png, lz_rows=None,
             tracked=None, arch=None):
    meta = REPORTS[report]
    c = Counter((f['group'], f['severity']) for f in findings)
    pending = sum(1 for f in findings if f.get('needsConfirmation'))
    groups = [g for g in meta['groups'] if any(group_of(k) == g for k in checks)]
    window_text = f'性能数据窗口：{cn_span(*perf_window)}。' if report == '04' and perf_window else ''
    lines = [f'# {cfg.name} Azure {meta["title"]}报告', '',
             f'**检查时间：{cn_date(snapshot)}。范围：{cfg.name} {readable} 个 Azure 订阅' + (f'（{scope_note}）' if scope_note else '') + f'。{window_text}'
             f'方式：{meta["method"]}。**', '',
             f'共发现 **{len(findings)}** 项问题：' + '，'.join(
                 f'{g} {sum(c[(g, s)] for s in "高中低")} 项（高 {c[(g, "高")]}、中 {c[(g, "中")]}、低 {c[(g, "低")]}）' for g in groups)
             + f'。其中 {pending} 项附有需要客户确认的事项（见 Excel“需要客户确认”列）。同类问题已按订阅或资源合并，完整清单见 Excel。', '',
             f'严重程度：{meta["severity"]}生产或测试环境按名称或标签推断，需客户确认。', ''] +             ([month_sentence(tracked, report), ''] if month_sentence(tracked, report) else []) + [
             '## 1. 需要优先处理的问题', '']
    top = narrative.get('topIssues') or default_top_issues(findings)
    with_impact = any(t.get('impact') for t in top)
    lines += ['|#|问题|影响|建议|', '|---|---|---|---|'] if with_impact else ['|#|问题|建议|', '|---|---|---|']
    for i, t in enumerate(top, 1):
        detail = t.get('detail') or ''
        problem = f'**{t["title"].rstrip("。")}' + ('**' if detail[:1] in '，；、' else '。**') + detail
        cells = [str(i), problem] + ([t.get('impact') or ''] if with_impact else []) + [recommendation_text(t.get('recommendation'))]
        lines.append('|' + '|'.join(x.replace('|', '/').replace('\n', ' ') for x in cells) + '|')
    notes = narrative.get('checkNotes') or {}
    for n, group in enumerate(groups, 2):
        lines += ['', f'## {n}. {group}', '', COUNT_NOTE, '', '|检查项|高|中|低|涉及资源数|主要发现|', '|---|---:|---:|---:|---|---|']
        for code in [k for k in checks if group_of(k) == group]:
            fs = [f for f in findings if f['check'] == code]
            h, m, lo = (by_check.get((code, s), 0) for s in ('高', '中', '低'))
            note = notes.get(code) or (default_check_note(fs) if fs else '未发现问题')
            lines.append(f'|{CHECKS.get(code, code)}|{h}|{m}|{lo}|{resources_text(fs)}|{note.replace("|", "/")}|')
        if group in pngs:
            lines += ['', f'![{group}各检查项问题数量]({pngs[group]})']
        if group == '卓越运营' and alert_png:
            lines += ['', f'![生产资源告警覆盖情况]({alert_png})']
        extra = (narrative.get('sectionNotes') or {}).get(group) or []
        for text in [extra] if isinstance(extra, str) else extra:
            lines += ['', text]
    n = len(groups) + 2
    arch_lines = architecture.section(arch, narrative) if report == '03' else []
    if arch_lines:
        lines += ['', f'## {n}. 架构总览', ''] + arch_lines
        n += 1
    if lz_rows:
        gaps = [r for r in lz_rows if r['status'] == '有不符合项']
        counts = Counter(r['status'] for r in lz_rows)
        lines += ['', f'## {n}. Landing Zone 对照', '',
                  f'按微软 Azure Landing Zone 检查清单中可自动核对的 {len(lz_rows)} 条：{counts["有不符合项"]} 条有不符合项，'
                  f'{counts["全部符合"]} 条全部符合，{counts["不适用（没有相关资源）"]} 条没有相关资源'
                  + (f'，{counts["读取失败"]} 条读取失败' if counts['读取失败'] else '') + '。这些是架构设计参考，不计入上面的问题数；'
                  '与上面问题重复的，以问题清单为准。完整结果见 Excel“Landing Zone 对照”。']
        if gaps:
            lines += ['', '|领域|条目|清单重要性|不符合|符合|示例|', '|---|---|---|---:|---:|---|']
            for r in gaps[:15]:
                lines.append(f'|{r["category"]}|{r["title"]}|{r["severity"]}|{r["nonCompliant"]}|{r["compliant"]}|{"、".join(r["examples"][:3])}|')
        if narrative.get('landingZoneNote'):
            lines += ['', narrative['landingZoneNote']]
        n += 1
    plan = narrative.get('actionPlan') or default_action_plan(findings)
    lines += ['', f'## {n}. 建议处理顺序', '']
    for key, label in (('week', '本周内'), ('month', '一个月内'), ('quarter', '一个季度内')):
        if plan.get(key):
            lines.append(f'- **{label}：**' + ''.join(plan[key]))
    lines += ['', '每项问题的资源明细、建议、验收标准和需要客户确认的内容见 Excel“问题清单”，可直接用于分配负责人和跟踪处理状态。', '',
              f'## {n + 1}. 检查范围与限制', '']
    limits = ([f'{scope_note}。'] if scope_note else []) + meta['notes'] + [
        '生产或测试环境按订阅、资源名称和标签推断，请客户确认。',
        f'配置为 {cn_date(snapshot)}读取的状态；读取后客户如有调整，以实际为准。'] + list(narrative.get('limitations') or [])
    lines += [f'- {x}' for x in limits]
    lines += ['', '## Microsoft 官方参考', ''] + [f'- [{t}]({u})' for t, u in meta['links']]
    return format_and_check('\n'.join(lines) + '\n')


# ---------------------------------------------------------------- build

def build(ws, cfg, report, narrative=None, log=print):
    narrative = narrative or {}
    datasets, findings = load(ws, report)
    if not datasets:
        log(f'{report}：没有分析结果（findings/waf/*.json），跳过')
        return None
    apply_narrative(findings, narrative)
    findings.sort(key=sort_key)
    by_check = Counter((f['check'], f['severity']) for f in findings)
    pillars_present = set(datasets)
    covered = {k for d in datasets.values() for k in d['coverage']}
    checks = [k for k in CHECKS if report_of(k) == report and (_check_in(k, pillars_present) or k in covered)]
    checks += sorted({f['check'] for f in findings} - set(checks), key=check_number)
    snapshot, perf_window = window_of(datasets)
    readable, scope_note = scope_text(ws)
    out = ws.month_dir('reports')
    md_stem, xlsx_stem = stems(report)
    ssh_rows, ssh_open, ssh_pwd = ssh_cross(datasets) if report == '03' else ([], 0, 0)
    pngs = waf_charts.make_pngs(report, findings, checks, out / 'charts')
    alert_png = waf_charts.alert_coverage_png(datasets.get('operations'), out / 'charts') if report == '04' else None
    xlsx = out / f'{xlsx_stem}.xlsx'
    from ..tracking import load as load_tracking
    tracked = load_tracking(ws)
    expected = write_excel(xlsx, cfg, report, findings, by_check, datasets, checks, snapshot, scope_note, ssh_rows, tracked)
    lz_rows = ((datasets.get('landing_zone') or {}).get('inventory') or {}).get('landingZone')
    arch = architecture.summary(ws, cfg) if report == '03' else None
    md = markdown(cfg, report, findings, by_check, checks, narrative, snapshot, perf_window, readable, scope_note, pngs, alert_png, lz_rows, tracked,
                  arch)
    (out / f'{md_stem}.md').write_text(md, encoding='utf-8')
    fdir = ws.month_dir('findings') / 'waf'
    result = verify(xlsx, expected, fdir / f'verification-{report}.json')
    counts = Counter(f['severity'] for f in findings)
    meta = {'report': report, 'total': len(findings), 'bySeverity': dict(counts),
            'byGroup': {f'{g}-{s}': n for (g, s), n in Counter((f['group'], f['severity']) for f in findings).items()},
            'pendingConfirmation': sum(1 for f in findings if f.get('needsConfirmation')),
            'severityOverrides': len(narrative.get('severityOverrides') or []), 'sshOpen': ssh_open, 'sshOpenAndPassword': ssh_pwd,
            'formulaCount': result['formulaCount'], 'recalculatedInExcel': result['recalculatedInExcel']}
    write_json(fdir / f'report-{report}.json', meta)
    log(f'{report} 报告：{len(findings)} 项问题（高 {counts["高"]}、中 {counts["中"]}、低 {counts["低"]}）；Excel 公式 {result["formulaCount"]} 个'
        + ('，已用 Excel 复算核对' if result['recalculatedInExcel'] else '，本机未能用 Excel 复算'))
    return meta


def _check_in(check, pillars):
    if check == 'S-I11':
        return 'defender' in pillars
    owner = {'R': 'reliability', 'S-N': 'security_network', 'S-I': 'security_identity', 'O': 'operations', 'P': 'performance'}
    head, num = check_number(check)
    original = {'R': 12, 'S-N': 8, 'S-I': 10, 'O': 10, 'P': 10}   # later checks come from the rule libraries
    return owner.get(head) in pillars and num <= original.get(head, 0)


def audit(ws, cfg, report, log=print):
    """Recheck the built report against the findings files."""
    from openpyxl import load_workbook
    datasets, findings = load(ws, report)
    if not datasets:
        return None
    meta = json.loads((ws.month_dir('findings') / 'waf' / f'report-{report}.json').read_text(encoding='utf-8'))
    assert meta['total'] == len(findings), '问题数与分析结果不一致'
    md_stem, xlsx_stem = stems(report)
    out = ws.month_dir('reports')
    wb = load_workbook(out / f'{xlsx_stem}.xlsx', read_only=True)
    ids = [r[0] for r in wb['问题清单'].iter_rows(min_row=4, values_only=True)]
    assert sorted(ids) == sorted(f['id'] for f in findings), 'Excel 问题清单与分析结果不一致'
    wb.close()
    md = (out / f'{md_stem}.md').read_text(encoding='utf-8')
    assert f'共发现 **{len(findings)}** 项问题' in md, 'Markdown 总数与分析结果不一致'
    verification = json.loads((ws.month_dir('findings') / 'waf' / f'verification-{report}.json').read_text(encoding='utf-8'))
    assert verification['totalErrors'] == 0, verification['errors'][:5]
    log(f'{report} 核对通过：{len(findings)} 项问题，Excel 问题清单逐条对应，公式 {verification["formulaCount"]} 个')
    return meta
