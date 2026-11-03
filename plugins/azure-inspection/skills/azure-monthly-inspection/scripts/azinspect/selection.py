"""Which reports a month covers (customer.yaml report.include) and what each step runs for them.

00 is always built and summarises the chosen reports only. 03 and 04 can be narrowed to some of their WAF pillars
(可靠性、安全 / 卓越运营、性能效率): the report keeps its number, its title names the pillars done. A report's own part
runs in full; another part runs only as far as a chosen report needs its data:
- 01 without 02: the VM inventory and SKU capabilities (01's month usage review), not the 30-day metrics;
- 02 without 01: which machines RI/SP cover (02's savings), not the cost review;
- a pillar or 05: the raw data of the WAF pillars it reads (collected, not analysed into a report); APRL rules belong
  to 可靠性 and also to 安全 (S-N9) and 卓越运营 (O11);
- 04 without 01: no cost data; the checks that use it say so in 04's limitations.
build records the choice in findings/selection.json, so crosscheck, package and 00 follow what was built even if
customer.yaml changes later. Months built before 0.9.0 have no record: every report and pillar.
"""
from __future__ import annotations

from .core.config import GROUPS, REPORTS
from .core.io import read_json, write_json
from .waf.common import PILLARS

TITLES = {'01': '月度成本', '02': '虚拟机规格', '03': '可靠性与安全', '04': '卓越运营与性能效率', '05': '同类资源配置对比'}
PART_OF = {'01': 'cost', '02': 'vm', '03': 'waf', '04': 'waf', '05': 'peer'}
# WAF pillar modules each pillar of 03/04 analyses; Landing Zone (an architecture reference table) comes with any of 03
ANALYSES = {'可靠性': {'reliability', 'aprl', 'landing_zone'},
            '安全': {'security_network', 'security_identity', 'defender', 'aprl', 'landing_zone'},
            '卓越运营': {'operations', 'amba', 'aprl'},
            '性能效率': {'performance'}}
# raw data they read on top: VM, AKS and Advisor data of reliability, AKS data of security_identity, metrics of performance
READS = {'可靠性': ANALYSES['可靠性'], '安全': ANALYSES['安全'] | {'reliability'},
         '卓越运营': ANALYSES['卓越运营'] | {'reliability', 'security_identity', 'performance'},
         '性能效率': ANALYSES['性能效率'] | {'reliability'}}
PEER_READS = {'reliability', 'security_network', 'security_identity', 'operations', 'performance'}
# 03's architecture overview lists resources from the operations pillar's inventory: without 卓越运营, collect that phase only
INVENTORY = 'operations:inventory'


def groups_of(reports, groups=None):
    """The chosen pillars of 03/04; every pillar of a chosen report when not given."""
    return tuple(g for g, code in GROUPS.items() if code in reports and (groups is None or g in groups))


def title(code, groups=None):
    """Report title: 03/04 name only the pillars done ('可靠性', '可靠性与安全')."""
    mine = [g for g, c in GROUPS.items() if c == code and (groups is None or g in groups)]
    return '与'.join(mine) if mine else TITLES[code]


def waf_pillars(reports, requested=None, collect=False, groups=None):
    """Pillar modules to collect (with what the pillars and 05 read) or to analyse (the chosen pillars), within `requested`."""
    chosen = groups_of(reports, groups)
    wanted = set().union(*((READS if collect else ANALYSES)[g] for g in chosen))
    if collect and '05' in reports:
        wanted |= PEER_READS
    out = [p for p in (requested or PILLARS) if p in wanted]
    if collect and '03' in reports and 'operations' not in wanted and (not requested or 'operations' in requested):
        out.append(INVENTORY)
    return out


def collect_plan(reports, part='all', requested=None, groups=None):
    """[(part, mode)] in collection order. vm: full | inventory; cost: full | vm-coverage; waf: list of pillars; peer: full."""
    plan = []
    if '02' in reports or '01' in reports:
        plan.append(('vm', 'full' if '02' in reports else 'inventory'))
    if '01' in reports or '02' in reports:
        plan.append(('cost', 'full' if '01' in reports else 'vm-coverage'))
    pillars = waf_pillars(reports, requested, collect=True, groups=groups)
    if pillars:
        plan.append(('waf', pillars))
    if '05' in reports:
        plan.append(('peer', 'full'))
    return [x for x in plan if part in ('all', x[0])]


def runs(reports, part, step):
    """Whether `step` (analyze or build) runs `part` for the chosen reports. 00 (summary) is always built."""
    if part == 'summary':
        return step == 'build'
    return any(PART_OF[r] == part for r in reports)


def skipped(reports, part):
    """Message for an explicit --part that no chosen report needs, else None."""
    owners = [r for r in REPORTS if PART_OF[r] == part]
    if not owners or any(r in reports for r in owners):
        return None
    return f'{"、".join(owners)}（{"、".join(TITLES[r] for r in owners)}）不在 customer.yaml 的 report.include 中，跳过 --part {part}'


def subscription_scope(ws, cfg, report=None):
    """Sentence for the reports when customer.yaml limits the subscriptions (scope include/exclude), else ''.
    Names the subscriptions read and the tenant-wide checks that do not follow the subscription choice: those of `report`,
    or of every chosen report (00)."""
    if not (cfg.include or cfg.exclude):
        return ''
    subs = None
    for rel in ('waf/scope.json', 'vm/inventory/subscriptions.json'):   # 03/04/05 collect the scope; 01/02 the VM inventory
        if ws.raw(rel).exists():
            data = read_json(ws.raw(rel))
            subs = data['subscriptions'] if isinstance(data, dict) else data
            break
    reports = [report] if report else load(ws)
    # management groups: 03's Landing Zone comparison and 04's governance check (O8, 卓越运营) read the whole tenant's
    groups_done = load_groups(ws)
    mg = (['Landing Zone 对照'] if '03' in reports else []) + (['治理检查'] if '04' in reports and '卓越运营' in groups_done else [])
    tenant = (['Entra ID 账号与凭据'] if '03' in reports and '安全' in groups_done else []) + \
             ([f'管理组（{"和".join(mg)}）'] if mg else []) + \
             (['预留和节省计划订单'] if '01' in reports else [])   # 02 alone reads only which machines RI/SP cover
    tail = f'；{"、".join(tenant)}不按订阅划分，仍按全租户检查' if tenant else ''
    if subs is None:
        return '按贵司选择，本次只检查 customer.yaml 中指定的订阅' + tail
    names = sorted(s['name'] for s in subs if s.get('state') == 'Enabled')
    shown = '、'.join(names) if len(names) <= 8 else '、'.join(names[:5]) + f' 等 {len(names)} 个'
    return f'按贵司选择，本次只检查 {len(names)} 个订阅：{shown}' + tail


def save(ws, reports, groups=None):
    write_json(ws.month_dir('findings') / 'selection.json', {'reports': list(reports), 'groups': list(groups_of(reports, groups))})


# Narrative files whose content depends on the choice: 00 summarises the chosen reports and pillars, 03/04 their pillars.
# build stamps each with the choice it was built under; a file left unchanged under another choice was written for that one.
STAMP = 'narrative-choice.json'


def _narrative_choice(code, reports, groups):
    chosen = groups_of(reports, groups)
    if code == '00':
        return {'reports': list(reports), 'groups': list(chosen)}
    return {'groups': [g for g in chosen if GROUPS[g] == code]}


def _describe(choice):
    return '、'.join(list(choice.get('reports') or []) + list(choice.get('groups') or [])) or '无'


def stale_narratives(ws, reports, groups=None):
    """[(file name, what it was written for)]: 00/03/04 narratives of chosen reports not edited since a build under another choice."""
    import hashlib
    stamp_path = ws.month_dir('findings') / STAMP
    stamp = read_json(stamp_path) if stamp_path.exists() else {}
    out = []
    for code in ('00', '03', '04'):
        path = ws.month_dir('narrative') / f'{code}.json'
        was = stamp.get(path.name)
        if code != '00' and code not in reports or not path.exists() or not was:
            continue
        if was['sha'] == hashlib.sha256(path.read_bytes()).hexdigest() and was['choice'] != _narrative_choice(code, reports, groups):
            out.append((path.name, _describe(was['choice'])))
    return out


def stamp_narratives(ws, reports, groups=None):
    import hashlib
    stamp_path = ws.month_dir('findings') / STAMP
    stamp = read_json(stamp_path) if stamp_path.exists() else {}
    for code in ('00', '03', '04'):
        path = ws.month_dir('narrative') / f'{code}.json'
        if (code == '00' or code in reports) and path.exists():
            stamp[path.name] = {'sha': hashlib.sha256(path.read_bytes()).hexdigest(), 'choice': _narrative_choice(code, reports, groups)}
    write_json(stamp_path, stamp)


def _record(ws):
    path = ws.month_dir('findings') / 'selection.json'
    return read_json(path) if path.exists() else {}


def load(ws):
    return tuple(_record(ws).get('reports') or REPORTS)


def load_groups(ws):
    """The pillars of 03/04 done this month (all of the chosen reports' when not recorded)."""
    record = _record(ws)
    return groups_of(tuple(record.get('reports') or REPORTS), record.get('groups'))
