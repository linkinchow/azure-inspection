"""Command line entry: python <skill>/scripts/azinspect_cli.py <command> [options]."""
from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

SKILL_DIR = Path(__file__).resolve().parents[2]
REQUIRED = {'openpyxl': 'openpyxl', 'matplotlib': 'matplotlib', 'markdown_it': 'markdown-it-py', 'yaml': 'PyYAML', 'cryptography': 'cryptography'}
CJK_FONTS = ['Microsoft YaHei', 'PingFang SC', 'Noto Sans CJK SC', 'Source Han Sans SC', 'SimHei', 'Heiti SC']


def cmd_version(_args) -> int:
    print(f'azinspect {__version__}')
    return 0


def cmd_doctor(_args) -> int:
    ok = True
    print(f'Python {platform.python_version()}：' + ('通过' if sys.version_info >= (3, 10) else '需要 3.10 或更高版本'))
    ok &= sys.version_info >= (3, 10)
    missing = []
    for module, package in REQUIRED.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(package)
    print('Python 依赖：' + ('通过' if not missing else '缺少 ' + '、'.join(missing)))
    if missing:
        ok = False
        print(f'  安装：python -m pip install --user -r "{SKILL_DIR / "scripts" / "requirements.txt"}"')
    az = shutil.which('az') or shutil.which('az.cmd')
    print('Azure CLI：' + ('通过' if az else '未找到，请先安装 Azure CLI'))
    ok &= bool(az)
    if 'matplotlib' not in missing:
        from matplotlib import font_manager
        names = {f.name for f in font_manager.fontManager.ttflist}
        font = next((f for f in CJK_FONTS if f in names), None)
        print('中文字体：' + (f'通过（{font}）' if font else '未找到，图表中文会显示成方框；请安装 Noto Sans CJK 或微软雅黑'))
        ok &= bool(font)
    if platform.system() == 'Windows':
        try:
            importlib.import_module('win32com.client')
            print('Excel 公式复算：可用（需要本机安装 Excel）')
        except ImportError:
            print('Excel 公式复算：未安装 pywin32，将改用 openpyxl 检查公式（可选：python -m pip install --user pywin32）')
    else:
        print('Excel 公式复算：非 Windows 环境，将改用 openpyxl 检查公式')
    print('环境检查' + ('通过' if ok else '未通过'))
    return 0 if ok else 1


def cmd_init(args) -> int:
    from .core.io import Workspace
    ws = Workspace(args.workspace, args.month)
    ws.create()
    if ws.config_path.exists():
        print(f'已存在 {ws.config_path}，未覆盖。')
    else:
        shutil.copyfile(SKILL_DIR / 'templates' / 'customer.example.yaml', ws.config_path)
        print(f'已生成 {ws.config_path}，请填写后运行 access-check。')
    print(f'工作目录：{ws.root}')
    return 0


def _client(workspace):
    from .core import config as config_mod
    from .core.auth import TokenProvider
    from .core.http import ReadOnlyClient
    cfg = config_mod.load(workspace.config_path)
    tokens = TokenProvider(cfg.readonly_account, cfg.tenant_id, cfg.token_subscription)
    return cfg, tokens, ReadOnlyClient(tokens, user_agent=f'azure-inspection-readonly/{__version__}')


def _writes(permissions) -> bool:
    """Can this role change resources? Microsoft.Support/* (opening support tickets) is part of several read-only roles."""
    actions = [a.lower() for p in permissions or [] for a in p.get('actions') or []]
    return any(a == '*' or a.endswith(('/write', '/delete')) or a.endswith('/*') and a != 'microsoft.support/*' for a in actions)


def _credentials(permissions) -> bool:
    """Can this role fetch credentials, keys or secrets (AKS kubeconfig, storage and Cosmos DB keys, web app settings,
    Key Vault secret values)? A wildcard counts as writing instead."""
    actions = [a.lower() for p in permissions or [] for a in (p.get('actions') or []) + (p.get('dataActions') or [])]
    words = ('credential', '/listkeys/', '/listsecrets/', '/regeneratekey', '/readonlykeys/', '/listconnectionstrings/',
             '/config/list/', '/secrets/getsecret/')
    return any(a.endswith('/action') and any(w in a for w in words) for a in actions)


# roles that can write only quota or support requests: named apart from roles that change resources
LOW_RISK_ROLES = {'Quota Request Operator', 'Support Request Contributor'}


def _roles(client, object_id, sub_ids, names):
    """Roles the account holds (directly, through groups or inherited) on each subscription in scope; flags roles that can write."""
    if not object_id:
        return {'read': False, 'error': '令牌里没有对象 ID'}
    defs, rows, denied = {}, [], []
    for sid in sub_ids:
        items, status, error = client.get_all(f"/subscriptions/{sid}/providers/Microsoft.Authorization/roleAssignments"
                                              f"?api-version=2022-04-01&$filter=assignedTo('{object_id}')", 'access', 'role-assignments')
        if items is None:
            denied.append({'subscriptionId': sid, 'status': status})
            continue
        for a in items:
            rid = a['properties']['roleDefinitionId']
            if rid not in defs:
                _status, d, _error = client.get(f'{rid}?api-version=2022-04-01', 'access', 'role-definition')
                props = (d or {}).get('properties') or {}
                defs[rid] = {'role': props.get('roleName') or rid.rsplit('/', 1)[-1], 'writes': _writes(props.get('permissions')) if d else None,
                             'credentials': _credentials(props.get('permissions')) if d else None}
            rows.append({'subscription': names.get(sid, sid), 'scope': a['properties'].get('scope'), **defs[rid]})
    low = sorted({r['role'] for r in rows if r['role'] in LOW_RISK_ROLES})
    write = sorted({r['role'] for r in rows if r['writes'] and r['role'] not in LOW_RISK_ROLES})
    creds = sorted({r['role'] for r in rows if r.get('credentials') and not r['writes'] and r['role'] not in LOW_RISK_ROLES})
    subs = sorted({r['subscription'] for r in rows if r['writes'] and r['role'] not in LOW_RISK_ROLES})
    if low:
        print(f'提示：该账号有只能提交配额申请或支持工单的角色（{"、".join(low)}），不能修改资源，风险较低。')
    if write:
        print(f'注意：该账号在 {len(subs)} 个订阅有可写角色（{"、".join(write)}）。巡检脚本只发读请求，'
              '但建议改用读者等只读角色；由 AI agent 执行巡检时，可写角色的风险更高。')
    if creds:
        print(f'注意：该账号有能取凭据或密钥的角色（{"、".join(creds)}），例如取得 AKS 的 kubeconfig 或存储账户密钥。'
              '巡检脚本会拦截这类请求、不取凭据，但建议移除；由 AI agent 执行巡检时风险更高。')
    if rows and not (write or low or creds):
        print('角色核对：只有只读角色。')
    if denied:
        print(f'  {len(denied)} 个订阅的角色分配读取失败，未能核对是否有可写角色')
    return {'read': not denied, 'assignments': rows, 'writeRoles': write, 'lowRiskRoles': low, 'credentialRoles': creds, 'writeSubscriptions': subs, 'denied': denied}


def cmd_access_check(args) -> int:
    from .core.io import Workspace, write_json
    ws = Workspace(args.workspace)
    cfg, tokens, client = _client(ws)
    identity = tokens.identity()
    print(f'只读账号核对通过：租户 {identity["tenant"]}，令牌有效至 {identity["expiresAt"]}')
    subs, status, error = client.get_all('/subscriptions?api-version=2022-12-01', 'access', 'subscriptions')
    if subs is None:
        print(f'无法列出订阅（{status} {error}）')
        return 1
    rows = [{'subscriptionId': s['subscriptionId'], 'displayName': s.get('displayName'), 'state': s.get('state'),
             'inScope': s.get('state') == 'Enabled' and cfg.in_scope(s['subscriptionId'], s.get('displayName') or '')}
            for s in subs if str(s.get('tenantId', cfg.tenant_id)).lower() == cfg.tenant_id]
    in_scope = [r['subscriptionId'] for r in rows if r['inScope']]
    disabled = [r for r in rows if r['state'] != 'Enabled']
    print(f'可见订阅 {len(rows)} 个：纳入巡检 {len(in_scope)} 个，已停用 {len(disabled)} 个，按配置排除 {len(rows) - len(in_scope) - len(disabled)} 个')
    result = {'checkedAt': datetime.now(timezone.utc).isoformat(), 'tenant': identity['tenant'], 'subscriptions': rows}
    if in_scope:
        counts, status, error = client.arg('resources | summarize resources=count() by subscriptionId', in_scope, 'access', 'resource-graph')
        result['resourceGraph'] = {'status': status, 'error': error, 'perSubscription': counts}
        print('资源读取（Resource Graph）：' + (f'通过，共 {sum(c["resources"] for c in counts)} 个资源' if counts is not None else f'失败（{status} {error}）'))
        empty = set(in_scope) - {c['subscriptionId'] for c in counts or []}
        if counts is not None and empty:
            print(f'  其中 {len(empty)} 个订阅没有读到任何资源（可能确实为空，也可能没有读取权限）')
        probe = in_scope[0]
        body = {'type': 'ActualCost', 'timeframe': 'MonthToDate', 'dataset': {'granularity': 'None', 'aggregation': {'totalCost': {'name': 'Cost', 'function': 'Sum'}}}}
        status, _data, error = client.request('POST', f'https://management.azure.com/subscriptions/{probe}/providers/Microsoft.CostManagement/query?api-version=2023-11-01',
                                              'access', 'cost-management', body=body)
        result['costManagement'] = {'probeSubscription': probe, 'status': status, 'error': error}
        needed = bool({'01', '02'} & set(cfg.reports))   # 01 costs, 02 RI/SP coverage; 04 only narrows a few checks without it
        result['costManagement']['neededByChosenReports'] = needed
        print('费用读取（Cost Management）：' + ('通过' if status == 200 else
              f'失败（{status} {error}），01 月度成本和 02 虚拟机规格需要“成本管理读者”或“读者”权限' if needed else
              f'失败（{status} {error}）；所选报告不含 01、02，不影响本次巡检'))
        result['roles'] = _roles(client, identity.get('objectId'), in_scope, {r['subscriptionId']: r['displayName'] for r in rows})
    write_json(ws.access_dir / 'access-check.json', result)
    ws.save_calls('access-check', client.calls)
    print(f'结果已保存：{ws.access_dir / "access-check.json"}')
    return 0


PARTS = ('cost', 'vm', 'waf', 'peer', 'summary')


def _month_workspace(args):
    from .core.io import Workspace
    from .core.period import ReportPeriod
    period = ReportPeriod.build(args.month)
    ws = Workspace(args.workspace, period.current.key)
    ws.create()
    return ws, period


def _narrative(ws, report):
    from .core.io import read_json
    path = ws.month_dir('narrative') / f'{report}.json'
    return read_json(path) if path.exists() else {}


def calls_stage(part, pillars):
    """Call log name: a run of chosen WAF pillars keeps its own file instead of overwriting the last run's."""
    return f'collect-{part}' + (f'-{"-".join(p.strip() for p in pillars.split(",") if p.strip())}' if pillars else '')


def cmd_collect(args) -> int:
    """Collects what the reports chosen in customer.yaml (report.include) need. Exit code 1 when a WAF pillar failed.
    An interrupted `--part all` lists the parts still to collect: users tend to rerun only cost and waf, and 05 then
    lacks resource creation times."""
    from .core.reuse import Reuse
    from .selection import collect_plan
    from .waf.pipeline import parse
    ws, period = _month_workspace(args)
    cfg, _tokens, client = _client(ws)
    plan = collect_plan(cfg.reports, args.part, parse(args.pillars), cfg.groups)
    if not plan:
        print(f'所选报告（{"、".join(cfg.reports)}）不需要 --part {args.part} 的数据，跳过（见 customer.yaml 的 report.include）')
        return 0
    command = f'collect --workspace "{ws.root}" --month {period.current.key}'
    parts = [part for part, _mode in plan]
    done, failed = [], []
    try:
        for part, mode in plan:
            if part == 'vm':
                from .vm.collect import collect
                collect(ws, cfg, client, period, inventory_only=mode == 'inventory')
            elif part == 'cost' and mode == 'full':
                from .cost.pipeline import collect
                collect(ws, cfg, client, period, resume=args.resume)
            elif part == 'cost':
                from .cost.commitments import collect_vm_coverage
                if not ws.raw('vm/inventory/subscriptions.json').exists():
                    raise SystemExit(f'02 要用的 RI/SP 覆盖按虚拟机清单读取，先运行：{command} --part vm')
                collect_vm_coverage(ws, client, period, reuse=Reuse(args.resume))
            elif part == 'waf':
                from .waf.pipeline import collect
                failed = collect(ws, cfg, client, pillars=mode) or []
            else:
                from .peer import collect
                from .waf.common import window
                collect(ws, cfg, client, window())
            done.append(part)
    except BaseException:
        left = [p for p in parts if p not in done]
        if args.part == 'all' and left:
            print(f'采集中断：已完成 {"、".join(done) or "无"}，未完成 {"、".join(left)}。逐个补采：')
            for p in left:
                print(f'  {command} --part {p}' + (' --resume' if p == 'cost' else ''))
            if 'cost' in left:
                print('  费用部分加 --resume：已成功读取的查询（7 天内）会直接复用，只读取缺少或失败的部分。')
            if 'peer' in left:
                print('  同类对比（peer）也要补采，否则 05 没有资源创建时间。')
        elif left == ['cost']:
            print(f'费用采集中断。重跑时加 --resume，已成功读取的查询会直接复用：\n  {command} --part cost --resume')
        raise
    finally:
        ws.save_calls(calls_stage(args.part, args.pillars), client.calls)
    missing = {}
    if ('cost', 'full') in plan:
        from .cost.collect import unread
        missing = unread(ws)
    if missing:
        names = '、'.join(f'{n}（{"、".join(k)}）' for n, k in sorted(missing.items()))
        print(f'费用采集完成，但 {len(missing)} 个订阅的费用没读到：{names}。01 不会包含这些费用，不能当作 0。'
              f'多半是限流或服务端出错，过一段时间后补读（已读到的会直接复用）：')
        print(f'  {command} --part cost --resume')
    if failed:
        print(f'采集完成，但以下支柱失败：{"、".join(failed)}。查明原因后补采：')
        print(f'  {command} --part waf --pillars {",".join(failed)}')
    return 1 if failed or missing else 0


def _chosen(ws, part, step):
    """customer.yaml and whether `step` runs `part` for the chosen reports (prints why not)."""
    from .core import config as config_mod
    from .selection import runs, skipped
    cfg = config_mod.load(ws.config_path)
    ok = runs(cfg.reports, part, step)
    if not ok and part != 'summary':
        print(skipped(cfg.reports, part))
    return cfg, ok


def cmd_analyze(args) -> int:
    ws, period = _month_workspace(args)
    client = None
    if not args.offline:
        _cfg, _tokens, client = _client(ws)
    parts = PARTS[:4] if args.part == 'all' else (args.part,)
    for part in ('vm', 'cost', 'waf', 'peer'):
        if part not in parts:
            continue
        cfg, ok = _chosen(ws, part, 'analyze')
        if not ok:
            continue
        if part == 'vm':
            from .vm.pipeline import analyze
            analyze(ws, client, args.price_date, fetch_prices=not args.offline)
        elif part == 'cost':
            from .cost.pipeline import analyze
            analyze(ws, period)
        elif part == 'waf':
            from .selection import waf_pillars
            from .waf.pipeline import analyze, parse
            analyze(ws, cfg, pillars=waf_pillars(cfg.reports, parse(args.pillars), groups=cfg.groups))
        else:
            from .peer import analyze
            analyze(ws, cfg)
    from .package import analysis_problems
    return 1 if analysis_problems(ws) else 0


def cmd_build(args) -> int:
    from .core import config as config_mod
    from .package import record_build, snapshot
    from .selection import save as save_selection, stale_narratives, stamp_narratives
    ws, period = _month_workspace(args)
    chosen = config_mod.load(ws.config_path)
    stale = stale_narratives(ws, chosen.reports, chosen.groups)
    if stale and not args.narrative_checked:
        print('这些说明文件是按另一次报告选择写的，之后没有改过：' + '；'.join(f'{n}（当时为 {was}）' for n, was in stale))
        print('请按本次选择改写（只写所选报告和支柱的内容；改回全部时要补上其他报告和支柱），再重新 build。'
              '确认内容仍然适用时，加 --narrative-checked 重新 build。')
        return 2
    from .waf.report import NarrativeError
    from .package import ASIDE, set_aside
    moved = set_aside(ws, chosen.reports)
    if moved:
        print(f'本月没有选择的报告的旧文件已移到 reports/{ASIDE}/：{"、".join(moved[:6])}' + (f' 等 {len(moved)} 个' if len(moved) > 6 else ''))
    started, before, built = time.time(), snapshot(ws), []
    parts = ('vm', 'cost', 'peer', 'waf', 'summary') if args.part == 'all' else (args.part,)
    try:
        for part in parts:   # peer before 03/04: their issue lists take the peer columns; summary last: 00 reads the others
            built += _build_part(ws, period, part, save_selection)
    except NarrativeError as e:   # e.g. a narrative pointing at problems of a pillar not chosen: say so, keep what was built
        record_build(ws, started, before, built)
        print(f'说明文件有误，报告没有生成完：{e}')
        print('请按本次选择改写说明文件（去掉没选的报告或支柱的问题编号和内容），再重新 build。'
              + (f'已生成的报告：{"、".join(built)}。' if built else ''))
        return 2
    record_build(ws, started, before, built)
    stamp_narratives(ws, chosen.reports, chosen.groups)
    return 0


def _build_part(ws, period, part, save_selection):
    """Builds one part for the chosen reports; returns the report codes built."""
    cfg, ok = _chosen(ws, part, 'build')
    save_selection(ws, cfg.reports, cfg.groups)
    if not ok:
        return []
    codes = {'vm': ['02'], 'cost': ['01'], 'peer': ['05'], 'summary': ['00'],
             'waf': [c for c in ('03', '04') if c in cfg.reports]}[part]
    if part == 'vm':
        from .vm.audit import audit
        from .vm.report import build
        build(ws, cfg, _narrative(ws, '02'))
        audit(ws)
    elif part == 'cost':
        from .cost.audit import audit
        from .cost.report import build
        build(ws, cfg, period, _narrative(ws, '01'))
        audit(ws, period)
    elif part == 'peer':
        from .peer import report as peer_report
        if peer_report.build(ws, cfg, _narrative(ws, '05')):
            peer_report.audit(ws)
    elif part == 'waf':
        from .waf.pipeline import build
        build(ws, cfg, {'03': _narrative(ws, '03'), '04': _narrative(ws, '04')}, codes=[c for c in ('03', '04') if c in cfg.reports])
    else:
        from .summary import build as build_summary
        build_summary(ws, cfg, period, _narrative(ws, '00'))
    return codes


def cmd_crosscheck(args) -> int:
    from .crosscheck import run
    ws, _period = _month_workspace(args)
    out = run(ws)
    return 0 if all(r['status'] in ('通过', '已处理', '需人工确认', '未检查', '不适用') for r in out['rules']) else 2


def cmd_package(args) -> int:
    from .core import config as config_mod
    from .package import build
    ws, period = _month_workspace(args)
    build(ws, config_mod.load(ws.config_path), period, allow_open=args.allow_open)
    return 0


def cmd_quality_check(args) -> int:
    from .core.quality import check_markdown, check_tree, left_out
    target = Path(args.path)
    skipped = left_out(target) if target.is_dir() else []
    if skipped:
        print(f'本月未选择这些报告，不检查（package 也不打包）：{"、".join(skipped)}')
    results = check_tree(target) if target.is_dir() else ({target.name: check_markdown(target)} if check_markdown(target) else {})
    for name, issues in results.items():
        print(name)
        for issue in issues:
            print('  - ' + issue)
    print('质量检查' + ('通过' if not results else f'未通过：{sum(len(v) for v in results.values())} 处问题'))
    return 0 if not results else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='azinspect', description='Azure 月度巡检（只读）')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('version').set_defaults(func=cmd_version)
    sub.add_parser('doctor', help='检查 Python、依赖、Azure CLI、中文字体').set_defaults(func=cmd_doctor)
    p = sub.add_parser('init', help='创建客户工作目录和 customer.yaml 模板')
    p.add_argument('--workspace', required=True)
    p.add_argument('--month', help='YYYY-MM，可选，同时创建该月目录')
    p.set_defaults(func=cmd_init)
    p = sub.add_parser('access-check', help='核对只读账号、可见订阅、资源和费用读取权限')
    p.add_argument('--workspace', required=True)
    p.set_defaults(func=cmd_access_check)
    for name, func, text in [('collect', cmd_collect, '只读采集（费用、资源、指标）'), ('analyze', cmd_analyze, '按规则分析，生成问题和建议'),
                             ('build', cmd_build, '生成报告（Markdown、Excel、图表）并核对')]:
        p = sub.add_parser(name, help=text)
        p.add_argument('--workspace', required=True)
        p.add_argument('--month', help='巡检的月份 YYYY-MM，默认上一个完整月')
        p.add_argument('--part', choices=PARTS + ('all',), default='all')
        if name == 'build':
            p.add_argument('--narrative-checked', action='store_true',
                           help='说明文件是按另一次报告选择写的、但已确认仍然适用时使用')
        if name != 'build':
            p.add_argument('--pillars', help='只处理部分支柱（逗号分隔），例如 aprl,defender；默认全部')
        if name == 'collect':
            p.add_argument('--resume', action='store_true',
                           help='续采：费用部分复用 7 天内已成功读取的结果，只读取缺少或失败的部分（中断后重跑时使用）')
        if name == 'analyze':
            p.add_argument('--offline', action='store_true', help='只用已保存的官网价格，不联网查询')
            p.add_argument('--price-date', help='价格日期 YYYY-MM-DD，默认今天；只使用该日期及之前查询的价格')
        p.set_defaults(func=func)
    p = sub.add_parser('crosscheck', help='跨报告交叉核对（X1–X12），结果写入 findings/crosscheck.json')
    p.add_argument('--workspace', required=True)
    p.add_argument('--month', help='巡检的月份 YYYY-MM，默认上一个完整月')
    p.set_defaults(func=cmd_crosscheck)
    p = sub.add_parser('package', help='打包交付文件夹和压缩包（先运行 build 和 crosscheck）')
    p.add_argument('--workspace', required=True)
    p.add_argument('--month', help='巡检的月份 YYYY-MM，默认上一个完整月')
    p.add_argument('--allow-open', action='store_true', help='交叉核对仍有“需要处理”的规则时也打包（必须告诉用户哪些只加了提醒）')
    p.set_defaults(func=cmd_package)
    p = sub.add_parser('quality-check', help='检查客户 Markdown（星号、图片、表格、内部用语、邮箱）')
    p.add_argument('--path', required=True)
    p.set_defaults(func=cmd_quality_check)
    args = parser.parse_args(argv)
    _matplotlib_cache(getattr(args, 'workspace', None))
    return args.func(args)


def _mpl_default_dir() -> Path:
    """Where matplotlib keeps its cache when MPLCONFIGDIR is not set: an existing ~/.matplotlib, else the platform's
    place (%LOCALAPPDATA%\\matplotlib on Windows)."""
    home = Path.home() / '.matplotlib'
    if home.is_dir() or platform.system() == 'Darwin':
        return home
    if platform.system() == 'Windows' and os.environ.get('LOCALAPPDATA'):
        return Path(os.environ['LOCALAPPDATA']) / 'matplotlib'
    return Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'matplotlib'


def _writable(directory) -> bool:
    """Can a file be written in `directory`? A directory made for the test is removed again: matplotlib chooses its place
    by what exists."""
    d = Path(directory)
    created = not d.exists()
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / f'.write-test-{os.getpid()}'
        probe.write_text('x', encoding='utf-8')
        probe.unlink()
        return True
    except OSError:
        return False
    finally:
        if created:
            try:
                d.rmdir()
            except OSError:
                pass


def _matplotlib_cache(workspace, default_ok=None):
    """Charts need a writable matplotlib cache. In a sandbox (Codex on Windows) matplotlib's own place is not writable and
    its fallback, a new directory under TEMP, cannot be written into either, and the agent may not set environment
    variables: use <workspace>/.cache/matplotlib then (outside raw/, never packaged)."""
    if not workspace or os.environ.get('MPLCONFIGDIR'):
        return
    if default_ok if default_ok is not None else _writable(_mpl_default_dir()):
        return
    os.environ['MPLCONFIGDIR'] = str(Path(workspace) / '.cache' / 'matplotlib')
