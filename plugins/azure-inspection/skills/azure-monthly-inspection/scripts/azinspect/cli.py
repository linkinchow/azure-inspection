"""Command line entry: python <skill>/scripts/azinspect_cli.py <command> [options]."""
from __future__ import annotations

import argparse
import importlib
import json
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
                defs[rid] = {'role': props.get('roleName') or rid.rsplit('/', 1)[-1], 'writes': _writes(props.get('permissions')) if d else None}
            rows.append({'subscription': names.get(sid, sid), 'scope': a['properties'].get('scope'), **defs[rid]})
    write = sorted({r['role'] for r in rows if r['writes']})
    subs = sorted({r['subscription'] for r in rows if r['writes']})
    if write:
        print(f'注意：该账号在 {len(subs)} 个订阅有可写角色（{"、".join(write)}）。巡检脚本只发读请求，'
              '但建议改用读者等只读角色；由 AI agent 执行巡检时，可写角色的风险更高。')
    elif rows:
        print('角色核对：只有只读角色。')
    if denied:
        print(f'  {len(denied)} 个订阅的角色分配读取失败，未能核对是否有可写角色')
    return {'read': not denied, 'assignments': rows, 'writeRoles': write, 'writeSubscriptions': subs, 'denied': denied}


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
        print('费用读取（Cost Management）：' + ('通过' if status == 200 else f'失败（{status} {error}），月度成本巡检需要“成本管理读者”或“读者”权限'))
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


COLLECT_ORDER = ('vm', 'cost', 'waf', 'peer')


def cmd_collect(args) -> int:
    """Exit code 1 when a WAF pillar failed. An interrupted `--part all` lists the parts still to collect, peer included:
    users tend to rerun only cost and waf, and 05 then lacks resource creation times."""
    ws, period = _month_workspace(args)
    cfg, _tokens, client = _client(ws)
    command = f'collect --workspace "{ws.root}" --month {period.current.key}'
    parts = COLLECT_ORDER if args.part == 'all' else tuple(p for p in COLLECT_ORDER if p == args.part)
    done, failed = [], []
    try:
        for part in parts:
            if part == 'vm':
                from .vm.collect import collect
                collect(ws, cfg, client, period)
            elif part == 'cost':
                from .cost.pipeline import collect
                collect(ws, cfg, client, period, resume=args.resume)
            elif part == 'waf':
                from .waf.pipeline import collect, parse
                failed = collect(ws, cfg, client, pillars=parse(args.pillars)) or []
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
            print('  同类对比（peer）也要补采，否则 05 没有资源创建时间。')
        elif left == ['cost']:
            print(f'费用采集中断。重跑时加 --resume，已成功读取的查询会直接复用：\n  {command} --part cost --resume')
        raise
    finally:
        ws.save_calls(f'collect-{args.part}', client.calls)
    if failed:
        print(f'采集完成，但以下支柱失败：{"、".join(failed)}。查明原因后补采：')
        print(f'  {command} --part waf --pillars {",".join(failed)}')
        return 1
    return 0


def cmd_analyze(args) -> int:
    ws, period = _month_workspace(args)
    client = None
    if not args.offline:
        _cfg, _tokens, client = _client(ws)
    if args.part in ('vm', 'all'):
        from .vm.pipeline import analyze
        analyze(ws, client, args.price_date, fetch_prices=not args.offline)
    if args.part in ('cost', 'all'):
        from .cost.pipeline import analyze
        analyze(ws, period)
    if args.part in ('waf', 'all'):
        from .core import config as config_mod
        from .waf.pipeline import analyze, parse
        analyze(ws, config_mod.load(ws.config_path), pillars=parse(args.pillars))
    if args.part in ('peer', 'all'):
        from .core import config as config_mod
        from .peer import analyze
        analyze(ws, config_mod.load(ws.config_path))
    return 0


def cmd_build(args) -> int:
    from .core import config as config_mod
    from .package import record_build
    ws, period = _month_workspace(args)
    cfg = config_mod.load(ws.config_path)
    started = time.time()
    if args.part in ('vm', 'all'):
        from .vm.audit import audit
        from .vm.report import build
        build(ws, cfg, _narrative(ws, '02'))
        audit(ws)
    if args.part in ('cost', 'all'):
        from .cost.audit import audit
        from .cost.report import build
        build(ws, cfg, period, _narrative(ws, '01'))
        audit(ws, period)
    if args.part in ('peer', 'all'):   # before 03/04: their issue lists take the peer columns from findings/peer/links.json
        from .peer import report as peer_report
        if peer_report.build(ws, cfg, _narrative(ws, '05')):
            peer_report.audit(ws)
    if args.part in ('waf', 'all'):
        from .waf.pipeline import build
        build(ws, cfg, {'03': _narrative(ws, '03'), '04': _narrative(ws, '04')})
    if args.part in ('summary', 'all'):   # last: 00 reads every other report's numbers
        from .summary import build as build_summary
        build_summary(ws, cfg, period, _narrative(ws, '00'))
    record_build(ws, started)
    return 0


def cmd_crosscheck(args) -> int:
    from .crosscheck import run
    ws, _period = _month_workspace(args)
    out = run(ws)
    return 0 if all(r['status'] in ('通过', '已处理', '需人工确认', '未检查') for r in out['rules']) else 2


def cmd_package(args) -> int:
    from .core import config as config_mod
    from .package import build
    ws, period = _month_workspace(args)
    build(ws, config_mod.load(ws.config_path), period, allow_open=args.allow_open)
    return 0


def cmd_quality_check(args) -> int:
    from .core.quality import check_markdown, check_tree
    target = Path(args.path)
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
        if name != 'build':
            p.add_argument('--pillars', help='只处理部分支柱（逗号分隔），例如 aprl,defender；默认全部')
        if name == 'collect':
            p.add_argument('--resume', action='store_true',
                           help='续采：费用部分复用 7 天内已成功读取的结果，只读取缺少或失败的部分（中断后重跑时使用）')
        if name == 'analyze':
            p.add_argument('--offline', action='store_true', help='只用已保存的官网价格，不联网查询')
            p.add_argument('--price-date', help='价格日期 YYYY-MM-DD，默认今天；只使用该日期及之前查询的价格')
        p.set_defaults(func=func)
    p = sub.add_parser('crosscheck', help='跨报告交叉核对（X1–X9），结果写入 findings/crosscheck.json')
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
    return args.func(args)
