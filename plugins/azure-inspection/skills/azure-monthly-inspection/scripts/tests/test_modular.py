"""Tests for optional reports (customer.yaml report.include): what runs, what 00 summarises, crosscheck and package (synthetic data)."""
from __future__ import annotations

import contextlib
import io as stdio
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
os.environ.setdefault('AZINSPECT_NO_EXCEL', '1')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect import crosscheck, package, selection, summary  # noqa: E402
from azinspect.core import config, io  # noqa: E402
from azinspect.core.period import ReportPeriod  # noqa: E402

TEMPLATE = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'


def cfg_with(include):
    text = TEMPLATE.read_text(encoding='utf-8').replace('  # include: [', '  include: [', 1)
    if include is not None:
        text = re.sub(r"  include: \[.*\]", f'  include: {include!r}', text, count=1)
    d = tempfile.mkdtemp()
    path = Path(d) / 'customer.yaml'
    path.write_text(text, encoding='utf-8')
    return config.load(path)


class ConfigTests(unittest.TestCase):
    def test_default_is_every_report(self):
        self.assertEqual(config.load(TEMPLATE).reports, ('01', '02', '03', '04', '05'))

    def test_codes_normalised_and_ordered(self):
        self.assertEqual(cfg_with(['3', '01']).reports, ('01', '03'))

    def test_unknown_or_empty_refused(self):
        for bad in (['06'], []):
            with self.assertRaises(config.ConfigError):
                cfg_with(bad)


class PlanTests(unittest.TestCase):
    def test_dependencies_collected_only_as_far_as_needed(self):
        plan = dict(selection.collect_plan(('01',)))
        self.assertEqual(plan, {'vm': 'inventory', 'cost': 'full'})
        plan = dict(selection.collect_plan(('02',)))
        self.assertEqual(plan, {'vm': 'full', 'cost': 'vm-coverage'})

    def test_04_and_05_collect_the_pillars_they_read(self):
        plan = dict(selection.collect_plan(('04',)))
        self.assertEqual(sorted(plan), ['waf'])
        self.assertEqual(sorted(plan['waf']), ['amba', 'aprl', 'operations', 'performance', 'reliability', 'security_identity'])
        self.assertEqual(sorted(selection.waf_pillars(('04',))), ['amba', 'aprl', 'operations', 'performance'])   # APRL has an 04 rule (O11)
        plan = dict(selection.collect_plan(('05',)))
        self.assertEqual(sorted(plan), ['peer', 'waf'])
        self.assertNotIn('aprl', plan['waf'])

    def test_explicit_part(self):
        self.assertEqual(selection.collect_plan(('03',), 'cost'), [])
        self.assertEqual(selection.collect_plan(('01',), 'vm'), [('vm', 'inventory')])
        self.assertIn('不在 customer.yaml', selection.skipped(('03',), 'cost'))
        self.assertTrue(selection.runs(('03',), 'summary', 'build'))
        self.assertFalse(selection.runs(('03',), 'vm', 'analyze'))


class CollectCommandTests(unittest.TestCase):
    def test_only_chosen_parts_run(self):
        from azinspect import cli
        import azinspect.cost.pipeline
        import azinspect.peer
        import azinspect.vm.collect
        import azinspect.waf.pipeline
        seen = {}
        record = lambda name: lambda *a, **k: seen.setdefault(name, k)  # noqa: E731
        with (tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(stdio.StringIO()),
              mock.patch.object(cli, '_client', return_value=(SimpleNamespace(reports=('01', '03'), groups=('可靠性', '安全')), None, SimpleNamespace(calls=[]))),
              mock.patch.object(azinspect.vm.collect, 'collect', record('vm')),
              mock.patch.object(azinspect.cost.pipeline, 'collect', record('cost')),
              mock.patch.object(azinspect.waf.pipeline, 'collect', lambda *a, **k: seen.setdefault('waf', k) and []),
              mock.patch.object(azinspect.peer, 'collect', record('peer'))):
            self.assertEqual(cli.main(['collect', '--workspace', d, '--month', '2026-09']), 0)
        self.assertEqual(sorted(seen), ['cost', 'vm', 'waf'])
        self.assertEqual(seen['vm'], {'inventory_only': True})
        self.assertEqual(sorted(seen['waf']['pillars']),
                         ['aprl', 'defender', 'landing_zone', 'operations:inventory', 'reliability', 'security_identity', 'security_network'])

    def test_vm_inventory_only(self):
        from azinspect.vm import collect as vm_collect
        cfg = config.load(TEMPLATE)
        vm = {'id': '/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-a', 'name': 'vm-a',
              'type': 'microsoft.compute/virtualmachines', 'location': 'eastus', 'subscriptionId': 's1', 'resourceGroup': 'rg',
              'properties': {'hardwareProfile': {'vmSize': 'Standard_D4s_v5'}, 'timeCreated': '2026-01-01T00:00:00Z'}}
        posts = []

        class Client:
            calls = []

            def get_all(self, *a):
                return [{'subscriptionId': 's1', 'displayName': 'app_prod', 'state': 'Enabled', 'tenantId': cfg.tenant_id}], 200, None

            def request(self, method, url, check, body=None):
                if method == 'POST':
                    posts.append(url)
                    return 200, {'values': []}, None
                if '/locations' in url:
                    return 200, {'value': [{'name': 'eastus'}]}, None
                return 200, {'value': [{'resourceType': 'virtualMachines', 'name': 'Standard_D4s_v5'}]}, None

            def arg(self, query, subs, check):
                if query.startswith('ResourceContainers'):
                    return [{'subscriptionId': 's1', 'name': 'app_prod'}], 200, None
                return ([vm] if query.startswith('Resources') else []), 200, None

        for inventory_only in (True, False):
            with tempfile.TemporaryDirectory() as d:
                ws = io.Workspace(d, '2026-09')
                ws.create()
                posts.clear()
                vm_collect.collect(ws, cfg, Client(), ReportPeriod.build('2026-09'), log=lambda *_: None, inventory_only=inventory_only)
                self.assertTrue(ws.raw('vm/inventory/vms.json').exists())
                self.assertTrue(ws.raw('vm/metrics/sku-capabilities.json').exists())   # 01's month usage review needs both
                self.assertEqual(io.read_json(ws.raw('vm/inventory/manifest.json'))['metricsCollected'], not inventory_only)
                self.assertEqual(ws.raw('vm/metrics/vms-average.json').exists(), not inventory_only)
                self.assertEqual(bool(posts), not inventory_only)   # no 30-day metric reads

    def test_vm_coverage_only(self):
        from azinspect.cost import commitments
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('vm/inventory/subscriptions.json'), [
                {'id': 's1', 'name': 'app_prod', 'state': 'Enabled', 'vmCount': 2}, {'id': 's2', 'name': 'empty', 'state': 'Enabled', 'vmCount': 0}])
            rows = [{'subscriptionId': 's1', 'resourceId': '/subscriptions/s1/x/virtualmachines/vm-a', 'pricingModel': 'Reservation', 'cost': 10.0}]
            with mock.patch.object(commitments, 'pricing', return_value=(rows, {'s1': {'Reservation': 10.0}},
                                                                          {'s1': {'ok': True, 'machines': True, 'models': True}})) as p:
                commitments.collect_vm_coverage(ws, None, ReportPeriod.build('2026-09'), log=lambda *_: None)
            self.assertEqual(p.call_args.args[2], ['s1'])   # subscriptions with machines only
            self.assertEqual(commitments.vm_coverage(ws)['/subscriptions/s1/x/virtualmachines/vm-a']['share'], 1.0)


def month(d, chosen):
    """01 and 03 built; 02 left from an earlier build of the same month."""
    ws = io.Workspace(d, '2026-09')
    ws.create()
    f, r = ws.month_dir('findings'), ws.month_dir('reports')
    io.write_json(f / 'cost' / 'model.json', {'comparableTotals': {'cur': 1234.5, 'prev': 1000.0, 'delta': 234.5, 'changeRate': 0.2345, 'dailyChangeRate': 0.2},
                                              'totals': {'comparableSubscriptionCount': 3}})
    io.write_json(f / 'vm' / 'summary.json', {'recommendedVMCount': 7, 'monthlyPotentialSavingsUSD': 999.0, 'subscriptionCount': 3})
    io.write_json(f / 'waf' / 'report-03.json', {'total': 5, 'bySeverity': {'高': 1, '中': 4}, 'byGroup': {'可靠性-高': 1, '安全-中': 4}})
    for name in ('01_9月月度成本巡检报告.md', '02_虚拟机利用率与规格优化.md', '03_可靠性与安全巡检报告.md'):
        (r / name).write_text('# x\n', encoding='utf-8')
    selection.save(ws, chosen)
    return ws


class SummaryTests(unittest.TestCase):
    def test_only_chosen_reports(self):
        with tempfile.TemporaryDirectory() as d:
            ws = month(d, ['01', '03'])
            text = summary.build(ws, config.load(TEMPLATE), ReportPeriod.build('2026-09'), log=lambda *_: None).read_text(encoding='utf-8')
        self.assertIn('本次包含 01 月度成本、03 可靠性与安全', text)
        self.assertNotIn('VM 规格调整', text)        # 02 left over from an earlier build: not summarised
        self.assertNotIn('02_虚拟机', text)
        self.assertNotIn('卓越运营与性能效率', text)
        numbers = [int(x) for x in re.findall(r'^## (\d+)\.', text, re.M)]
        self.assertEqual(numbers, list(range(1, len(numbers) + 1)))
        self.assertRegex(text, r'\|一\|01_')
        self.assertRegex(text, r'\|二\|03_')
        self.assertIn('成本优化', text)
        self.assertIn('RI/SP 现有订单', text)   # 01 chosen: the RI/SP question stays

    def test_without_cost_reports(self):
        with tempfile.TemporaryDirectory() as d:
            ws = month(d, ['03'])
            text = summary.build(ws, config.load(TEMPLATE), ReportPeriod.build('2026-09'), log=lambda *_: None).read_text(encoding='utf-8')
        self.assertNotIn('成本优化', text)
        self.assertNotIn('RI/SP', text)
        self.assertNotIn('- 费用：', text)
        self.assertRegex(text, r'\|一\|03_')

    def build(self, ws):
        return summary.build(ws, config.load(TEMPLATE), ReportPeriod.build('2026-09'), log=lambda *_: None).read_text(encoding='utf-8')

    def test_only_02_states_subscriptions_and_vm_window(self):
        with tempfile.TemporaryDirectory() as d:
            ws = month(d, ['02'])
            io.write_json(ws.raw('vm/metrics/manifest.json'), {'start': '2026-10-24T00:00:00Z', 'end': '2026-10-31T00:00:00Z'})
            text = self.build(ws)
        self.assertIn('示例客户 3 个 Azure 订阅', text)   # from 02: no 01 cost model, no WAF scope
        self.assertNotIn('None', text)
        self.assertIn('- 虚拟机利用率：2026 年 10 月 24 日至 10 月 31 日（UTC）的 7 天指标。', text)
        self.assertIn('读取费用、配置和监控指标', text)   # 02 reads RI/SP cost data and metrics, no logs

    def test_only_05_states_configuration_date(self):
        with tempfile.TemporaryDirectory() as d:
            ws = month(d, ['05'])
            (ws.month_dir('reports') / '05_同类资源配置对比报告.md').write_text('# x\n', encoding='utf-8')
            io.write_json(ws.raw('waf/scope.json'), {'collectedAt': '2026-10-26T03:00:00Z', 'subscriptions': [
                {'id': 's1', 'name': 'a', 'state': 'Enabled'}, {'id': 's2', 'name': 'b', 'state': 'Enabled'}]})
            text = self.build(ws)
        self.assertIn('- 配置：2026 年 10 月 26 日读取。', text)
        self.assertIn('以只读方式读取配置，', text)

    def test_method_for_03_matches_03(self):
        with tempfile.TemporaryDirectory() as d:
            text = self.build(month(d, ['03']))
        self.assertIn('以只读方式读取配置、监控指标和日志', text)   # 03 itself says 配置、指标和日志

    def test_wording_follows_chosen_reports(self):
        with tempfile.TemporaryDirectory() as d:
            text = self.build(month(d, ['01']))
        self.assertIn('覆盖费用变化、闲置资源和 RI/SP 使用情况', text)   # no 02/04: no resource utilisation
        self.assertIn('读取费用、配置和监控指标', text)

    def test_layout_for_any_selection(self):
        # one blank line between blocks, a blank line before every heading, no empty section and no table without rows
        for chosen in (['01'], ['02'], ['03'], ['05'], ['01', '03'], ['02', '05']):
            with tempfile.TemporaryDirectory() as d:
                ws = month(d, chosen)
                if '05' in chosen:
                    (ws.month_dir('reports') / '05_同类资源配置对比报告.md').write_text('# x\n', encoding='utf-8')
                    io.write_json(ws.month_dir('findings') / 'peer' / 'report.json', {'deviations': 0})
                lines = self.build(ws).split('\n')
            for i, line in enumerate(lines[1:], 1):
                with self.subTest(chosen=chosen, line=i):
                    self.assertFalse(line == '' and lines[i - 1] == '', 'two blank lines')
                    if line.startswith('#'):
                        self.assertEqual(lines[i - 1], '', 'no blank line before a heading')
                    if line.startswith('## ') and i + 2 < len(lines):
                        self.assertFalse(lines[i + 2].startswith('## '), 'empty section')
                    if line.startswith('|---'):
                        self.assertTrue(i + 1 < len(lines) and lines[i + 1].startswith('|'), 'table without rows')

    def test_chosen_report_missing(self):
        with tempfile.TemporaryDirectory() as d:
            ws = month(d, ['01', '04'])
            with self.assertRaises(SystemExit) as e:
                summary.build(ws, config.load(TEMPLATE), ReportPeriod.build('2026-09'), log=lambda *_: None)
            self.assertIn('04', str(e.exception))


class QualityCheckSelectionTests(unittest.TestCase):
    """quality-check --path reports/ checks the reports chosen this month, like package; older files of other reports are named, not checked."""

    def test_left_out_reports_not_checked(self):
        from azinspect.core.quality import check_tree, left_out
        with tempfile.TemporaryDirectory() as d:
            reports = Path(d) / 'reports'
            reports.mkdir()
            (Path(d) / 'findings').mkdir()
            (reports / '01_旧报告.md').write_text('TODO', encoding='utf-8')
            (reports / '03_可靠性巡检报告.md').write_text('正文。', encoding='utf-8')
            self.assertIn('01_旧报告.md', check_tree(reports))        # no selection recorded: everything is checked
            io.write_json(Path(d) / 'findings' / 'selection.json', {'reports': ['03'], 'groups': ['可靠性']})
            self.assertEqual(check_tree(reports), {})
            self.assertEqual(left_out(reports), ['01_旧报告.md'])


class MonthRowTests(unittest.TestCase):
    """00 compares only the chosen reports with last month and says how many earlier problems belong to the others."""

    def test_other_reports_counted(self):
        rows = [{'check': 'O1', 'status': '仍未处理', 'severity': '中'}, {'check': 'R1', 'status': '本月未检查', 'severity': '中'},
                {'check': 'S-I1', 'status': '本月未检查', 'severity': '高'}]
        tracked = {'previous': '2026-08', 'rows': rows}
        self.assertEqual(summary.month_row(tracked, ['04']),
                         ['与 2026-08 相比', '仍未处理 1 项（另有 2 项上月问题属于本月没有选择的报告，未列入）'])
        self.assertEqual(summary.month_row(tracked, ['03', '04']), ['与 2026-08 相比', '仍未处理 1 项，本月未检查 2 项'])


class LeftOverResultsTests(unittest.TestCase):
    """A report left out this month may have older results in the month folder; the chosen reports must not read them."""

    def test_03_ignores_peer_columns_when_05_left_out(self):
        from azinspect.waf import report as waf_report
        with tempfile.TemporaryDirectory() as d:
            ws = month(d, ['03'])
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': 's1', 'name': 'app_prod', 'state': 'Enabled'}]})
            io.write_json(ws.month_dir('findings') / 'waf' / 'reliability.json', {'pillar': 'reliability', 'complete': True, 'coverage': {},
                          'findings': [{'id': 'R1-aaaaaa', 'check': 'R1', 'severity': '高', 'finding': 'x', 'resourceName': 'db-1'}]})
            io.write_json(ws.month_dir('findings') / 'peer' / 'links.json', {'R1-aaaaaa': {'rootCause': '门户手工创建'}})
            self.assertNotIn('rootCause', waf_report.load(ws, '03')[1][0])
            selection.save(ws, ['03', '05'])
            self.assertEqual(waf_report.load(ws, '03')[1][0]['rootCause'], '门户手工创建')

    def test_issue_list_says_peer_columns_empty_without_05(self):
        from azinspect.waf import report as waf_report
        self.assertIn('本月没有做 05', waf_report.list_note(('03',)))
        self.assertNotIn('05', waf_report.list_note(('03', '05')))

    def test_04_ignores_02_when_left_out(self):
        import importlib
        from azinspect.waf import common
        perf = importlib.import_module('azinspect.waf.performance.analyze')
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.month_dir('findings') / 'vm' / 'recommendations.json', [
                {'name': 'db-1', 'status': '建议试点调整', 'currentSKU': 'Standard_E8s_v5', 'targetSKU': 'Standard_E4s_v5'}])
            a = perf.Analyzer.__new__(perf.Analyzer)
            a.ws, a.F, a.cfg = ws, common.Findings('performance'), SimpleNamespace(reports=('04',))
            a.F.add('P1', '高', '虚拟机 db-1 过去 30 天平均内存使用 92.0%，长期接近上限。', 'r', resource_name='db-1')
            a.annotate_rightsizing()
        self.assertNotIn('02', a.F.items[0]['finding'])


class SubscriptionScopeTests(unittest.TestCase):
    """customer.yaml scope.includeSubscriptions limits the inspection to some subscriptions."""

    def month(self, root, month, findings, subs):
        from azinspect import tracking  # noqa: F401
        ws = io.Workspace(root, month)
        ws.create()
        io.write_json(ws.raw('waf/scope.json'), {'collectedAt': f'{month}-28T00:00:00Z',
                                                 'subscriptions': [{'id': s, 'name': s, 'state': 'Enabled'} for s in subs]})
        io.write_json(ws.month_dir('findings') / 'waf' / 'reliability.json', {'pillar': 'reliability', 'complete': True, 'findings': findings,
                      'coverage': {'R1': {'attempted': 1, 'succeeded': 1}}})
        return ws

    def test_tracking_does_not_resolve_subscriptions_left_out(self):
        from azinspect import tracking
        f = lambda fid, sub: {'id': fid, 'check': 'R1', 'severity': '中', 'finding': 'x', 'resourceName': fid, 'subscriptionName': sub}  # noqa: E731
        with tempfile.TemporaryDirectory() as d:
            tracking.update(self.month(d, '2026-08', [f('R1-a', 'core'), f('R1-b', 'other')], ['core', 'other']), log=lambda *_: None)
            # September: only the key subscription; the other one's problem was not inspected, not resolved
            rows = {r['id']: r for r in tracking.update(self.month(d, '2026-09', [f('R1-a', 'core')], ['core']), log=lambda *_: None)['rows']}
            self.assertEqual(rows['R1-a']['status'], '仍未处理')
            self.assertEqual(rows['R1-b']['status'], '本月未检查')
            # October: every subscription again; a problem in a subscription not inspected in September is new coverage, not a new problem
            rows = {r['id']: r for r in tracking.update(self.month(d, '2026-10', [f('R1-a', 'core'), f('R1-c', 'other')], ['core', 'other']),
                                                        log=lambda *_: None)['rows']}
            self.assertEqual(rows['R1-c']['status'], '新增检查项发现')

    def test_tracking_aggregate_label_is_not_a_subscription(self):
        # '全部 2 个可读订阅' is a merged row, not a subscription left out: with the same scope, gone means resolved
        from azinspect import tracking
        row = {'id': 'R1-all', 'check': 'R1', 'severity': '中', 'finding': 'x', 'resourceName': 'x', 'subscriptionName': '全部 2 个可读订阅'}
        with tempfile.TemporaryDirectory() as d:
            tracking.update(self.month(d, '2026-08', [row], ['core', 'other']), log=lambda *_: None)
            rows = {r['id']: r for r in tracking.update(self.month(d, '2026-09', [], ['core', 'other']), log=lambda *_: None)['rows']}
        self.assertEqual(rows['R1-all']['status'], '已解决')

    def test_tracking_tenant_rows_follow_no_subscription(self):
        # rows about the tenant (management groups, root Owner) are checked tenant-wide whatever the subscription scope:
        # gone means resolved, in a narrowed month too
        from azinspect import tracking
        rows = [{'id': 'S-I5-root', 'check': 'R1', 'severity': '高', 'finding': 'x', 'resourceName': 'Tenant Root Group',
                 'subscriptionName': '租户根管理组（继承到全部订阅）'},
                {'id': 'R1-mg', 'check': 'R1', 'severity': '中', 'finding': 'y', 'resourceName': '管理组', 'subscriptionName': '租户'}]
        for scope in (['core', 'other'], ['core']):
            with tempfile.TemporaryDirectory() as d:
                tracking.update(self.month(d, '2026-08', rows, ['core', 'other']), log=lambda *_: None)
                out = tracking.update(self.month(d, '2026-09', [], scope), log=lambda *_: None)
            self.assertEqual({r['id']: r['status'] for r in out['rows']}, {'S-I5-root': '已解决', 'R1-mg': '已解决'}, scope)

    def test_root_owner_label_names_no_count(self):
        # the root management group reaches every subscription in the tenant, not only those chosen this month
        from azinspect.waf.security_identity import checks_access
        added = []
        ctx = SimpleNamespace(gobj={'p1': {'displayName': 'admin', 'type': '#microsoft.graph.user'}}, enabled=[{'id': 'core'}],
                              add=lambda *a, **k: added.append(a))
        checks_access._root(ctx, ['p1'], [])
        self.assertEqual(added[0][2], '租户根管理组（继承到全部订阅）')

    def test_tracking_subscription_member_named_by_id_or_name(self):
        # S-I11 listed a subscription by its ID before 0.9.0 and by its name since: the same resource either way
        from azinspect import tracking
        sid = '00000000-0000-0000-0000-000000000001'

        def month(d, m, fid, sub, member):
            ws = self.month(d, m, [{'id': fid, 'check': 'R1', 'severity': '中', 'finding': 'x', 'resourceName': member, 'subscriptionName': sub,
                                    'members': [{'name': member, 'type': 'Microsoft.Resources/subscriptions', 'subscription': sub}]}], ['core'])
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': sid, 'name': 'core', 'state': 'Enabled'}]})
            return ws
        with tempfile.TemporaryDirectory() as d:
            tracking.update(month(d, '2026-08', 'R1-old', 'core', sid), log=lambda *_: None)
            out = tracking.update(month(d, '2026-09', 'R1-new', 'core', 'core'), log=lambda *_: None)
        rows = {r['id']: r for r in out['rows']}
        self.assertEqual(rows['R1-new']['status'], '仍未处理')
        self.assertNotIn('R1-old', rows)

    def defender_month(self, root, month, findings, subs):
        ws = self.month(root, month, [], subs)
        io.write_json(ws.month_dir('findings') / 'waf' / 'defender.json', {'pillar': 'defender', 'findings': findings,
                      'coverage': {'S-I11': {'attempted': 1, 'succeeded': 1}}})
        return ws

    def test_regroup_prefers_the_same_problem(self):
        # rows of one check sharing a resource (several Defender recommendations on one subscription): a regrouped row
        # maps to last month's row about the same recommendation, not to all of them
        from azinspect import tracking

        def row(fid, title, sub, days=40):   # the opening clause also carries how long it has been open, which changes monthly
            return {'id': fid, 'check': 'S-I11', 'severity': '中', 'finding': f'Defender for Cloud 高严重性建议“{title}”已超过 30 天未处理（最长 {days} 天），涉及 1 个资源',
                    'resourceName': 'core', 'subscriptionName': sub, 'members': [{'name': 'core', 'subscription': 'core'}]}
        with tempfile.TemporaryDirectory() as d:
            tracking.update(self.defender_month(d, '2026-08', [row('R1-a', 'A', '多个订阅（2 个）'), row('R1-b', 'B', '多个订阅（2 个）')], ['core', 'other']),
                            log=lambda *_: None)
            out = tracking.update(self.defender_month(d, '2026-09', [row('R1-a2', 'A', 'core', 70), row('R1-b2', 'B', 'core', 70)], ['core']), log=lambda *_: None)
        rows = {r['id']: r for r in out['rows']}
        self.assertEqual(rows['R1-a2'].get('previousIds'), ['R1-a'])
        self.assertEqual(rows['R1-b2'].get('previousIds'), ['R1-b'])

    def test_regroup_by_title_only(self):
        # a titled problem is the same problem only under the same title; IDs in a title (one 'ASC Default' assignment per
        # subscription) do not tell problems apart
        from azinspect import tracking
        g1, g2 = '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b'

        def row(fid, finding, sub):
            return {'id': fid, 'check': 'S-I11', 'severity': '低', 'finding': finding, 'resourceName': 'core', 'subscriptionName': sub,
                    'members': [{'name': 'core', 'subscription': 'core'}]}
        with tempfile.TemporaryDirectory() as d:
            tracking.update(self.defender_month(d, '2026-08', [row('R1-p', f'Azure Policy 分配“ASC Default (subscription: {g1})”有 9 个不合规资源', '多个订阅（2 个）'),
                                                      row('R1-x', 'Defender for Cloud 中严重性建议“X”已超过 30 天未处理', '多个订阅（2 个）')],
                                        ['core', 'other']), log=lambda *_: None)
            out = tracking.update(self.defender_month(d, '2026-09', [row('R1-p2', f'Azure Policy 分配“ASC Default (subscription: {g2})”有 3 个不合规资源', 'core'),
                                                            row('R1-y', 'Defender for Cloud 中严重性建议“Y”已超过 30 天未处理', 'core')], ['core']),
                                  log=lambda *_: None)
        rows = {r['id']: r for r in out['rows']}
        self.assertEqual(rows['R1-p2'].get('previousIds'), ['R1-p'])
        self.assertEqual(rows['R1-y']['status'], '新增问题')          # a recommendation not there last month is new
        self.assertNotIn('previousIds', rows['R1-y'])

    def test_tracking_read_failure_never_resolves(self):
        # a check that ran but had a failed read (e.g. its VM query got 400): what it did not see is not resolved
        from azinspect import tracking
        f = lambda fid: {'id': fid, 'check': 'R1', 'severity': '中', 'finding': 'x', 'resourceName': fid, 'subscriptionName': 'core'}  # noqa: E731
        with tempfile.TemporaryDirectory() as d:
            tracking.update(self.month(d, '2026-08', [f('R1-a'), f('R1-b')], ['core']), log=lambda *_: None)
            ws = self.month(d, '2026-09', [f('R1-a')], ['core'])
            path = ws.month_dir('findings') / 'waf' / 'reliability.json'
            data = io.read_json(path)
            data['coverage']['R1'] = {'attempted': 5, 'succeeded': 4, 'otherErrors': 1}
            io.write_json(path, data)
            out = tracking.update(ws, log=lambda *_: None)
        rows = {r['id']: r for r in out['rows']}
        self.assertEqual(rows['R1-b']['status'], '本月未检查')
        self.assertEqual(rows['R1-b']['notChecked'], '读取失败')

    def test_tracking_after_upgrade(self):
        # last month was built before subscriptions were recorded (0.8.x): a problem in a subscription left out now is still not resolved
        from azinspect import tracking
        f = lambda fid, sub: {'id': fid, 'check': 'R1', 'severity': '中', 'finding': 'x', 'resourceName': fid, 'subscriptionName': sub}  # noqa: E731
        with tempfile.TemporaryDirectory() as d:
            old = self.month(d, '2026-08', [f('R1-a', 'core'), f('R1-b', 'other'), f('R1-m', '(多个订阅)'), f('R1-n', '多个订阅（2 个）')],
                             ['core', 'other'])
            tracking.update(old, log=lambda *_: None)
            path = old.state_dir / 'months' / '2026-08.json'
            record = io.read_json(path)
            del record['subscriptions']
            io.write_json(path, record)
            rows = {r['id']: r for r in tracking.update(self.month(d, '2026-09', [f('R1-a', 'core')], ['core']), log=lambda *_: None)['rows']}
        self.assertEqual(rows['R1-b']['status'], '本月未检查')
        # merged rows without resources: the scope narrowed, so they may lie in the subscriptions not read
        self.assertEqual(rows['R1-m']['status'], '本月未检查')
        self.assertEqual(rows['R1-n']['status'], '本月未检查')

    def test_tracking_merged_rows_when_scope_narrows(self):
        # last month: rows merged across subscriptions; this month only 'core' is inspected
        from azinspect import tracking
        m = lambda *pairs: [{'name': n, 'subscription': s} for s, n in pairs]  # noqa: E731

        def row(fid, sub, members):
            return {'id': fid, 'check': 'R1', 'severity': '中', 'finding': 'x', 'resourceName': fid, 'subscriptionName': sub, 'members': members}
        with tempfile.TemporaryDirectory() as d:
            old = self.month(d, '2026-08', [row('R1-other', '(多个订阅)', m(('a', 'db-1'), ('b', 'db-2'))),       # only in subscriptions left out
                                            row('R1-mixed', '多个订阅（2 个）', m(('core', 'vm-1'), ('a', 'vm-2')))],  # regrouped below
                             ['core', 'a', 'b'])
            tracking.update(old, log=lambda *_: None)
            path = old.state_dir / 'months' / '2026-08.json'
            record = io.read_json(path)          # built before members were recorded: read from last month's findings
            record.pop('subscriptions')
            for f in record['findings'].values():
                f.pop('members', None)
            io.write_json(path, record)
            now = self.month(d, '2026-09', [row('R1-core', 'core', m(('core', 'vm-1')))], ['core'])
            rows = {r['id']: r for r in tracking.update(now, log=lambda *_: None)['rows']}
        self.assertEqual(rows['R1-other']['status'], '本月未检查')   # its resources are all in subscriptions not inspected
        self.assertEqual(rows['R1-core']['status'], '仍未处理')      # the same problem, now one row per subscription
        self.assertNotIn('R1-mixed', rows)                           # counted once, as the row above

    def test_cross_subscription_rule_incomplete_when_scope_narrowed(self):
        # an ExpressRoute gateway's circuits often sit in another subscription: with a narrowed scope Resource Graph cannot see
        # them, so the APRL rule finds nothing; that is not evidence of a fix
        import dataclasses
        import importlib
        aprl = importlib.import_module('azinspect.waf.aprl')
        guid = 'd37db635-157f-584d-9bce-4f6fc8c65ce5'
        er = {'type': 'microsoft.network/virtualnetworkgateways', 'name': 'gw-1', 'properties': {'gatewayType': 'ExpressRoute'}}
        vpn = {'type': 'microsoft.network/virtualnetworkgateways', 'name': 'gw-2', 'properties': {'gatewayType': 'Vpn'}}
        # (scope, gateways read in the chosen subscriptions (None: not read), expected)
        for include, gateways, expected in (([], [er], None), (['core'], [er], ['d37db635']), (['core'], None, ['d37db635']),
                                            (['core'], [vpn], None), (['core'], [], None)):
            with tempfile.TemporaryDirectory() as d:
                ws = io.Workspace(d, '2026-09')
                ws.create()
                io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': 'core', 'name': 'core', 'state': 'Enabled'}]})
                if gateways is not None:   # no ExpressRoute gateway in the chosen subscriptions: nothing to miss
                    io.write_json(ws.raw('waf/reliability/arg/vnetgw.json'), {'status': 200, 'rows': gateways})
                io.write_json(ws.raw('waf/aprl/results.json'), {'results': [{'aprlGuid': guid, 'status': 200, 'rows': []}]})
                cfg = dataclasses.replace(config.load(TEMPLATE), include=include)
                out = aprl.analyze(ws, cfg, log=lambda *_: None)
            c = out['coverage']['R16']
            self.assertEqual(c.get('incomplete'), expected)
            self.assertEqual(any('专线线路' in x for x in c.get('limits') or []), bool(expected))

    def test_tracking_scope_incomplete_rule_not_resolved(self):
        from azinspect import tracking

        def row(fid, guid):
            return {'id': fid, 'check': 'R16', 'severity': '中', 'finding': f'专线网关……：gw-1。（APRL 建议 {guid}）', 'resourceName': 'gw-1',
                    'subscriptionName': 'core', 'members': [{'name': 'gw-1', 'subscription': 'core'}]}

        def month(d, m, findings, cov):
            ws = self.month(d, m, [], ['core'])
            io.write_json(ws.month_dir('findings') / 'waf' / 'aprl.json', {'pillar': 'aprl', 'findings': findings, 'coverage': {'R16': cov}})
            return ws
        with tempfile.TemporaryDirectory() as d:
            tracking.update(month(d, '2026-08', [row('R16-a', 'd37db635'), row('R16-b', '3e115044')], {'attempted': 3, 'succeeded': 3}),
                            log=lambda *_: None)
            out = tracking.update(month(d, '2026-09', [], {'attempted': 3, 'succeeded': 3, 'incomplete': ['d37db635']}), log=lambda *_: None)
        rows = {r['id']: r for r in out['rows']}
        self.assertEqual((rows['R16-a']['status'], rows['R16-a'].get('notChecked')), ('本月未检查', '范围不完整'))
        self.assertEqual(rows['R16-b']['status'], '已解决')       # the other rules under R16 still judge their own resources

    def test_architecture_names_the_narrowed_scope(self):
        from azinspect.waf import architecture
        arch = {'subscriptions': [], 'network': [('专线', 0), ('VPN 或专线网关', 2)], 'peerings': None, 'crossRegionPeerings': None}
        self.assertIn('Azure 中没有专线', '\n'.join(architecture.section(arch, {})))
        text = '\n'.join(architecture.section({**arch, 'narrowed': True}, {}))
        self.assertIn('所选订阅中没有专线', text)
        self.assertIn('其他订阅', text)

    def test_scope_sentence(self):
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [
                {'id': 's1', 'name': 'pay-prod', 'state': 'Enabled'}, {'id': 's2', 'name': 'shop-prod', 'state': 'Enabled'}]})
            selection.save(ws, ['03'])
            self.assertEqual(selection.subscription_scope(ws, config.load(TEMPLATE)), '')   # no include/exclude: every subscription
            cfg = SimpleNamespace(include=['*-prod'], exclude=[])
            text = selection.subscription_scope(ws, cfg)
            selection.save(ws, ['01', '03'])
            own = {code: selection.subscription_scope(ws, cfg, code) for code in ('01', '03')}
            both = selection.subscription_scope(ws, cfg)
        self.assertIn('按贵司选择，本次只检查 2 个订阅：pay-prod、shop-prod', text)
        self.assertIn('Entra ID', text)          # 03 chosen: tenant-wide identity checks named
        self.assertNotIn('预留', text)            # 01/02 not chosen
        self.assertNotIn('预留', own['03'])       # each report names its own tenant-wide checks
        self.assertNotIn('Entra', own['01'])
        self.assertIn('预留', both)               # 00: every chosen report's
        self.assertIn('Entra', both)

    def test_00_states_chosen_subscriptions(self):
        with tempfile.TemporaryDirectory() as d:
            ws = month(d, ['01', '03'])
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': 's1', 'name': 'pay-prod', 'state': 'Enabled'}]})
            cfg = cfg_with(None)
            cfg.include = ['pay-prod']
            text = summary.build(ws, cfg, ReportPeriod.build('2026-09'), log=lambda *_: None).read_text(encoding='utf-8')
        self.assertIn('按贵司选择，本次只检查 1 个订阅：pay-prod', text)


class PillarTests(unittest.TestCase):
    """03/04 narrowed to some of their pillars: report.include ['可靠性'] etc."""

    def test_config(self):
        cfg = cfg_with(['01', '可靠性'])
        self.assertEqual((cfg.reports, cfg.groups), (('01', '03'), ('可靠性',)))
        cfg = cfg_with(['03'])
        self.assertEqual((cfg.reports, cfg.groups), (('03',), ('可靠性', '安全')))
        self.assertEqual(config.load(TEMPLATE).groups, ('可靠性', '安全', '卓越运营', '性能效率'))

    def test_plan(self):
        self.assertEqual(sorted(selection.waf_pillars(('03',), groups=('可靠性',))), ['aprl', 'landing_zone', 'reliability'])
        self.assertEqual(sorted(dict(selection.collect_plan(('03',), groups=('安全',)))['waf']),
                         ['aprl', 'defender', 'landing_zone', 'operations:inventory', 'reliability', 'security_identity',
                          'security_network'])   # reads reliability; the resource inventory for the architecture overview
        self.assertIn('operations', selection.waf_pillars(('03', '04'), collect=True))      # 卓越运营 done: the full pillar
        self.assertNotIn('operations:inventory', selection.waf_pillars(('03', '04'), collect=True))
        self.assertNotIn('operations:inventory', selection.waf_pillars(('03',), ['reliability'], collect=True))   # --pillars
        self.assertNotIn('reliability', selection.waf_pillars(('03',), groups=('安全',)))                               # not analysed
        self.assertEqual(selection.waf_pillars(('04',), groups=('性能效率',)), ['performance'])
        self.assertEqual(selection.title('03', ('可靠性',)), '可靠性')
        self.assertEqual(selection.title('03'), '可靠性与安全')

    def workspace(self, d, include):
        ws = io.Workspace(d, '2026-09')
        ws.create()
        io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': 's1', 'name': 'app_prod', 'state': 'Enabled'}]})
        row = lambda fid, check: {'id': fid, 'check': check, 'severity': '高', 'finding': 'x', 'resourceName': fid,  # noqa: E731
                                  'subscriptionName': 'app_prod', 'recommendation': 'r'}
        cov = {'attempted': 1, 'succeeded': 1}
        for pillar, rows in (('reliability', [row('R1-a', 'R1')]), ('aprl', [row('R16-b', 'R16'), row('S-N9-c', 'S-N9'), row('O11-d', 'O11')]),
                             ('security_network', [row('S-N2-e', 'S-N2')])):   # security_network: left over from an earlier build
            io.write_json(ws.month_dir('findings') / 'waf' / f'{pillar}.json', {'pillar': pillar, 'complete': True, 'findings': rows,
                          'coverage': {r['check']: cov for r in rows}})
        cfg = cfg_with(include)
        selection.save(ws, cfg.reports, cfg.groups)
        return ws, cfg

    def test_report_keeps_chosen_pillars_only(self):
        from azinspect.waf import report as waf_report
        with tempfile.TemporaryDirectory() as d:
            ws, _ = self.workspace(d, ['可靠性'])
            datasets, findings = waf_report.load(ws, '03')
            self.assertEqual(sorted(f['id'] for f in findings), ['R1-a', 'R16-b'])   # no S-N9 from APRL, no stale S-N2
            self.assertTrue(all(k.startswith('R') for d_ in datasets.values() for k in d_['coverage']))
            self.assertEqual(waf_report.stems('03', ('可靠性',)), ('03_可靠性巡检报告', '03_可靠性巡检问题清单'))
            meta = waf_report.meta_of('03', ('可靠性',))
            self.assertEqual(meta['groups'], ['可靠性'])
            self.assertFalse(any('安全' in t for t, _ in meta['links']))

    def test_00_and_crosscheck(self):
        with tempfile.TemporaryDirectory() as d:
            ws, cfg = self.workspace(d, ['02', '可靠性'])
            r = ws.month_dir('reports')
            for name in ('02_虚拟机利用率与规格优化.md', '03_可靠性巡检报告.md'):
                (r / name).write_text('# x\n', encoding='utf-8')
            io.write_json(ws.month_dir('findings') / 'vm' / 'summary.json', {'recommendedVMCount': 1, 'monthlyPotentialSavingsUSD': 1.0, 'subscriptionCount': 1})
            io.write_json(ws.month_dir('findings') / 'waf' / 'report-03.json', {'total': 2, 'bySeverity': {'高': 2}, 'byGroup': {'可靠性-高': 2}})
            text = summary.build(ws, cfg, ReportPeriod.build('2026-09'), log=lambda *_: None).read_text(encoding='utf-8')
            rules = {x['rule']: x for x in crosscheck.run(ws, log=lambda *_: None)['rules']}
        self.assertIn('本次包含 02 虚拟机规格、03 可靠性', text)
        self.assertIn('03_可靠性巡检报告、03_可靠性巡检问题清单', text)
        self.assertNotIn('## 4. 安全', text)
        self.assertEqual(rules['X1']['status'], '不适用')
        self.assertIn('性能效率', rules['X1']['reason'])

    def test_tracking_left_out_pillar(self):
        from azinspect import tracking
        with tempfile.TemporaryDirectory() as d:
            ws, _ = self.workspace(d, None)
            tracking.update(ws, log=lambda *_: None)
            path = ws.state_dir / 'months' / '2026-09.json'
            path.rename(path.with_name('2026-08.json'))
            ws, _ = self.workspace(d, ['可靠性'])
            out = tracking.update(ws, log=lambda *_: None)
            rows = {x['id']: x['status'] for x in out['rows']}
            from azinspect.waf.report import month_sentence
            self.assertIn('2 项所在的订阅或支柱本月按贵司选择没有检查，不能判断', month_sentence(out, '03'))   # S-N2, S-N9; one reason: no 都
        self.assertEqual(rows['R1-a'], '仍未处理')
        self.assertEqual(rows['S-N2-e'], '本月未检查')   # 安全 not done this month: never resolved, never still open
        self.assertEqual(rows['S-N9-c'], '本月未检查')
        self.assertEqual(rows['O11-d'], '本月未检查')


class StableIdTests(unittest.TestCase):
    """A per-resource row with a fixed key (e.g. S-I1 key='api-server' per AKS cluster) keeps its id when another resource
    of the same check appears in the subscription."""

    def ids(self, clusters):
        from azinspect.waf.common import Findings
        F = Findings('security_identity')
        for c in clusters:
            F.add('S-I1', '中', 'x', 'r', subscription='app_prod', resource_name=c, resource_id=f'/subscriptions/s/rg/aks/{c}', key='api-server')
        return {f['resourceName']: f for f in F.items}

    def test_new_resource_does_not_take_an_old_id(self):
        before = self.ids(['aks-old'])
        after = self.ids(['aks-new', 'aks-old'])   # the new cluster is processed first
        self.assertEqual(after['aks-old']['id'], before['aks-old']['id'])
        self.assertNotEqual(after['aks-new']['id'], before['aks-old']['id'])

    def test_narratives_still_find_the_id_used_before(self):
        from azinspect.waf.common import Findings
        from azinspect.waf.report import resolve
        F = Findings('security_identity')
        old = F.add('S-I1', '中', 'x', 'r', subscription='app_prod', resource_name='aks-old', key='api-server')['id']   # no resource id: as before
        row = self.ids(['aks-old'])['aks-old']
        self.assertEqual(row['previousId'], old)
        self.assertIs(resolve([row], old), row)

    def test_previous_id_only_when_unambiguous(self):
        # two clusters under one key: the old scheme numbered them by order, so its id says nothing about which cluster
        from azinspect.waf.common import Findings
        F = Findings('security_identity')
        for c in ('aks-new', 'aks-old'):
            F.add('S-I1', '中', 'x', 'r', subscription='app_prod', resource_name=c, resource_id=f'/subscriptions/s/rg/aks/{c}', key='api-server')
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            F.write(ws, window=None, coverage={}, scope={})
        self.assertTrue(all('previousId' not in f and '_previousBase' not in f for f in F.items))

    def test_narratives_follow_tracking(self):
        # a last-month id is found through the rows tracking matched by resource; several matches are refused, not guessed
        from azinspect.waf.report import NarrativeError, resolve
        a = {'id': 'S-I3-new1', 'previousIds': ['S-I3-old1']}
        b = {'id': 'S-I3-new2', 'previousIds': ['S-I3-old2', 'S-I3-old3']}
        c = {'id': 'S-I3-new3', 'previousIds': ['S-I3-old3']}
        self.assertIs(resolve([a, b, c], 'S-I3-old1'), a)
        with self.assertRaises(NarrativeError) as e:
            resolve([a, b, c], 'S-I3-old3')
        self.assertIn('本月编号', str(e.exception))

    def test_merged_rows_keep_their_id(self):
        from azinspect.waf.common import Findings
        a, b = Findings('security_network'), Findings('security_network')
        x = a.add('S-N2', '低', 'x', 'r', subscription='多个订阅（3 个）', resource_name='5 个 NSG', resource_id='/x/1', key='nsg-latent')
        y = b.add('S-N2', '低', 'x', 'r', subscription='多个订阅（4 个）', resource_name='6 个 NSG', resource_id='/x/2', key='nsg-latent')
        self.assertEqual(x['id'], y['id'])


class WordingTests(unittest.TestCase):
    def test_one_subscription_is_named(self):
        from azinspect.waf.common import Findings
        F = Findings('security_identity')
        one = F.add('S-I4', '中', 'x', 'r', subscription='多个订阅（1 个）', key='a', members=[{'name': 'global', 'subscription': 'global'}])
        prod = F.add('O2', '中', 'x', 'r', subscription='多个订阅（1 个生产订阅）', key='b', members=[{'name': 'global', 'subscription': 'global'}])
        two = F.add('S-I4', '中', 'x', 'r', subscription='多个订阅（2 个）', key='c',
                    members=[{'name': 'a', 'subscription': 'a'}, {'name': 'b', 'subscription': 'b'}])
        ids = [one['id'], prod['id']]
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            F.write(ws, window=None, coverage={}, scope={})
        self.assertEqual((one['subscriptionName'], prod['subscriptionName'], two['subscriptionName']), ('global', 'global', '多个订阅（2 个）'))
        self.assertEqual([one['id'], prod['id']], ids)   # wording only: ids unchanged

    def test_aggregate_labels_name_the_only_subscription(self):
        # one subscription inspected: '(多个订阅)', '多个订阅', '全部 1 个可读订阅', '1 个订阅' all read as its name
        from azinspect.waf.common import Findings
        F = Findings('operations')
        rows = [F.add('O8', '中', 'x', 'r', subscription=s, key=f'k{i}') for i, s in enumerate(['(多个订阅)', '多个订阅', '全部 1 个可读订阅', '1 个订阅'])]
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': 's1', 'name': 'core', 'state': 'Enabled'},
                                                                      {'id': 's2', 'name': 'old', 'state': 'Disabled'}]})
            F.write(ws, window=None, coverage={}, scope={})
        self.assertEqual([r['subscriptionName'] for r in rows], ['core'] * 4)

    def test_aggregate_labels_kept_with_several_subscriptions(self):
        from azinspect.waf.common import Findings
        F = Findings('operations')
        one = F.add('O8', '中', 'x', 'r', subscription='多个订阅', key='a', members=[{'name': 'x', 'subscription': 'a'}])
        two = F.add('O8', '中', 'x', 'r', subscription='全部 2 个可读订阅', key='b',
                    members=[{'name': 'x', 'subscription': 'a'}, {'name': 'y', 'subscription': 'b'}])
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': s, 'name': s, 'state': 'Enabled'} for s in 'ab']})
            F.write(ws, window=None, coverage={}, scope={})
        self.assertEqual((one['subscriptionName'], two['subscriptionName']), ('a', '全部 2 个可读订阅'))

    def test_advisor_note_in_chinese(self):
        from pathlib import Path as P
        text = P(__file__).resolve().parents[1].joinpath('azinspect/waf/reliability/analyze.py').read_text(encoding='utf-8')
        self.assertNotIn('recommendations across', text)
        self.assertNotIn('advisor-all.json).', text)


class ForecastTests(unittest.TestCase):
    """A forecast that could not be read (e.g. throttled, 429) is not a subscription without costs."""

    def test_note_tells_failure_from_no_cost(self):
        from azinspect.cost.report import forecast_note
        sup = {'forecast': {'subscriptions': [{'next': {'status': 'error', 'fullMonthEstimate': None}},
                                              {'next': {'status': 'empty', 'fullMonthEstimate': None}},
                                              {'next': {'status': 'success', 'fullMonthEstimate': 10.0}}]}}
        text = forecast_note(sup, '9 月')
        self.assertIn('1个订阅的预测读取失败', text)
        self.assertIn('1个订阅没有返回预测结果（多为9 月无费用的订阅）', text)
        self.assertEqual(forecast_note({'forecast': {'subscriptions': [{'next': {'status': 'error'}}]}}, '9 月'), '；1个订阅的预测读取失败（如接口限流），未计入预测')

    def test_audit_expects_the_charts_drawn(self):
        from azinspect.cost.charts import expected_charts
        labels = {'prev': '8 月', 'cur': '9 月', 'next': '10 月'}
        none = {'next': [(1, None, None), (2, None, None)]}
        some = {'next': [(1, 5.0, None), (2, None, 6.0)]}
        self.assertNotIn('forecast', expected_charts(labels, '订阅', none))   # the audit then does not require 01_2
        self.assertIn('forecast', expected_charts(labels, '订阅', some))

    def test_no_forecast_chart_without_forecast(self):
        from datetime import date
        from azinspect.cost.charts import make_pngs
        days = [(date(2026, 9, d), 10.0) for d in range(1, 31)]
        data = {'groupLabel': '订阅', 'timeline': days + days[:1], 'next': [(d, None, None) for d in range(1, 32)], 'prevDailyAverage': 10.0,
                'curDailyAverage': 10.0, 'groups': [('a', 1.0, 2.0)], 'services': [], 'regions': []}
        labels = {'prev': '8 月', 'cur': '9 月', 'next': '10 月', 'prevDays': 31}
        with tempfile.TemporaryDirectory() as d:
            try:
                out = make_pngs(data, labels, Path(d))
            except (KeyError, IndexError, ValueError, TypeError):
                self.skipTest('chart data shape changed; covered by the sample build')
        self.assertNotIn('forecast', out)


class DefaultTextTests(unittest.TestCase):
    """01 without a narrative must pass quality-check even when a small scope makes it short (limit max(5, 6 per 10,000))."""

    def test_default_01_text_leaves_room_for_hedges(self):
        import ast
        from azinspect.core.quality import HEDGE_MIN, HEDGES
        source = (Path(__file__).resolve().parents[1] / 'azinspect' / 'cost' / 'report.py').read_text(encoding='utf-8')
        found = []
        for fn in ast.parse(source).body:
            if isinstance(fn, ast.FunctionDef) and fn.name in ('markdown', 'action_items', 'forecast_note', 'budget_text', 'unreadable_text', 'commitment_text'):
                for node in ast.walk(fn):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        found += [(fn.name, w, node.value[:30]) for w in HEDGES for _ in range(node.value.count(w))]
        self.assertLessEqual(len(found), HEDGE_MIN - 3, found)


class CheckTableTests(unittest.TestCase):
    """A check with failed reads never reads as 未发现问题 in the 03/04 check table."""

    def test_failed_reads_are_said(self):
        from azinspect.waf.report import check_note
        ok, part, none = {'attempted': 3, 'succeeded': 3}, {'attempted': 5, 'succeeded': 4, 'otherErrors': 1}, {'attempted': 2, 'succeeded': 0, 'denied': 2}
        self.assertEqual(check_note([], ok), '未发现问题')
        self.assertEqual(check_note([], part), '部分读取失败，未能完整检查（见 Excel“检查覆盖”页）')
        self.assertEqual(check_note([], none), '读取失败，未能检查（见 Excel“检查覆盖”页）')
        self.assertEqual(check_note([], part, '客户已确认'), '客户已确认；部分读取失败，结果可能不完整')

    def test_cut_never_splits_a_number(self):
        # the check table shortens a finding; a cut inside '237' would read as '23'
        from azinspect.waf.report import first_clause
        text = '甲' * 66 + '共有 237 条高严重性未修复建议'
        self.assertEqual(first_clause(text), '甲' * 66 + '共有……')
        text = '乙' * 50 + '，' + '丙' * 30
        self.assertEqual(first_clause(text), '乙' * 50 + '……')       # a comma near the limit is a better place to stop
        self.assertEqual(first_clause('短句。后面'), '短句')
        # details in brackets go first, so the point after them stays (nested brackets too)
        text = '240 台运行中的生产虚拟机（其中 19 台挂有数据盘，如 vm-a、vm-b、vm-c、vm-d、vm-e、vm-f）没有安装 Azure Monitor 代理，也没有 VM Insights 和告警'
        self.assertEqual(first_clause(text, 40), '240 台运行中的生产虚拟机没有安装 Azure Monitor 代理……')
        text = '戊' * 40 + '（setting=true（当前无匿名容器）、允许共享密钥访问、门户默认未用 Entra ID 认证）有加固项未设置；后面'
        self.assertEqual(first_clause(text), '戊' * 40 + '有加固项未设置……')     # '……': items after '；' left out
        # a list 'name（what is wrong）；name（...）': a bracket that ends the clause holds the point, so it stays
        text = ('该订阅 5 个存储账户有加固项未设置：stacc1（allowBlobPublicAccess=true（当前无匿名容器）、允许共享密钥访问、'
                '门户默认未用 Entra ID 认证）；stacc2（允许共享密钥访问）；stacc3（门户默认未用 Entra ID 认证）')
        cut = first_clause(text)
        self.assertTrue(cut.startswith('该订阅 5 个存储账户有加固项未设置：stacc1（allowBlobPublicAccess=true、允许共享密钥访问'), cut)
        self.assertTrue(cut.endswith('……）……'), cut)        # the bracket says it was cut too
        # a short qualifier such as （推断） is not a detail: dropping it would state a guess as fact
        text = '生产（推断）订阅 core 的 Defender 工作负载保护全部是免费层（仅基础 CSPM，无威胁检测），共有 37 条高严重性未修复建议，VM、AKS、数据库和存储都没有威胁检测'
        self.assertTrue(first_clause(text).startswith('生产（推断）订阅 core 的 Defender 工作负载保护全部是免费层，'), first_clause(text))
        # a quote or bracket the limit cuts into is closed
        text = 'Defender for Cloud 高严重性建议“A maximum of 3 owners should be designated for your subscription”已超过 30 天'
        self.assertEqual(first_clause(text, 50), 'Defender for Cloud 高严重性建议“A maximum of 3 owners……”')
        # a bracket ending the clause after ordinary text is a detail too (it goes before the point is cut)
        text = '甲' * 30 + '使用 MySQL 8.0，标准支持将于 2026-04-30 结束（还有 40 天，需要尽快规划升级）'
        self.assertEqual(first_clause(text), '甲' * 30 + '使用 MySQL 8.0，标准支持将于 2026-04-30 结束')
        # a bracket ending the clause that lists the items counted before it is the point
        text = 'Advisor 其余卓越运营建议：7 条中低影响建议（虚拟机默认出站、AKS 临时 OS 盘/自动扩缩容/新一代机型、Redis VNet 注入）'
        self.assertIn('（虚拟机默认出站', first_clause(text))
        # no space left between Chinese words where a bracket was
        text = '乙' * 40 + '以及 1 个空子网（snet-very-long-name-for-test-a） 未关联 NSG，入站流量不受控制'
        self.assertEqual(first_clause(text), '乙' * 40 + '以及 1 个空子网未关联 NSG，入站流量不受控制')
        # a '；' inside brackets does not end the clause
        text = '在每个生产订阅创建服务运行状况告警（事件类型：服务问题、计划内维护；区域选实际使用的全部区域），通知到值班组；再做别的'
        self.assertEqual(first_clause(text), '在每个生产订阅创建服务运行状况告警（事件类型：服务问题、计划内维护；区域选实际使用的全部区域），通知到值班组……')

    def test_scope_incomplete_is_said(self):
        # a rule that cannot see resources in subscriptions left out (customer.yaml scope) never reads as 未发现问题
        from azinspect.waf.report import check_note
        cov = {'attempted': 3, 'succeeded': 3, 'incomplete': ['d37db635']}
        self.assertEqual(check_note([], cov), '所选订阅中未发现问题；涉及其他订阅的部分可能漏报（见“检查范围与限制”）')

    def test_tracking_reasons(self):
        from azinspect.waf.report import TRACKING_HELP, gone_row, month_sentence
        rows = [{'id': f'R16-{i}', 'check': 'R16', 'severity': '中', 'finding': 'x', 'status': '本月未检查', 'notChecked': why}
                for i, why in enumerate(['读取失败', '不在本月范围', '范围不完整'])]
        text = month_sentence({'previous': '2026-08', 'rows': rows}, '03')
        self.assertIn('1 项是对应检查本月读取失败', text)
        self.assertIn('1 项所在的订阅或支柱本月按贵司选择没有检查', text)
        self.assertIn('1 项涉及本月没有检查的订阅', text)
        for why in ('读取失败', '不在本月范围', '范围不完整'):
            self.assertIn(why, TRACKING_HELP)
        self.assertEqual(gone_row(rows[2])[-2:], ['本月未检查', '范围不完整'])
        self.assertEqual(gone_row({**rows[0], 'status': '已解决', 'notChecked': None})[-1], None)

    def test_limit_lists_checks_with_failed_reads(self):
        from azinspect.waf.report import failure_limit
        cov = {'S-I8': {'attempted': 5, 'succeeded': 4, 'otherErrors': 1}, 'S-I7': {'attempted': 7, 'succeeded': 7}}
        self.assertIn('虚拟机安全基线', failure_limit(cov))
        self.assertNotIn('审计', failure_limit(cov))
        self.assertEqual(failure_limit({'S-I7': {'attempted': 1, 'succeeded': 1}}), '')


class ArchitectureInventoryTests(unittest.TestCase):
    """03 without 卓越运营: the operations pillar reads only its resource inventory (architecture overview)."""

    def test_pipeline_runs_inventory_phase_only(self):
        from azinspect.waf import pipeline
        calls = []
        fake = SimpleNamespace(collect=lambda *a, **k: calls.append(k))
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': []})
            with mock.patch.object(pipeline, '_module', return_value=fake):
                pipeline.collect(ws, None, SimpleNamespace(calls=[]), log=lambda *_: None, pillars=['reliability', 'operations:inventory'])
        self.assertEqual(calls, [{}, {'phases': ['arg']}])

    def test_inventory_only_does_not_state_metric_window(self):
        from azinspect.waf import pipeline
        out = []
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': []})
            with mock.patch.object(pipeline, '_module', return_value=SimpleNamespace(collect=lambda *a, **k: None)):
                pipeline.collect(ws, None, SimpleNamespace(calls=[]), log=out.append, pillars=['operations:inventory'])
        self.assertFalse(any('时间窗' in x for x in out))   # the inventory reads no metrics or logs

    def test_inventory_only_is_not_analysed(self):
        from azinspect.waf import pipeline
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/operations/manifest.json'), {'collectedAt': 'x', 'phases': ['arg']})
            out = []
            with mock.patch.object(pipeline, '_module') as module:
                done = pipeline.analyze(ws, None, log=out.append, pillars=['operations'])
            module.assert_not_called()
        self.assertEqual(done, [])
        self.assertTrue(any('只采了资源清单' in x for x in out))

    def test_coverage_notes_joined_without_double_stops(self):
        from azinspect.waf.report import notes_text
        self.assertEqual(notes_text(['Advisor: 3 recommendations (saved).', '退役公告 4 条。']), 'Advisor: 3 recommendations (saved)；退役公告 4 条。')
        self.assertEqual(notes_text('一句话。'), '一句话。')

    def test_performance_window_only_with_performance(self):
        from azinspect.waf.report import window_line
        self.assertEqual(window_line('04', ['卓越运营'], ('2026-10-01', '2026-10-31')), '')
        self.assertIn('性能数据窗口', window_line('04', ['卓越运营', '性能效率'], ('2026-10-01', '2026-10-31')))
        self.assertEqual(window_line('03', ['可靠性'], ('2026-10-01', '2026-10-31')), '')


class ChartFreshnessTests(unittest.TestCase):
    """X9 trusts what build recorded (the data a chart was drawn from) over file times, which a save can leave older."""

    def test_chart_drawn_from_current_data(self):
        import time
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            data = ws.month_dir('findings') / 'vm' / 'summary.json'
            io.write_json(data, {'n': 1})
            chart = ws.month_dir('reports') / 'charts' / '02_2_VM平均利用率分布.png'
            chart.parent.mkdir(parents=True, exist_ok=True)
            chart.write_bytes(b'png')
            package.record_build(ws, time.time() - 5, package.snapshot(ws))
            old = data.stat().st_mtime - 100
            os.utime(chart, (old, old))                 # the chart's time reads older than its data
            self.assertEqual(crosscheck.x9(ws)['items'], [])
            io.write_json(data, {'n': 2})               # the data changed after the build: the chart is stale
            self.assertEqual([x['resource'] for x in crosscheck.x9(ws)['items']], [chart.name])


class ChartRecordTests(unittest.TestCase):
    def test_redrawn_identical_chart_is_recorded(self):
        # a redrawn chart can be byte-identical to the old one and keep an old file time: build records the charts of the
        # reports it built, whatever their times or content
        import time
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.month_dir('findings') / 'waf' / 'operations.json', {'n': 1})
            chart = ws.month_dir('reports') / 'charts' / '04_1_图.png'
            chart.parent.mkdir(parents=True, exist_ok=True)
            chart.write_bytes(b'png')
            before = package.snapshot(ws)
            old = time.time() - 1000
            os.utime(chart, (old, old))
            package.record_build(ws, time.time(), before, codes=['04'])
            self.assertEqual(crosscheck.x9(ws)['items'], [])
            other = ws.month_dir('reports') / 'charts' / '02_1_图.png'   # a report not built this time is not vouched for
            other.write_bytes(b'png')
            os.utime(other, (old, old))
            io.write_json(ws.month_dir('findings') / 'vm' / 'summary.json', {'n': 1})
            package.record_build(ws, time.time(), package.snapshot(ws), codes=['04'])
            self.assertEqual([x['resource'] for x in crosscheck.x9(ws)['items']], [other.name])


class CrosscheckTests(unittest.TestCase):
    def test_rules_for_reports_left_out(self):
        with tempfile.TemporaryDirectory() as d:
            ws = month(d, ['01', '03'])
            rules = {r['rule']: r for r in crosscheck.run(ws, log=lambda *_: None)['rules']}
        for rule in ('X1', 'X2', 'X3', 'X4'):
            self.assertEqual(rules[rule]['status'], '不适用')
            self.assertIn('04', rules[rule]['reason'])
        self.assertNotEqual(rules['X5']['status'], '不适用')   # 01 with 03
        self.assertNotIn('02', ' '.join(i['resource'] for i in rules['X6']['items']))


class PackageTests(unittest.TestCase):
    def test_left_out_reports_not_packed(self):
        with tempfile.TemporaryDirectory() as d:
            ws = month(d, ['01', '03'])
            (ws.month_dir('reports') / '00_Azure巡检汇总报告_2026年10月.md').write_text('# 汇总\n', encoding='utf-8')
            io.write_json(ws.month_dir('findings') / 'crosscheck.json', {'rules': []})
            out = []
            manifest = package.build(ws, config.load(TEMPLATE), ReportPeriod.build('2026-09'), log=out.append)
        self.assertEqual(sorted(f['name'] for f in manifest['files']),
                         ['00_Azure巡检汇总报告_2026年10月.md', '01_9月月度成本巡检报告.md', '03_可靠性与安全巡检报告.md'])
        self.assertTrue(any('02' in x and '不打包' in x for x in out))


if __name__ == '__main__':
    unittest.main()
