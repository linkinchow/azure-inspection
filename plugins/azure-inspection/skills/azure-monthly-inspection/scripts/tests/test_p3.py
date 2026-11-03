"""0.10.5: smaller fixes from the 0.10.x test rounds (synthetic data, no network)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect import crosscheck  # noqa: E402
from azinspect.core import io  # noqa: E402


class X10MatchingTests(unittest.TestCase):
    def items(self, table, conclusion):
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            (ws.month_dir('reports') / '00_Azure巡检汇总报告_2026年10月.md').write_text(
                f'# x\n\n## 1. 总体结论\n\n|指标|结果|\n|---|---|\n|{table}|\n\n{conclusion}\n\n## 2. 其他\n', encoding='utf-8')
            return [i['resource'] for i in crosscheck.x10(ws)['items']]

    def test_whole_figures_and_rounding(self):
        # 2.5% was taken as in the table because the table had 12.5%; 14.8% was listed although the table had 14.82%
        self.assertEqual(self.items('费用|USD 1,200.00，增加 14.82%，占比 12.5%', '费用增加 14.8%，其中 2.5% 来自新服务。'), ['2.5%'])
        self.assertEqual(self.items('费用|USD 1,200.00', '9 月费用 USD 1,200.00，另有 USD 200.00 待确认。'), ['USD 200.00'])
        self.assertEqual(self.items('节省|USD 11,200.00', '每月节省 USD 1,200.00。'), ['USD 1,200.00'])   # not part of 11,200.00

    def test_whole_amounts(self):
        # a whole amount in a conclusion was not checked at all
        self.assertEqual(self.items('费用|USD 8,315,402.37', '9 月费用约 USD 8,315,402，另有 USD 5,000 的预留。'), ['USD 5,000'])
        self.assertEqual(self.items('费用|USD 1,200.00', '约 USD 1.2 万。'), [])   # a rounded amount in 万 is left alone


class TruncationTests(unittest.TestCase):
    def test_unit_after_a_space(self):
        # 04 "磁盘与 IO" read "IOPS：30……" for "IOPS：30 天达到 100%": the space before 天 hid the unit
        from azinspect.waf.report import _cut
        text = '数据盘 data-disk-01 的 IOPS：30 天达到 100%，吞吐也接近上限，建议升级磁盘'
        cut = _cut(text, 27, '')
        self.assertTrue(cut.startswith('数据盘 data-disk-01 的 IOPS：30 天'), cut)
        self.assertEqual(_cut('近 7 次 备份失败，最近一次在周一，其余略' * 2, 3, ''), '近 7 次……')


class SmallFixesTests(unittest.TestCase):
    def test_report_file_names_keep_their_spelling(self):
        # 00's attachment table read "01_9 月月度成本巡检报告": the spacing rule split the file name
        from azinspect.core.fmt_md import format_markdown
        self.assertIn('|01_9月月度成本巡检报告（Markdown、Excel）|', format_markdown('|一|01_9月月度成本巡检报告（Markdown、Excel）|9月费用|\n'))
        self.assertIn('9 月费用', format_markdown('|一|x|9月费用|\n'))   # prose still spaced

    def test_02_alone_reads_no_reservation_orders(self):
        # 02 only reads which machines RI/SP cover; its scope sentence named the orders as read tenant-wide
        from types import SimpleNamespace
        from azinspect import selection
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': 's1', 'name': 'pay-prod', 'state': 'Enabled'}]})
            cfg = SimpleNamespace(include=['pay-prod'], exclude=[])
            selection.save(ws, ['02'])
            self.assertNotIn('订单', selection.subscription_scope(ws, cfg))
            selection.save(ws, ['01', '02'])
            self.assertIn('预留和节省计划订单', selection.subscription_scope(ws, cfg))

    def test_partly_missing_top_issue_is_flagged(self):
        # a top issue keeping some of its ids still told the story of the skipped ones
        from azinspect.waf.report import apply_narrative
        findings = [{'id': 'R1-aaaaaa', 'severity': '中', 'finding': 'x'}]
        _out, warnings = apply_narrative(findings, {'topIssues': [{'title': 'a', 'findingIds': ['R1-aaaaaa', 'S-N2-bbbbbb']}]})
        self.assertTrue(any('“a”' in w and '核对' in w for w in warnings))

    def test_peer_gap_without_internal_path(self):
        import importlib
        text = importlib.import_module('azinspect.peer.analyze').CREATED_GAP
        self.assertNotIn('raw/', text)

    def test_bar_limits_follow_the_data(self):
        # every change an increase left the left half of 01_4/01_5 empty
        from azinspect.core.charts import bar_limits
        lo, hi = bar_limits([100.0, 40.0, 5.0])
        self.assertGreaterEqual(lo, -10)
        self.assertGreater(hi, 100)
        lo, hi = bar_limits([-80.0, 100.0])
        self.assertLess(lo, -80)
        self.assertGreater(hi, 100)

    def test_last_day_may_be_incomplete_early_in_the_month(self):
        from datetime import date
        from azinspect.cost.report import late_cost_note
        self.assertIn('10月最后一天', late_cost_note('2026-11-01T15:00:00Z', date(2026, 10, 31), '10月'))
        self.assertEqual(late_cost_note('2026-11-05T15:00:00Z', date(2026, 10, 31), '10月'), '')


class WordingTests(unittest.TestCase):
    def test_over_report_names_the_row(self):
        # the check's 主要发现 named one problem and then said "可能多报，请核对" about another
        from azinspect.waf.report import check_note
        fs = [{'id': 'R20-a', 'finding': '未开启自动扩缩容', 'severity': '中', 'rule': 'aaaaaaaa'},
              {'id': 'R20-b', 'finding': 'AKS 集群没有配置备份', 'severity': '中', 'rule': '3e115044'}]
        cov = {'attempted': 2, 'succeeded': 2, 'overReport': ['3e115044'], 'incomplete': ['d37db635']}
        note = check_note(fs, cov, '未开启自动扩缩容')
        self.assertIn('“AKS 集群没有配置备份”可能多报', note)
        self.assertIn('可能漏报', note)
        self.assertNotIn('可能漏报或多报', note)

    def test_new_rules_are_named_as_such(self):
        # a rule added to a check that ran last month read as if the whole check were new
        from azinspect.waf.report import month_sentence
        rows = [{'id': 'R9-a', 'check': 'R9', 'severity': '中', 'finding': 'x', 'status': '新增检查项发现'}]
        text = month_sentence({'previous': '2026-08', 'rows': rows}, '03')
        self.assertIn('新增的检查规则', text)


class SetAsideTests(unittest.TestCase):
    def test_reports_not_chosen_are_moved_aside(self):
        # after the choice changed, reports/ still held 02, 04 and 05 from the earlier full build
        from azinspect import package
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            r = ws.month_dir('reports')
            (r / 'charts').mkdir(exist_ok=True)
            for name in ('00_汇总.md', '01_成本.md', '02_规格.md', '02_规格.xlsx', 'charts/02_1_x.png', 'charts/01_1_x.png'):
                (r / name).write_text('x', encoding='utf-8')
            moved = package.set_aside(ws, ('01',))
            self.assertEqual(sorted(moved), ['02_规格.md', '02_规格.xlsx', 'charts/02_1_x.png'])
            self.assertTrue((r / package.ASIDE / '02_规格.md').exists())
            self.assertTrue((r / package.ASIDE / 'charts' / '02_1_x.png').exists())
            self.assertTrue((r / '00_汇总.md').exists() and (r / '01_成本.md').exists() and (r / 'charts' / '01_1_x.png').exists())
            self.assertEqual(package.set_aside(ws, ('01',)), [])   # nothing left to move
            from azinspect.core.quality import check_tree
            (r / package.ASIDE / '02_规格.md').write_text('# x' + chr(10) * 2 + '![a](charts/none.png)' + chr(10), encoding='utf-8')   # would fail the checks
            self.assertNotIn(f'{package.ASIDE}', ' '.join(check_tree(r)))


class ErrorWordingTests(unittest.TestCase):
    def test_api_errors_in_plain_chinese_with_the_original(self):
        # the coverage page showed "2 calls HTTP 400: FeatureNotSupportedForAccount: Blob is not supported for the account"
        from azinspect.waf.common import plain_error
        text = plain_error(400, 'FeatureNotSupportedForAccount: Blob is not supported for the account', 2)
        self.assertTrue(text.startswith('2 次读取：资源不支持这项功能，不适用这一检查'), text)
        self.assertIn('FeatureNotSupportedForAccount: Blob is not supported for the account', text)
        self.assertIn('接口限流', plain_error(429, 'HTTP 429', 1))
        self.assertIn('接口报错', plain_error(400, 'SomethingNew: odd', 1))
        self.assertNotIn('calls', plain_error(500, 'HTTP 500', 3))
        # calls recorded before 0.10.4 kept no error text: "None: None"
        self.assertEqual(plain_error(422, 'None: None', 1), '1 次读取：接口报错（HTTP 422）')


class ReadTimeFailedTests(unittest.TestCase):
    def test_failed_reads_do_not_stretch_the_span(self):
        # a failed query retried on resume stretched 区域和变化原因 to two days; the pricing split read that day was left out
        from azinspect.cost.report import read_times
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-10')
            ws.create()
            io.write_json(ws.raw('cost/queries/s1.curActual.json'), {'result': {'ok': True, 'pages': [{'queriedAt': '2026-11-01T10:00:00'}]}})
            io.write_json(ws.raw('cost/queries/s1.prevPricingModel.json'), {'result': {'ok': True, 'pages': [{'queriedAt': '2026-11-03T02:00:00'}]}})
            io.write_json(ws.raw('cost/supplement/queries/region.s1.json'), {'result': {'ok': True, 'pages': [{'queriedAt': '2026-11-01T11:00:00'}]}})
            io.write_json(ws.raw('cost/supplement/queries/pilot.s1.json'), {'result': {'ok': False, 'pages': []}, 'completedAt': '2026-11-03T02:20:00'})
            times = read_times(ws)
        self.assertEqual(times['supplement'], ('2026-11-01T11:00', '2026-11-01T11:00'))
        self.assertEqual(times['costs'], ('2026-11-01T10:00', '2026-11-03T02:00'))


class ReadTimeTests(unittest.TestCase):
    def test_times_come_from_the_saved_reads(self):
        # after collect --resume, 01 said the reused costs were queried "today" and the forecast re-read today "on 11-01"
        from azinspect.cost.report import read_times, read_time_text
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-10')
            ws.create()
            for name, at in (('s1.curActual', '2026-11-01T10:00:00+00:00'), ('s1.prevActual', '2026-11-01T11:30:00+00:00')):
                io.write_json(ws.raw(f'cost/queries/{name}.json'), {'result': {'pages': [{'queriedAt': at}]}})
            io.write_json(ws.raw('cost/supplement/queries/forecast.s1.next.json'), {'result': {'pages': [{'queriedAt': '2026-11-02T08:00:00+00:00'}]}})
            io.write_json(ws.raw('cost/supplement/queries/region.s1.json'), {'result': {'pages': [{'queriedAt': '2026-11-01T12:00:00+00:00'}]}})
            times = read_times(ws)
        self.assertEqual(times['costs'], ('2026-11-01T10:00', '2026-11-01T11:30'))
        self.assertEqual(times['forecast'], ('2026-11-02T08:00', '2026-11-02T08:00'))
        self.assertEqual(read_time_text(times['costs']), '2026 年 11 月 1 日 10:00 至 11:30')
        self.assertEqual(read_time_text(('2026-11-01T10:00', '2026-11-02T08:00')), '2026 年 11 月 1 日 10:00 至 11 月 2 日 08:00')
        self.assertEqual(read_time_text(times['forecast']), '2026 年 11 月 2 日 08:00')
        from azinspect.cost.report import read_line
        one = ('2026-11-01T10:00', '2026-11-01T10:05')
        self.assertIn('费用、区域、变化原因和预测读取于 2026 年 11 月 1 日 10:00 至 10:05', read_line({'costs': one, 'supplement': one, 'forecast': one}, '', '9月', '10月', '10月26日'))
        self.assertIn('预测读取于 2026 年 11 月 2 日 08:00', read_line(times, '', '9月', '10月', '10月26日'))


class CommitmentChargeTests(unittest.TestCase):
    def test_daily_change_without_purchases(self):
        # a month with a reservation bought read as everyday use going up
        from azinspect.cost.model import commitment_charges
        from azinspect.cost.report import without_commitments
        rows = {'prevPricingModel': [{'subscriptionId': 'a', 'pricingModel': 'OnDemand', 'cost': 3000.0}],
                'curPricingModel': [{'subscriptionId': 'a', 'pricingModel': 'OnDemand', 'cost': 2790.0},
                                    {'subscriptionId': 'a', 'pricingModel': 'Reservation', 'cost': 9000.0},
                                    {'subscriptionId': 'x', 'pricingModel': 'Reservation', 'cost': 500.0}]}   # not comparable
        cc = commitment_charges(rows, {'a'})
        self.assertEqual(cc, {'prev': 0.0, 'cur': 9000.0})
        totals = {'prev': 3000.0, 'cur': 11790.0}
        text = without_commitments(totals, cc, 30, 31)
        self.assertIn('不含预留和节省计划的购买费用', text)
        self.assertIn('-10.00%', text)       # 2790/31 vs 3000/30
        self.assertEqual(without_commitments(totals, {'prev': 0.0, 'cur': 100.0}, 30, 31), '')   # too small to matter
        self.assertEqual(without_commitments(totals, None, 30, 31), '')                          # no data (earlier collections)
        self.assertIsNone(commitment_charges({'curPricingModel': rows['curPricingModel']}, {'a'}))


class RegionNameTests(unittest.TestCase):
    def test_cost_locations_read_in_chinese(self):
        # 01's region table and chart showed Cost Management's location name ("eu west"); 03 had the Chinese name
        from azinspect.core.config import region_name
        self.assertEqual([region_name(x) for x in ('JA East', 'US East 2', 'AU East', 'EU West', 'IN Central', 'japaneast')],
                         ['日本东部', '美国东部 2', '澳大利亚东部', '西欧', '印度中部', '日本东部'])
        self.assertEqual(region_name('Unassigned'), 'Unassigned')

    def test_notice_text_spacing(self):
        # "AKS需要迁移或升级": a Latin product name runs into the Chinese that follows (Excel is not reformatted)
        from azinspect.waf.reliability.lifecycle import notice_text
        self.assertTrue(notice_text('Upgrade your AKS clusters', '2026-11-20').startswith('AKS 需要迁移或升级'))
        self.assertTrue(notice_text('Transition to the ContainerLogV2 table', '').startswith('容器日志（Container Insights）需要'))


if __name__ == '__main__':
    unittest.main()
