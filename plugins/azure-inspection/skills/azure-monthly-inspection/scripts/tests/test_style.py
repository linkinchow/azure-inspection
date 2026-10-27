"""Tests for the writing checks: hedging, repeated confirmation clauses, named resources, hand edits (synthetic data, no network)."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
os.environ.setdefault('AZINSPECT_NO_EXCEL', '1')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect import package  # noqa: E402
from azinspect.core import config, io  # noqa: E402
from azinspect.core.period import ReportPeriod  # noqa: E402
from azinspect.core.quality import check_markdown, check_narratives  # noqa: E402

TEMPLATE = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'


def md(d, text):
    path = Path(d) / '03_报告.md'
    path.write_text(text, encoding='utf-8')
    return path


class StyleTests(unittest.TestCase):
    def test_plain_report_passes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(check_markdown(md(d, '# 报告\n\n为 pg-order-prod 开启存储自动增长，可在线修改。\n')), [])

    def test_repeated_confirmation_and_hedging(self):
        text = '# 报告\n\n' + '收紧入口，需客户确认后执行。' * 3 + '这不等于已经暴露，不能据此断言风险，尚不能确认。不代表没有问题，不能把它当作结论。\n'
        with tempfile.TemporaryDirectory() as d:
            issues = '\n'.join(check_markdown(md(d, text)))
        self.assertIn('出现 3 次', issues)
        self.assertIn('否定和保留说法太多', issues)

    def test_process_words(self):
        with tempfile.TemporaryDirectory() as d:
            issues = check_markdown(md(d, '# 报告\n\n跨报告复核后，命中检查的实例需要处理。\n'))
        self.assertTrue(any('跨报告' in x for x in issues) and any('命中' in x for x in issues))

    def test_top_issues_name_resources(self):
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.month_dir('findings') / 'waf' / 'reliability.json', {'findings': [
                {'id': 'R13-aaaaaa', 'resourceName': '2 个资源', 'subscriptionName': 'app-prod',
                 'members': [{'name': 'pg-order-prod'}, {'name': 'pg-user-prod'}]}]})
            io.write_json(ws.month_dir('narrative') / '03.json', {'topIssues': [
                {'title': '为 PostgreSQL 开启自动增长', 'detail': '命中检查的实例应先确认容量。', 'findingIds': ['R13-aaaaaa']},
                {'title': '为 pg-order-prod 开启自动增长', 'detail': '', 'findingIds': ['R13-aaaaaa']}]})
            issues = check_narratives(ws.month_dir())
        self.assertEqual(len(issues), 1)
        self.assertIn('第 1 条', issues[0])

    def test_summary_conclusion_and_impact_column(self):
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.month_dir('findings') / 'waf' / 'reliability.json', {'findings': [
                {'id': 'R13-aaaaaa', 'severity': '高', 'resourceName': 'pg-order-prod', 'subscriptionName': 'app-prod'}]})
            io.write_json(ws.month_dir('narrative') / '00.json', {'conclusion': ['优先保障数据库可写，再推进规格优化。']})
            io.write_json(ws.month_dir('narrative') / '03.json', {'topIssues': [
                {'title': 'pg-order-prod 关闭自动增长', 'impact': '写满后只读', 'findingIds': ['R13-aaaaaa']},
                {'title': 'pg-order-prod 没有维护窗口', 'findingIds': ['R13-aaaaaa']}]})
            text = ' / '.join(check_narratives(ws.month_dir()))
            self.assertIn('00 结论没有写金额', text)
            self.assertIn('00 结论没有点名', text)
            self.assertIn('03 第 2 条缺少“影响”', text)
            io.write_json(ws.month_dir('narrative') / '00.json', {'conclusion': ['pg-order-prod 关闭了自动增长；9 月费用增加 USD 100。']})
            self.assertNotIn('00 结论', ' / '.join(check_narratives(ws.month_dir())))


class HandEditTests(unittest.TestCase):
    def test_package_refuses_edited_report(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            reports = ws.month_dir('reports')
            report = reports / '03_可靠性与安全巡检报告.md'
            report.write_text('# 报告\n\n为 pg-order-prod 开启存储自动增长。\n', encoding='utf-8')
            package.record_build(ws, report.stat().st_mtime)
            io.write_json(ws.month_dir('findings') / 'crosscheck.json', {'rules': []})
            report.write_text('# 报告\n\n手工改过的内容。\n', encoding='utf-8')
            with self.assertRaises(SystemExit):
                package.build(ws, cfg, ReportPeriod.build('2026-09'), log=lambda *_: None)


if __name__ == '__main__':
    unittest.main()
