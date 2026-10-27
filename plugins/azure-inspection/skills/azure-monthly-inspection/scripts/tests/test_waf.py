"""Tests for the shared WAF finding format and the 03/04 report builder (synthetic data, no network)."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
os.environ.setdefault('AZINSPECT_NO_EXCEL', '1')  # structural formula check only; Excel recalculation is slow
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.core import config, io  # noqa: E402
from azinspect.waf import common, report  # noqa: E402

TEMPLATE = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'


def workspace(d):
    ws = io.Workspace(d, '2026-09')
    ws.create()
    io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [
        {'id': f'{i:08d}-0000-0000-0000-000000000000', 'name': f'app_{i}_prod', 'state': 'Enabled'} for i in range(3)]
        + [{'id': f'{i:08d}-0000-0000-0000-000000000001', 'name': f'lab-old{i}', 'state': 'Disabled'} for i in range(5)]})
    return ws


def sample(ws, cfg):
    f = common.Findings('reliability')
    e = common.env(cfg, 'app_1_prod', 'aks-app')
    f.add('R1', '高', '子网只剩 10 个 IP', '换用更大的子网', subscription='app_1_prod', resource_name='vnet/aks-subnet',
          resource_type='Microsoft.Network/virtualNetworks/subnets', environment=e, legacy_id='REL-001')
    f.add('R7', '中', '3 台虚拟机没有备份', '配置备份', subscription='app_1_prod', resource_name='3 台虚拟机', environment=e,
          members=[{'name': f'vm{i}', 'type': 'Microsoft.Compute/virtualMachines', 'subscription': 'app_1_prod'} for i in range(3)],
          needs_confirmation='确认哪些机器有数据')
    f.add('R7', '低', '测试机没有备份', '按需配置', subscription='app_2_prod', resource_name='vm0',
          resource_type='Microsoft.Compute/virtualMachines', environment=e)
    f.write(ws, window=common.window(), coverage={'R1': common.coverage_entry()}, scope={})
    return f


class FindingTests(unittest.TestCase):
    def test_ids_are_stable_and_unique(self):
        a, b = common.Findings('reliability'), common.Findings('reliability')
        x = a.add('R1', '高', 'f', 'r', subscription='S', resource_name='n')
        y = a.add('R1', '高', 'f', 'r', subscription='S', resource_name='n')
        z = b.add('R1', '中', 'other text', 'r', subscription='s', resource_name='N')
        self.assertNotEqual(x['id'], y['id'])
        self.assertEqual(x['id'], z['id'])
        self.assertTrue(x['id'].startswith('R1-'))

    def test_env_uses_customer_rules(self):
        cfg = config.load(TEMPLATE)
        self.assertEqual(common.env(cfg, 'region_app', 'redis-app-test01')['value'], 'test')
        self.assertEqual(common.env_text(common.env(cfg, 'region_app_prod', 'x')), '生产（推断：订阅名称）')


class ReportTests(unittest.TestCase):
    def test_build_counts_resources_and_scope(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as d:
            ws = workspace(d)
            sample(ws, cfg)
            meta = report.build(ws, cfg, '03', {}, log=lambda *_: None)
            self.assertEqual(meta['total'], 3)
            self.assertEqual(meta['pendingConfirmation'], 1)
            md = (ws.month_dir('reports') / '03_可靠性与安全巡检报告.md').read_text(encoding='utf-8')
            self.assertIn('共发现 **3** 项问题', md)
            self.assertIn('4 台虚拟机', md)
            self.assertIn('lab-old*', md)
            report.audit(ws, cfg, '03', log=lambda *_: None)

    def test_narrative_overrides_and_validation(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as d:
            ws = workspace(d)
            sample(ws, cfg)
            narrative = {'severityOverrides': [{'findingId': 'REL-001', 'severity': '中', 'reason': '已确认有备用子网'}],
                         'topIssues': [{'title': '子网不足', 'detail': 'd', 'impact': 'i', 'recommendation': {'rootCause': 'a', 'fix': 'b'},
                                        'findingIds': ['REL-001']}]}
            meta = report.build(ws, cfg, '03', narrative, log=lambda *_: None)
            self.assertEqual(meta['bySeverity'].get('高', 0), 0)
            md = (ws.month_dir('reports') / '03_可靠性与安全巡检报告.md').read_text(encoding='utf-8')
            self.assertIn('**根本原因**：a', md)
            self.assertNotIn('## 3. 安全', md)
            with self.assertRaises(report.NarrativeError):
                report.build(ws, cfg, '03', {'topIssues': [{'title': 'x', 'findingIds': ['R9-000000']}]}, log=lambda *_: None)
            with self.assertRaises(report.NarrativeError):
                report.build(ws, cfg, '03', {'severityOverrides': [{'findingId': 'REL-001', 'severity': '低'}]}, log=lambda *_: None)


if __name__ == '__main__':
    unittest.main()
