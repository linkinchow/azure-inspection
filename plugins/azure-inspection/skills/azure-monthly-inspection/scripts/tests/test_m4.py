"""Tests for crosscheck and package (synthetic data, no network)."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
os.environ.setdefault('AZINSPECT_NO_EXCEL', '1')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect import crosscheck, package, tracking  # noqa: E402
from azinspect.core import config, io  # noqa: E402
from azinspect.core.period import ReportPeriod  # noqa: E402

TEMPLATE = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'
POOL = '/subscriptions/x/resourcegroups/mc_rg_aks-app_region/providers/microsoft.compute/virtualmachinescalesets/aks-big-123-vmss'


def workspace(d):
    ws = io.Workspace(d, '2026-09')
    ws.create()
    f = ws.month_dir('findings')
    io.write_json(f / 'vm' / 'recommendations.json', [
        {'name': 'vm-a', 'subscriptionName': 'app_prod', 'status': '建议试点调整', 'currentSKU': 'D8', 'targetSKU': 'D4', 'pool': None},
        {'name': 'aks-big-123-vmss_0', 'subscriptionName': 'app_prod', 'status': '建议试点调整', 'currentSKU': 'D4', 'targetSKU': 'E2', 'pool': POOL}])
    perf = [{'id': 'P1-aaaaaa', 'check': 'P1', 'severity': '高', 'finding': 'CPU 打满', 'members': [{'name': 'vm-a'}], 'evidence': {}},
            {'id': 'P2-bbbbbb', 'check': 'P2', 'severity': '高', 'finding': '内存超出', 'subscriptionName': 'app_prod', 'members': [],
             'evidence': {'items': [{'cluster': 'aks-app', 'pool': 'big', 'subscriptionName': 'app_prod'}]}}]
    io.write_json(f / 'waf' / 'performance.json', {'pillar': 'performance', 'findings': perf, 'complete': True})
    return ws


class CrosscheckTests(unittest.TestCase):
    def test_conflicts_found_then_marked_handled(self):
        with tempfile.TemporaryDirectory() as d:
            ws = workspace(d)
            rules = {r['rule']: r for r in crosscheck.run(ws, log=lambda *_: None)['rules']}
            self.assertEqual(rules['X1']['status'], '需要处理')
            self.assertEqual(rules['X3']['status'], '需要处理')
            io.write_json(ws.month_dir('narrative') / '02.json', {'crossCheckNotes': [
                {'subscription': 'app_prod', 'namePrefix': 'vm-a', 'note': 'x'},
                {'subscription': 'app_prod', 'namePrefix': 'aks-big-123-vmss', 'note': 'y'}]})
            rules = {r['rule']: r for r in crosscheck.run(ws, log=lambda *_: None)['rules']}
            self.assertEqual(rules['X1']['status'], '已处理')
            self.assertEqual(rules['X3']['status'], '已处理')


class PackageTests(unittest.TestCase):
    def test_package_blocks_open_rules_and_verifies_zip(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as d:
            ws = workspace(d)
            reports = ws.month_dir('reports')
            (reports / 'charts').mkdir(parents=True, exist_ok=True)
            (reports / 'charts' / '03_1_x.png').write_bytes(b'png')
            (reports / '03_可靠性与安全巡检报告.md').write_text('# 报告\n\n![图](charts/03_1_x.png)\n', encoding='utf-8')
            (reports / '~$锁文件.xlsx').write_bytes(b'lock')
            period = ReportPeriod.build('2026-09')
            io.write_json(ws.month_dir('findings') / 'crosscheck.json', {'rules': [{'rule': 'X1', 'status': '需要处理'}]})
            with self.assertRaises(SystemExit):
                package.build(ws, cfg, period, log=lambda *_: None)
            manifest = package.build(ws, cfg, period, allow_open=True, log=lambda *_: None)
            names = [f['name'] for f in manifest['files']]
            self.assertEqual(sorted(names), ['03_可靠性与安全巡检报告.md', 'charts/03_1_x.png'])
            with zipfile.ZipFile(manifest['zip']) as z:
                self.assertIsNone(z.testzip())


class TrackingTests(unittest.TestCase):
    def month(self, root, month, findings, coverage):
        ws = io.Workspace(root, month)
        ws.create()
        io.write_json(ws.month_dir('findings') / 'waf' / 'reliability.json',
                      {'pillar': 'reliability', 'findings': findings, 'coverage': coverage, 'complete': True})
        return ws

    def test_statuses(self):
        f = lambda fid, check, sev='中': {'id': fid, 'check': check, 'severity': sev, 'finding': 'x', 'resourceName': fid}
        ok = {'attempted': 1, 'succeeded': 1}
        with tempfile.TemporaryDirectory() as d:
            first = tracking.update(self.month(d, '2026-08', [f('R1-a', 'R1'), f('R2-b', 'R2'), f('R3-c', 'R3')],
                                               {'R1': ok, 'R2': ok, 'R3': ok}), log=lambda *_: None)
            self.assertTrue(first['first'])
            ws = self.month(d, '2026-09', [f('R1-a', 'R1', '高'), f('R1-n', 'R1'), f('R13-x', 'R13')],
                            {'R1': ok, 'R2': ok, 'R3': {'attempted': 1, 'succeeded': 0, 'denied': 1}, 'R13': ok})
            rows = {r['id']: r for r in tracking.update(ws, log=lambda *_: None)['rows']}
            self.assertEqual(rows['R1-a']['status'], '仍未处理')
            self.assertEqual(rows['R1-a']['previousSeverity'], '中')
            self.assertEqual(rows['R1-n']['status'], '新增问题')
            self.assertEqual(rows['R13-x']['status'], '新增检查项发现')
            self.assertEqual(rows['R2-b']['status'], '已解决')
            self.assertEqual(rows['R3-c']['status'], '本月未检查')


if __name__ == '__main__':
    unittest.main()
