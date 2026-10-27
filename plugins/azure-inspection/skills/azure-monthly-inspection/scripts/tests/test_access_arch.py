"""Tests for the write-role check, default region names and the 03 architecture overview (synthetic data, no network)."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
os.environ.setdefault('AZINSPECT_NO_EXCEL', '1')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.cli import _writes  # noqa: E402
from azinspect.core import config, io  # noqa: E402
from azinspect.waf import architecture  # noqa: E402

TEMPLATE = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'
SUB = '00000000-0000-0000-0000-0000000000a1'


class WriteRoleTests(unittest.TestCase):
    def test_read_only_roles(self):
        self.assertFalse(_writes([{'actions': ['*/read']}]))
        self.assertFalse(_writes([{'actions': ['*/read', 'Microsoft.Support/*', 'Microsoft.OperationalInsights/workspaces/search/action']}]))

    def test_write_roles(self):
        self.assertTrue(_writes([{'actions': ['*']}]))
        self.assertTrue(_writes([{'actions': ['Microsoft.Compute/*']}]))
        self.assertTrue(_writes([{'actions': ['Microsoft.Storage/storageAccounts/write']}]))


class RegionTests(unittest.TestCase):
    def test_default_and_override(self):
        cfg = config.load(TEMPLATE)
        self.assertEqual(cfg.region('JapanEast'), '日本东部')
        self.assertEqual(cfg.region('somewhere'), 'somewhere')
        cfg.region_labels['japaneast'] = '东京'
        self.assertEqual(cfg.region('japaneast'), '东京')


class ArchitectureTests(unittest.TestCase):
    def test_section_from_inventory(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': SUB, 'name': 'app-prod', 'state': 'Enabled'}]})
            rows = [{'id': f'/x/{i}', 'type': t, 'subscriptionId': SUB, 'location': 'japaneast'} for i, t in enumerate(
                ['microsoft.containerservice/managedclusters', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines',
                 'microsoft.network/virtualnetworks', 'microsoft.network/privateendpoints'])]
            io.write_json(ws.raw('waf/operations/arg/resources.json'), {'rows': rows, 'error': None})
            arch = architecture.summary(ws, cfg)
            lines = architecture.section(arch, {'architecture': '业务运行在 AKS 上。'})
            text = '\n'.join(lines)
            self.assertIn('|app-prod|5|日本东部|AKS 集群 1 个、虚拟机 2 个|', text)
            self.assertIn('虚拟网络 1 个', text)
            self.assertIn('Azure 中没有专线', text)
            self.assertTrue(text.endswith('业务运行在 AKS 上。'))
            self.assertEqual(architecture.section(None, {}), [])


if __name__ == '__main__':
    unittest.main()
