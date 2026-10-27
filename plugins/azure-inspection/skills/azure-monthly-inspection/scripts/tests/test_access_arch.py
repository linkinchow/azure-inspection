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



class SshExposureTests(unittest.TestCase):
    def test_password_finding_states_port_22_result(self):
        from azinspect.waf.pipeline import SSH_PENDING, resolve_ssh_exposure
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            fdir = ws.month_dir('findings') / 'waf'
            io.write_json(fdir / 'security_network.json', {'findings': [{'check': 'S-N3', 'evidence': {'vmsWithDirectPublicIp': [
                {'endpoint': 'VM ops-01', 'internetReachableMgmtPorts': []}, {'endpoint': 'VM ops-02', 'internetReachableMgmtPorts': [22]}]}}]})
            io.write_json(fdir / 'security_identity.json', {'findings': [{'check': 'S-I8', 'finding': '有被暴力破解的风险' + SSH_PENDING,
                'evidence': {'vms': [{'name': 'ops-01'}, {'name': 'ops-02'}, {'name': 'ops-03'}]}}]})
            resolve_ssh_exposure(ws, log=lambda *_: None)
            text = io.read_json(fdir / 'security_identity.json')['findings'][0]['finding']
        self.assertIn('ops-02 的 22 端口对公网开放', text)
        self.assertIn('按当前 NSG，ops-01 的 22 端口没有对公网开放', text)
        self.assertIn('ops-03 的 22 端口是否对公网开放未能核对', text)
        self.assertNotIn('以网络检查结果为准', text)


if __name__ == '__main__':
    unittest.main()
