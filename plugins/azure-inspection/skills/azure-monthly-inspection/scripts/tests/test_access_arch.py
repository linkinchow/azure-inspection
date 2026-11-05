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
    def test_lustre_hpc_component(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as directory:
            ws = io.Workspace(directory, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': SUB, 'name': 'hpc-prod', 'state': 'Enabled'}]})
            io.write_json(ws.raw('waf/operations/arg/resources.json'), {'rows': [
                {'id': '/lustre/fs', 'type': 'microsoft.storagecache/amlfilesystems', 'subscriptionId': SUB, 'location': 'japaneast'}]})
            text = '\n'.join(architecture.section(architecture.summary(ws, cfg), {}))
            self.assertIn('Azure Managed Lustre HPC 文件系统 1 个', text)

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



class LustreNetworkTests(unittest.TestCase):
    def test_network_analyzer_retains_inventory_and_unknown_coverage(self):
        from azinspect.waf.security_network.analyze import analyze
        from azinspect.waf.common import Raw
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as directory:
            ws = io.Workspace(directory, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': SUB, 'name': 'hpc-prod', 'state': 'Enabled'}]})
            result = analyze(ws, cfg, log=lambda *_: None)
            self.assertGreater(result['coverage']['S-N10']['otherErrors'], 0)
            raw = Raw(ws, 'security_network')
            raw.save('lustre/inventory.json', {'status': 403, 'rows': [], 'errors': [], 'error': 'Forbidden'})
            result = analyze(ws, cfg, log=lambda *_: None)
            self.assertEqual(result['coverage']['S-N10']['denied'], 1)
            row = {'id': f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs',
                   'name': 'fs', 'subscriptionId': SUB, 'resourceGroup': 'rg', 'sku': {'name': 'AMLFS-Durable-Premium-125', 'tier': 'Premium'},
                   'location': 'eastus', 'zones': ['1'], 'properties': {'storageCapacityTiB': 8, 'rootSquashSettings': {'mode': 'RootOnly'}}}
            raw.save('lustre/inventory.json', {'status': 200, 'rows': [row], 'errors': []})
            result = analyze(ws, cfg, log=lambda *_: None)
            self.assertEqual(result['inventory']['lustre']['rows'], [row])
            self.assertEqual(result['findings'], [])
            self.assertTrue(any('归属未检查' in note for note in result['coverage']['S-N1']['notes']))

    def test_filesystem_subnet_not_empty_and_internal_ssh_not_public(self):
        from azinspect.waf.security_network.checks import Draft, check_subnets, check_nsg
        from azinspect.waf.security_network.network import Ctx, evaluate_exposures, public_paths
        cfg = config.load(TEMPLATE)
        base = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network'
        subnet_id = base + '/virtualNetworks/hpc/subnets/lustre'
        filesystem = {'id': f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs',
                      'name': 'fs', 'properties': {'filesystemSubnet': subnet_id.upper()}}
        subnet = {'id': subnet_id, 'name': 'lustre', 'properties': {'addressPrefix': '10.0.0.0/24'}}
        vnet = {'id': base + '/virtualNetworks/hpc', 'name': 'hpc', 'subscriptionId': SUB, 'resourceGroup': 'rg',
                'properties': {'subnets': [subnet]}}
        data = {'vnets': [vnet]}
        context = Ctx(lambda key: data.get(key, []), {SUB: 'hpc-prod'})
        draft = Draft(context, cfg)
        inventory = check_subnets(context, draft, [filesystem])
        self.assertEqual(inventory[0]['owners']['lustre'], [filesystem['id']])
        self.assertEqual(len(draft.items), 1)
        self.assertNotIn('空子网', draft.items[0]['finding'])
        self.assertIn('不能判定公网可达', draft.items[0]['finding'])
        nsg = {'id': base + '/networkSecurityGroups/lustre', 'name': 'lustre', 'subscriptionId': SUB, 'resourceGroup': 'rg',
               'properties': {'securityRules': [{'name': 'required-ssh', 'properties': {'direction': 'Inbound', 'access': 'Allow',
                    'priority': 100, 'protocol': 'Tcp', 'sourceAddressPrefix': '10.0.0.0/24',
                    'destinationAddressPrefix': '10.0.0.0/24', 'destinationPortRange': '22'}}]}}
        subnet['properties']['networkSecurityGroup'] = {'id': nsg['id']}
        data['nsgs'] = [nsg]
        context = Ctx(lambda key: data.get(key, []), {SUB: 'hpc-prod'})
        draft = Draft(context, cfg)
        check_subnets(context, draft, [filesystem])
        check_nsg(context, draft, evaluate_exposures(context, public_paths(context)))
        self.assertEqual(draft.items, [])

    def test_root_squash_modes_missing_read_error_and_customer_cmk(self):
        from azinspect.waf.security_network.checks import Draft, check_lustre
        from azinspect.waf.security_network.network import Ctx
        from azinspect.waf.common import coverage_entry
        cfg = config.load(TEMPLATE)
        context = Ctx(lambda key: [], {SUB: 'hpc-prod'})
        rows = []
        for index, mode in enumerate(('None', 'RootOnly', 'All', None, 'None')):
            rows.append({'id': f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs{index}',
                         'name': f'fs{index}', 'subscriptionId': SUB, 'resourceGroup': 'rg',
                         'properties': {'rootSquashSettings': {'mode': mode}}})
        rows[-1]['_readError'] = 'HTTP 403'
        draft, coverage = Draft(context, cfg), coverage_entry()
        check_lustre(draft, {'rows': rows}, coverage)
        self.assertEqual(len(draft.items), 1)
        self.assertEqual(draft.items[0]['severity'], '低')
        self.assertTrue(draft.items[0]['needsConfirmation'])
        self.assertTrue(any('未检查' in note for note in coverage['notes']))
        self.assertTrue(any('403' in note for note in coverage['notes']))
        cfg.managed_lustre = {'requireCmk': True, 'requireRootSquash': True}
        draft, coverage = Draft(context, cfg), coverage_entry()
        check_lustre(draft, {'rows': rows[:1]}, coverage)
        self.assertEqual(len(draft.items), 1)
        self.assertEqual(draft.items[0]['severity'], '中')
        self.assertTrue(any('CMK' in note for note in coverage['notes']))
        rows[0]['properties']['encryptionSettings'] = {'keyEncryptionKey': None}
        draft = Draft(context, cfg)
        check_lustre(draft, {'rows': rows[:1]}, coverage)
        self.assertEqual(len(draft.items), 2)
        rows[0]['properties']['encryptionSettings'] = {'keyEncryptionKey': {'keyUrl': 'https://example.vault.azure.net/keys/lustre/version'}}
        draft = Draft(context, cfg)
        check_lustre(draft, {'rows': rows[:1]}, coverage)
        self.assertEqual(len(draft.items), 1)


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
