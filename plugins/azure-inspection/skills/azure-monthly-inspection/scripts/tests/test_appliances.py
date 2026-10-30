"""Tests for network appliances (firewalls, packet brokers): recognised from image publisher, plan or OS name (synthetic data)."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.core import appliance  # noqa: E402

VM = 'Microsoft.Compute/virtualMachines'


def vm(name, publisher=None, plan=None, os_name=None, scale_set=False):
    ref = {'publisher': publisher, 'offer': 'x', 'sku': 'y'} if publisher else {'id': '/subscriptions/s/galleries/g/images/custom'}
    storage = {'imageReference': ref}
    props = {'virtualMachineProfile': {'storageProfile': storage}} if scale_set else {'storageProfile': storage}
    if os_name:
        props['extended'] = {'instanceView': {'osName': os_name, 'osVersion': '7.4'}}
    return {'id': f'/subscriptions/s/resourceGroups/rg/providers/{VM}/{name}', 'name': name, 'properties': props,
            'plan': {'publisher': plan, 'product': 'p', 'name': 'n'} if plan else None}


class RecogniseTests(unittest.TestCase):
    def test_signals(self):
        self.assertEqual(appliance.of(vm('fw-1', publisher='paloaltonetworks')), '镜像发布者 paloaltonetworks')
        self.assertEqual(appliance.of(vm('probe-1', plan='gigamon-inc')), '购买计划发布者 gigamon-inc')
        self.assertEqual(appliance.of(vm('fw-2', os_name='PAN-OS')), '系统 PAN-OS')
        self.assertEqual(appliance.of(vm('nva-pool', publisher='paloaltonetworks', scale_set=True)), '镜像发布者 paloaltonetworks')
        self.assertIsNone(appliance.of(vm('app-1', publisher='Canonical', os_name='ubuntu')))
        flat = {'name': 'fw-3', 'imageReference': {'publisher': 'checkpoint'}, 'osName': None, 'plan': None}
        self.assertEqual(appliance.of(flat), '镜像发布者 checkpoint')
        self.assertEqual(appliance.of({'name': 'fw-4', 'osName': 'PAN-OS'}), '系统 PAN-OS')

    def test_customer_name_rule_only(self):
        rule = re.compile('^edge-fw', re.I)
        self.assertEqual(appliance.of(vm('edge-fw-01'), rule), '名称规则（customer.yaml）')
        self.assertIsNone(appliance.of(vm('app-firewall-test')))          # no built-in name keywords
        self.assertIsNone(appliance.of(vm('app-01'), rule))


    def test_rule_from_customer_yaml(self):
        import tempfile
        from azinspect.core import config
        template = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'
        self.assertIsNone(config.load(template).appliance_names())
        text = template.read_text(encoding='utf-8')
        line = next(x for x in text.splitlines() if 'networkAppliances' in x and x.strip().startswith('#'))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'customer.yaml'
            p.write_text(text.replace(line, line.replace('# ', '', 1)), encoding='utf-8')
            names = config.load(p).appliance_names()
        self.assertEqual(appliance.of(vm('fgt-edge-01'), names), '名称规则（customer.yaml）')


if __name__ == '__main__':
    unittest.main()


import importlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import tempfile  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from azinspect.core import config, io  # noqa: E402
from azinspect.waf import common  # noqa: E402

TEMPLATE = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'
FW, APP = vm('fw-1', publisher='paloaltonetworks', os_name='PAN-OS'), vm('app-1', publisher='Canonical', os_name='ubuntu')


class ChecksTests(unittest.TestCase):
    def test_p1_memory_not_judged(self):
        perf = importlib.import_module('azinspect.waf.performance.analyze')
        a = perf.Analyzer.__new__(perf.Analyzer)
        found = []
        a.days, a.window, a.inv = 30, {'start': '2026-09-01T00:00:00Z', 'end': '2026-10-01T00:00:00Z'}, {}
        a.cov = {f'P{i}': {'notes': []} for i in range(1, 11)}
        a.appliances = {FW['id'].lower(): '系统 PAN-OS'}
        a.add = lambda check, sev, rid, rtype, name, *rest, **k: found.append((check, name))
        a.month_vm_usage, a.env_of = lambda: {}, lambda *x, **k: {'value': 'prod', 'label': '生产', 'basis': ''}
        metrics = {'Percentage CPU': {'avg': 3.0, 'maxDailyMax': 6.0, 'daysMaxGE': 0, 'days': 30},
                   'Available Memory Percentage': {'avg': 0.0, 'days': 30}}
        a.metric = lambda label, rid, m, *th: metrics.get(m, {'error': 'not queried'})
        a.data = SimpleNamespace(rows=lambda n: [dict(FW, power='PowerState/running', vmSize='Standard_F4s_v2', location='eastus'),
                                                 dict(APP, power='PowerState/running', vmSize='Standard_D4s_v5', location='eastus')],
                                 subname=lambda rid: 'app-prod', series=lambda *x: ([], None), daily=lambda s: [])
        a.p1_p4_vms()
        self.assertEqual(found, [('P1', 'app-1')])                   # the ordinary VM with the same reading is reported
        self.assertTrue(any('1 台网络设备只判断 CPU' in n and 'fw-1' in n for n in a.cov['P1']['notes']))

    def test_ip_forwarding_not_reported_for_appliances(self):
        aprl = importlib.import_module('azinspect.waf.aprl')
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': 's', 'name': 'app-prod', 'state': 'Enabled'}]})
            io.write_json(ws.raw('waf/reliability/arg/vms.json'), {'status': 200, 'rows': [FW, APP]})
            io.write_json(ws.raw('waf/aprl/results.json'), {'results': [{'aprlGuid': '41a22a5e-5e08-9647-92d0-2ffe9ef1bdad', 'status': 200,
                                                                         'rows': [{'id': FW['id'], 'name': 'fw-1'}, {'id': FW['id'], 'name': 'fw-1'},
                                                                                  {'id': APP['id'], 'name': 'app-1'}]}]})
            out = aprl.analyze(ws, config.load(TEMPLATE), log=lambda *_: None)
        sn9 = [f for f in out['findings'] if f['check'] == 'S-N9']
        self.assertEqual([m['name'] for f in sn9 for m in f['members']], ['app-1'])
        self.assertIn('自建 Kubernetes 节点', sn9[0]['recommendation'])
        self.assertTrue(any('1 台网络设备' in n for n in out['coverage']['S-N9']['notes']))    # one VM with two NICs

    def test_ssh_password_finding_for_appliances(self):
        checks = importlib.import_module('azinspect.waf.security_identity.checks_resources')
        added = []
        row = lambda v, pw: {'id': v['id'], 'name': v['name'], 'resourceGroup': 'rg', 'subscriptionId': 's', 'osType': 'Linux',  # noqa: E731
                             'disablePasswordAuthentication': pw, 'powerState': 'PowerState/running', 'tags': {}}
        rel_files = {'arg/vms.json': {'rows': [FW, APP]}}
        ctx = SimpleNamespace(rows=lambda n: [row(FW, False), row(APP, False)] if n == 'vms' else [], cfg=None,
                              raw=SimpleNamespace(load=lambda name: None, other=lambda p: SimpleNamespace(load=rel_files.get)),
                              name_of=lambda sid: 'app-prod', env=lambda *a, **k: {'value': 'prod', 'label': '生产', 'basis': ''},
                              sub_env=lambda n: {'value': 'prod', 'label': '生产', 'basis': ''},
                              add=lambda *a, **k: added.append(k), inventory={}, notes={'S-I8': []})
        checks.vms(ctx)
        device = next(f for f in added if f.get('key') == 'appliance-admin-login')
        self.assertIn('fw-1', device['finding'])
        self.assertIn('管理口', device['recommendation'])
        private = next(f for f in added if f.get('key') == 'ssh-password-private')
        self.assertEqual([m['name'] for m in private['members']], ['app-1'])

    def test_os_end_of_support_not_judged(self):
        from azinspect.waf.reliability import lifecycle
        run = SimpleNamespace(rows=lambda n: [FW] if n == 'vms' else [], raw=SimpleNamespace(load=lambda n: None),
                              now=__import__('datetime').datetime(2026, 10, 30, tzinfo=__import__('datetime').timezone.utc),
                              coverage={'R9': common.coverage_entry()}, findings=SimpleNamespace(items=[]), add=lambda *a, **k: None,
                              subname=lambda x: 'app-prod', env=lambda *a, **k: {}, cfg=None)
        inv = {}
        lifecycle.check(run, inv, lambda *a: {})
        self.assertEqual(inv['lifecycle']['notJudged'], [{'name': 'fw-1', 'type': lifecycle.VM_TYPE, 'reason': '网络设备'}])
        self.assertTrue(any('是网络设备' in x for x in run.coverage['R9']['limits']))

    def test_02_marks_appliances(self):
        from azinspect.vm import scalesets, wording
        vmss = {'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/probes',
                'type': 'Microsoft.Compute/virtualMachineScaleSets', 'name': 'probes', 'plan': {'publisher': 'gigamon-inc'}, 'properties': {}}
        resources = [dict(FW, type=VM), dict(APP, type=VM), vmss]
        vms = [{'id': FW['id'], 'kind': 'vm'}, {'id': APP['id'], 'kind': 'vm'}, {'id': vmss['id'] + '/virtualMachines/0', 'kind': 'vmss',
                                                                                 'metricResourceId': vmss['id']}]
        self.assertEqual(scalesets.mark_appliances(vms, resources), 2)
        self.assertEqual([v.get('appliance') for v in vms], ['镜像发布者 paloaltonetworks', None, '购买计划发布者 gigamon-inc'])
        self.assertEqual(wording.STATUS['保持现状：网络设备'], '网络设备：不建议调整规格')


class RightsizingNoteTests(unittest.TestCase):
    """04 states 02's advice for the same machine, so the two reports do not read as contradicting each other."""

    def test_p1_and_p4_mention_02(self):
        perf = importlib.import_module('azinspect.waf.performance.analyze')
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.month_dir('findings') / 'vm' / 'recommendations.json', [
                {'name': 'db-1', 'status': '建议试点调整', 'currentSKU': 'Standard_E8s_v5', 'targetSKU': 'Standard_E4s_v5',
                 'candidate': {'direction': '只减CPU，内存保留'}},
                {'name': 'web-1', 'status': '保持现状：平均利用率不低', 'currentSKU': 'Standard_D4s_v5'}])
            a = perf.Analyzer.__new__(perf.Analyzer)
            a.ws, a.F = ws, common.Findings('performance')
            a.F.add('P1', '高', '虚拟机 db-1 过去 30 天平均内存使用 92.0%，长期接近上限。', 'r', resource_name='db-1')
            a.F.add('P4', '高', '3 台虚拟机的磁盘/虚拟机 IO 上限频繁被打满。', 'r', resource_name='3 台虚拟机',
                    members=[{'name': n} for n in ('db-1', 'web-1', 'app-9')])
            a.F.add('P1', '中', '虚拟机 web-1 CPU 平均 10%。', 'r', resource_name='web-1')
            a.annotate_rightsizing()
        p1, p4, other = a.F.items
        self.assertIn('02 建议该机CPU核数减半，内存容量不变（Standard_E8s_v5 → Standard_E4s_v5），调整前一并考虑本项。', p1['finding'])
        self.assertIn('其中 1 台在 02 被建议降配（db-1）', p4['finding'])
        self.assertNotIn('02', other['finding'])
        self.assertEqual(p1['evidence']['rightsizing02'][0]['name'], 'db-1')
