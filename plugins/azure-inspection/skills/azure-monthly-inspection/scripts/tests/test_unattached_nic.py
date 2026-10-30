"""Tests for network interfaces left without a VM (synthetic data): not counted as VM exposure in S-N2/S-N3; X5 covers the network checks."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
os.environ.setdefault('AZINSPECT_NO_EXCEL', '1')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect import crosscheck  # noqa: E402
from azinspect.core import io  # noqa: E402
from azinspect.waf.security_network.checks import Draft, check_nsg, check_public_ips  # noqa: E402
from azinspect.waf.security_network.network import Ctx, evaluate_exposures, public_paths  # noqa: E402

SUB = '00000000-0000-0000-0000-000000000001'
RG = f'/subscriptions/{SUB}/resourceGroups/net-rg/providers'
VNET = f'{RG}/Microsoft.Network/virtualNetworks/vnet-1'


class Cfg:
    def environment(self, *_):
        return 'prod', '订阅名'


def rid(kind, name):
    return f'{RG}/Microsoft.Network/{kind}/{name}'


def nic(name, subnet, pip, vm=None):
    props = {'ipConfigurations': [{'id': rid('networkInterfaces', name) + '/ipConfigurations/ipconfig1', 'properties': {
        'subnet': {'id': f'{VNET}/subnets/{subnet}'}, 'publicIPAddress': {'id': rid('publicIPAddresses', pip)},
        'privateIPAddress': '10.0.0.4' if subnet == 'left' else '10.0.1.4'}}]}
    if vm:
        props['virtualMachine'] = {'id': f'{RG}/Microsoft.Compute/virtualMachines/{vm}'}
    return {'id': rid('networkInterfaces', name), 'name': name, 'subscriptionId': SUB, 'resourceGroup': 'net-rg', 'properties': props}


def pip(name, ip, nic_name):
    return {'id': rid('publicIPAddresses', name), 'name': name, 'subscriptionId': SUB, 'resourceGroup': 'net-rg',
            'sku': {'name': 'Standard'}, 'properties': {'ipAddress': ip, 'ipConfiguration': {
                'id': rid('networkInterfaces', nic_name) + '/ipConfigurations/ipconfig1'}}}


def nsg(name, subnet):
    rule = {'name': 'allow-any', 'properties': {'direction': 'Inbound', 'access': 'Allow', 'priority': 100, 'protocol': '*',
                                                'sourceAddressPrefix': '*', 'destinationPortRange': '*', 'destinationAddressPrefix': '*'}}
    return {'id': rid('networkSecurityGroups', name), 'name': name, 'subscriptionId': SUB, 'resourceGroup': 'net-rg',
            'properties': {'securityRules': [rule], 'subnets': [{'id': f'{VNET}/subnets/{subnet}'}]}}


def run(with_vm):
    """Subnet `left` holds two NICs left behind by deleted VMs; with_vm adds a running VM in subnet `app` under its own open NSG."""
    subnets = [{'id': f'{VNET}/subnets/left', 'name': 'left', 'properties': {'networkSecurityGroup': {'id': rid('networkSecurityGroups', 'nsg-left')}}}]
    nics = [nic('nic-left-1', 'left', 'pip-left-1'), nic('nic-left-2', 'left', 'pip-left-2')]
    pips = [pip('pip-left-1', '20.0.0.1', 'nic-left-1'), pip('pip-left-2', '20.0.0.2', 'nic-left-2')]
    nsgs = [nsg('nsg-left', 'left')]
    vms = []
    if with_vm:
        subnets.append({'id': f'{VNET}/subnets/app', 'name': 'app', 'properties': {'networkSecurityGroup': {'id': rid('networkSecurityGroups', 'nsg-app')}}})
        nics.append(nic('nic-app-1', 'app', 'pip-app-1', vm='app-1'))
        pips.append(pip('pip-app-1', '20.0.0.3', 'nic-app-1'))
        nsgs.append(nsg('nsg-app', 'app'))
        vms.append({'id': f'{RG}/Microsoft.Compute/virtualMachines/app-1', 'name': 'app-1', 'properties': {'powerState': 'PowerState/running'}})
    rows = {'nsgs': nsgs, 'nics': nics, 'publicips': pips, 'vms': vms,
            'vnets': [{'id': VNET, 'name': 'vnet-1', 'subscriptionId': SUB, 'resourceGroup': 'net-rg', 'properties': {'subnets': subnets}}]}
    c = Ctx(lambda k: rows.get(k), {SUB: 'app_prod'})
    paths = public_paths(c)
    exposures = evaluate_exposures(c, paths)
    F = Draft(c, Cfg())
    _, mgmt_direct = check_nsg(c, F, exposures)
    check_public_ips(c, F, paths, exposures, mgmt_direct)
    return F.items


class UnattachedNicTests(unittest.TestCase):
    def test_nics_without_vm_are_a_latent_risk_not_exposure(self):
        items = run(with_vm=False)
        self.assertEqual([i for i in items if i['check'] == 'S-N3'], [])
        sn2 = [i for i in items if i['check'] == 'S-N2']
        self.assertEqual([(i['severity'], i['key']) for i in sn2], [('低', 'nsg-latent')])
        text = sn2[0]['finding']
        self.assertIn('nsg-left', text)
        self.assertIn('没有挂虚拟机', text)
        self.assertNotIn('实际可达', text)
        left = sn2[0]['evidence']['nsgs'][0]['unattachedNics']
        self.assertEqual(sorted(x['nic'] for x in left), ['nic-left-1', 'nic-left-2'])
        self.assertTrue(all(x['attachedToVm'] is False for x in left))

    def test_vm_nics_still_reported(self):
        items = run(with_vm=True)
        sn3 = [i for i in items if i['check'] == 'S-N3']
        self.assertEqual(len(sn3), 1)
        self.assertEqual(sn3[0]['severity'], '高')
        self.assertIn('1 个 VM 网卡', sn3[0]['finding'])
        self.assertEqual([m['name'] for m in sn3[0]['members']], ['app-1'])
        latent = [i for i in items if i['check'] == 'S-N2' and i['key'] == 'nsg-latent']
        self.assertEqual([n['nsg'] for n in latent[0]['evidence']['nsgs']], ['nsg-left'])

    def test_allowing_nsg_named_when_rule_opens_every_port(self):
        # an any-port rule is reported as S-N2 high, not as management ports only: S-N3 still names the NSG that lets SSH/RDP in
        sn3 = [i for i in run(with_vm=True) if i['check'] == 'S-N3'][0]
        self.assertIn('放行的 NSG：nsg-app。', sn3['finding'])
        self.assertEqual(sn3['evidence']['vmsWithDirectPublicIp'][0]['allowingNsgRules'], ['nsg-app/allow-any'])


class IdleVsExposedTests(unittest.TestCase):
    def test_x5_covers_network_findings(self):
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.raw('cost/review/results.json'), {'wasteFindings': [
                {'name': 'pip-old', 'subscriptionName': 'app_prod', 'category': '闲置公网 IP'},
                {'name': 'nsg-old', 'subscriptionName': 'app_prod', 'category': 'orphan:network-security-groups'}]})
            io.write_json(ws.month_dir('findings') / 'waf' / 'security_network.json', {'pillar': 'security_network', 'complete': True, 'findings': [
                {'id': 'S-N3-aaaaaa', 'check': 'S-N3', 'severity': '中', 'finding': '公网 IP pip-old 为 Basic SKU', 'resourceName': 'pip-old',
                 'members': [{'name': 'pip-old', 'type': 'Microsoft.Network/publicIPAddresses'}], 'evidence': {}},
                # an unused NSG is idle in 01 and a latent risk in 03: both say the same, not a conflict
                {'id': 'S-N2-bbbbbb', 'check': 'S-N2', 'severity': '低', 'finding': '潜在风险：nsg-old', 'resourceName': '1 个 NSG',
                 'members': [{'name': 'nsg-old', 'type': 'Microsoft.Network/networkSecurityGroups'}], 'evidence': {}},
                # a VM sharing its name with an idle public IP is a different resource
                {'id': 'S-N3-cccccc', 'check': 'S-N3', 'severity': '高', 'finding': 'VM 直连公网 IP', 'resourceName': '1 台 VM',
                 'members': [{'name': 'pip-old', 'type': 'Microsoft.Compute/virtualMachines'}], 'evidence': {}}]})
            x5 = {r['rule']: r for r in crosscheck.run(ws, log=lambda *_: None)['rules']}['X5']
            self.assertEqual(x5['status'], '需人工确认')
            self.assertEqual([i['resource'] for i in x5['items']], ['pip-old'])
            self.assertIn('清理', x5['items'][0]['suggestion'])


if __name__ == '__main__':
    unittest.main()
