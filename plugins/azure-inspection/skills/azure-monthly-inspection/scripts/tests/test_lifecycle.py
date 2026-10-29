"""Tests for R9 version end of support and service retirements (synthetic data and calendar, no network)."""
from __future__ import annotations

import base64
import importlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.waf import common  # noqa: E402
from azinspect.waf.reliability import lifecycle  # noqa: E402

# the pillar package exports functions named collect and analyze, which hide the modules of the same name
rel_analyze = importlib.import_module('azinspect.waf.reliability.analyze')
rel_collect = importlib.import_module('azinspect.waf.reliability.collect')
NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)
CALENDAR = {'reviewedAt': '2026-10-30', 'entries': [
    {'product': 'mysql', 'version': '5.7', 'label': 'MySQL 5.7', 'end': '2026-09-30', 'extendedEnd': '2029-03-31', 'extendedPaid': True, 'source': 'x'},
    {'product': 'postgres', 'version': '16', 'label': 'PostgreSQL 16', 'end': '2028-11-09', 'source': 'x'},
    {'product': 'postgres', 'version': '14', 'label': 'PostgreSQL 14', 'end': '2027-01-31', 'extendedEnd': '2029-11-11', 'extendedPaid': True, 'source': 'x'},
    {'product': 'os-centos', 'version': '7', 'label': 'CentOS 7', 'end': '2024-06-30', 'source': 'x'},
    {'product': 'os-ubuntu', 'version': '20.04', 'label': 'Ubuntu 20.04', 'end': '2025-05-31', 'extendedEnd': '2030-04-30', 'extendedPaid': True, 'source': 'x'},
    {'product': 'os-windows-server', 'version': '2012 R2', 'label': 'Windows Server 2012 R2', 'end': '2023-10-10', 'extendedEnd': '2026-10-13', 'source': 'x'},
    {'product': 'os-windows-server', 'version': '2016', 'label': 'Windows Server 2016', 'end': '2027-01-12', 'source': 'x'},
    {'product': 'os-windows-server', 'version': '2012', 'label': 'Windows Server 2012', 'end': '2023-10-10', 'extendedEnd': '2027-10-13', 'source': 'x'},
    {'product': 'runtime-python', 'version': '3.10', 'label': 'Python 3.10', 'end': '2026-10-31', 'source': 'x'},
    {'product': 'redis-tier', 'version': 'basic-standard-premium', 'label': 'Azure Cache for Redis（基本/标准/高级层）', 'end': '2028-09-30', 'source': 'x'}]}


def rid(sub, provider, name):
    return f'/subscriptions/{sub}/resourceGroups/rg/providers/{provider}/{name}'


def certificate(days):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'www.contoso.com')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(NOW - timedelta(days=300)).not_valid_after(NOW + timedelta(days=days)).sign(key, hashes.SHA256()))
    return cert, pkcs7.serialize_certificates([cert], serialization.Encoding.DER)


class KeyTests(unittest.TestCase):
    def test_grade(self):
        self.assertEqual([lifecycle.grade(NOW + timedelta(days=d), NOW) for d in (-1, 100, 300, 400)], ['高', '中', '低', None])

    def test_engine_versions(self):
        self.assertEqual((lifecycle.mysql_key('8.0.21'), lifecycle.mysql_key('5.7'), lifecycle.major_key('16'), lifecycle.major_key('6.0')),
                         ('8.0', '5.7', '16', '6'))
        self.assertEqual(lifecycle.redis_tier('microsoft.cache/redisenterprise', 'Enterprise_E10'), 'enterprise')
        self.assertIsNone(lifecycle.redis_tier('microsoft.cache/redisenterprise', 'Balanced_B5'))   # Azure Managed Redis

    def test_operating_systems(self):
        cases = [(('Windows Server 2012 R2 Datacenter', '6.3.9600'), None, ('os-windows-server', '2012 R2')),
                 ((None, None), {'publisher': 'MicrosoftWindowsServer', 'offer': 'WindowsServer', 'sku': '2016-Datacenter'}, ('os-windows-server', '2016')),
                 (('ubuntu', '20.04'), None, ('os-ubuntu', '20.04')),
                 ((None, None), {'publisher': 'Canonical', 'offer': '0001-com-ubuntu-server-focal', 'sku': '20_04-lts-gen2'}, ('os-ubuntu', '20.04')),
                 ((None, None), {'publisher': 'Canonical', 'offer': 'UbuntuServer', 'sku': '18.04-LTS'}, ('os-ubuntu', '18.04')),
                 (('centos', '7.9.2009'), None, ('os-centos', '7')),
                 ((None, None), {'publisher': 'OpenLogic', 'offer': 'CentOS', 'sku': '7_9'}, ('os-centos', '7')),
                 (('redhat', '8.6'), None, ('os-rhel', '8')),
                 ((None, None), {'publisher': 'RedHat', 'offer': 'RHEL', 'sku': '94_gen2'}, ('os-rhel', '9')),
                 ((None, None), {'publisher': 'RedHat', 'offer': 'RHEL', 'sku': '7-LVM'}, ('os-rhel', '7')),
                 (('centos', '14.7.0.60'), None, None),
                 (('rocky', '8.8'), None, ('os-rocky', '8')),
                 ((None, None), {'publisher': 'resf', 'offer': 'rockylinux-x86_64', 'sku': '9-base'}, ('os-rocky', '9')),
                 (('unknownos', '1.0'), None, None)]
        for (name, version), image, expected in cases:
            self.assertEqual(lifecycle.os_key(name, version, image), expected, (name, version, image))

    def test_runtimes(self):
        keys = lambda c: [(p, v) for p, v, _ in lifecycle.runtime_keys(c)]  # noqa: E731
        self.assertEqual(keys({'linuxFxVersion': 'PYTHON|3.9'}), [('runtime-python', '3.9')])
        self.assertEqual(keys({'linuxFxVersion': 'NODE|18-lts'}), [('runtime-node', '18')])
        self.assertEqual(keys({'linuxFxVersion': 'DOTNETCORE|6.0'}), [('runtime-dotnet', '6.0')])
        self.assertEqual(keys({'linuxFxVersion': 'DOCKER|nginx:latest'}), [])
        self.assertEqual(keys({'netFrameworkVersion': 'v4.0', 'phpVersion': 'OFF'}), [])
        self.assertEqual(keys({'netFrameworkVersion': 'v8.0', 'javaVersion': '1.8', 'phpVersion': '8.1'}),
                         [('runtime-dotnet', '8.0'), ('runtime-php', '8.1'), ('runtime-java', '8')])

    def test_web_config_keeps_versions_only(self):
        config = {'linuxFxVersion': 'PYTHON|3.10', 'machineKey': {'decryptionKey': 'k', 'validationKey': 'v'},
                  'azureStorageAccounts': {'s': {'accessKey': 'a'}}, 'phpVersion': ''}
        self.assertEqual(rel_collect.runtime_fields(config), {'linuxFxVersion': 'PYTHON|3.10'})

    def test_certificate_expiry(self):
        from cryptography.hazmat.primitives import serialization
        cert, bundle = certificate(10)
        for data in (bundle, cert.public_bytes(serialization.Encoding.DER)):
            exp, subject = lifecycle.cert_expiry(base64.b64encode(data).decode())
            self.assertEqual(exp, cert.not_valid_after_utc)
            self.assertIn('www.contoso.com', subject)
        self.assertIsNone(lifecycle.cert_expiry('bm90IGEgY2VydA=='))


class CheckTests(unittest.TestCase):
    def run_check(self, rows, files=None, reviewed='2026-10-30', advisor_members=()):
        found = []
        items = [{'check': 'R9', 'evidence': {'advisorProblem': 'x'}, 'members': [{'name': n} for n in advisor_members]}] if advisor_members else []

        def add(check, sev, rid_or_sub, rtype, name, environment, finding, evidence, rec, confirm=None, rg=None, sub=None, members=None, key=None):
            found.append({'severity': sev, 'name': name, 'finding': finding, 'confirm': confirm, 'sub': sub, 'evidence': evidence,
                          'members': sorted(m['name'] for m in members or [])})
        run = SimpleNamespace(rows=lambda name: rows.get(name, []), raw=SimpleNamespace(load=lambda name: (files or {}).get(name)), now=NOW,
                              coverage={'R9': common.coverage_entry()}, findings=SimpleNamespace(items=items), add=add,
                              subname=lambda x: {'a': 'app-prod', 'b': 'app-test'}.get(rel_analyze.sid_of(x) if '/' in x else x, x),
                              env=lambda *a, **k: {'value': 'prod', 'label': '生产', 'basis': ''})
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'lifecycle.json'
            path.write_text(json.dumps(dict(CALENDAR, reviewedAt=reviewed)), encoding='utf-8')
            inv = {}
            lifecycle.check(run, inv, rel_analyze.member, path)
        return found, run, inv

    def test_versions_grouped_and_graded(self):
        _, gw_cert = certificate(10)
        rows = {
            'mysql': [{'id': rid('a', 'Microsoft.DBforMySQL/flexibleServers', f'mysql-{i}'), 'name': f'mysql-{i}', 'resourceGroup': 'rg',
                       'type': 'microsoft.dbformysql/flexibleservers', 'properties': {'version': '5.7'}} for i in range(2)],
            'postgres': [{'id': rid('a', 'Microsoft.DBforPostgreSQL/flexibleServers', 'pg-new'), 'name': 'pg-new', 'resourceGroup': 'rg',
                          'properties': {'version': '16'}},
                         {'id': rid('b', 'Microsoft.DBforPostgreSQL/flexibleServers', 'pg-old'), 'name': 'pg-old', 'resourceGroup': 'rg',
                          'properties': {'version': '14'}}],
            'vms': [{'id': rid('a', 'Microsoft.Compute/virtualMachines', 'vm-centos'), 'name': 'vm-centos', 'resourceGroup': 'rg',
                     'properties': {'extended': {'instanceView': {'osName': 'centos', 'osVersion': '7.9.2009'}}}},
                    {'id': rid('a', 'Microsoft.Compute/virtualMachines', 'vm-centos2'), 'name': 'vm-centos2', 'resourceGroup': 'rg',
                     'properties': {'storageProfile': {'imageReference': {'publisher': 'OpenLogic', 'offer': 'CentOS', 'sku': '7_9'}}}},
                    {'id': rid('a', 'Microsoft.Compute/virtualMachines', 'vm-rocky'), 'name': 'vm-rocky', 'resourceGroup': 'rg',
                     'properties': {'extended': {'instanceView': {'osName': 'rocky', 'osVersion': '9.3'}}}},
                    {'id': rid('a', 'Microsoft.Compute/virtualMachines', 'vm-mystery'), 'name': 'vm-mystery', 'resourceGroup': 'rg', 'properties': {}}],
            'vmss': [{'id': rid('a', 'Microsoft.Compute/virtualMachineScaleSets', 'aks-np'), 'name': 'aks-np', 'resourceGroup': 'MC_rg_aks_eastus',
                      'properties': {'virtualMachineProfile': {'storageProfile': {'imageReference': {'publisher': 'Canonical', 'sku': '20_04-lts'}}}}}],
            'redis': [{'id': rid('a', 'Microsoft.Cache/Redis', 'redis-a'), 'name': 'redis-a', 'resourceGroup': 'rg', 'type': 'microsoft.cache/redis',
                       'properties': {'redisVersion': '6.0', 'sku': {'name': 'Standard'}}}],
            'webapps': [{'id': rid('a', 'Microsoft.Web/sites', 'web-a'), 'name': 'web-a', 'resourceGroup': 'rg'},
                        {'id': rid('a', 'Microsoft.Web/sites', 'web-b'), 'name': 'web-b', 'resourceGroup': 'rg'}],
            'webconfig': [{'id': rid('a', 'Microsoft.Web/sites', 'web-a') + '/config/web', 'linuxFxVersion': 'PYTHON|3.10'}],
            'appgw': [{'id': rid('a', 'Microsoft.Network/applicationGateways', 'agw-a'), 'name': 'agw-a', 'resourceGroup': 'rg', 'properties': {
                'sslCertificates': [{'name': 'cert-web', 'properties': {'publicCertData': base64.b64encode(gw_cert).decode()}},
                                    {'name': 'cert-kv', 'properties': {'keyVaultSecretId': '[REDACTED]'}}]}}]}
        found, run, inv = self.run_check(rows)
        by_name = {f['name']: f for f in found}
        about = lambda text: next(f for f in found if text in f['finding'])  # noqa: E731
        mysql = about('MySQL 5.7')
        self.assertEqual((mysql['severity'], mysql['members']), ('高', ['mysql-0', 'mysql-1']))
        self.assertIn('付费的延长支持（到 2029-03-31）', mysql['finding'])
        centos = about('CentOS 7')
        self.assertEqual((centos['severity'], centos['members']), ('高', ['vm-centos', 'vm-centos2']))
        self.assertIn('有 2 台虚拟机使用 CentOS 7', centos['finding'])
        self.assertEqual(by_name['pg-old']['severity'], '中')                       # standard support ends in 93 days
        self.assertNotIn('pg-new', by_name)                                         # more than a year away
        self.assertNotIn('aks-np', by_name)                                         # AKS node pools are checked with the cluster
        self.assertEqual(by_name['web-a']['severity'], '中')
        self.assertNotIn('redis-a', by_name)                                        # tier retirement is more than a year away
        self.assertEqual(by_name['agw-a/cert-web']['severity'], '中')
        not_judged = {x['name']: x['reason'] for x in inv['lifecycle']['notJudged']}
        self.assertEqual(not_judged, {'vm-mystery': '未识别操作系统版本', 'vm-rocky': '支持日历中没有该版本', 'web-b': '未取得运行时版本'})
        self.assertTrue(any('1 台虚拟机未识别操作系统版本' in x and '1 台虚拟机的系统版本不在支持日历中' in x for x in run.coverage['R9']['limits']))
        self.assertTrue(any('1 个应用网关证书未取得到期日期' in n for n in run.coverage['R9']['notes']))
        self.assertTrue(any('Key Vault' in x for x in run.coverage['R9']['limits']))
        self.assertFalse(any('最后核对于' in x for x in run.coverage['R9']['limits']))

    def test_extended_security_updates_described(self):
        vm = lambda name, os_name: {'id': rid('a', 'Microsoft.Compute/virtualMachines', name), 'name': name, 'resourceGroup': 'rg',  # noqa: E731
                                    'properties': {'extended': {'instanceView': {'osName': os_name, 'osVersion': ''}}}}
        found, _run, _inv = self.run_check({'vms': [vm('vm-2012r2', 'Windows Server 2012 R2 Datacenter'), vm('vm-2012', 'Windows Server 2012 Datacenter'),
                                                    vm('vm-focal', 'ubuntu 20.04')]})
        by_name = {f['name']: f for f in found}
        self.assertIn('延长安全更新也已于 2026-10-13 结束', by_name['vm-2012r2']['finding'])
        self.assertIsNone(by_name['vm-2012r2']['confirm'])
        self.assertIn('在 Azure 上可免费获得的延长安全更新到 2027-10-13', by_name['vm-2012']['finding'])
        self.assertIn('可购买的延长安全更新到 2030-04-30', by_name['vm-focal']['finding'])
        self.assertIn('延长安全更新', by_name['vm-focal']['confirm'])

    def test_stale_calendar_noted(self):
        _found, run, _inv = self.run_check({}, reviewed='2026-01-01')
        self.assertTrue(any('支持日历最后核对于 2026-01-01' in x for x in run.coverage['R9']['limits']))

    def test_retirement_notices(self):
        st = rid('a', 'Microsoft.Storage/storageAccounts', 'stlegacy')
        rows = {'retirements': [
                    {'subscriptionId': 'a', 'trackingId': 'AB-1', 'title': 'Retirement notice: migrate GPv1 storage', 'status': 'Active',
                     'retirementDate': '2026-12-31T00:00:00Z'},
                    {'subscriptionId': 'b', 'trackingId': 'AB-1', 'title': 'Retirement notice: migrate GPv1 storage', 'status': 'Active',
                     'retirementDate': '2026-12-31T00:00:00Z'},
                    {'subscriptionId': 'a', 'trackingId': 'CD-2', 'title': 'Retirement notice: feature X', 'status': 'Active',
                     'retirementDate': '2027-03-01T00:00:00Z'},
                    {'subscriptionId': 'a', 'trackingId': 'EF-3', 'title': 'Retirement notice: far away', 'status': 'Active',
                     'retirementDate': '2029-01-01T00:00:00Z'}],
                'retirement_resources': [{'trackingId': 'AB-1', 'targetResourceId': st, 'targetResourceType': 'Microsoft.Storage/storageAccounts'}],
                'retirement_advisor': [{'trackingId': 'AB-1', 'resourceId': st.lower()}]}
        found, run, inv = self.run_check(rows)
        notice = next(f for f in found if 'AB-1' in f['finding'])
        self.assertEqual((notice['severity'], notice['members']), ('中', ['stlegacy']))
        unlinked = next(f for f in found if '未能关联到具体资源' in f['finding'])
        self.assertIn('feature X', unlinked['finding'])
        self.assertNotIn('far away', unlinked['finding'])
        self.assertEqual(len(inv['lifecycle']['retirements']), 3)
        self.assertTrue(any('受影响资源只覆盖部分服务' in x for x in run.coverage['R9']['limits']))
        found, run, _inv = self.run_check(rows, advisor_members=['stlegacy'])
        self.assertFalse(any('AB-1' in f['finding'] for f in found))


if __name__ == '__main__':
    unittest.main()
