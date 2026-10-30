"""Regression tests for problems that show up on large tenants (synthetic data, no network)."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from http.client import IncompleteRead
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlparse

sys.dont_write_bytecode = True
os.environ.setdefault('AZINSPECT_NO_EXCEL', '1')
SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from azinspect.core import excel, http  # noqa: E402
from azinspect.cost import report as cost_report  # noqa: E402
from azinspect.vm import prices  # noqa: E402
from azinspect.vm import report as vm_report  # noqa: E402
from azinspect.waf import common  # noqa: E402
from azinspect.waf.operations import governance, monitoring  # noqa: E402
from azinspect.waf.performance import lib as perf_lib  # noqa: E402
from azinspect.waf.security_identity import checks_access, checks_resources  # noqa: E402

# the pillar packages export a function named analyze, which hides the module of the same name
perf_analyze = importlib.import_module('azinspect.waf.performance.analyze')
rel_analyze = importlib.import_module('azinspect.waf.reliability.analyze')


class FakeRaw:
    def __init__(self, files):
        self.files = files

    def load(self, name):
        return self.files.get(name)


def advisor(category, problem=None, **extra):
    p = {'category': category, 'impact': 'Low', 'impactedField': 'Microsoft.Subscriptions/subscriptions', 'impactedValue': 'sub-a',
         'resourceMetadata': {'resourceId': '/subscriptions/a'}, **extra}
    if problem is not None:
        p['shortDescription'] = {'problem': problem, 'solution': problem}
    return {'_subscriptionName': 'app-prod', 'properties': p}


class AdvisorWithoutDescriptionTests(unittest.TestCase):
    """Some Advisor recommendations come without properties.shortDescription; they must be kept, not crash."""
    recs = [advisor('HighAvailability'), advisor('HighAvailability', 'Use Availability zones'), advisor('OperationalExcellence'),
            advisor('Performance')]

    def test_problem_text(self):
        self.assertEqual(common.advisor_problem(self.recs[0]), '')
        self.assertEqual(common.advisor_problem(self.recs[0], common.ADVISOR_NO_TEXT), common.ADVISOR_NO_TEXT)
        self.assertEqual(common.advisor_problem(self.recs[1]), 'Use Availability zones')

    def test_reliability_groups_missing_text(self):
        run = SimpleNamespace(raw=FakeRaw({'advisor-all.json': {'recommendations': self.recs, 'subscriptions': ['a']}}),
                              coverage={'R9': {'notes': []}}, add=lambda *a, **k: None)
        inv = {}
        rel_analyze._advisor(run, inv)
        self.assertEqual(inv['advisor']['highAvailabilityByProblem'], {common.ADVISOR_NO_TEXT: 1, 'Use Availability zones': 1})

    def test_operations_and_performance_keep_records(self):
        d = SimpleNamespace(advisor={'recommendations': self.recs}, failed_ops=[], sub_env=lambda n: None)
        inventory = {}
        governance.check_advisor(d, SimpleNamespace(add=lambda *a, **k: None), inventory)
        self.assertEqual([a['recommendation'] for a in inventory['advisorOperationalExcellence']], [common.ADVISOR_NO_TEXT])
        self.assertEqual(monitoring.advisor_count(d, 'zones'), 1)
        fake = SimpleNamespace(rel_load=lambda *_: {'recommendations': self.recs}, cov={'P10': {'notes': []}}, inv={})
        perf_analyze.Analyzer.p10_advisor(fake)
        self.assertEqual(list(fake.inv['advisorPerformance']), [common.ADVISOR_NO_TEXT])

    def test_no_direct_indexing_left(self):
        pattern = re.compile(r"\[['\"]shortDescription['\"]\]")
        hits = [f'{p.relative_to(SCRIPTS)}:{i}' for p in (SCRIPTS / 'azinspect').rglob('*.py')
                for i, line in enumerate(p.read_text(encoding='utf-8').splitlines(), 1) if pattern.search(line)]
        self.assertEqual(hits, [], 'use common.advisor_problem() instead of indexing shortDescription')


def price_item(sku, product, region='eastus', **extra):
    return {'armRegionName': region, 'armSkuName': sku, 'productName': product, 'skuName': sku[9:].replace('_', ' '), 'meterName': sku[9:],
            'serviceName': 'Virtual Machines', 'currencyCode': 'USD', 'unitOfMeasure': '1 Hour', 'effectiveStartDate': '2026-01-01T00:00:00Z',
            'tierMinimumUnits': 0, 'type': 'Consumption', 'retailPrice': 1.5, **extra}


class RedactedSavedDataTests(unittest.TestCase):
    """Raw files saved before 0.6.5 may hold '[REDACTED]' where a list or dict belongs: report it as not judged."""

    def test_key_vault_policies_not_judged(self):
        added = []
        ctx = SimpleNamespace(rows=lambda name: [{
            'id': '/subscriptions/a/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-app', 'name': 'kv-app', 'subscriptionId': 'a',
            'resourceGroup': 'rg', 'enablePurgeProtection': True, 'enableSoftDelete': True, 'enableRbacAuthorization': False,
            'accessPolicies': [{'permissions': {'keys': '[REDACTED]', 'secrets': '[REDACTED]'}}]}],
            name_of=lambda sid: 'app-prod', env=lambda *a: {'value': 'prod', 'label': '生产'}, add=lambda *a, **k: added.append(k),
            inventory={}, notes={'S-I9': []})
        checks_resources.keyvaults(ctx)
        item = ctx.inventory['keyVaults'][0]
        self.assertIsNone(item['fullSecretKeyPolicies'])
        self.assertEqual(item['unjudgedAccessPolicies'], 1)
        self.assertEqual(added, [])
        self.assertTrue(any('无法判断' in n and 'kv-app' in n for n in ctx.notes['S-I9']))

    def test_metrics_entry_redacted(self):
        rid = '/subscriptions/a/resourcegroups/rg/providers/microsoft.storage/storageaccounts/phonestore'
        fake = SimpleNamespace(load=lambda name: {'results': {rid: '[REDACTED]'}})
        self.assertEqual(perf_lib.Data.series(fake, 'storage', rid, 'Transactions'), ([], 'saved data was redacted'))


PRICE_DATE = '2100-01-01'  # price files are only reused when queried on or before the price date


class FakePriceApi:
    """Retail Prices API stand-in: armSkuName matches case-sensitively, as the real API does."""

    def __init__(self, items):
        self.items, self.filters = items, []

    def request(self, method, url, check):
        filt = parse_qs(urlparse(url).query)['$filter'][0]
        self.filters.append(filt)
        names = set(re.findall(r"armSkuName eq '([^']+)'", filt))
        return 200, {'Items': [i for i in self.items if i['armSkuName'] in names]}, None


class PriceLookupTests(unittest.TestCase):
    def test_query_uses_proper_spelling(self):
        api = FakePriceApi([price_item('Standard_D8s_v5', 'Virtual Machines Dsv5 Series')])
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d) / 'prices'
            catalog = prices.ensure_prices(api, directory, [('eastus', 'Standard_D8s_v5'), ('eastus', 'standard_d8s_v5')], PRICE_DATE, log=lambda *_: None)
        self.assertIn("armSkuName eq 'Standard_D8s_v5'", api.filters[0])
        self.assertIn(('eastus', 'standard_d8s_v5', 'linux', 'payg'), catalog)

    def test_sku_list_spelling_wins_and_old_lowercase_cache_is_requeried(self):
        api = FakePriceApi([price_item('Standard_E64is_v3', 'Virtual Machines Eisv3 Series')])
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d) / 'prices'
            directory.mkdir()
            filt = "serviceName eq 'Virtual Machines' and armRegionName eq 'eastus' and (armSkuName eq 'standard_e64is_v3')"
            (directory / 'vm-eastus-old.json').write_text(json.dumps({
                'filter': filt, 'items': [], 'queriedAt': '2026-09-30T00:00:00Z',
                'source': prices.PRICES + '?' + prices.urlencode({'currencyCode': "'USD'", '$filter': filt})}), encoding='utf-8')
            catalog = prices.ensure_prices(api, directory, [('eastus', 'standard_e64is_v3')], PRICE_DATE, log=lambda *_: None,
                                           canonical={'standard_e64is_v3': 'Standard_E64is_v3'})
        self.assertEqual(len(api.filters), 1)
        self.assertIn("armSkuName eq 'Standard_E64is_v3'", api.filters[0])
        self.assertIn(('eastus', 'standard_e64is_v3', 'linux', 'payg'), catalog)

    def test_series_product_names_accepted(self):
        api = FakePriceApi([price_item('Standard_NC40ads_H100_v5', 'NCads H100 v5 Series Linux'),
                            price_item('Standard_NC40ads_H100_v5', 'NCads H100 v5 Series Windows', retailPrice=2.5),
                            price_item('Standard_NC40ads_H100_v5', 'Cloud Services NCads H100 v5 Series')])
        with tempfile.TemporaryDirectory() as d:
            catalog = prices.ensure_prices(api, Path(d) / 'prices', [('eastus', 'Standard_NC40ads_H100_v5')], PRICE_DATE, log=lambda *_: None)
        self.assertEqual(catalog[('eastus', 'standard_nc40ads_h100_v5', 'linux', 'payg')]['retailPrice'], 1.5)
        self.assertEqual(catalog[('eastus', 'standard_nc40ads_h100_v5', 'windows', 'payg')]['retailPrice'], 2.5)


class ExcelLimitTests(unittest.TestCase):
    def test_subscription_total_formula_stays_short(self):
        rows = list(range(4, 20004)) + [20010, 20011, 20020]
        expression = vm_report._sum_rows(rows)
        self.assertEqual(expression, "=SUM('价格计算依据'!D4:D20003,'价格计算依据'!D20010:D20011,'价格计算依据'!D20020)")
        scattered = vm_report._sum_rows(list(range(4, 2004, 2)))
        self.assertLess(len(max(re.findall(r'SUM\(([^)]*)\)', scattered), key=len)), 8192)
        self.assertTrue(all(s.count(',') < 255 for s in re.findall(r'SUM\(([^)]*)\)', scattered)))

    def test_resource_sheet_capped_total_kept(self):
        rows = [{'cost': c, 'subscriptionName': 's'} for c in (5.0, 1.0, None, 7.0, 3.0)]
        shown, rest = cost_report.fit_rows(rows, 3)
        self.assertEqual([r['cost'] for r in shown], [7.0, 5.0, 3.0])
        self.assertEqual(sum(r['cost'] or 0 for r in rest), 1.0)
        self.assertEqual(cost_report.fit_rows(rows, 5), (rows, []))


class RetryTests(unittest.TestCase):
    def test_incomplete_read_retried(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"value": []}'

        attempts = []

        def open_(req, timeout):
            attempts.append(1)
            if len(attempts) == 1:
                raise IncompleteRead(b'{"val')
            return Response()

        client = http.ReadOnlyClient(SimpleNamespace(get=lambda audience: 'token'), opener=SimpleNamespace(open=open_))
        with mock.patch.object(http.time, 'sleep'):
            status, data, error = client.get('/subscriptions?api-version=2022-12-01', 'test')
        self.assertEqual((status, data, error, len(attempts)), (200, {'value': []}, None, 2))


def health_row(sub, provider, name, status, summary=''):
    rtype = provider.lower()
    return {'rid': f'/subscriptions/{sub}/resourcegroups/rg/providers/{rtype}/{name}', 'rtype': rtype, 'status': status, 'summary': summary}


VM_TYPE = 'Microsoft.Compute/virtualMachines'


def run_r11(files, rows, per=()):
    """Run R11 on fake raw files; returns (run, findings as {'name', 'members', 'finding', 'environment'})."""
    found = []

    def add(check, sev, rid_or_sub, rtype, name, environment, finding, evidence, rec, confirm=None, rg=None, sub=None, members=None, key=None):
        found.append({'name': name, 'members': sorted(m['name'] for m in members) if members else [name], 'finding': finding, 'sub': sub,
                      'evidence': evidence})
    files = {'arg/health.json': {'status': 200, 'rows': rows}, 'health/current-per-resource.json': list(per), **files}
    run = SimpleNamespace(raw=FakeRaw(files), rows=lambda name: (files.get(f'arg/{name}.json') or {}).get('rows') or [],
                          cover=lambda *a: None, coverage={'R11': common.coverage_entry()}, inventory={}, add=add,
                          subname=lambda rid: {'a': 'app-prod', 'b': 'app-test'}.get(rel_analyze.sid_of(rid), rid),
                          env=lambda sub, name=None, tags=None, rg=None: {'value': 'prod' if 'prod' in f'{name}' else 'test', 'label': '', 'basis': ''})
    rel_analyze.r11(run)
    return run, found


class StaleHealthRecordTests(unittest.TestCase):
    """healthresources keeps statuses of deleted resources; only resources still in the inventory are problems."""
    rows = [health_row('a', VM_TYPE, 'vm-live', 'Unavailable', 'down'), health_row('a', VM_TYPE, 'vm-gone', 'Unknown'),
            health_row('a', 'Microsoft.Cache/redis', 'redis-app', 'Degraded', 'slow'), health_row('a', VM_TYPE, 'vm-ok', 'Available')]

    def test_deleted_vms_counted_not_reported(self):
        vms = {'status': 200, 'rows': [{'id': '/subscriptions/a/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-live'}]}
        run, found = run_r11({'arg/vms.json': vms, 'arg/vmss.json': {'status': 200, 'rows': []}}, self.rows)
        self.assertEqual([f['members'] for f in found], [['redis-app', 'vm-live']])
        self.assertEqual(run.inventory['R11']['notInInventory'], {'Unknown': 1})
        self.assertTrue(any('1 条' in x for x in run.coverage['R11']['limits']))

    def test_unread_inventory_never_drops_records(self):
        run, found = run_r11({'arg/vms.json': {'status': 429, 'error': 'throttled', 'rows': None}}, self.rows)
        self.assertEqual([f['members'] for f in found], [['redis-app', 'vm-gone', 'vm-live']])
        self.assertEqual(run.inventory['R11']['notInInventory'], {})


class HealthGroupingTests(unittest.TestCase):
    """R11 lists unhealthy resources per subscription; unavailable production databases, clusters and caches stay separate."""

    def test_grouped_by_subscription(self):
        rows = [health_row('a', VM_TYPE, f'vm-{i}', 'Unknown') for i in range(3)] + [
            health_row('a', VM_TYPE, 'vm-x', 'Unavailable', 'host failure'),
            health_row('a', 'Microsoft.Cache/redis', 'redis-test', 'Degraded'),
            health_row('a', 'Microsoft.Cache/redis', 'redis-prod', 'Unknown'),
            health_row('a', 'Microsoft.DBforPostgreSQL/flexibleServers', 'pg-order-prod', 'Unavailable', 'maintenance'),
            health_row('b', VM_TYPE, 'vm-solo', 'Degraded', 'disk')]
        per = [{'id': '/subscriptions/a/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg-order-prod', 'status': 200,
                'availabilityState': 'Unavailable', 'summary': 'maintenance'}]
        _run, found = run_r11({}, rows, per)
        by_name = {tuple(f['members']): f for f in found}
        self.assertEqual(sorted(by_name), [('pg-order-prod',), ('redis-prod', 'redis-test', 'vm-0', 'vm-1', 'vm-2', 'vm-x'), ('vm-solo',)])
        merged = by_name[('redis-prod', 'redis-test', 'vm-0', 'vm-1', 'vm-2', 'vm-x')]
        self.assertIn('订阅 app-prod 有 6 个资源', merged['finding'])
        self.assertIn('Unknown 4 个', merged['finding'])
        self.assertEqual(len(merged['evidence']['resources']), 6)
        self.assertIn('Unavailable', by_name[('pg-order-prod',)]['finding'])
        self.assertIn('disk', by_name[('vm-solo',)]['finding'])


class CredentialWordingTests(unittest.TestCase):
    def finding(self, *creds):
        added = []
        ctx = SimpleNamespace(graph_ok=True, today=datetime(2026, 10, 1, tzinfo=timezone.utc), sub_env=lambda n: {'value': 'prod'},
                              graph={'spCredentials': {'p1': {'servicePrincipalType': 'Application', 'displayName': 'sp-deploy',
                                                              'spPasswordCredentials': list(creds)}}},
                              add=lambda *a, **k: added.append(k), inventory={}, notes={'S-I6': []})
        items = [{'subscription': 'app-prod', 'subscriptionId': 'a', 'role': 'Owner', 'scopeLevel': 'subscription', 'scope': '/subscriptions/a'}]
        checks_access.credentials(ctx, {'p1': items})
        return added[0] if added else None

    def test_long_lived_valid_credential_not_called_expiring(self):
        f = self.finding({'startDateTime': '2025-03-01T00:00:00Z', 'endDateTime': '2075-03-01T00:00:00Z'})
        self.assertNotIn('过期', f['finding'])
        self.assertIn('有效期长达约 50 年', f['finding'])
        self.assertNotIn('删除已过期', f['recommendation'])

    def test_each_state_described(self):
        f = self.finding({'startDateTime': '2025-01-01T00:00:00Z', 'endDateTime': '2026-09-01T00:00:00Z'},
                         {'startDateTime': '2025-01-01T00:00:00Z', 'endDateTime': '2026-10-20T00:00:00Z'},
                         {'startDateTime': '2024-01-01T00:00:00Z', 'endDateTime': '2034-01-01T00:00:00Z'})
        for text in ('1 个凭据已过期', '1 个凭据将在 60 天内到期', '1 个凭据有效期长达约 10 年', '删除已过期'):
            self.assertIn(text, f['finding'] + f['recommendation'])

    def test_credential_kind_in_plain_chinese(self):
        f = self.finding({'startDateTime': '2025-01-01T00:00:00Z', 'endDateTime': '2026-09-01T00:00:00Z'})
        self.assertIn('服务主体上的密码于 2026-09-01 到期', f['finding'])
        self.assertNotIn('Credentials', f['finding'])


class ExcelRecalculationTests(unittest.TestCase):
    def workbook(self, d):
        from openpyxl import Workbook
        path = Path(d) / 'book.xlsx'
        wb = Workbook()
        wb.active['A1'] = '=1+1'
        wb.save(path)
        return path

    def test_failure_reason_recorded(self):
        class Excel:
            Visible = DisplayAlerts = AutomationSecurity = None

            class Workbooks:
                @staticmethod
                def Open(*a, **k):
                    raise RuntimeError('Open method of Workbooks class failed')

            def Quit(self):
                pass

        fake_com = SimpleNamespace(CoInitialize=lambda: None, CoUninitialize=lambda: None)
        fake_client = SimpleNamespace(DispatchEx=lambda name: Excel())
        with (tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {'AZINSPECT_NO_EXCEL': ''}),
              mock.patch.object(excel.platform, 'system', return_value='Windows'),
              mock.patch.dict(sys.modules, {'pythoncom': fake_com, 'win32com': SimpleNamespace(client=fake_client), 'win32com.client': fake_client})):
            path = self.workbook(d)
            result = excel.verify(path, {'Sheet!A1': 2}, Path(d) / 'verification.json')
            saved = json.loads((Path(d) / 'verification.json').read_text(encoding='utf-8'))
        self.assertFalse(result['recalculatedInExcel'])
        self.assertIn('Open method of Workbooks class failed', saved['recalculationError'])

    def test_disconnected_excel_falls_back(self):
        """Excel disconnects during recalculation and Close/Quit then fail too: the build keeps the structural check."""
        disconnected = RuntimeError('(-2147417848, The object invoked has disconnected from its clients.)')
        released = []

        class Book:
            def Close(self, **k):
                raise disconnected

        class Excel:
            Visible = DisplayAlerts = AutomationSecurity = None

            class Workbooks:
                @staticmethod
                def Open(*a, **k):
                    return Book()

            def CalculateFullRebuild(self):
                raise RuntimeError('recalculation interrupted')

            @property
            def Quit(self):     # a disconnected COM object fails on attribute access already
                raise AttributeError('Open.Quit')

        fake_com = SimpleNamespace(CoInitialize=lambda: None, CoUninitialize=lambda: released.append(True))
        fake_client = SimpleNamespace(DispatchEx=lambda name: Excel())
        with (tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {'AZINSPECT_NO_EXCEL': ''}),
              mock.patch.object(excel.platform, 'system', return_value='Windows'),
              mock.patch.dict(sys.modules, {'pythoncom': fake_com, 'win32com': SimpleNamespace(client=fake_client), 'win32com.client': fake_client})):
            result = excel.verify(self.workbook(d), {'Sheet!A1': 2})
        self.assertFalse(result['recalculatedInExcel'])
        self.assertIn('recalculation interrupted', result['recalculationError'])
        self.assertEqual(released, [True])

    def test_skipped_recalculation_says_why(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {'AZINSPECT_NO_EXCEL': '1'}):
            result = excel.verify(self.workbook(d), {'Sheet!A1': 2})
        self.assertIn('AZINSPECT_NO_EXCEL', result['recalculationError'])

    def test_timeout_grows_with_workbook(self):
        self.assertEqual(excel.recalculation_timeout(100_000), 150)
        self.assertGreater(excel.recalculation_timeout(40_000_000), 600)
        self.assertLessEqual(excel.recalculation_timeout(10 ** 10), 3600)


class CollectCommandTests(unittest.TestCase):
    def run_collect(self, failing=None, failed_pillars=()):
        from azinspect import cli
        import azinspect.cost.pipeline
        import azinspect.peer
        import azinspect.vm.collect
        import azinspect.waf.pipeline
        ran = []

        def part(name, result=None):
            def fn(*a, **k):
                if name == failing:
                    raise KeyboardInterrupt
                ran.append(name)
                return result
            return fn
        out = io.StringIO()
        with (tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(out),
              mock.patch.object(cli, '_client', return_value=(None, None, SimpleNamespace(calls=[]))),
              mock.patch.object(azinspect.vm.collect, 'collect', part('vm')),
              mock.patch.object(azinspect.cost.pipeline, 'collect', part('cost')),
              mock.patch.object(azinspect.waf.pipeline, 'collect', part('waf', list(failed_pillars))),
              mock.patch.object(azinspect.peer, 'collect', part('peer'))):
            try:
                code = cli.main(['collect', '--workspace', d, '--month', '2026-09'])
            except KeyboardInterrupt:
                code = 'interrupted'
        return code, ran, out.getvalue()

    def test_failed_pillars_give_nonzero_exit(self):
        code, ran, out = self.run_collect(failed_pillars=['reliability', 'operations'])
        self.assertEqual((code, ran), (1, ['vm', 'cost', 'waf', 'peer']))
        self.assertIn('--pillars reliability,operations', out)

    def test_interrupted_run_names_remaining_parts(self):
        code, ran, out = self.run_collect(failing='cost')
        self.assertEqual((code, ran), ('interrupted', ['vm']))
        for part in ('--part cost --resume', '--part waf', '--part peer'):
            self.assertIn(part, out)
        self.assertNotIn('--part vm', out)

    def test_resume_passed_to_cost_collection(self):
        from azinspect import cli
        import azinspect.cost.pipeline
        seen = {}
        with (tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()),
              mock.patch.object(cli, '_client', return_value=(None, None, SimpleNamespace(calls=[]))),
              mock.patch.object(azinspect.cost.pipeline, 'collect', lambda *a, **k: seen.update(k))):
            self.assertEqual(cli.main(['collect', '--workspace', d, '--month', '2026-09', '--part', 'cost', '--resume']), 0)
        self.assertEqual(seen, {'resume': True})

    def test_clean_run(self):
        self.assertEqual(self.run_collect()[:2], (0, ['vm', 'cost', 'waf', 'peer']))


if __name__ == '__main__':
    unittest.main()


def vm_row(name, sub='app-prod', status='建议调整（先小范围试用）', saving=10.0, pool=None, current='Standard_D8s_v5', target='Standard_D4s_v5',
           note='CPU核数减半，内存容量不变', running=True):
    changing = status.startswith('建议调整')
    io = {m: 10.0 for m, _, _ in vm_report.IO}
    return {'subscriptionName': sub, 'subscriptionId': sub + '-id', 'resourceGroup': 'rg', 'name': name, 'region': 'eastus', 'vmId': '/x/' + name,
            'currentSKU': current, 'effectiveSKU': target if changing else current, 'changing': changing, 'running': running, 'status': status,
            'cpuCurrent': 10.0, 'cpuAfter': 20.0 if changing else 10.0, 'memoryCurrent': 50.0, 'memoryAfter': 50.0, 'currentIO': io, 'afterIO': io,
            'currentMonthlyPAYG': 100.0, 'costs': {k: 100.0 - (saving if changing else 0) for k in prices.KEYS},
            'monthlyRightsizingSavings': saving if changing else 0, 'note': note, 'poolName': pool}


class VmMarkdownSizeTests(unittest.TestCase):
    """02 keeps fixed summary tables; the per-machine table is only attached up to a configurable number of machines."""

    rows = ([vm_row(f'aks-np-{i}', pool='np-big', saving=30.0) for i in range(3)]
            + [vm_row('vm-a', saving=50.0), vm_row('vm-b', sub='data-prod', saving=5.0, current='Standard_E8s_v5', target='Standard_E4s_v5'),
               vm_row('vm-c', status='保持原规格：CPU和内存均不低于20%', note='CPU和内存平均利用率均不低于20%'),
               vm_row('vm-d', status='暂不调整：见备注', note='目标规格不能挂载现有数量的数据盘；暂不更换为 Standard_D4s_v5'),
               vm_row('vm-e', status='暂不调整：见备注', note='目标规格没有更便宜'),
               vm_row('vm-f', status='读取权限不足，暂不判断', note='指标读取权限不足（HTTP403），无法判断利用率')])

    def section(self, limit):
        return '\n'.join(vm_report.summary_section(self.rows, sum(r['monthlyRightsizingSavings'] for r in self.rows), limit))

    def test_detail_attached_within_limit(self):
        text = self.section(len(self.rows))
        self.assertIn('### 2.5 逐台明细', text)
        self.assertEqual(sum(1 for line in text.splitlines() if line.startswith('|app-prod|rg|aks-np-')), 3)

    def test_detail_replaced_above_limit(self):
        text = self.section(len(self.rows) - 1)
        self.assertNotIn('### 2.5', text)
        self.assertIn(f'共 {len(self.rows)} 台，逐台明细见 Excel“VM建议指标价格总表”', text)
        self.assertFalse(any(line.startswith('|app-prod|rg|aks-np-') for line in text.splitlines()))

    def test_summary_tables(self):
        text = self.section(0)
        self.assertIn('|app-prod|8|8|4|140.00|', text)
        self.assertIn('|合计|9|9|5|145.00|', text)
        self.assertIn('|暂不调整：目标规格不能挂载现有数量的数据盘|1|', text)
        self.assertIn('|暂不调整：目标规格没有更便宜|1|', text)
        self.assertIn('|读取权限不足，暂不判断|1|', text)
        self.assertIn('|Standard_D8s_v5|Standard_D4s_v5|4|140.00|', text)
        top = text.split('### 2.4')[1].split('###')[0]
        self.assertIn('|节点池/VMSS np-big|3|', top)
        self.assertLess(top.index('np-big'), top.index('vm-a'))

    def test_reasons_with_numbers_grouped(self):
        rows = [vm_row(f'vm-{p}', status='暂不调整：见备注', note=f'Uncached MB/s 目标平均消耗率 {p}%超过 50%；暂不更换为 Standard_D4s_v5')
                for p in ('93.57', '52.04')]
        text = '\n'.join(vm_report.summary_section(rows, 0, 0))
        self.assertIn('|暂不调整：更换后磁盘 IOPS 或吞吐的平均消耗率超过 50%|2|', text)

    def test_limit_configurable(self):
        from azinspect.core import config
        template = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'
        self.assertEqual(config.load(template).vm_detail_max_rows, 500)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'customer.yaml'
            p.write_text(template.read_text(encoding='utf-8').replace('  currency: USD', '  currency: USD\n  vmDetailMaxRows: -1'), encoding='utf-8')
            with self.assertRaises(config.ConfigError):
                config.load(p)

    def test_quality_check_rejects_large_markdown(self):
        from azinspect.core.quality import check_markdown
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / '02_报告.md'
            p.write_text('# 报告\n\n' + '很长的段落。' * 30_000 + '\n', encoding='utf-8')
            self.assertTrue(any('KB' in x for x in check_markdown(p)))


class FlexibleScaleSetTests(unittest.TestCase):
    """Machines in a Flexible scale set are also standalone VM resources: counted once, as the VM."""
    FLEX = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/flex'
    UNI = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/uni'
    resources = [{'id': FLEX, 'type': 'Microsoft.Compute/virtualMachineScaleSets', 'properties': {'orchestrationMode': 'Flexible'}},
                 {'id': UNI, 'type': 'Microsoft.Compute/virtualMachineScaleSets', 'properties': {'orchestrationMode': 'Uniform'}},
                 {'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-a', 'name': 'vm-a', 'subscriptionId': 's',
                  'type': 'Microsoft.Compute/virtualMachines', 'properties': {'virtualMachineScaleSet': {'id': FLEX}}},
                 {'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-b', 'name': 'vm-b', 'subscriptionId': 's',
                  'type': 'Microsoft.Compute/virtualMachines', 'properties': {}}]

    def vms(self):
        vm = lambda name: {'id': f'/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{name}', 'name': name,  # noqa: E731
                           'kind': 'vm', 'metricResourceId': f'/subscriptions/s/x/{name}', 'subscriptionId': 's', 'state': 'PowerState/running'}
        child = lambda parent, name: {'id': f'{parent}/virtualMachines/{name}', 'name': name, 'kind': 'vmss', 'metricResourceId': parent,  # noqa: E731
                                      'subscriptionId': 's', 'state': 'Unknown'}
        return [vm('vm-a'), vm('vm-b'), child(self.FLEX, 'vm-a'), child(self.FLEX, 'vm-gone'), child(self.UNI, '0')]

    def test_duplicates_removed_and_missing_counted(self):
        from azinspect.vm import scalesets
        kept, duplicates, missing = scalesets.drop_flexible_duplicates(self.vms(), self.resources)
        self.assertEqual(sorted(v['id'].rsplit('/', 2)[-2] + '/' + v['name'] for v in kept),
                         ['virtualMachines/0', 'virtualMachines/vm-a', 'virtualMachines/vm-b'])
        self.assertEqual([v['name'] for v in duplicates], ['vm-a'])
        self.assertEqual([v['name'] for v in missing], ['vm-gone'])
        self.assertEqual(sum(v['kind'] == 'vmss' for v in kept), 1)

    def test_nothing_to_drop_without_flexible_sets(self):
        from azinspect.vm import scalesets
        vms = [v for v in self.vms() if self.FLEX not in v['metricResourceId']]
        self.assertEqual(scalesets.drop_flexible_duplicates(vms, self.resources), (vms, [], []))

    def test_summary_sentence(self):
        from azinspect.vm import scalesets
        text = scalesets.note(40, 7)
        self.assertIn('Flexible', text)
        self.assertIn('去掉 40 条重复记录', text)
        self.assertIn('7 个实例在采集时已不存在或无法读取', text)
        self.assertEqual(scalesets.note(0, 0), '')
