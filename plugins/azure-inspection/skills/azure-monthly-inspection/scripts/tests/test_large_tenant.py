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
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {'AZINSPECT_NO_EXCEL': ''}),                 mock.patch.object(excel.platform, 'system', return_value='Windows'),                 mock.patch.dict(sys.modules, {'pythoncom': fake_com, 'win32com': SimpleNamespace(client=fake_client), 'win32com.client': fake_client}):
            path = self.workbook(d)
            result = excel.verify(path, {'Sheet!A1': 2}, Path(d) / 'verification.json')
            saved = json.loads((Path(d) / 'verification.json').read_text(encoding='utf-8'))
        self.assertFalse(result['recalculatedInExcel'])
        self.assertIn('Open method of Workbooks class failed', saved['recalculationError'])

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
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(out),                 mock.patch.object(cli, '_client', return_value=(None, None, SimpleNamespace(calls=[]))),                 mock.patch.object(azinspect.vm.collect, 'collect', part('vm')),                 mock.patch.object(azinspect.cost.pipeline, 'collect', part('cost')),                 mock.patch.object(azinspect.waf.pipeline, 'collect', part('waf', list(failed_pillars))),                 mock.patch.object(azinspect.peer, 'collect', part('peer')):
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
        for part in ('--part cost', '--part waf', '--part peer'):
            self.assertIn(part, out)
        self.assertNotIn('--part vm', out)

    def test_clean_run(self):
        self.assertEqual(self.run_collect()[:2], (0, ['vm', 'cost', 'waf', 'peer']))


if __name__ == '__main__':
    unittest.main()
