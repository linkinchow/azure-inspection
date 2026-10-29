"""Tests for `collect --resume`: reuse of saved query results, split queries, smaller RI/SP reads (synthetic data, no network)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.core import reuse  # noqa: E402

NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)


class ReuseTests(unittest.TestCase):
    def saved(self, d, signature, ok=True, age_days=1):
        path = Path(d) / 'q.json'
        record = {'result': {'ok': ok}, '_resume': {'signature': signature, 'savedAt': (NOW - timedelta(days=age_days)).isoformat()}}
        path.write_text(json.dumps(record), encoding='utf-8')
        return path

    def test_reuse_rules(self):
        sig = reuse.signature('cost', 'curActual', 'https://x', {'timePeriod': {'from': '2026-09-01'}})
        ok = lambda rec: rec['result']['ok']  # noqa: E731
        with tempfile.TemporaryDirectory() as d:
            r = reuse.Reuse(True, now=NOW)
            self.assertIsNotNone(r.load(self.saved(d, sig), sig, ok))
            self.assertIsNone(r.load(self.saved(d, sig), reuse.signature('cost', 'curActual', 'https://x', {'timePeriod': {'from': '2026-08-01'}}), ok))
            self.assertIsNone(r.load(self.saved(d, sig, ok=False), sig, ok))
            self.assertIsNone(r.load(self.saved(d, sig, age_days=8), sig, ok))
            self.assertIsNone(r.load(Path(d) / 'missing.json', sig, ok))
            self.assertIsNone(reuse.Reuse(False, now=NOW).load(self.saved(d, sig), sig, ok))
            self.assertEqual((r.reused, r.checked), (1, 5))

    def test_stamp_round_trip(self):
        sig = reuse.signature('a', 1)
        r = reuse.Reuse(True, now=NOW)
        record = r.stamp({'result': {'ok': True}}, sig)
        self.assertEqual(record['_resume']['signature'], sig)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'q.json'
            path.write_text(json.dumps(record), encoding='utf-8')
            self.assertIsNotNone(r.load(path, sig))

    def test_signature_ignores_key_order(self):
        self.assertEqual(reuse.signature({'a': 1, 'b': [1, 2]}), reuse.signature({'b': [1, 2], 'a': 1}))
        self.assertNotEqual(reuse.signature({'a': 1}), reuse.signature({'a': 2}))


if __name__ == '__main__':
    unittest.main()


from datetime import date  # noqa: E402
from unittest import mock  # noqa: E402

from azinspect.core import io  # noqa: E402
from azinspect.core.period import ReportPeriod  # noqa: E402
from azinspect.cost import collect as cost_collect  # noqa: E402

SUB = {'id': '00000000-0000-0000-0000-000000000001', 'name': 'app-prod', 'group': '其他'}
LEDGER = [('rg-a', 'vm-1', 'Virtual Machines', 100.0), ('rg-b', 'vm-2', 'Virtual Machines', 50.0), ('rg-c', 'st-1', 'Storage', 7.5),
          ('rg-d', 'db-1', 'Azure Database for MySQL', 30.0), ('rg-e', 'kv-1', 'Key Vault', 0.25), ('', None, 'Azure Reservations', 12.0)]


class FakeCostApi:
    """Answers Cost Management queries from LEDGER; ResourceGroupName filters are honoured; chosen calls can fail."""

    def __init__(self, fail_on=()):
        self.calls, self.fail_on = [], set(fail_on)

    def request(self, method, url, check, target='', body=None):
        names = [g['name'] for g in body['dataset']['grouping']]
        groups = ((body['dataset'].get('filter') or {}).get('dimensions') or {}).get('values')
        self.calls.append(groups)
        if groups and tuple(groups) in self.fail_on:
            return 429, None, 'HTTP 429'
        rows = [x for x in LEDGER if groups is None or x[0] in groups]
        if 'ResourceId' in names:
            out = [[cost, f'/subscriptions/{SUB["id"]}/resourceGroups/{rg}/providers/x/{rid}' if rid else '', service, 'USD']
                   for rg, rid, service, cost in rows]
            columns = ['Cost', 'ResourceId', 'ServiceName', 'Currency']
        else:
            out = [[cost, 20260915, service, rg, 'USD'] for rg, _rid, service, cost in rows]
            columns = ['Cost', 'UsageDate', 'ServiceName', 'ResourceGroupName', 'Currency']
        return 200, {'properties': {'columns': [{'name': c} for c in columns], 'rows': out}}, None


class SplitResourceQueryTests(unittest.TestCase):
    def collector(self, ws, api, resume=False):
        period = ReportPeriod.build('2026-09', run_date=date(2026, 10, 15))
        c = cost_collect.Collector(ws, api, period, [SUB], 'USD', log=lambda *_: None, reuse=reuse.Reuse(resume))
        c.run_jobs([(SUB, 'curActual')])
        return c

    def test_batches_add_up_to_month_total(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(cost_collect, 'SPLIT_RESOURCE_GROUPS', 2), \
                mock.patch.object(cost_collect, 'RESOURCE_GROUP_BATCH', 2):
            ws = io.Workspace(d, '2026-09')
            ws.create()
            c = self.collector(ws, FakeCostApi())
            c.run_resource_jobs([SUB])
            record, rows = c.records[(SUB['id'], 'curResources')]
            parts = sorted(p.name for p in ws.raw('cost/queries').glob('*.curResources.part*.json'))
        self.assertEqual(len(parts), 3)                                   # 5 resource groups in batches of 2
        self.assertEqual(record['split']['batches'], 3)
        self.assertAlmostEqual(sum(r['cost'] for r in rows), sum(x[3] for x in LEDGER))
        rest = [r for r in rows if r['serviceName'] == cost_collect.UNASSIGNED_SERVICE]
        self.assertEqual([r['cost'] for r in rest], [12.0])

    def test_few_resource_groups_read_whole(self):
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            c = self.collector(ws, FakeCostApi())
            c.run_resource_jobs([SUB])
            self.assertTrue(ws.raw(f'cost/queries/{SUB["id"]}.curResources.json').exists())
            self.assertNotIn('split', c.records[(SUB['id'], 'curResources')][0])

    def test_resume_reads_only_missing_batches(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(cost_collect, 'SPLIT_RESOURCE_GROUPS', 2), \
                mock.patch.object(cost_collect, 'RESOURCE_GROUP_BATCH', 2):
            ws = io.Workspace(d, '2026-09')
            ws.create()
            first = self.collector(ws, FakeCostApi(fail_on=[('rg-c', 'rg-d')]))
            first.run_resource_jobs([SUB])
            self.assertFalse(first.records[(SUB['id'], 'curResources')][0]['result']['ok'])
            api = FakeCostApi()
            second = self.collector(ws, api, resume=True)
            second.run_resource_jobs([SUB])
            record, rows = second.records[(SUB['id'], 'curResources')]
        self.assertEqual(api.calls, [['rg-c', 'rg-d']])                  # curActual and the good batches were reused
        self.assertTrue(record['result']['ok'])
        self.assertAlmostEqual(sum(r['cost'] for r in rows), sum(x[3] for x in LEDGER))
        self.assertEqual(second.reuse.reused, 3)


from azinspect.cost import commitments  # noqa: E402

PRICED = [('microsoft.compute/virtualmachines', 'vm-1', 'Reservation', 60.0), ('microsoft.compute/virtualmachines', 'vm-1', 'OnDemand', 5.0),
          ('microsoft.compute/virtualmachinescalesets', 'aks-np', 'SavingsPlan', 40.0), ('microsoft.storage/storageaccounts', 'st-1', 'OnDemand', 9.0)]


class FakePricingApi:
    def __init__(self, refuse_filter=False):
        self.refuse_filter, self.calls = refuse_filter, []

    def request(self, method, url, check, target='', body=None):
        names = [g['name'] for g in body['dataset']['grouping']]
        flt = (body['dataset'].get('filter') or {}).get('dimensions')
        self.calls.append((tuple(names), bool(flt)))
        if flt and self.refuse_filter:
            return 400, None, 'BadRequest: filter not supported'
        rows = [x for x in PRICED if not flt or x[0] in flt['values']]
        if 'ResourceId' in names:
            out = [[cost, f'/subscriptions/s/resourceGroups/rg/providers/{t}/{n}', model, 'USD'] for t, n, model, cost in rows]
        else:
            totals = {}
            for _t, _n, model, cost in rows:
                totals[model] = totals.get(model, 0) + cost
            out = [[cost, model, 'USD'] for model, cost in totals.items()]
        columns = ['Cost'] + (['ResourceId'] if 'ResourceId' in names else []) + ['PricingModel', 'Currency']
        return 200, {'properties': {'columns': [{'name': c} for c in columns], 'rows': out}}, None


class PricingTests(unittest.TestCase):
    period = ReportPeriod.build('2026-09', run_date=date(2026, 10, 15))

    def read(self, api, resume=False, d=None):
        ws = io.Workspace(d, '2026-09')
        ws.create()
        return commitments.pricing(ws, api, ['s'], self.period, reuse.Reuse(resume))

    def check(self, rows, by_model):
        self.assertEqual(by_model['s'], {'Reservation': 60.0, 'OnDemand': 14.0, 'SavingsPlan': 40.0})
        self.assertEqual(sorted({r['resourceId'].rsplit('/', 1)[-1] for r in rows}), ['aks-np', 'vm-1'])
        cover = commitments.summary({'pricingByResource': rows, 'pricingByModel': by_model})
        self.assertEqual(cover['byModel'], {'reservation': 60.0, 'ondemand': 14.0, 'savingsplan': 40.0})

    def test_totals_and_machines(self):
        with tempfile.TemporaryDirectory() as d:
            rows, by_model, statuses = self.read(FakePricingApi(), d=d)
        self.check(rows, by_model)
        self.assertEqual(statuses['s'], {'ok': True, 'error': None, 'models': True, 'machines': True})

    def test_refused_filter_filtered_locally(self):
        api = FakePricingApi(refuse_filter=True)
        with tempfile.TemporaryDirectory() as d:
            rows, by_model, _statuses = self.read(api, d=d)
        self.check(rows, by_model)
        self.assertIn((('ResourceId', 'PricingModel'), False), api.calls)

    def test_resume_reuses_saved_reads(self):
        with tempfile.TemporaryDirectory() as d:
            self.read(FakePricingApi(), d=d)
            api = FakePricingApi()
            rows, by_model, _statuses = self.read(api, resume=True, d=d)
        self.assertEqual(api.calls, [])
        self.check(rows, by_model)


from azinspect.cost import model as cost_model  # noqa: E402


class ModelSplitTests(unittest.TestCase):
    def model(self, n=30):
        rows = [{'subscriptionId': 's', 'subscriptionName': 'app-prod', 'group': '其他', 'resourceGroup': 'rg', 'resourceId': f'/x/r{i}',
                 'resourceName': f'r{i}', 'serviceName': 'Storage', 'cost': float(100 - i)} for i in range(n)]
        return {'totals': {'cur': 1.0}, 'resources': rows}

    def test_round_trip(self):
        m = self.model()
        with tempfile.TemporaryDirectory() as d:
            fdir = Path(d)
            cost_model.save(fdir, m)
            slim = json.loads((fdir / 'model.json').read_text(encoding='utf-8'))
            self.assertNotIn('resources', slim)
            self.assertEqual((len(slim['topResources']), slim['resourceCount']), (20, 30))
            self.assertEqual(cost_model.load_resources(fdir), m['resources'])
            self.assertNotIn('\n', (fdir / 'resources.json').read_text(encoding='utf-8').strip())

    def test_old_model_file_still_read(self):
        m = self.model(3)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'model.json').write_text(json.dumps(m), encoding='utf-8')
            self.assertEqual(cost_model.load_resources(Path(d)), m['resources'])
