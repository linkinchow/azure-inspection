"""0.10.9: lighter performance collection and other fixes after the 0.10.8 runs (synthetic data, no network)."""
from __future__ import annotations

import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from azinspect.core import io  # noqa: E402


def collector(labels):
    import importlib
    from types import SimpleNamespace
    pc = importlib.import_module('azinspect.waf.performance.collect')
    c = object.__new__(pc.Collector)
    c.rows = lambda name: [{'id': f'/subscriptions/s/x/{name}1', 'name': f'{name}1', 'subscriptionId': 's', 'location': 'regiona', 'power': 'PowerState/running',
                            'sku': {'name': 'Standard'}}]
    c.batch_metrics = lambda label, *a, **k: labels.append(label) or {}
    c.client = SimpleNamespace(get_all=lambda *a, **k: ([], 200, None), get=lambda *a, **k: (200, {}, None))
    c.save, c.log = (lambda *a, **k: None), (lambda *a, **k: None)
    return c


class UnusedMetricsTests(unittest.TestCase):
    # several metric reads were saved but no check read them; the heaviest (per-instance and per-backend-IP) were
    # throttled on large tenants and made P1 and P9 read as incomplete
    UNUSED = {'vmss-daily', 'vmss-instance-daily', 'aks-node', 'ai-tokens', 'ai-ptu', 'ai-calls', 'lb-dip'}

    def test_unused_metrics_are_not_read(self):
        labels = []
        c = collector(labels)
        c.phase_compute()
        c.phase_aks()
        self.assertEqual(self.UNUSED & set(labels), set())
        self.assertIn('vmss-instance-hourly-cpu', labels)
        self.assertIn('aks-nodecond', labels)

    def test_old_reads_of_unused_metrics_do_not_count(self):
        from types import SimpleNamespace
        from azinspect.waf.performance.analyze import Analyzer
        calls = [{'check': 'P9', 'target': 'lb-dip/s/regiona', 'status': 529}, {'check': 'P9', 'target': 'lb-vip/s/regiona', 'status': 200},
                 {'check': 'P1', 'target': 'vmss-instance-daily/s/regiona', 'status': 529}]
        files = {'index.json': {'calls': calls},
                 'metrics/lb-dip.json': {'label': 'lb-dip', 'results': {'/lb1': {'_error': 'HTTP 529: Throttled'}}},
                 'metrics/vmss-instance-daily.json': {'label': 'vmss-instance-daily', 'results': {'/v1': {'_error': 'HTTP 529: Throttled'}}}}
        a = object.__new__(Analyzer)
        a.raw = SimpleNamespace(load=lambda rel, default=None: files.get(rel, default))
        a.cov = {f'P{i}': {'attempted': 0, 'succeeded': 0, 'denied': 0, 'otherErrors': 0, 'notes': []} for i in range(1, 11)}
        a.coverage_from_index()
        self.assertEqual((a.cov['P9']['attempted'], a.cov['P9']['otherErrors']), (1, 0))
        self.assertEqual((a.cov['P1']['attempted'], a.cov['P1']['otherErrors']), (0, 0))
        self.assertFalse(a.cov['P9']['notes'])


class NarrowFallbackTests(unittest.TestCase):
    # node conditions of the largest clusters were throttled even one cluster and ten days at a time
    def test_single_resource_falls_back_to_the_narrow_filter(self):
        import importlib
        from types import SimpleNamespace
        from urllib.parse import parse_qs, urlparse
        pc = importlib.import_module('azinspect.waf.performance.collect')
        seen = []

        def request(method, url, check, target='', body=None, **kw):
            flt = parse_qs(urlparse(url).query).get('filter', [''])[0]
            seen.append(flt)
            if 'Ready' not in flt:
                return 529, None, 'Throttled: backend'
            ts = [{'metadatavalues': [{'name': {'value': 'condition'}, 'value': 'Ready'}, {'name': {'value': 'status'}, 'value': 'true'}],
                   'data': [{'timeStamp': '2026-10-02T00:00:00Z', 'average': 5}]}]
            return 200, {'values': [{'resourceid': r, 'value': [{'name': {'value': 'kube_node_status_condition'}, 'errorCode': 'Success',
                                                                 'timeseries': ts}]} for r in body['resourceids']]}, None
        c = object.__new__(pc.Collector)
        c.client, c.log, c.start, c.end, c.denied = SimpleNamespace(request=request), (lambda *_: None), '2026-10-01T00:00:00Z', '2026-10-31T00:00:00Z', set()
        c.raw = SimpleNamespace(save=lambda rel, obj: None)
        res = c.batch_metrics('aks-nodecond', 'P2', [{'id': '/subscriptions/s/x/c1', 'subscriptionId': 's', 'location': 'regiona'}], 'ns',
                              ['kube_node_status_condition'], 'average,maximum', interval='PT12H',
                              flt="condition eq '*' and status eq '*'", narrow="condition eq 'Ready' and status eq '*'")
        r = res['/subscriptions/s/x/c1']
        self.assertNotIn('_error', r)
        self.assertEqual(r['_narrowed'], "condition eq 'Ready' and status eq '*'")
        self.assertEqual(len(r['kube_node_status_condition']), 1)

    def test_narrowed_reads_are_noted(self):
        from types import SimpleNamespace
        from azinspect.waf.performance.analyze import Analyzer
        files = {'index.json': {'calls': [{'check': 'P2', 'target': 'aks-nodecond/s/regiona', 'status': 200}]},
                 'metrics/aks-nodecond.json': {'label': 'aks-nodecond', 'results': {'/c1': {'m': [], '_narrowed': "condition eq 'Ready'"}}}}
        a = object.__new__(Analyzer)
        a.raw = SimpleNamespace(load=lambda rel, default=None: files.get(rel, default))
        a.cov = {f'P{i}': {'attempted': 0, 'succeeded': 0, 'denied': 0, 'otherErrors': 0, 'notes': []} for i in range(1, 11)}
        a.coverage_from_index()
        self.assertEqual(a.cov['P2']['otherErrors'], 1)
        self.assertTrue(any('只读到 Ready' in n and 'c1' in n for n in a.cov['P2']['notes']))


class PriceDateLogTests(unittest.TestCase):
    def test_log_names_when_prices_were_read(self):
        # an offline analyze logged "价格日期 <today>" though the prices were read on the collection day
        from urllib.parse import urlencode
        from azinspect.core.http import PRICES
        from azinspect.vm.prices import queried_dates
        with tempfile.TemporaryDirectory() as d:
            for name, sku, day in (('a', 'x', '2026-11-03'), ('b', 'y', '2026-11-04')):
                filt = f"serviceName eq 'Virtual Machines' and armRegionName eq 'r' and (armSkuName eq '{sku}')"
                source = PRICES + '?' + urlencode({'api-version': '2023-01-01-preview', 'currencyCode': "'USD'", '$filter': filt})
                io.write_json(Path(d) / f'{name}.json', {'filter': filt, 'source': source, 'queriedAt': f'{day}T10:00:00+00:00',
                                                         'priceAsOfDate': day, 'items': []})
            self.assertEqual(queried_dates(d, '2026-11-09'), ['2026-11-03', '2026-11-04'])
            self.assertEqual(queried_dates(d, '2026-11-03'), ['2026-11-03'])

class NodeOsWordingTests(unittest.TestCase):
    def test_r9_and_o4_wording(self):
        from azinspect.waf.checks import node_os_text
        self.assertEqual(node_os_text(None), '节点操作系统没有开启自动更新')
        self.assertEqual(node_os_text('None'), '节点操作系统没有开启自动更新')
        self.assertEqual(node_os_text('NodeImage'), '节点操作系统自动更新通道为 NodeImage')


class StaleFailureNoteTests(unittest.TestCase):
    def test_note_saying_read_failure_without_one(self):
        # a narrative written last month said "部分资源健康状态读取失败" after the read no longer failed
        from azinspect.waf.report import stale_failure_notes
        coverage = {'R11': {'attempted': 5, 'succeeded': 5, 'denied': 0, 'otherErrors': 0},
                    'S-I4': {'attempted': 5, 'succeeded': 3, 'denied': 2, 'otherErrors': 0}}
        notes = {'R11': '资源健康正常；部分资源健康状态读取失败。', 'S-I4': '部分订阅读取失败。', 'R1': '子网不足。'}
        self.assertEqual(stale_failure_notes(notes, coverage), ['R11'])


class RetryRoundRecordTests(unittest.TestCase):
    def test_forecast_retry_round_reports_turns_and_wait(self):
        # 17 throttled forecast reads showed waited 0 each; the round itself waited about 12 minutes, recorded nowhere
        from azinspect.core.reuse import Reuse
        from azinspect.cost import supplement_costs as sc
        from test_throttle import PERIOD, SUBS, Clock, ForecastApi
        clock = Clock()
        api = ForecastApi(clock, [(6, 300)])
        logs = []
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            run = sc.Runner(ws, api, SUBS, 'USD', Reuse(False))
            left = sc.forecast_first_pass(run, [s['id'] for s in SUBS], PERIOD)
            stats = sc.forecast_retry(run, left, PERIOD, log=logs.append, clock=clock, sleep=clock.sleep)
        self.assertGreater(stats['turns'], 1)
        self.assertGreater(stats['waitedSeconds'], 0)
        self.assertTrue(any('轮' in x and '等待' in x for x in logs))


class OnlineRunFollowUpTests(unittest.TestCase):
    def test_note_of_a_check_without_problems_is_not_shown(self):
        # R11 had no problem this month; the table still showed last month's note naming an unhealthy scale set
        from azinspect.waf.report import check_note, notes_without_findings
        self.assertEqual(check_note([], {'attempted': 3, 'succeeded': 3}, 'vmss-a 的健康状态为 Unknown。'), '未发现问题')
        self.assertEqual(notes_without_findings({'R11': 'x', 'R1': 'y'}, [{'check': 'R1'}], {'R11': {'attempted': 1, 'succeeded': 1}}), ['R11'])
        self.assertEqual(check_note([], {'attempted': 3, 'succeeded': 2, 'otherErrors': 1}, '客户已确认'), '客户已确认；部分读取失败，结果可能不完整')

    def test_p5_resource_types_are_arm_types(self):
        # P5 rows typed 'redis' and 'Microsoft.Cache/Redis' counted one cache twice in the 04 table
        from azinspect.waf.performance.analyze import CACHE_TYPES
        self.assertEqual(CACHE_TYPES['redis'], 'Microsoft.Cache/Redis')
        self.assertEqual(CACHE_TYPES['redisenterprise'], 'Microsoft.Cache/redisEnterprise')
        self.assertEqual(CACHE_TYPES['mongoclusters'], 'Microsoft.DocumentDB/mongoClusters')

    def test_activity_log_read_in_parallel_windows(self):
        # 606 pages of failed operations were read one after another (21 minutes, no throttling)
        import importlib
        from types import SimpleNamespace
        rc = importlib.import_module('azinspect.waf.reliability.collect')
        urls, saved = [], {}

        def get_all(url, check, target='', max_pages=None, report_truncation=True, **kw):
            urls.append(url)
            return [{'eventTimestamp': '2026-10-05T00:00:00Z', 'operationName': {'value': 'op'}, 'status': {'value': 'Failed'},
                     'correlationId': f'c{len(urls)}'}], 200, None
        c = object.__new__(rc._Collector)
        c.c, c.subs = SimpleNamespace(get_all=get_all), [{'id': 's1', 'name': 'sub1'}]
        c.window = {'start': '2026-10-01T00:00:00Z', 'snapshot': '2026-10-30'}
        c.raw = SimpleNamespace(save=lambda rel, obj: saved.update({rel: obj}))
        c.activity()
        self.assertEqual(len(urls), 15)          # 30 days in windows of two
        out = saved['activity/failed-ops.json']
        self.assertEqual(len(out), 1)
        self.assertEqual(len(out[0]['events']), 15)
        self.assertEqual(out[0]['status'], 200)


class ForecastNoteTests(unittest.TestCase):
    def test_no_forecast_rows_is_not_a_failed_read(self):
        # 01 said "7 个订阅的预测读取失败（如接口限流）" though 5 returned no forecast rows and all 7 had no cost
        from azinspect.cost.report import forecast_note
        subs = [{'next': {'status': 'noForecastRows', 'fullMonthEstimate': None}} for _ in range(5)] + \
               [{'next': {'status': 'error', 'fullMonthEstimate': None}} for _ in range(2)] + \
               [{'next': {'status': 'skipped', 'fullMonthEstimate': None}} for _ in range(3)]
        text = forecast_note({'forecast': {'subscriptions': subs}}, '10月')
        self.assertIn('2个订阅的预测读取失败', text)
        self.assertIn('5个订阅没有返回预测结果', text)
        self.assertIn('3个订阅10月无费用，未读取预测', text)

    def test_subscriptions_without_cost_are_not_forecast(self):
        # 20 minutes of retries ended with two throttled subscriptions that had no cost this month
        from azinspect.cost.supplement_costs import with_cost
        ref = {('a', 'cur'): 120.0, ('b', 'cur'): 0.0, ('c', 'prev'): 5.0}
        self.assertEqual(with_cost(['a', 'b', 'c'], ref), ['a'])

    def test_retry_round_reports_progress(self):
        from azinspect.core.reuse import Reuse
        from azinspect.cost import supplement_costs as sc
        from test_throttle import PERIOD, SUBS, Clock, ForecastApi
        clock = Clock()
        api = ForecastApi(clock, [(6, 1100)])
        logs = []
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            run = sc.Runner(ws, api, SUBS, 'USD', Reuse(False))
            left = sc.forecast_first_pass(run, [s['id'] for s in SUBS], PERIOD)
            sc.forecast_retry(run, left, PERIOD, log=logs.append, clock=clock, sleep=clock.sleep)
        self.assertTrue(any('仍在补读' in x for x in logs))


class SecurityNodeOsWordingTests(unittest.TestCase):
    def test_s_i3_uses_the_same_wording(self):
        # S-I3 still wrote "节点 OS 升级通道为 None" while the rest of the reports said "不自动更新"
        import inspect
        from azinspect.waf.security_identity import checks_aks
        src = inspect.getsource(checks_aks)
        self.assertNotIn('节点 OS 升级通道为 {channel}', src)
        self.assertIn('node_os_text(channel)', src)


class Rc1OnlineFollowUpTests(unittest.TestCase):
    def test_activity_windows_use_le_only(self):
        # the activity log API rejects "lt": BadRequest "The comparison operator: lt for the id property is not supported."
        import importlib
        from types import SimpleNamespace
        from urllib.parse import unquote
        rc = importlib.import_module('azinspect.waf.reliability.collect')
        urls = []

        def get_all(url, check, target='', max_pages=None, report_truncation=True, **kw):
            urls.append(unquote(url))
            return [], 200, None
        c = object.__new__(rc._Collector)
        c.c, c.subs = SimpleNamespace(get_all=get_all), [{'id': 's1', 'name': 'sub1'}]
        c.window = {'start': '2026-10-01T00:00:00Z', 'snapshot': '2026-10-30'}
        c.raw = SimpleNamespace(save=lambda rel, obj: None)
        c.activity()
        self.assertFalse(any(' lt ' in u for u in urls))
        bounds = sorted((u.split("ge '")[1][:20], u.split("le '")[1][:20]) for u in urls)
        for (a1, b1), (a2, _b2) in zip(bounds, bounds[1:]):
            self.assertLess(b1, a2)          # no overlap: one second apart

    def test_narrow_filter_is_also_read_in_windows(self):
        import importlib
        from types import SimpleNamespace
        from urllib.parse import parse_qs, urlparse
        pc = importlib.import_module('azinspect.waf.performance.collect')

        def request(method, url, check, target='', body=None, **kw):
            q = parse_qs(urlparse(url).query)
            whole = (q['starttime'][0], q['endtime'][0]) == ('2026-10-01T00:00:00Z', '2026-10-31T00:00:00Z')
            if 'Ready' not in q.get('filter', [''])[0] or whole:
                return 529, None, 'Throttled'
            ts = [{'metadatavalues': [], 'data': [{'timeStamp': q['starttime'][0], 'average': 1}]}]
            return 200, {'values': [{'resourceid': r, 'value': [{'name': {'value': 'm'}, 'errorCode': 'Success', 'timeseries': ts}]}
                                    for r in body['resourceids']]}, None
        c = object.__new__(pc.Collector)
        c.client, c.log, c.start, c.end, c.denied = SimpleNamespace(request=request), (lambda *_: None), '2026-10-01T00:00:00Z', '2026-10-31T00:00:00Z', set()
        c.raw = SimpleNamespace(save=lambda rel, obj: None)
        res = c.batch_metrics('aks-nodecond', 'P2', [{'id': '/subscriptions/s/x/c1', 'subscriptionId': 's', 'location': 'regiona'}], 'ns',
                              ['m'], 'average', narrow="condition eq 'Ready'")
        r = res['/subscriptions/s/x/c1']
        self.assertEqual(r['_narrowed'], "condition eq 'Ready'")
        self.assertEqual(len(r['m'][0]['data']), 3)


class TruncatedReadTests(unittest.TestCase):
    # the activity log stopped after 600 pages and the read counted as complete: one subscription's 30 days covered
    # about 5 (an earlier collection) and a failed operation was missed
    def test_truncated_paging_is_a_failed_read_in_the_call_log(self):
        from types import SimpleNamespace
        from azinspect.core import http
        n = [0]

        class Resp:
            def __init__(self, body):
                self.status, self.body = 200, body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return self.body

        def opener(req, timeout):
            n[0] += 1
            return Resp(('{"value": [{"a": %d}], "nextLink": "https://management.azure.com/subscriptions/s/next%d"}' % (n[0], n[0])).encode())
        client = http.ReadOnlyClient(SimpleNamespace(get=lambda a: 't'), opener=SimpleNamespace(open=opener))
        items, status, error = client.get_all('/subscriptions/s/x?api-version=1', 'R12', 'sub', max_pages=3)
        self.assertEqual(len(items), 3)
        self.assertIn('truncated', error)
        last = client.calls[-1]
        self.assertEqual((last['check'], last['status']), ('R12', None))
        self.assertIn('truncated', last['error'])
        from azinspect.waf.common import plain_error
        self.assertIn('只读到最近的一部分', plain_error(None, last['error']))

    def test_truncated_activity_windows_are_split(self):
        import importlib
        from types import SimpleNamespace
        from urllib.parse import unquote
        rc = importlib.import_module('azinspect.waf.reliability.collect')
        recorded, saved = [], {}

        def get_all(url, check, target='', max_pages=None, report_truncation=True, **kw):
            u = unquote(url)
            a, b = u.split("ge '")[1][:19], u.split("le '")[1][:19]
            from datetime import datetime
            hours = (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 3600
            ev = [{'eventTimestamp': b + 'Z', 'operationName': {'value': 'op'}, 'status': {'value': 'Failed'}, 'correlationId': a}]
            return (ev, 200, 'truncated after 600 pages') if hours > 30 else (ev, 200, None)
        c = object.__new__(rc._Collector)
        c.c = SimpleNamespace(get_all=get_all, record=lambda *a, **k: recorded.append(a))
        c.subs = [{'id': 's1', 'name': 'sub1'}]
        c.window = {'start': '2026-10-01T00:00:00Z', 'snapshot': '2026-10-30'}
        c.raw = SimpleNamespace(save=lambda rel, obj: saved.update({rel: obj}))
        c.activity()
        out = saved['activity/failed-ops.json'][0]
        self.assertEqual(out['status'], 200)
        self.assertFalse(out.get('truncated'))
        self.assertEqual(recorded, [])
        self.assertGreater(len(out['events']), 15)

    def test_r12_says_what_was_not_read(self):
        from types import SimpleNamespace
        import importlib
        ra = importlib.import_module('azinspect.waf.reliability.analyze')
        from azinspect.waf.common import coverage_entry
        files = {'activity/failed-ops.json': [{'subscriptionId': 's', 'subscriptionName': 'sub1', 'status': 200, 'error': None, 'events': [],
                                                'truncated': [['2026-10-01T00:00:00Z', '2026-10-01T05:00:00Z']]}]}
        run = SimpleNamespace(raw=SimpleNamespace(load=lambda rel, default=None: files.get(rel, default)), coverage={'R12': coverage_entry()},
                              window={'start': '2026-10-01T00:00:00Z', 'end': '2026-10-31T00:00:00Z', 'snapshot': '2026-10-30', 'days': 30},
                              cover=lambda *a: None, add=lambda *a, **k: {}, inventory={}, subname=lambda x: 'sub1',
                              env=lambda *a, **k: {'value': 'prod', 'label': '生产', 'basis': ''})
        ra.r12(run)
        self.assertTrue(any('sub1' in x and '10-01' in x for x in run.coverage['R12'].get('limits') or []))
        # data collected before 0.10.9: only the error says the paging was cut off
        files['activity/failed-ops.json'] = [{'subscriptionId': 's', 'subscriptionName': 'sub1', 'status': 200, 'error': 'truncated after 600 pages',
                                              'events': [{'t': '2026-10-30T01:00:00Z', 'op': 'x'}, {'t': '2026-11-03T01:00:00Z', 'op': 'x'}]}]
        run.coverage = {'R12': coverage_entry()}
        ra.r12(run)
        self.assertEqual(run.coverage['R12']['otherErrors'], 1)
        self.assertTrue(any('10-30 至 11-03' in x for x in run.coverage['R12']['limits']))


class ActivitySpeedTests(unittest.TestCase):
    # the activity log of one subscription took about an hour: windows of five days, and a window cut off at 600 pages
    # was dropped and read again in halves from the start
    def run_activity(self, get_all):
        import importlib
        from types import SimpleNamespace
        rc = importlib.import_module('azinspect.waf.reliability.collect')
        saved = {}
        c = object.__new__(rc._Collector)
        c.c = SimpleNamespace(get_all=get_all, record=lambda *a, **k: None)
        c.subs = [{'id': 's1', 'name': 'sub1'}]
        c.window = {'start': '2026-10-01T00:00:00Z', 'snapshot': '2026-10-30'}
        c.raw = SimpleNamespace(save=lambda rel, obj: saved.update({rel: obj}))
        c.activity()
        return saved['activity/failed-ops.json'][0], rc

    def test_windows_of_about_two_days(self):
        from urllib.parse import unquote
        from datetime import datetime
        spans = []

        def get_all(url, check, target='', max_pages=None, report_truncation=True, **kw):
            u = unquote(url)
            spans.append((datetime.fromisoformat(u.split("ge '")[1][:19]), datetime.fromisoformat(u.split("le '")[1][:19])))
            return [], 200, None
        self.run_activity(get_all)
        self.assertGreaterEqual(len(spans), 15)
        self.assertTrue(all((b - a).total_seconds() <= 2 * 86400 for a, b in spans))

    def test_cut_off_window_continues_from_the_earliest_event(self):
        from urllib.parse import unquote
        from datetime import datetime, timedelta
        fmt = '%Y-%m-%dT%H:%M:%SZ'
        calls, earliest = [], {}

        def get_all(url, check, target='', max_pages=None, report_truncation=True, **kw):
            u = unquote(url)
            a, b = u.split("ge '")[1][:20], u.split("le '")[1][:20]
            calls.append((a, b))
            if a not in earliest:      # first read of a window: cut off after reading its newest day
                ev = (datetime.strptime(b, fmt) - timedelta(days=1)).strftime(fmt)
                earliest[a] = ev
                return [{'eventTimestamp': ev, 'operationName': {'value': 'op'}, 'status': {'value': 'Failed'}, 'correlationId': b}], 200, 'truncated after 600 pages'
            return [{'eventTimestamp': a, 'operationName': {'value': 'op'}, 'status': {'value': 'Failed'}, 'correlationId': a + 'x'}], 200, None
        out, rc = self.run_activity(get_all)
        seconds = {}
        for a, b in calls:
            seconds.setdefault(a, []).append(b)
        for a, bs in seconds.items():
            self.assertEqual(len(bs), 2)
            self.assertEqual(bs[1], (datetime.strptime(earliest[a], fmt) - timedelta(seconds=1)).strftime(fmt))
        self.assertFalse(out.get('truncated'))
        self.assertEqual(len(out['events']), 2 * len(seconds))

class ActivityTimeLimitTests(unittest.TestCase):
    # one large subscription read its activity log for more than ten hours: the API pages through every event and
    # cannot filter on status, so each subscription now stops at a time limit and says which days were not read
    def setUp(self):
        import importlib
        self.rc = importlib.import_module('azinspect.waf.reliability.collect')
        self.old = (self.rc._clock, self.rc.ACTIVITY_WORKERS)
        self.now = [0.0]
        self.rc._clock = lambda: self.now[0]
        self.rc.ACTIVITY_WORKERS = 1             # one window after another: the clock is predictable

    def tearDown(self):
        self.rc._clock, self.rc.ACTIVITY_WORKERS = self.old

    def run_activity(self, get_all, recorded):
        from types import SimpleNamespace
        saved = {}
        c = object.__new__(self.rc._Collector)
        c.c = SimpleNamespace(get_all=get_all, record=lambda *a, **k: recorded.append(a))
        c.subs = [{'id': 's1', 'name': 'sub1'}]
        c.window = {'start': '2026-10-01T00:00:00Z', 'snapshot': '2026-10-30'}
        c.raw = SimpleNamespace(save=lambda rel, obj: saved.update({rel: obj}))
        c.activity()
        return saved['activity/failed-ops.json'][0]

    def test_stops_at_the_time_limit_newest_days_first(self):
        from urllib.parse import unquote
        from datetime import datetime, timedelta
        fmt = '%Y-%m-%dT%H:%M:%SZ'
        calls, recorded = [], []

        def get_all(url, check, target='', max_pages=None, report_truncation=True, deadline=None, **kw):
            u = unquote(url)
            a, b = u.split("ge '")[1][:20], u.split("le '")[1][:20]
            calls.append((a, b, deadline))
            self.now[0] += 1000                  # each window takes 1000 s; the limit passes during the second
            if self.now[0] >= deadline:
                ev = (datetime.strptime(b, fmt) - timedelta(hours=6)).strftime(fmt)
                return [{'eventTimestamp': ev, 'operationName': {'value': 'op'}, 'status': {'value': 'Failed'}, 'correlationId': b}], 200, 'truncated after 9 pages'
            return [{'eventTimestamp': b, 'operationName': {'value': 'op'}, 'status': {'value': 'Failed'}, 'correlationId': b}], 200, None
        out = self.run_activity(get_all, recorded)
        self.assertEqual(len(calls), 2)                              # windows after the limit are not read
        self.assertTrue(calls[0][1].startswith('2026-10-30T23:59:59'))   # newest days first
        self.assertEqual(calls[0][2], self.rc.ACTIVITY_MAX_SECONDS)  # one deadline per subscription
        self.assertTrue(out['timeLimited'])
        self.assertEqual(len(out['events']), 2)                      # what was read is kept
        # one merged range of unread days: from the start of the month to just before the earliest event read
        self.assertEqual(len(out['truncated']), 1)
        self.assertEqual(out['truncated'][0][0], '2026-10-01T00:00:00Z')
        self.assertTrue(out['truncated'][0][1] < calls[1][1])
        self.assertEqual(len(recorded), 1)                           # a failed read in the call log
        from azinspect.waf.common import plain_error
        self.assertIn('在时限内没有读完', plain_error(None, recorded[0][4]))

    def test_get_all_stops_at_deadline(self):
        from azinspect.core import http
        pages = []

        class Fake:
            def get(self, url, check, target='', **kw):
                pages.append(url)
                return 200, {'value': [1], 'nextLink': 'https://x/next'}, None
            record = lambda *a, **k: None
        fake = Fake()
        items, status, error = http.ReadOnlyClient.get_all(fake, 'https://x/first', 'R12', max_pages=600, report_truncation=False, deadline=0)
        self.assertEqual(len(pages), 1)
        self.assertEqual(items, [1])
        self.assertIn('truncated', error)
        self.assertIn('time limit', error)

    def test_r12_names_the_unread_days(self):
        from types import SimpleNamespace
        import importlib
        ra = importlib.import_module('azinspect.waf.reliability.analyze')
        from azinspect.waf.common import coverage_entry
        files = {'activity/failed-ops.json': [{'subscriptionId': 's', 'subscriptionName': 'sub1', 'status': 200, 'error': None, 'events': [],
                                                'timeLimited': True, 'truncated': [['2026-10-01T00:00:00Z', '2026-10-20T05:00:00Z']]}]}
        run = SimpleNamespace(raw=SimpleNamespace(load=lambda rel, default=None: files.get(rel, default)), coverage={'R12': coverage_entry()},
                              window={'start': '2026-10-01T00:00:00Z', 'end': '2026-10-31T00:00:00Z', 'snapshot': '2026-10-30', 'days': 30},
                              cover=lambda *a: None, add=lambda *a, **k: {}, inventory={}, subname=lambda x: 'sub1',
                              env=lambda *a, **k: {'value': 'prod', 'label': '生产', 'basis': ''})
        ra.r12(run)
        text = ' '.join(run.coverage['R12'].get('limits') or [])
        self.assertIn('30 分钟内没有读完', text)
        self.assertIn('只读到约 259 小时（10-20 05:00 至 10-30 23:59）的失败操作', text)   # what was read, not a list of gaps
        # read before the snapshot day ended: the last period stops when the log was read (76 hours said, about 66 read)
        files['manifest.json'] = {'collectedAt': '2026-10-30T14:31:40+00:00'}
        run.coverage = {'R12': coverage_entry()}
        ra.r12(run)
        self.assertIn('只读到约 250 小时（10-20 05:00 至 10-30 14:31）', ' '.join(run.coverage['R12']['limits']))
        files['activity/failed-ops.json'][0]['readAt'] = '2026-10-30T14:00:00+00:00'   # 0.10.9: recorded when the log was read
        run.coverage = {'R12': coverage_entry()}
        ra.r12(run)
        self.assertIn('10-20 05:00 至 10-30 14:00', ' '.join(run.coverage['R12']['limits']))


class StuckRequestTests(unittest.TestCase):
    # 0.10.9 online: two activity log requests ran almost six hours each (the server kept sending a little), the 30-minute
    # limit was only checked between pages and the 120 s socket timeout never fired
    class Resp:
        def __init__(self, clock, step):
            self.clock, self.step, self.status = clock, step, 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read1(self, n=-1):
            self.clock[0] += self.step       # a few bytes, slowly, never the end
            return b' '

    def client(self, clock, step):
        from azinspect.core import http
        resp = self.Resp(clock, step)
        opener = type('O', (), {'open': lambda self_, req, timeout=None: resp})()
        tokens = type('T', (), {'get': lambda self_, aud: 'x'})()
        return http.ReadOnlyClient(tokens, opener=opener)

    URL = 'https://management.azure.com/subscriptions/s/resourcegroups?api-version=2021-04-01'

    def test_one_request_stops_at_its_total_time(self):
        from unittest import mock
        clock = [0.0]
        c = self.client(clock, 30)
        with mock.patch('azinspect.core.http.time.monotonic', lambda: clock[0]), mock.patch('azinspect.core.http.time.sleep', lambda s: None):
            status, data, error = c.get(self.URL, 'X', max_attempts=2, max_seconds=300)
        self.assertIsNone(status)
        self.assertIn('timed out', error)
        self.assertLess(clock[0], 2 * 300 + 120)   # two attempts at most, each cut at its limit

    def test_a_deadline_stops_the_request_without_retries(self):
        from unittest import mock
        clock = [0.0]
        c = self.client(clock, 30)
        with mock.patch('azinspect.core.http.time.monotonic', lambda: clock[0]), mock.patch('azinspect.core.http.time.sleep', lambda s: None):
            items, status, error = c.get_all(self.URL, 'R12', max_pages=600, report_truncation=False, deadline=100)
        self.assertEqual(items, [])                     # nothing read, but not a failed read: the time limit
        self.assertIn('time limit', error)
        self.assertEqual(c.calls[-1]['attempts'], 1)
        self.assertLess(clock[0], 200)


class R12ReasonTests(unittest.TestCase):
    def run_r12(self, entry, calls=(), manifest=None):
        from types import SimpleNamespace
        import importlib
        ra = importlib.import_module('azinspect.waf.reliability.analyze')
        from azinspect.waf.common import coverage_entry
        files = {'activity/failed-ops.json': [entry], 'manifest.json': manifest}
        run = SimpleNamespace(raw=SimpleNamespace(load=lambda rel, default=None: files.get(rel, default)), coverage={'R12': coverage_entry()},
                              window={'start': '2026-10-01T00:00:00Z', 'end': '2026-10-31T00:00:00Z', 'snapshot': '2026-10-30', 'days': 30},
                              cover=lambda *a: None, add=lambda *a, **k: {}, inventory={}, subname=lambda x: 'sub1', calls=list(calls),
                              env=lambda *a, **k: {'value': 'prod', 'label': '生产', 'basis': ''})
        ra.r12(run)
        return ' '.join(run.coverage['R12'].get('limits') or [])

    def test_failed_read_is_not_too_many_records(self):
        # a subscription answering 401 was written as "活动日志记录太多，在 30 分钟内没有读完……只读到约 279 小时"
        text = self.run_r12({'subscriptionId': 's', 'subscriptionName': 'sub1', 'status': 401, 'error': 'HTTP 401', 'events': None,
                             'timeLimited': True, 'truncated': [['2026-10-01T00:00:00Z', '2026-10-20T00:00:00Z']]})
        self.assertNotIn('记录太多', text)

    def test_nothing_read_in_time(self):
        text = self.run_r12({'subscriptionId': 's', 'subscriptionName': 'sub1', 'status': 200, 'error': None, 'events': [],
                             'timeLimited': True, 'truncated': [['2026-10-01T00:00:00Z', '2026-10-30T23:59:59Z']]})
        self.assertIn('在 30 分钟内没有读到任何记录', text)
        self.assertNotIn('记录太多', text)

    def test_read_period_ends_when_reading_began(self):
        # the collection ended the next day, so "read until" became the end of the window: about 7 hours too many
        calls = [{'check': 'R12', 'target': 'sub1', 'at': '2026-10-30T16:45:00Z', 'elapsed': 240},
                 {'check': 'R12', 'target': 'sub1', 'at': '2026-10-31T02:30:00Z', 'elapsed': 30000}]
        text = self.run_r12({'subscriptionId': 's', 'subscriptionName': 'sub1', 'status': 200, 'error': None, 'events': [{'t': 'x'}],
                             'timeLimited': True, 'readAt': '2026-10-31T02:30:30+00:00',
                             'truncated': [['2026-10-01T00:00:00Z', '2026-10-30T10:00:00Z']]},
                            calls, {'collectedAt': '2026-10-31T02:31:00+00:00'})
        self.assertIn('10-30 10:00 至 16:41', text)      # reading began at 16:41 (the first request's start)
        text = self.run_r12({'subscriptionId': 's', 'subscriptionName': 'sub1', 'status': 200, 'error': None, 'events': [{'t': 'x'}],
                             'timeLimited': True, 'readStart': '2026-10-30T16:00:00Z',
                             'truncated': [['2026-10-01T00:00:00Z', '2026-10-30T10:00:00Z']]})
        self.assertIn('10-30 10:00 至 16:00', text)
        self.assertIn('的活动日志在 30 分钟内没有读完', text)   # not "记录太多": a slow answer looks the same
        self.assertNotIn('记录太多', text)


class StoppedAtLimitWordingTests(unittest.TestCase):
    def test_stop_at_time_limit_is_not_an_api_error(self):
        # 0.10.10 rc1 online: "8 次读取：接口报错（HTTP None：stopped at time limit）" in the Excel coverage page
        from azinspect.waf.common import plain_error
        text = plain_error(None, 'stopped at time limit', 8)
        self.assertNotIn('接口报错', text)
        self.assertNotIn('stopped', text)
        self.assertNotIn('None', text)
        self.assertIn('时限', text)


class R5StoppedServerTests(unittest.TestCase):
    def test_stopped_server_is_not_a_failover_problem(self):
        # a stopped PostgreSQL server: "高可用状态为 ，当前不能保证故障切换" as 高
        from types import SimpleNamespace
        import importlib
        ra = importlib.import_module('azinspect.waf.reliability.analyze')
        from azinspect.waf.common import coverage_entry
        added = []
        server = {'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg1', 'name': 'pg1',
                  'resourceGroup': 'rg', 'tags': {}, 'sku': {'name': 'D4', 'tier': 'GeneralPurpose'},
                  'properties': {'state': 'Stopped', 'highAvailability': {'mode': 'ZoneRedundant', 'state': ''},
                                 'backup': {'backupRetentionDays': 14, 'geoRedundantBackup': 'Enabled'}}}
        run = SimpleNamespace(rows=lambda kind: [server] if kind == 'postgres' else [], coverage={'R5': coverage_entry()},
                              cover=lambda *a: None, add=lambda *a, **k: added.append(a) or {}, inventory={}, subname=lambda x: 'sub1',
                              env=lambda *a, **k: {'value': 'prod', 'label': '生产', 'basis': ''}, raw=SimpleNamespace(load=lambda *a, **k: None))
        try:
            ra.r5(run)
        except Exception:
            pass                                          # later parts of R5 need more inventory; the HA rows come first
        self.assertFalse([a for a in added if a[1] == '高'], added)


class MergedRowIdTests(unittest.TestCase):
    def test_subnet_full_row_does_not_depend_on_failure_counts(self):
        # the same three node pools got another id each month as their failure counts changed order
        from types import SimpleNamespace
        import importlib
        ra = importlib.import_module('azinspect.waf.reliability.analyze')
        from azinspect.waf.common import coverage_entry

        def ids(counts):
            events = [{'t': f'2026-10-0{i}T00:00:00Z', 'op': 'Microsoft.Compute/virtualMachineScaleSets/write', 'resourceId': f'/subscriptions/s/resourceGroups/rg/providers/x/{name}',
                       'statusMessage': '{"code": "SubnetIsFull"}'} for name, n in counts for i in range(1, n + 1)]
            files = {'activity/failed-ops.json': [{'subscriptionId': 's', 'subscriptionName': 'sub1', 'status': 200, 'error': None, 'events': events}]}
            added = []
            run = SimpleNamespace(raw=SimpleNamespace(load=lambda rel, default=None: files.get(rel, default)), coverage={'R12': coverage_entry()},
                                  window={'start': '2026-10-01T00:00:00Z', 'snapshot': '2026-10-30'}, cover=lambda *a: None, inventory={},
                                  add=lambda *a, **k: added.append(a[2]) or {}, subname=lambda x: 'sub1',
                                  env=lambda *a, **k: {'value': 'prod', 'label': '生产', 'basis': ''})
            ra.r12(run)
            return added
        self.assertEqual(ids([('pool-b', 5), ('pool-a', 1)]), ids([('pool-b', 1), ('pool-a', 5)]))


class MySql84CalendarTests(unittest.TestCase):
    def test_mysql_84_is_in_the_calendar(self):
        # servers upgraded to 8.4 read as "不在支持日历中"
        from azinspect.waf.reliability.lifecycle import load_calendar
        _data, cal = load_calendar()
        self.assertIn(('mysql', '8.4'), cal)
        self.assertGreater(cal[('mysql', '8.4')]['end'], '2030-01-01')


class CrosscheckTypeMatchTests(unittest.TestCase):
    # X4 matched a PostgreSQL server and a Redis cache that share a name; X5 an idle NSG and a load balancer
    def test_x4_and_x5_match_the_resource_type(self):
        from azinspect import crosscheck
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-10')
            ws.create()
            io.write_json(ws.raw('cost/resources/databases.json'), {'resources': [
                {'name': 'app1', 'type': 'microsoft.cache/redis', 'subscriptionName': 's', 'flags': ['LOW_UTILIZATION']},
                {'name': 'app2', 'type': 'microsoft.cache/redis', 'subscriptionName': 's', 'flags': ['LOW_UTILIZATION']}]})
            perf = [{'id': 'P4-a', 'check': 'P4', 'severity': '中', 'finding': 'IOPS 打满', 'resourceName': 'app1',
                     'members': [{'name': 'app1', 'type': 'Microsoft.DBforPostgreSQL/flexibleServers'}]},
                    {'id': 'P5-b', 'check': 'P5', 'severity': '中', 'finding': '内存增长', 'resourceName': 'app2',
                     'members': [{'name': 'app2', 'type': 'Microsoft.Cache/Redis'}]},
                    {'id': 'P9-c', 'check': 'P9', 'severity': '中', 'finding': '前端不可用', 'resourceName': 'proxy',
                     'members': [{'name': 'proxy', 'type': 'Microsoft.Network/loadBalancers'}]}]
            io.write_json(ws.month_dir('findings') / 'waf' / 'performance.json', {'pillar': 'performance', 'findings': perf, 'complete': True})
            io.write_json(ws.raw('cost/review/results.json'), {'wasteFindings': [
                {'category': '未关联 NSG', 'name': 'proxy', 'resourceId': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/proxy'}]})
            self.assertEqual([i['resource'] for i in crosscheck.x4(ws)['items']], ['app2'])
            self.assertEqual(crosscheck.x5(ws)['items'], [])


class SmallOnlineFollowUpTests(unittest.TestCase):
    def test_cache_hit_rate_is_not_internal_wording(self):
        # quality-check flagged "缓存命中率" as the internal word "命中"
        from azinspect.core import quality

        def issues(text):
            with tempfile.TemporaryDirectory() as d:
                f = Path(d) / 'r.md'
                f.write_text(text, encoding='utf-8')
                return [x for x in quality.check_markdown(f) if '命中' in x]
        self.assertEqual(issues('# 报告\n\nRedis 缓存命中率 98%。\n'), [])
        self.assertTrue(issues('# 报告\n\n规则命中 3 项。\n'))

    def test_gateway_with_listeners_reads_as_to_confirm(self):
        # an application gateway with four public listeners was listed as idle
        from azinspect.cost.orphan import LABELS
        self.assertIn('需要确认用途', LABELS['application-gateways'])


class LogSourceFailureTests(unittest.TestCase):
    def test_failed_source_query_is_said(self):
        # three workspaces showed "-" as their main sources; one query had failed (400 BadArgumentError)
        from azinspect.cost.report import log_sources
        self.assertEqual(log_sources({'topDataTypeBreakdownError': 'HTTP 400'}), '来源查询失败')
        self.assertEqual(log_sources({}), '-')
        self.assertIn('kube 2 GB', log_sources({'topDataTypeBreakdown': {'rows': [{'Category': 'kube', 'BilledGB': 2.0}]}}))


class RunningHoursTests(unittest.TestCase):
    # 02 priced every running machine at 730 hours a month: autoscaled nodes running part of the week inflated the RI/SP saving
    def test_running_share_from_sample_coverage(self):
        from azinspect.vm.rules import running_share
        vms = [{'kind': 'vm', 'metrics': {'Percentage CPU': {'sampleCount': 1000, 'coverage': 1.0}}},
               {'kind': 'vm', 'metrics': {'Percentage CPU': {'sampleCount': 250, 'coverage': 0.25}}},
               {'kind': 'vmss', 'metrics': {'Percentage CPU': {'sampleCount': 30, 'coverage': None}}},
               {'kind': 'vmss', 'metrics': {'Percentage CPU': {'sampleCount': 120, 'coverage': None}}},
               {'kind': 'vm', 'metrics': {}}]
        shares = running_share(vms)
        self.assertEqual(shares[:2], [1.0, 0.25])
        self.assertAlmostEqual(shares[2], 0.25)          # no reference in its group: largest count of its kind
        self.assertEqual(shares[4], 1.0)                 # nothing known: a whole month, as before

    def test_no_samples_or_a_few_missing_is_a_whole_month(self):
        # rc5: running machines with no samples were priced at 0 hours; a few missing samples lowered whole-week machines
        from azinspect.vm.rules import running_share
        vms = [{'kind': 'vm', 'metrics': {'Percentage CPU': {'sampleCount': 0, 'coverage': 0.0}}},
               {'kind': 'vm', 'metrics': {'Percentage CPU': {'sampleCount': 996, 'coverage': 0.996}}},
               {'kind': 'vm', 'metrics': {'Percentage CPU': {'sampleCount': 1000, 'coverage': 1.0}}}]
        self.assertEqual(running_share(vms), [1.0, 1.0, 1.0])

    def test_kept_wording_passes_quality(self):
        # rc5: the kept status and reason used an internal word and failed quality-check
        from azinspect.core.quality import BANNED
        from azinspect.vm.rules import KEPT, apply_keep
        recs = [{'subscriptionName': 's', 'name': 'a', 'status': '建议试点调整', 'reasons': []}]
        apply_keep(recs, [{'subscription': 's', 'namePrefix': 'a', 'note': 'n', 'keep': True}])
        for text in [KEPT, recs[0]['reasons'][-1]]:
            self.assertFalse([w for w in BANNED if w in text], text)

    def test_commitments_only_where_cheaper(self):
        from azinspect.vm.table import portfolio_totals
        full = {'running': True, 'currentMonthlyPAYG': 100.0, 'costs': {'payg': 100.0, 'ri1': 60.0, 'ri3': 40.0, 'sp1': 70.0, 'sp3': 50.0}}
        part = {'running': True, 'currentMonthlyPAYG': 25.0, 'costs': {'payg': 25.0, 'ri1': 60.0, 'ri3': 40.0, 'sp1': 70.0, 'sp3': 50.0}}
        out = portfolio_totals([full, part])
        plans = {p['key']: p for p in out['plans']}
        self.assertEqual(out['currentMonthly'], 125.0)
        self.assertEqual(plans['ri1']['monthlyCost'], 85.0)         # RI for the full-time machine, on demand for the other
        self.assertIn('1 台', plans['ri1']['note'])


class KeepNoteTests(unittest.TestCase):
    def test_kept_machines_leave_the_recommendation(self):
        # machines a crosscheck note keeps were still counted in 02's machines and saving
        from azinspect.vm.rules import apply_keep
        recs = [{'subscriptionName': 's', 'name': 'viz-1', 'status': '建议试点调整', 'targetSKU': 'E4', 'monthlySavingsUSD': 50.0, 'reasons': []},
                {'subscriptionName': 's', 'name': 'app-1', 'status': '建议试点调整', 'targetSKU': 'D2', 'monthlySavingsUSD': 30.0, 'reasons': []}]
        apply_keep(recs, [{'subscription': 's', 'namePrefix': 'viz', 'note': '04 显示磁盘带宽打满', 'keep': True},
                          {'subscription': 's', 'namePrefix': 'app', 'note': '只是提醒'}])
        self.assertEqual(recs[0]['status'], '暂不调整：结合其他检查结果保持原规格')
        self.assertEqual((recs[0]['targetSKU'], recs[0]['monthlySavingsUSD']), (None, 0))
        self.assertIn('04 显示磁盘带宽打满', recs[0]['reasons'][-1])
        self.assertEqual(recs[1]['status'], '建议试点调整')

    def test_stale_keep_named(self):
        # a keep note written after analyze: build says to rerun analyze
        from azinspect.vm.rules import stale_keep
        recs = [{'subscriptionName': 's', 'name': 'viz-1', 'status': '建议试点调整'}]
        notes = [{'subscription': 's', 'namePrefix': 'viz', 'keep': True}, {'subscription': 's', 'namePrefix': 'app', 'keep': True}]
        self.assertEqual(stale_keep(recs, notes), ['s/viz'])
        recs[0]['status'] = '暂不调整：结合其他检查结果保持原规格'
        self.assertEqual(stale_keep(recs, notes), [])


class KeptNoteWordingTests(unittest.TestCase):
    def test_kept_note_once_without_doubled_punctuation(self):
        # rc7: the note column of a kept machine repeated the narrative note and read "。；"
        from azinspect.vm.rules import apply_keep
        from azinspect.vm.table import extra_note
        from azinspect.vm.wording import customer_note
        rec = {'subscriptionName': 's', 'name': 'a1', 'status': '建议试点调整', 'state': 'PowerState/running', 'kind': 'vm',
               'candidate': {'sku': 'D8', 'direction': 'CPU与内存减半'}, 'reasons': [], 'currentCores': 4, 'currentMemoryGiB': 16}
        notes = [{'subscription': 's', 'namePrefix': 'a', 'note': '月底有批量任务，暂不调整。', 'keep': True}]
        apply_keep([rec], notes)
        text = customer_note(rec, {}, None) + ''.join('；' + x for x in extra_note({'subscriptionName': 's', 'name': 'a1'}, notes))
        self.assertEqual(text.count('月底有批量任务'), 1, text)
        self.assertNotIn('。；', text)
        self.assertNotIn('。', text[-1])


class AzureReferenceTests(unittest.TestCase):
    # 02 counts the last week as the month; Azure's own recommendations (30 days, customer prices) go next to it
    COMMITMENTS = {
        'recommendationStatus': {'S1|RI|VirtualMachines': {'ok': True}, 'S1|SP|P1Y': {'ok': True}, 'S2|RI|VirtualMachines': {'ok': False}},
        'recommendations': [
            {'kind': '预留实例', 'subscription': 'a', 'resourceType': 'VirtualMachines', 'term': 'P1Y', 'saving': 100.0, 'quantity': 3},
            {'kind': '预留实例', 'subscription': 'a', 'resourceType': 'VirtualMachines', 'term': 'P1Y', 'saving': 50.0, 'quantity': 2},
            {'kind': '预留实例', 'subscription': 'a', 'resourceType': 'PostgreSQL', 'term': 'P1Y', 'saving': 999.0},
            {'kind': '节省计划', 'subscription': 'a', 'resourceType': 'Compute_Savings_Plan', 'term': 'P1Y', 'saving': 80.0, 'quantity': 1.5},
            {'kind': '节省计划', 'subscription': 'a', 'resourceType': 'Database_Savings_Plan', 'term': 'P1Y', 'saving': 60.0, 'quantity': 0.5},
            {'kind': '预留实例', 'subscription': 'other', 'resourceType': 'VirtualMachines', 'term': 'P1Y', 'saving': 7.0}]}

    def test_reference_sums_virtual_machine_ri_and_sp_for_02_subscriptions(self):
        from azinspect.vm.table import azure_reference
        ref = azure_reference(self.COMMITMENTS, [{'id': 's1', 'name': 'a'}, {'id': 's2', 'name': 'b'}])
        self.assertEqual(ref['plans']['ri1'], {'saving': 150.0, 'count': 2, 'quantity': 5.0})
        self.assertEqual(ref['plans']['sp1'], {'saving': 80.0, 'count': 1, 'quantity': 1.5})
        self.assertEqual(ref['plans']['ri3']['count'], 0)
        self.assertEqual((ref['read'], ref['tried']), (2, 3))
        self.assertIsNone(azure_reference(None, []))

    def test_02_and_00_text(self):
        from azinspect.core.quality import BANNED
        from azinspect.summary import azure_reference_note, azure_ri_row
        from azinspect.vm.report import azure_reference_lines
        from azinspect.vm.table import azure_reference
        ref = azure_reference(self.COMMITMENTS, [{'id': 's1', 'name': 'a'}, {'id': 's2', 'name': 'b'}])
        plans = [{'key': k, 'monthlySaving': 100.0 if k == 'payg' else 300.0} for k in ('payg', 'ri1', 'ri3', 'sp1', 'sp3')]
        text = '\n'.join(azure_reference_lines({'plans': plans, 'azureReference': ref}))
        self.assertIn('|1年RI（虚拟机）|5 台|150.00|200.00|300.00|', text)   # RI/SP alone: 02's plan less its rightsizing
        self.assertIn('|1年SP|每小时 USD 1.50|80.00|200.00|300.00|', text)
        self.assertIn('高于贵司实际价格', text)
        self.assertIn('|3年RI（虚拟机）|-|没有建议|200.00|300.00|', text)
        self.assertIn('2/3 次查询成功', text)
        missing = '\n'.join(azure_reference_lines({'plans': plans, 'azureReference': None}))
        self.assertIn('没有读取', missing)
        prices = {'azureReference': ref}
        # 00 section 1: Azure's own amount, not 02's estimate (one customer: 3,000 times Azure's)
        row = azure_ri_row(prices)
        self.assertEqual(row[0], '按 Azure 建议购买 1 年期虚拟机预留')
        self.assertIn('USD 150.00', row[1])
        self.assertIn('先降配', row[1])   # bought for the current sizes, then resized: sizes would not match
        self.assertIn('1 年期计算节省计划每月约省 USD 80.00', azure_reference_note(prices)[0])
        self.assertIsNone(azure_ri_row({}))
        for t in [text, missing, azure_reference_note(prices)[0], azure_reference_note({})[0]]:
            self.assertFalse([w for w in BANNED if w in t], t)


class NoReadingsWordingTests(unittest.TestCase):
    def test_no_readings_is_not_zero_days(self):
        # the sample's running machine without readings read "CPU/内存只有 0 天有效数据"
        from azinspect.vm.wording import customer_note
        rec = {'status': '数据不足：暂不能判断', 'state': 'PowerState/running', 'kind': 'vm', 'reasons': [], 'currentCores': 4, 'currentMemoryGiB': 16}
        vm = {'metrics': {'Percentage CPU': {'validDays': 0}, 'Available Memory Percentage': {'validDays': 0}}}
        text = customer_note(rec, vm)
        self.assertNotIn('0天', text.replace(' ', ''))
        self.assertIn('没有CPU/内存读数', text)
        vm['metrics']['Percentage CPU']['validDays'] = vm['metrics']['Available Memory Percentage']['validDays'] = 3
        self.assertIn('只有3天有效数据', customer_note(rec, vm))


class PlanExclusionTests(unittest.TestCase):
    # 02 priced RI/SP for every running machine as if on demand: also those already under RI/SP and Spot machines
    ROWS = [
        {'running': True, 'currentMonthlyPAYG': 100.0, 'costs': {'payg': 100.0, 'ri1': 60.0, 'ri3': 40.0, 'sp1': 70.0, 'sp3': 50.0}},
        {'running': True, 'currentMonthlyPAYG': 100.0, 'planExcluded': 'covered', 'costs': {'payg': 100.0, 'ri1': 60.0, 'ri3': 40.0, 'sp1': 70.0, 'sp3': 50.0}},
        {'running': True, 'currentMonthlyPAYG': 100.0, 'planExcluded': 'spot', 'costs': {'payg': 100.0, 'ri1': 60.0, 'ri3': 40.0, 'sp1': 70.0, 'sp3': 50.0}}]

    def test_excluded_machines_stay_on_demand_in_every_plan(self):
        from azinspect.vm.audit import plan_totals
        from azinspect.vm.table import plan_cost, plan_exclusion, portfolio_totals
        self.assertEqual(plan_cost(self.ROWS[1], 'ri1'), 100.0)
        out = portfolio_totals(self.ROWS)
        plans = {p['key']: p for p in out['plans']}
        self.assertEqual(plans['ri1']['monthlyCost'], 260.0)
        self.assertEqual(out['excluded'], {'covered': 1, 'spot': 1})
        self.assertIn('1 台已由 RI/SP 覆盖', plans['ri1']['note'])
        self.assertIn('1 台 Spot', plans['ri1']['note'])
        self.assertNotIn('Spot', plans['payg']['note'])
        self.assertEqual(plan_totals(self.ROWS), {p['key']: p['monthlyCost'] for p in out['plans']})
        self.assertEqual(plan_exclusion(0.5, {'priority': 'Regular'}), 'covered')
        self.assertEqual(plan_exclusion(0.2, {'priority': 'Spot'}), 'spot')
        self.assertIsNone(plan_exclusion(None, {}))


class KeepEffectTests(unittest.TestCase):
    def test_each_keep_note_says_how_many_machines_it_kept(self):
        # one wide prefix kept 314 machines where 29 had a conflict
        from azinspect.vm.rules import apply_keep, keep_effect
        recs = [{'subscriptionName': 's', 'name': f'es-{i}', 'status': '建议试点调整', 'monthlySavingsUSD': 10.0, 'reasons': []} for i in range(3)]
        notes = [{'subscription': 's', 'namePrefix': 'es-', 'note': 'x', 'keep': True}, {'subscription': 's', 'namePrefix': 'zz', 'keep': True}]
        apply_keep(recs, notes)
        self.assertEqual(keep_effect(recs, notes), [('s/es-', 3, 30.0, False, 0, 0.0), ('s/zz', 0, 0.0, False, 0, 0.0)])
        from azinspect.vm.pipeline import keep_line
        self.assertNotIn('同池', keep_line('s/a', 1, 5.0, False))      # a single machine: no pool, no prefix advice
        self.assertNotIn('完整机器名', keep_line('s/a', 1, 5.0, False))
        self.assertIn('同池', keep_line('s/es-', 3, 30.0, True))
        self.assertIn('完整机器名', keep_line('s/es-', 3, 30.0, True))


class R12ReadTimeTests(unittest.TestCase):
    def test_limit_text_says_what_was_read(self):
        # "10-10 至 10-25、10-25 至 10-27 … 的失败操作没有读到" looked like the whole month was missing; about 14 hours were read
        from azinspect.waf.reliability.analyze import read_periods
        cut = [['2026-10-01T00:00:00Z', '2026-10-25T09:56:35Z'], ['2026-10-25T11:59:00Z', '2026-10-30T23:59:59Z']]
        hours, text = read_periods(cut, '2026-10-01T00:00:00Z', '2026-10-30T23:59:59Z')
        self.assertAlmostEqual(hours, 2.04, places=1)
        self.assertEqual(text, '10-25 09:56 至 11:59')

    def test_internal_error_text_not_shown(self):
        from azinspect.waf.common import plain_error
        text = plain_error(None, 'truncated after time limit, not read: 2026-10-10T00:00:00Z..2026-10-25T09:56:35Z')
        self.assertNotIn('not read', text)
        self.assertNotIn('None', text)
        self.assertIn('在时限内没有读完', text)


class X10EvidenceTests(unittest.TestCase):
    def test_amount_in_a_table_without_usd_counts_as_found(self):
        # X10 said "01–05 报告中也没有" for 47,845.23, which 02's plan table shows (its columns say USD, the cells do not)
        from azinspect.crosscheck import _in_report
        self.assertTrue(_in_report('USD47,845.23', '|调整后：1年RI|44,302.30|47,845.23|'))
        self.assertFalse(_in_report('USD47,845.23', '|147,845.23|'))
        self.assertFalse(_in_report('USD7,845.23', '|47,845.23|'))
        self.assertTrue(_in_report('USD5,000', 'USD5,000.40'))


class KeepPoolEffectTests(unittest.TestCase):
    def test_pool_members_left_out_are_named_with_the_note(self):
        # keep took 7 machines and 832.20 in the log; 121 to 113 and 1,058.50 in the report: a pool member had stopped too
        from azinspect.vm.pipeline import keep_line
        line = keep_line('s/a', 2, 452.6, True, 1, 226.3)
        self.assertIn('另有同池 1 台因此不再整池调整，每月少计 USD 226.30', line)


class RunningHoursAuditTests(unittest.TestCase):
    def test_plan_totals_match_report(self):
        # rc5: the audit summed commitments where the report used on demand (commitment dearer), and build stopped
        from azinspect.vm.audit import plan_totals
        from azinspect.vm.table import portfolio_totals
        rows = [{'running': True, 'currentMonthlyPAYG': 100.0, 'costs': {'payg': 100.0, 'ri1': 60.0, 'ri3': 40.0, 'sp1': 70.0, 'sp3': None}},
                {'running': True, 'currentMonthlyPAYG': 4.0, 'costs': {'payg': 4.0, 'ri1': 60.0, 'ri3': 40.0, 'sp1': 70.0, 'sp3': 50.0}},
                {'running': False, 'currentMonthlyPAYG': 0, 'costs': {'payg': 9.0, 'ri1': 1.0, 'ri3': 1.0, 'sp1': 1.0, 'sp3': 1.0}}]
        totals = plan_totals(rows)
        self.assertEqual(totals, {p['key']: p['monthlyCost'] for p in portfolio_totals(rows)['plans']})
        self.assertEqual(totals['ri1'], 64.0)

    def test_audit_uses_running_hours(self):
        # the 02 audit recomputed savings at 730 hours and would flag every part-time machine
        import inspect
        from azinspect.vm import audit
        source = inspect.getsource(audit)
        self.assertIn("r.get('monthlyHours', 730)", source)
        self.assertIn("u.get('monthlyHours', 730) if key == 'payg'", source)


if __name__ == '__main__':
    unittest.main()
