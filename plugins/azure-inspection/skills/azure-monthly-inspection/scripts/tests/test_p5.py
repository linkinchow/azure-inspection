"""0.10.8: fixes from the October formal inspections, second part (synthetic data, no network)."""
from __future__ import annotations

import sys
import tempfile
import unittest
import unittest.mock
from datetime import date
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from azinspect.core import io  # noqa: E402
from azinspect.core.period import ReportPeriod  # noqa: E402


def cost_data(sub='a'):
    rows = {'prevActual': [{'subscriptionId': sub, 'serviceName': 'Virtual Machines', 'resourceGroup': 'rg', 'date': 20260915, 'cost': 3000.0, 'currency': 'USD'}],
            'curActual': [{'subscriptionId': sub, 'serviceName': 'Virtual Machines', 'resourceGroup': 'rg', 'date': 20261015, 'cost': 11790.0, 'currency': 'USD'}],
            'prevPricingModel': [{'subscriptionId': sub, 'pricingModel': 'OnDemand', 'cost': 3000.0, 'currency': 'USD'}],
            'curPricingModel': [{'subscriptionId': sub, 'pricingModel': 'OnDemand', 'cost': 2790.0, 'currency': 'USD'},
                                {'subscriptionId': sub, 'pricingModel': 'Reservation', 'cost': 9000.0, 'currency': 'USD'}]}
    index = [{'subscriptionId': sub, 'queryKind': k, 'ok': True} for k in rows]
    return {'complete': True, 'currency': 'USD', 'rows': rows, 'index': index,
            'coverage': {k: {'attempted': 1, 'successful': 1} for k in rows},
            'subscriptions': [{'id': sub, 'name': 'sub-a', 'group': 'g', 'state': 'Enabled'}]}


class CommitmentChargesInModelTests(unittest.TestCase):
    def test_review_data_does_not_hide_commitment_charges(self):
        # with raw/cost/review/results.json (every full collection), build() reused the name `rows` for the orphan
        # findings, so commitmentCharges was always None and 01 never showed the daily change without purchases
        from azinspect.cost.model import build
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-10')
            ws.create()
            io.write_json(ws.raw('cost/cost-data.json'), cost_data())
            io.write_json(ws.raw('cost/review/results.json'), {'wasteFindings': []})
            m = build(ws, ReportPeriod.build('2026-10', run_date=date(2026, 11, 3)))
        self.assertEqual(m['commitmentCharges'], {'prev': 0.0, 'cur': 9000.0})


class TokenRetryTests(unittest.TestCase):
    # after hours of collection, one failed `az account get-access-token` ended the whole cost or WAF collection;
    # the next part got a token at once
    def provider(self, results):
        from azinspect.core import auth
        from test_core import SUB, TENANT, fake_token
        calls = []

        def runner(s, a):
            calls.append(a)
            r = results.pop(0)
            if r == 'fail':
                raise auth.TokenUnavailable(1)
            return fake_token()
        return auth.TokenProvider('ro@contoso.com', TENANT, SUB, runner=runner), calls

    def test_a_later_failure_is_retried(self):
        from azinspect.core import auth
        p, calls = self.provider(['ok', 'fail', 'fail', 'ok'])
        with unittest.mock.patch.object(auth.time, 'sleep') as sleep:
            p.get(auth.ARM)
            p._cache.clear()        # the token expired
            self.assertTrue(p.get(auth.ARM))
        self.assertEqual(len(calls), 4)
        self.assertEqual(sleep.call_count, 2)

    def test_first_failure_stops_at_once_with_the_exit_code(self):
        from azinspect.core import auth
        p, calls = self.provider(['fail'])
        with unittest.mock.patch.object(auth.time, 'sleep') as sleep, self.assertRaises(SystemExit) as e:
            p.get(auth.ARM)
        self.assertEqual(sleep.call_count, 0)
        self.assertIn('退出码 1', str(e.exception))

    def test_gives_up_after_three_tries(self):
        from azinspect.core import auth
        p, calls = self.provider(['ok', 'fail', 'fail', 'fail'])
        with unittest.mock.patch.object(auth.time, 'sleep'):
            p.get(auth.ARM)
            p._cache.clear()
            with self.assertRaises(SystemExit) as e:
                p.get(auth.ARM)
        self.assertIn('试了 3 次', str(e.exception))


class WafInterruptedTests(unittest.TestCase):
    def test_interrupted_waf_names_the_pillars_left(self):
        from azinspect.waf import pipeline
        logs = []

        class Mod:
            def __init__(self, name):
                self.name = name

            def collect(self, *a, **k):
                if self.name == 'aprl':
                    raise SystemExit('无法取得只读账号的令牌（az 退出码 1）')
        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.object(pipeline, '_module', Mod), unittest.mock.patch.object(pipeline, 'save_scope'):
            ws = io.Workspace(d, '2026-10')
            ws.create()
            with self.assertRaises(SystemExit):
                pipeline.collect(ws, None, None, log=logs.append, pillars=['reliability', 'aprl', 'performance'])
        text = '\n'.join(logs)
        self.assertIn('已完成 reliability', text)
        self.assertIn('--part waf --pillars aprl,performance', text)


class NewResourceCountTests(unittest.TestCase):
    def test_huge_counts_read_as_billing_ids(self):
        # 01 section 3 said "新增 N 个资源" with N in the millions: distinct billing resource IDs (rotating snapshots, disks, scale-set instances)
        from azinspect.cost.views import driver_auto_text
        base = {'decomposition': {'newMeters': 5000.0}}
        few = driver_auto_text({**base, 'resources': {'newCount': 3, 'newCost': 1200.0}})
        self.assertIn('本月新出现 3 个计费资源，合计 USD 1,200.00', few)
        # "新增 1 个资源，合计 USD 0.00"; and 38 disks of replaced nodes read as 38 new resources
        tiny = driver_auto_text({**base, 'resources': {'newCount': 1, 'newCost': 0.003}})
        self.assertIn('合计不到 USD 0.01', tiny)
        many = driver_auto_text({**base, 'resources': {'newCount': 250000, 'newCost': 9000.0}})
        self.assertIn('本月新出现 250,000 个计费资源 ID（合计 USD 9,000.00）', many)
        self.assertNotIn('新增 250000 个资源', many)


class CommitmentOrderNameTests(unittest.TestCase):
    def test_purchase_orders_are_named(self):
        # 01 section 4 listed reservation purchases as "未归属" with an empty resource name
        from azinspect.cost.model import resource_place
        rid = '/providers/microsoft.capacity/reservationorders/11111111-2222-3333-4444-555555555555/reservations/'
        self.assertEqual(resource_place(rid), ('预留和节省计划购买', '预留订单 11111111…（购买）'))
        sp = '/providers/microsoft.billingbenefits/savingsplanorders/66666666-2222-3333-4444-555555555555/savingsplans/77777777-2222-3333-4444-555555555555'
        self.assertEqual(resource_place(sp), ('预留和节省计划购买', '节省计划订单 66666666…（购买）'))
        vm = '/subscriptions/s/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/vm-1'
        self.assertEqual(resource_place(vm), ('rg-a', 'vm-1'))
        self.assertEqual(resource_place('无资源ID'), ('未归属', '无资源ID'))


class WordingTests(unittest.TestCase):
    def test_r2_points_to_r1_only_when_r1_found_something(self):
        # R2 always said "先解决节点子网 IP 不足（见 R1）", also in months without any R1 problem
        from azinspect.waf.reliability.analyze import system_pool_fix
        self.assertIn('见 R1', system_pool_fix(True))
        self.assertNotIn('R1', system_pool_fix(False))
        self.assertIn('先查明', system_pool_fix(False))

    def test_o2_without_a_workspace_name(self):
        # "已采集 Container Insights（工作区 None）"
        from azinspect.waf.operations.monitoring import collected_text
        self.assertEqual(collected_text(None), '已采集 Container Insights')
        self.assertEqual(collected_text('law-a'), '已采集 Container Insights（工作区 law-a）')

    def test_05_business_line_ratio_has_a_space(self):
        # 05 conclusion "AI7/7 个（100%）"
        from azinspect.peer.report import labelled_ratio
        self.assertEqual(labelled_ratio('AI', 7, 7, 100), 'AI 7/7 个（100%）')


class LongQueryProgressTests(unittest.TestCase):
    def test_paged_query_reports_progress(self):
        # one per-resource cost query paged for hours with a single line in the log
        from azinspect.cost import collect as cc
        logs, clock = [], [0.0]
        pages = {'n': 0}

        class Client:
            def request(self, method, url, check, target='', body=None, **kw):
                pages['n'] += 1
                clock[0] += 120        # two minutes a page
                nxt = f'https://x/page{pages["n"] + 1}' if pages['n'] < 12 else None
                return 200, {'properties': {'columns': [{'name': 'Cost'}], 'rows': [], 'nextLink': nxt}}, None
        progress = cc.progress_log(logs.append, 'sub-a 逐资源费用', clock=lambda: clock[0], every=600)
        out = cc.fetch_pages(Client(), 'https://x/page1', {}, 'curResources', progress=progress)
        self.assertTrue(out['ok'])
        self.assertEqual(len(out['pages']), 12)
        self.assertEqual(len(logs), 2)          # every 10 minutes: after pages 5 and 10
        self.assertIn('sub-a 逐资源费用：已读 5 页', logs[0])


class SmallFixesTests(unittest.TestCase):
    def test_same_severity_override_is_not_a_change(self):
        # Excel said "严重程度由低调整为低" when the plugin's own severity already matched the override
        from azinspect.waf.report import apply_narrative
        findings = [{'id': 'R3-aaaaaa', 'check': 'R3', 'severity': '低', 'finding': 'x'}]
        _n, warnings = apply_narrative(findings, {'severityOverrides': [{'findingId': 'R3-aaaaaa', 'severity': '低', 'reason': 'r'}]})
        self.assertNotIn('originalSeverity', findings[0])
        self.assertTrue(any('已经是低' in w for w in warnings))

    def test_note_ending_in_a_full_stop(self):
        # "……自建 MySQL。；部分读取失败，结果可能不完整"
        from azinspect.waf.report import check_note
        text = check_note([{'finding': 'x'}], {'denied': 0, 'otherErrors': 2, 'succeeded': 3}, '主要问题在自建 MySQL。')
        self.assertEqual(text, '主要问题在自建 MySQL；部分读取失败，结果可能不完整')

    def test_less_than_a_cent(self):
        # "9月几乎没有这项费用（USD 0.00）"
        from azinspect.cost.report import daily_phrase
        self.assertEqual(daily_phrase({'prev': 0.003, 'cur': 50.0, 'dailyChangeRate': 999.0}, '9月'), '9月几乎没有这项费用（不到 USD 0.01）')
        self.assertEqual(daily_phrase({'prev': 0.2, 'cur': 50.0, 'dailyChangeRate': 249.0}, '9月'), '9月几乎没有这项费用（USD 0.20）')


class AksCoverageNoteTests(unittest.TestCase):
    def test_note_counts_the_clusters_read(self):
        # P2's coverage cell said "3 个资源……未读到" and "已读取全部 12 个集群的 AKS 平台指标" side by side
        from azinspect.waf.performance.analyze import platform_note
        self.assertTrue(platform_note(12, 12).startswith('已读取全部 12 个集群'))
        self.assertTrue(platform_note(9, 12).startswith('已读取 9/12 个集群'))


class X12StepsTests(unittest.TestCase):
    def test_intermediate_upgrade_steps_are_not_targets(self):
        # "先升到 1.29 再升级到 1.30" was reported as a target below support
        from azinspect import crosscheck, selection
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            vals = [{'version': v, 'capabilities': {'supportPlan': plans}} for v, plans in
                    (('1.29', ['AKSLongTermSupport']), ('1.30', ['KubernetesOfficial']), ('1.31', ['KubernetesOfficial']))]
            io.write_json(ws.raw('waf/reliability/aks/k8s-versions.json'), {'s/regiona': {'status': 200, 'data': {'values': vals}}})
            io.write_json(ws.month_dir('narrative') / '03.json', {'topIssues': [{'title': 'x', 'recommendation': '先升到 1.29，再升级到 1.30'}]})
            selection.save(ws, ['03'])
            r = {x['rule']: x for x in crosscheck.run(ws, log=lambda *_: None)['rules']}['X12']
        self.assertEqual(r['status'], '通过')


class UnsupportedResourceTypeTests(unittest.TestCase):
    def test_resource_health_unsupported_type_is_not_a_failed_read(self):
        # MongoDB vCore resource health answers 422 UnsupportedResourceType; 03 said 资源健康 had failed reads
        from azinspect.waf.common import not_applicable
        self.assertTrue(not_applicable({'status': 422, 'error': 'UnsupportedResourceType: Resource type not supported.',
                                        'url': 'https://management.azure.com/subscriptions/s/x/mongoClusters/m/providers/Microsoft.ResourceHealth/availabilityStatuses'}))
        self.assertFalse(not_applicable({'status': 422, 'error': 'Something else', 'url': 'https://management.azure.com/x'}))


class CredentialActionTests(unittest.TestCase):
    def test_more_ways_to_read_secrets(self):
        # Key Vault Secrets User (a data action), web app config/list, Cosmos DB read-only keys were not named
        from azinspect.cli import _credentials
        self.assertTrue(_credentials([{'actions': [], 'dataActions': ['Microsoft.KeyVault/vaults/secrets/getSecret/action']}]))
        self.assertTrue(_credentials([{'actions': ['Microsoft.Web/sites/config/list/Action']}]))
        self.assertTrue(_credentials([{'actions': ['Microsoft.DocumentDB/databaseAccounts/readonlykeys/action']}]))
        self.assertTrue(_credentials([{'actions': ['Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action']}]))
        self.assertFalse(_credentials([{'actions': ['*/read'], 'dataActions': ['Microsoft.KeyVault/vaults/secrets/readMetadata/action']}]))


class PackageFolderBusyTests(unittest.TestCase):
    def test_busy_folder_gets_a_plain_message(self):
        # rmtree raised WinError 32 with a traceback when a terminal sat in the old package folder
        from azinspect import package
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / 'pkg'
            folder.mkdir()
            err = PermissionError(32, 'The process cannot access the file because it is being used by another process')
            with unittest.mock.patch.object(package.shutil, 'rmtree', side_effect=err), self.assertRaises(SystemExit) as e:
                package.remove_old(folder)
        self.assertIn('包文件夹被占用', str(e.exception))


class MetricSplitSoonerTests(unittest.TestCase):
    def test_batches_split_after_fewer_tries_and_unread_are_logged(self):
        # 529 batches were retried six times (about a minute each) before splitting; the log did not say what stayed unread
        import importlib
        import json as _json
        from types import SimpleNamespace
        pc = importlib.import_module('azinspect.waf.performance.collect')
        tries, logs = [], []
        bad = '/subscriptions/s/resourceGroups/rg/providers/x/r3'

        def request(method, url, check, target='', body=None, max_attempts=6):
            rids = body['resourceids']
            tries.append((len(rids), max_attempts))
            if len(rids) > 1 or bad in rids:
                return 529, None, 'HTTP 529'
            return 200, {'values': [{'resourceid': rids[0], 'value': []}]}, None
        c = object.__new__(pc.Collector)
        c.client, c.log, c.start, c.end, c.denied = SimpleNamespace(request=request), logs.append, 's', 'e', set()
        c.raw = SimpleNamespace(save=lambda rel, obj: None)
        items = [{'id': f'/subscriptions/s/resourceGroups/rg/providers/x/r{i}', 'subscriptionId': 's', 'location': 'regiona'} for i in range(4)]
        c.batch_metrics('lb-dip', 'P9', items, 'ns', ['DipAvailability'], 'average')
        self.assertTrue(all(m == 3 for n, m in tries if n > 1))
        self.assertTrue(any('lb-dip' in x and '1 个资源' in x for x in logs))


class DriverLimitTests(unittest.TestCase):
    # one change breakdown paged for many hours for a small change
    def test_query_stops_at_the_page_limit(self):
        from azinspect.cost import supplement_costs as sc
        calls = []

        class Client:
            def request(self, method, url, check, target='', body=None, **kw):
                calls.append(url)
                return 200, {'properties': {'columns': [{'name': 'Cost'}], 'rows': [[1.0]], 'nextLink': f'https://x/p{len(calls) + 1}'}}, None
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-10')
            ws.create()
            run = sc.Runner(ws, Client(), [{'id': 's', 'name': 'sub-a', 'group': 'g'}], 'USD')
            it = run.run('drivers.increase01.s.prev', 's', 'drivers-prev', 'query', {}, max_pages=5)
        self.assertFalse(it['ok'])
        self.assertEqual(len(calls), 5)
        self.assertTrue(it['error'].get('tooLarge'))

    def test_01_says_the_data_was_too_large(self):
        from azinspect.cost.report import drivers_intro
        pairs = [{'rank': 1, 'kind': 'increase', 'subscriptionName': 'sub1', 'serviceName': 'Storage', 'status': 'failed',
                  'errors': {'prev': {'tooLarge': True, 'message': 'x'}}},
                 {'rank': 2, 'kind': 'increase', 'subscriptionName': 'sub2', 'serviceName': 'VM', 'status': 'success'}]
        text = drivers_intro({'pairs': pairs}, '9月', '10月')
        self.assertIn('sub1 的 Storage（数据量太大', text)
        self.assertNotIn('续采时补读', text)


class SecurityNotRegisteredTests(unittest.TestCase):
    def test_unregistered_security_provider_is_a_finding_not_a_failed_read(self):
        # S-I4 already reports "未注册 Microsoft.Security"; its 404s also made 03 say Defender had failed reads
        from azinspect.waf.common import not_applicable
        call = {'status': 404, 'error': 'Subscription Not Registered: Please register to Microsoft.Security in order to view your security status',
                'url': 'https://management.azure.com/subscriptions/s/providers/Microsoft.Security/pricings?api-version=2024-01-01'}
        self.assertTrue(not_applicable(call))
        self.assertFalse(not_applicable(dict(call, url='https://management.azure.com/subscriptions/s/providers/Microsoft.Web/sites')))


class ResourceSplitByPagesTests(unittest.TestCase):
    # a subscription with fewer resource groups than the 100 that trigger splitting paged for hours;
    # an interruption meant reading it all again
    def test_many_pages_last_month_splits_this_month(self):
        from test_resume import SUB, FakeCostApi
        from azinspect.core.reuse import Reuse
        from azinspect.cost import collect as cc
        period = ReportPeriod.build('2026-09', run_date=date(2026, 10, 15))
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(io.Workspace(d, period.previous.key).raw('cost/query-pages.json'), {SUB['id']: {'curResources': 300}})
            api, logs = FakeCostApi(), []
            c = cc.Collector(ws, api, period, [SUB], 'USD', log=logs.append, reuse=Reuse(False))
            c.run_jobs([(SUB, 'curActual')])
            c.run_resource_jobs([SUB])
            record, rows = c.records[(SUB['id'], 'curResources')]
            self.assertEqual(record['split']['batches'], 5)              # 5 resource groups, one per batch
            self.assertTrue(any('上月' in x and '300 页' in x for x in logs))
            c.snapshot(True)
            pages = io.read_json(ws.raw('cost/query-pages.json'))
        self.assertEqual(pages[SUB['id']]['curResources'], 5)

    def test_few_pages_last_month_reads_whole(self):
        from test_resume import SUB, FakeCostApi
        from azinspect.core.reuse import Reuse
        from azinspect.cost import collect as cc
        period = ReportPeriod.build('2026-09', run_date=date(2026, 10, 15))
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(io.Workspace(d, period.previous.key).raw('cost/query-pages.json'), {SUB['id']: {'curResources': 3}})
            c = cc.Collector(ws, FakeCostApi(), period, [SUB], 'USD', log=lambda *_: None, reuse=Reuse(False))
            c.run_jobs([(SUB, 'curActual')])
            c.run_resource_jobs([SUB])
            self.assertNotIn('split', c.records[(SUB['id'], 'curResources')][0])


class SingleResourceWindowSplitTests(unittest.TestCase):
    # node conditions of clusters with many node pools answered 529 even one cluster at a time
    def test_single_resource_is_read_in_shorter_windows(self):
        import importlib
        from types import SimpleNamespace
        pc = importlib.import_module('azinspect.waf.performance.collect')
        seen = []

        def request(method, url, check, target='', body=None, **kw):
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(url).query)
            start, end = q['starttime'][0], q['endtime'][0]
            seen.append((len(body['resourceids']), start, end))
            if start == '2026-10-01T00:00:00Z' and end == '2026-10-31T00:00:00Z':
                return 529, None, 'HTTP 529'
            ts = [{'metadatavalues': [{'name': {'value': 'condition'}, 'value': 'Ready'}], 'data': [{'timeStamp': start, 'average': 1}]}]
            return 200, {'values': [{'resourceid': r, 'value': [{'name': {'value': 'm'}, 'errorCode': 'Success', 'timeseries': ts}]}
                                    for r in body['resourceids']]}, None
        c = object.__new__(pc.Collector)
        c.client, c.log, c.start, c.end, c.denied = SimpleNamespace(request=request), (lambda *_: None), '2026-10-01T00:00:00Z', '2026-10-31T00:00:00Z', set()
        c.raw = SimpleNamespace(save=lambda rel, obj: None)
        res = c.batch_metrics('aks-nodecond', 'P2', [{'id': '/subscriptions/s/x/c1', 'subscriptionId': 's', 'location': 'regiona'}],
                              'ns', ['m'], 'average')
        r = res['/subscriptions/s/x/c1']
        self.assertNotIn('_error', r)
        self.assertEqual(len(r['m']), 1)                    # one series, its data joined over the windows
        self.assertEqual(len(r['m'][0]['data']), 3)
        self.assertEqual(len([x for x in seen if x[1] != '2026-10-01T00:00:00Z' or x[2] != '2026-10-31T00:00:00Z']), 3)


class ServerErrorTextTests(unittest.TestCase):
    def test_server_error_keeps_its_message(self):
        # 529 was saved as "HTTP 529" only (and in results as "HTTP 529: HTTP 529")
        import io as stdio
        import urllib.error
        from types import SimpleNamespace
        from azinspect.core import http

        def open_(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 529, 'x', {}, stdio.BytesIO(b'{"error": {"code": "TooBusy", "message": "Response too large"}}'))
        client = http.ReadOnlyClient(SimpleNamespace(get=lambda a: 't'), opener=SimpleNamespace(open=open_))
        with unittest.mock.patch.object(http.time, 'sleep'):
            status, _d, error = client.get('/subscriptions?api-version=2022-12-01', 'test', max_attempts=2)
        self.assertEqual(status, 529)
        self.assertIn('TooBusy', error)

    def test_metric_error_text_not_doubled(self):
        from azinspect.waf.performance.collect import http_error
        self.assertEqual(http_error(529, 'HTTP 529'), 'HTTP 529')
        self.assertEqual(http_error(529, 'TooBusy: Response too large'), 'HTTP 529: TooBusy: Response too large')


class CallLogPerPillarsTests(unittest.TestCase):
    def test_waf_runs_by_pillar_keep_their_call_logs(self):
        # a second `collect --part waf --pillars x` overwrote raw/_calls/collect-waf.json of the first
        from azinspect.cli import calls_stage
        self.assertEqual(calls_stage('waf', None), 'collect-waf')
        self.assertEqual(calls_stage('waf', 'performance,operations'), 'collect-waf-performance-operations')
        self.assertEqual(calls_stage('cost', None), 'collect-cost')


class Rc1FollowUpTests(unittest.TestCase):
    def test_not_registered_401_is_not_a_failed_read(self):
        # autoProvisioningSettings answered 401 "Subscription Not Registered" for the same subscriptions
        from azinspect.waf.common import not_applicable
        self.assertTrue(not_applicable({'http': 401, 'error': 'Subscription Not Registered: Please register to Microsoft.Security',
                                        'url': 'https://management.azure.com/subscriptions/s/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview'}))
        self.assertFalse(not_applicable({'http': 401, 'error': 'InvalidAuthenticationToken',
                                         'url': 'https://management.azure.com/subscriptions/s/providers/Microsoft.Security/pricings'}))

    def test_resource_without_a_health_record_is_not_resolved(self):
        # a scale set reported Unknown last month had no health record this month and read as 已解决
        from azinspect import tracking
        f = lambda fid, name: {'id': fid, 'check': 'R11', 'severity': '低', 'finding': 'x', 'resourceName': name,
                               'members': [{'name': name, 'subscription': 'sub-a'}]}
        ok = {'attempted': 1, 'succeeded': 1}
        with tempfile.TemporaryDirectory() as d:
            for month, findings, cov in (('2026-08', [f('R11-a', 'vmss-a'), f('R11-b', 'vmss-b')], {'R11': ok}),
                                         ('2026-09', [], {'R11': dict(ok, unseen=['vmss-a'])})):
                ws = io.Workspace(d, month)
                ws.create()
                io.write_json(ws.month_dir('findings') / 'waf' / 'reliability.json',
                              {'pillar': 'reliability', 'findings': findings, 'coverage': cov, 'complete': True})
                out = tracking.update(ws, log=lambda *_: None)
        rows = {r['id']: r for r in out['rows']}
        self.assertEqual(rows['R11-a']['status'], '本月未检查')
        self.assertEqual(rows['R11-b']['status'], '已解决')

    def test_r11_lists_resources_without_records(self):
        from types import SimpleNamespace
        import importlib
        ra = importlib.import_module('azinspect.waf.reliability.analyze')
        from azinspect.waf.common import coverage_entry
        files = {'arg/vmss.json': {'status': 200, 'rows': [{'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-a'},
                                                            {'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-b'}]}}
        health = [{'rid': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-b',
                   'rtype': 'microsoft.compute/virtualmachinescalesets', 'status': 'Available'}]
        run = SimpleNamespace(rows=lambda n: health if n == 'health' else [], raw=SimpleNamespace(load=lambda rel, default=None: files.get(rel, default)),
                              coverage={'R11': coverage_entry()}, inventory={}, cover=lambda *a: None, calls=[],
                              subname=lambda x: 'sub-a', add=lambda *a, **k: {}, env=lambda *a, **k: {'value': 'prod', 'label': '生产', 'basis': ''})
        ra.r11(run)
        self.assertEqual(run.coverage['R11'].get('unseen'), ['vmss-a'])


class PunctuationTests(unittest.TestCase):
    def test_label_ending_in_a_bracket_gets_no_space(self):
        # "某厂商（供应商） 4/9 个"
        from azinspect.peer.report import labelled_ratio
        self.assertEqual(labelled_ratio('X（供应商）', 4, 9, 44), 'X（供应商）4/9 个（44%）')

    def test_join_drops_full_stops(self):
        # "……需立即更新证书。；严重程度由高调整为中：……"
        from azinspect.waf.report import join_notes
        self.assertEqual(join_notes(['需立即更新证书。', '严重程度由高调整为中：客户确认。']), '需立即更新证书；严重程度由高调整为中：客户确认。')
        self.assertEqual(join_notes([None, 'a。']), 'a。')


class PartialWindowTests(unittest.TestCase):
    # a load balancer read two of three windows (the third throttled): the whole resource was dropped; and single
    # resources still waited through six tries per window
    def test_windows_read_are_kept_and_marked_partial(self):
        import importlib
        from types import SimpleNamespace
        from urllib.parse import parse_qs, urlparse
        pc = importlib.import_module('azinspect.waf.performance.collect')
        tries = []

        def request(method, url, check, target='', body=None, max_attempts=6):
            q = parse_qs(urlparse(url).query)
            start, end = q['starttime'][0], q['endtime'][0]
            tries.append(max_attempts)
            if (start, end) == ('2026-10-01T00:00:00Z', '2026-10-31T00:00:00Z') or start == '2026-10-21T00:00:00Z':
                return 529, None, 'Throttled: backend'
            ts = [{'metadatavalues': [], 'data': [{'timeStamp': start, 'average': 1}]}]
            return 200, {'values': [{'resourceid': r, 'value': [{'name': {'value': 'm'}, 'errorCode': 'Success', 'timeseries': ts}]}
                                    for r in body['resourceids']]}, None
        c = object.__new__(pc.Collector)
        logs = []
        c.client, c.log, c.start, c.end, c.denied = SimpleNamespace(request=request), logs.append, '2026-10-01T00:00:00Z', '2026-10-31T00:00:00Z', set()
        c.raw = SimpleNamespace(save=lambda rel, obj: None)
        res = c.batch_metrics('lb-dip', 'P9', [{'id': '/subscriptions/s/x/lb1', 'subscriptionId': 's', 'location': 'regiona'}], 'ns', ['m'], 'average')
        r = res['/subscriptions/s/x/lb1']
        self.assertEqual(len(r['m'][0]['data']), 2)
        self.assertEqual(r['_partial'], [['2026-10-21T00:00:00Z', '2026-10-31T00:00:00Z']])
        self.assertTrue(all(m == 3 for m in tries))
        self.assertTrue(any('部分时段' in x for x in logs))

    def test_partial_resources_are_failed_reads(self):
        from types import SimpleNamespace
        from azinspect.waf.performance.analyze import Analyzer
        calls = [{'check': 'P9', 'target': 'lb-dip/s/regiona', 'status': 200}]
        files = {'index.json': {'calls': calls},
                 'metrics/lb-dip.json': {'label': 'lb-dip', 'results': {'/lb1': {'m': [], '_partial': [['a', 'b']]}}}}
        a = object.__new__(Analyzer)
        a.raw = SimpleNamespace(load=lambda rel, default=None: files.get(rel, default))
        a.cov = {f'P{i}': {'attempted': 0, 'succeeded': 0, 'denied': 0, 'otherErrors': 0, 'notes': []} for i in range(1, 11)}
        a.coverage_from_index()
        self.assertEqual(a.cov['P9']['otherErrors'], 1)
        self.assertTrue(any('只读到部分时段' in n and 'lb1' in n for n in a.cov['P9']['notes']))


class ThrottledBackendTests(unittest.TestCase):
    def test_backend_throttling_counts_as_throttled(self):
        # 529 "The metrics backend reported 'Throttled'" was recorded with throttled 0
        import io as stdio
        import urllib.error
        from types import SimpleNamespace
        from azinspect.core import http

        def open_(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 529, 'x', {}, stdio.BytesIO(b'{"error": {"code": "Throttled", "message": "The metrics backend is temporarily throttling this request."}}'))
        client = http.ReadOnlyClient(SimpleNamespace(get=lambda a: 't'), opener=SimpleNamespace(open=open_))
        with unittest.mock.patch.object(http.time, 'sleep'):
            client.get('/subscriptions?api-version=2022-12-01', 'test', max_attempts=2)
        self.assertEqual(client.calls[-1]['throttled'], 2)

    def test_note_says_the_backend_throttled(self):
        from types import SimpleNamespace
        from azinspect.waf.performance.analyze import Analyzer
        calls = [{'check': 'P2', 'target': 'aks-nodecond/s/regiona', 'status': 529}]
        files = {'index.json': {'calls': calls},
                 'metrics/aks-nodecond.json': {'label': 'aks-nodecond', 'results': {'/c3': {'_error': 'HTTP 529: Throttled: The metrics backend reported ...'}}}}
        a = object.__new__(Analyzer)
        a.raw = SimpleNamespace(load=lambda rel, default=None: files.get(rel, default))
        a.cov = {f'P{i}': {'attempted': 0, 'succeeded': 0, 'denied': 0, 'otherErrors': 0, 'notes': []} for i in range(1, 11)}
        a.coverage_from_index()
        self.assertTrue(any('指标后端限流' in n and 'c3' in n for n in a.cov['P2']['notes']))


class TrackingMembersWarningTests(unittest.TestCase):
    def test_warns_when_last_months_findings_are_missing(self):
        # a record from an old version without members, and last month's findings not in the workspace: compared by id silently
        from azinspect import tracking
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            io.write_json(ws.state_dir / 'months' / '2026-08.json',
                          {'month': '2026-08', 'findings': {'R1-a': {'check': 'R1', 'source': 'reliability', 'severity': '中', 'finding': 'x'}},
                           'checksRun': ['reliability:R1']})
            io.write_json(ws.month_dir('findings') / 'waf' / 'reliability.json',
                          {'pillar': 'reliability', 'findings': [], 'coverage': {'R1': {'attempted': 1, 'succeeded': 1}}, 'complete': True})
            logs = []
            tracking.update(ws, log=logs.append)
        self.assertTrue(any('2026-08' in x and 'findings' in x for x in logs))


class NoReadingSentenceTests(unittest.TestCase):
    def test_no_reading_reason_is_said(self):
        # 03 read "“本月未检查”中，不能判断是否已解决。" for a problem whose resource had no reading this month
        from azinspect.waf.report import TRACKING_HELP, month_sentence
        tracked = {'previous': '2026-09', 'rows': [{'id': 'R11-a', 'check': 'R11', 'status': '本月未检查', 'notChecked': '本月没有该资源的读数',
                                                     'severity': '低', 'finding': 'x'}]}
        text = month_sentence(tracked, '03')
        self.assertIn('1 项的资源本月没有读数', text)
        self.assertNotIn('中，不能', text)
        self.assertIn('本月没有该资源的读数', TRACKING_HELP)


class CoverageNoteTextTests(unittest.TestCase):
    def test_occasional_unhealthy_backends_in_plain_words(self):
        # 04 "检查覆盖" showed "gw-a：后端偶发不健康 [{'backend': ..., 'unhealthyAvg': 0.0, 'daysWithUnhealthy': 2, ...}]"
        from azinspect.waf.performance.analyze import unhealthy_note
        text = unhealthy_note('gw-a', [{'backend': 'pool-a~setting-a', 'unhealthyAvg': 0.0, 'daysWithUnhealthy': 2, 'healthyMax': 2}], 30)
        self.assertEqual(text, 'gw-a 的后端 pool-a~setting-a 在 30 天中有 2 天出现不健康实例。')
        self.assertNotIn('{', text)

    def test_partial_note_names_the_missing_days(self):
        from types import SimpleNamespace
        from azinspect.waf.performance.analyze import Analyzer
        files = {'index.json': {'calls': [{'check': 'P9', 'target': 'lb-dip/s/regiona', 'status': 200}]},
                 'metrics/lb-dip.json': {'label': 'lb-dip', 'results': {'/lb1': {'m': [], '_partial': [['2026-10-26T00:00:00Z', '2026-11-05T00:00:00Z']]}}}}
        a = object.__new__(Analyzer)
        a.raw = SimpleNamespace(load=lambda rel, default=None: files.get(rel, default))
        a.cov = {f'P{i}': {'attempted': 0, 'succeeded': 0, 'denied': 0, 'otherErrors': 0, 'notes': []} for i in range(1, 11)}
        a.coverage_from_index()
        self.assertTrue(any('lb1 缺 10-26 至 11-05' in n for n in a.cov['P9']['notes']))


if __name__ == '__main__':
    unittest.main()
