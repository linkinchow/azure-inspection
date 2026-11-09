"""0.10.7: fixes from the October formal inspections (synthetic data, no network)."""
from __future__ import annotations

import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from azinspect.core import io  # noqa: E402,F401


def pair(rank, kind, status='success', http=None):
    p = {'rank': rank, 'kind': kind, 'subscriptionName': f'sub{rank}', 'serviceName': f'svc{rank}', 'status': status}
    if status == 'failed':
        p['errors'] = {'cur': {'httpStatus': http, 'message': f'HTTP {http}'}}
    return p


class DriverIntroTests(unittest.TestCase):
    def test_a_failed_breakdown_is_said(self):
        # 01 section 3 said all 15 were broken down while one had failed (throttled) and the table had 14 rows
        from azinspect.cost.report import drivers_intro
        pairs = [pair(i, 'increase') for i in range(1, 8)] + [pair(8, 'increase', 'failed', 429)] + \
                [pair(i, 'increase') for i in range(9, 11)] + [pair(i, 'decrease') for i in range(11, 16)]
        text = drivers_intro({'pairs': pairs}, '9月', '10月')
        self.assertIn('15 项中 14 项已拆分到具体资源', text)
        self.assertIn('sub8 的 svc8', text)
        self.assertIn('接口限流', text)
        self.assertNotIn('均已拆分', text)
        ok = drivers_intro({'pairs': [p for p in pairs if p['status'] == 'success']}, '9月', '10月')
        self.assertIn('前 9 项增长和前 5 项下降均已拆分到具体资源', ok)


class DailyChangeTests(unittest.TestCase):
    def test_last_month_almost_zero_reads_as_new(self):
        # the recommendation list gave a daily change of millions of percent for a service that cost cents last month
        from azinspect.cost.report import daily_change
        self.assertEqual(daily_change({'prev': 0.02, 'cur': 900.0, 'dailyChangeRate': 44999.0}), '新增（上月不到 USD 1）')
        self.assertEqual(daily_change({'prev': 0, 'cur': 50.0, 'dailyChangeRate': None}), '新增')
        self.assertEqual(daily_change({'prev': 100.0, 'cur': 1200.0, 'dailyChangeRate': 10.0}), '+1000.00%')
        self.assertEqual(daily_change({'prev': 0, 'cur': 0, 'dailyChangeRate': None}), '不适用')
        self.assertEqual(daily_change({'prev': 0.5, 'cur': 0.6, 'dailyChangeRate': 0.2}), '+20.00%')   # small on both sides: not new

    def test_large_growth_from_a_real_cost_reads_as_a_multiple(self):
        # a service with a few dollars last month was called "新增", another with about the same share showed thousands of percent
        from azinspect.cost.report import daily_change
        self.assertEqual(daily_change({'prev': 6.0, 'cur': 600.0, 'dailyChangeRate': 99.0}), '约 100 倍')
        self.assertEqual(daily_change({'prev': 5.0, 'cur': 460.0, 'dailyChangeRate': 91.0572}), '约 92 倍')

    def test_recommendation_list_says_last_month_had_none(self):
        from azinspect.cost.report import daily_phrase
        self.assertEqual(daily_phrase({'prev': 0, 'cur': 50.0, 'dailyChangeRate': None}, '9月'), '9月没有这项费用')
        self.assertEqual(daily_phrase({'prev': 0.02, 'cur': 900.0, 'dailyChangeRate': 44999.0}, '9月'), '9月几乎没有这项费用（USD 0.02）')
        self.assertEqual(daily_phrase({'prev': 6.0, 'cur': 600.0, 'dailyChangeRate': 99.0}, '9月'), '日均费用约为9月的 100 倍')
        self.assertEqual(daily_phrase({'prev': 100.0, 'cur': 150.0, 'dailyChangeRate': 0.5}, '9月'), '日均变化+50.00%')


class CostLimitationsTests(unittest.TestCase):
    def test_narrative_limitations_reach_01(self):
        # 01 ignored narrative/01.json "limitations" (the other reports read it)
        from azinspect.cost.report import narrative_limitations
        self.assertEqual(narrative_limitations({'limitations': ['甲', '乙']}), ['甲', '乙'])
        self.assertEqual(narrative_limitations({'limitations': '丙'}), ['丙'])
        self.assertEqual(narrative_limitations({}), [])


class CoverageLabelTests(unittest.TestCase):
    def test_every_cost_query_has_a_chinese_name(self):
        # Excel "数据覆盖与说明" showed the raw key prevPricingModel
        from azinspect.cost.collect import KINDS
        from azinspect.cost.report import kind_labels
        names = kind_labels({'prev': '9月', 'cur': '10月'})
        self.assertEqual([k for k in KINDS if k not in names], [])
        self.assertEqual(names['prevPricingModel'], '9月计价方式')


class CollectionNoiseTests(unittest.TestCase):
    def test_defender_log_does_not_say_zero_when_graph_returns_nothing(self):
        # "未处理的高、中严重性建议 0 条" while the per-subscription read found many
        from azinspect.waf import defender
        logs = []

        class Client:
            def arg(self, query, subs, rule, key):
                return [], 200, None
        with tempfile.TemporaryDirectory() as d,                 unittest.mock.patch.object(defender, 'load_scope', return_value=[]),                 unittest.mock.patch.object(defender, 'Raw') as raw:
            raw.return_value.save = lambda *a, **k: None
            defender.collect(None, {}, Client(), {}, log=logs.append)
        self.assertNotIn('建议 0 条', logs[0])
        self.assertIn('按订阅', logs[0])

    def test_pkcs7_ber_warning_is_not_printed(self):
        # cryptography warns (with the plugin path) when a PKCS#7 blob is BER; the certificate is still read
        import warnings
        from cryptography.hazmat.primitives.serialization import pkcs7
        from azinspect.waf.reliability import lifecycle
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from test_lifecycle import certificate  # noqa: E402
        cert, blob = certificate(90)
        real = pkcs7.load_der_pkcs7_certificates

        def noisy(b):
            warnings.warn('PKCS#7 certificates could not be parsed as DER, falling back to parsing as BER.', UserWarning)
            return real(b)
        import base64
        with unittest.mock.patch.object(pkcs7, 'load_der_pkcs7_certificates', noisy), warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter('always')
            self.assertIsNotNone(lifecycle.cert_expiry(base64.b64encode(blob).decode()))
        self.assertEqual([str(w.message) for w in seen], [])


class LandingZoneDepthTests(unittest.TestCase):
    def test_subscriptions_under_root_are_within_four_levels(self):
        # upstream ALZ query also requires a management group below root, so subscriptions under root failed
        # "管理组层级不超过四层" as well as "订阅不直接放在根管理组下"
        from azinspect.waf import landing_zone as lz
        depth, root = '2df27ee4-12e7-4f98-9f63-04722dd69c5b', '33b6b780-8b9f-4e5c-9104-9d403a923c34'
        subs = [{'id': f'/subscriptions/{i}', 'name': f'sub{i}'} for i in range(3)]
        results = [{'guid': depth, 'status': 200, 'error': None, 'rows': [dict(s, compliant=0) for s in subs]},
                   {'guid': root, 'status': 200, 'error': None,
                    'rows': [dict(subs[0], compliant=0), dict(subs[1], compliant=0), dict(subs[2], compliant=1)]}]
        saved = {}

        class Raw:
            def __init__(self, ws, name):
                pass

            def load(self, name):
                return {'results': results, 'commit': 'x'} if name == 'results.json' else {}

        class Findings:
            def __init__(self, pillar):
                pass

            def write(self, ws, **kw):
                saved.update(kw)
                return kw
        with unittest.mock.patch.object(lz, 'Raw', Raw), unittest.mock.patch.object(lz, 'Findings', Findings), \
                unittest.mock.patch.object(lz, 'load_scope', return_value=[]):
            lz.analyze(None, {}, log=lambda *_: None)
        rows = {r['guid']: r for r in saved['inventory']['landingZone']}
        self.assertEqual((rows[depth]['compliant'], rows[depth]['nonCompliant']), (2, 1))
        self.assertEqual(rows[depth]['examples'], ['sub2'])
        self.assertEqual(rows[root]['nonCompliant'], 2)


class LandingZoneLabelTests(unittest.TestCase):
    def test_scope_rows_are_named(self):
        # the Owner item listed "（未命名）": its rows only have a scope like /subscriptions/<id>
        from azinspect.waf.landing_zone import _label
        subs = {'0000-1': 'sub-a'}
        self.assertEqual(_label({'scope': '/subscriptions/0000-1', 'ownerCount': 6, 'compliant': 0}, subs), 'sub-a（6 个 Owner）')
        self.assertEqual(_label({'scope': '/subscriptions/0000-2/resourceGroups/rg-x', 'compliant': 0}, subs), '资源组 rg-x')
        self.assertEqual(_label({'scope': '/providers/Microsoft.Management/managementGroups/mg-1', 'compliant': 0}, subs), '管理组 mg-1')
        self.assertEqual(_label({'scope': '/', 'compliant': 0}, subs), '租户根')
        self.assertEqual(_label({'name': 'vnet-a', 'compliant': 0}), 'vnet-a')


class AutoTextTests(unittest.TestCase):
    def test_created_by_spacing(self):
        # 05 wrote "按 标准方式 创建"
        from azinspect.peer.context import created_by
        self.assertEqual(created_by('标准方式'), '按标准方式创建')
        self.assertEqual(created_by('Terraform'), '按 Terraform 创建')

    def test_merged_network_rows_count_the_resource(self):
        # "该订阅有 N 个资源公网应用网关不带 WAF"
        from azinspect.waf.security_network.analyze import consolidate
        rows = [{'check': 'S-N6', 'resourceType': 'Microsoft.Network/applicationGateways', 'subscriptionId': 's', 'severity': '中',
                 'finding': f'应用网关 agw{i} 为 Standard_v2（不带 WAF），……', 'resourceName': f'agw{i}', 'resourceGroup': 'rg',
                 'environment': {'value': 'prod'}, 'evidence': {}, 'needsConfirmation': True, 'members': []} for i in range(3)]
        out = consolidate(rows)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]['finding'].startswith('该订阅有 3 个公网应用网关不带 WAF：'), out[0]['finding'])

    def test_app_gateway_without_listeners(self):
        # "直接对外提供 0 个监听（端口 ）"
        from azinspect.waf.security_network.checks import listener_text
        self.assertEqual(listener_text([]), '目前没有配置监听')
        self.assertEqual(listener_text([{'port': 443}, {'port': 80}, {'port': 443}]), '直接对外提供 3 个监听（端口 80, 443）')


class ZeroCountTests(unittest.TestCase):
    def test_only_text(self):
        # "只有 0 台装了 Azure Monitor 代理"
        from azinspect.waf.checks import only_text
        self.assertEqual(only_text(0, 12, '台', '装了代理'), '没有一台装了代理')
        self.assertEqual(only_text(3, 12, '台', '装了代理'), '只有 3 台装了代理')
        self.assertEqual(only_text(12, 12, '台', '装了代理'), '12 台都装了代理')

    def test_of_which(self):
        # "（含 0 个生产订阅）", "（其中 0 台在生产订阅）"
        from azinspect.waf.checks import of_which
        self.assertEqual(of_which(0, '含 {} 个生产订阅'), '')
        self.assertEqual(of_which(2, '其中 {} 台在生产订阅'), '（其中 2 台在生产订阅）')


class SingleResourceTextTests(unittest.TestCase):
    def test_r9_single_resource_name_is_followed_by_a_space(self):
        # "订阅 x 中的虚拟机 vm-a使用 Ubuntu 22.04 LTS"
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_lifecycle as tl
        rows = {'postgres': [{'id': tl.rid('b', 'Microsoft.DBforPostgreSQL/flexibleServers', 'pg-old'), 'name': 'pg-old',
                              'resourceGroup': 'rg', 'properties': {'version': '14'}}]}
        found, _run, _inv = tl.CheckTests.run_check(None, rows)
        self.assertIn('pg-old 使用 PostgreSQL 14', found[0]['finding'])

    def test_one_database_is_not_all(self):
        # "1 个生产 MySQL/PostgreSQL 主库都没有开启异地冗余备份"
        from azinspect.waf.checks import all_of
        self.assertEqual(all_of(1), '')
        self.assertEqual(all_of(3), '都')


class CrosscheckRuleNoteTests(unittest.TestCase):
    def test_x3_note_with_rules_is_matched(self):
        # crossCheckNotes with "rules": ["X3"] never covered X3 (the rule was not passed on)
        from azinspect import crosscheck
        import test_m4
        with tempfile.TemporaryDirectory() as d:
            ws = test_m4.workspace(d)
            io.write_json(ws.month_dir('narrative') / '02.json', {'crossCheckNotes': [
                {'subscription': 'app_prod', 'namePrefix': 'aks-big-123-vmss', 'note': 'y', 'rules': ['X3']}]})
            rules = {r['rule']: r for r in crosscheck.run(ws, log=lambda *_: None)['rules']}
            self.assertEqual(rules['X3']['status'], '已处理')
            io.write_json(ws.month_dir('narrative') / '02.json', {'crossCheckNotes': [
                {'subscription': 'app_prod', 'namePrefix': 'aks-big-123-vmss', 'note': 'y', 'rules': ['X1']}]})
            rules = {r['rule']: r for r in crosscheck.run(ws, log=lambda *_: None)['rules']}
            self.assertEqual(rules['X3']['status'], '需要处理')


class CostRetryRoundTests(unittest.TestCase):
    # four main cost queries gave up after minutes of 429s and the collection went on without them
    def collector(self, ws, api):
        from datetime import date
        from azinspect.core.period import ReportPeriod
        from azinspect.core.reuse import Reuse
        from azinspect.cost import collect as cc
        subs = [{'id': f'0000-{i}', 'name': f'sub{i}', 'group': 'g'} for i in range(3)]
        period = ReportPeriod.build('2026-09', run_date=date(2026, 10, 15))
        return cc.Collector(ws, api, period, subs, 'USD', log=lambda *_: None, reuse=Reuse(False)), subs

    class Api:
        def __init__(self, clock, throttle):
            self.clock, self.throttle, self.calls = clock, throttle, []

        def request(self, method, url, check, target='', body=None, max_attempts=6):
            self.calls.append((url.split('/')[4], target, max_attempts))
            self.clock.t += 5
            if self.throttle(url.split('/')[4], target, self.clock.t):
                return 429, None, 'HTTP 429'
            cols = [{'name': n} for n in ('Cost', 'UsageDate', 'ServiceName', 'ResourceGroupName', 'Currency')]
            return 200, {'properties': {'columns': cols, 'rows': [[10.0, 20260915, 'Storage', 'rg', 'USD']]}}, None

    def test_throttled_queries_are_read_again_at_the_end(self):
        from test_throttle import Clock
        clock = Clock()
        api = self.Api(clock, lambda sid, kind, t: sid == '0000-1' and kind in ('curActual', 'prevActual') and t < 300)
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            c, subs = self.collector(ws, api)
            c.run_jobs([(s, k) for s in subs for k in ('curActual', 'prevActual')])
            self.assertFalse(c.records[('0000-1', 'curActual')][0]['result']['ok'])
            c.retry_throttled(('curActual', 'prevActual'), clock=clock, sleep=clock.sleep)
            self.assertTrue(all(c.records[(s['id'], k)][0]['result']['ok'] for s in subs for k in ('curActual', 'prevActual')))
        retries = [x for x in api.calls if x[2] == 1]
        self.assertTrue(retries)
        self.assertEqual({x[0] for x in retries}, {'0000-1'})

    def test_retry_round_has_a_time_limit(self):
        from test_throttle import Clock
        from azinspect.cost import collect as cc
        clock = Clock()
        api = self.Api(clock, lambda sid, kind, t: sid == '0000-2' and kind == 'curActual')
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            c, subs = self.collector(ws, api)
            c.run_jobs([(s, 'curActual') for s in subs])
            start = clock.t
            c.retry_throttled(('curActual',), clock=clock, sleep=clock.sleep)
            self.assertFalse(c.records[('0000-2', 'curActual')][0]['result']['ok'])
        self.assertLessEqual(clock.t - start, cc.RETRY_SECONDS + 60)


class MissingCostExitTests(unittest.TestCase):
    def test_collect_says_which_costs_are_missing(self):
        # collect exited 0 with two subscriptions' costs unread and no word on how to read them again
        import contextlib
        import io as stdio
        from types import SimpleNamespace
        from azinspect import cli
        import azinspect.cost.pipeline

        def fake_collect(ws, *a, **k):
            io.write_json(ws.raw('cost/cost-data.json'), {'index': [
                {'name': 'sub-a', 'queryKind': 'curActual', 'status': 'success'},
                {'name': 'sub-b', 'queryKind': 'curActual', 'status': 'error'},
                {'name': 'sub-b', 'queryKind': 'prevActual', 'status': 'error'},
                {'name': 'sub-c', 'queryKind': 'curActual', 'status': 'denied'}]})
        out = stdio.StringIO()
        cfg = SimpleNamespace(reports=('01',), groups=())
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(out),                 unittest.mock.patch.object(cli, '_client', return_value=(cfg, None, SimpleNamespace(calls=[]))),                 unittest.mock.patch.object(azinspect.cost.pipeline, 'collect', fake_collect):
            code = cli.main(['collect', '--workspace', d, '--month', '2026-09', '--part', 'cost'])
        self.assertEqual(code, 1)
        text = out.getvalue()
        self.assertIn('sub-b', text)
        self.assertNotIn('sub-c', text)   # no permission: reading again does not help
        self.assertIn('--part cost --resume', text)


class ResumeStepTests(unittest.TestCase):
    def test_steps_run_again_when_more_costs_were_read(self):
        # a resumed collection reused the database/storage/log step chosen from costs that missed two subscriptions
        from azinspect.cost.pipeline import step_signature
        before = {'index': [{'subscriptionId': 'a', 'queryKind': 'curActual', 'ok': True},
                            {'subscriptionId': 'b', 'queryKind': 'curActual', 'ok': False}]}
        after = {'index': [{'subscriptionId': 'a', 'queryKind': 'curActual', 'ok': True},
                           {'subscriptionId': 'b', 'queryKind': 'curActual', 'ok': True}]}
        same = step_signature('resources', '2026-10', ['a', 'b'], before)
        self.assertEqual(same, step_signature('resources', '2026-10', ['b', 'a'], before))
        self.assertNotEqual(same, step_signature('resources', '2026-10', ['a', 'b'], after))


class SummaryPlanTests(unittest.TestCase):
    def test_merged_plan_drops_repeats_and_names_near_repeats(self):
        # 00 without its own actionPlan listed a 03 item and an almost identical 04 item one after the other
        from azinspect.summary import default_plan, similar_plan_items
        d = {'narrative': {'03': {'actionPlan': {'quarter': ['把存储账户模板的默认网络规则改为只允许专用终结点（见 05）', '为关键数据库开启异地备份']}},
                           '04': {'actionPlan': {'quarter': ['统一由流水线发布生产变更，并把存储模板的默认网络规则改为只允许专用终结点（见 05）',
                                                             '为关键数据库开启异地备份。']}}}}
        plan = default_plan(d)
        self.assertEqual(len(plan['quarter']), 3)
        pairs = similar_plan_items(plan)
        self.assertEqual(len(pairs), 1)
        self.assertIn('流水线', pairs[0][1])


class MetricBatchSplitTests(unittest.TestCase):
    # getBatch answered 400 "response size ... exceeded maximum limit of 125MB" for many scale sets whose instances
    # changed names all month, and 529 for a few large resources, every time: the whole batch went unread
    def collector(self, fail):
        import json as _json
        from types import SimpleNamespace
        import importlib
        pc = importlib.import_module('azinspect.waf.performance.collect')
        calls = []

        def request(method, url, check, target='', body=None, **kw):
            rids = body['resourceids']
            calls.append(len(rids))
            status = fail(rids)
            if status:
                return status, None, ('HTTP 400: The response size of 600000000 exceeded maximum limit of 125MB.' if status == 400 else f'HTTP {status}')
            values = [{'resourceid': r, 'value': [{'name': {'value': 'Percentage CPU'}, 'errorCode': 'Success',
                                                   'timeseries': [{'metadatavalues': [], 'data': [{'average': 1.0}]}]}]} for r in rids]
            return 200, {'values': values}, None
        c = object.__new__(pc.Collector)
        c.client, c.log, c.start, c.end, c.denied = SimpleNamespace(request=request), (lambda *_: None), 's', 'e', set()
        saved = {}
        c.raw = SimpleNamespace(save=lambda rel, obj: saved.update({rel: _json.loads(_json.dumps(obj))}))
        items = [{'id': f'/subscriptions/s/resourceGroups/rg/providers/x/vmss{i:02d}', 'subscriptionId': 's', 'location': 'regiona'} for i in range(12)]
        return c, items, calls

    def test_too_large_batch_is_split(self):
        c, items, calls = self.collector(lambda rids: 400 if len(rids) > 3 else None)
        res = c.batch_metrics('x', 'P2', items, 'ns', ['Percentage CPU'], 'average', interval='PT1H', flt="VMName eq '*'", top=1000)
        self.assertEqual(len(res), 12)
        self.assertFalse(any('_error' in v for v in res.values()))
        self.assertEqual(calls[0], 12)

    def test_529_is_split_and_only_the_failing_resource_stays_unread(self):
        bad = '/subscriptions/s/resourceGroups/rg/providers/x/vmss05'
        c, items, calls = self.collector(lambda rids: 529 if len(rids) > 4 or bad in rids else None)
        res = c.batch_metrics('x', 'P9', items, 'ns', ['Percentage CPU'], 'average')
        failed = sorted(k for k, v in res.items() if '_error' in v)
        self.assertEqual(failed, [bad.lower()])


class FileStorageTests(unittest.TestCase):
    def test_file_only_accounts_are_not_asked_for_blob_settings(self):
        # GET .../blobServices/default on a FileStorage account answers 400 FeatureNotSupportedForAccount: a read failure
        import importlib
        from types import SimpleNamespace
        rc = importlib.import_module('azinspect.waf.reliability.collect')
        asked, saved = [], {}

        def get(url, check, target=''):
            asked.append(url)
            return 200, {'properties': {}, 'value': []}, None
        c = object.__new__(rc._Collector)
        rows = [{'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/blobacct', 'name': 'blobacct', 'kind': 'StorageV2'},
                {'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/fileacct', 'name': 'fileacct', 'kind': 'FileStorage'}]
        c.c, c.window, c.log = SimpleNamespace(get=get), {'end': '2026-10-31T00:00:00Z'}, (lambda *_: None)
        c.raw = SimpleNamespace(save=lambda rel, obj: saved.update({rel: obj}), load=lambda rel, default=None: {'rows': rows})
        c.storage()
        self.assertFalse(any('fileacct/blobServices' in u for u in asked))
        blob = {x['name']: x for x in saved['storage/blobservices.json']}
        self.assertEqual(blob['fileacct']['status'], 'not-applicable')
        self.assertEqual(blob['blobacct']['status'], 200)


class ClassicAdminTests(unittest.TestCase):
    def test_retired_classic_administrators_are_not_read(self):
        # the retired classicAdministrators API answers 404 InvalidResourceType, counted as a failed read
        import importlib
        from types import SimpleNamespace
        sc = importlib.import_module('azinspect.waf.security_identity.collect')
        urls = []
        client = SimpleNamespace(request=lambda method, url, *a, **k: (urls.append(url), (200, {'value': []}, None))[1],
                                 get_all=lambda url, *a, **k: (urls.append(url), ([], 200, None))[1])
        sc._per_subscription(SimpleNamespace(save=lambda *a: None), client, {'id': 's1', 'name': 'sub1'})
        self.assertTrue(urls)
        self.assertFalse(any('classicAdministrators' in u for u in urls))


class CredentialRoleTests(unittest.TestCase):
    def test_roles_that_can_fetch_credentials_are_named(self):
        # access-check did not mention a role that can download an AKS kubeconfig (listClusterUserCredential)
        import contextlib
        import io as stdio
        from azinspect import cli

        class Client:
            def get_all(self, *_a, **_k):
                return [{'properties': {'roleDefinitionId': f'/r/{x}', 'scope': '/subscriptions/s'}} for x in ('aks', 'support', 'reader')], 200, None

            def get(self, rid, *_a, **_k):
                perms = {'aks': ('Azure Kubernetes Service Cluster User Role', ['Microsoft.ContainerService/managedClusters/listClusterUserCredential/action',
                                                                                'Microsoft.ContainerService/managedClusters/read']),
                         'support': ('Support Request Contributor', ['Microsoft.Authorization/*/read', 'Microsoft.Support/*']),
                         'reader': ('Reader', ['*/read'])}[rid.split('?')[0].rsplit('/', 1)[-1]]
                return 200, {'properties': {'roleName': perms[0], 'permissions': [{'actions': perms[1]}]}}, None
        out = stdio.StringIO()
        with contextlib.redirect_stdout(out):
            result = cli._roles(Client(), 'oid', ['s'], {'s': 'core'})
        self.assertEqual(result['credentialRoles'], ['Azure Kubernetes Service Cluster User Role'])
        self.assertEqual(result['lowRiskRoles'], ['Support Request Contributor'])
        self.assertIn('Azure Kubernetes Service Cluster User Role', out.getvalue())
        self.assertIn('凭据', out.getvalue())


class AppGatewayTextTests(unittest.TestCase):
    def test_autoscale_and_zones_are_described(self):
        # "固定只有 None 个实例、未开启自动扩缩容，也未显式配置可用区" for gateways with autoscale and zones; and with autoscale
        # the gateway stays highly available even at a minimum of 0 (Microsoft): the effect is minutes of scale-out, not an outage
        from azinspect.waf.reliability.analyze import appgw_low_instances
        text, rec, sev = appgw_low_instances('agw-a', 'Standard_v2', None, {'minCapacity': 0, 'maxCapacity': 4}, ['1', '2'], '中')
        self.assertIn('开启了自动扩缩容（最少 0 个、最多 4 个实例）', text)
        self.assertIn('已跨可用区 1、2 部署', text)
        self.assertIn('仍保持高可用', text)
        self.assertIn('3–5 分钟', text)
        for word in ('None', '中断', '未显式配置可用区'):
            self.assertNotIn(word, text)
        self.assertNotIn('可用区', rec)
        self.assertEqual(sev, '低')
        text, rec, sev = appgw_low_instances('agw-b', 'Standard_v2', 1, None, None, '中')
        self.assertIn('固定只有 1 个实例、未开启自动扩缩容，也未显式配置可用区', text)
        self.assertIn('中断', text)
        self.assertNotIn('缩到 0', text)
        self.assertIn('可用区', rec)
        self.assertEqual(sev, '中')


class AksStandardVersionTests(unittest.TestCase):
    def test_majority_version_out_of_support_is_not_the_standard(self):
        # 05 took the majority minor version as the standard and advised upgrading to it, though 03 found it past support
        from azinspect.peer.types_platform import standard_version
        versions = {'s/regiona': {'data': {'values': [
            {'version': v, 'capabilities': {'supportPlan': plans}} for v, plans in
            (('1.29', ['AKSLongTermSupport']), ('1.30', ['KubernetesOfficial']), ('1.31', ['KubernetesOfficial']), ('1.32', ['KubernetesOfficial']))]}}}
        self.assertEqual(standard_version('1.29', versions, ['s/regiona']), ('1.30', True))
        self.assertEqual(standard_version('1.31', versions, ['s/regiona']), ('1.31', False))
        self.assertEqual(standard_version('1.29', {}, ['s/regiona']), ('1.29', False))


class LogAnalyticsStandardTests(unittest.TestCase):
    def test_current_retention_is_not_shown_as_the_recommendation(self):
        # 05: "没有内部范例，按微软推荐：retentionInDays：30｜9 个都不符合" while every workspace kept 30 days,
        # and 04 found 30 days too short
        from types import SimpleNamespace
        from azinspect.peer import engine, types_data
        ws = [{'id': f'/w{i}', 'name': f'law-{i}', 'retention': 30} for i in range(3)]
        ctx = SimpleNamespace(rows=lambda rel: ws if 'workspaces' in rel or 'loganalytics' in rel else [])
        with unittest.mock.patch.object(engine.TypeReport, 'basic', lambda self, r, name=None: {'name': r['name'], 'id': None}):
            T, attributes = types_data.la_type(ctx)
        self.assertNotIn('retentionInDays', attributes)
        self.assertTrue(any('180' in str(v) for v in attributes.values()))
        self.assertIn('保留期', [g['attribute'] for g in T.uniform_gaps])


class AmaGapTests(unittest.TestCase):
    def test_monitor_agent_gap_has_numbers(self):
        # 05 section 7 said only "安装了 Azure Monitor 代理的机器数。"
        from azinspect.peer.types_infra import ama_gap
        g = ama_gap([{'ama': True}, {'ama': False}, {'ama': False}])
        self.assertEqual((g['followedBy'], g['of']), (1, 3))
        self.assertEqual(g['note'], '3 台中 1 台安装了 Azure Monitor 代理。')


class NodeOsChannelTests(unittest.TestCase):
    def test_channel_none_is_explained(self):
        # 03/04/05 wrote "节点操作系统自动更新通道为 None": Azure's value, read as a missing value
        from azinspect.waf.checks import node_os_channel
        # 0.10.9: one wording for 'None' and unset (the same table read "未设置（不自动更新）" and "None（不自动更新）")
        self.assertEqual(node_os_channel('None'), '不自动更新')
        self.assertEqual(node_os_channel(None), '不自动更新')
        self.assertEqual(node_os_channel('NodeImage'), 'NodeImage')


class NotApplicableReadTests(unittest.TestCase):
    def test_answers_that_mean_not_applicable_are_not_failed_reads(self):
        # data collected before the fix: R6 and S-I5 read "部分读取失败" because of a FileStorage account's Blob 400
        # and the retired classicAdministrators 404
        from azinspect.waf.common import not_applicable
        from azinspect.waf.reliability.analyze import _Run as Run
        calls = [{'check': 'R6', 'status': 400, 'error': 'FeatureNotSupportedForAccount: Blob is not supported for the account.',
                  'url': 'https://management.azure.com/subscriptions/s/x/storageAccounts/f/blobServices/default'},
                 {'check': 'R6', 'status': 200, 'error': None, 'url': 'https://management.azure.com/a'},
                 {'check': 'S-I5', 'status': 404, 'error': 'InvalidResourceType: x',
                  'url': 'https://management.azure.com/subscriptions/s/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01'}]
        self.assertEqual([not_applicable(c) for c in calls], [True, False, True])
        from azinspect.waf.common import coverage_entry
        run = object.__new__(Run)
        run.calls, run.coverage = calls[:2], {'R6': coverage_entry()}
        run.cover(['R6'], 'R6')
        self.assertEqual((run.coverage['R6']['attempted'], run.coverage['R6']['otherErrors']), (1, 0))


class AksVersionCrosscheckTests(unittest.TestCase):
    # X12: 05 advised upgrading AKS clusters to a version 03 found past standard support, and the advice reached the
    # 03 issue list through links.json
    def workspace(self, d, target):
        from azinspect import selection
        ws = io.Workspace(d, '2026-09')
        ws.create()
        vals = [{'version': v, 'capabilities': {'supportPlan': plans}} for v, plans in
                (('1.29', ['AKSLongTermSupport']), ('1.30', ['KubernetesOfficial']), ('1.31', ['KubernetesOfficial']))]
        io.write_json(ws.raw('waf/reliability/aks/k8s-versions.json'), {'s/regiona': {'status': 200, 'data': {'values': vals}}})
        aks = {'type': 'AKS 集群', 'typeKey': 'aks', 'baseline': {'attributes': {'version': target}},
               'deviations': [{'resourceName': 'aks-1', 'recommendation': f'逐个小版本升级到 {target}（先升控制面）'}]}
        io.write_json(ws.month_dir('findings') / 'peer' / 'baseline.json', {'types': [aks]})
        io.write_json(ws.month_dir('findings') / 'peer' / 'links.json', {'R9-aaaaaa': {'alignment': f'逐个小版本升级到 {target}'}})
        selection.save(ws, ['03', '05'])
        return ws

    def rule(self, ws):
        from azinspect import crosscheck
        return {r['rule']: r for r in crosscheck.run(ws, log=lambda *_: None)['rules']}['X12']

    def test_target_below_supported_needs_handling(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self.workspace(d, '1.29')
            r = self.rule(ws)
            self.assertEqual(r['status'], '需要处理')
            self.assertTrue(any('links.json' in i['resource'] for i in r['items']))
            self.assertTrue(all('1.30' in i['evidence'] for i in r['items']))
            io.write_json(ws.month_dir('narrative') / '05.json', {'topDeviations': [{'resource': 'aks-1', 'alignment': '升级到 1.30'}]})
            io.write_json(ws.month_dir('narrative') / '03.json', {'topIssues': [{'title': 'x', 'recommendation': '逐个小版本升级到 1.29'}]})
            r = self.rule(ws)
            self.assertTrue(any('narrative/03.json' in i['resource'] for i in r['items']))
            self.assertFalse(any('narrative/05.json' in i['resource'] for i in r['items']))

    def test_supported_target_passes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.rule(self.workspace(d, '1.30'))['status'], '通过')

    def test_without_version_table_not_checked(self):
        from azinspect import crosscheck, selection
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-09')
            ws.create()
            selection.save(ws, ['03'])
            r = {x['rule']: x for x in crosscheck.run(ws, log=lambda *_: None)['rules']}['X12']
            self.assertEqual(r['status'], '未检查')


class MergedRowSpacingTests(unittest.TestCase):
    def test_latin_summary_gets_a_space(self):
        # "11 个Azure Managed Redis 数据库使用明文协议" in the Excel issue list
        from azinspect.waf.security_network.analyze import consolidate
        rows = [{'check': 'S-N7', 'resourceType': 'Microsoft.Cache/redisEnterprise/databases', 'subscriptionId': 's', 'severity': '中',
                 'finding': f'amr{i} 使用 Plaintext 协议', 'resourceName': f'amr{i}', 'resourceGroup': 'rg',
                 'environment': {'value': 'prod'}, 'evidence': {}, 'needsConfirmation': False, 'members': []} for i in range(2)]
        self.assertTrue(consolidate(rows)[0]['finding'].startswith('该订阅有 2 个 Azure Managed Redis 数据库使用明文协议'))


class MetricUnreadCoverageTests(unittest.TestCase):
    def test_resources_still_unread_after_splitting_are_failed_reads(self):
        # aks-nodecond and lb-dip: a few resources stayed unread (529) but 04 did not say the check was incomplete,
        # so last month's problems on them would read as resolved
        from types import SimpleNamespace
        from azinspect.waf.performance.analyze import Analyzer
        calls = [{'check': 'P9', 'target': 'lb-vip/s/regiona', 'status': 529}, {'check': 'P9', 'target': 'lb-vip/s/regiona', 'status': 200},
                 {'check': 'P9', 'target': 'lb-vip/s/regiona', 'status': 529}, {'check': 'P2', 'target': 'aks-nodepool/s/regiona', 'status': 200}]
        files = {'index.json': {'calls': calls},
                 'metrics/lb-vip.json': {'label': 'lb-vip', 'results': {'/lb1': {'DipAvailability': []}, '/lb2': {'_error': 'HTTP 529: HTTP 529'},
                                                                         '/lb3': {'_error': 'not returned by getBatch'}}},
                 'metrics/aks-nodepool.json': {'label': 'aks-nodepool', 'results': {'/aks1': {'x': []}}}}
        a = object.__new__(Analyzer)
        a.raw = SimpleNamespace(load=lambda rel, default=None: files.get(rel, default), path=lambda rel: Path('/nonexistent') / rel)
        a.cov = {f'P{i}': {'attempted': 0, 'succeeded': 0, 'denied': 0, 'notes': []} for i in range(1, 11)}
        a.coverage_from_index()
        self.assertEqual(a.cov['P9']['otherErrors'], 1)
        self.assertTrue(any('lb2' in n for n in a.cov['P9']['notes']))
        self.assertEqual(a.cov['P2'].get('otherErrors', 0), 0)


if __name__ == '__main__':
    unittest.main()
