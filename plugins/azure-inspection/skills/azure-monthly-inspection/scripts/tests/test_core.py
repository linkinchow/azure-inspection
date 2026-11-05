"""Unit tests for the safety-critical core. Run: python -m unittest discover -s <skill>/scripts/tests"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import time
import unittest
import urllib.parse
from datetime import date
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.core import auth, config, fmt_md, http, io, period, quality  # noqa: E402

TENANT = '11111111-2222-3333-4444-555555555555'
SUB = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
TEMPLATE = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'


def fake_token(**claims):
    body = {'upn': 'ro@contoso.com', 'tid': TENANT, 'aud': 'https://management.azure.com/', 'exp': time.time() + 3600}
    body.update(claims)
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip('=')
    return f'{enc({"alg": "none"})}.{enc(body)}.sig'


class AuthTests(unittest.TestCase):
    def provider(self, **claims):
        return auth.TokenProvider('ro@contoso.com', TENANT, SUB, runner=lambda s, a: fake_token(**claims))

    def test_accepts_matching_identity(self):
        self.assertTrue(self.provider().get(auth.ARM))

    def test_rejects_other_account(self):
        with self.assertRaises(auth.IdentityMismatch):
            self.provider(upn='admin@contoso.com').get(auth.ARM)

    def test_rejects_other_tenant(self):
        with self.assertRaises(auth.IdentityMismatch):
            self.provider(tid='99999999-2222-3333-4444-555555555555').get(auth.ARM)

    def test_rejects_wrong_audience(self):
        with self.assertRaises(auth.IdentityMismatch):
            self.provider(aud='https://graph.microsoft.com').get(auth.ARM)

    def test_graph_audience_alias(self):
        self.assertTrue(self.provider(aud='00000003-0000-0000-c000-000000000000').get(auth.GRAPH))


class HttpGuardTests(unittest.TestCase):
    def test_reads_allowed(self):
        self.assertEqual(http.classify('GET', f'https://management.azure.com/subscriptions/{SUB}/resources?api-version=1'), auth.ARM)
        self.assertEqual(http.classify('POST', http.ARG_URL), auth.ARM)
        self.assertEqual(http.classify('POST', f'https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.CostManagement/query?api-version=2023-11-01'), auth.ARM)
        self.assertEqual(http.classify('POST', f'https://eastus.metrics.monitor.azure.com/subscriptions/{SUB}/metrics:getBatch?api-version=2023-10-01'), auth.METRICS)
        self.assertIsNone(http.classify('GET', http.PRICES + "?$filter=serviceName eq 'Virtual Machines'"))

    def test_writes_refused(self):
        for method in ('PUT', 'PATCH', 'DELETE'):
            with self.assertRaises(http.BlockedRequest):
                http.classify(method, f'https://management.azure.com/subscriptions/{SUB}?api-version=1')

    def test_secret_endpoints_refused(self):
        for path in ('/providers/Microsoft.Storage/storageAccounts/x/listKeys', '/providers/Microsoft.ContainerService/managedClusters/x/listClusterUserCredential',
                     '/providers/Microsoft.Web/sites/x/config/publishingcredentials/list', '/providers/Microsoft.KeyVault/vaults/x/secrets/y'):
            with self.assertRaises(http.BlockedRequest):
                http.classify('POST', f'https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg{path}?api-version=1')
            if 'secrets' in path:
                with self.assertRaises(http.BlockedRequest):
                    http.classify('GET', f'https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg{path}?api-version=1')

    def test_other_posts_and_hosts_refused(self):
        with self.assertRaises(http.BlockedRequest):
            http.classify('POST', f'https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Compute/virtualMachines/x/start?api-version=1')
        with self.assertRaises(http.BlockedRequest):
            http.classify('GET', 'https://myaccount.blob.core.windows.net/container/file')
        with self.assertRaises(http.BlockedRequest):
            http.classify('GET', 'http://management.azure.com/subscriptions')


class PortTests(unittest.TestCase):
    def test_default_port_allowed_other_ports_blocked(self):
        self.assertEqual(http.classify('GET', 'https://management.azure.com:443/subscriptions?api-version=1'), http.ARM)
        for url in ('https://management.azure.com:8443/subscriptions', 'https://user@management.azure.com/subscriptions'):
            with self.assertRaises(http.BlockedRequest):
                http.classify('GET', url)
        with self.assertRaises(http.BlockedRequest):
            http.classify('POST', 'https://management.azure.com:443/subscriptions/x/providers/Microsoft.Compute/virtualMachines/vm/start')


class UrlQuoteTests(unittest.TestCase):
    def test_spaces_encoded_existing_escapes_kept(self):
        url = "https://management.azure.com/x?$filter=a ge '2026-01-01'&b=%2F"
        self.assertEqual(urllib.parse.quote(url, safe=http._URL_SAFE),
                         "https://management.azure.com/x?$filter=a%20ge%20'2026-01-01'&b=%2F")


class FrontDoorCertificateTests(unittest.TestCase):
    def test_only_front_door_certificate_reference_is_allowed(self):
        sub = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        ok = f'https://management.azure.com/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Cdn/profiles/afd/secrets/cert?api-version=2024-02-01'
        self.assertEqual(http.classify('GET', ok), http.ARM)
        for url in (f'https://management.azure.com/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv/secrets/s',
                    f'https://management.azure.com/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Web/sites/app/config/secrets'):
            with self.assertRaises(http.BlockedRequest):
                http.classify('GET', url)

    def test_feature_switch_not_redacted(self):
        out = io.sanitize({'addonProfiles': {'azureKeyvaultSecretsProvider': {'enabled': True, 'config': {'enableSecretRotation': 'false'}}}})
        self.assertTrue(out['addonProfiles']['azureKeyvaultSecretsProvider']['enabled'])


class ConfigTests(unittest.TestCase):
    def test_template_needs_filling_but_parses(self):
        cfg = config.load(TEMPLATE)
        self.assertEqual(cfg.environment('region_app', 'redis-app-test01')[0], 'test')
        self.assertEqual(cfg.environment('region_app_prod', 'x')[0], 'prod')
        self.assertEqual(cfg.environment('', 'x', {'Environment': 'prod'}), ('prod', '标签 Environment=prod'))
        self.assertEqual(cfg.region('JapanEast'), '日本东部')

    def test_template_subscription_example(self):
        text = TEMPLATE.read_text(encoding='utf-8')
        line = next(x for x in text.splitlines() if 'contoso-core' in x)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'customer.yaml'
            p.write_text(text.replace(line, line.replace('#  - ', '- ')), encoding='utf-8')
            cfg = config.load(p)
        self.assertEqual(cfg.environment('contoso-core', 'vm-01')[0], 'prod')
        self.assertEqual(cfg.environment('shared', 'contoso-core')[0], 'unknown')

    def test_standard_tag_key_variants(self):
        cfg = config.load(TEMPLATE)
        cfg.standard_tag = {'key': 'managed_by', 'value': 'terraform'}
        for key in ('managed_by', 'managedBy', 'Managed-By'):
            self.assertTrue(cfg.created_by_standard({key: 'Terraform'}))
        self.assertFalse(cfg.created_by_standard({'owner': 'terraform'}))

    def test_scope_filters(self):
        cfg = config.load(TEMPLATE)
        cfg.exclude = ['sandbox-*']
        self.assertFalse(cfg.in_scope(SUB, 'sandbox-01'))
        self.assertTrue(cfg.in_scope(SUB, 'prod-01'))

    def test_invalid_config_reports_all_errors(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'customer.yaml'
            p.write_text('customer: {name: "", fileName: "a b"}\naccess: {tenantId: x}\n', encoding='utf-8')
            with self.assertRaises(config.ConfigError) as ctx:
                config.load(p)
            for word in ('customer.name', 'customer.fileName', 'access.tenantId', 'access.tokenSubscription', 'readonlyAccount'):
                self.assertIn(word, str(ctx.exception))


class PeriodTests(unittest.TestCase):
    def test_previous_and_days(self):
        p = period.ReportPeriod.build('2026-09', run_date=date(2026, 10, 15))
        self.assertEqual((p.previous.key, p.current.days, p.previous.days, p.following.key), ('2026-08', 30, 31, '2026-10'))
        self.assertEqual(period.Month.parse('2026-01').shift(-1).key, '2025-12')

    def test_unfinished_month_refused(self):
        with self.assertRaises(ValueError):
            period.ReportPeriod.build('2026-10', run_date=date(2026, 10, 15))

    def test_default_is_last_complete_month(self):
        self.assertEqual(period.ReportPeriod.build(run_date=date(2026, 1, 3)).current.key, '2025-12')


class CredentialMetadataTests(unittest.TestCase):
    def test_credential_expiry_kept_secret_parts_removed(self):
        out = io.sanitize({'passwordCredentials': [{'endDateTime': '2026-01-01', 'hint': 'abc', 'secretText': 'x', 'keyId': 'k'}],
                           'adminPassword': 'p'})
        cred = out['passwordCredentials'][0]
        self.assertEqual(cred['endDateTime'], '2026-01-01')
        self.assertEqual(cred['hint'], '[REDACTED]')
        self.assertEqual(cred['secretText'], '[REDACTED]')
        self.assertEqual(out['adminPassword'], '[REDACTED]')


class SanitizeTests(unittest.TestCase):
    def test_secrets_emails_phones_removed(self):
        out = io.sanitize({'primaryKey': 'abc', 'conn': 'AccountKey=xyz', 'owner': 'a.b@contoso.com 负责', 'phoneNumber': '123', 'count': 3})
        self.assertEqual(out['primaryKey'], '[REDACTED]')
        self.assertEqual(out['conn'], '[REDACTED]')
        self.assertEqual(out['owner'], '[email] 负责')
        self.assertEqual(out['phoneNumber'], '[REDACTED]')
        self.assertEqual(out['count'], 3)

    def test_key_vault_permission_names_kept(self):
        policy = {'accessPolicies': [{'objectId': 'o', 'permissions': {'keys': ['Get', 'List', 'unwrapKey'], 'secrets': ['all'], 'certificates': []}}]}
        self.assertEqual(io.sanitize(policy), policy)
        out = io.sanitize({'permissions': {'keys': ['c2VjcmV0LWtleS0x='], 'secrets': ['get']}, 'keys': ['Get'], 'properties': {'secrets': ['get']}})
        self.assertEqual(out['permissions'], {'keys': '[REDACTED]', 'secrets': '[REDACTED]'})
        self.assertEqual(out['keys'], '[REDACTED]')
        self.assertEqual(out['properties']['secrets'], '[REDACTED]')
        self.assertEqual(io.sanitize({'permissions': {'password': ['hunter'], 'keys': ['get']}})['permissions']['password'], '[REDACTED]')

    def test_resource_id_keys_are_data_not_field_names(self):
        rid = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/phonestore'
        kv = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/app-secrets'
        out = io.sanitize({'results': {rid: {'Transactions': [{'data': [1]}]}, kv: {'conn': 'AccountKey=xyz', 'password': 'p'}}})
        self.assertEqual(out['results'][rid], {'Transactions': [{'data': [1]}]})
        self.assertEqual(out['results'][kv], {'conn': '[REDACTED]', 'password': '[REDACTED]'})

    def test_contact_phone_fields_removed(self):
        out = io.sanitize({'smsReceivers': [{'phoneNumber': '1'}], 'businessPhones': ['1'], 'mobilePhone': '1', 'telephoneNumber': '1',
                           'contact': {'phone': '1'}, 'phonestore': {'sku': 'x'}})
        for key in ('smsReceivers', 'businessPhones', 'mobilePhone', 'telephoneNumber'):
            self.assertEqual(out[key], '[REDACTED]')
        self.assertEqual(out['contact']['phone'], '[REDACTED]')
        self.assertEqual(out['phonestore'], {'sku': 'x'})


class MarkdownTests(unittest.TestCase):
    def test_bold_punctuation_moved_outside(self):
        self.assertEqual(fmt_md.fix_bold('**容器允许匿名访问。**任何人'), '**容器允许匿名访问**。任何人')
        self.assertEqual(fmt_md.fix_bold('**（根本原因）**'), '（**根本原因**）')

    def test_format_keeps_numbers_and_links(self):
        text = '共 128 项问题，见[报告](a.md)和 `aks-prod-01`。'
        self.assertEqual(fmt_md.format_and_check(text), '共 128 项问题，见[报告](a.md)和 `aks-prod-01`。')

    def test_quality_check_finds_problems(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'r.md'
            p.write_text('**说明。**后文\n\n![图](charts/none.png)\n\n|a|b|\n|---|---|\n|1|2|3|\n\n本轮口径 x@y.com\n', encoding='utf-8')
            issues = '\n'.join(quality.check_markdown(p))
            for word in ('星号', '图片不存在', '列数', '本轮', '口径', '邮箱'):
                self.assertIn(word, issues)


class CostReportTests(unittest.TestCase):
    def test_dates_in_chinese(self):
        from azinspect.cost import report
        self.assertEqual(report.cn_date('2026-10-14T19:06:08Z'), '10月14日')
        self.assertEqual(report.cn_span('2026-10-07T08:00:00Z', '2026-10-14T08:00:00Z'), '10月7日至14日')
        self.assertEqual(report.cn_span('2026-09-28', '2026-10-03'), '9月28日至10月3日')
        self.assertEqual(report.two_months(period.ReportPeriod.build('2026-09', date(2026, 10, 15))), '2026年8月与9月')

    def test_unreadable_subscriptions_never_zero(self):
        from azinspect.cost import report
        subs = [{'name': f'lab-sub{i}', 'state': 'Disabled', 'cur': None, 'prev': None} for i in range(5)]
        subs.append({'name': 'prod', 'state': 'Enabled', 'cur': 10.0, 'prev': 8.0})
        subs.append({'name': 'denied', 'state': 'Enabled', 'cur': None, 'prev': 3.0})
        groups = report.unreadable({'subscriptions': subs})
        self.assertEqual(len(groups['订阅未启用']), 5)
        self.assertEqual(groups['费用查询失败或无权限'], ['denied'])
        self.assertIn('lab-sub*', report.unreadable_text({'subscriptions': subs}))

    def test_budget_text_counts(self):
        from azinspect.cost import report
        model = {'subscriptions': [{}] * 10, 'budgets': {'subscriptionsQueried': 4, 'budgets': [
            {'subscriptionName': 'a', 'properties': {'timeGrain': 'Annually', 'amount': 1000}}]}}
        text = report.budget_text(model, {'cur': '9月'})
        self.assertIn('对4个有费用订阅查询预算：3个无预算记录', text)
        self.assertIn('其余6个订阅未查询预算', text)


class LustreCostTests(unittest.TestCase):
    def paired_billing(self):
        root = f'/subscriptions/{SUB}/resourceGroups/rg/providers/'
        filesystem = root + 'Microsoft.StorageCache/amlFilesystems/'
        bill = lambda resource, value, service='Storage': {'subscriptionId': SUB, 'resourceId': resource,
                                                         'serviceName': service, 'cost': value, 'currency': 'USD'}
        data = {'subscriptions': [{'id': SUB, 'name': 'One', 'group': '其他'}], 'index': [
            {'subscriptionId': SUB, 'queryKind': kind, 'ok': True} for kind in
            ('curActual', 'prevActual', 'curResources', 'prevResources')], 'rows': {
                'prevActual': [bill(None, 80)],
                'curActual': [bill(None, 100), bill(None, 20, 'Bandwidth')],
                'prevResources': [bill(filesystem + 'old', 40), bill(filesystem + 'continuing', 25),
                                  bill(root + 'Microsoft.Storage/storageAccounts/account', 15)],
                'curResources': [bill(filesystem + 'new', 20), bill((filesystem + 'continuing').upper(), 30),
                                 bill(filesystem + 'continuing', 20, 'Bandwidth'),
                                 bill(filesystem + 'continuing/importJobs/job', 5),
                                 bill(root + 'Microsoft.StorageCache/caches/cache', 10),
                                 bill(root + 'Microsoft.Storage/storageAccounts/account', 35)]}}
        return data

    def test_paired_model_uses_billing_union_and_nonadditive_storage_child(self):
        from azinspect.cost.model import build_lustre_costs
        data = self.paired_billing()
        result = build_lustre_costs(data, period.ReportPeriod.build('2026-10', date(2026, 11, 5)))
        rows = {resource['name']: resource for resource in result['resources']}
        self.assertEqual(set(rows), {'old', 'new', 'continuing'})
        self.assertEqual((rows['old']['prevCostUSD'], rows['old']['curCostUSD']), (40, 0))
        self.assertEqual((rows['new']['prevCostUSD'], rows['new']['curCostUSD']), (0, 20))
        self.assertEqual((rows['continuing']['prevCostUSD'], rows['continuing']['curCostUSD']), (25, 50))
        storage = result['storageBreakdown']
        self.assertEqual((storage['prev'], storage['cur'], storage['delta']), (65, 50, -15))
        self.assertEqual((storage['parentPrev'], storage['parentCur']), (80, 100))
        self.assertEqual((storage['remainingPrev'], storage['remainingCur']), (15, 50))
        self.assertAlmostEqual(storage['dailyChangeRate'], (50 / 31) / (65 / 30) - 1)
        self.assertFalse(storage['additive'])

    def test_missing_previous_resource_query_stays_unknown(self):
        from azinspect.cost.model import build_lustre_costs
        data = self.paired_billing()
        data['index'] = [record for record in data['index'] if record['queryKind'] != 'prevResources']
        data['rows'].pop('prevResources')
        result = build_lustre_costs(data, period.ReportPeriod.build('2026-10', date(2026, 11, 5)))
        self.assertIsNone(result['storageBreakdown']['prev'])
        self.assertIsNone(result['storageBreakdown']['delta'])
        self.assertTrue(all(resource['prevCostUSD'] is None for resource in result['resources']))

    def test_comparison_view_retains_historical_billing_without_configuration(self):
        from azinspect.cost.model import build_lustre_costs
        from azinspect.cost import views
        billing = build_lustre_costs(self.paired_billing(), period.ReportPeriod.build('2026-10', date(2026, 11, 5)))
        continuing = next(resource for resource in billing['resources'] if resource['name'] == 'continuing')
        data = {'status': 200, 'resources': [{'resourceId': continuing['resourceId'], 'name': 'Continuing',
                                             'curCostUSD': 999, 'tier': 'Premium', 'capacityTiB': 8}]}
        merged = views.lustre_comparison(data, {'lustreCosts': billing})
        resources = {resource['name']: resource for resource in merged['resources']}
        self.assertEqual(len(resources), 3)
        self.assertEqual(resources['Continuing']['curCostUSD'], 50)
        self.assertEqual(resources['Continuing']['tier'], 'Premium')
        self.assertEqual(resources['old']['configurationStatus'], 'not_in_current_inventory')
        self.assertNotIn('capacityTiB', resources['old'])
        self.assertEqual(data['resources'][0]['curCostUSD'], 999)

    def test_paired_markdown_and_excel_show_months_and_read_statuses(self):
        from openpyxl import Workbook
        from azinspect.cost.model import build_lustre_costs
        from azinspect.cost import views
        from azinspect.cost.report import lustre_markdown
        billing = build_lustre_costs(self.paired_billing(), period.ReportPeriod.build('2026-10', date(2026, 11, 5)))
        data = views.lustre_comparison({'status': 200, 'resources': []}, {'lustreCosts': billing})
        text = '\n'.join(lustre_markdown(data, '10月', '9月'))
        for expected in ('9月实际费用USD', '10月实际费用USD', '其中：Azure Managed Lustre（已包含）', '65.00', '50.00', '-15.00', '日均变化率', '仅上月有账单记录', '当前配置快照'):
            self.assertIn(expected, text)
        workbook = Workbook()
        def sheet(name, title, note, columns):
            result = workbook.create_sheet(name)
            for values in ([title], [note], columns):
                result.append(values)
            return result
        worksheet = views.lustre_sheet(sheet, data, '10月', '9月')
        columns = {cell.value: cell.column for cell in worksheet[3]}
        self.assertIn('9月实际费用USD', columns)
        self.assertIn('9月读取情况', columns)
        self.assertIn('10月读取情况', columns)
        self.assertEqual(worksheet.max_row, 6)

    def test_lustre_summary_rounds_only_at_display_time(self):
        from azinspect.cost.model import build_lustre_costs
        data = self.paired_billing()
        root = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/'
        data['rows']['curResources'] = [{'subscriptionId': SUB, 'resourceId': root + name, 'serviceName': 'Storage',
                                         'cost': value, 'currency': 'USD'} for name, value in (('one', 1.005), ('two', 2.005))]
        data['rows']['curActual'] = [{'subscriptionId': SUB, 'serviceName': 'Storage', 'cost': 3.01, 'currency': 'USD'}]
        result = build_lustre_costs(data, period.ReportPeriod.build('2026-10', date(2026, 11, 5)))
        self.assertAlmostEqual(result['storageBreakdown']['cur'], 3.01)
        resource = next(resource for resource in result['resources'] if resource['name'] == 'one')
        self.assertEqual(resource['curCostUSD'], 1.005)

    def test_partial_denied_and_failed_months_do_not_become_zero(self):
        from azinspect.cost.model import build_lustre_costs
        for status in ('partial', 'denied', 'error'):
            with self.subTest(status=status):
                data = self.paired_billing()
                if status == 'partial':
                    data['rows']['prevResources'][0]['cost'] += 10
                else:
                    query = next(record for record in data['index'] if record['queryKind'] == 'prevResources')
                    query.update(ok=False, status=status, error={'httpStatus': 403 if status == 'denied' else 429})
                result = build_lustre_costs(data, period.ReportPeriod.build('2026-10', date(2026, 11, 5)))
                self.assertIsNone(result['storageBreakdown']['prev'])
                self.assertIsNone(result['storageBreakdown']['delta'])
                self.assertTrue(all(resource['prevCostUSD'] is None for resource in result['resources']))

    def test_credit_is_preserved_without_misleading_percentage(self):
        from azinspect.cost.model import build_lustre_costs
        data = self.paired_billing()
        data['rows']['prevResources'][1]['cost'] = -5
        data['rows']['prevActual'][0]['cost'] -= 30
        result = build_lustre_costs(data, period.ReportPeriod.build('2026-10', date(2026, 11, 5)))
        resource = next(resource for resource in result['resources'] if resource['name'] == 'continuing')
        self.assertEqual((resource['prevCostUSD'], resource['deltaUSD']), (-5, 55))
        self.assertIsNone(resource['changeRate'])
        self.assertIsNone(resource['dailyChangeRate'])

    def test_storage_breakdown_does_not_change_totals_services_or_charts(self):
        from azinspect.cost import model, charts
        data = self.paired_billing()
        data.update(complete=True, currency='USD', coverage={kind: {'attempted': 1} for kind in data['rows']})
        for rows in data['rows'].values():
            for record in rows:
                record.update(name='One', group='其他')
        report_period = period.ReportPeriod.build('2026-10', date(2026, 11, 5))
        with tempfile.TemporaryDirectory() as directory:
            workspace = io.Workspace(directory, '2026-10')
            workspace.save_raw('cost/cost-data.json', data)
            result = model.build(workspace, report_period)
        self.assertEqual((result['totals']['prev'], result['totals']['cur']), (80, 120))
        self.assertEqual({service['name'] for service in result['services']}, {'Storage', 'Bandwidth'})
        self.assertEqual(sum(service['cur'] for service in result['services']), 120)
        chart = charts.chart_data(result, {'forecast': {'subscriptions': []}, 'region': {'overall': {'byLocation': []}}}, report_period)
        self.assertEqual({name for name, delta in chart['services']}, {'Storage', 'Bandwidth'})

    def test_previous_resource_read_does_not_invalidate_current_configuration_steps(self):
        from azinspect.cost.pipeline import step_signature
        data = self.paired_billing()
        without_previous = {**data, 'index': [record for record in data['index'] if record['queryKind'] != 'prevResources']}
        self.assertEqual(step_signature('resources', '2026-10', [SUB], data),
                         step_signature('resources', '2026-10', [SUB], without_previous))

    def test_cost_only_collects_lustre_without_waf_or_usage_reads(self):
        from azinspect.cost import resources, views

        resource_id = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs'
        resource = {'id': resource_id, 'name': 'fs', 'subscriptionId': SUB, 'resourceGroup': 'rg',
                    'type': 'Microsoft.StorageCache/amlFilesystems', 'properties': {'storageCapacityTiB': 8}}

        class Client:
            def __init__(self, status):
                self.status, self.queries = status, []

            def arg(self, query, subs, check, label=None):
                self.queries.append(query)
                if 'amlfilesystems' in query.lower():
                    return ([resource], 200, None) if self.status == 200 else ([], self.status, 'HTTP 403')
                return [], 200, None

            def get(self, url, check, label):
                return 200, resource, None

            def request(self, *args, **kwargs):
                raise AssertionError('No metric or dependency calls are required for cost-only Lustre')

        for status in (200, 403):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                workspace = io.Workspace(directory, '2026-09')
                client = Client(status)
                resources.collect(workspace, client, period.ReportPeriod.build('2026-09', date(2026, 10, 5)),
                                  {'resources': [{'resourceId': resource_id, 'serviceName': 'Azure Managed Lustre', 'cost': 20}]},
                                  [{'id': SUB, 'name': 'One', 'state': 'Enabled'}], log=lambda *_: None)
                saved = views.load_lustre(workspace)
                self.assertEqual(saved['status'], status)
                self.assertFalse(workspace.raw('waf').exists())
                if status == 200:
                    self.assertEqual(saved['resources'][0]['curCostUSD'], 20)
                    self.assertEqual(saved['resources'][0]['capacityTiB'], 8)
                else:
                    self.assertIn('不完整', views.lustre_coverage(saved))
                self.assertEqual(sum('amlfilesystems' in query.lower() for query in client.queries), 1)

    def test_resume_requires_lustre_outputs_and_successful_inventory(self):
        from unittest.mock import Mock
        from azinspect.core.reuse import Reuse
        from azinspect.cost.pipeline import STEP_OUTPUTS, _step

        with tempfile.TemporaryDirectory() as directory:
            workspace = io.Workspace(directory, '2026-09')
            reuse = Reuse(True)
            marker = workspace.raw('cost/_steps/resources.json')
            old_outputs = [output for output in STEP_OUTPUTS['resources'] if 'lustre' not in output]
            for output in old_outputs:
                workspace.save_raw(output, {})
            io.write_json(marker, reuse.stamp({'outputs': old_outputs}, 'same'))
            run = Mock()
            _step(workspace, reuse, 'resources', 'same', run, lambda *_: None)
            run.assert_called_once()
            workspace.save_raw('cost/resources/lustre.json', {})
            workspace.save_raw('cost/resources/lustre/inventory.json', {'status': 403, 'errors': []})
            run.reset_mock()
            _step(workspace, reuse, 'resources', 'same', run, lambda *_: None)
            run.assert_called_once()
            workspace.save_raw('cost/resources/lustre/inventory.json', {'status': 200, 'errors': []})
            run.reset_mock()
            _step(workspace, reuse, 'resources', 'same', run, lambda *_: None)
            run.assert_not_called()

    def test_saved_raw_view_and_excel_keep_unknown_cost_blank(self):
        from openpyxl import Workbook, load_workbook
        from azinspect.cost import views
        from azinspect.cost.report import lustre_markdown

        resource_id = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs'
        data = {'status': 200, 'errors': [], 'snapshotAt': '2026-10-05T00:00:00Z',
                'resources': [{'resourceId': resource_id, 'name': 'fs', 'subscriptionName': 'One', 'skuName': 'Lustre-SKU',
                               'capacityTiB': 8, 'curCostUSD': None}]}
        with tempfile.TemporaryDirectory() as directory:
            workspace = io.Workspace(directory, '2026-09')
            self.assertIsNone(views.load_lustre(workspace)['status'])
            workspace.save_raw('cost/resources/lustre.json', data)
            saved = views.load_lustre(workspace)
            workbook = Workbook()

            def sheet(name, title, note, columns):
                result = workbook.create_sheet(name)
                for values in ([title], [note], columns):
                    result.append(values)
                return result

            worksheet = views.lustre_sheet(sheet, saved, '9月')
            path = Path(directory) / 'lustre.xlsx'
            workbook.save(path)
            reopened = load_workbook(path)
            columns = {cell.value: cell.column for cell in reopened[worksheet.title][3]}
            self.assertIsNone(reopened[worksheet.title].cell(4, columns['9月实际费用USD']).value)
            self.assertEqual(reopened[worksheet.title].cell(4, 4).value, resource_id)
            self.assertEqual(reopened[worksheet.title].cell(4, columns['配置容量TiB']).value, 8)
            reopened.close()
            text = '\n'.join(lustre_markdown(saved, '9月'))
            self.assertIn('Lustre-SKU', text)
            self.assertIn('费用未知', text)
            self.assertIn('未取得成本月份', text)
            self.assertIn('暂不估算节省金额', text)
            self.assertNotIn('删除', text)
            self.assertNotIn('暂停', text)
            self.assertIn('未检查', '\n'.join(lustre_markdown({'status': None, 'resources': []}, '9月')))
        self.assertIn('不完整', views.lustre_coverage({'status': 403, 'resources': []}))

    def test_inventory_costs_use_full_arm_ids_and_keep_unknowns(self):
        from copy import deepcopy
        from azinspect.cost.resources import collect_lustre

        resource_id = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/shared'
        other_id = resource_id.replace(SUB, 'bbbbbbbb-1111-2222-3333-444444444444')
        unknown_id = resource_id.replace('/shared', '/unknown')
        resources = [{'id': rid, 'name': rid.split('/')[-1], 'subscriptionId': rid.split('/')[2],
                      'resourceGroup': 'rg', 'type': 'Microsoft.StorageCache/amlFilesystems', 'location': 'eastus',
                      'sku': {'name': 'AMLFS-Durable-Premium-125'}, 'properties': {'storageCapacityTiB': 8}}
                     for rid in (resource_id, other_id, unknown_id)]

        class Client:
            def arg(self, query, subs, check, label):
                self.subs = subs
                return resources, 200, None

            def get(self, url, check, label):
                resource = next(item for item in resources if item['id'] == url.split('?')[0].removeprefix('https://management.azure.com'))
                return 200, resource, None

        model = {'resources': [{'resourceId': resource_id.upper(), 'cost': 12.5}, {'resourceId': resource_id, 'cost': -2.5},
                               {'resourceId': other_id, 'cost': 33}, {'resourceId': '', 'cost': 7}]}
        original = deepcopy(model)
        client = Client()
        with tempfile.TemporaryDirectory() as directory:
            workspace = io.Workspace(Path(directory), '2026-09')
            result = collect_lustre(workspace, client, period.ReportPeriod.build('2026-09', date(2026, 10, 5)), model,
                                    [{'id': SUB, 'name': 'One', 'state': 'Enabled'},
                                     {'id': other_id.split('/')[2], 'name': 'Two', 'state': 'Enabled'},
                                     {'id': 'disabled', 'name': 'Disabled', 'state': 'Disabled'}])
            rows = {item['resourceId']: item for item in result['resources']}
            self.assertEqual(rows[resource_id]['curCostUSD'], 10)
            self.assertEqual(rows[other_id]['curCostUSD'], 33)
            self.assertIsNone(rows[unknown_id]['curCostUSD'])
            self.assertEqual(rows[resource_id]['capacityTiB'], 8)
            self.assertIn('未采集', rows[resource_id]['telemetryNote'])
            self.assertTrue(workspace.raw('cost/resources/lustre/inventory.json').exists())
            self.assertTrue(workspace.raw('cost/resources/lustre.json').exists())
            self.assertNotIn('disabled', client.subs)
        self.assertEqual(model, original)


if __name__ == '__main__':
    unittest.main()
