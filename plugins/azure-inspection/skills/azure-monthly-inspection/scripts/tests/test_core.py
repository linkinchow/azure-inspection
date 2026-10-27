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


if __name__ == '__main__':
    unittest.main()
