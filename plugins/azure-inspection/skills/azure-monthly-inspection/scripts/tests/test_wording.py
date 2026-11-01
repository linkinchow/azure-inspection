"""Customer-facing wording when counts are 0 or 1 (a single subscription makes these common) and related display fixes."""
from __future__ import annotations

import contextlib
import importlib
import io as stdio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))


class AcceptanceTests(unittest.TestCase):
    """R9 covers AKS versions, end of support, certificates and retirement notices: its default criterion fits them all."""

    def test_r9_default_is_not_about_aks(self):
        from azinspect.waf.checks import ACCEPTANCE
        self.assertNotIn('节点镜像', ACCEPTANCE['R9'])
        self.assertNotIn('集群', ACCEPTANCE['R9'])

    def test_retirement_notices_have_their_own_criterion(self):
        from test_lifecycle import CheckTests, rid
        st = rid('a', 'Microsoft.Storage/storageAccounts', 'stlegacy')
        rows = {'retirements': [{'subscriptionId': 'a', 'trackingId': 'AB-1', 'title': 'Retirement notice: x', 'status': 'Active',
                                 'retirementDate': '2026-12-31T00:00:00Z'},
                                {'subscriptionId': 'a', 'trackingId': 'CD-2', 'title': 'Retirement notice: y', 'status': 'Active',
                                 'retirementDate': '2027-03-01T00:00:00Z'}],
                'retirement_resources': [{'trackingId': 'AB-1', 'targetResourceId': st, 'targetResourceType': 'Microsoft.Storage/storageAccounts'}],
                'retirement_advisor': []}
        found, _run, _inv = CheckTests().run_check(rows)
        linked = next(f for f in found if 'AB-1' in f['finding'])
        unlinked = next(f for f in found if '未能关联到具体资源' in f['finding'])
        self.assertIn('退役日期前', linked['acceptance'])
        self.assertIn('退役日期前', unlinked['acceptance'])


class CountWordingTests(unittest.TestCase):
    def test_root_owner_sentence_skips_zero(self):
        from azinspect.waf.security_identity import checks_access
        added = []
        ctx = SimpleNamespace(gobj={'p1': {'displayName': 'admin', 'type': '#microsoft.graph.user'}}, enabled=[],
                              add=lambda *a, **k: added.append(k))
        checks_access._root(ctx, [], ['p1'])
        self.assertNotIn('0 个用户账户', added[0]['finding'])
        self.assertIn('1 个用户在根范围', added[0]['finding'])
        added.clear()
        checks_access._root(ctx, ['p1'], [])
        self.assertIn('直接给 1 个用户账户分配了 Owner', added[0]['finding'])
        self.assertNotIn('另有 0 个', added[0]['finding'])

    def test_peer_ratio(self):
        from azinspect.peer.report import ratio
        self.assertEqual(ratio(1, 1, 100.0), '1/1 个（100%）')
        self.assertEqual(ratio(2, 5, 40.0), '2/5 个（40%）')

    def test_vm_title_and_pools(self):
        from azinspect.vm.report import adjust_line, title_line
        self.assertEqual(title_line('示例客户', 1), '# 示例客户：VM规格建议与预计节省')
        self.assertEqual(title_line('示例客户', 3), '# 示例客户：各订阅VM规格建议与预计节省')
        self.assertEqual(adjust_line(2, 0, 0), '- 建议调整 **2台机器**，都是独立VM。')
        self.assertIn('其中1台独立VM，1台在1个节点池中', adjust_line(2, 1, 1))

    def test_subscription_phrase(self):
        from azinspect.waf.common import subs_phrase
        self.assertEqual(subs_phrase(['core']), '订阅 core')
        self.assertEqual(subs_phrase(['a', 'b']), '2 个订阅')
        self.assertEqual(subs_phrase(['a', 'b'], '生产订阅'), '2 个生产订阅')
        self.assertEqual(subs_phrase(['core'], '生产订阅'), '生产订阅 core')
        self.assertEqual(subs_phrase(['core'], '生产订阅', '的'), '生产订阅 core 的')   # a space between the name and the Chinese after it
        self.assertEqual(subs_phrase(['a', 'b'], '生产订阅', '的'), '2 个生产订阅的')

    def test_none_have(self):
        from azinspect.waf.common import none_have
        self.assertEqual(none_have(['core']), '订阅 core 没有')
        self.assertEqual(none_have(['a', 'b']), '2 个订阅都没有')
        self.assertEqual(none_have(['core'], '生产（推断）订阅'), '生产（推断）订阅 core 没有')

    def test_defender_free_tier_single_subscription(self):
        root = Path(__file__).resolve().parents[1] / 'azinspect'
        text = (root / 'waf/security_identity/checks_access.py').read_text(encoding='utf-8')
        for old in ("f'{len(prod_off)} 个生产（推断）订阅的", "f'{len(unk_off)} 个环境不明的订阅", "f'{len(test_off)} 个测试/开发订阅",
                    "f'{len(no_reg)} 个订阅未注册"):
            self.assertNotIn(old, text)

    def test_peer_compliance_counts(self):
        from azinspect.peer.report import compliance
        t = {'typeKey': 'storage', 'population': {'total': 1}, 'deviations': [], 'uniformGaps': False,
             'baseline': {'attributeAdoption': {'x': 1}, 'fullyCompliantResources': []}}
        self.assertEqual(compliance(t)[2], '0/1 个完全符合')
        t['baseline']['fullyCompliantResources'] = ['a']
        self.assertEqual(compliance(t)[2], '1/1 个完全符合')

    def test_subscription_sentences_read_naturally(self):
        # the sentences reported from a single-subscription run
        root = Path(__file__).resolve().parents[1] / 'azinspect'
        text = ''.join((root / p).read_text(encoding='utf-8') for p in
                       ('waf/security_identity/checks_access.py', 'waf/security_identity/checks_resources.py', 'waf/operations/governance.py'))
        self.assertNotIn("个订阅都没有配置 Defender for Cloud 安全联系人", text)
        for new in ("f'订阅 {no_export[0]} 没有'", 'f"订阅 {without[0]} 没有任何预算或费用告警"', "'所查订阅'"):
            self.assertIn(new, text)


class EdgeAlertTests(unittest.TestCase):
    """O2 lists only the kinds of entry and hybrid network resources that lack alerts (no '应用网关 0 个')."""

    def test_zero_kinds_left_out(self):
        from unittest import mock
        from azinspect.waf.operations import monitoring
        added = []
        out = SimpleNamespace(add=lambda *a, **k: added.append(a))
        gw = {'type': 'microsoft.network/virtualnetworkgateways', 'environment': {'value': 'prod'}, 'alerts': 0, 'resourceName': 'gw-1',
              'typeLabel': 'VPN', 'subscriptionName': 'core', 'diagnosticSettings': None, 'hasDiagnosticLogs': False}
        with mock.patch.object(monitoring, 'advisor_count', return_value=0), mock.patch.object(monitoring, 'is_prod', return_value=True):
            monitoring.check_edge(SimpleNamespace(), out, [gw])
        text, recommendation = added[0][2], added[0][3]
        self.assertNotIn('0 个', text)
        self.assertNotIn('应用网关', recommendation + text)          # advice and consequences follow the kinds present
        self.assertNotIn('Front Door', recommendation + text)
        self.assertIn('ExpressRoute/VPN', recommendation)
        self.assertIn('专线或 VPN 中断', text)
        self.assertIn('ExpressRoute/VPN 网关和线路 1 个', text)
        self.assertNotIn('Connection Monitor', text)
        fd = {**gw, 'type': 'microsoft.cdn/profiles', 'resourceName': 'fd-1'}
        added.clear()
        with mock.patch.object(monitoring, 'advisor_count', return_value=0), mock.patch.object(monitoring, 'is_prod', return_value=True):
            monitoring.check_edge(SimpleNamespace(), out, [fd])
        self.assertIn('Front Door 1 个（未开日志）', added[0][2])


class DefenderMemberTests(unittest.TestCase):
    """S-I11 members: a subscription is named, and counted once whether it came from Defender or Policy."""

    def test_member(self):
        defender = importlib.import_module('azinspect.waf.defender')
        subs = {'0000-1': 'core'}
        self.assertEqual(defender._member('/subscriptions/0000-1', subs),
                         {'name': 'core', 'type': 'Microsoft.Resources/subscriptions', 'subscription': 'core'})
        self.assertEqual(defender._member('/subscriptions/0000-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1', subs),
                         {'name': 'st1', 'type': 'Microsoft.Storage/storageAccounts', 'subscription': 'core'})


class AmbaThresholdTests(unittest.TestCase):
    def test_bytes_read_in_tb(self):
        from azinspect.waf.amba import threshold_text
        self.assertEqual(threshold_text('UsedCapacity', 500000000000000.0), '500 TB')
        self.assertEqual(threshold_text('Percentage CPU', 80.0), '80')
        self.assertEqual(threshold_text('Percentage CPU', 2.5), '2.5')


class WriteRoleTests(unittest.TestCase):
    """access-check: roles that can only file quota or support requests are named apart from roles that change resources."""

    def test_low_risk_roles_named_apart(self):
        from azinspect import cli

        class Client:
            def get_all(self, *_a, **_k):
                return [{'properties': {'roleDefinitionId': '/r/quota', 'scope': '/subscriptions/s'}},
                        {'properties': {'roleDefinitionId': '/r/reader', 'scope': '/subscriptions/s'}}], 200, None

            def get(self, rid, *_a, **_k):
                perms = {'/r/quota?api-version=2022-04-01': ('Quota Request Operator', ['Microsoft.Quota/quotas/write']),
                         '/r/reader?api-version=2022-04-01': ('Reader', ['*/read'])}[rid]
                return 200, {'properties': {'roleName': perms[0], 'permissions': [{'actions': perms[1]}]}}, None
        out = stdio.StringIO()
        with contextlib.redirect_stdout(out):
            result = cli._roles(Client(), 'oid', ['s'], {'s': 'core'})
        self.assertEqual(result['writeRoles'], [])
        self.assertEqual(result['lowRiskRoles'], ['Quota Request Operator'])
        self.assertNotIn('可写角色', out.getvalue())
        self.assertIn('Quota Request Operator', out.getvalue())


if __name__ == '__main__':
    unittest.main()
