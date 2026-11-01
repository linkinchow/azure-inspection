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
        added, recorded = [], []

        def add(*a, **k):
            added.append(a)
            recorded.append(k)
        out = SimpleNamespace(add=add)
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
        self.assertIn('1 个生产混合网络资源没有任何告警', text)        # backlog Z: the title names only the kinds present
        item = recorded[0]
        self.assertIn('BGP', item['acceptance'])
        self.assertNotIn('应用网关', item['acceptance'])
        self.assertIn('ExpressRoute/VPN 网关 1 个', text)              # only gateways here: no 线路
        self.assertNotIn('Connection Monitor', text)
        fd = {**gw, 'type': 'microsoft.cdn/profiles', 'resourceName': 'fd-1'}
        added.clear()
        recorded.clear()
        with mock.patch.object(monitoring, 'advisor_count', return_value=0), mock.patch.object(monitoring, 'is_prod', return_value=True):
            monitoring.check_edge(SimpleNamespace(), out, [fd])
        self.assertIn('Front Door 1 个（未开日志）', added[0][2])
        self.assertIn('1 个生产入口资源没有任何告警', added[0][2])
        self.assertIn('Front Door 已配置', recorded[0]['acceptance'])


class LongNameTests(unittest.TestCase):
    """A very long resource name in a shortened finding must not push out the figure and the conclusion (backlog Y)."""

    def test_long_name_shortened_first(self):
        from azinspect.waf.report import first_clause
        name = 'app-service-backend-worker-node-pool-20260101-instance-0042'
        text = f'虚拟机 {name} 过去 30 天平均内存使用 91.7%，长期接近上限，业务高峰时可能触发内存不足'
        cut = first_clause(text, names=[name])
        self.assertIn('91.7%', cut)
        self.assertIn('长期接近上限', cut)
        self.assertIn('app-service-', cut)               # the name stays recognisable: its start and its end
        self.assertIn('0042', cut)
        self.assertNotIn(name, cut)
        self.assertEqual(first_clause(f'虚拟机 {name} 内存高', names=[name]), f'虚拟机 {name} 内存高')   # short enough: unchanged
        self.assertIn(name[:24], first_clause(text))   # only the finding's own resource names are shortened

    def test_shortened_names_stay_apart(self):
        # names that would look alike shortened keep more of their start and end, or stay whole
        from azinspect.waf.report import first_clause
        a, b = 'nsg-shared-east-prod-app-subnet-0001-default', 'nsg-shared-east-prod-web-subnet-0001-default'
        cut = first_clause(f'网络安全组 {a} 和 {b} 的入站规则对 Internet 开放了 22 端口，任何地址都能尝试登录，风险很高需要尽快收紧', names=[a, b])
        self.assertIn(a, cut)              # they would look alike shortened: telling them apart comes first
        c = 'nsg-shared-east-prod-app-subnet-0001-zz-a1'
        cut = first_clause(f'网络安全组 {c} 的入站规则对 Internet 开放了 22 端口，任何地址都能尝试登录，风险很高需要尽快收紧，请检查', names=[c, a])
        self.assertIn('22 端口', cut)       # alone in its sentence and distinct from the others: shortened

    def test_parent_child_name_keeps_the_child(self):
        # 'vnet/subnet': the start is the shared parent, the end is a common word; the child part tells it apart
        from azinspect.waf.report import first_clause
        name = 'shared-hub-vnet/frontend-subnet'
        text = f'子网 {name} 未关联 NSG，子网内有 VM 网卡 8 个、私有终结点 2 个，入站流量只靠 VM 自身的规则控制，风险较高需要尽快处理'
        cut = first_clause(text, names=[name])
        self.assertNotIn('shared-hub-v…subnet', cut)

    def test_names_kept_whole_when_shortening_keeps_nothing_more(self):
        # the cut stops at the same place either way: the name stays whole
        from azinspect.waf.report import first_clause
        name = 'service-backend-pool-alpha-0001'
        text = f'负载均衡 {name} 的后端只有 1 台虚拟机，' + '没有冗余任何一台维护都会中断服务' * 4
        self.assertIn(name, first_clause(text, 50, [name]))

    def test_listed_names_are_separate_names(self):
        # a resource column listing several names ('a, b, c') is not one long name (04 P8 read as one VM)
        from azinspect.waf.report import first_clause, member_names
        names = ['vm-sg-app-0001', 'vm-sg-app-0002', 'vm-sg-app-0003']
        f = {'resourceName': ', '.join(names), 'members': [{'name': n} for n in names]}
        text = f"虚拟机 {', '.join(names)}（法国中部）9 月跨洲出站 2,460 GB（约 USD 205），按区域间流量计费，建议把服务和数据放在同一区域"
        cut = first_clause(text, names=member_names(f))
        self.assertIn(', '.join(names), cut)
        self.assertNotIn(', '.join(names), member_names(f))

    def test_names_followed_only_by_names_or_brackets_stay(self):
        from azinspect.waf.report import first_clause, member_names
        a, b = 'eventhubs-namespace-shared-prod-a01', 'eventhubs-namespace-shared-prod-b01'
        f = {'resourceName': f'{a}、{b}', 'members': [{'name': a}, {'name': b}]}
        text = f'Event Hubs 标准层未开启自动扩容，吞吐单元用满后会被限流：{a}、{b}（APRL 建议 fbfef3df（规则库））'
        cut = first_clause(text, names=member_names(f))
        self.assertIn(a, cut)
        self.assertNotIn('…', cut.replace('……', ''))

    def test_settings_and_addresses_are_not_names(self):
        from azinspect.waf.report import first_clause
        text = 'MySQL 服务器 db-1 的参数 require_secure_transport=OFF，客户端可以不加密连接，数据在传输中可能被窃听，建议尽快打开强制加密并检查客户端'
        self.assertIn('require_secure_transport=OFF', first_clause(text, names=['db-1']))

    def test_unit_kept_with_its_number(self):
        from azinspect.waf.report import first_clause
        text = '丙' * 60 + '跨洲出站 2,460 GB（约 USD 205），费用较高'
        self.assertIn('2,460 GB', first_clause(text))

    def test_unit_kept_when_the_cut_falls_inside_it(self):
        from azinspect.waf.report import first_clause
        for pad in range(55, 66):   # the limit falls anywhere in '2,460 GB'
            text = '丙' * pad + '跨洲出站 2,460 GB（约 USD 205），费用较高'
            cut = first_clause(text)
            self.assertNotRegex(cut, r'[\d,]……$', cut)
            self.assertFalse(cut.endswith('2,460……') or cut.endswith('1,……'), cut)

    def test_a_colon_is_followed_by_its_first_item(self):
        from azinspect.waf.report import first_clause
        text = '戊' * 62 + '目标资源已删除：pe-storage-blob-01（目标：存储账户 st01）、pe-kv-01'
        cut = first_clause(text)
        self.assertIn('：pe-storage-blob-01', cut)

    def test_no_tiny_bracket_left(self):
        from azinspect.waf.report import first_clause
        text = '丁' * 66 + '（目标：存储账户 stdata01）未开启专用 DNS'
        self.assertNotIn('（目', first_clause(text, 68))

    def test_names_only_sentence_keeps_names(self):
        # a sentence that only lists names: nothing follows them to keep, so the first name stays whole
        from azinspect.waf.report import first_clause
        a, b = 'lb-group-east-prod-frontend-external-a', 'lb-group-east-prod-frontend-internal-b'
        cut = first_clause(f'生产负载均衡的前端未跨可用区：{a}、{b}')
        self.assertIn(a, cut)
        self.assertNotIn('………', cut)
        self.assertTrue(cut.endswith('……'), cut)


class KeyRowTests(unittest.TestCase):
    """A virtual network gateway read both with the key resources and with the gateway query is one resource."""

    def test_gateway_counted_once(self):
        from azinspect.waf.operations.data import build_key_rows
        gid = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworkGateways/gw-1'
        target = {'id': gid, 'name': 'gw-1', 'type': 'microsoft.network/virtualnetworkgateways', 'subscriptionId': 's', 'resourceGroup': 'rg'}
        vnetgw = {**target, 'gwType': 'ExpressRoute', 'sku': 'ErGw1AZ'}
        circuit = {'id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/expressRouteCircuits/er-1', 'name': 'er-1',
                   'type': 'microsoft.network/expressroutecircuits', 'subscriptionId': 's', 'resourceGroup': 'rg'}
        d = SimpleNamespace(targets=[target], diag_idx={}, storage_cost={}, rows=lambda name: [vnetgw, circuit] if name == 'vnetgw' else [],
                            subname=lambda s: 'core', env_of=lambda *a: {'value': 'prod'}, sub_env=lambda s: {'value': 'prod'})
        rows = build_key_rows(d, [])
        self.assertEqual(sorted(r['resourceName'] for r in rows), ['er-1', 'gw-1'])
        self.assertEqual(next(r for r in rows if r['resourceName'] == 'gw-1')['gatewayType'], 'ExpressRoute')


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
