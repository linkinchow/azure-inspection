"""Tests for the shared WAF finding format and the 03/04 report builder (synthetic data, no network)."""
from __future__ import annotations

import os
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
os.environ.setdefault('AZINSPECT_NO_EXCEL', '1')  # structural formula check only; Excel recalculation is slow
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.core import config, io  # noqa: E402
from azinspect.waf import common, report  # noqa: E402

TEMPLATE = Path(__file__).resolve().parents[2] / 'templates' / 'customer.example.yaml'


def workspace(d):
    ws = io.Workspace(d, '2026-09')
    ws.create()
    io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [
        {'id': f'{i:08d}-0000-0000-0000-000000000000', 'name': f'app_{i}_prod', 'state': 'Enabled'} for i in range(3)]
        + [{'id': f'{i:08d}-0000-0000-0000-000000000001', 'name': f'lab-old{i}', 'state': 'Disabled'} for i in range(5)]})
    return ws


def sample(ws, cfg):
    f = common.Findings('reliability')
    e = common.env(cfg, 'app_1_prod', 'aks-app')
    f.add('R1', '高', '子网只剩 10 个 IP', '换用更大的子网', subscription='app_1_prod', resource_name='vnet/aks-subnet',
          resource_type='Microsoft.Network/virtualNetworks/subnets', environment=e, legacy_id='REL-001')
    f.add('R7', '中', '3 台虚拟机没有备份', '配置备份', subscription='app_1_prod', resource_name='3 台虚拟机', environment=e,
          members=[{'name': f'vm{i}', 'type': 'Microsoft.Compute/virtualMachines', 'subscription': 'app_1_prod'} for i in range(3)],
          needs_confirmation='确认哪些机器有数据')
    f.add('R7', '低', '测试机没有备份', '按需配置', subscription='app_2_prod', resource_name='vm0',
          resource_type='Microsoft.Compute/virtualMachines', environment=e)
    f.write(ws, window=common.window(), coverage={'R1': common.coverage_entry()}, scope={})
    return f


class LustreReliabilityTests(unittest.TestCase):
    def test_completed_archive_does_not_hide_observed_hsm_errors(self):
        from azinspect.waf.reliability.analyze import _Run, managed_lustre
        with tempfile.TemporaryDirectory() as directory:
            ws = workspace(directory)
            raw = common.Raw(ws, 'reliability')
            resource_id = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs'
            raw.save('lustre/inventory.json', {'status': 200, 'errors': [], 'rows': [
                {'id': resource_id, 'name': 'fs', 'properties': {'health': {'state': 'Available'},
                 'hsm': {'settings': {'container': '/storage/container'}, 'archiveStatus': {'status': 'Completed'}}}}]})
            raw.save('lustre/metrics.json', {'resources': {resource_id.lower(): {'HSMActionErrors': [
                {'dims': {'mdtnum': '0'}, 'data': [{'timeStamp': '2026-10-01T00:00:00Z', 'total': 2}]}]}}})
            run = _Run(ws, config.load(TEMPLATE))
            managed_lustre(run)
            self.assertEqual([item['check'] for item in run.findings.items], ['R22'])
            self.assertEqual(run.findings.items[0]['evidence']['errorCounts']['HSMActionErrors'], 2)

    def test_missing_inventory_and_denied_discovery_are_not_healthy(self):
        from azinspect.waf.reliability.analyze import _Run, managed_lustre
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as directory:
            ws = workspace(directory)
            for record in (None, {'status': 403, 'error': 'Forbidden', 'rows': [], 'errors': []}):
                if record is not None:
                    common.Raw(ws, 'reliability').save('lustre/inventory.json', record)
                run = _Run(ws, cfg)
                managed_lustre(run)
                self.assertEqual(run.findings.items, [])
                self.assertGreater(run.coverage['R22']['otherErrors'], 0)
                self.assertEqual(run.coverage['R22']['succeeded'], 0)
                if record:
                    self.assertEqual(run.coverage['R22']['denied'], 1)

    def test_confirmed_failures_only_and_full_inventory(self):
        from azinspect.waf.reliability.analyze import _Run, managed_lustre
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as directory:
            ws = workspace(directory)
            raw = common.Raw(ws, 'reliability')
            rows = []
            for index, properties in enumerate((
                {'health': {'state': 'Degraded'}, 'hsm': {'archiveStatus': {'status': 'Failed'}}},
                {'health': {'state': 'Maintenance'}}, {},
                {'health': {'state': 'Unavailable'}},
            )):
                rows.append({'id': f'/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs{index}',
                             'name': f'fs{index}', 'sku': {'name': 'AMLFS-Durable-Premium-125', 'tier': 'Premium'},
                             'location': 'eastus', 'zones': ['1'], 'properties': {**properties, 'storageCapacityTiB': 8}})
            rows[-1]['_readError'] = 'HTTP 403'
            raw.save('lustre/inventory.json', {'status': 200, 'rows': rows, 'errors': [{'status': 403}]})
            run = _Run(ws, cfg)
            managed_lustre(run)
            self.assertEqual([item['check'] for item in run.findings.items], ['R11', 'R22'])
            self.assertEqual(run.inventory['lustre']['rows'], rows)
            self.assertTrue(any('403' in note for note in run.coverage['R11']['notes']))
            self.assertTrue(any('未检查' in note for note in run.coverage['R22']['notes']))
            self.assertGreater(run.coverage['R22']['otherErrors'], 0)


class LustreOperationsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.ws = workspace(self.directory.name)
        self.cfg = config.load(TEMPLATE)
        self.raw = common.Raw(self.ws, 'operations')
        self.subscription = '00000000-0000-0000-0000-000000000000'
        self.resource_id = f'/subscriptions/{self.subscription}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs'
        self.group_id = f'/subscriptions/{self.subscription}/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/oncall'
        self.row = {'id': self.resource_id, 'name': 'fs', 'subscriptionId': self.subscription, 'resourceGroup': 'rg',
                    'type': 'Microsoft.StorageCache/amlFilesystems', 'location': 'eastus', 'zones': ['1'],
                    'sku': {'name': 'AMLFS-Durable-Premium-125', 'tier': 'Premium'},
                    'properties': {'storageCapacityTiB': 8, 'maintenanceWindow': {'dayOfWeek': 'Sunday', 'timeOfDayUTC': '02:00'}}}
        self.save_inventory([self.row])
        self.raw.save('arg/alertrules.json', {'status': 200, 'rows': []})
        self.raw.save('arg/actiongroups.json', {'status': 200, 'rows': []})
        self.raw.save('diagnostic-settings.json', [{'id': self.resource_id, 'self': {'http': 200, 'value': []}}])

    def save_inventory(self, rows, errors=None):
        self.raw.save('lustre/inventory.json', {'status': 200, 'rows': rows, 'errors': errors or []})

    def analyze(self):
        from azinspect.waf.operations.analyze import analyze
        return analyze(self.ws, self.cfg, log=lambda *_: None)

    def metric_rule(self, name, metric, scope=None, **properties):
        return {'id': f'/subscriptions/{self.subscription}/resourceGroups/rg/providers/Microsoft.Insights/metricAlerts/{name}',
                'name': name, 'type': 'microsoft.insights/metricalerts', 'subscriptionId': self.subscription, 'resourceGroup': 'rg',
                'properties': {'enabled': True, 'scopes': [scope or self.resource_id],
                               'criteria': {'allOf': [{'metricName': metric, 'metricNamespace': self.row['type'],
                                                       'operator': 'GreaterThan', 'threshold': 100, 'timeAggregation': 'Average'}]},
                               'actions': [{'actionGroupId': self.group_id}], **properties}}

    def alerts(self, rules, groups=None):
        self.raw.save('arg/alertrules.json', {'status': 200, 'rows': rules})
        self.raw.save('arg/actiongroups.json', {'status': 200, 'rows': groups if groups is not None else [
            {'id': self.group_id, 'name': 'oncall', 'enabled': True, 'email': 1}]})

    def diagnostics(self, logs, metrics=None, destination=True, status=200):
        from azinspect.waf.operations.collect import _diag_values
        properties = {'logs': logs, 'metrics': metrics or []}
        if destination:
            properties['workspaceId'] = f'/subscriptions/{self.subscription}/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/audit'
        settings = _diag_values({'value': [{'name': 'audit', 'properties': properties}]})
        self.raw.save('diagnostic-settings.json', [{'id': self.resource_id, 'self': {'http': status, 'value': settings if status == 200 else None}}])

    def lustre_findings(self, result):
        return [finding for finding in result['findings'] if finding.get('resourceType') == self.row['type']]

    def test_inventory_all_filesystems_sku_tier_capacity_region_zones(self):
        second = copy.deepcopy(self.row)
        second['id'] = second['id'].replace(self.subscription, '00000001-0000-0000-0000-000000000000')
        second['subscriptionId'] = '00000001-0000-0000-0000-000000000000'
        second['sku']['tier'] = 'Other'
        self.save_inventory([self.row, second])
        self.raw.save('diagnostic-settings.json', [{'id': row['id'], 'self': {'http': 200, 'value': []}}
                               for row in (self.row, second)])
        result = self.analyze()
        rows = [row for row in result['inventory']['keyResources'] if row['type'] == self.row['type'].lower()]
        self.assertEqual(result['inventory']['lustre']['rows'], [self.row, second])
        self.assertEqual(len(rows), 2)
        self.assertEqual({row['tier'] for row in rows}, {'Premium', 'Other'})
        for row in rows:
            self.assertEqual(row['sku'], 'AMLFS-Durable-Premium-125')
            self.assertEqual(row['storageCapacityTiB'], 8)
            self.assertEqual(row['location'], 'eastus')
            self.assertEqual(row['zones'], ['1'])
            self.assertIn('无需代理', row['platformMetrics'])
        findings = self.lustre_findings(result)
        self.assertEqual({finding['check'] for finding in findings}, {'O2', 'O3'})
        self.assertEqual(len({finding['id'] for finding in findings}), 4)

    def test_enabled_capacity_inode_alerts_and_audit_without_metrics_export(self):
        self.alerts([self.metric_rule('bytes', 'OSTBytesUsed'), self.metric_rule('files', 'MDTFilesUsed')])
        self.diagnostics([{'category': 'AmlfsAuditEvent', 'enabled': True}])
        result = self.analyze()
        self.assertEqual(self.lustre_findings(result), [])
        row = result['inventory']['keyResources'][0]
        self.assertTrue(row['lustreAuditLogging'])
        self.assertEqual(row['auditRetentionReview']['settings'][0]['logs'], ['AmlfsAuditEvent'])
        maintenance = result['inventory']['lustreMaintenance'][0]
        self.assertEqual(maintenance['maintenanceWindow']['dayOfWeek'], 'Sunday')
        self.assertIn('人工', maintenance['suitability'])

    def test_and_combined_capacity_inode_rule_is_not_independent_coverage(self):
        rule = self.metric_rule('combined', 'OSTBytesUsed')
        rule['properties']['criteria']['allOf'].extend(self.metric_rule('files', 'MDTFilesUsed')['properties']['criteria']['allOf'])
        self.alerts([rule])
        self.diagnostics([{'category': 'AmlfsAuditEvent', 'enabled': True}])
        result = self.analyze()
        self.assertEqual([item['check'] for item in self.lustre_findings(result)], ['O2'])

    def test_alert_scope_type_region_namespace_and_action_group_are_required(self):
        from azinspect.waf.operations.data import Data, build_key_rows
        from azinspect.waf.operations.monitoring import lustre_alerts
        good = self.metric_rule('bytes', 'OSTBytesUsed')
        variants = []
        for field, value in (('enabled', False), ('scopes', [self.resource_id + '-other']), ('actions', [])):
            rule = copy.deepcopy(good)
            rule['properties'][field] = value
            variants.append(rule)
        unrelated = self.metric_rule('cpu', 'Percentage CPU')
        variants.append(unrelated)
        wrong_namespace = copy.deepcopy(good)
        wrong_namespace['properties']['criteria']['allOf'][0]['metricNamespace'] = 'Microsoft.Compute/virtualMachines'
        variants.append(wrong_namespace)
        partial_targets = copy.deepcopy(good)
        partial_targets['properties']['criteria']['allOf'][0]['dimensions'] = [
            {'name': 'ostnum', 'operator': 'Include', 'values': ['0']}]
        variants.append(partial_targets)
        for rule in variants:
            with self.subTest(properties=rule['properties']):
                self.alerts([rule])
                data = Data(self.ws, self.cfg)
                self.assertFalse(any(lustre_alerts(data, build_key_rows(data, [])[0]).values()))
        for group in ({'id': self.group_id, 'enabled': False, 'email': 1},
                      {'id': self.group_id, 'enabled': True, 'email': 0},
                      {'id': self.group_id + '-other', 'enabled': True, 'email': 1}):
            self.alerts([good], [group])
            data = Data(self.ws, self.cfg)
            self.assertFalse(any(lustre_alerts(data, build_key_rows(data, [])[0]).values()))
        scope = f'/subscriptions/{self.subscription}/resourceGroups/rg'
        for resource_type, region, expected in ((self.row['type'], 'eastus', True),
                                                (self.row['type'], 'westus', False), ('Microsoft.Compute/virtualMachines', 'eastus', False)):
            self.alerts([self.metric_rule('bytes', 'OSTBytesUsed', scope.upper(),
                                       targetResourceType=resource_type, targetResourceRegion=region)])
            data = Data(self.ws, self.cfg)
            self.assertEqual(bool(lustre_alerts(data, build_key_rows(data, [])[0])['capacity']), expected)

    def test_metrics_only_disabled_audit_and_no_destination_do_not_prove_audit(self):
        for logs, destination in (([], True), ([{'category': 'AmlfsAuditEvent', 'enabled': False}], True),
                                  ([{'category': 'AmlfsAuditEvent', 'enabled': True}], False)):
            self.diagnostics(logs, [{'category': 'AllMetrics', 'enabled': True}], destination)
            result = self.analyze()
            self.assertEqual(len([finding for finding in self.lustre_findings(result) if finding['check'] == 'O3']), 1)

    def test_unknown_alerts_diagnostics_maintenance_and_failed_get_not_healthy(self):
        self.raw.save('arg/alertrules.json', {'status': 403, 'error': 'Forbidden', 'rows': None})
        self.diagnostics([], status=403)
        self.row['properties'].pop('maintenanceWindow')
        self.save_inventory([self.row])
        result = self.analyze()
        self.assertEqual(self.lustre_findings(result), [])
        for check in ('O2', 'O3', 'O4'):
            self.assertTrue(any('未检查' in note for note in result['coverage'][check]['notes']))
            self.assertGreater(result['coverage'][check]['otherErrors'], 0)
        self.row['_readError'] = 'HTTP 403'
        self.save_inventory([self.row], [{'resourceId': self.resource_id, 'status': 403}])
        result = self.analyze()
        self.assertEqual(self.lustre_findings(result), [])
        self.assertEqual(result['coverage']['O1']['denied'], 1)

    def test_diagnostics_collects_all_lustre_without_cost_or_performance(self):
        from azinspect.waf.operations.collect import _Collector
        class Client:
            def __init__(self):
                self.urls = []

            def get(self, url, check, target):
                self.urls.append(url)
                return 200, {'value': []}, None

        client = Client()
        collector = _Collector(self.ws, self.cfg, client, {}, lambda *_: None)
        collector.diagnostics()
        self.assertEqual(len(client.urls), 1)
        self.assertIn(self.resource_id, client.urls[0])
        self.assertNotIn('blobServices', client.urls[0])
        self.assertEqual(len(self.raw.load('diagnostic-settings.json')), 1)


class LustreCollectorTests(unittest.TestCase):
    def test_each_pillar_collects_its_own_inventory_without_performance(self):
        from azinspect.core import lustre
        from azinspect.waf.reliability.collect import _Collector as ReliabilityCollector
        from azinspect.waf.operations.collect import _Collector as OperationsCollector
        from azinspect.waf.security_network.collect import collect as collect_network
        cfg = config.load(TEMPLATE)
        subscription = '00000000-0000-0000-0000-000000000000'
        row = {'id': f'/subscriptions/{subscription}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs',
               'name': 'fs', 'subscriptionId': subscription, 'resourceGroup': 'rg', 'type': lustre.RESOURCE_TYPE,
               'location': 'eastus', 'zones': ['1'], 'sku': {'name': 'AMLFS-Durable-Premium-125', 'tier': 'Premium'},
               'properties': {'storageCapacityTiB': 8}}

        class Client:
            def __init__(self):
                self.calls, self.discoveries, self.reads = [], [], []

            def arg(self, query, subscriptions, check, target):
                if query == lustre.QUERY:
                    self.discoveries.append((subscriptions, check))
                    return [copy.deepcopy(row)], 200, None
                return [], 200, None

            def get(self, url, check, target):
                self.reads.append(url)
                return 200, copy.deepcopy(row), None

        with tempfile.TemporaryDirectory() as directory:
            ws = workspace(directory)
            client = Client()
            ReliabilityCollector(ws, client, {}, lambda *_: None).lustre()
            OperationsCollector(ws, cfg, client, {}, lambda *_: None).lustre()
            collect_network(ws, cfg, client, {}, log=lambda *_: None)
            self.assertEqual(len(client.discoveries), 3)
            self.assertEqual({check for _, check in client.discoveries}, {'R22', 'O1', 'S-N10'})
            self.assertTrue(all(len(subscriptions) == 3 for subscriptions, _ in client.discoveries))
            self.assertEqual(len(client.reads), 3)
            for pillar in ('reliability', 'security_network', 'operations'):
                saved = common.Raw(ws, pillar).load('lustre/inventory.json')
                self.assertEqual(saved['rows'][0]['sku']['tier'], 'Premium')
                self.assertEqual(saved['rows'][0]['properties']['storageCapacityTiB'], 8)
            self.assertFalse(ws.raw('waf/performance').exists())


class FindingTests(unittest.TestCase):
    def test_ids_are_stable_and_unique(self):
        a, b = common.Findings('reliability'), common.Findings('reliability')
        x = a.add('R1', '高', 'f', 'r', subscription='S', resource_name='n')
        y = a.add('R1', '高', 'f', 'r', subscription='S', resource_name='n')
        z = b.add('R1', '中', 'other text', 'r', subscription='s', resource_name='N')
        self.assertNotEqual(x['id'], y['id'])
        self.assertEqual(x['id'], z['id'])
        self.assertTrue(x['id'].startswith('R1-'))

    def test_env_uses_customer_rules(self):
        cfg = config.load(TEMPLATE)
        self.assertEqual(common.env(cfg, 'region_app', 'redis-app-test01')['value'], 'test')
        self.assertEqual(common.env_text(common.env(cfg, 'region_app_prod', 'x')), '生产（推断：订阅名称）')


class ReportTests(unittest.TestCase):
    def test_build_counts_resources_and_scope(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as d:
            ws = workspace(d)
            sample(ws, cfg)
            meta = report.build(ws, cfg, '03', {}, log=lambda *_: None)
            self.assertEqual(meta['total'], 3)
            self.assertEqual(meta['pendingConfirmation'], 1)
            md = (ws.month_dir('reports') / '03_可靠性与安全巡检报告.md').read_text(encoding='utf-8')
            self.assertIn('共发现 **3** 项问题', md)
            self.assertIn('4 台虚拟机', md)
            self.assertIn('lab-old*', md)
            report.audit(ws, cfg, '03', log=lambda *_: None)

    def test_narrative_overrides_and_validation(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as d:
            ws = workspace(d)
            sample(ws, cfg)
            narrative = {'severityOverrides': [{'findingId': 'REL-001', 'severity': '中', 'reason': '已确认有备用子网'}],
                         'topIssues': [{'title': '子网不足', 'detail': 'd', 'impact': 'i', 'recommendation': {'rootCause': 'a', 'fix': 'b'},
                                        'findingIds': ['REL-001']}]}
            meta = report.build(ws, cfg, '03', narrative, log=lambda *_: None)
            self.assertEqual(meta['bySeverity'].get('高', 0), 0)
            md = (ws.month_dir('reports') / '03_可靠性与安全巡检报告.md').read_text(encoding='utf-8')
            self.assertIn('**根本原因**：a', md)
            self.assertNotIn('## 3. 安全', md)
            said = []   # an id that does not exist is left out with a warning (0.10.4), not a stop
            report.build(ws, cfg, '03', {'topIssues': [{'title': 'x', 'findingIds': ['R9-000000']}]}, log=said.append)
            self.assertTrue(any('R9-000000' in s for s in said))
            with self.assertRaises(report.NarrativeError):
                report.build(ws, cfg, '03', {'severityOverrides': [{'findingId': 'REL-001', 'severity': '低'}]}, log=lambda *_: None)


    def test_coverage_limits_listed_in_scope_section(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as d:
            ws = workspace(d)
            f = common.Findings('reliability')
            f.add('R1', '高', '子网只剩 10 个 IP', '换用更大的子网', subscription='app_1_prod', resource_name='vnet/aks-subnet')
            text = '资源健康数据里还有 3 条已删除资源的残留状态记录（Unknown 3 条），这些资源不在本次读取的资源清单中，没有列为问题。'
            f.write(ws, window=common.window(), coverage={'R11': {**common.coverage_entry(), 'limits': [text]}}, scope={})
            report.build(ws, cfg, '03', {}, log=lambda *_: None)
            md = (ws.month_dir('reports') / '03_可靠性与安全巡检报告.md').read_text(encoding='utf-8')
        self.assertIn(f'- {text}', md.split('检查范围与限制')[1])



class ActionPlanTests(unittest.TestCase):
    """actionPlan entries may be a list or a string with items separated by '；' (00, 03 and 04 alike)."""

    def test_string_and_list_normalized(self):
        self.assertEqual(report.action_plan({'week': '关闭公网入口；开启异地备份；', 'month': ['补齐告警；配置预算', ' '], 'quarter': None}),
                         {'week': ['关闭公网入口', '开启异地备份'], 'month': ['补齐告警', '配置预算']})

    def test_03_lists_each_item(self):
        cfg = config.load(TEMPLATE)
        with tempfile.TemporaryDirectory() as d:
            ws = workspace(d)
            sample(ws, cfg)
            report.build(ws, cfg, '03', {'actionPlan': {'week': ['扩容子网。', '配置备份'], 'month': '整理标签；清理闲置盘'}}, log=lambda *_: None)
            md = (ws.month_dir('reports') / '03_可靠性与安全巡检报告.md').read_text(encoding='utf-8')
        section = md.split('建议处理顺序')[1].split('##')[0]
        for item in ('扩容子网', '配置备份', '整理标签', '清理闲置盘'):
            self.assertIn(f'  - {item}\n', section)
        self.assertNotIn('扩容子网。配置备份', section)

    def test_00_plan_never_split_into_characters(self):
        from azinspect import summary
        d = {'narrative': {'03': {'actionPlan': {'week': '扩容子网；配置备份'}}, '04': {'actionPlan': {'week': ['补齐告警']}}}}
        plan = summary.default_plan(d)
        self.assertEqual(plan, {'week': ['扩容子网', '配置备份', '补齐告警']})
        lines = summary.plan_lines({'week': '关闭公网入口；开启异地备份', 'month': ['补齐告警']})
        self.assertIn('- 关闭公网入口', lines)
        self.assertIn('- 补齐告警', lines)
        self.assertFalse(any(len(x) == 3 and x.startswith('- ') for x in lines))


if __name__ == '__main__':
    unittest.main()
