"""Managed Lustre inspection uses synthetic management-plane evidence only."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.core.lustre import capacity_pressure, resource_summary, collect_inventory, collect_metrics, missing_targets, error_totals


def series(target, values):
    return {'dims': {'ostnum': target}, 'data': [
        {'timeStamp': f'2026-10-01T{hour:02d}:00:00Z', 'average': value}
        for hour, value in values]}


class CapacityTests(unittest.TestCase):
    def test_hot_target_is_not_hidden_by_healthy_target(self):
        metrics = {'OSTBytesUsed': [series('0', [(hour, 96) for hour in range(3)]),
                                    series('1', [(hour, 1) for hour in range(3)])],
                   'OSTBytesTotal': [series(target, [(hour, 100) for hour in range(3)]) for target in ('0', '1')]}
        result = capacity_pressure(metrics)
        hot = next(row for row in result if row['target'] == '0')
        self.assertEqual(hot['peakPct'], 96)
        self.assertEqual(hot['criticalHours'], 3)
        self.assertEqual(hot['sustainedHours'], 3)

    def test_missing_zero_denominator_and_different_targets_are_unknown(self):
        self.assertEqual(capacity_pressure({}), [])
        self.assertEqual(capacity_pressure({'OSTBytesUsed': [series('0', [(0, 0)])],
                                            'OSTBytesTotal': [series('0', [(0, 0)])]}), [])
        self.assertEqual(capacity_pressure({'OSTBytesUsed': [series('0', [(0, 98)])],
                                            'OSTBytesTotal': [series('1', [(0, 100)])]}), [])

    def test_gaps_and_unaligned_timestamps_do_not_form_a_sustained_event(self):
        result = capacity_pressure({'OSTBytesUsed': [series('0', [(0, 95), (2, 95), (3, 95)])],
                                    'OSTBytesTotal': [series('0', [(0, 100), (1, 100), (2, 100), (3, 100)])]})
        self.assertEqual(result[0]['sustainedHours'], 2)
        self.assertEqual(result[0]['samples'], 3)

    def test_valid_zero_is_retained_and_capacity_is_time_aligned(self):
        result = capacity_pressure({'OSTBytesUsed': [series('0', [(0, 0), (1, 90)])],
                                    'OSTBytesTotal': [series('0', [(0, 100), (1, 200)])]})
        self.assertEqual(result[0]['peakPct'], 45)
        self.assertEqual(result[0]['samples'], 2)


class InventoryTests(unittest.TestCase):
    def test_partial_target_usage_is_not_a_filesystem_total(self):
        resource = {'id': '/fs', 'name': 'fs'}
        metrics = {'OSTBytesUsed': [series('0', [(0, 10)])],
                   'OSTBytesTotal': [series(target, [(0, 100)]) for target in ('0', '1')]}
        self.assertIsNone(resource_summary(resource, metrics)['observedUsedTiB'])
        self.assertIn(('OST', 'Bytes', '1'), missing_targets(metrics, capacity_pressure(metrics)))
        metrics['OSTBytesUsed'].append(series('1', [(0, 20)]))
        self.assertEqual(resource_summary(resource, metrics)['observedUsedTiB'], 30 / 2**40)

    def test_error_counts_deduplicate_chunk_boundary_samples(self):
        entry = {'dims': {'mdtnum': '0'}, 'data': [{'timeStamp': '2026-10-01T00:00:00Z', 'total': 4}]}
        self.assertEqual(error_totals({'HSMActionErrors': [entry, entry]})['HSMActionErrors'], 4)
        self.assertIsNone(error_totals({})['HSMActionErrors'])

    def test_tier_capacity_and_unknown_values(self):
        row = resource_summary({'id': '/filesystem/fs', 'name': 'fs', 'sku': {'name': 'AMLFS-Durable-Premium-250'},
                                'properties': {'storageCapacityTiB': 8}, 'zones': ['1']})
        self.assertEqual((row['tier'], row['sku'], row['capacityTiB']), ('Durable-Premium', 'AMLFS-Durable-Premium-250', 8))
        self.assertEqual(row['tierSource'], 'sku.name')
        self.assertIsNone(row['ClientReadThroughput'])
        self.assertIsNone(resource_summary({'id': '/fs', 'name': 'fs'})['capacityTiB'])

    def test_failed_config_keeps_error_and_inventory(self):
        saved = {}
        resource = {'id': '/subscriptions/s/providers/Microsoft.StorageCache/amlFilesystems/fs',
                    'name': 'fs', 'subscriptionId': 's', 'properties': {'storageCapacityTiB': 8}}
        client = SimpleNamespace(arg=lambda *args: ([resource], 200, None), get=lambda *args: (403, None, 'Forbidden'))
        result = collect_inventory(client, [{'id': 's'}], lambda key, value: saved.update({key: value}), 'P7')
        self.assertEqual(result['rows'][0]['_readError'], 'Forbidden')
        self.assertEqual(result['errors'][0]['status'], 403)
        self.assertIn('lustre/inventory.json', saved)

    def test_definitions_and_metric_requests_are_read_only_and_dimensioned(self):
        calls, saved = [], {}

        def get(url, *args):
            calls.append(url)
            if '/metricDefinitions?' in url:
                return 200, {'value': [{'name': {'value': name}, 'supportedAggregationTypes': ['Average'],
                                       'dimensions': [{'value': 'ostnum'}]} for name in ('OSTBytesUsed', 'OSTBytesTotal')]}, None
            return 200, {'value': [{'name': {'value': name}, 'timeseries': [
                {'metadatavalues': [{'name': {'value': 'ostnum'}, 'value': '0'}],
                 'data': [{'timeStamp': '2026-10-01T00:00:00Z', 'average': value}]}]}
                for name, value in (('OSTBytesUsed', 90), ('OSTBytesTotal', 100))]}, None
        resource = {'id': '/subscriptions/s/providers/Microsoft.StorageCache/amlFilesystems/fs', 'name': 'fs'}
        result = collect_metrics(SimpleNamespace(get=get), [resource],
                                 {'start': '2026-10-01T00:00:00Z', 'end': '2026-10-02T00:00:00Z'},
                                 lambda key, value: saved.update({key: value}))
        metrics = result['resources'][resource['id'].lower()]
        self.assertEqual(capacity_pressure(metrics)[0]['peakPct'], 90)
        self.assertIn('%24filter=ostnum+eq+%27%2A%27', calls[-1])
        self.assertIn('interval=PT1H', calls[-1])
        from urllib.parse import parse_qs, urlsplit
        query = parse_qs(urlsplit(calls[-1]).query)
        self.assertEqual(query['timespan'], ['2026-10-01T00:00:00Z/2026-10-02T00:00:00Z'])


class MetricSelectionTests(unittest.TestCase):
    def collect(self, selection=None, definitions_by_resource=None, failed_definitions=(), metric_errors=None,
                resource_names=('first', 'second', 'third')):
        from urllib.parse import parse_qs, urlsplit
        from azinspect.core.lustre import METRICS
        calls, saved = {}, {}

        def get(url, check, target):
            if '/metricDefinitions?' in url:
                if target in failed_definitions:
                    return 403, None, 'Forbidden'
                selected = (definitions_by_resource or {}).get(target, METRICS)
                return 200, {'value': [
                    {'name': {'value': name}, 'supportedAggregationTypes': [METRICS[name][0]],
                     'dimensions': [{'value': METRICS[name][1]}] if METRICS[name][1] else []}
                    for name in selected]}, None
            names = parse_qs(urlsplit(url).query)['metricnames'][0].split(',')
            calls.setdefault(target, set()).update(names)
            return 200, {'value': [{'name': {'value': name}, 'timeseries': [],
                                   **({'errorCode': 'BadRequest', 'errorMessage': metric_errors[name]}
                                      if metric_errors and name in metric_errors else {})} for name in names]}, None

        resources = [{'id': f'/subscriptions/s/providers/Microsoft.StorageCache/amlFilesystems/{name}', 'name': name}
                     for name in resource_names]
        result = collect_metrics(SimpleNamespace(get=get), resources,
                                 {'start': '2026-10-01T00:00:00Z', 'end': '2026-10-02T00:00:00Z'},
                                 lambda key, value: saved.update({key: value}), names=selection)
        return calls, result

    def test_every_filesystem_requests_all_supported_metrics(self):
        from azinspect.core.lustre import METRICS
        calls, _ = self.collect()
        for resource, names in calls.items():
            with self.subTest(resource=resource):
                self.assertEqual(names, set(METRICS))

    def test_explicit_subset_is_preserved_for_every_filesystem(self):
        selected = ('OSTBytesUsed', 'OSTBytesTotal', 'LustreClientEvictions', 'ManualImporterErrors')
        calls, _ = self.collect(selected)
        self.assertEqual(len(calls), 3)
        for resource, names in calls.items():
            with self.subTest(resource=resource):
                self.assertEqual(names, set(selected))

    def test_resource_order_does_not_change_requested_metrics(self):
        calls, _ = self.collect()
        reversed_calls, _ = self.collect(resource_names=('third', 'second', 'first'))
        self.assertEqual(calls, reversed_calls)

    def test_reliability_subset_is_preserved_and_input_is_not_modified(self):
        selected = ['HSMActionErrors', 'AutoImporterErrors', 'ManualImporterErrors']
        calls, _ = self.collect(selected)
        self.assertEqual(selected, ['HSMActionErrors', 'AutoImporterErrors', 'ManualImporterErrors'])
        self.assertTrue(all(names == set(selected) for names in calls.values()))

    def test_first_filesystem_definitions_do_not_limit_later_filesystems(self):
        from azinspect.core.lustre import METRICS
        calls, _ = self.collect(definitions_by_resource={'first': ('OSTBytesUsed',)})
        self.assertEqual(calls['first'], {'OSTBytesUsed'})
        self.assertEqual(calls['second'], set(METRICS))
        self.assertEqual(calls['third'], set(METRICS))

    def test_failed_definitions_do_not_prevent_later_filesystems(self):
        from azinspect.core.lustre import METRICS
        calls, _ = self.collect(failed_definitions=('first',))
        self.assertNotIn('first', calls)
        self.assertEqual(calls['second'], set(METRICS))
        self.assertEqual(calls['third'], set(METRICS))

    def test_request_evidence_distinguishes_empty_samples_from_not_requested(self):
        from azinspect.core.lustre import METRICS
        _, record = self.collect()
        for resource in record['resources'].values():
            self.assertEqual(set(resource['_planned']), set(METRICS))
            self.assertEqual(set(resource['_supported']), set(METRICS))
            for item in resource['_coverage'].values():
                self.assertEqual(item['state'], 'empty_samples')
                self.assertEqual(item['requests'][0]['http'], 200)
                self.assertEqual(item['samples'], 0)

    def test_http_success_with_metric_error_is_not_valid_data(self):
        _, record = self.collect(metric_errors={'ManualImporterErrors': 'No preaggregation'})
        for resource in record['resources'].values():
            item = resource['_coverage']['ManualImporterErrors']
            self.assertEqual(item['state'], 'metric_error')
            self.assertEqual(item['requests'][0]['http'], 200)
            self.assertEqual(resource['_errors']['ManualImporterErrors'], 'No preaggregation')

    def test_optional_metric_error_does_not_invalidate_complete_capacity(self):
        from azinspect.core.lustre import apply_coverage
        coverage = {'attempted': 0, 'succeeded': 0, 'denied': 0, 'otherErrors': 0, 'notes': []}
        resource = {'_errors': {'ManualImporterErrors': 'No preaggregation'}, '_coverage': {
            'OSTBytesUsed': {'state': 'complete'}, 'OSTBytesTotal': {'state': 'complete'},
            'ManualImporterErrors': {'state': 'metric_error'}}}
        apply_coverage(coverage, {'status': 200, 'errors': [], 'rows': []}, {'resources': {'/fs': resource}})
        self.assertEqual(coverage['otherErrors'], 0)
        self.assertTrue(any('可选' in note for note in coverage['notes']))
        resource['_coverage']['OSTBytesUsed']['state'] = 'empty_samples'
        apply_coverage(coverage, {'status': 200, 'errors': [], 'rows': []}, {'resources': {'/fs': resource}})
        self.assertEqual(coverage['otherErrors'], 1)


class PolicyTests(unittest.TestCase):
    def test_configuration_validation(self):
        import yaml
        from azinspect.core import config
        template = Path(__file__).resolve().parents[2] / 'templates/customer.example.yaml'
        data = yaml.safe_load(template.read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'customer.yaml'
            for value in ({'warningPct': True}, {'warningPct': 95, 'criticalPct': 90}, {'sustainedHours': 0},
                          {'requireCmk': 'false'}, {'minCoveragePct': 101}, {'extra': 1}):
                data['rules']['managedLustre'] = value
                path.write_text(yaml.safe_dump(data), encoding='utf-8')
                with self.assertRaises(config.ConfigError):
                    config.load(path)
            data['rules']['managedLustre'] = {'warningPct': 80, 'requireCmk': True}
            path.write_text(yaml.safe_dump(data), encoding='utf-8')
            self.assertTrue(config.load(path).managed_lustre['requireCmk'])


class ListRenderingTests(unittest.TestCase):
    def test_healthy_filesystem_is_listed_with_tier_and_capacity(self):
        from azinspect.core import config
        from azinspect.waf.report import lustre_rows, write_excel
        from openpyxl import load_workbook
        resource = {'id': '/fs', 'name': 'healthy-fs', 'sku': {'name': 'AMLFS-Durable-Premium-250'},
                    'location': 'eastus', 'zones': ['1'], 'properties': {'storageCapacityTiB': 8}}
        datasets = {'reliability': {'coverage': {}, 'inventory': {'lustre': {'rows': [resource]}}}}
        rows = lustre_rows(datasets)
        self.assertEqual(rows[0]['tier'], 'Durable-Premium')
        cfg = config.load(Path(__file__).resolve().parents[2] / 'templates/customer.example.yaml')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lustre.xlsx'
            write_excel(path, cfg, '03', [], {}, datasets, [], '2026-10-01', '', [])
            workbook = load_workbook(path)
            sheet = workbook['Lustre文件系统']
            self.assertEqual(sheet.cell(4, 3).value, 'healthy-fs')
            self.assertEqual(sheet.cell(4, 4).value, 'Durable-Premium')
            self.assertEqual(sheet.cell(4, 7).value, 8)
            self.assertIsNone(sheet.cell(4, 10).value)
            workbook.close()


class PerformanceTests(unittest.TestCase):
    def test_lustre_analysis_keeps_list_and_generates_target_specific_finding(self):
        from azinspect.core import config, io
        from azinspect.waf import common
        from azinspect.waf.performance.analyze import Analyzer
        template = Path(__file__).resolve().parents[2] / 'templates/customer.example.yaml'
        with tempfile.TemporaryDirectory() as directory:
            ws = io.Workspace(directory, '2026-09')
            ws.create()
            subscription_id = '00000000-0000-0000-0000-000000000000'
            io.write_json(ws.raw('waf/scope.json'), {'subscriptions': [{'id': subscription_id, 'name': 'app-prod', 'state': 'Enabled'}]})
            raw = common.Raw(ws, 'performance')
            raw.save('manifest.json', {'window': {'start': '2026-10-01T00:00:00Z', 'end': '2026-10-01T03:00:00Z', 'days': 1}})
            resource_id = f'/subscriptions/{subscription_id}/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/fs'
            raw.save('lustre/inventory.json', {'status': 200, 'errors': [], 'rows': [
                {'id': resource_id, 'name': 'fs', 'location': 'eastus', 'sku': {'name': 'AMLFS-Durable-Premium-250'},
                 'properties': {'storageCapacityTiB': 8}}]})
            metrics = {f'{kind}{unit}{role}': [
                {'dims': {dimension: '0'}, 'data': [{'timeStamp': f'2026-10-01T{hour:02d}:00:00Z', 'average': value}
                                                   for hour in range(3)]}]
                       for kind, dimension in (('MDT', 'mdtnum'), ('OST', 'ostnum'))
                       for unit in ('Bytes', 'Files') for role, value in (('Used', 96 if kind == 'OST' else 1), ('Total', 100))}
            metrics['LustreClientEvictions'] = [{'dims': {}, 'data': [
                {'timeStamp': '2026-10-01T00:00:00Z', 'total': 0}]}]
            raw.save('lustre/metrics.json', {'resources': {resource_id.lower(): metrics}})
            analyzer = Analyzer(ws, config.load(template), log=lambda *args: None)
            analyzer.p7_lustre()
            self.assertEqual(len(analyzer.F.items), 2)
            self.assertTrue(all(item['severity'] == '高' for item in analyzer.F.items))
            self.assertEqual(analyzer.inv['managedLustre'][0]['capacityTiB'], 8)
            self.assertEqual(analyzer.inv['managedLustre'][0]['tier'], 'Durable-Premium')
            self.assertEqual(analyzer.cov['P7']['otherErrors'], 0)
            raw.save('lustre/metrics.json', {'resources': {}})
            missing = Analyzer(ws, config.load(template), log=lambda *args: None)
            missing.p7_lustre()
            self.assertEqual(missing.F.items, [])
            self.assertGreater(missing.cov['P7']['otherErrors'], 0)

    def test_partial_target_read_does_not_resolve_last_month(self):
        from azinspect import tracking
        from azinspect.core import io
        with tempfile.TemporaryDirectory() as directory:
            old = io.Workspace(directory, '2026-08')
            old.create()
            finding = {'id': 'P7-lustre', 'check': 'P7', 'rule': 'lustre-capacity', 'severity': '中',
                       'finding': 'Lustre fs OST 1 容量紧张', 'resourceName': 'fs'}
            io.write_json(old.month_dir('findings') / 'waf/performance.json', {
                'pillar': 'performance', 'findings': [finding],
                'coverage': {'P7': {'attempted': 1, 'succeeded': 1, 'rules': ['lustre-capacity']}}, 'complete': True})
            tracking.update(old, log=lambda *args: None)
            current = io.Workspace(directory, '2026-09')
            current.create()
            metrics = {'OSTBytesUsed': [series('0', [(0, 1)])],
                       'OSTBytesTotal': [series(target, [(0, 100)]) for target in ('0', '1')]}
            gaps = missing_targets(metrics, capacity_pressure(metrics))
            io.write_json(current.month_dir('findings') / 'waf/performance.json', {
                'pillar': 'performance', 'findings': [], 'coverage': {'P7': {
                    'attempted': 1, 'succeeded': 1, 'otherErrors': len(gaps), 'rules': ['lustre-capacity']}}, 'complete': True})
            result = tracking.update(current, log=lambda *args: None)
            self.assertEqual(result['rows'][0]['status'], '本月未检查')


if __name__ == '__main__':
    unittest.main()