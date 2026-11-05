"""Tests for the peer-comparison engine and the 03/04 links (synthetic data, no network)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.peer import links  # noqa: E402
from azinspect.peer.engine import TypeReport, most_common, std_root_cause, worst  # noqa: E402


class FakeCtx:
    standard_name, standard_label = 'Terraform', 'managed_by=terraform'

    def __init__(self, created=None, findings=()):
        self.created_map, self.findings = created or {}, list(findings)

    def sub_name(self, sid):
        return sid

    def env(self, sub, name='', tags=None):
        value = 'test' if 'test' in name else 'prod'
        return {'value': value, 'label': '测试' if value == 'test' else '生产', 'basis': '资源名称'}

    def standard(self, tags):
        return (tags or {}).get('managed_by') == 'terraform'

    def line(self, sub, rg='', name=''):
        return 'APP'

    def created(self, rid):
        return self.created_map.get(rid)

    def vendor(self, name, rg=''):
        return 'Acme' if name.startswith('acme') else None

    def region(self, location):
        return location

    def creation_deploy(self, name, sub=None, rtype=None):
        return {'deployment': 'microsoft.aks-1', 'date': '2026-01-01', 'method': '门户向导', 'attempts': 1} if name == 'portal1' else None

    def portal_changes(self, name, sub=None):
        return []

    def linked(self, *names, checks=None):
        return [fid for fid, _c, text, _l in self.findings if any(n in text for n in names)]


def build(ctx):
    T = TypeReport(ctx, 'x', '测试资源')
    for name, private, tf in (('std1', True, True), ('std2', True, True), ('portal1', False, False), ('acme-a', False, False), ('app-test', False, True)):
        it = T.basic({'id': f'/subscriptions/s/resourceGroups/rg/providers/T/x/{name}', 'name': name, 'subscriptionId': 's', 'resourceGroup': 'rg',
                      'type': 'T/x', 'tags': {'managed_by': 'terraform'} if tf else {}})
        it['private'] = private
        T.items.append(it)
    T.attr('net', '网络', '私有（2/5）', lambda r: '公网', lambda r: not r['private'], rec='关闭公网',
           feas=lambda r: '需供应商确认' if r['vendor'] else '原地修改', major=lambda r: r['prod'])
    peers = {r['name']: r['created'] for r in T.items if r['tf']}
    T.run(lambda r: std_root_cause(ctx, r, [], peers))
    return T


class EngineTests(unittest.TestCase):
    def test_adoption_deviations_and_method(self):
        ctx = FakeCtx(created={f'/subscriptions/s/resourceGroups/rg/providers/T/x/{n}': d
                               for n, d in (('std1', '2026-03-01'), ('std2', '2026-03-05'), ('portal1', '2026-02-01'))})
        T = build(ctx)
        self.assertEqual(T.attr_stats['net']['followedBy'], 2)
        self.assertEqual(sorted(d['resourceName'] for d in T.deviations), ['acme-a', 'app-test', 'portal1'])
        by = {r['name']: r for r in T.items}
        self.assertEqual(by['portal1']['_method'], '门户向导')
        self.assertEqual(by['acme-a']['_method'], '供应商')
        self.assertEqual(by['std1']['_method'], 'Terraform')
        dev = {d['resourceName']: d for d in T.deviations}
        self.assertTrue(dev['portal1']['impact'].startswith('高'))
        self.assertFalse(dev['app-test']['impact'].startswith('高'))           # test environment: not high impact
        self.assertEqual(dev['acme-a']['feasibility'], '需供应商确认')
        self.assertTrue(any('早于全部按标准方式创建的同类' in n for n in dev['portal1']['rootCauseEvidence']['notes']))

    def test_helpers(self):
        self.assertEqual(worst(['原地修改', '需重建并迁移', '原地修改（需维护窗口或应用配合）']), '需重建并迁移')
        self.assertEqual(most_common(['1.34', '1.33', '1.34', None]), '1.34')


class LinkTests(unittest.TestCase):
    def test_links_use_finding_ids_and_relevant_attributes(self):
        ctx = FakeCtx(findings=[('R3-aaaaaa', 'R3', 'portal1 未跨可用区', None), ('S-N1-bbbbbb', 'S-N1', 'portal1 子网', None)])
        T = build(ctx)
        data = {'types': [T.to_json()]}
        out = links.build_links(ctx, data)
        self.assertIn('R3-aaaaaa', out)
        self.assertIn('网络', out['R3-aaaaaa']['difference'])
        self.assertIn('门户向导', out['R3-aaaaaa']['rootCause'])
        self.assertIn('关闭公网', out['R3-aaaaaa']['alignment'])


class ManagedLustrePeerTests(unittest.TestCase):
    def build_saved(self, rows, require_cmk=False):
        import tempfile
        from types import SimpleNamespace
        from azinspect.core.io import Workspace, read_json
        from azinspect.peer.types_data import managed_lustre_type

        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(directory, '2026-09')
            workspace.save_raw('waf/performance/lustre/inventory.json', {'status': 200, 'rows': rows, 'errors': []})
            ctx = FakeCtx(findings=[('S-N10-lustre', 'S-N10', rows[0]['id'].lower(), None)])
            ctx.cfg = SimpleNamespace(managed_lustre={'requireCmk': require_cmk})
            ctx.load = lambda rel, default=None: read_json(workspace.raw('waf/' + rel)) if workspace.raw('waf/' + rel).exists() else default
            report, attrs = managed_lustre_type(ctx)
            return report.to_json(attrs)

    def resource(self, name, properties=None, **extra):
        return {'id': f'/subscriptions/s/resourceGroups/rg/providers/Microsoft.StorageCache/amlFilesystems/{name}',
                'name': name, 'subscriptionId': 's', 'resourceGroup': 'rg', 'type': 'Microsoft.StorageCache/amlFilesystems',
                'properties': properties or {}, **extra}

    def analyze_inventory(self, workspace, inventory):
        import importlib
        from types import SimpleNamespace
        from unittest.mock import patch
        from azinspect.core.io import read_json
        from azinspect.peer.types_data import managed_lustre_type

        if inventory is not None:
            workspace.save_raw('waf/performance/lustre/inventory.json', inventory)
        ctx = FakeCtx()
        ctx.cfg = SimpleNamespace(name='Contoso', business_lines=[], standard_tag=None, vendor_managed=[])
        ctx.created_meta, ctx.created_map = None, {}
        ctx.load = lambda rel, default=None: read_json(workspace.raw('waf/' + rel)) if workspace.raw('waf/' + rel).exists() else default
        analyze = importlib.import_module('azinspect.peer.analyze')
        with patch.object(analyze, 'Context', return_value=ctx), patch.object(analyze, 'BUILDERS', [managed_lustre_type]):
            result = analyze.analyze(workspace, ctx.cfg, log=lambda *_: None)
        self.assertEqual(read_json(workspace.month_dir('findings') / 'peer/baseline.json'), result)
        return result, ctx.cfg

    def test_analysis_persists_complete_filesystem_inventory(self):
        import tempfile
        from azinspect.core.io import Workspace

        resources = [self.resource('healthy', {'storageCapacityTiB': 8},
                                   sku={'name': 'AMLFS-Durable-Premium-125', 'tier': 'Premium'}, location='eastus', zones=['1']),
                     self.resource('inferred', {'storageCapacityTiB': 16}, sku={'name': 'AMLFS-Durable-Premium-250'}),
                     self.resource('denied', _readError='HTTP 403')]
        with tempfile.TemporaryDirectory() as directory:
            data, _cfg = self.analyze_inventory(Workspace(directory, '2026-09'),
                                                {'status': 200, 'rows': resources, 'errors': []})
        filesystems = data['types'][0]['filesystems']
        self.assertEqual(len(filesystems), 3)
        self.assertEqual(filesystems[0]['resourceId'], resources[0]['id'])
        self.assertEqual(filesystems[0]['subscriptionId'], 's')
        self.assertEqual(filesystems[0]['subscriptionName'], 's')
        self.assertEqual(filesystems[0]['tier'], 'Premium')
        self.assertEqual(filesystems[0]['tierSource'], 'sku.tier')
        self.assertEqual(filesystems[0]['sku'], 'AMLFS-Durable-Premium-125')
        self.assertEqual(filesystems[0]['capacityTiB'], 8)
        self.assertEqual(filesystems[0]['region'], 'eastus')
        self.assertEqual(filesystems[0]['zones'], ['1'])
        self.assertIsNone(filesystems[0]['observedUsedTiB'])
        self.assertEqual(filesystems[1]['tier'], 'Durable-Premium')
        self.assertEqual(filesystems[1]['tierSource'], 'sku.name')
        self.assertEqual(filesystems[1]['capacityTiB'], 16)
        self.assertEqual(filesystems[2]['configurationError'], 'HTTP 403')
        self.assertIsNone(filesystems[2]['capacityTiB'])

    def test_report_lists_healthy_filesystems_caps_markdown_and_keeps_excel_complete(self):
        import tempfile
        from unittest.mock import patch
        from openpyxl import load_workbook
        from azinspect.core.io import Workspace
        from azinspect.peer.report import markdown, write_excel

        resources = [self.resource(f'healthy-{index:02d}', {
            'storageCapacityTiB': 8, 'rootSquashSettings': {'mode': 'RootOnly'},
            'maintenanceWindow': {'dayOfWeek': 'Monday', 'timeOfDayUTC': '2:00'}},
            sku={'name': 'AMLFS-Durable-Premium-125', 'tier': 'Premium'}, location='eastus', zones=['1'])
            for index in range(21)]
        resources[1]['_readError'] = 'HTTP 403'
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(directory, '2026-09')
            data, cfg = self.analyze_inventory(workspace, {'status': 200, 'rows': resources, 'errors': []})
            self.assertEqual(data['types'][0]['deviations'], [])
            self.assertEqual(len(data['types'][0]['baseline']['fullyCompliantResources']), 20)
            labels = {'standard': 'Terraform', 'standardTag': None}
            with patch('azinspect.peer.report.scope_line', return_value='Contoso 测试订阅'):
                text = markdown(workspace, cfg, data, {}, {}, labels)
            self.assertIn('healthy-00', text)
            self.assertIn('healthy-19', text)
            self.assertNotIn('healthy-20', text)
            for value in ('Premium', 'sku.tier', 'AMLFS-Durable-Premium-125', '|8|eastus|1|', 'HTTP 403'):
                self.assertIn(value, text)
            self.assertIn('21 个文件系统', text)
            path = Path(directory) / 'peer.xlsx'
            write_excel(path, cfg, data, {}, labels)
            workbook = load_workbook(path)
            try:
                sheet = workbook['Lustre 文件系统清单']
                rows = list(sheet.iter_rows(min_row=4, values_only=True))
                self.assertEqual(len(rows), 21)
                self.assertEqual(rows[0], ('healthy-00', 's', 's', 'Premium', 'sku.tier',
                                           'AMLFS-Durable-Premium-125', 8, 'eastus', '1', None, 'rg', resources[0]['id']))
                self.assertEqual(rows[1][9], 'HTTP 403')
                self.assertEqual(rows[-1][0], 'healthy-20')
                self.assertEqual(sheet.freeze_panes, 'A4')
                self.assertEqual(sheet.auto_filter.ref, 'A3:L24')
            finally:
                workbook.close()

    def test_reports_without_inventory_or_resources_omit_filesystem_list(self):
        import tempfile
        from unittest.mock import patch
        from openpyxl import load_workbook
        from azinspect.core.io import Workspace
        from azinspect.peer.report import markdown, write_excel

        for inventory in (None, {'status': 200, 'rows': [], 'errors': []}):
            with self.subTest(inventory=inventory), tempfile.TemporaryDirectory() as directory:
                workspace = Workspace(directory, '2026-09')
                data, cfg = self.analyze_inventory(workspace, inventory)
                self.assertEqual(data['types'], [])
                labels = {'standard': 'Terraform', 'standardTag': None}
                with patch('azinspect.peer.report.scope_line', return_value='Contoso 测试订阅'):
                    self.assertNotIn('文件系统清单', markdown(workspace, cfg, data, {}, {}, labels))
                path = Path(directory) / 'peer.xlsx'
                write_excel(path, cfg, data, {}, labels)
                workbook = load_workbook(path)
                try:
                    self.assertNotIn('Lustre 文件系统清单', workbook.sheetnames)
                finally:
                    workbook.close()

    def test_known_fields_and_unknown_applicability(self):
        rows = [self.resource('disabled', {'rootSquashSettings': {'mode': 'None'},
                                         'maintenanceWindow': {'dayOfWeek': 'Monday', 'timeOfDayUTC': '99:00'}}),
                self.resource('configured', {'rootSquashSettings': {'mode': 'RootOnly'},
                                           'maintenanceWindow': {'dayOfWeek': 'Friday', 'timeOfDayUTC': '02:30'}}),
                self.resource('unknown')]
        result = self.build_saved(rows)
        adoption = result['baseline']['attributeAdoption']
        self.assertEqual(adoption['rootSquash']['applicable'], 2)
        self.assertEqual(adoption['maintenance']['applicable'], 2)
        self.assertEqual(result['baseline']['fullyCompliantResources'], ['configured'])
        self.assertEqual([item['resourceName'] for item in result['deviations']], ['disabled'])
        self.assertEqual(set(result['deviations'][0]['differingAttributes']), {'rootSquash', 'maintenance'})
        self.assertEqual(result['deviations'][0]['linkedFindingIds'], ['S-N10-lustre'])

    def test_cmk_requires_policy_and_known_encryption(self):
        rows = [self.resource('platform', {'encryptionSettings': {}}),
                self.resource('cmk', {'encryptionSettings': {'keyEncryptionKey': {'keyUrl': 'https://example.vault.azure.net/keys/k'}}}),
                self.resource('unknown')]
        self.assertEqual(self.build_saved(rows)['deviationCount'], 0)
        result = self.build_saved(rows, require_cmk=True)
        self.assertEqual(result['baseline']['attributeAdoption']['cmk']['applicable'], 2)
        self.assertEqual([item['resourceName'] for item in result['deviations']], ['platform'])

    def test_denied_get_excludes_apparently_valid_arg_configuration(self):
        properties = {'rootSquashSettings': {'mode': 'RootOnly'},
                      'maintenanceWindow': {'dayOfWeek': 'Monday', 'timeOfDayUTC': '02:00'},
                      'encryptionSettings': {'keyEncryptionKey': {'keyUrl': 'https://example.vault.azure.net/keys/k'}}}
        denied = self.resource('denied', properties, _readError='HTTP 403')
        partial = self.resource('partial', {**properties, 'rootSquashSettings': {'mode': 'None'},
                                           'encryptionSettings': {}}, _readError='HTTP 403')
        result = self.build_saved([denied, partial, self.resource('healthy', properties)], require_cmk=True)
        for attribute in result['baseline']['attributeAdoption'].values():
            self.assertEqual(attribute['applicable'], 1)
            self.assertEqual(attribute['followedBy'], 1)
        self.assertEqual(result['baseline']['fullyCompliantResources'], ['healthy'])
        self.assertEqual(result['deviations'], [])
        self.assertIn('未检查', result['baseline']['rationale'])

    def test_single_digit_maintenance_hour_is_valid(self):
        for time in ('0:00', '2:00', '02:00', '23:59'):
            with self.subTest(time=time):
                result = self.build_saved([self.resource('healthy', {
                    'rootSquashSettings': {'mode': 'RootOnly'},
                    'maintenanceWindow': {'dayOfWeek': 'Monday', 'timeOfDayUTC': time}})])
                self.assertEqual(result['deviations'], [])
                self.assertEqual(result['baseline']['fullyCompliantResources'], ['healthy'])

    def test_singleton_capacity_sku_zone_and_optional_hsm_are_not_defects(self):
        result = self.build_saved([self.resource('only', {'storageCapacityTiB': 8}, sku={'name': 'SKU-A'}, zones=['1'])])
        self.assertEqual(result['deviationCount'], 0)
        self.assertEqual(result['uniformGaps'], [])
        self.assertEqual(result['baseline']['followedBy'], 0)
        self.assertIn('单个文件系统', result['baseline']['rationale'])

    def test_builder_registered_and_old_snapshots_empty(self):
        from types import SimpleNamespace
        from azinspect.peer.analyze import BUILDERS
        from azinspect.peer.types_data import managed_lustre_type
        self.assertIn(managed_lustre_type, BUILDERS)
        ctx = FakeCtx()
        ctx.cfg = SimpleNamespace()
        ctx.load = lambda rel, default=None: default
        report, attrs = managed_lustre_type(ctx)
        self.assertEqual(report.items, [])

    def test_analysis_surfaces_unknown_and_failed_empty_inventory_in_coverage(self):
        import importlib
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        from azinspect.core.io import Workspace, read_json
        from azinspect.peer.types_data import managed_lustre_type

        analyze = importlib.import_module('azinspect.peer.analyze')
        for inventory in (None, {'status': 403, 'rows': [], 'errors': [], 'error': 'HTTP 403'},
                          {'status': 200, 'rows': [self.resource('unknown')], 'errors': []}):
            with self.subTest(inventory=inventory), tempfile.TemporaryDirectory() as directory:
                workspace = Workspace(directory, '2026-09')
                if inventory is not None:
                    workspace.save_raw('waf/performance/lustre/inventory.json', inventory)
                ctx = FakeCtx()
                ctx.cfg = SimpleNamespace()
                ctx.created_meta, ctx.created_map = None, {}
                ctx.load = lambda rel, default=None: read_json(workspace.raw('waf/' + rel)) if workspace.raw('waf/' + rel).exists() else default
                with patch.object(analyze, 'Context', return_value=ctx), patch.object(analyze, 'BUILDERS', [managed_lustre_type]):
                    result = analyze.analyze(workspace, ctx.cfg, log=lambda *_: None)
                gaps = ' '.join(result['coverageGaps'])
                self.assertIn('Azure Managed Lustre', gaps)
                self.assertIn('未检查', gaps)
                if inventory and inventory.get('rows'):
                    self.assertIn('未取得', result['types'][0]['baseline']['rationale'])


if __name__ == '__main__':
    unittest.main()
