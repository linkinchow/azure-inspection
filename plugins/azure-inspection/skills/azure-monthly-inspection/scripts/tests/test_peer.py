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


if __name__ == '__main__':
    unittest.main()
