"""Tests for RI/SP coverage, utilization and expiry flags (synthetic data, no network)."""
from __future__ import annotations

import datetime as dt
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.cost import commitments  # noqa: E402
from azinspect.vm.table import committed_share  # noqa: E402

VM = '/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-a'
VMSS = '/subscriptions/s/resourcegroups/mc_rg/providers/microsoft.compute/virtualmachinescalesets/aks-pool-1-vmss'


class CommitmentTests(unittest.TestCase):
    def data(self):
        return {
            'pricingByResource': [
                {'resourceId': VM, 'pricingModel': 'Reservation', 'cost': 80.0},
                {'resourceId': VM, 'pricingModel': 'OnDemand', 'cost': 20.0},
                {'resourceId': VMSS, 'pricingModel': 'OnDemand', 'cost': 50.0}],
            'pricingStatus': {'s': {'ok': True}},
            'reservations': [
                {'name': 'ri-low', 'utilization': {'days30': 55.0}, 'expiry': '2027-06-01T00:00:00Z', 'renew': False},
                {'name': 'ri-soon', 'utilization': {'days30': 99.0}, 'expiry': '2026-11-20T00:00:00Z', 'renew': False}],
            'reservationStatus': {'ok': True},
            'savingsPlans': [], 'savingsPlanStatus': {'ok': False, 'httpStatus': 403},
            'recommendations': [{'kind': '预留实例', 'saving': 12.5}], 'recommendationStatus': {'a': {'ok': True}}}

    def test_summary_flags_and_coverage(self):
        s = commitments.summary(self.data(), dt.date(2026, 10, 27))
        self.assertAlmostEqual(s['coverage'][VM]['share'], 0.8)
        self.assertEqual(s['coverage'][VMSS]['share'], 0.0)
        notes = {c['name']: c['notes'] for c in s['commitments']}
        self.assertTrue(any('未用满' in n for n in notes['ri-low']))
        self.assertTrue(any('天后到期' in n for n in notes['ri-soon']))
        self.assertTrue(s['reservationsRead'])
        self.assertFalse(s['savingsPlansRead'])

    def test_vm_share_uses_scale_set_for_instances(self):
        coverage = commitments.summary(self.data(), dt.date(2026, 10, 27))['coverage']
        self.assertAlmostEqual(committed_share({'vmId': VM, 'pool': None}, coverage), 0.8)
        self.assertEqual(committed_share({'vmId': VMSS + '/virtualmachines/0', 'pool': VMSS}, coverage), 0.0)
        self.assertIsNone(committed_share({'vmId': VM, 'pool': None}, None))


if __name__ == '__main__':
    unittest.main()
