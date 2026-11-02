"""Tests for chart axes: amount ticks stay distinct when the tick step is not a whole thousand (synthetic data, no network)."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
os.environ.setdefault('AZINSPECT_NO_EXCEL', '1')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.core import charts as cs  # noqa: E402


def drawn_ticks(make):
    """Draw the charts and return {file name: (x tick labels, y tick labels)} as rendered."""
    seen = {}

    def save(fig, path):
        fig.canvas.draw()
        ax = fig.axes[0]
        seen[Path(path).name] = ([t.get_text() for t in ax.get_xticklabels() if t.get_visible() and t.get_text()],
                                 [t.get_text() for t in ax.get_yticklabels() if t.get_visible() and t.get_text()])
        cs.plt.close(fig)
        return Path(path)
    with tempfile.TemporaryDirectory() as d, mock.patch.object(cs, 'save', save):
        make(Path(d))
    return seen


class AmountTickTests(unittest.TestCase):
    def test_half_thousand_steps_are_distinct(self):
        labels = [cs.amount_tick(x) for x in range(0, 4001, 500)]
        self.assertEqual(labels, ['0', '500', '1K', '1.5K', '2K', '2.5K', '3K', '3.5K', '4K'])

    def test_other_steps_are_distinct(self):
        for step in (0.25, 0.5, 2.5, 25, 250, 2500, 25000):
            labels = [cs.amount_tick(i * step) for i in range(-8, 9)]
            self.assertEqual(len(set(labels)), len(labels), (step, labels))
        self.assertEqual(cs.amount_tick(-1500), '-1.5K')
        self.assertEqual(cs.amount_tick(12000), '12K')

    def test_vm_plan_chart_ticks_are_distinct(self):
        from azinspect.vm.charts import make_pngs
        data = {'runningWithData': 2, 'distribution': [('<10%', 1, 1), ('10–20%', 1, 1)], 'cpuBelow20': 2, 'memoryBelow20': 2,
                'status': [('建议调整规格', 2)], 'subscriptions': [('a', 1800.0), ('b', 700.0)],
                'plans': [('当前规格，按需', 2931.10), ('降配后，按需', 2170.59), ('降配后，1 年 SP', 1650.0), ('降配后，1 年 RI', 1302.35),
                          ('降配后，3 年 SP', 1200.0), ('降配后，3 年 RI', 900.0)]}
        seen = drawn_ticks(lambda d: make_pngs(data, d))
        for name in ('02_1_VM各方案每月费用.png', '02_4_各订阅每月预计节省.png'):
            ticks = seen[name][0]
            self.assertGreater(len(ticks), 3, name)
            self.assertEqual(len(set(ticks)), len(ticks), (name, ticks))

    def test_cost_chart_ticks_are_distinct(self):
        from datetime import date
        from azinspect.cost.charts import make_pngs
        days = [(date(2026, 8, d), 400.0 + 10 * (d % 7)) for d in range(1, 32)] + [(date(2026, 9, d), 420.0 + 12 * (d % 7)) for d in range(1, 31)]
        data = {'groupLabel': '订阅', 'timeline': days, 'next': [(d, None, None) for d in range(1, 32)], 'prevDailyAverage': 430.0,
                'curDailyAverage': 450.0, 'groups': [('a', 2400.0, 2900.0), ('b', 1200.0, 1100.0)],
                'services': [('x', 1400.0), ('y', -600.0)], 'regions': [('日本东部', 1300.0), ('美国东部', -300.0)]}
        labels = {'prev': '8 月', 'cur': '9 月', 'next': '10 月', 'prevDays': 31}
        seen = drawn_ticks(lambda d: make_pngs(data, labels, d))
        self.assertTrue(seen)
        for name, (xs, ys) in seen.items():
            ticks = ys if name.startswith('01_1_') else xs
            self.assertGreater(len(ticks), 3, name)
            self.assertEqual(len(set(ticks)), len(ticks), (name, ticks))


if __name__ == '__main__':
    unittest.main()
