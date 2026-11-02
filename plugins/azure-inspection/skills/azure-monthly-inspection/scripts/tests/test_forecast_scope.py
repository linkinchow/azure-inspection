"""Next-month forecast that does not cover every subscription: compared only with the subscriptions it covers, and said
so (synthetic data, no network)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect import crosscheck  # noqa: E402
from azinspect.core import io  # noqa: E402
from azinspect.cost import forecast_scope as fsc  # noqa: E402

LABELS = {'Ln': '11月', 'Lc': '10月', 'dn': 30, 'dc': 31}


def case(rows):
    """rows: (subscription id, this month's cost, full-month forecast or None, HTTP status of a failed read)."""
    model = {'subscriptions': [{'id': sid, 'cur': cur} for sid, cur, _est, _http in rows],
             'comparableSubscriptionIds': [sid for sid, *_ in rows]}
    subs = []
    for sid, _cur, est, http in rows:
        nxt = ({'status': 'success', 'fullMonthEstimate': est, 'actualToDate': est / 2, 'forecastRemainder': est / 2} if est is not None else
               {'status': 'error', 'fullMonthEstimate': None, 'reason': f'HTTP {http}: {{"httpStatus": {http}, "message": "HTTP {http}"}}'}
               if http else {'status': 'empty', 'fullMonthEstimate': None, 'reason': 'forecast API returned an empty table'})
        subs.append({'subscriptionId': sid, 'name': sid, 'group': 'g', 'next': nxt})
    return {'subscriptions': subs}, model


class CoverageTests(unittest.TestCase):
    def test_compared_with_its_own_subscriptions(self):
        # a: 3100 this month, 3000 next month (same daily); b: 900 this month, throttled; c: no costs, no forecast.
        # Throttled b used to be counted in this month's side: 3000/30 vs 4000/31 read as 22.5% lower
        fc = fsc.coverage(*case([('a', 3100.0, 3000.0, None), ('b', 900.0, None, 429), ('c', 0.0, None, None)]), 30, 31)
        self.assertEqual((fc['subscriptions'], fc['missed'], round(fc['share'], 3)), (1, 1, 0.775))
        self.assertFalse(fc['complete'])
        self.assertAlmostEqual(fc['dailyChange'], 0.0)

    def test_complete_when_missing_subscriptions_cost_little(self):
        fc = fsc.coverage(*case([('a', 9700.0, 9000.0, None), ('b', 300.0, None, 429)]), 30, 31)
        self.assertTrue(fc['complete'])
        line = fsc.line_01(fc, LABELS)
        self.assertIn('**11月预计约USD 9,000.00**', line)
        self.assertIn('1 个订阅没有读到预测', line)

    def test_incomplete_forecast_says_so(self):
        fc = fsc.coverage(*case([('a', 3100.0, 3000.0, None), ('b', 900.0, None, 429)]), 30, 31)
        line = fsc.line_01(fc, LABELS)
        self.assertIn('预测不完整', line)
        self.assertNotIn('**11月预计约', line)
        self.assertIn('77.5%', line)
        self.assertEqual(fsc.row_00(fc, '11 月', '10 月')[1][:5], '预测不完整')

    def test_no_forecast_at_all(self):
        # used to read as -100% in the Excel total row
        fc = fsc.coverage(*case([('a', 3100.0, None, 429), ('b', 900.0, None, 429)]), 30, 31)
        self.assertIsNone(fc['dailyChange'])
        self.assertIn('没有读到', fsc.line_01(fc, LABELS))
        self.assertIn('没有读到', fsc.row_00(fc, '11 月', '10 月')[1])

    def test_nothing_to_say_without_costs(self):
        fc = fsc.coverage(*case([('a', 0.0, None, None)]), 30, 31)
        self.assertIsNone(fsc.line_01(fc, LABELS))
        self.assertIsNone(fsc.row_00(fc, '11 月', '10 月'))

    def test_note_cell_in_chinese(self):
        _f, _m = case([('b', 900.0, None, 429), ('c', 0.0, None, None), ('d', 50.0, None, 500), ('e', 0.0, None, 429)])
        notes = [fsc.note_cell(s['next'], cur, '10月') for s, cur in zip(_f['subscriptions'], (900.0, 0.0, 50.0, 0.0))]
        self.assertEqual(notes, ['预测接口限流（429），未读到', '10月无费用，预测接口未返回结果', '预测读取失败（HTTP 500）',
                                 '预测接口限流（429），未读到（10月无费用）'])


def big_day_case(cur_big=False):
    """One subscription, USD 100 a day. Next month: day 5 actual 11,500 (a one-off purchase), day 30 forecast 2,600."""
    daily = [{'date': f'2026-11-{d:02d}', 'costStatus': 'Actual' if d <= 10 else 'Forecast',
              'cost': 11500.0 if d == 5 else 2600.0 if d == 30 else 100.0} for d in range(1, 31)]
    actual = sum(p['cost'] for p in daily if p['costStatus'] == 'Actual')
    rest = sum(p['cost'] for p in daily if p['costStatus'] == 'Forecast')
    cur = [{'day': d, 'cur': 3200.0 if cur_big and d == 12 else 100.0, 'prev': 100.0} for d in range(1, 32)]
    model = {'subscriptions': [{'id': 'a', 'cur': sum(r['cur'] for r in cur)}], 'comparableSubscriptionIds': ['a'], 'daily': cur}
    forecast = {'subscriptions': [{'subscriptionId': 'a', 'name': 'a', 'group': 'g', 'next': {
        'status': 'success', 'fullMonthEstimate': actual + rest, 'actualToDate': actual, 'forecastRemainder': rest, 'daily': daily}}]}
    return forecast, model


class BigDayTests(unittest.TestCase):
    def test_one_off_days_do_not_drive_the_daily_comparison(self):
        # seen: a daily average more than twice this month's while everyday costs were lower; two purchase days and one forecast day drove it
        fc = fsc.coverage(*big_day_case(), 30, 31)
        self.assertEqual([(b['date'], b['kind']) for b in fc['bigDays']], [('2026-11-05', 'actual'), ('2026-11-30', 'forecast')])
        self.assertAlmostEqual(fc['adjustedChange'], 0.0)
        line = fsc.line_01(fc, LABELS)
        self.assertIn('其中 11月5日单日费用特别大', line)          # the actual day; the forecast day is said once, below
        self.assertEqual(line.count('11月30日'), 1)
        self.assertIn('去掉这 2 天后日均约USD 100.00', line)
        self.assertNotIn('全月日均', line)          # the unadjusted comparison is not given
        self.assertIn('11月30日', line)             # the forecast's own large day, with its share of the forecast part
        self.assertIn('57.8%', line)
        self.assertIn('请核对', fsc.row_00(fc, '11 月', '10 月')[1])

    def test_one_forecast_day(self):
        forecast, model = big_day_case()
        nxt = forecast['subscriptions'][0]['next']
        for p in nxt['daily']:
            if p['date'] == '2026-11-05':
                p['cost'] = 100.0
        nxt['actualToDate'] = 1000.0
        nxt['fullMonthEstimate'] = nxt['actualToDate'] + nxt['forecastRemainder']
        line = fsc.line_01(fsc.coverage(forecast, model, 30, 31), LABELS)
        self.assertNotIn('其中', line)
        self.assertEqual(line.count('11月30日'), 1)
        self.assertIn('去掉这一天后日均', line)

    def test_this_months_large_days_left_out_too(self):
        fc = fsc.coverage(*big_day_case(cur_big=True), 30, 31)
        self.assertAlmostEqual(fc['adjustedChange'], 0.0)
        self.assertIn('10月也去掉 1 天', fsc.line_01(fc, LABELS))

    def test_only_this_month_has_a_large_day(self):
        forecast, model = big_day_case(cur_big=True)
        for p in forecast['subscriptions'][0]['next']['daily']:
            p['cost'] = 100.0
        nxt = forecast['subscriptions'][0]['next']
        nxt['actualToDate'], nxt['forecastRemainder'], nxt['fullMonthEstimate'] = 1000.0, 2000.0, 3000.0
        line = fsc.line_01(fsc.coverage(forecast, model, 30, 31), LABELS)
        self.assertIn('10月有 1 天单日费用特别大', line)
        self.assertNotIn('去掉这些天', line)

    def test_ordinary_months_unchanged(self):
        fc = fsc.coverage(*case([('a', 3100.0, 3000.0, None)]), 30, 31)
        self.assertEqual(fc['bigDays'], [])
        self.assertIn('全月日均约USD 100.00', fsc.line_01(fc, LABELS))


class X11Tests(unittest.TestCase):
    def run_x11(self, rows, summary=None, conclusion=None):
        forecast, model = case(rows)
        forecast['months'] = {'next': '2026-11'}
        with tempfile.TemporaryDirectory() as d:
            ws = io.Workspace(d, '2026-10')
            ws.create()
            io.write_json(ws.month_dir('findings') / 'cost' / 'model.json', model)
            io.write_json(ws.raw('cost/supplement/forecast.json'), forecast)
            if summary is not None:
                io.write_json(ws.month_dir('narrative') / '01.json', {'forecastSummary': summary})
            if conclusion is not None:
                io.write_json(ws.month_dir('narrative') / '00.json', {'conclusion': [conclusion]})
            return crosscheck.x11(ws)

    def test_incomplete_forecast_must_be_called_so(self):
        # a narrative forecastSummary or 00 conclusion can still state a tenant-wide forecast: it must not be packed as is.
        # The reports themselves cannot tell: 00's own table already says 预测不完整
        rows = [('a', 3100.0, 3000.0, None), ('b', 900.0, None, 429)]
        rule = self.run_x11(rows, '11月预计约USD 3,000.00', '11 月预计约 USD 3,000.00，比 10 月继续下降。')
        self.assertEqual(rule['status'], '需要处理')
        self.assertEqual([i['resource'] for i in rule['items']], ['01', '00'])
        rule = self.run_x11(rows, '11月预测不完整：……', '11 月预测不完整，只覆盖部分订阅。')
        self.assertEqual(rule['status'], '通过')
        rule = self.run_x11(rows, None, '优先处理数据库，每月预计节省 USD 300.00。')   # no forecast mentioned: nothing to say
        self.assertEqual(rule['status'], '通过')

    def test_complete_forecast_passes(self):
        self.assertEqual(self.run_x11([('a', 9700.0, 9000.0, None), ('b', 300.0, None, 429)], '11月预计约USD 9,000.00')['status'], '通过')


if __name__ == '__main__':
    unittest.main()
