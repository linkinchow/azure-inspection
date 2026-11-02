"""Throttling (429): no wait after the last attempt; forecasts the API throttles wait for one retry round after the other
cost queries instead of each waiting minutes in turn (synthetic data, no network)."""
from __future__ import annotations

import sys
import tempfile
import unittest
import urllib.error
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from azinspect.core import http, io  # noqa: E402
from azinspect.core.reuse import Reuse  # noqa: E402
from azinspect.core.period import ReportPeriod  # noqa: E402
from azinspect.cost import supplement_costs as sc  # noqa: E402

PERIOD = ReportPeriod.build('2026-09', run_date=date(2026, 10, 15))
SUBS = [{'id': f's{i}', 'name': f'sub{i}', 'group': 'g'} for i in range(6)]


class RetryTests(unittest.TestCase):
    def test_no_wait_after_the_last_attempt(self):
        # each throttled forecast waited 2+4+8+16+32+64 s: the last 64 s came after the sixth and final attempt
        def open_(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 429, 'Too Many Requests', {}, None)
        client = http.ReadOnlyClient(SimpleNamespace(get=lambda audience: 'token'), opener=SimpleNamespace(open=open_))
        with mock.patch.object(http.time, 'sleep') as sleep:
            status, _data, error = client.get('/subscriptions?api-version=2022-12-01', 'test')
        self.assertEqual((status, error), (429, 'HTTP 429'))
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [2, 4, 8, 16, 32])


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class ForecastApi:
    """Cost Management forecast that throttles while the clock is inside `throttled` (start, end) windows, or per
    subscription while `per_sub[sid]` (start, end) holds."""

    def __init__(self, clock, throttled, per_sub=None):
        self.clock, self.throttled, self.per_sub, self.calls = clock, throttled, per_sub or {}, []

    def request(self, method, url, check, target='', body=None, max_attempts=6):
        self.calls.append(target)
        self.clock.t += 5   # each request takes a few seconds
        sid = target.split('.')[1]
        windows = self.throttled + ([self.per_sub[sid]] if sid in self.per_sub else [])
        if any(a <= self.clock.t < b for a, b in windows):
            return 429, None, 'HTTP 429'
        rows = [[10.0, 20261001, 'Actual', 'USD']] + [[10.0, 20261000 + d, 'Forecast', 'USD'] for d in range(2, 32)]
        cols = [{'name': n} for n in ('Cost', 'UsageDate', 'CostStatus', 'Currency')]
        return 200, {'properties': {'columns': cols, 'rows': rows}}, None


class ForecastTests(unittest.TestCase):
    def read(self, throttled, per_sub=None, d=None, resume=False):
        clock = Clock()
        api = ForecastApi(clock, throttled, per_sub)
        with tempfile.TemporaryDirectory() as tmp:
            ws = io.Workspace(d or tmp, '2026-09')
            ws.create()
            run = sc.Runner(ws, api, SUBS, 'USD', Reuse(resume))
            ids = [s['id'] for s in SUBS]
            left = sc.forecast_first_pass(run, ids, PERIOD)
            first = list(api.calls)
            sc.forecast_retry(run, left, PERIOD, log=lambda *_: None, clock=clock, sleep=clock.sleep)
            out = sc.task_forecast(run, ids, PERIOD)
        return out, first, api.calls, clock.t

    def test_next_month_only(self):
        out, first, _calls, _t = self.read([])
        self.assertEqual(first, [f'forecast.{s["id"]}.next' for s in SUBS])
        self.assertEqual(list(out['months']), ['next'])
        self.assertEqual(out['overall']['next']['subscriptionsWithEstimate'], 6)
        self.assertNotIn('next2', out['subscriptions'][0])

    def test_throttled_forecasts_wait_for_the_retry_round(self):
        # throttled from the second forecast for ten minutes: each is tried once without waiting, then read again later
        out, first, _calls, t = self.read([(6, 600)])
        self.assertEqual(first, [f'forecast.{s["id"]}.next' for s in SUBS])
        self.assertEqual(out['overall']['next']['subscriptionsWithEstimate'], 6)
        self.assertLess(t, 15 * 60)

    def test_resume_keeps_forecasts_already_read(self):
        # a resumed collection overwrote last night's good forecasts with 429 when the API throttled again
        # (the first two had failed: two throttled in a row sent the rest to the retry round without trying their saved reads)
        never = (0, 10 ** 6)
        with tempfile.TemporaryDirectory() as d:
            self.read([], per_sub={'s0': never, 's1': never}, d=d)
            out, _first, calls, _t = self.read([never], d=d, resume=True)
        self.assertEqual(set(calls), {'forecast.s0.next', 'forecast.s1.next'})
        self.assertEqual(out['overall']['next']['subscriptionsWithEstimate'], 4)

    def test_retry_round_takes_turns(self):
        # throttled one subscription at a time (seen: one throttled for many minutes while others read at once):
        # the retry round must not keep waiting on the first one
        out, _first, calls, _t = self.read([], per_sub={'s0': (0, 10 ** 6), 's1': (0, 200), 's2': (0, 200)})
        est = {s['subscriptionId']: s['next']['fullMonthEstimate'] for s in out['subscriptions']}
        self.assertEqual([s for s, v in est.items() if v is None], ['s0'])
        self.assertLess(calls.index('forecast.s2.next', 3), len(calls))   # s2 read again, not left behind s0
        self.assertIn('429', out['subscriptions'][0]['next']['reason'])

    def test_retry_round_has_a_time_limit(self):
        out, _first, _calls, t = self.read([(6, 10 ** 6)])
        self.assertLessEqual(t, sc.FORECAST_RETRY_SECONDS + 120)
        self.assertEqual(out['overall']['next']['subscriptionsWithEstimate'], 1)
        self.assertEqual(out['overall']['next']['subscriptionsPlanned'], 6)
        left = [s for s in out['subscriptions'] if s['next']['fullMonthEstimate'] is None]
        self.assertEqual(len(left), 5)
        self.assertTrue(all('429' in s['next']['reason'] for s in left))   # read as failed, as before


if __name__ == '__main__':
    unittest.main()
