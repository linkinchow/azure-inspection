"""Reading the saved performance raw data: ARG rows, normalized metric series, daily roll-ups (no network calls)."""
from __future__ import annotations

import math
import re
from collections import defaultdict


def num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def fmt(x, n=1):
    return None if x is None else round(x, n)


def rg_of(rid):
    m = re.search(r'/resourcegroups/([^/]+)', rid or '', re.I)
    return m.group(1) if m else None


def sub_of(rid):
    m = re.search(r'/subscriptions/([0-9a-fA-F-]{36})', rid or '')
    return m.group(1).lower() if m else (rid or '').lower()


class Data:
    """Cached access to raw/waf/performance/ for one analysis run, limited to the lookback window."""

    def __init__(self, raw, start: str, end: str, subscriptions: list[dict]):
        self.raw, self.start, self.end = raw, start[:19], end[:19]
        self.names = {s['id'].lower(): s['name'] for s in subscriptions}
        self._cache = {}

    def load(self, rel):
        if rel not in self._cache:
            self._cache[rel] = self.raw.load(rel)
        return self._cache[rel]

    def rows(self, name):
        return (self.load(f'arg/{name}.json') or {}).get('rows') or []

    def subname(self, rid_or_sub):
        return self.names.get(sub_of(rid_or_sub))

    def in_window(self, ts: str) -> bool:
        return self.start <= (ts or '')[:19] < self.end

    def series(self, label, rid, metric):
        """-> (list of {'dims', 'data'}, error or None)."""
        r = ((self.load(f'metrics/{label}.json') or {}).get('results') or {}).get((rid or '').lower())
        if r is None:
            return [], 'not queried'
        if not isinstance(r, dict):
            return [], 'saved data was redacted'
        if r.get('_error'):
            return [], r['_error']
        if metric in (r.get('_errors') or {}):
            return [], r['_errors'][metric]
        if metric not in r:
            return [], 'metric not returned'
        return [{'dims': {(k or '').lower(): v for k, v in (x.get('dims') or {}).items()}, 'data': x['data']} for x in r[metric]], None

    def daily(self, points):
        """Group points (any grain up to one day) by UTC date inside the window."""
        by = defaultdict(list)
        for p in points or []:
            ts = p.get('timeStamp') or ''
            if self.in_window(ts):
                by[ts[:10]].append(p)
        return [rec for day, ps in sorted(by.items()) if len(rec := _day(day, ps)) > 1]

    def summarize(self, points, peak_thr=None, avg_thr=None, low_thr=None):
        """Count-weighted window average; highest daily max; days with daily max >= peak_thr;
        days with daily avg >= avg_thr; days with daily min <= low_thr; window total."""
        days = self.daily(points)
        res = {'days': len(days)}
        with_avg = [d for d in days if 'avg' in d]
        if with_avg:
            if all(d.get('count') for d in with_avg):
                n = sum(d['count'] for d in with_avg)
                res['avg'] = sum(d['avg'] * d['count'] for d in with_avg) / n
            else:
                res['avg'] = sum(d['avg'] for d in with_avg) / len(with_avg)
            res['avgDays'] = len(with_avg)
            res['maxDailyAvg'] = max(d['avg'] for d in with_avg)
            if avg_thr is not None:
                res['daysAvgGE'] = sum(1 for d in with_avg if d['avg'] >= avg_thr)
        maxes = [d for d in days if 'max' in d]
        if maxes:
            top = max(maxes, key=lambda d: d['max'])
            res['maxDailyMax'], res['maxDate'] = top['max'], top['date']
            if peak_thr is not None:
                res['daysMaxGE'] = sum(1 for d in maxes if d['max'] >= peak_thr)
        mins = [d for d in days if 'min' in d]
        if mins:
            res['minDailyMin'] = min(d['min'] for d in mins)
            if low_thr is not None:
                res['daysMinLE'] = sum(1 for d in mins if d['min'] <= low_thr)
        totals = [d for d in days if 'total' in d]
        if totals:
            res['total'] = sum(d['total'] for d in totals)
        return res

    def metric(self, label, rid, metric, thr=None, avg_thr=None, low=None):
        """Summary of the first series of one metric, or {'error': ...}."""
        s, e = self.series(label, rid, metric)
        if e:
            return {'error': e}
        if not s:
            return {'error': 'no time series returned (no data in window)'}
        return self.summarize(s[0]['data'], thr, avg_thr, low)


def first(series_list):
    return series_list[0]['data'] if series_list else []


def _day(day, points):
    rec = {'date': day}
    av = [(p['average'], p.get('count')) for p in points if num(p.get('average'))]
    if av:
        if all(num(c) and c > 0 for _, c in av):
            n = sum(c for _, c in av)
            rec['avg'], rec['count'] = sum(a * c for a, c in av) / n, n
        else:
            rec['avg'], rec['count'] = sum(a for a, _ in av) / len(av), None
    for key, agg, fn in (('max', 'maximum', max), ('min', 'minimum', min), ('total', 'total', sum)):
        vals = [p[agg] for p in points if num(p.get(agg))]
        if vals:
            rec[key] = fn(vals)
    return rec
