"""Cost supplements (read-only Cost Management queries), run after the base model:

  region    ActualCost prev/cur grouped by ResourceLocation + ServiceName (comparable subscriptions)
  forecast  forecast for the following month (actual to date + Azure forecast), optionally the month after
  drivers   top-10 increases / top-5 decreases (subscription, service) split by resource and meter with
            Cost + UsageQuantity: new, removed, daily-rate quantity, calendar (day-count) and unit-cost effects

Output: <workspace>/<month>/raw/cost/supplement/{region,forecast,drivers}.json; raw answers in .../queries/.
"""
from __future__ import annotations

import datetime as dt
import json
import math

from ..core.io import write_json

API = '2025-03-01'
ARM = 'https://management.azure.com'
DRIVER_GROUPINGS = [
    ['ResourceId', 'MeterCategory', 'MeterSubcategory', 'Meter', 'UnitOfMeasure'],
    ['ResourceId', 'MeterCategory', 'MeterSubcategory', 'Meter'],
    ['ResourceId', 'MeterId'],
    ['ResourceId', 'Meter'],
]


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parse_rows(result):
    rows = []
    for page in result.get('pages', []):
        props = page['body'].get('properties', {})
        cols = [c['name'] for c in props.get('columns', [])]
        for row in props.get('rows', []):
            if len(row) != len(cols):
                raise ValueError('row/column length mismatch')
            rows.append({c.lower(): v for c, v in zip(cols, row)})
    return rows


def cost_of(row):
    for k in ('cost', 'pretaxcost', 'totalcost', 'costusd'):
        if k in row and row[k] is not None:
            v = float(row[k])
            if not math.isfinite(v):
                raise ValueError('nonfinite cost')
            return v
    raise ValueError('missing cost column')


def qty_of(row):
    for k in ('usagequantity', 'totalquantity', 'quantity'):
        if k in row and row[k] is not None:
            return float(row[k])
    return None


class Runner:
    """Runs one Cost Management query (all pages), saves it, keeps a small index for coverage."""

    def __init__(self, ws, client, subs, currency):
        self.ws, self.client, self.subs, self.currency = ws, client, {s['id']: s for s in subs}, currency
        self.index = {}

    def run(self, qid, sid, kind, endpoint, body, extra=None):
        url = f'{ARM}/subscriptions/{sid}/providers/Microsoft.CostManagement/{endpoint}?api-version={API}'
        pages, error, seen = [], None, set()
        while url:
            if url in seen or len(seen) >= 500:
                error = {'message': 'Duplicate nextLink or pagination limit reached'}
                break
            seen.add(url)
            status, data, err = self.client.request('POST', url, 'cost-supplement', qid, body=body)
            if status != 200:
                error = {'httpStatus': status, 'message': err}
                break
            props = (data or {}).get('properties') or {}
            if 'rows' not in props or 'columns' not in props:
                error = {'httpStatus': status, 'message': 'Successful response missing cost table; not treated as empty'}
                break
            pages.append({'httpStatus': status, 'queriedAt': now(), 'body': data})
            url = props.get('nextLink') or None
        rec = {'queryId': qid, 'kind': kind, 'endpoint': endpoint, 'subscription': {k: self.subs[sid][k] for k in ('id', 'name', 'group')},
               'query': body, 'extra': extra or {}, 'result': {'ok': error is None, 'pages': pages, 'error': error}, 'completedAt': now()}
        self.ws.save_raw(f'cost/supplement/queries/{qid}.json', rec)
        rows, verr = [], None
        if error is None:
            try:
                rows = parse_rows(rec['result'])
                currencies = {r.get('currency') for r in rows}
                if rows and currencies != {self.currency}:
                    raise ValueError(f'Expected {self.currency} only, got {sorted(map(str, currencies))}')
                total = math.fsum(cost_of(r) for r in rows)
            except (ValueError, TypeError, KeyError) as exc:
                verr = str(exc)
        ok = error is None and verr is None
        http = (error or {}).get('httpStatus') if error else 200
        self.index[qid] = {'queryId': qid, 'subscriptionId': sid, 'kind': kind, 'ok': ok, 'httpStatus': http,
                           'status': ('empty' if not rows else 'success') if ok else 'denied' if http in (401, 403) else 'notFound' if http == 404 else 'error',
                           'error': ({'validation': verr} if verr else error) if not ok else None, 'rowCount': len(rows) if ok else None,
                           'totalCost': total if ok else None,
                           'columns': [c['name'] for c in (pages[0]['body']['properties'].get('columns', []) if pages else [])] if ok else None}
        self._rows = getattr(self, '_rows', {})
        self._rows[qid] = rows if ok else None
        return self.index[qid]

    def rows(self, qid):
        return self._rows.get(qid)


def region_body(window):
    return {'type': 'ActualCost', 'timeframe': 'Custom', 'timePeriod': window,
            'dataset': {'granularity': 'None', 'aggregation': {'totalCost': {'name': 'Cost', 'function': 'Sum'}},
                        'grouping': [{'type': 'Dimension', 'name': 'ResourceLocation'}, {'type': 'Dimension', 'name': 'ServiceName'}]}}


def forecast_body(window):
    return {'type': 'ActualCost', 'timeframe': 'Custom', 'timePeriod': window,
            'dataset': {'granularity': 'Daily', 'aggregation': {'totalCost': {'name': 'Cost', 'function': 'Sum'}}},
            'includeActualCost': True, 'includeFreshPartialCost': False}


def driver_body(window, service, dims):
    return {'type': 'ActualCost', 'timeframe': 'Custom', 'timePeriod': window,
            'dataset': {'granularity': 'None',
                        'aggregation': {'totalCost': {'name': 'Cost', 'function': 'Sum'}, 'totalQuantity': {'name': 'UsageQuantity', 'function': 'Sum'}},
                        'grouping': [{'type': 'Dimension', 'name': d} for d in dims],
                        'filter': {'dimensions': {'name': 'ServiceName', 'operator': 'In', 'values': [service]}}}}


def task_region(run, comparable, ref, period):
    windows = {'prev': period.previous.cost_range(), 'cur': period.current.cost_range()}
    dp, dc = period.previous.days, period.current.days
    for sid in comparable:
        for m, window in windows.items():
            run.run(f'region.{sid}.{m}', sid, f'region-{m}', 'query', region_body(window))
    per_sub, overall, overall_svc, mismatches = [], {'prev': {}, 'cur': {}}, {'prev': {}, 'cur': {}}, []
    for sid in comparable:
        s = run.subs[sid]
        entry = {'subscriptionId': sid, 'name': s['name'], 'group': s['group'], 'months': {}, 'reconciliation': {}}
        for m in ('prev', 'cur'):
            it = run.index[f'region.{sid}.{m}']
            if not it['ok']:
                entry['months'][m] = {'status': it['status'], 'total': None, 'error': it['error']}
                entry['reconciliation'][m] = {'ok': None, 'reason': 'query failed'}
                continue
            rows = run.rows(f'region.{sid}.{m}')
            tot = math.fsum(cost_of(r) for r in rows)
            by_loc = {}
            for r in rows:
                loc = (r.get('resourcelocation') or '').strip().lower() or '(blank)'
                svc = r.get('servicename') or '(blank)'
                c = cost_of(r)
                by_loc[loc] = by_loc.get(loc, 0) + c
                overall[m][loc] = overall[m].get(loc, 0) + c
                overall_svc[m][(loc, svc)] = overall_svc[m].get((loc, svc), 0) + c
            entry['months'][m] = {'status': it['status'], 'total': tot, 'rowCount': len(rows), 'byLocation': dict(sorted(by_loc.items(), key=lambda kv: -abs(kv[1])))}
            expected = ref.get((sid, m))
            diff = None if expected is None else tot - expected
            ok = None if expected is None else abs(diff) <= 0.01
            entry['reconciliation'][m] = {'expected': expected, 'actual': tot, 'diff': diff, 'ok': ok}
            if ok is False:
                mismatches.append({'subscriptionId': sid, 'name': s['name'], 'month': m, 'expected': expected, 'actual': tot, 'diff': diff})
        per_sub.append(entry)
    gt = {m: math.fsum(overall[m].values()) for m in ('prev', 'cur')}
    locs = sorted(set(overall['prev']) | set(overall['cur']), key=lambda l: -(overall['cur'].get(l, 0) + overall['prev'].get(l, 0)))
    loc_table = [{'location': l, 'prev': overall['prev'].get(l, 0.0), 'cur': overall['cur'].get(l, 0.0),
                  'delta': overall['cur'].get(l, 0.0) - overall['prev'].get(l, 0.0), 'prevDaily': overall['prev'].get(l, 0.0) / dp,
                  'curDaily': overall['cur'].get(l, 0.0) / dc, 'curShare': overall['cur'].get(l, 0.0) / gt['cur'] if gt['cur'] else None} for l in locs]
    keys = set(overall_svc['prev']) | set(overall_svc['cur'])
    ls_table = sorted([{'location': k[0], 'serviceName': k[1], 'prev': overall_svc['prev'].get(k, 0.0), 'cur': overall_svc['cur'].get(k, 0.0),
                        'delta': overall_svc['cur'].get(k, 0.0) - overall_svc['prev'].get(k, 0.0)} for k in keys],
                      key=lambda x: -max(abs(x['prev']), abs(x['cur'])))
    return {'description': 'ActualCost by ResourceLocation and ServiceName, full natural months', 'apiVersion': API, 'periods': windows,
            'coverage': {'planned': len(comparable) * 2, 'successful': sum(run.index[f'region.{sid}.{m}']['ok'] for sid in comparable for m in ('prev', 'cur'))},
            'overall': {'totals': gt, 'note': 'Sum over successful queries only; failed months are excluded (not zero).',
                        'byLocation': loc_table, 'byLocationService': ls_table},
            'reconciliation': {'tolerance': 0.01, 'mismatches': mismatches,
                               'allOk': all(e['reconciliation'][m].get('ok') is True for e in per_sub for m in ('prev', 'cur'))},
            'subscriptions': per_sub, 'complete': True}


def summarize_forecast(run, qid, window):
    it = run.index[qid]
    if not it['ok']:
        return {'status': it['status'], 'actualToDate': None, 'forecastRemainder': None, 'fullMonthEstimate': None,
                'reason': f"HTTP {it['httpStatus']}: " + json.dumps(it['error'], ensure_ascii=False)[:600]}
    rows = run.rows(qid)
    if not rows:
        return {'status': 'empty', 'actualToDate': None, 'forecastRemainder': None, 'fullMonthEstimate': None, 'reason': 'forecast API returned an empty table'}
    daily = []
    for r in rows:
        d = str(r.get('usagedate') or r.get('date'))
        d = dt.datetime.strptime(d, '%Y%m%d').date().isoformat() if len(d) == 8 and d.isdigit() else d[:10]
        daily.append({'date': d, 'costStatus': r.get('coststatus'), 'cost': cost_of(r)})
    daily.sort(key=lambda x: (x['date'], str(x['costStatus'])))
    lo, hi = window['from'][:10], window['to'][:10]
    outside = [x for x in daily if not lo <= x['date'] <= hi]
    act = [x for x in daily if str(x['costStatus']).lower() == 'actual']
    fc = [x for x in daily if str(x['costStatus']).lower() == 'forecast']
    overlap = sorted({x['date'] for x in act} & {x['date'] for x in fc})
    a, f = math.fsum(x['cost'] for x in act), math.fsum(x['cost'] for x in fc)
    total_days = (dt.date.fromisoformat(hi) - dt.date.fromisoformat(lo)).days + 1
    out = {'status': 'success', 'actualDays': len({x['date'] for x in act}), 'actualFrom': act[0]['date'] if act else None,
           'actualTo': act[-1]['date'] if act else None, 'forecastDays': len({x['date'] for x in fc}),
           'forecastFrom': fc[0]['date'] if fc else None, 'forecastTo': fc[-1]['date'] if fc else None,
           'daysCovered': len({x['date'] for x in daily}), 'daysInMonth': total_days, 'actualToDate': a,
           'forecastRemainder': f if fc else None, 'overlapDates': overlap, 'rowsOutsideMonth': len(outside), 'daily': daily}
    if fc and not overlap and not outside:
        out['fullMonthEstimate'] = a + f
    elif not fc and act and len({x['date'] for x in act}) == total_days:
        out.update(fullMonthEstimate=a, forecastRemainder=0.0, note='month already complete: all actual')
    else:
        out['fullMonthEstimate'] = None
        out['reason'] = 'no forecast rows returned' if not fc else f'actual/forecast overlap on {overlap}' if overlap else f'{len(outside)} rows outside month'
        if not fc:
            out['status'] = 'noForecastRows'
    return out


def task_forecast(run, comparable, period, include_second=True):
    months = {'next': period.following, 'next2': period.following.shift(1)}
    if not include_second:
        months.pop('next2')
    for key, month in months.items():
        for sid in comparable:
            run.run(f'forecast.{sid}.{key}', sid, f'forecast-{key}', 'forecast', forecast_body(month.cost_range()))
    subs = []
    for sid in comparable:
        s = run.subs[sid]
        e = {'subscriptionId': sid, 'name': s['name'], 'group': s['group']}
        for key, month in months.items():
            e[key] = summarize_forecast(run, f'forecast.{sid}.{key}', month.cost_range())
        subs.append(e)

    def totals(key):
        ok = [e for e in subs if e[key].get('fullMonthEstimate') is not None]
        return {'subscriptionsWithEstimate': len(ok), 'subscriptionsPlanned': len(subs),
                'actualToDate': math.fsum(e[key]['actualToDate'] for e in ok), 'forecastRemainder': math.fsum(e[key]['forecastRemainder'] for e in ok),
                'fullMonthEstimate': math.fsum(e[key]['fullMonthEstimate'] for e in ok)}
    return {'description': 'Cost Management forecast API (ActualCost, Daily, includeActualCost=true). fullMonthEstimate = Actual + Forecast rows as returned by Azure.',
            'apiVersion': API, 'queriedOn': dt.date.today().isoformat(), 'months': {k: m.key for k, m in months.items()},
            'periods': {k: m.cost_range() for k, m in months.items()}, 'overall': {k: totals(k) for k in months}, 'subscriptions': subs, 'complete': True}


def decompose(prev_rows, cur_rows, dims, dp, dc):
    def key_of(r):
        return tuple(str(r.get(d.lower()) or '').lower() if d == 'ResourceId' else str(r.get(d.lower()) or '') for d in dims)
    agg = {}
    for m, rows in (('prev', prev_rows), ('cur', cur_rows)):
        for r in rows:
            a = agg.setdefault(key_of(r), {'prevCost': 0.0, 'curCost': 0.0, 'prevQty': 0.0, 'curQty': 0.0, 'prevRows': 0, 'curRows': 0, 'qtyMissing': False})
            a[m + 'Cost'] += cost_of(r)
            q = qty_of(r)
            if q is None:
                a['qtyMissing'] = True
            else:
                a[m + 'Qty'] += q
            a[m + 'Rows'] += 1
    comp = {'newMeters': 0.0, 'removedMeters': 0.0, 'quantityAtPrevUnitCost': 0.0, 'calendarEffect': 0.0,
            'dailyRateQuantityEffect': 0.0, 'unitCostChange': 0.0, 'residual': 0.0}
    items = []
    for k, a in agg.items():
        rec = dict(zip(dims, k))
        rid = rec.get('ResourceId', '')
        rec['resourceName'] = rid.rstrip('/').split('/')[-1] if rid else '(no resource id)'
        rec.update(a)
        rec['delta'] = a['curCost'] - a['prevCost']
        rec['prevUnitCost'] = a['prevCost'] / a['prevQty'] if a['prevQty'] > 0 else None
        rec['curUnitCost'] = a['curCost'] / a['curQty'] if a['curQty'] > 0 else None
        cat = {}
        if a['prevRows'] == 0:
            cat['newMeters'], rec['class'] = a['curCost'], 'new'
        elif a['curRows'] == 0:
            cat['removedMeters'], rec['class'] = -a['prevCost'], 'removed'
        elif a['prevQty'] > 0 and a['curQty'] > 0:
            up, uc = rec['prevUnitCost'], rec['curUnitCost']
            q_eff = (a['curQty'] - a['prevQty']) * up
            cal = (a['prevQty'] * dc / dp - a['prevQty']) * up
            cat.update(quantityAtPrevUnitCost=q_eff, calendarEffect=cal, dailyRateQuantityEffect=q_eff - cal, unitCostChange=a['curQty'] * (uc - up))
            cat['residual'] = rec['delta'] - q_eff - cat['unitCostChange']
            rec['class'] = 'continuing'
        else:
            cat['residual'], rec['class'] = rec['delta'], 'continuing-no-quantity'
        for c, v in cat.items():
            comp[c] += v
        rec['components'] = cat
        items.append(rec)
    items.sort(key=lambda x: -abs(x['delta']))
    return comp, items


def _roll(items, keyf):
    out = {}
    for it in items:
        a = out.setdefault(keyf(it), {'prevCost': 0.0, 'curCost': 0.0, 'prevQty': 0.0, 'curQty': 0.0, 'n': 0, 'prevRows': 0, 'curRows': 0})
        for f in ('prevCost', 'curCost', 'prevQty', 'curQty', 'prevRows', 'curRows'):
            a[f] += it[f]
        a['n'] += 1
    return out


def task_drivers(run, model, period):
    dp, dc = period.previous.days, period.current.days
    windows = {'prev': period.previous.cost_range(), 'cur': period.current.cost_range()}
    dr = model['subscriptionServiceDrivers']
    pairs = ([('increase', x) for x in sorted([x for x in dr if x['delta'] > 0], key=lambda x: -x['delta'])[:10]]
             + [('decrease', x) for x in sorted([x for x in dr if x['delta'] < 0], key=lambda x: x['delta'])[:5]])
    dims, trials = None, []
    if pairs:  # find the richest grouping that Cost Management accepts together with UsageQuantity
        probe = pairs[min(3, len(pairs) - 1)][1]
        for i, candidate in enumerate(DRIVER_GROUPINGS):
            it = run.run(f'pilot.drivers.g{i}', probe['subscriptionId'], 'drivers-pilot', 'query',
                         driver_body(windows['cur'], probe['serviceName'], candidate), {'dims': candidate})
            has_qty = bool(it['ok'] and any(c.lower() in ('usagequantity', 'totalquantity') for c in it['columns'] or []))
            trials.append({'dims': candidate, 'status': it['status'], 'httpStatus': it['httpStatus'], 'quantityColumn': has_qty})
            if has_qty:
                dims = candidate
                break
            if it['httpStatus'] in (401, 403, 404):
                break
    out = []
    for rank, (kind, p) in enumerate(pairs if dims else [], 1):
        sid, svc, tag = p['subscriptionId'], p['serviceName'], f'{kind}{rank:02d}'
        for m in ('prev', 'cur'):
            run.run(f'drivers.{tag}.{sid}.{m}', sid, f'drivers-{m}', 'query', driver_body(windows[m], svc, dims), {'serviceName': svc, 'pairKind': kind})
        e = {'rank': rank, 'kind': kind, 'subscriptionId': sid, 'subscriptionName': p['subscriptionName'], 'group': p['group'], 'serviceName': svc,
             'model': {k: p[k] for k in ('prev', 'cur', 'delta', 'prevDaily', 'curDaily', 'dailyChangeRate')}}
        its = {m: run.index[f'drivers.{tag}.{sid}.{m}'] for m in ('prev', 'cur')}
        if not all(it['ok'] for it in its.values()):
            e.update(status='failed', decomposition=None, errors={m: it['error'] for m, it in its.items() if not it['ok']})
            out.append(e)
            continue
        comp, items = decompose(run.rows(f'drivers.{tag}.{sid}.prev'), run.rows(f'drivers.{tag}.{sid}.cur'), dims, dp, dc)
        tp, tc = math.fsum(i['prevCost'] for i in items), math.fsum(i['curCost'] for i in items)
        e.update(status='success', totals={'prev': tp, 'cur': tc, 'delta': tc - tp},
                 reconciliation={'tolerance': 0.01, 'prevDiff': tp - p['prev'], 'curDiff': tc - p['cur'], 'ok': abs(tp - p['prev']) <= 0.01 and abs(tc - p['cur']) <= 0.01},
                 decomposition=comp)
        res_roll = _roll(items, lambda i: i.get('ResourceId', ''))
        new_res, rem_res = {r for r, a in res_roll.items() if a['prevRows'] == 0}, {r for r, a in res_roll.items() if a['curRows'] == 0}
        e['resources'] = {'countPrev': sum(1 for a in res_roll.values() if a['prevRows']), 'countCur': sum(1 for a in res_roll.values() if a['curRows']),
                          'newCount': len(new_res), 'removedCount': len(rem_res), 'newCost': math.fsum(res_roll[r]['curCost'] for r in new_res),
                          'removedCost': math.fsum(res_roll[r]['prevCost'] for r in rem_res)}
        e['topResources'] = [{'resourceId': r, 'resourceName': r.rstrip('/').split('/')[-1] if r else '(no resource id)', 'prev': a['prevCost'], 'cur': a['curCost'],
                              'delta': a['curCost'] - a['prevCost'], 'status': 'new' if r in new_res else 'removed' if r in rem_res else 'continuing'}
                             for r, a in sorted(res_roll.items(), key=lambda kv: -abs(kv[1]['curCost'] - kv[1]['prevCost']))[:10]]
        meter_dims = [d for d in dims if d != 'ResourceId']
        mroll = _roll(items, lambda i: tuple(i.get(d, '') for d in meter_dims))
        e['topMeters'] = [{**dict(zip(meter_dims, k)), 'prev': a['prevCost'], 'cur': a['curCost'], 'delta': a['curCost'] - a['prevCost'],
                           'prevQty': a['prevQty'], 'curQty': a['curQty'], 'prevUnitCost': a['prevCost'] / a['prevQty'] if a['prevQty'] > 0 else None,
                           'curUnitCost': a['curCost'] / a['curQty'] if a['curQty'] > 0 else None, 'resourceCount': a['n']}
                          for k, a in sorted(mroll.items(), key=lambda kv: -abs(kv[1]['curCost'] - kv[1]['prevCost']))[:10]]
        out.append(e)
    return {'description': 'Per (subscription, service) driver decomposition at (resource, meter) level; components sum to cur - prev.',
            'apiVersion': API, 'groupingUsed': dims, 'pilot': trials, 'days': {'prev': dp, 'cur': dc}, 'pairs': out,
            'coverage': {'pairs': len(out), 'successful': sum(e['status'] == 'success' for e in out),
                         'reconciled': sum(bool(e.get('reconciliation', {}).get('ok')) for e in out)}, 'complete': True}


def collect(ws, cfg, client, period, model, log=print):
    from ..core.io import read_json
    cd = read_json(ws.raw('cost/cost-data.json'))
    comparable = model['comparableSubscriptionIds']
    ref = {(r['subscriptionId'], r['queryKind'][:4] if r['queryKind'].startswith('prev') else 'cur'): r['totalCost']
           for r in cd['index'] if r['queryKind'] in ('prevActual', 'curActual') and r['ok']}
    run = Runner(ws, client, cd['subscriptions'], cfg.currency)
    region = task_region(run, comparable, ref, period)
    write_json(ws.raw('cost/supplement/region.json'), region)
    forecast = task_forecast(run, comparable, period)
    write_json(ws.raw('cost/supplement/forecast.json'), forecast)
    drivers = task_drivers(run, model, period)
    write_json(ws.raw('cost/supplement/drivers.json'), drivers)
    log(f'区域、预测、变化原因：区域合计{"一致" if region["reconciliation"]["allOk"] else "有差异"}；'
        f'{forecast["overall"]["next"]["subscriptionsWithEstimate"]} 个订阅有预测；变化原因拆解 {drivers["coverage"]["reconciled"]}/{drivers["coverage"]["pairs"]} 项对上')
    return region, forecast, drivers
