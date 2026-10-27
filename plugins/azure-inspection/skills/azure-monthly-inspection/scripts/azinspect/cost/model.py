"""Monthly cost model: review month (cur) against the month before (prev), using real day counts.

Only subscriptions whose cost could be read for both months are compared; failed reads stay None (never 0).
"""
from __future__ import annotations

import math
from collections import defaultdict

from ..core.io import read_json


def total(rows):
    return math.fsum(float(r['cost']) for r in rows)


def compare(rows_prev, rows_cur, field, dp, dc):
    groups = defaultdict(lambda: {'prev': [], 'cur': []})
    for period, rows in [('prev', rows_prev), ('cur', rows_cur)]:
        for r in rows:
            groups[r.get(field) or '未归属'][period].append(float(r['cost']))
    result = []
    for key, parts in groups.items():
        prev, cur = math.fsum(parts['prev']), math.fsum(parts['cur'])
        result.append({'name': key, 'prev': prev, 'cur': cur, 'delta': cur - prev, 'changeRate': cur / prev - 1 if prev > 0 else None,
                       'prevDaily': prev / dp, 'curDaily': cur / dc, 'dailyChangeRate': (cur / dc) / (prev / dp) - 1 if prev > 0 else None})
    return sorted(result, key=lambda r: (-r['cur'], r['name']))


def build(ws, period):
    data = read_json(ws.raw('cost/cost-data.json'))
    if not data.get('complete'):
        raise RuntimeError('费用采集未完成，不能把部分结果当作整月费用')
    dp, dc = period.previous.days, period.current.days
    rows = {k: v for k, v in data['rows'].items() if data.get('coverage', {}).get(k, {}).get('attempted', 0) > 0}
    subs, index = data['subscriptions'], data['index']
    actual_prev, actual_cur, amort = rows['prevActual'], rows['curActual'], rows.get('curAmortized', [])
    for source, rs in rows.items():
        assert all(r.get('currency') == data['currency'] for r in rs if r.get('currency')), source
        assert all(isinstance(r.get('cost'), (int, float)) and math.isfinite(r['cost']) for r in rs), source
    index = [r for r in index if r.get('queryKind') in rows]
    query = {(r['subscriptionId'], r['queryKind']): r for r in index}

    def status(q):
        return '已读取' if q.get('ok') and q.get('rowCount', 0) > 0 else '查询成功，无费用记录' if q.get('ok') else '读取失败，未计为0'

    subscription_rows = []
    for s in subs:
        qp, qc, qa = query.get((s['id'], 'prevActual'), {}), query.get((s['id'], 'curActual'), {}), query.get((s['id'], 'curAmortized'), {})
        prev = total(r for r in actual_prev if r['subscriptionId'] == s['id']) if qp.get('ok') else None
        cur = total(r for r in actual_cur if r['subscriptionId'] == s['id']) if qc.get('ok') else None
        am = total(r for r in amort if r['subscriptionId'] == s['id']) if qa.get('ok') else None
        subscription_rows.append({**s, 'prev': prev, 'cur': cur, 'delta': cur - prev if prev is not None and cur is not None else None,
                                  'changeRate': cur / prev - 1 if prev and prev > 0 and cur is not None else None,
                                  'prevDaily': prev / dp if prev is not None else None, 'curDaily': cur / dc if cur is not None else None,
                                  'dailyChangeRate': (cur / dc) / (prev / dp) - 1 if prev and prev > 0 and cur is not None else None,
                                  'amortizedCur': am, 'actualCurStatus': status(qc), 'actualPrevStatus': status(qp)})
    subscription_rows.sort(key=lambda r: (-(r['cur'] or 0), r['name'].lower()))
    submap = {s['id']: s for s in subs}

    def aggregate_parts(parts, dimensions):
        result = []
        for keys, values in parts.items():
            prev, cur, sid = math.fsum(values['prev']), math.fsum(values['cur']), keys[0]
            item = {'subscriptionId': sid, 'subscriptionName': submap[sid]['name'], 'group': submap[sid]['group'], 'prev': prev, 'cur': cur,
                    'delta': cur - prev, 'changeRate': cur / prev - 1 if prev > 0 else None, 'prevDaily': prev / dp, 'curDaily': cur / dc,
                    'dailyChangeRate': (cur / dc) / (prev / dp) - 1 if prev > 0 else None}
            item.update(dict(zip(dimensions, keys[1:])))
            result.append(item)
        return sorted(result, key=lambda r: (-abs(r['delta']), r['subscriptionName']))

    rg, service_drivers = defaultdict(lambda: {'prev': [], 'cur': []}), defaultdict(lambda: {'prev': [], 'cur': []})
    for p, rs in [('prev', actual_prev), ('cur', actual_cur)]:
        for r in rs:
            rg[(r['subscriptionId'], r.get('resourceGroup') or '未归属')][p].append(float(r['cost']))
            service_drivers[(r['subscriptionId'], r.get('serviceName') or '未归属')][p].append(float(r['cost']))
    resource_groups, drivers = aggregate_parts(rg, ['resourceGroup']), aggregate_parts(service_drivers, ['serviceName'])
    resources = defaultdict(list)
    for r in rows.get('curResources', []):
        resources[(r['subscriptionId'], r.get('resourceId') or '无资源ID', r.get('serviceName') or '未归属')].append(float(r['cost']))
    resource_rows = []
    for (sid, rid, service), values in resources.items():
        parts = rid.split('/')
        lower = [p.lower() for p in parts]
        resource_rows.append({'subscriptionId': sid, 'subscriptionName': submap[sid]['name'], 'group': submap[sid]['group'],
                              'resourceGroup': parts[lower.index('resourcegroups') + 1] if 'resourcegroups' in lower else '未归属',
                              'resourceId': rid, 'resourceName': parts[-1] if rid != '无资源ID' else rid, 'serviceName': service, 'cost': math.fsum(values)})
    resource_rows.sort(key=lambda r: -r['cost'])
    daily = defaultdict(lambda: {'prev': [], 'cur': []})
    for p, rs in [('prev', actual_prev), ('cur', actual_cur)]:
        for r in rs:
            date = str(r.get('date', '')).replace('-', '')[:8]
            if len(date) == 8 and date.isdigit():
                daily[int(date[-2:])][p].append(float(r['cost']))
    daily_rows = [{'day': day, 'prev': math.fsum(parts['prev']) if day <= dp else None, 'cur': math.fsum(parts['cur']) if day <= dc else None}
                  for day, parts in sorted(daily.items())]
    am_services, pricing = defaultdict(list), defaultdict(list)
    for r in amort:
        am_services[r.get('serviceName') or '未归属'].append(float(r['cost']))
    for r in rows.get('curPricingModel', []):
        pricing[r.get('pricingModel') or '未归属'].append(float(r['cost']))
    completeness = {kind: {'success': sum(r.get('ok', False) for r in index if r['queryKind'] == kind),
                           'failed': [{'subscriptionId': r['subscriptionId'], 'name': submap[r['subscriptionId']]['name'], 'error': r.get('error')}
                                      for r in index if r['queryKind'] == kind and not r.get('ok')]} for kind in rows}
    comparable = {r['id'] for r in subscription_rows if r['prev'] is not None and r['cur'] is not None}
    paired_prev = [r for r in actual_prev if r['subscriptionId'] in comparable]
    paired_cur = [r for r in actual_cur if r['subscriptionId'] in comparable]
    cp, cc = total(paired_prev), total(paired_cur)
    comparison_totals = {'prev': cp, 'cur': cc, 'delta': cc - cp, 'changeRate': cc / cp - 1 if cp > 0 else None,
                         'prevDaily': cp / dp, 'curDaily': cc / dc, 'dailyChangeRate': (cc / dc) / (cp / dp) - 1 if cp > 0 else None}
    groups = compare(paired_prev, paired_cur, 'group', dp, dc)
    services = compare(paired_prev, paired_cur, 'serviceName', dp, dc)
    drivers = [r for r in drivers if r['subscriptionId'] in comparable]
    resource_groups = [r for r in resource_groups if r['subscriptionId'] in comparable]
    budget_path, review_path = ws.raw('cost/budgets.json'), ws.raw('cost/review/results.json')
    review = read_json(review_path) if review_path.exists() else None
    if review is not None:
        from .orphan import findings as orphan_findings
        rows, counts, orphans = orphan_findings(ws, {s['id'].lower(): s['name'] for s in subs})
        review['wasteFindings'] = review.get('wasteFindings', []) + rows
        review.setdefault('wasteSummary', {}).setdefault('classificationCounts', {}).update(counts)
        review['orphanQueries'] = {'commit': orphans['commit'], 'failed': [r['key'] for r in orphans['results'] if r['status'] != 200]} if orphans else None
    tp, tc = total(actual_prev), total(actual_cur)
    return {'scope': {'subscriptionCount': len(subs), 'subscriptionNames': [s['name'] for s in subs],
                      'months': {'cur': period.current.key, 'prev': period.previous.key}, 'days': {'cur': dc, 'prev': dp},
                      'currency': data['currency'], 'queriedAt': data.get('completedAt'), 'coverage': completeness, 'sourceCoverage': data.get('coverage')},
            'totals': {'prev': tp, 'cur': tc, 'delta': tc - tp, 'changeRate': tc / tp - 1 if tp > 0 else None,
                       'prevDaily': tp / dp, 'curDaily': tc / dc, 'dailyChangeRate': (tc / dc) / (tp / dp) - 1 if tp > 0 else None,
                       'amortizedCur': total(amort), 'comparableSubscriptionCount': len(comparable), 'comparablePrev': cp, 'comparableCur': cc},
            'comparableTotals': comparison_totals, 'comparableSubscriptionIds': sorted(comparable),
            'groups': groups, 'subscriptions': subscription_rows, 'services': services, 'subscriptionServiceDrivers': drivers,
            'resourceGroups': resource_groups, 'resources': resource_rows, 'daily': daily_rows,
            'amortizedServices': [{'serviceName': n, 'cost': math.fsum(v)} for n, v in sorted(am_services.items(), key=lambda t: -math.fsum(t[1]))],
            'pricingModels': [{'pricingModel': n, 'cost': math.fsum(v)} for n, v in sorted(pricing.items(), key=lambda t: -math.fsum(t[1]))],
            'resourceReview': review,
            'budgets': read_json(budget_path) if budget_path.exists() else None}
