"""Existing reservations (RI) and savings plans (SP): coverage, utilization, expiry, and Azure's purchase recommendations.

Read-only. Three parts, each recorded with its own status (a failed or denied read is never "no commitments"):
1. pricing: Cost Management AmortizedCost for the review month per subscription with cost: totals by PricingModel (01),
   and by ResourceId + PricingModel for virtual machines and scale sets only, which tells 02 which machines are already
   covered by RI/SP so their downsizing is not counted as a direct saving. Reading every resource here was as large as
   the per-resource cost query and was only ever used for machines.
2. orders: reservations (Microsoft.Capacity) and savings plans (Microsoft.BillingBenefits) with 7/30-day utilization and
   expiry. Needs Reservations Reader / billing read access; usually denied for a plain subscription reader.
3. Azure's purchase recommendations per subscription (Consumption reservationRecommendations, Cost Management
   benefitRecommendations), last 30 days, single scope. Savings are for the 30-day look-back, i.e. about a month.
Each subscription's reads are saved under raw/cost/commitments/ so `collect --resume` can skip them.
Output: raw/cost/commitments.json.
"""
from __future__ import annotations

import datetime as dt
import math
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from ..core.io import read_json, write_json
from ..core.reuse import Reuse, signature
from .collect import API, ARM, COLLECTOR_VERSION, fetch_pages, parse_rows

RESERVATION_API = '2022-11-01'
CONSUMPTION_API = '2023-05-01'
RI_TYPES = ['VirtualMachines', 'PostgreSQL', 'MySQL', 'RedisCache', 'ManagedDisk', 'BlockBlob', 'CosmosDB', 'SQLDatabases']
COMMITTED = ('reservation', 'savingsplan')
LOW_UTILIZATION = 80        # % over 30 days
WORKERS = 4                 # subscriptions read in parallel (Consumption APIs throttle per caller)
EXPIRY_DAYS = 90


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _status(status, error):
    return {'httpStatus': status, 'error': error, 'ok': status == 200}


MACHINE_TYPES = ['microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachinescalesets']


def pricing_body(period, by_resource):
    grouping = ([{'type': 'Dimension', 'name': 'ResourceId'}] if by_resource else []) + [{'type': 'Dimension', 'name': 'PricingModel'}]
    body = {'type': 'AmortizedCost', 'timeframe': 'Custom', 'timePeriod': period.current.cost_range(),
            'dataset': {'granularity': 'None', 'aggregation': {'totalCost': {'name': 'Cost', 'function': 'Sum'}}, 'grouping': grouping}}
    if by_resource:
        body['dataset']['filter'] = {'dimensions': {'name': 'ResourceType', 'operator': 'In', 'values': MACHINE_TYPES}}
    return body


def _saved_read(ws, reuse, rel, sig, read):
    """A per-subscription read saved under raw/cost/commitments/; reused with --resume when it succeeded."""
    record = reuse.load(ws.raw(rel), sig, lambda r: r.get('ok'))
    if record is None:
        record = reuse.stamp({**read(), 'queriedAt': now()}, sig)
        write_json(ws.raw(rel), record)
    return record


def _pricing_rows(result):
    for r in parse_rows(result):
        lower = {k.lower(): v for k, v in r.items()}
        cost = next((lower[k] for k in ('costusd', 'pretaxcost', 'cost', 'totalcost') if k in lower), None)
        if cost is not None and math.isfinite(float(cost)):
            yield str(lower.get('resourceid') or '').lower(), str(lower.get('pricingmodel') or 'OnDemand'), float(cost)


def pricing(ws, client, sub_ids, period, reuse=None):
    """(machine rows by resource and pricing model, {subscription: {pricing model: cost}}, statuses)."""
    reuse = reuse or Reuse(False)
    url = lambda sid: f'{ARM}/subscriptions/{sid}/providers/Microsoft.CostManagement/query?api-version={API}'  # noqa: E731

    def one(sid):
        def read(by_resource):
            body = pricing_body(period, by_resource)
            result = fetch_pages(client, url(sid), body, 'curResourcePricing')
            if by_resource and not result['ok'] and (result.get('error') or {}).get('httpStatus') == 400:
                # the resource type filter was refused: read every resource and keep the machines here
                del body['dataset']['filter']
                result = fetch_pages(client, url(sid), body, 'curResourcePricing')
                result['machineFilterLocal'] = True
            if result['ok']:
                rows = [(rid, model, cost) for rid, model, cost in _pricing_rows(result)
                        if not by_resource or (rid and '/providers/' in rid and '/'.join(rid.split('/providers/')[1].split('/')[:2]) in MACHINE_TYPES)]
                return {'ok': True, 'error': None, 'rows': rows, 'machineFilterLocal': result.get('machineFilterLocal', False)}
            return {'ok': False, 'error': result['error'], 'rows': []}
        models = _saved_read(ws, reuse, f'cost/commitments/{sid}.pricingModels.json',
                             signature('pricing-models', COLLECTOR_VERSION, url(sid), pricing_body(period, False)), lambda: read(False))
        machines = _saved_read(ws, reuse, f'cost/commitments/{sid}.machinePricing.json',
                               signature('machine-pricing', COLLECTOR_VERSION, url(sid), pricing_body(period, True)), lambda: read(True))
        return sid, models, machines

    with ThreadPoolExecutor(WORKERS) as pool:
        results = list(pool.map(one, sub_ids))
    rows, by_model, statuses = [], {}, {}
    for sid, models, machines in results:
        statuses[sid] = {'ok': models['ok'] and machines['ok'], 'error': models['error'] or machines['error'],
                         'models': models['ok'], 'machines': machines['ok']}
        if models['ok']:
            by_model[sid] = {}
            for _rid, model, cost in models['rows']:
                by_model[sid][model] = by_model[sid].get(model, 0.0) + cost
        rows += [{'subscriptionId': sid, 'resourceId': rid, 'pricingModel': model, 'cost': cost} for rid, model, cost in machines['rows'] if rid]
    return rows, by_model, statuses


def _utilization(props):
    util = props.get('utilization') or {}
    agg = {f'{a.get("grain")}{a.get("grainUnit", "")}'.lower(): a.get('value') for a in util.get('aggregates') or []}
    return {'trend': util.get('trend'), 'days7': agg.get('7days'), 'days30': agg.get('30days')}


def _summary_utilization(client, order_id, period_end):
    """Average daily utilization over 30 days from reservation summaries, when the reservation has no utilization block."""
    end = period_end.date()
    start = end - dt.timedelta(days=30)
    url = (f'{ARM}/providers/Microsoft.Capacity/reservationorders/{order_id}/providers/Microsoft.Consumption/reservationSummaries'
           f"?grain=daily&$filter=properties/usageDate ge '{start.isoformat()}' and properties/usageDate le '{end.isoformat()}'"
           f'&api-version={CONSUMPTION_API}')
    items, status, error = client.get_all(url, 'commitments', f'summaries {order_id}')
    values = [(i.get('properties') or {}).get('avgUtilizationPercentage') for i in items or []]
    values = [v for v in values if isinstance(v, (int, float))]
    return (sum(values) / len(values) if values else None), status, error


def orders(client, period_end):
    out = {'reservations': [], 'savingsPlans': []}
    items, status, error = client.get_all(f'{ARM}/providers/Microsoft.Capacity/reservationOrders?api-version={RESERVATION_API}',
                                          'commitments', 'reservationOrders')
    out['reservationStatus'] = _status(status if items is not None else status, error)
    for order in items or []:
        oid = order.get('name') or str(order.get('id', '')).split('/')[-1]
        res, st, err = client.get_all(f'{ARM}/providers/Microsoft.Capacity/reservationOrders/{oid}/reservations?api-version={RESERVATION_API}',
                                      'commitments', f'reservations {oid}')
        for r in res or []:
            p = r.get('properties') or {}
            util = _utilization(p)
            if util['days30'] is None:
                util['days30'], util['summaryStatus'], util['summaryError'] = _summary_utilization(client, oid, period_end)
            out['reservations'].append({
                'orderId': oid, 'name': p.get('displayName') or r.get('name'), 'sku': (r.get('sku') or {}).get('name'),
                'description': p.get('skuDescription'), 'resourceType': p.get('reservedResourceType'), 'quantity': p.get('quantity'),
                'term': p.get('term'), 'scope': p.get('appliedScopeType'), 'expiry': p.get('expiryDateTime') or p.get('expiryDate'),
                'renew': p.get('renew'), 'state': p.get('provisioningState'), 'utilization': util, 'readStatus': _status(st, err)})
    items, status, error = client.get_all(f'{ARM}/providers/Microsoft.BillingBenefits/savingsPlanOrders?api-version={RESERVATION_API}',
                                          'commitments', 'savingsPlanOrders')
    out['savingsPlanStatus'] = _status(status, error)
    for order in items or []:
        oid = order.get('name') or str(order.get('id', '')).split('/')[-1]
        plans, st, err = client.get_all(f'{ARM}/providers/Microsoft.BillingBenefits/savingsPlanOrders/{oid}/savingsPlans?api-version={RESERVATION_API}',
                                         'commitments', f'savingsPlans {oid}')
        for s in plans or []:
            p = s.get('properties') or {}
            commit = p.get('commitment') or {}
            out['savingsPlans'].append({
                'orderId': oid, 'name': p.get('displayName') or s.get('name'), 'commitment': commit.get('amount'),
                'currency': commit.get('currencyCode'), 'grain': commit.get('grain'), 'term': p.get('term'),
                'scope': p.get('appliedScopeType'), 'expiry': p.get('expiryDateTime'), 'renew': p.get('renew'),
                'state': p.get('provisioningState') or p.get('displayProvisioningState'), 'utilization': _utilization(p),
                'readStatus': _status(st, err)})
    return out


def _amount(x):
    """Legacy recommendations carry numbers, modern ones {'currency','value'}."""
    if isinstance(x, dict):
        return x.get('value')
    return x


def recommendations(client, sub_ids, sub_names, log=print, ws=None, reuse=None):
    rows, statuses, done = [], {}, []
    reuse = reuse or Reuse(False)

    def one(sid):
        if ws is None:
            rows_, statuses_ = _recommendations_for(client, sid, sub_names)
        else:
            sig = signature('purchase-recommendations', COLLECTOR_VERSION, sid, RI_TYPES, CONSUMPTION_API, API)
            record = reuse.load(ws.raw(f'cost/commitments/{sid}.recommendations.json'), sig,
                                lambda r: all(s.get('ok') for s in r['statuses'].values()))
            if record is None:
                rows_, statuses_ = _recommendations_for(client, sid, sub_names)
                write_json(ws.raw(f'cost/commitments/{sid}.recommendations.json'),
                           reuse.stamp({'subscriptionId': sid, 'queriedAt': now(), 'rows': rows_, 'statuses': statuses_}, sig))
            else:
                rows_, statuses_ = record['rows'], record['statuses']
        done.append(sid)
        log(f'  Azure 购买建议：{len(done)}/{len(sub_ids)} 个订阅已读取')
        return rows_, statuses_

    with ThreadPoolExecutor(WORKERS) as pool:
        for rows_, statuses_ in pool.map(one, sub_ids):
            rows += rows_
            statuses.update(statuses_)
    return rows, statuses


def _recommendations_for(client, sid, sub_names):
    rows, statuses = [], {}
    for rtype in RI_TYPES:
        flt = f"properties/scope eq 'Single' AND properties/lookBackPeriod eq 'Last30Days' AND properties/resourceType eq '{rtype}'"
        items, status, error = client.get_all(f'{ARM}/subscriptions/{sid}/providers/Microsoft.Consumption/reservationRecommendations'
                                              f'?api-version={CONSUMPTION_API}&$filter={flt}', 'commitments', f'ri-rec {rtype}')
        statuses[f'{sid}|RI|{rtype}'] = _status(status, error)
        for i in items or []:
            p = i.get('properties') or {}
            rows.append({'kind': '预留实例', 'subscription': sub_names.get(sid, sid), 'resourceType': rtype,
                         'sku': p.get('skuName') or i.get('sku') or p.get('normalizedSize'), 'region': i.get('location'),
                         'term': p.get('term'), 'quantity': p.get('recommendedQuantity'),
                         'costWithout': _amount(p.get('costWithNoReservedInstances')), 'costWith': _amount(p.get('totalCostWithReservedInstances')),
                         'saving': _amount(p.get('netSavings')), 'lookBack': p.get('lookBackPeriod')})
    for term in ('P1Y', 'P3Y'):
        flt = f"properties/scope eq 'Single' AND properties/lookBackPeriod eq 'Last30Days' AND properties/term eq '{term}'"
        items, status, error = client.get_all(f'{ARM}/subscriptions/{sid}/providers/Microsoft.CostManagement/benefitRecommendations'
                                              f'?api-version={API}&$filter={flt}', 'commitments', f'sp-rec {term}')
        statuses[f'{sid}|SP|{term}'] = _status(status, error)
        for i in items or []:
            p = i.get('properties') or {}
            d = p.get('recommendationDetails') or {}
            if not d.get('commitmentAmount'):
                continue
            rows.append({'kind': '节省计划', 'subscription': sub_names.get(sid, sid), 'resourceType': p.get('armSkuName'),
                         'sku': f'每小时承诺 {d.get("commitmentAmount")}', 'region': None, 'term': p.get('term'),
                         'quantity': d.get('commitmentAmount'), 'costWithout': p.get('costWithoutBenefit'), 'costWith': d.get('totalCost'),
                         'saving': d.get('savingsAmount'), 'coverage': d.get('coveragePercentage'),
                         'utilization': d.get('averageUtilizationPercentage'), 'lookBack': p.get('lookBackPeriod')})
    return rows, statuses


def collect(ws, client, period, log=print, reuse=None):
    data = read_json(ws.raw('cost/cost-data.json'))
    names = {s['id']: s['name'] for s in data['subscriptions']}
    active = list(data.get('optionalScope') or [])
    log(f'RI/SP：读取 {len(active)} 个有费用订阅的计价方式（按计价方式汇总，及虚拟机和规模集的逐资源计价方式）')
    machine_pricing, by_model, pricing_status = pricing(ws, client, active, period, reuse)
    end = dt.datetime.now(dt.timezone.utc)
    log('RI/SP：读取现有预留和节省计划订单')
    held = orders(client, end)
    recs, rec_status = recommendations(client, active, names, log, ws, reuse)
    out = {'collectedAt': now(), 'month': period.current.key, 'subscriptionsQueried': len(active),
           'pricingByResource': machine_pricing, 'pricingByModel': by_model, 'pricingScope': 'machines',
           'pricingStatus': pricing_status, **held, 'recommendations': recs, 'recommendationStatus': rec_status}
    write_json(ws.raw('cost/commitments.json'), out)
    s = summary(out, end)
    log(f'RI/SP：按资源计价方式 {s["pricingRead"]}/{len(active)} 个订阅读取成功；'
        f'预留订单{"读取成功，" + str(len(held["reservations"])) + " 个预留" if held["reservationStatus"]["ok"] else "读取失败或无权限"}，'
        f'节省计划{"读取成功，" + str(len(held["savingsPlans"])) + " 个" if held["savingsPlanStatus"]["ok"] else "读取失败或无权限"}；'
        f'Azure 购买建议 {len(recs)} 条')
    return out


def load(ws):
    path = ws.raw('cost/commitments.json')
    return read_json(path) if path.exists() else None


def _expiry(value):
    try:
        return dt.datetime.fromisoformat(str(value).replace('Z', '+00:00')).date()
    except ValueError:
        return None


def summary(data, today=None):
    """Coverage per resource, flagged commitments, totals for the report."""
    if isinstance(today, dt.datetime):
        today = today.date()
    today = today or dt.datetime.now(dt.timezone.utc).date()
    per = defaultdict(lambda: defaultdict(float))
    for r in data.get('pricingByResource') or []:
        per[r['resourceId']][r['pricingModel'].lower().replace(' ', '')] += r['cost']
    coverage = {}
    for rid, models in per.items():
        total = math.fsum(models.values())
        committed = math.fsum(v for k, v in models.items() if k in COMMITTED)
        coverage[rid] = {'total': total, 'committed': committed, 'share': committed / total if total > 0 else None, 'models': dict(models)}
    by_model = defaultdict(float)
    if 'pricingByModel' in data:     # 0.7.0+: totals read per subscription; per-resource rows cover machines only
        for models in data['pricingByModel'].values():
            for k, v in models.items():
                by_model[k.lower().replace(' ', '')] += v
    else:
        for models in per.values():
            for k, v in models.items():
                by_model[k] += v
    flagged = []
    for kind, items in (('预留实例', data.get('reservations') or []), ('节省计划', data.get('savingsPlans') or [])):
        for c in items:
            notes = []
            u30 = (c.get('utilization') or {}).get('days30')
            if isinstance(u30, (int, float)) and u30 < LOW_UTILIZATION:
                notes.append(f'近 30 天使用率 {u30:.0f}%，未用满')
            exp = _expiry(c.get('expiry'))
            if exp and 0 <= (exp - today).days <= EXPIRY_DAYS:
                notes.append(f'{(exp - today).days} 天后到期' + ('，已设置自动续订' if c.get('renew') else '，未设置自动续订'))
            elif exp and (exp - today).days < 0:
                notes.append('已到期')
            flagged.append({**c, 'kind': kind, 'notes': notes, 'expiryDate': exp.isoformat() if exp else None})
    statuses = data.get('pricingStatus') or {}
    return {'coverage': coverage, 'byModel': dict(by_model), 'commitments': flagged,
            'pricingRead': sum(1 for s in statuses.values() if s.get('models', s.get('ok'))),
            'reservationsRead': (data.get('reservationStatus') or {}).get('ok', False),
            'savingsPlansRead': (data.get('savingsPlanStatus') or {}).get('ok', False),
            'recommendations': sorted(data.get('recommendations') or [], key=lambda r: (str(r.get('subscription') or ''), r['kind'], str(r.get('term')), -(r.get('saving') or 0))),
            # RI and SP, 1-year and 3-year are alternatives for the same usage: totals are kept per (kind, term) and never added up
            'recommendationTotals': {f'{k}|{t}': v for (k, t), v in _totals(data.get('recommendations') or []).items()},
            'recommendationsRead': sum(1 for s in (data.get('recommendationStatus') or {}).values() if s.get('ok')),
            'recommendationsTried': len(data.get('recommendationStatus') or {})}


def _totals(recs):
    out = defaultdict(float)
    for r in recs:
        out[(r['kind'], r.get('term'))] += r.get('saving') or 0
    return out


def vm_coverage(ws):
    """resource id (lower) -> share of amortized cost covered by RI/SP in the review month; None when not read."""
    data = load(ws)
    if not data or not any(s.get('machines', s.get('ok')) for s in (data.get('pricingStatus') or {}).values()):
        return None
    return {rid: c for rid, c in summary(data)['coverage'].items() if c['total'] > 0}
