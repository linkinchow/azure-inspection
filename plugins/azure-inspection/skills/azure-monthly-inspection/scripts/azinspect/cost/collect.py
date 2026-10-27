"""Cost Management collection for the monthly report (read-only).

Per subscription, for the review month (cur) and the month before (prev):
  curActual / prevActual      ActualCost, Daily, by ServiceName + ResourceGroupName
  curAmortized                AmortizedCost, Monthly, by ServiceName
  curResources                ActualCost, Monthly, by ResourceId + ServiceName
  curPricingModel             ActualCost, Monthly, by PricingModel (subscriptions with cost only)
  curResourceGroups           fallback when the combined Service+ResourceGroup grouping is rejected
  budgets                     existing budgets (GET; subscriptions with cost only)

Failures are recorded with their HTTP status and never turned into zero cost. Successful empty answers
are kept apart from denied or failed reads. Output: <workspace>/<month>/raw/cost/.
"""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import json
import math

from ..core.io import read_json, write_json

API = '2025-03-01'
CORE = ('curActual', 'prevActual', 'curAmortized', 'curResources')
KINDS = CORE + ('curPricingModel', 'curResourceGroups', 'budgets')
ARM = 'https://management.azure.com'


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def query_body(kind, period):
    definitions = {
        'curActual': ('ActualCost', 'Daily', ['ServiceName', 'ResourceGroupName']),
        'prevActual': ('ActualCost', 'Daily', ['ServiceName', 'ResourceGroupName']),
        'curAmortized': ('AmortizedCost', 'Monthly', ['ServiceName']),
        'curResources': ('ActualCost', 'Monthly', ['ResourceId', 'ServiceName']),
        'curPricingModel': ('ActualCost', 'Monthly', ['PricingModel']),
        'curResourceGroups': ('ActualCost', 'Daily', ['ResourceGroupName']),
    }
    cost_type, granularity, dimensions = definitions[kind]
    window = period.previous.cost_range() if kind == 'prevActual' else period.current.cost_range()
    return {'type': cost_type, 'timeframe': 'Custom', 'timePeriod': window,
            'dataset': {'granularity': granularity, 'aggregation': {'totalCost': {'name': 'Cost', 'function': 'Sum'}},
                        'grouping': [{'type': 'Dimension', 'name': dim} for dim in dimensions]}}


def parse_rows(record):
    rows = []
    for page in (record.get('result', record)).get('pages', []):
        props = page['body'].get('properties', {})
        columns = [c['name'] for c in props.get('columns', [])]
        if len(columns) != len(set(columns)):
            raise ValueError('Duplicate column names')
        for row in props.get('rows', []):
            if len(row) != len(columns):
                raise ValueError('Cost row length does not match columns')
            rows.append(dict(zip(columns, row)))
    return rows


def normalized(record, currency):
    sub = record['subscription']
    rows = []
    for raw in parse_rows(record):
        lower = {k.lower(): v for k, v in raw.items()}
        cost = next((lower[k] for k in ('pretaxcost', 'cost', 'totalcost', 'costusd') if k in lower), None)
        if cost is None or not math.isfinite(float(cost)):
            raise ValueError('Missing/nonfinite cost column')
        if lower.get('currency') != currency:
            raise ValueError(f'Expected {currency}, received {lower.get("currency")!r}; no mixed-currency totals permitted')
        date = lower.get('usagedate', lower.get('date'))
        if date is not None:
            text = str(date)
            date = dt.datetime.strptime(text, '%Y%m%d').date().isoformat() if len(text) == 8 and text.isdigit() else dt.date.fromisoformat(text[:10]).isoformat()
            window = record['query']['timePeriod']
            if not window['from'][:10] <= date <= window['to'][:10]:
                raise ValueError('Cost date outside requested complete month')
        if record['query']['dataset']['granularity'] == 'Daily' and date is None:
            raise ValueError('Daily response missing date')
        rows.append({'subscriptionId': sub['id'], 'name': sub['name'], 'group': sub['group'], 'date': date,
                     'serviceName': lower.get('servicename'), 'resourceGroup': lower.get('resourcegroupname', lower.get('resourcegroup')),
                     'resourceId': lower.get('resourceid'), 'pricingModel': lower.get('pricingmodel'), 'cost': float(cost), 'currency': lower.get('currency')})
    return rows


def fetch_pages(client, url, body, kind):
    """All pages of one query. A successful page without a cost table is an error, never 'empty'."""
    pages, error, seen = [], None, set()
    while url:
        if url in seen or len(seen) >= 10000:
            error = {'message': 'Duplicate nextLink or pagination limit reached', 'queriedAt': now()}
            break
        seen.add(url)
        status, data, err = client.request('GET' if kind == 'budgets' else 'POST', url, 'cost', kind, body=body)
        if status != 200:
            error = {'httpStatus': status, 'message': err, 'queriedAt': now(), 'url': url}
            break
        data = data or {}
        if kind != 'budgets' and not all(k in (data.get('properties') or {}) for k in ('rows', 'columns')):
            error = {'httpStatus': status, 'message': 'Successful response missing cost table; not treated as empty', 'queriedAt': now()}
            break
        if kind == 'budgets' and not isinstance(data.get('value'), list):
            error = {'httpStatus': status, 'message': 'Successful budgets response missing value array; not treated as empty', 'queriedAt': now()}
            break
        pages.append({'url': url, 'httpStatus': status, 'queriedAt': now(), 'headers': [], 'body': data})
        url = data.get('nextLink') if kind == 'budgets' else data['properties'].get('nextLink')
    return {'ok': error is None, 'pages': pages, 'attempts': [], 'error': error}


class Collector:
    def __init__(self, ws, client, period, subscriptions, currency, log=print):
        self.ws, self.client, self.period, self.subscriptions, self.currency, self.log = ws, client, period, subscriptions, currency, log
        self.records = {}
        self.started = now()
        self.optional_scope = []

    def job(self, sub, kind):
        body = None if kind == 'budgets' else query_body(kind, self.period)
        suffix = 'Microsoft.Consumption/budgets?api-version=2024-08-01' if kind == 'budgets' else f'Microsoft.CostManagement/query?api-version={API}'
        url = f"{ARM}/subscriptions/{sub['id']}/providers/{suffix}"
        record = {'collectorVersion': 2, 'subscription': sub, 'queryKind': kind, 'query': body, 'url': url, 'startedAt': now()}
        record['result'] = fetch_pages(self.client, url, body, kind)
        record['completedAt'] = now()
        if kind == 'curActual' and not record['result']['ok'] and (record['result']['error'] or {}).get('httpStatus') == 400:
            detail = json.dumps(record['result']['error']).lower()
            if 'group' in detail or 'dimension' in detail:
                fallback = query_body(kind, self.period)
                fallback['dataset']['grouping'] = [{'type': 'Dimension', 'name': 'ServiceName'}]
                record['unsupportedCombinedGrouping'] = record['result']
                record['query'] = fallback
                record['result'] = fetch_pages(self.client, url, fallback, kind)
                record['resourceGroupFallbackRequired'] = True
        try:
            rows = normalized(record, self.currency) if kind != 'budgets' else []
            if record['result']['ok']:
                record['validation'] = {'ok': True, 'rowCount': len(rows)}
        except (ValueError, TypeError, KeyError) as exc:
            record['validation'] = {'ok': False, 'error': str(exc)}
            rows = []
        self.ws.save_raw(f'cost/queries/{sub["id"]}.{kind}.json', record)
        self.records[(sub['id'], kind)] = (record, rows)
        return record

    def run_jobs(self, jobs):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            for future in concurrent.futures.as_completed([pool.submit(self.job, s, k) for s, k in jobs]):
                future.result()

    def snapshot(self, complete):
        index, all_rows, coverage = [], {kind: [] for kind in KINDS if kind != 'budgets'}, {}
        for (sid, kind), (record, rows) in self.records.items():
            result = record['result']
            ok = result['ok'] and record.get('validation', {}).get('ok', True)
            denied = not ok and (result.get('error') or {}).get('httpStatus') in (401, 403)
            count = sum(len(p['body'].get('value', [])) for p in result['pages']) if kind == 'budgets' else len(rows)
            status = ('empty' if count == 0 else 'success') if ok else ('denied' if denied else 'error')
            index.append({'subscriptionId': sid, 'name': record['subscription']['name'], 'group': record['subscription']['group'],
                          'queryKind': kind, 'ok': ok, 'status': status, 'rowCount': count,
                          'totalCost': math.fsum(r['cost'] for r in rows) if ok and kind != 'budgets' else None,
                          'error': (record.get('validation') or {}).get('error') or result.get('error')})
            if kind != 'budgets' and ok:
                all_rows[kind].extend(rows)
        for kind in KINDS:
            selected = [r for r in index if r['queryKind'] == kind]
            coverage[kind] = {'attempted': len(selected), 'successful': sum(r['ok'] for r in selected),
                              'empty': sum(r['status'] == 'empty' for r in selected), 'denied': sum(r['status'] == 'denied' for r in selected),
                              'errors': sum(r['status'] == 'error' for r in selected)}
        meta = {'collectorVersion': 2, 'startedAt': self.started, 'completedAt': now() if complete else None, 'complete': complete,
                'apiVersion': API, 'currency': self.currency,
                'periods': {'cur': self.period.current.cost_range(), 'prev': self.period.previous.cost_range()},
                'months': {'cur': self.period.current.key, 'prev': self.period.previous.key},
                'subscriptions': self.subscriptions, 'scopeCount': len(self.subscriptions), 'optionalScope': self.optional_scope,
                'coverage': coverage, 'index': sorted(index, key=lambda r: (r['subscriptionId'], r['queryKind'])),
                'limitations': ['Cost Management 实际费用查询结果，不是最终发票；税费、信用额度和发票调整未核对。',
                                '每日行是计费记录，不是资源数量；零费用和负费用都保留。',
                                '计价方式金额不等于 RI/SP 覆盖率；实际费用与分摊费用相同不能证明没有承诺。',
                                '查询成功但为空与无权限、失败分开记录；不同分组方式的月度合计不能相加。']}
        write_json(self.ws.raw('cost/cost-data.json'), {**meta, 'rows': all_rows})
        return meta


def collect(ws, cfg, client, period, log=print):
    from ..vm.collect import subscriptions_in_scope
    subs = []
    for s in subscriptions_in_scope(client, cfg):
        subs.append({**s, 'group': cfg.business_line(s['name']) or '其他', 'stateAtCollection': s['state']})
    collector = Collector(ws, client, period, subs, cfg.currency, log)
    log(f'费用采集：{len(subs)} 个订阅，{period.current.label}（对比 {period.previous.label}）')
    collector.run_jobs([(s, k) for s in subs for k in CORE])
    supplemental = [(r['subscription'], 'curResourceGroups') for r, _ in list(collector.records.values()) if r.get('resourceGroupFallbackRequired')]
    if supplemental:
        collector.run_jobs(supplemental)
    collector.optional_scope = [s['id'] for s in subs if any(
        rec['result']['ok'] and any(row['cost'] != 0 for row in rows)
        for (sid, kind), (rec, rows) in collector.records.items() if sid == s['id'] and kind in ('curActual', 'prevActual'))]
    active = [s for s in subs if s['id'] in collector.optional_scope]
    collector.run_jobs([(s, 'curPricingModel') for s in active] + [(s, 'budgets') for s in active])
    meta = collector.snapshot(True)
    budgets = []
    for (sid, kind), (record, _rows) in collector.records.items():
        if kind == 'budgets' and record['result']['ok']:
            for page in record['result']['pages']:
                for b in page['body'].get('value', []):
                    budgets.append({**b, 'subscriptionId': sid, 'subscriptionName': record['subscription']['name']})
    write_json(ws.raw('cost/budgets.json'), {'queriedAt': now(), 'subscriptionsQueried': len(active), 'budgets': budgets})
    cov = meta['coverage']
    log(f'费用采集完成：本月 {cov["curActual"]["successful"]}/{cov["curActual"]["attempted"]}，上月 {cov["prevActual"]["successful"]}/{cov["prevActual"]["attempted"]} 个订阅读取成功；'
        f'无权限 {cov["curActual"]["denied"]}，失败 {cov["curActual"]["errors"]}')
    return meta
