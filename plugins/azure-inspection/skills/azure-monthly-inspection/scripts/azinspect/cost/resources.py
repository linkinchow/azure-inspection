"""Databases/caches, storage accounts and Log Analytics for the review month (read-only).

Configuration is the current snapshot, not the configuration during the month. Usage is the review month.
Missing data stays null with the reason. Output: <workspace>/<month>/raw/cost/resources/{databases,storage,logs}.json.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

from ..core.io import write_json

MYSQL, PG = 'microsoft.dbformysql/flexibleservers', 'microsoft.dbforpostgresql/flexibleservers'
REDIS, AMR, AMRDB = 'microsoft.cache/redis', 'microsoft.cache/redisenterprise', 'microsoft.cache/redisenterprise/databases'
MONGO, STORAGE = 'microsoft.documentdb/mongoclusters', 'microsoft.storage/storageaccounts'
WS, AKS = 'microsoft.operationalinsights/workspaces', 'microsoft.containerservice/managedclusters'
INV_TYPES = [MYSQL, PG, REDIS, AMR, AMRDB, MONGO, STORAGE, WS, AKS]
DB_TYPES = [MYSQL, PG, REDIS, AMR, MONGO]
NAMESPACE = {MYSQL: 'Microsoft.DBforMySQL/flexibleServers', PG: 'Microsoft.DBforPostgreSQL/flexibleServers',
             REDIS: 'Microsoft.Cache/redis', AMR: 'Microsoft.Cache/redisEnterprise', MONGO: 'Microsoft.DocumentDB/mongoClusters'}
CANDIDATES = {
    MYSQL: {'cpu': ['cpu_percent'], 'memory': ['memory_percent'], 'storage': ['storage_percent'], 'io': ['io_consumption_percent']},
    PG: {'cpu': ['cpu_percent'], 'memory': ['memory_percent'], 'storage': ['storage_percent']},
    REDIS: {'cpu': ['percentProcessorTime'], 'serverLoad': ['serverLoad'], 'memory': ['usedmemorypercentage'], 'usedMemoryBytes': ['usedmemory']},
    AMR: {'cpu': ['percentProcessorTime', 'CPU', 'cpu_percent', 'CpuPercent'], 'serverLoad': ['serverLoad'],
          'memory': ['usedmemorypercentage', 'usedMemoryPercentage', 'MemoryPercent'], 'usedMemoryBytes': ['usedmemory']},
    MONGO: {'cpu': ['CpuPercent', 'cpu_percent'], 'memory': ['MemoryPercent', 'memory_percent'],
            'storage': ['StoragePercent', 'storage_percent'], 'storageUsed': ['StorageUsed']},
}
ARM = 'https://management.azure.com'


def now():
    return datetime.now(timezone.utc).isoformat()


class _Ctx:
    def __init__(self, ws, client, period):
        self.ws, self.client = ws, client
        self.start = f'{period.current.first.isoformat()}T00:00:00Z'
        self.end = f'{period.current.shift(1).first.isoformat()}T00:00:00Z'
        self.days = period.current.days
        last = period.current.last
        self.tail_start = (last - timedelta(days=6)).isoformat()
        self.tail_end = period.current.shift(1).first.isoformat()
        self.limitations = []

    def call(self, check, url, body=None):
        status, data, error = self.client.request('POST' if body is not None else 'GET', url, check, body=body)
        st = 'ok' if status == 200 else {401: 'denied', 403: 'denied', 404: 'notFound'}.get(status, 'error')
        return {'status': st, 'http': status, 'data': data if status == 200 else None, 'error': error}

    def graph(self, query, subs):
        rows, status, error = self.client.arg(query, subs, 'cost-resources')
        if status != 200 or rows is None:
            raise RuntimeError(f'Resource Graph 查询失败：HTTP {status} {error}')
        return rows


def _pmap(fn, items):
    with ThreadPoolExecutor(max_workers=3) as pool:
        return list(pool.map(fn, items))


def summarize_points(ctx, points, error=None):
    daily, valid, totals = [], [], []
    for p in points or []:
        st = p.get('timeStamp')
        if not (st and ctx.start[:19] <= st[:19] < ctx.end[:19]):
            continue
        a, c, t = p.get('average'), p.get('count'), p.get('total')
        daily.append({'date': st[:10], 'average': a, 'count': c, 'total': t})
        if isinstance(a, (int, float)) and math.isfinite(a) and isinstance(c, (int, float)) and c > 0:
            valid.append((st[:10], a, c))
        if isinstance(t, (int, float)) and math.isfinite(t):
            totals.append((st[:10], t))
    n = sum(c for _, _, c in valid)
    res = {'average': (sum(a * c for _, a, c in valid) / n) if n else None, 'sampleCount': n, 'validDays': len({d for d, _, _ in valid}),
           'total': sum(t for _, t in totals) if totals else None, 'totalDays': len(totals),
           'firstValid': {'date': valid[0][0], 'average': valid[0][1]} if valid else None,
           'lastValid': {'date': valid[-1][0], 'average': valid[-1][1]} if valid else None, 'daily': daily}
    if error:
        res['error'] = error
    elif not valid and not totals:
        res['error'] = 'No valid samples (Count>0) in the review month'
    return res


def metric_batches(ctx, label, items, namespace, metricnames, aggregation, mfilter=None):
    groups = defaultdict(list)
    for it in items:
        groups[(it['subscriptionId'].lower(), it['region'].lower())].append(it['metricResourceId'])
    jobs = []
    for (sub, region), rids in sorted(groups.items()):
        rids = sorted(set(rids), key=str.lower)
        for off in range(0, len(rids), 50):
            jobs.append((sub, region, rids[off:off + 50]))
    params = {'api-version': '2024-02-01', 'metricnamespace': namespace, 'metricnames': ','.join(metricnames),
              'starttime': ctx.start, 'endtime': ctx.end, 'interval': 'P1D', 'aggregation': aggregation, 'top': '100'}
    if mfilter:
        params['filter'] = mfilter
    results, fallback = {}, []

    def run(job):
        sub, region, rids = job
        if not re.fullmatch(r'[a-z][a-z0-9]{1,40}', region):
            return job, {'status': 'error'}
        return job, ctx.call('metrics', f'https://{region}.metrics.monitor.azure.com/subscriptions/{sub}/metrics:getBatch?' + urlencode(params), {'resourceids': rids})
    for job, rec in _pmap(run, jobs):
        if rec['status'] != 'ok':
            fallback.extend(job[2])
            continue
        wanted = {r.lower() for r in job[2]}
        for v in rec['data'].get('values', []):
            rid = (v.get('resourceid') or '').lower()
            if rid in wanted:
                results[rid] = {'source': 'getBatch', 'metrics': v.get('value', [])}
        fallback.extend(r for r in job[2] if r.lower() not in results)
    if fallback:
        ctx.limitations.append(f'{label}：{len(fallback)} 个资源批量指标接口失败或未返回，改为逐个读取')

    def single(rid):
        q = {'api-version': '2023-10-01', 'metricnamespace': namespace, 'metricnames': ','.join(metricnames),
             'timespan': f'{ctx.start}/{ctx.end}', 'interval': 'P1D', 'aggregation': aggregation, 'top': '100'}
        if mfilter:
            q['$filter'] = mfilter
        return rid, ctx.call('metrics', ARM + quote(rid) + '/providers/Microsoft.Insights/metrics?' + urlencode(q))
    for rid, rec in _pmap(single, fallback):
        results[rid.lower()] = ({'source': 'armMetrics', 'metrics': rec['data'].get('value', [])} if rec['status'] == 'ok'
                                else {'source': 'armMetrics', 'error': f'HTTP {rec.get("http")}: {(rec.get("error") or "")[:300]}', 'status': rec['status']})
    return results


def metric_series(result, name):
    if not result:
        return [], 'Resource not returned by metrics API'
    if result.get('error'):
        return [], result['error']
    m = next((m for m in result['metrics'] if (m.get('name') or {}).get('value', '').lower() == name.lower()), None)
    if not m:
        return [], 'Metric not returned'
    if (m.get('errorCode') or 'Success').lower() != 'success':
        return [], f'{m.get("errorCode")}: {m.get("errorMessage", "")}'
    return m.get('timeseries', []), None


def single_metric(ctx, result, name):
    ts, err = metric_series(result, name)
    if err:
        return summarize_points(ctx, [], err)
    if len(ts) > 1:
        return summarize_points(ctx, [], f'Expected 1 series, got {len(ts)}')
    return summarize_points(ctx, ts[0].get('data', []) if ts else [])


def _table(rec):
    if rec['status'] != 'ok':
        return None
    t = (rec['data'].get('tables') or [None])[0]
    if not t:
        return []
    cols = [c['name'] for c in t['columns']]
    return [dict(zip(cols, row)) for row in t['rows']]


def collect(ws, client, period, model, subscriptions, log=print):
    ctx = _Ctx(ws, client, period)
    subname = {s['id'].lower(): s['name'] for s in subscriptions}
    enabled = [s['id'] for s in subscriptions if s.get('state') == 'Enabled']
    cost, cost_svc = defaultdict(float), defaultdict(lambda: defaultdict(float))
    for r in model['resources']:
        cost[r['resourceId'].lower()] += r['cost'] or 0
        cost_svc[r['resourceId'].lower()][r['serviceName']] += r['cost'] or 0

    def costof(rid):
        k = rid.lower()
        return (round(cost[k], 2) if k in cost else None), {s: round(v, 2) for s, v in cost_svc.get(k, {}).items()}
    snapshot = now()
    inventory = ctx.graph('Resources | where type in~ (' + ','.join(repr(t) for t in INV_TYPES) + ')'
                          ' | project id,name,type,location,subscriptionId,resourceGroup,sku,kind,tags,properties,zones,identity | order by id asc', enabled)
    inventory = list({r['id'].lower(): r for r in inventory}.values())
    by_type = defaultdict(list)
    for r in inventory:
        by_type[r['type'].lower()].append(r)
    ws.save_raw('cost/resources/inventory.json', {'snapshotAt': snapshot, 'count': len(inventory), 'resources': inventory})
    scope = [{'id': s['id'], 'name': s['name'], 'state': s.get('state')} for s in subscriptions]
    discovered = {}
    for t in (AMR, MONGO, REDIS, MYSQL, PG):
        if by_type[t]:
            rec = ctx.call('metricdefinitions', ARM + quote(by_type[t][0]['id']) + '/providers/Microsoft.Insights/metricDefinitions?api-version=2023-10-01')
            discovered[t] = [d['name']['value'] for d in rec['data'].get('value', [])] if rec['status'] == 'ok' else None
    chosen = {}
    for t in DB_TYPES:
        names = {n.lower(): n for n in discovered[t]} if discovered.get(t) else None
        chosen[t] = {}
        for role, cands in CANDIDATES[t].items():
            pick = next((names[c.lower()] for c in cands if names and c.lower() in names), None) or (cands[0] if names is None else None)
            if pick:
                chosen[t][role] = pick
    db_rows = []
    for t in DB_TYPES:
        if not by_type[t]:
            continue
        mres = metric_batches(ctx, t.split('/')[-1], [{'subscriptionId': r['subscriptionId'], 'region': r['location'], 'metricResourceId': r['id']} for r in by_type[t]],
                              NAMESPACE[t], list(dict.fromkeys(chosen[t].values())), 'Average,Count')
        for r in by_type[t]:
            p, c = r.get('properties') or {}, costof(r['id'])
            sku = r.get('sku') or p.get('sku') or {}
            result = mres.get(r['id'].lower())
            metrics = {role: dict(single_metric(ctx, result, m), metricName=m) for role, m in chosen[t].items()}
            row = {'subscriptionId': r['subscriptionId'], 'subscriptionName': subname.get(r['subscriptionId'].lower()), 'resourceGroup': r['resourceGroup'],
                   'name': r['name'], 'type': r['type'], 'region': r['location'], 'resourceId': r['id'], 'curCostUSD': c[0], 'curCostByService': c[1],
                   'skuName': sku.get('name'), 'skuTier': sku.get('tier'), 'skuFamily': sku.get('family'), 'skuCapacity': sku.get('capacity'),
                   'metricsSource': (result or {}).get('source')}
            if t in (MYSQL, PG):
                st = p.get('storage') or {}
                row.update(storageSizeGB=st.get('storageSizeGB'), autoGrow=st.get('autoGrow'), haMode=(p.get('highAvailability') or {}).get('mode'),
                           state=p.get('state'), version=p.get('version'), replicationRole=p.get('replicationRole'))
            elif t in (REDIS, AMR):
                row.update(capacity=sku.get('capacity'), state=p.get('provisioningState') or p.get('resourceState'), redisVersion=p.get('redisVersion'))
            elif t == MONGO:
                row.update(state=p.get('clusterStatus') or p.get('provisioningState'), serverVersion=p.get('serverVersion'))
            row['metrics'] = metrics
            row['averages'] = {role: (round(mm['average'], 2) if mm['average'] is not None else None) for role, mm in metrics.items()}
            row['validDays'] = {role: mm['validDays'] for role, mm in metrics.items()}
            vd = list(row['validDays'].values())
            row['coverage'] = ('denied' if (result or {}).get('status') == 'denied' else 'complete' if vd and all(v == ctx.days for v in vd)
                               else 'missing' if all(v == 0 for v in vd) else 'partial')
            flags, cpu, mem = [], metrics.get('cpu'), metrics.get('memory')
            if cpu and mem and cpu['average'] is not None and mem['average'] is not None and cpu['validDays'] == ctx.days and mem['validDays'] == ctx.days \
                    and cpu['average'] < 20 and mem['average'] < 20:
                flags.append('LOW_UTILIZATION')
            for role, mm in metrics.items():
                if role in ('storageUsed', 'usedMemoryBytes'):
                    if mm['average'] is not None:
                        row['averages'][role + 'GiB'] = round(mm['average'] / 2**30, 3)
                    continue
                if mm['average'] is not None and mm['average'] >= 80:
                    flags.append(f'HIGH_UTILIZATION:{role}')
            row['flags'] = flags
            db_rows.append(row)
    db_cov = {t: {'found': sum(r['type'].lower() == t for r in db_rows), **Counter(r['coverage'] for r in db_rows if r['type'].lower() == t),
                  'curCostUSD': round(sum(r['curCostUSD'] or 0 for r in db_rows if r['type'].lower() == t), 2)} for t in DB_TYPES if any(r['type'].lower() == t for r in db_rows)}
    write_json(ws.raw('cost/resources/databases.json'), {'snapshotAt': snapshot, 'period': {'start': ctx.start, 'end': ctx.end, 'days': ctx.days}, 'complete': True,
                                                         'metricNamesChosen': chosen, 'coverage': db_cov, 'subscriptionScope': scope, 'resources': db_rows})

    accts = by_type[STORAGE]
    acct_m = metric_batches(ctx, 'storage-account', [{'subscriptionId': r['subscriptionId'], 'region': r['location'], 'metricResourceId': r['id']} for r in accts],
                            'Microsoft.Storage/storageAccounts', ['UsedCapacity', 'Transactions', 'Egress'], 'Average,Count,Total')
    blob_m = metric_batches(ctx, 'storage-blob', [{'subscriptionId': r['subscriptionId'], 'region': r['location'], 'metricResourceId': r['id'] + '/blobServices/default'}
                                                  for r in accts if (r.get('kind') or '') != 'FileStorage'],
                            'Microsoft.Storage/storageAccounts/blobServices', ['BlobCapacity', 'BlobCount'], 'Average,Count', "Tier eq '*'")
    policies = dict(_pmap(lambda r: (r['id'].lower(), ctx.call('storage', ARM + quote(r['id']) + '/managementPolicies/default?api-version=2023-05-01')), accts))
    st_rows = []
    for r in accts:
        p, sku, c = r.get('properties') or {}, r.get('sku') or {}, costof(r['id'])
        am = acct_m.get(r['id'].lower())
        used, eg = single_metric(ctx, am, 'UsedCapacity'), single_metric(ctx, am, 'Egress')
        tiers = {}
        if r.get('kind') != 'FileStorage':
            ts, _err = metric_series(blob_m.get((r['id'] + '/blobServices/default').lower()), 'BlobCapacity')
            for s in ts:
                tier = next((str(a.get('value')) for a in s.get('metadatavalues', []) if (a.get('name') or {}).get('value', '').lower() == 'tier'), 'unknown')
                sm = summarize_points(ctx, s.get('data', []))
                tiers[tier] = sm['lastValid']['average'] if sm['lastValid'] else None
        pol = policies.get(r['id'].lower())
        if pol['status'] == 'ok':
            rules = ((pol['data'].get('properties') or {}).get('policy') or {}).get('rules') or []
            pstat = {'status': '已配置', 'ruleCount': len(rules), 'rules': [{'name': x.get('name'), 'actions': list(((x.get('definition') or {}).get('actions') or {}).get('baseBlob', {}).keys())} for x in rules]}
        elif pol['status'] == 'notFound':
            pstat = {'status': '未配置'}
        else:
            pstat = {'status': '未知', 'http': pol.get('http')}
        first, last = used['firstValid'], used['lastValid']
        growth = (last['average'] - first['average']) if first and last else None
        st_rows.append({'subscriptionId': r['subscriptionId'], 'subscriptionName': subname.get(r['subscriptionId'].lower()), 'resourceGroup': r['resourceGroup'],
                        'name': r['name'], 'region': r['location'], 'resourceId': r['id'], 'kind': r.get('kind'), 'skuName': sku.get('name'),
                        'redundancy': (sku.get('name') or '').split('_')[-1] or None, 'accessTier': p.get('accessTier'), 'createdAt': p.get('creationTime'),
                        'curCostUSD': c[0], 'curCostByService': c[1],
                        'usedCapacity': {'firstBytes': first['average'] if first else None, 'lastGiB': round(last['average'] / 2**30, 2) if last else None,
                                         'growthGiB': round(growth / 2**30, 2) if growth is not None else None,
                                         'growthPct': round(growth / first['average'] * 100, 2) if growth is not None and first['average'] and first['average'] >= 2**30 else None,
                                         'validDays': used['validDays'], 'error': used.get('error')},
                        'egressGiBCur': round(eg['total'] / 2**30, 2) if eg['total'] is not None else None,
                        'tierMixLastDayGiB': {k: round(v / 2**30, 2) for k, v in tiers.items() if v is not None} or None,
                        'lifecyclePolicy': pstat, 'coverage': 'complete' if used['validDays'] == ctx.days else 'missing' if used['validDays'] == 0 else 'partial'})
    st_rows.sort(key=lambda x: -(x['curCostUSD'] or 0))
    st_cov = {'found': len(st_rows), 'complete': sum(r['coverage'] == 'complete' for r in st_rows),
              'lifecycle': dict(Counter(r['lifecyclePolicy']['status'] for r in st_rows)), 'curCostUSD': round(sum(r['curCostUSD'] or 0 for r in st_rows), 2)}
    write_json(ws.raw('cost/resources/storage.json'), {'snapshotAt': snapshot, 'period': {'start': ctx.start, 'end': ctx.end, 'days': ctx.days}, 'complete': True,
                                                       'coverage': st_cov, 'subscriptionScope': scope, 'accounts': st_rows})

    ws_rows = []
    for r in by_type[WS]:
        p, c = r.get('properties') or {}, costof(r['id'])
        ws_rows.append({'subscriptionId': r['subscriptionId'], 'subscriptionName': subname.get(r['subscriptionId'].lower()), 'resourceGroup': r['resourceGroup'],
                        'name': r['name'], 'region': r['location'], 'resourceId': r['id'], 'customerId': p.get('customerId'),
                        'retentionInDays': p.get('retentionInDays'), 'dailyQuotaGb': (p.get('workspaceCapping') or {}).get('dailyQuotaGb'),
                        'curCostUSD': c[0], 'curCostByService': c[1]})
    ws_rows.sort(key=lambda x: -(x['curCostUSD'] or 0))
    d0, d1 = ctx.start[:10], ctx.end[:10]
    usage_q = (f'Usage | where TimeGenerated >= datetime({d0}) and TimeGenerated < datetime({d1}) '
               '| summarize BillableGB=sumif(Quantity, IsBillable == true)/1000, TotalGB=sum(Quantity)/1000 by DataType, Solution | order by BillableGB desc')
    daily_q = (f'Usage | where TimeGenerated >= datetime({d0}) and TimeGenerated < datetime({d1}) '
               '| summarize BillableGB=sumif(Quantity, IsBillable == true)/1000 by Day=startofday(TimeGenerated) | order by Day asc')

    def la(row):
        cid = row['customerId']
        if not cid or not re.fullmatch(r'[0-9a-fA-F-]{36}', cid):
            row['usageError'] = 'no customerId'
            return row
        url = f'https://api.loganalytics.io/v1/workspaces/{cid}/query'
        u = ctx.call('logs', url, {'query': usage_q, 'timespan': f'{ctx.start}/{ctx.end}'})
        d = ctx.call('logs', url, {'query': daily_q, 'timespan': f'{ctx.start}/{ctx.end}'})
        bt, dt_ = _table(u), _table(d)
        row['usageStatus'] = u['status']
        if bt is not None:
            row['byDataType'] = [{k: (round(v, 4) if isinstance(v, float) else v) for k, v in x.items()} for x in bt]
            row['billableGB'] = round(sum(x['BillableGB'] or 0 for x in bt), 3)
        if dt_ is not None:
            row['daily'] = [{'date': str(x['Day'])[:10], 'billableGB': round(x['BillableGB'] or 0, 4)} for x in dt_]
            row['usageDaysPresent'] = len(row['daily'])
        return row
    big = [w for w in ws_rows if (w['curCostUSD'] or 0) >= 50]
    _pmap(la, big)
    ranked = sorted([w for w in big if w.get('billableGB') is not None], key=lambda w: -w['billableGB'])[:3]
    breakdown_q = {
        'AzureDiagnostics': f'AzureDiagnostics | where TimeGenerated >= datetime({ctx.tail_start}) and TimeGenerated < datetime({ctx.tail_end}) | where _IsBillable == true | summarize BilledGB=sum(_BilledSize)/1e9, Rows=count() by ResourceId=_ResourceId, Category | top 30 by BilledGB desc',
        'ContainerLogV2': f'ContainerLogV2 | where TimeGenerated >= datetime({ctx.tail_start}) and TimeGenerated < datetime({ctx.tail_end}) | where _IsBillable == true | summarize BilledGB=sum(_BilledSize)/1e9, Rows=count() by ResourceId=_ResourceId, PodNamespace, ContainerName | top 30 by BilledGB desc',
    }
    for w in ranked:
        w['top3'] = True
        top_type = next((x['DataType'] for x in (w.get('byDataType') or []) if x['BillableGB']), None)
        if top_type in breakdown_q:
            rows = _table(ctx.call('logs', f'https://api.loganalytics.io/v1/workspaces/{w["customerId"]}/query',
                                   {'query': breakdown_q[top_type], 'timespan': f'{ctx.tail_start}T00:00:00Z/{ctx.tail_end}T00:00:00Z'}))
            if rows is not None:
                w['topDataTypeBreakdown'] = {'dataType': top_type, 'window': f'{ctx.tail_start}..{ctx.tail_end}（7天）',
                                             'rows': [{k: (round(v, 3) if isinstance(v, float) else v) for k, v in x.items()} for x in rows]}
    ws_by_id = {w['resourceId'].lower(): w['name'] for w in ws_rows}
    candidates = sorted({r['id'] for r in by_type[MYSQL] + by_type[PG]}, key=str.lower)

    def diag(rid):
        rec = ctx.call('logs', ARM + quote(rid) + '/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview')
        if rec['status'] != 'ok':
            return {'resourceId': rid, 'status': rec['status']}
        dest = defaultdict(set)
        for s in rec['data'].get('value', []):
            sp = s.get('properties') or {}
            wsid = (sp.get('workspaceId') or '').lower()
            for x in sp.get('logs') or []:
                if x.get('enabled') and wsid:
                    dest[x.get('category') or 'group:' + str(x.get('categoryGroup'))].add(ws_by_id.get(wsid, wsid))
        return {'resourceId': rid, 'status': 'ok', 'duplicateDestinations': [{'category': c, 'workspaces': sorted(w)} for c, w in dest.items() if len(w) > 1]}
    diag_rows = _pmap(diag, candidates)
    lg_cov = {'found': len(ws_rows), 'curCostGE50': len(big), 'diagnosticSettingsChecked': len(diag_rows),
              'resourcesWithDuplicateDestinations': sum(bool(d.get('duplicateDestinations')) for d in diag_rows),
              'curCostUSD': round(sum(w['curCostUSD'] or 0 for w in ws_rows), 2)}
    write_json(ws.raw('cost/resources/logs.json'), {'snapshotAt': snapshot, 'period': {'start': ctx.start, 'end': ctx.end, 'days': ctx.days,
                                                                                       'sourceWindow': [ctx.tail_start, ctx.tail_end]},
                                                    'complete': True, 'coverage': lg_cov, 'top3ByBillableGB': [w['name'] for w in ranked],
                                                    'workspaces': ws_rows, 'diagnosticSettings': diag_rows, 'subscriptionScope': scope,
                                                    'limitations': ctx.limitations})
    log(f'数据库与缓存 {len(db_rows)} 个，存储账户 {len(st_rows)} 个，日志工作区 {len(ws_rows)} 个（其中 {len(big)} 个费用 ≥ 50 已查询摄取量）')
