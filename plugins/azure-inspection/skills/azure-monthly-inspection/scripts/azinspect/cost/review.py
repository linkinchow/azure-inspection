"""Review-month VM usage, current idle-resource candidates and RI/SP order visibility (read-only).

Uses the VM inventory collected by the VM stage (raw/vm/inventory). VMs that still exist are read for the
review month; VMs created after the month are excluded (null, never zero). Removed VMs cannot be reconstructed.
Idle-resource findings and order visibility describe the current state, not the review month.
Output: <workspace>/<month>/raw/cost/review/results.json
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from ..core.io import read_json, write_json
from ..vm.scalesets import drop_flexible_duplicates
from ..vm.collect import METRICS, _arm_metrics_as_batch, _Caller

DISK_FIELDS = dict(zip(METRICS[2:], ('uncachedIOPSAverage', 'uncachedBandwidthAverage', 'cachedIOPSAverage', 'cachedBandwidthAverage')))


def now():
    return datetime.now(timezone.utc).isoformat()


def stamp(value):
    try:
        d = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return d.astimezone(timezone.utc) if d.tzinfo else None
    except (ValueError, TypeError):
        return None


def aggregate(points, dates, start, end, error=None):
    daily = {d: {'date': d, 'average': None, 'count': None} for d in dates}
    invalid = []
    for point in points:
        t = stamp(point.get('timeStamp'))
        if not t or not start <= t < end:
            continue
        day = t.strftime('%Y-%m-%d')
        a, c = point.get('average'), point.get('count')
        if daily[day]['count'] is not None:
            invalid.append('Duplicate P1D bucket: ' + day)
            continue
        finite = lambda x: isinstance(x, (float, int)) and not isinstance(x, bool) and math.isfinite(x)
        if a is not None and (not finite(a) or not 0 <= a <= 100):
            invalid.append('Invalid percentage: ' + day)
            a = None
        if c is not None and (not finite(c) or c < 0):
            invalid.append('Invalid Count: ' + day)
            c = None
        daily[day].update(average=a, count=c)
    if invalid:
        error = '; '.join(invalid)
    valid = [p for p in daily.values() if p['average'] is not None and p['count'] is not None and p['count'] > 0]
    count = sum(p['count'] for p in valid)
    return {'average': sum(p['average'] * p['count'] for p in valid) / count if count and not error else None,
            'sampleCount': count if not error else 0, 'validDays': len(valid) if not error else 0, 'expectedDays': len(dates),
            'daily': list(daily.values()), 'error': error or (None if count else 'No valid Average/Count samples; missing is not zero')}


def _references(value):
    found = set()
    if isinstance(value, dict):
        for v in value.values():
            if isinstance(v, str) and v.lower().startswith('/subscriptions/'):
                found.add(v.lower())
            found.update(_references(v))
    elif isinstance(value, list):
        for v in value:
            found.update(_references(v))
    return found


def waste_review(resources, vms, subscriptions, snapshot):
    refs = set()
    for r in resources:
        refs.update(_references(r.get('properties') or {}))
    for v in vms:
        for k in ('osDisk', 'dataDisks', 'networkInterfaces'):
            refs.update(_references(v.get(k)))
    subnames = {s['id'].lower(): s['name'] for s in subscriptions}
    findings, classification = [], Counter()
    for r in resources:
        typ, p, rid = r['type'].lower(), r.get('properties') or {}, r['id'].lower()
        category = None
        if typ == 'microsoft.compute/disks':
            if p.get('diskState') == 'Unattached' and not r.get('managedBy') and not p.get('managedByExtended'):
                if rid in refs:
                    classification['unattachedDiskReferenced'] += 1
                else:
                    category = 'unattachedDiskCandidate'
        elif typ == 'microsoft.network/publicipaddresses':
            if not any(p.get(k) for k in ('ipConfiguration', 'natGateway', 'publicIPPrefix', 'linkedPublicIPAddress', 'servicePublicIPAddress')) \
                    and not r.get('managedBy') and rid not in refs:
                category = 'unassociatedPublicIPCandidate'
        elif typ == 'microsoft.network/networkinterfaces':
            if not p.get('virtualMachine') and not p.get('privateEndpoint') and not r.get('managedBy') and not p.get('hostedWorkloads') and rid not in refs:
                category = 'unassociatedNICCandidate'
        elif typ == 'microsoft.compute/snapshots':
            category = 'snapshotRetentionReview'
        if category:
            classification[category] += 1
            findings.append({'category': category, 'resourceId': r['id'], 'name': r['name'], 'subscriptionName': subnames.get(r['subscriptionId'].lower()),
                             'resourceGroup': r['resourceGroup'], 'region': r['location'], 'diskSizeGB': p.get('diskSizeGB'), 'createdAt': p.get('timeCreated'),
                             'inventorySnapshotAt': snapshot})
    return findings, {'inventorySnapshotAt': snapshot, 'classificationCounts': dict(classification), 'automaticDeletionPerformed': False}


def commitments(call):
    out = []
    for kind, url in [('reservationOrders', 'https://management.azure.com/providers/Microsoft.Capacity/reservationOrders?api-version=2022-11-01'),
                      ('savingsPlanOrders', 'https://management.azure.com/providers/Microsoft.BillingBenefits/savingsPlanOrders?api-version=2022-11-01')]:
        try:
            data = call.get(url)
            out.append({'kind': kind, 'status': 'visible-orders' if data.get('value') else 'no-visible-orders', 'visibleOrderCount': len(data.get('value', [])),
                        'completeList': not data.get('nextLink'), 'queriedAt': now()})
        except Exception as e:  # recorded, never treated as "no orders"
            out.append({'kind': kind, 'status': 'not-verified', 'error': str(e)[:300], 'queriedAt': now()})
    return out


def collect(ws, client, period, log=print):
    call = _Caller(client, 'cost-review')
    inv = ws.raw('vm/inventory')
    vms, resources, subscriptions = read_json(inv / 'vms.json'), read_json(inv / 'resources.json'), read_json(inv / 'subscriptions.json')
    vms = drop_flexible_duplicates(vms, resources)[0]   # Flexible scale set instances are already counted as VMs
    snapshot = read_json(inv / 'manifest.json')['collectedAt']
    sku_lookup = {(str(e['subscriptionId']).lower(), str(e['region']).lower(), str(s['name']).lower()): s
                  for e in read_json(ws.raw('vm/metrics/sku-capabilities.json')) for s in e.get('items', [])}
    start_s, end_s = f'{period.current.first.isoformat()}T00:00:00Z', f'{period.current.shift(1).first.isoformat()}T00:00:00Z'
    start, end = stamp(start_s), stamp(end_s)
    dates = [(period.current.first + timedelta(days=i)).isoformat() for i in range(period.current.days)]
    eligible = [v for v in vms if stamp(v.get('createdAt')) and stamp(v['createdAt']) < end]
    grouped = defaultdict(dict)
    for v in eligible:
        grouped[(v['subscriptionId'].lower(), v['region'], v['kind'])][v['metricResourceId'].lower()] = v['metricResourceId']
    jobs = []
    for (sub, region, kind), mapping in sorted(grouped.items()):
        ids = sorted(mapping.values(), key=str.lower)
        for offset in range(0, len(ids), 50):
            params = {'api-version': '2023-10-01', 'metricnamespace': 'Microsoft.Compute/virtualMachines' if kind == 'vm' else 'Microsoft.Compute/virtualMachineScaleSets',
                      'metricnames': ','.join(METRICS), 'starttime': start_s, 'endtime': end_s, 'interval': 'P1D', 'aggregation': 'Average,Count', 'top': '1000'}
            if kind == 'vmss':
                params['filter'] = "VMName eq '*'"
            jobs.append((sub, region, kind, ids[offset:offset + 50], f'https://{region}.metrics.monitor.azure.com/subscriptions/{sub}/metrics:getBatch?' + urlencode(params)))

    def batch(job):
        sub, region, kind, ids, url = job
        try:
            return job, {'status': 'ok', 'response': call.post(url, {'resourceids': ids})}
        except RuntimeError as e:
            if not str(e).startswith('HTTP 403'):
                return job, {'status': 'failed', 'error': str(e)}
            values = []
            for rid in ids:
                try:
                    values.append(_arm_metrics_as_batch(call, rid, kind, start_s, end_s))
                except Exception:
                    pass
            return job, {'status': 'ok', 'fallback': 'ARM per-resource metrics', 'response': {'values': values}}
    with ThreadPoolExecutor(max_workers=3) as pool:
        batches = list(pool.map(batch, jobs))
    byid, failures = {}, {}
    for job, rec in batches:
        if rec['status'] != 'ok':
            for rid in job[3]:
                failures[rid.lower()] = rec['error']
            continue
        for response in rec['response'].get('values', []):
            rid = response.get('resourceid', '').lower()
            if stamp(response.get('starttime')) != start or stamp(response.get('endtime')) != end or response.get('interval') != 'P1D':
                failures[rid] = 'Response period/interval differs from the exact month request'
                continue
            byid[rid] = response
    rows = []
    for v in vms:
        selected = stamp(v.get('createdAt')) is not None and stamp(v['createdAt']) < end
        rid = v['metricResourceId'].lower()
        response = byid.get(rid, {}) if selected else {}
        metrics = {}
        for name in METRICS:
            err = None if selected else 'Excluded: created after the review month'
            err = err or failures.get(rid)
            m = next((m for m in response.get('value', []) if m.get('name', {}).get('value', '').lower() == name.lower()), None)
            matched = []
            if not m:
                err = err or 'Metric not returned / unsupported'
            elif str(m.get('errorCode', 'Success')).lower() not in ('success', ''):
                err = err or f'{m.get("errorCode")}: {m.get("errorMessage", "")}'
            if m and not err:
                for ts in m.get('timeseries', []):
                    md = {a.get('name', {}).get('value', '').lower(): str(a.get('value', '')) for a in ts.get('metadatavalues', [])}
                    if v['kind'] == 'vm' or md.get('vmname', '').lower() == v['metricName'].lower():
                        matched.append(ts)
                if len(matched) != 1:
                    err = f'Expected one instance timeseries, returned {len(matched)}'
            metrics[name] = aggregate(matched[0].get('data', []) if len(matched) == 1 and not err else [], dates, start, end, err)
        cpu, avail = metrics[METRICS[0]]['average'], metrics[METRICS[1]]['average']
        caps = (sku_lookup.get((v['subscriptionId'].lower(), v['region'].lower(), str(v['size']).lower())) or {}).get('capabilities') or []
        caps = caps if isinstance(caps, dict) else {c['name']: c['value'] for c in caps}
        rows.append({'resourceId': v['id'], 'subscriptionName': v['subscriptionName'], 'resourceGroup': v['resourceGroup'],
                     'name': v.get('metricName') or v['name'], 'kind': v['kind'], 'region': v['region'], 'currentSKU': v['size'], 'currentState': v['state'],
                     'eligibleForMonth': selected, 'cpuAverage': cpu, 'memoryAverage': 100 - avail if avail is not None else None,
                     'validDays': min(metrics[METRICS[0]]['validDays'], metrics[METRICS[1]]['validDays']),
                     'sixMetricValidDays': min(m['validDays'] for m in metrics.values()), 'metrics': metrics,
                     'currentCores': caps.get('vCPUsAvailable') or caps.get('vCPUs'), 'currentMemoryGiB': caps.get('MemoryGB'),
                     **{field: metrics[name]['average'] for name, field in DISK_FIELDS.items()}})
    days = period.current.days
    er = [r for r in rows if r['eligibleForMonth']]
    low = lambda field, metric: sum(r['metrics'][metric]['validDays'] == days and r[field] is not None and r[field] < 20 for r in er)
    coverage = {'currentInventoryInstances': len(rows), 'eligibleMonthInstances': len(er), 'excludedCreatedAfterMonth': len(rows) - len(er),
                'completeMonthCPUMemoryInstances': sum(r['validDays'] == days for r in er), 'partialCPUMemoryInstances': sum(0 < r['validDays'] < days for r in er),
                'missingBothInstances': sum(r['cpuAverage'] is None and r['memoryAverage'] is None for r in er),
                'batchJobs': len(jobs), 'batchFailedJobs': sum(rec['status'] != 'ok' for _, rec in batches)}
    summary = {'lowCPUFullMonthCount': low('cpuAverage', METRICS[0]), 'lowMemoryUsedFullMonthCount': low('memoryAverage', METRICS[1]),
               'highMemoryUsedAverage80Count': sum(r['memoryAverage'] is not None and r['memoryAverage'] >= 80 for r in er)}
    findings, waste_summary = waste_review(resources, vms, subscriptions, snapshot)
    result = {'collectedAt': now(), 'period': {'start': start_s, 'endExclusive': end_s, 'days': days}, 'inventorySnapshotAt': snapshot,
              'vmMetrics': rows, 'summary': summary, 'coverage': coverage, 'wasteFindings': findings, 'wasteSummary': waste_summary,
              'commitmentStatus': commitments(call)}
    write_json(ws.raw('cost/review/results.json'), result)
    log(f'本月虚拟机用量：{len(er)} 台在月内已存在，其中 {coverage["completeMonthCPUMemoryInstances"]} 台有完整 {days} 天数据；'
        f'闲置资源候选 {sum(f["category"] != "snapshotRetentionReview" for f in findings)} 个，快照 {waste_summary["classificationCounts"].get("snapshotRetentionReview", 0)} 个')
    return result
