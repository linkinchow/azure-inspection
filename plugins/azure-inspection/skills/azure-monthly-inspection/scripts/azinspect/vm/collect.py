"""VM inventory, 7-day Average/Count metrics and SKU capabilities (read-only).

Output (under <workspace>/<month>/raw/vm/):
  inventory/  subscriptions.json, resources.json, vmss-instances.json, vms.json, aks-pools.json, subscription-containers.json
  metrics/    batch-*.json, vms-average.json, skus-*.json, sku-capabilities.json, manifest.json,
              collection-errors.json, metric-processing-errors.json, vmss-instance-coverage.json
The file formats match earlier inspections so earlier raw data can be replayed.

Current configuration is a fresh snapshot, not the configuration during the metric window.
Missing metrics stay null and are never treated as 0. A Batch API 403 falls back to the
per-resource ARM metrics API for the same window (same read-only account).
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlencode

from ..core.io import read_json

METRICS = ['Percentage CPU', 'Available Memory Percentage',
           'VM Uncached IOPS Consumed Percentage', 'VM Uncached Bandwidth Consumed Percentage',
           'VM Cached IOPS Consumed Percentage', 'VM Cached Bandwidth Consumed Percentage']
VM = 'microsoft.compute/virtualmachines'
CHILD = 'microsoft.compute/virtualmachinescalesets/virtualmachines'
VMSS = 'microsoft.compute/virtualmachinescalesets'
AKS = 'microsoft.containerservice/managedclusters'
TYPES = [VM, VMSS, AKS, 'microsoft.network/networkinterfaces', 'microsoft.compute/disks',
         'microsoft.compute/snapshots', 'microsoft.network/publicipaddresses']
ARM = 'https://management.azure.com'
WINDOW_DAYS = 7


def now():
    return datetime.now(timezone.utc).isoformat()


def state_of(properties):
    for view in (properties.get('extended', {}).get('instanceView', {}), properties.get('instanceView', {})):
        power = view.get('powerState', {})
        if isinstance(power, dict) and str(power.get('code', '')).lower().startswith('powerstate/'):
            return power['code']
        for status in view.get('statuses', []):
            if str(status.get('code', '')).lower().startswith('powerstate/'):
                return status['code']
    return 'Unknown'


def series(size):
    match = re.fullmatch(r'standard_([a-z]+)\d+([a-z]*)(?:_v(\d+))?', (size or '').lower())
    return tuple(match.groups()) if match else None


def weighted(points, start, end, error=None):
    """Daily Average weighted by Count over [start, end). Points outside the window are ignored."""
    daily, valid = [], []
    for p in points:
        stamp, average, count = p.get('timeStamp'), p.get('average'), p.get('count')
        if stamp and not start <= stamp < end:
            continue
        daily.append({'timeStamp': stamp, 'average': average, 'count': count})
        if (isinstance(average, (int, float)) and math.isfinite(average)
                and isinstance(count, (int, float)) and math.isfinite(count) and count > 0):
            valid.append((average, count, stamp))
    count = sum(p[1] for p in valid)
    result = {'average': sum(a * c for a, c, _ in valid) / count if count else None,
              'sampleCount': count, 'validDays': len({p[2] for p in valid}), 'daily': daily}
    if error:
        result['error'] = error
    elif not count:
        result['error'] = 'No valid Average/Count samples in observation window'
    return result


class _Caller:
    """Adapts the read-only client to 'return data or raise', which the collection flow relies on."""

    def __init__(self, client, check='vm'):
        self.client, self.check = client, check

    def get(self, url):
        status, data, error = self.client.request('GET', url, self.check)
        if status != 200:
            raise RuntimeError(f'HTTP {status}: {error}')
        return data

    def post(self, url, body):
        status, data, error = self.client.request('POST', url, self.check, body=body)
        if status != 200:
            raise RuntimeError(f'HTTP {status}: {error}')
        return data

    def arg(self, query, subscriptions):
        rows, status, error = self.client.arg(query, subscriptions, self.check)
        if status != 200 or rows is None:
            raise RuntimeError(f'HTTP {status}: {error}')
        return rows


def subscriptions_in_scope(client, cfg):
    """All subscriptions of the tenant visible to the read-only account; disabled ones stay listed as unverified."""
    items, status, error = client.get_all('/subscriptions?api-version=2022-12-01', 'vm', 'subscriptions')
    if items is None:
        raise RuntimeError(f'无法列出订阅（{status} {error}）')
    out = []
    for s in items:
        if str(s.get('tenantId', cfg.tenant_id)).lower() != cfg.tenant_id:
            continue
        if not cfg.in_scope(s['subscriptionId'], s.get('displayName') or ''):
            continue
        out.append({'id': s['subscriptionId'], 'name': s.get('displayName'), 'state': s.get('state'), 'tenantId': s.get('tenantId', cfg.tenant_id)})
    return out


def _arm_metrics_as_batch(call, resource_id, kind, start, end):
    """Per-resource ARM metrics, reshaped like one Batch API 'values' entry."""
    params = {'api-version': '2023-10-01', 'metricnames': ','.join(METRICS), 'timespan': f'{start}/{end}',
              'interval': 'P1D', 'aggregation': 'Average,Count'}
    if kind == 'vmss':
        params['$filter'] = "VMName eq '*'"
    data = call.get(f'{ARM}{resource_id}/providers/Microsoft.Insights/metrics?' + urlencode(params))
    return {'resourceid': resource_id, 'starttime': start, 'endtime': end, 'interval': 'P1D', 'value': data.get('value', []),
            'source': 'ARM per-resource metrics API (Batch API returned HTTP403)'}


def collect(ws, cfg, client, period, log=print):
    raw_dir, avg_dir = 'vm/inventory', 'vm/metrics'
    save = lambda folder, name, data: ws.save_raw(f'{folder}/{name}', data)
    call = _Caller(client)
    start, end = period.metric_window(WINDOW_DAYS)
    subscriptions = subscriptions_in_scope(client, cfg)
    enabled = [s for s in subscriptions if s['state'] == 'Enabled']
    ids = [s['id'] for s in enabled]
    subnames = {s['id'].lower(): s['name'] for s in subscriptions}
    errors, snapshot_at = [], now()
    scope_status = {s['id'].lower(): ({'inventoryStatus': 'ok', 'inventoryErrors': []} if s['state'] == 'Enabled' else
                                      {'inventoryStatus': 'unverified', 'inventoryErrors': [{'phase': 'subscriptionState', 'error': f'订阅状态为 {s["state"]}，无法读取资源'}]})
                    for s in subscriptions}
    log(f'订阅：纳入 {len(enabled)} 个，未启用 {len(subscriptions) - len(enabled)} 个；指标窗口 {start} 至 {end}')
    try:
        regions = {x['name'].lower() for x in call.get(f'{ARM}/subscriptions/{cfg.token_subscription}/locations?api-version=2022-12-01')['value']}
    except Exception as e:
        regions = set()
        errors.append({'phase': 'regions', 'error': str(e)})
    projection = ' | project id,name,type,location,subscriptionId,resourceGroup,sku,kind,managedBy,tags,properties,zones,plan | order by id asc'
    query = 'Resources | where type in~ (' + ','.join(repr(t) for t in TYPES) + ')' + projection

    def collect_query(q, label):
        try:
            return call.arg(q, ids)
        except Exception as error:
            log(f'资源查询 {label} 整体失败，改为逐个订阅：{str(error)[:200]}')
            rows = []

            def one(sub):
                try:
                    return sub, call.arg(q, [sub['id']]), None
                except Exception as e:
                    return sub, [], str(e)
            with ThreadPoolExecutor(max_workers=3) as pool:
                for sub, data, failure in pool.map(one, enabled):
                    rows.extend(data)
                    if failure:
                        scope_status[sub['id'].lower()]['inventoryStatus'] = 'failed'
                        scope_status[sub['id'].lower()]['inventoryErrors'].append({'query': label, 'error': failure})
                        errors.append({'phase': 'inventory', 'subscriptionId': sub['id'], 'query': label, 'error': failure})
            return rows

    resources = collect_query(query, 'resources')
    instances = collect_query("ComputeResources | where type =~ '" + CHILD + "'" + projection, 'vmss-instances')
    try:
        containers = call.arg("ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId,name,properties | order by subscriptionId asc", ids)
        visible = {x['subscriptionId'].lower() for x in containers}
        for sub in enabled:
            if sub['id'].lower() not in visible:
                scope_status[sub['id'].lower()]['inventoryStatus'] = 'unverified'
                error = {'phase': 'subscriptionVisibility', 'subscriptionId': sub['id'], 'error': 'Resource Graph 中看不到该订阅；没有读到虚拟机不代表没有虚拟机'}
                errors.append(error)
                scope_status[sub['id'].lower()]['inventoryErrors'].append(error)
        save(raw_dir, 'subscription-containers.json', containers)
    except Exception as e:
        errors.append({'phase': 'subscriptionVisibility', 'error': str(e)})
        for entry in scope_status.values():
            if entry['inventoryStatus'] == 'ok':
                entry['inventoryStatus'] = 'unverified'
    resources = list({r['id'].lower(): r for r in resources}.values())
    instances = list({r['id'].lower(): r for r in instances}.values())
    lookup = {r['id'].lower(): r for r in resources + instances}
    save(raw_dir, 'resources.json', resources)
    save(raw_dir, 'vmss-instances.json', instances)
    vms = []
    for r in sorted(resources + instances, key=lambda r: r['id'].lower()):
        typ = r['type'].lower()
        if typ not in (VM, CHILD):
            continue
        p = r.get('properties') or {}
        child = typ == CHILD
        parent_id = re.split(r'/virtualmachines/', r['id'], flags=re.I)[0] if child else r['id']
        parent = lookup.get(parent_id.lower(), {})
        parent_props = parent.get('properties') or {}
        instance_id = r['id'].split('/')[-1] if child else None
        size = p.get('hardwareProfile', {}).get('vmSize') or (r.get('sku') or {}).get('name') or (parent.get('sku') or {}).get('name')
        state = state_of(p)
        storage = p.get('storageProfile') or {}
        refs = p.get('networkProfile', {}).get('networkInterfaces') or []
        nics = []
        template = p.get('networkProfileConfiguration') or parent_props.get('virtualMachineProfile', {}).get('networkProfile') or {}
        for ref in refs:
            nic = lookup.get(ref.get('id', '').lower())
            props = (nic or {}).get('properties') or {}
            nics.append({'id': ref.get('id'), 'acceleratedNetworking': props.get('enableAcceleratedNetworking'),
                         'source': 'ResourceGraphNIC' if nic else 'VMSS template only / NIC not in ARG',
                         'properties': props if nic else {}, 'template': template if not nic else {}})
        v = {'id': r['id'], 'name': r['name'], 'metricName': parent_id.split('/')[-1] + '_' + instance_id if child else r['name'],
             'instanceId': instance_id, 'metricResourceId': parent_id, 'kind': 'vmss' if child else 'vm',
             'subscriptionId': r['subscriptionId'], 'subscriptionName': subnames.get(r['subscriptionId'].lower()),
             'resourceGroup': r['resourceGroup'], 'region': r['location'].lower(), 'size': size, 'state': state,
             'createdAt': p.get('timeCreated'), 'osDisk': storage.get('osDisk') or {}, 'dataDisks': storage.get('dataDisks') or [],
             'networkInterfaces': refs, 'securityProfile': p.get('securityProfile') or {}, 'licenseType': p.get('licenseType'),
             'priority': p.get('priority', 'Regular'), 'plan': r.get('plan'), 'tags': r.get('tags') or {},
             'additionalCapabilities': p.get('additionalCapabilities') or {}, 'zones': r.get('zones') or parent.get('zones') or [],
             'liveFound': True, 'liveSKU': size, 'liveState': state, 'configurationChanged': False,
             'configurationSnapshotAt': snapshot_at,
             'configurationWindowLimitation': f'Current SKU/configuration at snapshot; not verified historically for {start} to {end}',
             'nicConfiguration': nics, 'osType': (storage.get('osDisk') or {}).get('osType'),
             'attachedDiskConfiguration': [lookup[d['managedDisk']['id'].lower()] for d in [storage.get('osDisk') or {}] + (storage.get('dataDisks') or [])
                                           if d.get('managedDisk', {}).get('id', '').lower() in lookup]}
        if state == 'Unknown':
            errors.append({'phase': 'instanceState', 'vmId': r['id'], 'error': '没有读到电源状态；“未知”不按已释放处理'})
        vms.append(v)
    save(raw_dir, 'vms.json', vms)
    log(f'资源清单：{len(resources)} 个配置资源，{len(vms)} 台机器（独立 VM {sum(v["kind"] == "vm" for v in vms)}，VMSS 实例 {sum(v["kind"] == "vmss" for v in vms)}）')

    pools = []
    for r in resources:
        if r['type'].lower() != AKS:
            continue
        p = r.get('properties') or {}
        error, source = None, 'ResourceGraph.agentPoolProfiles'
        if not p.get('agentPoolProfiles') or any('count' not in pool for pool in p['agentPoolProfiles']):
            try:
                p = call.get(f'{ARM}{r["id"]}?api-version=2025-10-01').get('properties') or {}
                source = 'ManagedCluster GET'
            except Exception as e:
                error = str(e)
                errors.append({'phase': 'aksMetadata', 'clusterId': r['id'], 'error': error})
        pools.append({'id': r['id'], 'name': r['name'], 'subscriptionId': r['subscriptionId'], 'region': r['location'],
                      'nodeResourceGroup': p.get('nodeResourceGroup'), 'pools': p.get('agentPoolProfiles') or [],
                      'tier': r.get('sku'), 'monitor': p.get('azureMonitorProfile'), 'source': source,
                      'queriedAt': snapshot_at, 'error': error})
    save(raw_dir, 'aks-pools.json', pools)

    groups = defaultdict(dict)
    for v in vms:
        groups[(v['subscriptionId'].lower(), v['region'], v['kind'])][v['metricResourceId'].lower()] = v['metricResourceId']
    jobs = []
    for (sub, region, kind), mapping in sorted(groups.items()):
        resource_ids = sorted(mapping.values(), key=str.lower)
        for offset in range(0, len(resource_ids), 50):
            params = {'api-version': '2023-10-01', 'metricnamespace': 'Microsoft.Compute/virtualMachines' if kind == 'vm' else 'Microsoft.Compute/virtualMachineScaleSets',
                      'metricnames': ','.join(METRICS), 'starttime': start, 'endtime': end,
                      'interval': 'P1D', 'aggregation': 'Average,Count', 'top': '1000'}
            if kind == 'vmss':
                params['filter'] = "VMName eq '*'"
            url = f'https://{region}.metrics.monitor.azure.com/subscriptions/{sub}/metrics:getBatch?' + urlencode(params)
            jobs.append((sub, region, kind, resource_ids[offset:offset + 50], url, offset // 50))

    def batch(job):
        sub, region, kind, resource_ids, url, index = job
        filename = f'batch-{sub}-{region}-{kind}-{index:03d}.json'
        cached = ws.raw(f'{avg_dir}/{filename}')
        if cached.exists():
            old = read_json(cached)
            if not old.get('error') and old.get('url') == url and {x.lower() for x in old.get('body', {}).get('resourceids', [])} == {x.lower() for x in resource_ids}:
                return job, {**old, 'cacheSource': 'same-run cache'}
        try:
            if regions and region not in regions:
                raise RuntimeError(f'区域 {region!r} 不在 Azure 官方区域列表中，未调用指标接口')
            if not re.fullmatch(r'[a-z][a-z0-9]{1,40}', region):
                raise RuntimeError('Invalid Azure region name')
            try:
                response = call.post(url, {'resourceids': resource_ids})
                stored = {'url': url, 'body': {'resourceids': resource_ids}, 'queriedAt': now(), 'response': response}
            except RuntimeError as e:
                if not str(e).startswith('HTTP 403'):
                    raise
                values = []
                for rid in resource_ids:
                    try:
                        values.append(_arm_metrics_as_batch(call, rid, kind, start, end))
                    except Exception as inner:
                        errors.append({'phase': 'armMetricsFallback', 'resourceId': rid, 'error': str(inner)})
                stored = {'url': url, 'body': {'resourceids': resource_ids}, 'queriedAt': now(), 'batchError': str(e)[:500],
                          'fallback': 'ARM per-resource metrics API', 'response': {'values': values}}
                log(f'批量指标接口 403：{subnames.get(sub)} {region}，已改为逐台读取 {len(values)}/{len(resource_ids)} 台')
            save(avg_dir, filename, stored)
            return job, stored
        except Exception as e:
            stored = {'url': url, 'body': {'resourceids': resource_ids}, 'queriedAt': now(), 'error': str(e)}
            save(avg_dir, filename, stored)
            log(f'指标读取失败：{subnames.get(sub)} {region} {kind}：{str(e)[:200]}')
            return job, stored

    with ThreadPoolExecutor(max_workers=3) as pool:
        batches = list(pool.map(batch, jobs))
    byid, batch_errors, sources = {}, {}, {}
    for job, stored in batches:
        if stored.get('error'):
            errors.append({'phase': 'batch', 'subscriptionId': job[0], 'region': job[1], 'kind': job[2], 'resourceIds': job[3], 'error': stored['error']})
            for rid in job[3]:
                batch_errors[rid.lower()] = stored['error']
            continue
        wanted = {x.lower() for x in job[3]}
        for r in stored['response'].get('values', []):
            rid = r.get('resourceid', '').lower()
            if rid not in wanted:
                errors.append({'phase': 'batchResponse', 'error': 'Unexpected resource returned', 'resourceId': rid})
                continue
            if r.get('interval') != 'P1D' or r.get('starttime') != start or r.get('endtime') != end:
                batch_errors[rid] = 'Batch response window/interval differs from exact requested window'
                continue
            byid[rid] = r
            if r.get('source'):
                sources[rid] = r['source']
        for rid in wanted - set(byid):
            batch_errors.setdefault(rid, stored.get('batchError') or 'Resource not returned by Batch API')
    processing_errors, instance_coverage = [], []
    for v in vms:
        rid = v['metricResourceId'].lower()
        result = byid.get(rid) or {}
        returned = {m.get('name', {}).get('value', '').lower(): m for m in result.get('value', [])}
        metrics = {}
        for name in METRICS:
            m = returned.get(name.lower())
            error = batch_errors.get(rid)
            if not m:
                error = error or 'Metric not returned / unsupported by API'
            elif m.get('errorCode', 'Success').lower() not in ('success', ''):
                error = f'{m.get("errorCode")}: {m.get("errorMessage", "")}'
            matches = []
            if m and not error:
                for s in m.get('timeseries', []):
                    metadata = {a['name']['value'].lower(): str(a['value']) for a in s.get('metadatavalues', [])}
                    if v['kind'] == 'vm' or metadata.get('vmname', '').lower() == v['metricName'].lower():
                        matches.append(s)
                if len(matches) != 1:
                    error = f'Expected exactly one instance series; returned {len(matches)} matching series'
            metrics[name] = weighted(matches[0].get('data', []) if len(matches) == 1 and not error else [], start, end, error)
            if metrics[name].get('error'):
                processing_errors.append({'vmId': v['id'], 'subscriptionId': v['subscriptionId'], 'metric': name, 'error': metrics[name]['error']})
        v['metrics'] = metrics
        if rid in sources:
            v['metricsSource'] = sources[rid]
        v['cpuAverage'] = metrics['Percentage CPU']['average']
        available = metrics['Available Memory Percentage']['average']
        v['memoryAverage'] = 100 - available if available is not None else None
        v['metricsCoverageStatus'] = 'complete' if all(m['validDays'] == WINDOW_DAYS for m in metrics.values()) else 'partial-or-missing'
    for rid, parent in ((r['id'].lower(), r) for r in resources if r['type'].lower() == VMSS):
        actual = {v['metricName'].lower() for v in vms if v['kind'] == 'vmss' and v['metricResourceId'].lower() == rid}
        if not actual:
            continue
        result = byid.get(rid) or {}
        per_metric = {}
        for name in METRICS:
            m = next((m for m in result.get('value', []) if m.get('name', {}).get('value', '').lower() == name.lower()), {})
            names = {str(a.get('value', '')).lower() for s in m.get('timeseries', []) for a in s.get('metadatavalues', []) if a.get('name', {}).get('value', '').lower() == 'vmname'}
            per_metric[name] = {'returnedInstanceCount': len(names), 'actualInstanceCount': len(actual),
                                'missingCurrentInstances': sorted(actual - names), 'historicalInstancesNotInFreshInventory': sorted(names - actual),
                                'top1000PotentialTruncation': len(names) >= 1000}
        instance_coverage.append({'metricResourceId': parent['id'], 'subscriptionId': parent['subscriptionId'], 'actualInstanceCount': len(actual),
                                  'parentCapacity': (parent.get('sku') or {}).get('capacity'), 'perMetric': per_metric})
    save(avg_dir, 'vmss-instance-coverage.json', instance_coverage)
    save(avg_dir, 'metric-processing-errors.json', processing_errors)
    save(avg_dir, 'vms-average.json', vms)

    needed = defaultdict(set)
    for v in vms:
        needed[(v['subscriptionId'].lower(), v['region'])].add(v['size'])

    def fetch_skus(key):
        sub, region = key
        sizes = needed[key]
        families = {series(s) for s in sizes} - {None}
        conversions = {('e' if f[0] == 'd' else 'd', f[1], f[2]) for f in families if f[0] in ('d', 'e')}
        want = families | conversions
        url = f'{ARM}/subscriptions/{sub}/providers/Microsoft.Compute/skus?' + urlencode({'api-version': '2021-07-01', '$filter': "location eq '" + region + "'"})
        items = []
        try:
            next_url = url
            while next_url:
                result = call.get(next_url)
                items.extend(i for i in result.get('value', []) if i.get('resourceType') == 'virtualMachines'
                             and (series(i.get('name')) in want or i.get('name', '').lower() in {str(s).lower() for s in sizes}))
                next_url = result.get('nextLink')
            missing = sorted(str(s) for s in sizes if str(s).lower() not in {i['name'].lower() for i in items})
            record = {'subscriptionId': sub, 'region': region, 'queriedAt': now(), 'url': url, 'currentSizes': sorted(sizes, key=lambda x: x or ''),
                      'items': items, 'ok': True, 'restrictionsScope': 'subscription-specific', 'missingCurrentSKUs': missing}
        except Exception as e:
            record = {'subscriptionId': sub, 'region': region, 'queriedAt': now(), 'url': url, 'items': [], 'ok': False,
                      'currentSizes': sorted(sizes, key=lambda x: x or ''), 'error': str(e), 'restrictionsScope': 'UNVERIFIED'}
        save(avg_dir, f'skus-{sub}-{region}.json', record)
        return record

    with ThreadPoolExecutor(max_workers=3) as pool:
        sku_records = list(pool.map(fetch_skus, sorted(needed)))
    save(avg_dir, 'sku-capabilities.json', sku_records)
    for record in sku_records:
        if not record['ok'] or record.get('missingCurrentSKUs'):
            errors.append({'phase': 'skuCapabilities', 'subscriptionId': record['subscriptionId'], 'region': record['region'],
                           'error': record.get('error') or f'Current SKUs absent: {record["missingCurrentSKUs"]}'})
    for sub in subscriptions:
        sid = sub['id'].lower()
        subset = [v for v in vms if v['subscriptionId'].lower() == sid]
        sub.update(scope_status[sid])
        sub.update({'inventoryQueriedAt': snapshot_at, 'vmCount': len(subset), 'standaloneVMCount': sum(v['kind'] == 'vm' for v in subset),
                    'vmssInstanceCount': sum(v['kind'] == 'vmss' for v in subset), 'resourceCount': sum(r['subscriptionId'].lower() == sid for r in resources),
                    'hasVM': bool(subset), 'states': dict(Counter(v['state'] for v in subset)),
                    'metricMissingVMCount': sum(v['cpuAverage'] is None for v in subset),
                    'metricPartialVMCount': sum(v['metricsCoverageStatus'] != 'complete' for v in subset),
                    'skuScopeFailures': [r['region'] for r in sku_records if r['subscriptionId'] == sid and not r['ok']]})
    save(raw_dir, 'subscriptions.json', subscriptions)
    save(raw_dir, 'manifest.json', {'collectedAt': snapshot_at, 'tenantId': cfg.tenant_id, 'subscriptions': len(subscriptions),
                                    'resourceCount': len(resources), 'instanceCount': len(vms), 'start': start, 'end': end, 'interval': 'P1D'})
    manifest = {'customer': cfg.name, 'start': start, 'end': end, 'interval': 'P1D', 'aggregation': 'Average,Count',
                'queriedAt': now(), 'inventorySnapshotAt': snapshot_at, 'metricResourceCount': sum(len(x) for x in groups.values()),
                'metricResourceReturnedCount': len(byid), 'instanceCount': len(vms), 'batchRequests': len(jobs),
                'armFallbackResourceCount': len(sources), 'tenantId': cfg.tenant_id,
                'subscriptionCount': len(subscriptions), 'subscriptionCountWithVM': sum(s['hasVM'] for s in subscriptions),
                'subscriptionCountUnverified': sum(s['inventoryStatus'] != 'ok' for s in subscriptions),
                'metricNames': METRICS, 'singleDiskMetricsCollected': False, 'highPercentileOrMaxCollected': False,
                'coverage': {'cpuMissingInstances': sum(v['cpuAverage'] is None for v in vms), 'memoryMissingInstances': sum(v['memoryAverage'] is None for v in vms),
                             'completeSixMetricInstances': sum(v['metricsCoverageStatus'] == 'complete' for v in vms),
                             'processingErrorCount': len(processing_errors), 'skuScopeCount': len(sku_records),
                             'skuScopeFailureCount': sum(not r['ok'] for r in sku_records)},
                'errors': errors,
                'currentConfigurationLimitation': '规格和电源状态是采集时的当前配置，不是观察窗口内的历史配置；状态未知不按已释放处理；缺少的指标为空，不按 0 处理。'}
    save(avg_dir, 'collection-errors.json', errors)
    save(avg_dir, 'manifest.json', manifest)
    log(f'采集完成：{len(vms)} 台机器，{manifest["metricResourceReturnedCount"]}/{manifest["metricResourceCount"]} 个指标资源返回数据，'
        f'逐台补读 {len(sources)} 个；CPU 缺失 {manifest["coverage"]["cpuMissingInstances"]} 台')
    return manifest
