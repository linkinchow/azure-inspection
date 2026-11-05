"""Read-only Azure Managed Lustre evidence shared by cost and WAF collectors."""
from __future__ import annotations

import math
import urllib.parse
from datetime import datetime, timedelta

ARM = 'https://management.azure.com'
RESOURCE_TYPE = 'Microsoft.StorageCache/amlFilesystems'
API_VERSION = '2024-07-01'
QUERY = ("resources | where type =~ 'microsoft.storagecache/amlfilesystems' "
         '| project id,name,type,location,resourceGroup,subscriptionId,tags,sku,zones,properties')
DEFAULT_POLICY = {'warningPct': 85, 'criticalPct': 95, 'sustainedHours': 3, 'minCoveragePct': 80,
                  'requireRootSquash': False, 'requireCmk': False}
METRICS = {
    **{f'{kind}{suffix}': ('Average', dimension)
       for kind, dimension in (('MDT', 'mdtnum'), ('OST', 'ostnum'))
       for suffix in ('BytesUsed', 'BytesTotal', 'FilesUsed', 'FilesTotal')},
    **{name: ('Average', 'ostnum') for name in ('ClientReadThroughput', 'ClientWriteThroughput',
                                              'ClientReadLatencyAvg', 'ClientWriteLatencyAvg')},
    'LustreClientEvictions': ('Total', ''),
    'HSMActionErrors': ('Total', 'mdtnum'),
    'AutoImporterErrors': ('Total', 'phase'),
    'ManualImporterErrors': ('Total', 'phase'),
}
OPTIONAL_METRICS = ('HSMActionErrors', 'AutoImporterErrors', 'ManualImporterErrors')


def policy(cfg=None):
    return {**DEFAULT_POLICY, **(getattr(cfg, 'managed_lustre', None) or {})}


def timestamp(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def resource_summary(resource, metrics=None):
    props, sku = resource.get('properties') or {}, resource.get('sku') or {}
    name = sku.get('name')
    parts = str(name or '').split('-')
    tier = sku.get('tier')
    tier_source = 'sku.tier' if tier else None
    if not tier and len(parts) >= 4 and parts[0] == 'AMLFS':
        tier, tier_source = '-'.join(parts[1:-1]), 'sku.name'
    result = {'resourceId': resource['id'], 'resourceName': resource['name'], 'resourceGroup': resource.get('resourceGroup'),
              'sku': name, 'tier': tier, 'tierSource': tier_source, 'capacityTiB': props.get('storageCapacityTiB'),
              'region': resource.get('location'), 'zones': resource.get('zones'), 'configurationError': resource.get('_readError')}
    for metric in ('ClientReadThroughput', 'ClientWriteThroughput', 'ClientReadLatencyAvg', 'ClientWriteLatencyAvg'):
        by_time = {}
        for entry in (metrics or {}).get(metric) or []:
            target = (entry.get('dims') or {}).get('ostnum')
            for point in entry.get('data') or []:
                value = point.get('average')
                if number(value) and value >= 0:
                    by_time.setdefault(point.get('timeStamp'), {})[target] = value
        values = [sum(targets.values()) if 'Throughput' in metric else max(targets.values()) for targets in by_time.values()]
        result[metric] = max(values) if values else None
    pressure = capacity_pressure(metrics or {})
    ost_bytes = [target for target in pressure if target['kind'] == 'OST' and target['unit'] == 'Bytes']
    expected_targets = {(entry.get('dims') or {}).get('ostnum') for name in ('OSTBytesUsed', 'OSTBytesTotal')
                        for entry in (metrics or {}).get(name) or []}
    same_time = (len({target['observedAt'] for target in ost_bytes}) == 1
                 and {target['target'] for target in ost_bytes} == expected_targets
                 and not any(name in ((metrics or {}).get('_errors') or {}) for name in ('OSTBytesUsed', 'OSTBytesTotal')))
    result['observedUsedTiB'] = sum(target['lastUsed'] for target in ost_bytes) / 2**40 if ost_bytes and same_time else None
    result['observedTotalTiB'] = sum(target['lastTotal'] for target in ost_bytes) / 2**40 if ost_bytes and same_time else None
    result['observedAt'] = ost_bytes[0]['observedAt'] if ost_bytes and same_time else None
    for unit, key in (('Bytes', 'worstBytesPct'), ('Files', 'worstFilesPct')):
        peaks = [target['peakPct'] for target in pressure if target['unit'] == unit]
        result[key] = max(peaks) if peaks else None
    return result


def capacity_pressure(metrics, settings=None):
    settings = {**DEFAULT_POLICY, **(settings or {})}
    results = []
    for kind, dimension in (('MDT', 'mdtnum'), ('OST', 'ostnum')):
        for unit in ('Bytes', 'Files'):
            totals = {}
            for series in metrics.get(f'{kind}{unit}Total') or []:
                target = (series.get('dims') or {}).get(dimension)
                if target is None:
                    continue
                for point in series.get('data') or []:
                    total = point.get('average')
                    if number(total) and total > 0:
                        totals[(target, point.get('timeStamp'))] = total
            ratios, capacities = {}, {}
            for series in metrics.get(f'{kind}{unit}Used') or []:
                target = (series.get('dims') or {}).get(dimension)
                for point in series.get('data') or []:
                    total = totals.get((target, point.get('timeStamp')))
                    used, when = point.get('average'), timestamp(point.get('timeStamp'))
                    if total is not None and number(used) and used >= 0 and when is not None:
                        ratios.setdefault(target, {})[when] = used / total * 100
                        capacities[(target, when)] = (used, total)
            for target, values in sorted(ratios.items()):
                warning_run = critical_run = longest = critical_longest = 0
                previous = None
                for when, percent in sorted(values.items()):
                    contiguous = previous is not None and when - previous == timedelta(hours=1)
                    warning_run = (warning_run if contiguous else 0) + 1 if percent >= settings['warningPct'] else 0
                    critical_run = (critical_run if contiguous else 0) + 1 if percent >= settings['criticalPct'] else 0
                    longest, critical_longest = max(longest, warning_run), max(critical_longest, critical_run)
                    previous = when
                latest = max(values)
                used, total = capacities[(target, latest)]
                results.append({'kind': kind, 'unit': unit, 'target': target, 'samples': len(values),
                                'peakPct': round(max(values.values()), 2), 'sustainedHours': longest,
                                'criticalHours': critical_longest, 'lastUsed': used, 'lastTotal': total,
                                'observedAt': latest.isoformat()})
    return results


def missing_targets(metrics, pressure):
    expected = {(kind, unit, (entry.get('dims') or {}).get(dimension))
                for kind, dimension in (('MDT', 'mdtnum'), ('OST', 'ostnum'))
                for unit in ('Bytes', 'Files') for role in ('Used', 'Total')
                for entry in metrics.get(f'{kind}{unit}{role}') or []}
    paired = {(item['kind'], item['unit'], item['target']) for item in pressure}
    return sorted(expected - paired, key=str)


def error_totals(metrics):
    totals = {}
    for name in ('LustreClientEvictions', 'HSMActionErrors', 'AutoImporterErrors', 'ManualImporterErrors'):
        points = {}
        for entry in metrics.get(name) or []:
            dims = tuple(sorted((entry.get('dims') or {}).items()))
            for point in entry.get('data') or []:
                value = point.get('total')
                if number(value) and value >= 0:
                    points[(dims, point.get('timeStamp'))] = value
        totals[name] = sum(points.values()) if points else None
    return totals


def collect_inventory(client, subscriptions, save, check):
    rows, status, error = client.arg(QUERY, [sub['id'] for sub in subscriptions], check, 'lustre')
    record = {'apiVersion': API_VERSION, 'query': QUERY, 'status': status, 'error': error, 'rows': [], 'errors': []}
    for row in rows or []:
        status_get, resource, error_get = client.get(f"{ARM}{row['id']}?api-version={API_VERSION}", check, row['name'])
        if status_get == 200 and isinstance(resource, dict):
            record['rows'].append({**row, **resource, 'subscriptionId': row['subscriptionId'],
                                   'resourceGroup': row.get('resourceGroup'), 'type': RESOURCE_TYPE})
        else:
            record['rows'].append({**row, '_readError': error_get or f'HTTP {status_get}'})
            record['errors'].append({'resourceId': row['id'], 'status': status_get, 'error': error_get})
    save('lustre/inventory.json', record)
    return record


def collect_metrics(client, resources, window, save, check='P7', names=None):
    record = {'window': window, 'resources': {}}
    requested_names = tuple(METRICS) if names is None else tuple(names)
    if not resources:
        save('lustre/metrics.json', record)
        return record
    start, end = timestamp(window['start']), timestamp(window['end'])
    for resource in resources:
        resource_id = resource['id']
        result = record['resources'].setdefault(resource_id.lower(), {'_errors': {}, '_unsupported': [],
                                               '_planned': list(requested_names), '_supported': [],
                                               '_coverage': {name: {'state': 'not_requested', 'requests': []} for name in requested_names}})
        url = f'{ARM}{resource_id}/providers/Microsoft.Insights/metricDefinitions?api-version=2018-01-01'
        status, response, error = client.get(url, check, resource['name'])
        if status != 200:
            result['_errors']['definitions'] = error or f'HTTP {status}'
            for item in result['_coverage'].values():
                item.update(state='request_error', error=result['_errors']['definitions'])
            continue
        definitions = {(item.get('name') or {}).get('value'): item for item in (response or {}).get('value') or []}
        groups = {}
        for name in requested_names:
            aggregation, dimension = METRICS[name]
            definition = definitions.get(name)
            if definition is None:
                result['_coverage'][name].update(state='unsupported', error='Metric definition unavailable')
                if name.startswith(('MDT', 'OST')):
                    result['_errors'][name] = 'Metric definition unavailable'
                else:
                    result['_unsupported'].append(name)
                continue
            supported = definition.get('supportedAggregationTypes') or [definition.get('primaryAggregationType')]
            if aggregation not in supported:
                result['_errors'][name] = f'Unsupported aggregation: {aggregation}'
                result['_coverage'][name].update(state='unsupported', error=result['_errors'][name])
                continue
            dimensions = [item['value'] for item in definition.get('dimensions') or []]
            if dimension and dimension not in dimensions:
                result['_errors'][name] = f'Missing target dimension: {dimension}'
                result['_coverage'][name].update(state='unsupported', error=result['_errors'][name])
                continue
            result['_supported'].append(name)
            result['_coverage'][name].update(aggregation=aggregation, dimensions=dimensions)
            groups.setdefault((aggregation, tuple(dimensions)), []).append(name)
        for (aggregation, dimensions), group_names in groups.items():
            chunk_start = start
            while chunk_start is not None and end is not None and chunk_start < end:
                chunk_end = min(chunk_start + timedelta(days=7), end)
                params = {'api-version': '2023-10-01', 'metricnamespace': RESOURCE_TYPE, 'metricnames': ','.join(group_names),
                          'timespan': f'{chunk_start.strftime("%Y-%m-%dT%H:%M:%SZ")}/{chunk_end.strftime("%Y-%m-%dT%H:%M:%SZ")}', 'interval': 'PT1H',
                          'aggregation': aggregation}
                if dimensions:
                    params.update({'$filter': ' and '.join(f"{dimension} eq '*'" for dimension in dimensions), 'top': '10000'})
                url = f'{ARM}{resource_id}/providers/Microsoft.Insights/metrics?' + urllib.parse.urlencode(params)
                status, response, error = client.get(url, check, resource['name'])
                returned = {(metric.get('name') or {}).get('value'): metric for metric in (response or {}).get('value') or []}
                for name in group_names:
                    metric = returned.get(name)
                    outcome = {'start': chunk_start.strftime('%Y-%m-%dT%H:%M:%SZ'),
                               'end': chunk_end.strftime('%Y-%m-%dT%H:%M:%SZ'), 'http': status, 'samples': 0}
                    result['_coverage'][name]['requests'].append(outcome)
                    if status != 200 or metric is None:
                        result['_errors'][name] = error or f'HTTP {status}: metric not returned'
                        outcome.update(state='request_error', error=result['_errors'][name])
                        continue
                    if metric.get('errorCode', 'Success').lower() != 'success':
                        result['_errors'][name] = metric.get('errorMessage') or metric['errorCode']
                        outcome.update(state='metric_error', errorCode=metric['errorCode'], error=result['_errors'][name])
                        continue
                    series = metric.get('timeseries') or []
                    if len(series) >= 10000:
                        result['_errors'][name] = 'Target limit reached; coverage incomplete'
                    for entry in series:
                        dims = {(item.get('name') or {}).get('value'): item.get('value')
                                for item in entry.get('metadatavalues') or []}
                        points = [point for point in entry.get('data') or []
                                  if (when := timestamp(point.get('timeStamp'))) is not None and chunk_start <= when < chunk_end]
                        result.setdefault(name, []).append({'dims': dims, 'data': points})
                        outcome['samples'] += sum(number(point.get(aggregation.lower())) for point in points)
                    outcome.update(series=len(series), state='partial' if len(series) >= 10000 else
                                   'complete' if outcome['samples'] else 'empty_samples')
                chunk_start = chunk_end
        for item in result['_coverage'].values():
            outcomes = item['requests']
            if not outcomes:
                continue
            states = {outcome['state'] for outcome in outcomes}
            item['state'] = next(iter(states)) if len(states) == 1 else 'partial'
            item['samples'] = sum(outcome['samples'] for outcome in outcomes)
        result['_definitions'] = definitions
    save('lustre/metrics.json', record)
    return record


def apply_coverage(coverage, inventory, metrics=None):
    if inventory is None:
        coverage['notes'].append('Azure Managed Lustre：没有采集记录，本月未检查。')
        coverage['otherErrors'] += 1
        return
    coverage['attempted'] += 1
    if inventory.get('status') == 200 and not inventory.get('errors'):
        coverage['succeeded'] += 1
    else:
        coverage['otherErrors'] += 1
    if metrics is not None:
        for resource in metrics.get('resources', {}).values():
            errors = resource.get('_errors') or {}
            required = [item for name, item in (resource.get('_coverage') or {}).items() if name not in OPTIONAL_METRICS]
            if any(name not in OPTIONAL_METRICS for name in errors) or any(item['state'] != 'complete' for item in required):
                coverage['otherErrors'] += 1
            if any(name in errors for name in OPTIONAL_METRICS):
                coverage['notes'].append('Lustre 可选归档或导入指标未完整取得，原始错误已保留；容量与 inode 覆盖单独评估。')
    coverage['notes'].append(f"Azure Managed Lustre：读取 {len(inventory.get('rows') or [])} 个文件系统；缺失配置和指标不按正常或零用量处理。")