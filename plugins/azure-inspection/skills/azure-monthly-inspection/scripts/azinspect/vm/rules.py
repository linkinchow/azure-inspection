"""VM rightsizing rules (average-based). Ported unchanged from earlier inspections; only constants moved here.

Deployment SKU lookup is always subscription + region + size. Only established D/E same-generation
rules are enabled; other families keep their actual capabilities, metrics and prices with an explicit
reason rather than invented downsizing rules. Missing data is never filled with 0.
"""
from __future__ import annotations

import copy
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .prices import os_price_basis, quote_for

IO = (
    ('VM Uncached IOPS Consumed Percentage', 'UncachedDiskIOPS', 'Uncached IOPS'),
    ('VM Uncached Bandwidth Consumed Percentage', 'UncachedDiskBytesPerSecond', 'Uncached MB/s'),
    ('VM Cached IOPS Consumed Percentage', 'CombinedTempDiskAndCachedIOPS', 'Cached IOPS'),
    ('VM Cached Bandwidth Consumed Percentage', 'CombinedTempDiskAndCachedReadBytesPerSecond', 'Cached MB/s'),
)
METRICS = ('Percentage CPU', 'Available Memory Percentage', *(m for m, _, _ in IO))
POLICY = {
    'reducedDimensionAverageBelowPercent': 20, 'targetVMDiskAverageMaxPercent': 50,
    'minimumSampleCoverage': .95, 'validDailyBucketsRequired': 7,
    'capacityStep': '每项容量保持或减半；CPU/内存独立判断；同代保留a/d/s功能，仅允许E/D/低内存比切换',
    'aggregation': 'Average,Count / P1D', 'useMaxOrPercentiles': False,
    'singleDiskMetrics': False, 'hoursPerMonth': 730,
    'skuLookupKey': ['subscriptionId', 'region', 'size'],
    'unsupportedFamilies': '本轮未对该系列制定降档规则',
}
RUNNING = 'powerstate/running'
DEALLOCATED = 'powerstate/deallocated'
RECOMMEND = '建议试点调整'


def now():
    return datetime.now(timezone.utc).isoformat()


def caps(sku):
    values = (sku or {}).get('capabilities', [])
    return values if isinstance(values, dict) else {x['name']: x['value'] for x in values}


def number(c, key, default=None):
    try:
        value = float(c[key])
        return value if math.isfinite(value) else default
    except (KeyError, ValueError, TypeError):
        return default


def shape(name):
    m = re.fullmatch(r'standard_([de])(\d+)([a-z]*)_v(\d+)', str(name).lower())
    return (m[1], int(m[2]), m[3].replace('l', ''), m[4]) if m else None


def arm_subscription(resource_id):
    match = re.match(r'/subscriptions/([^/]+)(?:/|$)', str(resource_id), re.I)
    return match[1].lower() if match else None


def sku_key(vm, name=None):
    return (str(vm.get('subscriptionId', '')).lower(), str(vm.get('region', '')).lower(), str(name or vm.get('size', '')).lower())


def sku_lookup(envelopes):
    lookup = {}
    for envelope in envelopes:
        subscription = str(envelope.get('subscriptionId', '')).lower()
        region = str(envelope.get('region', '')).lower()
        if not subscription or not region:
            raise ValueError('Every SKU capability envelope must specify subscriptionId and region')
        for sku in envelope.get('items', []):
            key = (subscription, region, sku['name'].lower())
            if key in lookup and lookup[key] != sku:
                raise ValueError(f'Conflicting SKU metadata for scoped key {key!r}')
            lookup[key] = sku
    return lookup


def sizes_for(vm, skus):
    old = skus.get(sku_key(vm))
    source_shape = shape(vm.get('size'))
    if not old or not source_shape:
        return []
    current = caps(old)
    cores = number(current, 'vCPUsAvailable', number(current, 'vCPUs'))
    memory = number(current, 'MemoryGB')
    out = []
    for (subscription, region, name), sku in skus.items():
        target_shape = shape(sku['name'])
        if (subscription, region) != sku_key(vm)[:2] or not target_shape or target_shape[2:] != source_shape[2:]:
            continue
        target = caps(sku)
        cpu = number(target, 'vCPUsAvailable', number(target, 'vCPUs'))
        mem = number(target, 'MemoryGB')
        if not cpu or not mem or not cores or not memory or number(target, 'vCPUs') != cpu:
            continue
        rc, rm = cpu / cores, mem / memory
        if rc not in (.5, 1) or rm not in (.5, 1) or (rc, rm) == (1, 1):
            continue
        if rc < 1 and (vm.get('cpuAverage') is None or vm['cpuAverage'] >= 20):
            continue
        if rm < 1 and (vm.get('memoryAverage') is None or vm['memoryAverage'] >= 20):
            continue
        out.append((sku, rc, rm))
    return out


def deployment_checks(vm, source, sku):
    a, b = caps(source), caps(sku)
    checks = []
    if a.get('CpuArchitectureType') != b.get('CpuArchitectureType'):
        checks.append('目标CPU架构不同')
    # Same generation/features is not permission to swap a documented CPU model.
    for key in ('CpuModel', 'CPUModel', 'CpuManufacturer'):
        if a.get(key) and a.get(key) != b.get(key):
            checks.append('目标CPU型号/性能不同或缺失，尚未获得业务批准')
    if number(a, 'GPUs', 0) != number(b, 'GPUs', 0):
        checks.append('目标GPU数量/性能变化，尚未获得业务批准')
    if a.get('PremiumIO') == 'True' and b.get('PremiumIO') != 'True':
        checks.append('目标不保留Premium Storage能力')
    accelerated = a.get('AcceleratedNetworkingEnabled') == 'True' or any(n.get('acceleratedNetworking') for n in vm.get('nicConfiguration', []))
    if accelerated and b.get('AcceleratedNetworkingEnabled') != 'True':
        checks.append('目标不保留加速网络能力')
    if len(vm.get('dataDisks', [])) > number(b, 'MaxDataDiskCount', 0):
        checks.append('目标可挂数据盘数不足')
    if len(vm.get('networkInterfaces', [])) > number(b, 'MaxNetworkInterfaces', 0):
        checks.append('目标NIC数量上限不足')
    if number(b, 'MaxResourceVolumeMB', 0) < number(a, 'MaxResourceVolumeMB', 0):
        checks.append('临时盘容量减少，尚未验证本地数据需求')
    if (vm.get('osDisk') or {}).get('diffDiskSettings', {}).get('option') == 'Local' and b.get('EphemeralOSDiskSupported') != 'True':
        checks.append('目标不支持当前Ephemeral OS盘')
    security = vm.get('securityProfile') or {}
    if security.get('securityType') == 'TrustedLaunch' and (b.get('TrustedLaunchDisabled') == 'True' or 'V2' not in b.get('HyperVGenerations', '')):
        checks.append('目标不支持当前Trusted Launch/Gen2配置')
    if security.get('encryptionAtHost') and b.get('EncryptionAtHostSupported') != 'True':
        checks.append('目标不支持当前主机加密')
    if (vm.get('additionalCapabilities') or {}).get('ultraSSDEnabled') and b.get('UltraSSDAvailable') != 'True':
        checks.append('目标不支持当前Ultra SSD配置')
    if vm.get('configurationChanged'):
        checks.append('当前配置与观察窗口台账不一致，须先复核')
    if vm.get('liveFound') is False:
        checks.append('台账实例在当前订阅未找到')
    if vm.get('liveState') and str(vm['liveState']).lower() != str(vm.get('state', '')).lower():
        checks.append('当前电源状态与观察台账不一致')
    region = vm['region'].lower()
    for restriction in sku.get('restrictions', []):
        info = restriction.get('restrictionInfo') or {}
        locations = info.get('locations') or (restriction.get('values', []) if restriction.get('type') == 'Location' else [])
        if locations and region not in {x.lower() for x in locations}:
            continue
        if restriction.get('type') == 'Location':
            checks.append('目标在当前订阅/区域不可部署：' + restriction.get('reasonCode', '受限'))
        elif restriction.get('type') == 'Zone':
            restricted = set(info.get('zones', []))
            if not vm.get('zones') or restricted.intersection(vm['zones']):
                checks.append('目标可用区部署限制需复核：' + ','.join(sorted(restricted)))
    if vm.get('zones'):
        zones = {z for loc in sku.get('locationInfo', []) if str(loc.get('location', region)).lower() == region for z in loc.get('zones', [])}
        if not set(vm['zones']).issubset(zones):
            checks.append('目标不覆盖当前可用区')
    return list(dict.fromkeys(checks))


def add_coverage(vms):
    """Per kind/region/current SKU/metric reference; never a hardcoded expected count."""
    baseline = {}
    for vm in vms:
        for name in METRICS:
            m = vm.get('metrics', {}).get(name, {})
            count = number(m, 'sampleCount', 0)
            if str(vm.get('state', '')).lower() == RUNNING and m.get('validDays') == 7 and count > 0 and number(m, 'average') is not None:
                key = (vm.get('kind'), vm.get('region', '').lower(), str(vm.get('size', '')).lower(), name)
                baseline[key] = max(baseline.get(key, 0), count)
    for vm in vms:
        metrics = vm.setdefault('metrics', {})
        for name in METRICS:
            m = metrics.setdefault(name, {'average': None, 'sampleCount': 0, 'validDays': 0, 'daily': []})
            key = (vm.get('kind'), vm.get('region', '').lower(), str(vm.get('size', '')).lower(), name)
            expected = baseline.get(key)
            count = number(m, 'sampleCount', 0)
            average = number(m, 'average')
            m['average'] = average
            m['coverage'] = min(1, count / expected) if expected else None
            m['coverageReferenceCount'] = expected
            m['coverageReferenceGroup'] = list(key)
            m['sufficient'] = (m.get('validDays') == 7 and average is not None and 0 <= average <= 100
                               and m['coverage'] is not None and m['coverage'] >= .95)
        vm['cpuAverage'] = metrics['Percentage CPU']['average']
        available = metrics['Available Memory Percentage']['average']
        vm['memoryAverage'] = 100 - available if available is not None else None
    return baseline


def _group_members(records, vms, clusters):
    groups = defaultdict(list)
    vm_lookup = {v['id'].lower(): v for v in vms}
    for record in records:
        if record['kind'] == 'vmss':
            key = record['metricResourceId'].lower()
            groups[key].append(record)
            record['pool'] = key
    assigned = {}
    for cluster in clusters:
        subscription = str(cluster.get('subscriptionId') or arm_subscription(cluster.get('id')) or '').lower()
        for pool in cluster.get('pools', []):
            if pool.get('type') != 'VirtualMachines':
                continue
            key = (cluster['id'] + '/agentPools/' + pool['name']).lower()
            for record in records:
                vm = vm_lookup[record['vmId'].lower()]
                # A resource group or pool name alone is not globally unique.
                if (record['kind'] == 'vm' and record['subscriptionId'].lower() == subscription
                        and str(vm.get('resourceGroup', '')).lower() == str(cluster.get('nodeResourceGroup', '')).lower()
                        and record['name'].lower().startswith('aks-' + pool['name'].lower() + '-')):
                    identity = record['vmId'].lower()
                    if identity in assigned and assigned[identity] != key:
                        raise ValueError(f'Ambiguous standalone AKS pool membership for {identity}')
                    assigned[identity] = key
                    if record not in groups[key]:
                        groups[key].append(record)
                    record['pool'] = key
    return groups


def analyze(vms, sku_envelopes, clusters, catalog, subscriptions=(), manifest=None, price_date=None):
    """Pure analysis API. Returns (updated_vms, records, trials, pools, summary)."""
    vms = copy.deepcopy(vms)
    identities = [str(v['id']).lower() for v in vms]
    if len(set(identities)) != len(identities):
        raise ValueError('Duplicate case-insensitive VM ARM IDs in fresh inventory')
    for vm in vms:
        sub = arm_subscription(vm['id'])
        if not vm.get('subscriptionId') or (sub and sub != vm['subscriptionId'].lower()):
            raise ValueError('VM subscriptionId missing or inconsistent with ARM ID: ' + vm['id'])
    skus = sku_lookup(sku_envelopes)
    add_coverage(vms)
    possible = {v['id'].lower(): sizes_for(v, skus) for v in vms}
    records, trials = [], []
    trials_by_id = defaultdict(list)
    for v in vms:
        s = skus.get(sku_key(v))
        current = caps(s)
        p = quote_for(catalog, v)
        r = {
            'subscriptionName': v.get('subscriptionName'), 'subscriptionId': v['subscriptionId'], 'resourceGroup': v.get('resourceGroup'),
            'vmId': v['id'], 'name': v.get('metricName') or v['name'], 'region': v['region'], 'kind': v['kind'],
            'metricResourceId': v.get('metricResourceId') or v['id'], 'state': v.get('state', 'Unknown'),
            'currentSKU': v.get('size'), 'currentCaps': current,
            'currentCores': number(current, 'vCPUsAvailable', number(current, 'vCPUs')), 'currentMemoryGiB': number(current, 'MemoryGB'),
            'cpuAverage': v['cpuAverage'], 'memoryAverage': v['memoryAverage'],
            'currentPriceUSDHour': p['retailPrice'] if p else None, 'priceSource': p['sourceUrl'] if p else None,
            'currentPriceQuote': p, 'osPriceBasis': os_price_basis(v), 'licenseType': v.get('licenseType'),
            'metricErrors': {m: value['error'] for m, value in v.get('metrics', {}).items() if value.get('error')},
            'targetSKU': None, 'candidate': None, 'monthlySavingsUSD': 0, 'status': None, 'reasons': [], 'eligibleTargets': [], 'pool': None,
        }
        state = str(v.get('state', '')).lower()
        if state == DEALLOCATED:
            r.update(status='已释放：不计持续计算降配节省', reasons=['计算已释放，不重复计算关机或持续计算降配收益'])
        elif state != RUNNING:
            r.update(status='状态未确认释放：暂不能判断', reasons=['仅PowerState/deallocated确认已释放计算；当前状态不按运行或计算费0处理'])
        elif not s or not p or any(not v['metrics'][m]['sufficient'] for m in METRICS[:2]):
            missing = []
            errors = list(r['metricErrors'].values())
            if any(re.search(r'HTTP\s*403|AuthorizationFailed|checkAccess/read', str(error), re.I) for error in errors):
                missing.append('Batch API无读取权限（HTTP403），本次不判断')
            elif errors:
                missing.append('指标读取/处理失败，本次不判断；原始错误保留在metricErrors')
            if not s:
                missing.append('当前订阅/区域SKU能力未匹配')
            if not p:
                missing.append('当前OS/许可对应官网按需价格未匹配')
            if any(not v['metrics'][m]['sufficient'] for m in METRICS[:2]):
                missing.append('CPU/内存缺失、有效日不足7天或采样覆盖不足95%')
            r.update(status='数据不足：暂不能判断', reasons=missing + ['缺失不补0'])
        elif not shape(v.get('size')):
            reason = '本轮未对该系列制定降档规则'
            if number(current, 'GPUs', 0) > 0 or re.match(r'^standard_n', str(v.get('size')), re.I):
                reason += '；GPU数量/型号/性能变化需业务批准，当前保持原规格'
            if re.match(r'^standard_b', str(v.get('size')), re.I):
                reason += '；不凭平均CPU推断突发积分/持续性能余量，当前保持原规格'
            r.update(status='保持现状：该系列未制定降档规则', reasons=[reason])
        elif v['cpuAverage'] >= 20 and v['memoryAverage'] >= 20:
            r.update(status='保持现状：平均利用率不低', reasons=['CPU与内存周平均均不低于20%，本轮不减少容量'])
        else:
            for sku, rc, rm in possible[v['id'].lower()]:
                target = caps(sku)
                tp = quote_for(catalog, v, sku['name'])
                checks = deployment_checks(v, s, sku)
                if str(v.get('priority', 'Regular')).lower() in ('spot', 'low'):
                    checks.append('当前为Spot/低优先级；官网常规按需价不代表现有计费，不推断降档节省')
                if not tp:
                    checks.append('目标官网按需单价缺失')
                elif tp['retailPrice'] >= p['retailPrice']:
                    checks.append('目标官网价格未低于当前规格')
                projected, applicability = {}, {}
                for metric, limitkey, label in IO:
                    observed = v['metrics'][metric]
                    before, after = number(current, limitkey), number(target, limitkey)
                    if metric.startswith('VM Cached') and before == 0 and after == 0 and observed['average'] in (None, 0):
                        applicability[metric] = '不适用：SKU无此缓存性能路径'
                        projected[metric] = None
                        continue
                    applicability[metric] = '适用'
                    if not before or not after or observed['average'] is None or not observed['sufficient']:
                        checks.append(label + '指标或限额缺失/采样不足，无法校核')
                        projected[metric] = None
                        continue
                    value = observed['average'] * before / after
                    projected[metric] = value
                    if value > 50 + 1e-9:
                        checks.append(label + f'目标平均消耗率{value:.2f}%超过50%')
                direction = 'CPU与内存减半' if rc < 1 and rm < 1 else '只减CPU，内存保留' if rc < 1 else '只减内存，CPU保留'
                trial = {
                    'subscriptionName': r['subscriptionName'], 'subscriptionId': r['subscriptionId'], 'resourceGroup': r['resourceGroup'],
                    'region': r['region'], 'vmId': v['id'], 'name': r['name'], 'sku': sku['name'], 'direction': direction,
                    'cores': number(target, 'vCPUsAvailable', number(target, 'vCPUs')), 'memoryGiB': number(target, 'MemoryGB'),
                    'cpuRatio': rc, 'memoryRatio': rm, 'projectedCPUPercent': v['cpuAverage'] / rc,
                    'projectedMemoryPercent': v['memoryAverage'] / rm, 'priceUSDHour': tp['retailPrice'] if tp else None,
                    'priceSource': tp['sourceUrl'] if tp else None, 'priceQuote': tp, 'caps': target,
                    'projectedIO': projected, 'ioApplicability': applicability, 'checks': checks, 'passed': not checks,
                    'monthlyPriceDifferenceUSD': (p['retailPrice'] - tp['retailPrice']) * 730 if tp else None,
                }
                trials.append(trial)
                trials_by_id[v['id'].lower()].append(trial)
            options = sorted(trials_by_id[v['id'].lower()], key=lambda c: (not c['passed'], c['priceUSDHour'] if c['priceUSDHour'] is not None else math.inf, c['sku'].lower()))
            good = [c for c in options if c['passed']]
            r['eligibleTargets'] = [c['sku'] for c in good]
            if good:
                c = good[0]
                r.update(status=RECOMMEND, candidate=c, targetSKU=c['sku'], monthlySavingsUSD=c['monthlyPriceDifferenceUSD'],
                         reasons=[c['direction'] + '；拟减少的容量周平均<20%，目标VM级磁盘平均消耗率均≤50%，价格与已查兼容条件满足'])
            elif options:
                r.update(status='保持现状：目标条件不满足', candidate=options[0], reasons=options[0]['checks'])
            else:
                r.update(status='保持现状：无对应一档规格', reasons=['未找到保留同代a/d/s功能、各项容量保持或减半的对应SKU；不强制换其他类型'])
        if state == RUNNING and not shape(v.get('size')) and not any('本轮未对该系列制定降档规则' in text for text in r['reasons']):
            r['reasons'].append('本轮未对该系列制定降档规则；保持原规格，当前能力/指标/价格缺失不补0')
        records.append(r)
    groups = _group_members(records, vms, clusters)
    vm_lookup = {v['id'].lower(): v for v in vms}
    pools = []
    for key, members in sorted(groups.items()):
        running = [r for r in members if str(r['state']).lower() == RUNNING]
        uncertain = [r for r in members if str(r['state']).lower() not in (RUNNING, DEALLOCATED)]
        common = set.intersection(*(set(n.lower() for n in r['eligibleTargets']) for r in running)) if running else set()
        # Unknown members are not silently excluded from the all-current-running guarantee.
        if uncertain or len({(r['subscriptionId'].lower(), r['region'].lower()) for r in running}) > 1:
            common = set()
        chosen = None
        if common:
            chosen = min(common, key=lambda n: sum(quote_for(catalog, vm_lookup[r['vmId'].lower()], n)['retailPrice'] for r in running))
            for r in running:
                c = next(t for t in trials_by_id[r['vmId'].lower()] if t['sku'].lower() == chosen and t['passed'])
                r.update(status=RECOMMEND, candidate=c, targetSKU=c['sku'], monthlySavingsUSD=c['monthlyPriceDifferenceUSD'])
                r['reasons'] = [c['direction'] + '；拟减少的容量周平均<20%，目标VM级磁盘平均消耗率均≤50%，价格与已查兼容条件满足',
                                '同池全部运行节点通过，目标规格一致；仍需业务确认Pod资源与故障余量']
        else:
            for r in running:
                if r['status'] == RECOMMEND:
                    r.update(status='暂不调整：整池条件未满足', targetSKU=None, monthlySavingsUSD=0)
                    r['reasons'].append('同池其他节点未通过、状态未确认或无共同目标SKU，不计单节点价差为整池收益')
        pools.append({'id': key, 'name': key.split('/')[-1], 'subscriptionId': members[0]['subscriptionId'],
                      'subscriptionName': members[0]['subscriptionName'], 'resourceGroup': members[0]['resourceGroup'],
                      'runningCount': len(running), 'unknownStateCount': len(uncertain), 'instancePassedCount': sum(bool(r['eligibleTargets']) for r in running),
                      'targetSKU': running[0]['targetSKU'] if chosen else None,
                      'status': '建议整池试点' if chosen else '暂不调整：整池条件未满足',
                      'monthlySavingsUSD': sum(r['monthlySavingsUSD'] for r in running), 'members': [r['vmId'] for r in members]})
    by_sub = defaultdict(list)
    for record in records:
        by_sub[record['subscriptionId'].lower()].append(record)
    names = {str(s.get('id') or s.get('subscriptionId')).lower(): s.get('name') or s.get('subscriptionName') for s in subscriptions}
    names.update({r['subscriptionId'].lower(): r['subscriptionName'] for r in records})
    def counts(group):
        return {'vmCount': len(group), 'runningCount': sum(str(r['state']).lower() == RUNNING for r in group),
                'deallocatedCount': sum(str(r['state']).lower() == DEALLOCATED for r in group),
                'unknownOrOtherStateCount': sum(str(r['state']).lower() not in (RUNNING, DEALLOCATED) for r in group),
                'recommendedVMCount': sum(r['status'] == RECOMMEND for r in group),
                'monthlyPotentialSavingsUSD': sum(r['monthlySavingsUSD'] for r in group),
                'statusCounts': dict(Counter(r['status'] for r in group))}
    inventory_by_sub = {str(s.get('id') or s.get('subscriptionId')).lower(): s for s in subscriptions}
    subscription_summary = []
    for sub in sorted(names):
        inventory = inventory_by_sub.get(sub, {})
        subscription_summary.append({'subscriptionId': sub, 'subscriptionName': names[sub],
            'subscriptionState': inventory.get('state'), 'inventoryStatus': inventory.get('inventoryStatus', 'observed' if by_sub[sub] else 'not-specified'),
            'inventoryErrors': inventory.get('inventoryErrors', []),
            'verifiedNoVM': inventory.get('inventoryStatus') == 'ok' and not by_sub[sub], **counts(by_sub[sub])})
    aggregate = counts(records)
    summary = {
        'policy': {**POLICY, 'priceAsOfDate': price_date}, 'recordCount': len(records), **aggregate,
        'subscriptionCount': len(subscription_summary), 'subscriptionsWithVMs': len({r['subscriptionId'].lower() for r in records}),
        'subscriptionSummary': subscription_summary, 'subscriptionCounts': subscription_summary,
        'verifiedNoVMSubscriptionCount': sum(s['verifiedNoVM'] for s in subscription_summary),
        'unverifiedSubscriptionCount': sum(s['inventoryStatus'] == 'unverified' for s in subscription_summary),
        'subscriptionInventoryStatusCounts': dict(Counter(s['inventoryStatus'] for s in subscription_summary)),
        'recommendedPoolCount': sum(p['status'] == '建议整池试点' for p in pools),
        'analysisAt': now(), 'priceAsOfDate': price_date,
        'priceQueriedAt': max((q.get('queriedAt', '') for q in catalog.values()), default=None),
        'observationWindow': {k: (manifest or {}).get(k) for k in ('start', 'end', 'inventorySnapshotAt', 'inventoryCollectedAt')},
        'coverageMethod': '每指标与同类型/同区域/同当前SKU完整7天运行实例最高样本数比较，要求7个有效日且相对采样覆盖≥95%；不是5分钟桶覆盖率，孤立系列不能证明连续采样',
        'missingCurrentPAYGCount': sum(r['currentPriceUSDHour'] is None and str(r['state']).lower() == RUNNING for r in records),
        'windowsLicenseIncludedCount': sum(r['osPriceBasis'] == 'windows' for r in records),
        'unknownOSCount': sum(r['osPriceBasis'] == 'unknown' for r in records),
        'metricErrorVMCount': sum(bool(r['metricErrors']) for r in records),
        'metricPermissionBlockedSubscriptions': sorted({r['subscriptionName'] or r['subscriptionId'] for r in records
            if any(re.search(r'HTTP\s*403|AuthorizationFailed|checkAccess/read', str(error), re.I) for error in r['metricErrors'].values())}),
        'metricErrorSubscriptionSummary': [{'subscriptionId': sub, 'subscriptionName': names[sub],
            'metricErrorVMCount': sum(bool(r['metricErrors']) for r in by_sub[sub])} for sub in sorted(names)
            if any(r['metricErrors'] for r in by_sub[sub])],
        'limits': '平均负载试点建议，不保证瞬时峰值；未验证业务SLO、Pod requests/PDB、故障余量、实时库存/配额及实际协议价；不建议为已释放实例购买RI/SP',
    }
    return vms, records, trials, pools, summary
