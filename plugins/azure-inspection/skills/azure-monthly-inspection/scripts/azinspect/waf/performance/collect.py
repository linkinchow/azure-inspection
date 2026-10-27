"""Performance efficiency (P1..P10) read-only collection.

Raw layout under raw/waf/performance/ (same as earlier inspections, so earlier data can be replayed):
  arg/<name>.json, metrics/<label>.json, aks/agentpools.json, db/max_connections.json, ai/deployments.json,
  ai/usages.json, storage/premium-shares.json, la/container-insights.json, cost/bandwidth-month.json,
  index.json (calls of this pillar), manifest.json (window).
Reads only: ARG, ARM GET, metrics getBatch / ARM metrics GET, Log Analytics query, Cost Management query.
"""
from __future__ import annotations

import re
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date

from ...core.io import read_json
from ..common import Raw, enabled, load_scope, now

ARM = 'https://management.azure.com'
WORKERS = 3

ARG_QUERIES = {
    'vms': "resources | where type =~ 'microsoft.compute/virtualmachines' | project id,name,location,resourceGroup,subscriptionId,tags,vmSize=tostring(properties.hardwareProfile.vmSize),power=tostring(properties.extended.instanceView.powerState.code),os=tostring(properties.storageProfile.osDisk.osType),dataDisks=array_length(properties.storageProfile.dataDisks)",
    'vmss': "resources | where type =~ 'microsoft.compute/virtualmachinescalesets' | project id,name,location,resourceGroup,subscriptionId,tags,sku,poolName=tostring(tags['aks-managed-poolName']),clusterTag=tostring(tags['aks-managed-cluster-name'])",
    'aks': "resources | where type =~ 'microsoft.containerservice/managedclusters' | project id,name,location,resourceGroup,subscriptionId,tags,sku,nodeRG=tostring(properties.nodeResourceGroup),power=tostring(properties.powerState.code),addons=properties.addonProfiles,azureMonitorProfile=properties.azureMonitorProfile,autoScalerProfile=properties.autoScalerProfile",
    'mysql': "resources | where type =~ 'microsoft.dbformysql/flexibleservers' | project id,name,location,resourceGroup,subscriptionId,tags,sku,state=tostring(properties.state),replicationRole=tostring(properties.replicationRole),sourceServer=tostring(properties.sourceServerResourceId),storage=properties.storage",
    'postgres': "resources | where type =~ 'microsoft.dbforpostgresql/flexibleservers' | project id,name,location,resourceGroup,subscriptionId,tags,sku,state=tostring(properties.state),replicationRole=tostring(properties.replicationRole),sourceServer=tostring(properties.sourceServerResourceId),storage=properties.storage",
    'redis': "resources | where type =~ 'microsoft.cache/redis' | project id,name,location,resourceGroup,subscriptionId,tags,sku=properties.sku,state=tostring(properties.provisioningState)",
    'redisenterprise': "resources | where type =~ 'microsoft.cache/redisenterprise' | project id,name,location,resourceGroup,subscriptionId,tags,sku,state=tostring(properties.resourceState)",
    'mongoclusters': "resources | where type =~ 'microsoft.documentdb/mongoclusters' | project id,name,location,resourceGroup,subscriptionId,tags,compute=properties.compute,storage=properties.storage,tier=tostring(properties.nodeGroupSpecs[0].sku),state=tostring(properties.clusterStatus)",
    'storage': "resources | where type =~ 'microsoft.storage/storageaccounts' | project id,name,location,resourceGroup,subscriptionId,tags,sku,kind",
    'appgw': "resources | where type =~ 'microsoft.network/applicationgateways' | project id,name,location,resourceGroup,subscriptionId,tags,sku=properties.sku,autoscale=properties.autoscaleConfiguration,state=tostring(properties.operationalState),backendPools=array_length(properties.backendAddressPools)",
    'lbs': "resources | where type =~ 'microsoft.network/loadbalancers' | project id,name,location,resourceGroup,subscriptionId,tags,sku,frontends=array_length(properties.frontendIPConfigurations),rules=array_length(properties.loadBalancingRules),probes=array_length(properties.probes),backendPools=array_length(properties.backendAddressPools),internal=isnotempty(properties.frontendIPConfigurations[0].properties.subnet)",
    'frontdoor': "resources | where type =~ 'microsoft.cdn/profiles' or type =~ 'microsoft.network/frontdoors' | project id,name,type,location,resourceGroup,subscriptionId,tags,sku",
    'ai': "resources | where type =~ 'microsoft.cognitiveservices/accounts' | project id,name,kind,location,resourceGroup,subscriptionId,tags,sku,endpoint=tostring(properties.endpoint)",
    'workspaces': "resources | where type =~ 'microsoft.operationalinsights/workspaces' | project id,name,location,resourceGroup,subscriptionId,customerId=tostring(properties.customerId),retention=toint(properties.retentionInDays)",
    'pe': "resources | where type =~ 'microsoft.network/privateendpoints' | mv-expand c=array_concat(properties.privateLinkServiceConnections, properties.manualPrivateLinkServiceConnections) | project id,name,location,resourceGroup,subscriptionId,subnetId=tostring(properties.subnet.id),target=tostring(c.properties.privateLinkServiceId),groupIds=c.properties.groupIds,state=tostring(c.properties.privateLinkServiceConnectionState.status)",
    'peerings': "resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand p=properties.virtualNetworkPeerings | where isnotempty(p) | project id,name,location,resourceGroup,subscriptionId,peering=tostring(p.name),remote=tostring(p.properties.remoteVirtualNetwork.id),state=tostring(p.properties.peeringState),allowForwarded=tobool(p.properties.allowForwardedTraffic),useRemoteGw=tobool(p.properties.useRemoteGateways)",
    'vnetloc': "resources | where type =~ 'microsoft.network/virtualnetworks' | project id=tolower(id),name,location,subscriptionId",
    'alllocs': "resources | where type !in~ ('microsoft.network/networkinterfaces','microsoft.compute/disks','microsoft.compute/snapshots','microsoft.network/networksecuritygroups','microsoft.compute/virtualmachines/extensions','microsoft.network/publicipaddresses') | project id=tolower(id),type,location",
}

VM_METRICS = ['Percentage CPU', 'Available Memory Percentage', 'VM Cached IOPS Consumed Percentage',
              'VM Uncached IOPS Consumed Percentage', 'VM Cached Bandwidth Consumed Percentage',
              'VM Uncached Bandwidth Consumed Percentage', 'OS Disk IOPS Consumed Percentage',
              'OS Disk Bandwidth Consumed Percentage', 'Data Disk IOPS Consumed Percentage',
              'Data Disk Bandwidth Consumed Percentage']

LA_REASONS = "'FailedScheduling','OOMKilling','OOMKilled','Evicted','Preempted','NodeNotReady','FailedCreatePodSandBox','NotTriggerScaleUp','BackOff','Unhealthy','FailedMount','FailedAttachVolume'"
COST_TOP_SUBSCRIPTIONS = 10


def la_queries(start: str, end: str) -> dict:
    s, e = start[:10], end[:10]
    return {
        'events': f"""KubeEvents
| where TimeGenerated between (datetime({s}) .. datetime({e}))
| where Reason in ({LA_REASONS})
| summarize events=count(), objects=dcount(Name), days=dcount(bin(TimeGenerated, 1d)), firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated) by ClusterName, Namespace, Reason
| order by events desc""",
        'pending10m': f"""KubePodInventory
| where TimeGenerated between (datetime({s}) .. datetime({e}))
| where PodStatus == 'Pending'
| summarize firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated) by ClusterName, Namespace, Name, PodUid
| extend durMin = (lastSeen - firstSeen) / 1m
| where durMin > 10
| summarize pods=dcount(PodUid), maxDurMin=max(durMin), avgDurMin=avg(durMin), days=dcount(bin(firstSeen, 1d)), sample=take_any(Name) by ClusterName, Namespace
| order by pods desc""",
        'oomkilled': f"""KubePodInventory
| where TimeGenerated between (datetime({s}) .. datetime({e}))
| where ContainerLastStatus has 'OOMKilled'
| extend s = parse_json(ContainerLastStatus)
| extend fin = tostring(coalesce(s.finishedAt, s.lastTerminatedTime, s.FinishedAt)), reason = tostring(s.reason)
| where reason == 'OOMKilled' or ContainerLastStatus has 'OOMKilled'
| summarize oomEvents=dcount(strcat(Name, '/', ContainerName, '/', fin)), pods=dcount(Name), containers=dcount(ContainerName), days=dcount(bin(TimeGenerated, 1d)), sample=take_any(Name) by ClusterName, Namespace, ControllerName
| order by oomEvents desc""",
        'restarts': f"""KubePodInventory
| where TimeGenerated between (datetime({s}) .. datetime({e}))
| where isnotempty(ContainerName)
| summarize r=max(ContainerRestartCount) - min(ContainerRestartCount) by ClusterName, Namespace, ControllerName, Name, ContainerName
| summarize restarts=sum(r), pods=dcount(Name) by ClusterName, Namespace, ControllerName
| where restarts > 0
| top 40 by restarts desc""",
        'tables': f"""union withsource=T KubeEvents, KubePodInventory, KubeNodeInventory
| where TimeGenerated > datetime({s})
| summarize rows=count(), firstSeen=min(TimeGenerated), lastSeen=max(TimeGenerated) by T, ClusterName""",
    }


def pmap(fn, items, workers=WORKERS):
    with ThreadPoolExecutor(workers) as ex:
        return list(ex.map(fn, items))


def norm_values(values):
    """Azure Monitor 'value' list -> {metricName: [{'dims', 'data'}], '_errors': {...}}."""
    out, errs = {}, {}
    for m in values or []:
        name = (m.get('name') or {}).get('value')
        code = m.get('errorCode') or 'Success'
        if code.lower() != 'success':
            errs[name] = f"{code}: {m.get('errorMessage', '')}"[:300]
            continue
        out[name] = [{'dims': {(d.get('name') or {}).get('value'): d.get('value') for d in ts.get('metadatavalues') or []},
                      'data': ts.get('data') or []} for ts in m.get('timeseries') or []]
    if errs:
        out['_errors'] = errs
    return out


class Collector:
    def __init__(self, ws, cfg, client, window, log):
        self.ws, self.cfg, self.client, self.log = ws, cfg, client, log
        self.raw = Raw(ws, 'performance')
        self.start, self.end = window['start'], window['end']
        self.window = window
        self.subs = enabled(load_scope(ws))
        self.denied = set()   # (subscription, check) that returned 403 once: skip further metric calls of that kind

    def save(self, rel, obj):
        self.raw.save(rel, obj)

    def rows(self, name):
        return (self.raw.load(f'arg/{name}.json') or {}).get('rows') or []

    # ------------------------------------------------------------------ ARG
    def arg(self, names):
        ids = [s['id'] for s in self.subs]
        summary = self.raw.load('arg/_summary.json', {})
        for name in names:
            q = ARG_QUERIES[name]
            rows, status, error = self.client.arg(q, ids, 'ARG', name)
            self.save(f'arg/{name}.json', {'query': q, 'status': status, 'error': error, 'rows': rows})
            summary[name] = {'status': status, 'error': error, 'rows': None if rows is None else len(rows)}
        self.save('arg/_summary.json', summary)

    # ------------------------------------------------------------------ metrics
    def metrics_arm(self, rid, check, namespace, names, aggregation, interval='P1D', flt=None, top=None):
        q = {'api-version': '2023-10-01', 'metricnames': ','.join(names), 'timespan': f'{self.start}/{self.end}',
             'interval': interval, 'aggregation': aggregation, 'metricnamespace': namespace}
        if flt:
            q['$filter'] = flt
        if top:
            q['top'] = str(top)
        url = ARM + rid + '/providers/Microsoft.Insights/metrics?' + urllib.parse.urlencode(q, quote_via=urllib.parse.quote)
        return self.client.request('GET', url, check, rid.split('/')[-1])

    def batch_metrics(self, label, check, items, namespace, names, aggregation, interval='P1D', flt=None, top=None, force_arm=False):
        """metrics:getBatch (<=50 ids per subscription/region). A 400 with several metrics is retried metric by metric;
        'global' resources and a 403 use the per-resource ARM metrics GET; a second 403 stops that subscription."""
        res, calls, groups = {}, [], defaultdict(list)
        for it in items:
            groups[(it['subscriptionId'].lower(), (it.get('location') or '').lower())].append(it['id'])
        jobs = []
        for (sub, region), rids in sorted(groups.items()):
            rids = sorted(set(rids), key=str.lower)
            jobs += [(sub, region, rids[i:i + 50]) for i in range(0, len(rids), 50)]

        def merge(rid, norm):
            cur = res.setdefault(rid.lower(), {})
            errs = norm.pop('_errors', None)
            cur.update(norm)
            if errs:
                cur.setdefault('_errors', {}).update(errs)

        def run_batch(sub, region, rids, mnames):
            params = {'api-version': '2024-02-01', 'metricnamespace': namespace, 'metricnames': ','.join(mnames),
                      'starttime': self.start, 'endtime': self.end, 'interval': interval, 'aggregation': aggregation}
            if flt:
                params['filter'] = flt
            if top:
                params['top'] = str(top)
            url = (f'https://{region}.metrics.monitor.azure.com/subscriptions/{sub}/metrics:getBatch?'
                   + urllib.parse.urlencode(params, quote_via=urllib.parse.quote))
            return self.client.request('POST', url, check, f'{label}/{sub}/{region}', body={'resourceids': rids})

        def skipped(rid):
            res[rid.lower()] = {'_error': 'skipped: metrics denied (403) earlier for this subscription'}

        def arm_path(sub, rids):
            for r in rids:
                if (sub, check) in self.denied:
                    skipped(r)
                    continue
                st, data, err = self.metrics_arm(r, check, namespace, names, aggregation, interval, flt, top)
                calls.append({'rid': r, 'via': 'arm', 'status': st, 'error': err})
                if st == 200:
                    merge(r, norm_values(data.get('value')))
                elif st == 400 and len(names) > 1:
                    for n in names:
                        st2, d2, e2 = self.metrics_arm(r, check, namespace, [n], aggregation, interval, flt, top)
                        calls.append({'rid': r, 'via': 'arm', 'metric': n, 'status': st2, 'error': e2})
                        if st2 == 200:
                            merge(r, norm_values(d2.get('value')))
                        else:
                            res.setdefault(r.lower(), {}).setdefault('_errors', {})[n] = f'HTTP {st2}: {e2}'
                else:
                    res[r.lower()] = {'_error': f'HTTP {st}: {err}'}
                    if st == 403:
                        self.denied.add((sub, check))

        def job(j):
            sub, region, rids = j
            if (sub, check) in self.denied:
                for r in rids:
                    skipped(r)
                return
            if force_arm or region == 'global' or not re.fullmatch(r'[a-z][a-z0-9]{1,40}', region):
                arm_path(sub, rids)
                return
            st, data, err = run_batch(sub, region, rids, names)
            calls.append({'sub': sub, 'region': region, 'n': len(rids), 'metrics': names, 'status': st, 'error': err})
            if st == 200:
                got = set()
                for v in data.get('values') or []:
                    got.add((v.get('resourceid') or '').lower())
                    merge(v.get('resourceid') or '', norm_values(v.get('value')))
                for r in rids:
                    if r.lower() not in got:
                        res.setdefault(r.lower(), {})['_error'] = 'not returned by getBatch'
            elif st == 400 and len(names) > 1:
                for n in names:
                    st2, d2, e2 = run_batch(sub, region, rids, [n])
                    calls.append({'sub': sub, 'region': region, 'n': len(rids), 'metrics': [n], 'status': st2, 'error': e2})
                    if st2 == 200:
                        for v in d2.get('values') or []:
                            merge(v.get('resourceid') or '', norm_values(v.get('value')))
                    else:
                        for r in rids:
                            res.setdefault(r.lower(), {}).setdefault('_errors', {})[n] = f'HTTP {st2}: {e2}'
            elif st == 403:
                arm_path(sub, rids)
            else:
                for r in rids:
                    res[r.lower()] = {'_error': f'HTTP {st}: {err}'}

        pmap(job, jobs)
        self.save(f'metrics/{label}.json', {'label': label, 'namespace': namespace, 'metrics': names, 'aggregation': aggregation,
                                            'interval': interval, 'filter': flt, 'window': [self.start, self.end],
                                            'calls': calls, 'results': res})
        return res

    # ------------------------------------------------------------------ phases
    def phase_compute(self):
        vms = [v for v in self.rows('vms') if v.get('power') == 'PowerState/running']
        self.batch_metrics('vm-daily', 'P1/P4', vms, 'microsoft.compute/virtualmachines', VM_METRICS, 'average,maximum,count')
        vmss = self.rows('vmss')
        ns = 'microsoft.compute/virtualmachinescalesets'
        self.batch_metrics('vmss-daily', 'P1/P4', vmss, ns, VM_METRICS, 'average,maximum,count')
        self.batch_metrics('vmss-instance-daily', 'P1', vmss, ns, ['Percentage CPU', 'Available Memory Percentage'],
                           'average,maximum,count', flt="VMName eq '*'", top=1000)
        self.batch_metrics('vmss-instance-hourly-cpu', 'P2', vmss, ns, ['Percentage CPU'], 'average', interval='PT1H',
                           flt="VMName eq '*'", top=1000)

    def phase_aks(self):
        aks = self.rows('aks')
        ns = 'microsoft.containerservice/managedclusters'
        self.batch_metrics('aks-nodepool', 'P2', aks, ns, ['node_cpu_usage_percentage', 'node_memory_working_set_percentage',
                                                           'node_disk_usage_percentage'],
                           'average,maximum,count', interval='PT12H', flt="nodepool eq '*'", top=500)
        self.batch_metrics('aks-node', 'P2', aks, ns, ['node_cpu_usage_percentage', 'node_memory_working_set_percentage'],
                           'average,maximum,count', interval='PT12H', flt="node eq '*'", top=1000)
        self.batch_metrics('aks-podphase', 'P2', aks, ns, ['kube_pod_status_phase'], 'average,maximum', interval='PT12H',
                           flt="phase eq '*' and namespace eq '*'", top=2000)
        self.batch_metrics('aks-autoscaler', 'P2', aks, ns, ['cluster_autoscaler_unschedulable_pods_count',
                                                            'cluster_autoscaler_cluster_safe_to_autoscale',
                                                            'cluster_autoscaler_scale_down_in_cooldown',
                                                            'apiserver_cpu_usage_percentage', 'apiserver_memory_usage_percentage',
                                                            'etcd_database_usage_percentage'],
                           'average,maximum,minimum,count', interval='PT12H')
        self.batch_metrics('aks-nodecond', 'P2', aks, ns, ['kube_node_status_condition'], 'average,maximum', interval='PT12H',
                           flt="condition eq '*' and status eq '*'", top=500)
        fields = ('count', 'minCount', 'maxCount', 'enableAutoScaling', 'vmSize', 'mode', 'osDiskType', 'osDiskSizeGB', 'maxPods',
                  'powerState', 'scaleSetPriority', 'availabilityZones', 'orchestratorVersion', 'provisioningState')
        out = []
        for c in aks:
            items, st, err = self.client.get_all(c['id'] + '/agentPools?api-version=2025-05-01', 'P2', c['name'])
            out.append({'cluster': c['name'], 'id': c['id'], 'status': st, 'error': err,
                        'pools': [{'name': p['name'], **{k: p['properties'].get(k) for k in fields}} for p in (items or [])]})
        self.save('aks/agentpools.json', out)

    def phase_db(self):
        self.batch_metrics('mysql', 'P4/P5', self.rows('mysql'), 'microsoft.dbformysql/flexibleservers',
                           ['cpu_percent', 'memory_percent', 'io_consumption_percent', 'storage_percent', 'active_connections',
                            'aborted_connections', 'total_connections', 'replication_lag', 'cpu_credits_remaining', 'Slow_queries'],
                           'average,maximum,total,count')
        self.batch_metrics('postgres', 'P4/P5', self.rows('postgres'), 'microsoft.dbforpostgresql/flexibleservers',
                           ['cpu_percent', 'memory_percent', 'storage_percent', 'disk_iops_consumed_percentage',
                            'disk_bandwidth_consumed_percentage', 'active_connections', 'max_connections', 'connections_failed',
                            'connections_succeeded', 'physical_replication_delay_in_seconds', 'cpu_credits_remaining'],
                           'average,maximum,total,count')
        self.batch_metrics('redis', 'P5', self.rows('redis'), 'microsoft.cache/redis',
                           ['serverLoad', 'percentProcessorTime', 'usedmemorypercentage', 'evictedkeys', 'errors',
                            'connectedclients', 'cacheLatency'], 'average,maximum,total,count')
        self.batch_metrics('redisenterprise', 'P5', self.rows('redisenterprise'), 'microsoft.cache/redisenterprise',
                           ['serverLoad', 'percentProcessorTime', 'usedmemorypercentage', 'evictedkeys', 'connectedclients',
                            'cacheLatency', 'operationsPerSecond'], 'average,maximum,total,count')
        self.batch_metrics('mongo', 'P5', self.rows('mongoclusters'), 'microsoft.documentdb/mongoclusters',
                           ['CpuPercent', 'MemoryPercent', 'StoragePercent', 'IOPS'], 'average,maximum,count')

        def conf(r, kind):
            api = '2023-12-30' if kind == 'mysql' else '2024-08-01'
            st, d, err = self.client.get(r['id'] + f'/configurations/max_connections?api-version={api}', 'P5', r['name'])
            p = (d or {}).get('properties') or {}
            return {'id': r['id'], 'name': r['name'], 'kind': kind, 'status': st, 'error': err,
                    'value': p.get('value'), 'defaultValue': p.get('defaultValue'), 'source': p.get('source')}
        out = pmap(lambda r: conf(r, 'mysql'), self.rows('mysql')) + pmap(lambda r: conf(r, 'postgres'), self.rows('postgres'))
        self.save('db/max_connections.json', out)

    def phase_ai(self):
        ai = self.rows('ai')
        ns = 'microsoft.cognitiveservices/accounts'
        self.batch_metrics('ai-requests', 'P6', ai, ns, ['ModelRequests', 'AzureOpenAIRequests'], 'total',
                           flt="StatusCode eq '*' and ModelDeploymentName eq '*'", top=2000)
        self.batch_metrics('ai-latency', 'P6', ai, ns, ['AzureOpenAITimeToResponse', 'TimeToResponse', 'AzureOpenAITTLTInMS',
                                                        'AzureOpenAINormalizedTTFTInMS', 'TimeToLastByte'],
                           'average,maximum', flt="ModelDeploymentName eq '*'", top=1000)
        self.batch_metrics('ai-tokens', 'P6', ai, ns, ['TotalTokens', 'TokenTransaction', 'InputTokens', 'OutputTokens'],
                           'total', flt="ModelDeploymentName eq '*'", top=1000)
        self.batch_metrics('ai-ptu', 'P6', ai, ns, ['ProvisionedUtilization', 'AzureOpenAIProvisionedManagedUtilizationV2'],
                           'average,maximum', flt="ModelDeploymentName eq '*'", top=1000)
        self.batch_metrics('ai-calls', 'P6', ai, ns, ['TotalCalls', 'SuccessfulCalls', 'ClientErrors', 'ServerErrors',
                                                      'BlockedCalls', 'Ratelimit', 'Latency'], 'total,average,maximum')

        def deployments(a):
            items, st, err = self.client.get_all(a['id'] + '/deployments?api-version=2024-10-01', 'P6', a['name'])
            out = []
            for d in items or []:
                p = d.get('properties') or {}
                out.append({'name': d['name'], 'sku': d.get('sku'), 'model': p.get('model'), 'rateLimits': p.get('rateLimits'),
                            'versionUpgradeOption': p.get('versionUpgradeOption'), 'spillover': p.get('spilloverDeploymentName'),
                            'provisioningState': p.get('provisioningState')})
            return {'account': a['name'], 'id': a['id'], 'status': st, 'error': err, 'deployments': out}
        self.save('ai/deployments.json', pmap(deployments, ai))

        def usages(sl):
            sub, loc = sl
            items, st, err = self.client.get_all(
                f'/subscriptions/{sub}/providers/Microsoft.CognitiveServices/locations/{loc}/usages?api-version=2024-10-01', 'P6', f'{sub}/{loc}')
            return {'subscriptionId': sub, 'location': loc, 'status': st, 'error': err,
                    'usages': [u for u in (items or []) if (u.get('currentValue') or 0) > 0]}
        self.save('ai/usages.json', pmap(usages, sorted({(a['subscriptionId'], a['location']) for a in ai})))

    def phase_storage(self):
        accounts = self.rows('storage')
        ns = 'microsoft.storage/storageaccounts'
        self.batch_metrics('storage-tx', 'P7', accounts, ns, ['Transactions'], 'total', flt="ResponseType eq '*'", top=200)
        self.batch_metrics('storage-lat', 'P7', accounts, ns, ['SuccessE2ELatency', 'SuccessServerLatency', 'Availability'],
                           'average,maximum,minimum,count')
        out = []
        for a in [x for x in accounts if x.get('kind') == 'FileStorage']:
            items, st, err = self.client.get_all(a['id'] + '/fileServices/default/shares?api-version=2023-05-01', 'P7', a['name'])
            shares = []
            for sh in (items or [])[:60]:
                s2, d2, e2 = self.client.get(sh['id'] + '?api-version=2023-05-01&$expand=stats', 'P7', sh['name'])
                p = (d2 or {}).get('properties') or {}
                shares.append({'name': sh['name'], 'status': s2, 'error': e2, 'quotaGiB': p.get('shareQuota'),
                               'usageBytes': p.get('shareUsageBytes'), 'provisionedIops': p.get('provisionedIops'),
                               'provisionedBandwidthMibps': p.get('provisionedBandwidthMibps'), 'enabledProtocols': p.get('enabledProtocols')})
            out.append({'account': a['name'], 'id': a['id'], 'status': st, 'error': err,
                        'shareCount': None if items is None else len(items), 'shares': shares})
        self.save('storage/premium-shares.json', out)

    def phase_edge(self):
        ag = self.rows('appgw')
        ns = 'microsoft.network/applicationgateways'
        self.batch_metrics('appgw', 'P9', ag, ns, ['CapacityUnits', 'ComputeUnits', 'FixedBillableCapacityUnits', 'TotalRequests',
                                                   'FailedRequests', 'BackendLastByteResponseTime', 'ApplicationGatewayTotalTime',
                                                   'CurrentConnections', 'Throughput'], 'average,maximum,total,count')
        self.batch_metrics('appgw-status', 'P9', ag, ns, ['ResponseStatus'], 'total', flt="HttpStatusGroup eq '*'", top=50)
        self.batch_metrics('appgw-health', 'P9', ag, ns, ['UnhealthyHostCount', 'HealthyHostCount'], 'average,maximum,minimum',
                           flt="BackendSettingsPool eq '*'", top=200)
        fd = [x for x in self.rows('frontdoor') if x['type'].lower() == 'microsoft.cdn/profiles']
        ns = 'microsoft.cdn/profiles'
        self.batch_metrics('afd-req', 'P9', fd, ns, ['RequestCount', 'OriginRequestCount'], 'total',
                           flt="HttpStatusGroup eq '*'", top=50, force_arm=True)
        self.batch_metrics('afd-lat', 'P9', fd, ns, ['TotalLatency', 'OriginLatency', 'Percentage4XX', 'Percentage5XX'],
                           'average,maximum', force_arm=True)
        self.batch_metrics('afd-originhealth', 'P9', fd, ns, ['OriginHealthPercentage'], 'average,minimum',
                           flt="Origin eq '*'", top=200, force_arm=True)
        lbs = [x for x in self.rows('lbs') if ((x.get('sku') or {}).get('name') or '').lower() == 'standard']
        ns = 'microsoft.network/loadbalancers'
        self.batch_metrics('lb', 'P9', lbs, ns, ['VipAvailability', 'DipAvailability'], 'average,minimum,count')
        self.batch_metrics('lb-dip', 'P9', lbs, ns, ['DipAvailability'], 'average,minimum', flt="BackendIPAddress eq '*'", top=500)
        self.batch_metrics('lb-vip', 'P9', lbs, ns, ['VipAvailability'], 'average,minimum',
                           flt="FrontendIPAddress eq '*' and FrontendPort eq '*'", top=500)

    def phase_la(self):
        """Container Insights history for clusters that send it to a Log Analytics workspace."""
        workspaces = {w['id'].lower(): w for w in self.rows('workspaces')}
        targets = {}
        for c in self.rows('aks'):
            oms = (c.get('addons') or {}).get('omsagent') or {}
            wid = ((oms.get('config') or {}).get('logAnalyticsWorkspaceResourceID') or '').lower()
            if wid and oms.get('enabled'):
                targets.setdefault(wid, []).append(c['name'])
        queries = la_queries(self.start, self.end)
        out = []
        for wid, clusters in targets.items():
            w = workspaces.get(wid)
            if not w or not w.get('customerId'):
                out.append({'workspace': wid, 'clusters': clusters, 'error': 'workspace not found in inventory'})
                continue
            url = f"https://api.loganalytics.io/v1/workspaces/{w['customerId']}/query"
            res = {}
            for qn, q in queries.items():
                st, data, err = self.client.request('POST', url, 'P2', f"{w['name']}/{qn}", body={'query': q, 'timespan': f'{self.start}/{self.end}'})
                tbl = ((data or {}).get('tables') or [{}])[0] if st == 200 else {}
                cols = [c['name'] for c in tbl.get('columns') or []]
                res[qn] = {'status': st, 'error': err, 'rows': [dict(zip(cols, r)) for r in tbl.get('rows') or []]}
            out.append({'workspace': w['name'], 'workspaceId': w['id'], 'retentionDays': w.get('retention'),
                        'clusters': clusters, 'queries': queries, 'results': res})
        self.save('la/container-insights.json', out)

    def cost_subscriptions(self):
        """Subscriptions with the largest Bandwidth / Virtual Network spend in the review month (from the 01 cost data), else all."""
        path = self.ws.raw('cost/cost-data.json')
        if path.exists():
            spend = defaultdict(float)
            for r in read_json(path).get('rows', {}).get('curActual', []):
                if r.get('serviceName') in ('Bandwidth', 'Virtual Network'):
                    spend[r['subscriptionId'].lower()] += r.get('cost') or 0
            top = [sid for sid, v in sorted(spend.items(), key=lambda kv: -kv[1]) if v > 0][:COST_TOP_SUBSCRIPTIONS]
            if top:
                return [s for s in self.subs if s['id'].lower() in top]
        return self.subs

    def phase_cost(self):
        """Bandwidth / VNet transfer of the review month, for cross-region placement (P8)."""
        y, m = map(int, self.ws.month.split('-'))
        first = date(y, m, 1)
        last = date(y + (m == 12), m % 12 + 1, 1)
        out = []
        for s in self.cost_subscriptions():
            url = f"{ARM}/subscriptions/{s['id']}/providers/Microsoft.CostManagement/query?api-version=2023-11-01"
            for grp in (['MeterSubCategory', 'Meter'], ['ResourceId', 'Meter']):
                body = {'type': 'ActualCost', 'timeframe': 'Custom',
                        'timePeriod': {'from': f'{first.isoformat()}T00:00:00Z', 'to': f'{last.isoformat()}T00:00:00Z'},
                        'dataset': {'granularity': 'None',
                                    'aggregation': {'totalCost': {'name': 'Cost', 'function': 'Sum'},
                                                    'usage': {'name': 'UsageQuantity', 'function': 'Sum'}},
                                    'grouping': [{'type': 'Dimension', 'name': g} for g in grp],
                                    'filter': {'dimensions': {'name': 'MeterCategory', 'operator': 'In',
                                                              'values': ['Bandwidth', 'Virtual Network']}}}}
                st, data, err = self.client.request('POST', url, 'P8', f'{s["name"]}/{"+".join(grp)}', body=body)
                props = (data or {}).get('properties') or {}
                cols = [c['name'] for c in props.get('columns') or []]
                out.append({'subscription': s['name'], 'subscriptionId': s['id'], 'grouping': grp, 'status': st, 'error': err,
                            'rows': [dict(zip(cols, r)) for r in props.get('rows') or []], 'nextLink': props.get('nextLink')})
        self.save('cost/bandwidth-month.json', {'month': self.ws.month, 'results': out})


def collect(ws, cfg, client, window, log=print):
    c = Collector(ws, cfg, client, window, log)
    first_call = len(client.calls)
    log(f'性能效率：采集 {len(c.subs)} 个订阅，指标窗口 {window["start"][:10]} 至 {window["end"][:10]}')
    c.arg(list(ARG_QUERIES))
    for phase in (c.phase_compute, c.phase_aks, c.phase_db, c.phase_ai, c.phase_storage, c.phase_edge, c.phase_la, c.phase_cost):
        phase()
    calls = client.calls[first_call:]
    c.save('index.json', {'calls': calls, 'count': len(calls)})
    c.save('manifest.json', {'collectedAt': now(), 'window': window})
    denied = sum(1 for x in calls if x.get('status') in (401, 403))
    log(f'性能效率：{len(calls)} 次读取，其中 {denied} 次无权限（已记录，不按无问题处理）')
