"""Reliability (R1-R12): read-only collection.

Layout under raw/waf/reliability/ (same as earlier inspections' reliability/raw/, so earlier raw data can be replayed;
the performance pillar reads arg/*.json and aks/*.json from here):
  arg/<name>.json, aks/{clusters,vnets,vnet-usages,k8s-versions}.json, storage/{blobservices,used-capacity}.json,
  db/detail.json, backup/vaults.json, metrics/{lb-snat,natgw}.json, quota/compute-usages.json,
  health/current-per-resource.json, afd/custom-domains.json, activity/failed-ops.json,
  advisor-all.json, index.json (call records), manifest.json (collectedAt, window)
"""
from __future__ import annotations

import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from ..common import Raw, advisor_problem, enabled, load_scope, now

WORKERS = 4
AKS_API = '2025-05-01'

ARG_QUERIES = {
    'vms': "resources | where type =~ 'microsoft.compute/virtualmachines' | project id,name,type,location,resourceGroup,subscriptionId,zones,tags,properties,identity",
    'vmss': "resources | where type =~ 'microsoft.compute/virtualmachinescalesets' | project id,name,type,location,resourceGroup,subscriptionId,zones,tags,sku,properties",
    'aks': "resources | where type =~ 'microsoft.containerservice/managedclusters' | project id,name,location,resourceGroup,subscriptionId,sku,tags,properties",
    'mysql': "resources | where type =~ 'microsoft.dbformysql/flexibleservers' | project id,name,type,location,resourceGroup,subscriptionId,sku,tags,zones,properties",
    'postgres': "resources | where type =~ 'microsoft.dbforpostgresql/flexibleservers' | project id,name,type,location,resourceGroup,subscriptionId,sku,tags,zones,properties",
    'redis': "resources | where type =~ 'microsoft.cache/redis' | project id,name,type,location,resourceGroup,subscriptionId,tags,zones,properties",
    'redisenterprise': "resources | where type =~ 'microsoft.cache/redisenterprise' | project id,name,type,location,resourceGroup,subscriptionId,sku,tags,zones,properties",
    'mongoclusters': "resources | where type =~ 'microsoft.documentdb/mongoclusters' | project id,name,type,location,resourceGroup,subscriptionId,tags,properties",
    'storage': "resources | where type =~ 'microsoft.storage/storageaccounts' | project id,name,type,location,resourceGroup,subscriptionId,sku,kind,tags,properties",
    'appgw': "resources | where type =~ 'microsoft.network/applicationgateways' | project id,name,type,location,resourceGroup,subscriptionId,zones,tags,properties",
    'lbs': "resources | where type =~ 'microsoft.network/loadbalancers' | project id,name,type,location,resourceGroup,subscriptionId,sku,tags,properties",
    'pips': "resources | where type =~ 'microsoft.network/publicipaddresses' | project id,name,type,location,resourceGroup,subscriptionId,sku,zones,tags,properties",
    'natgw': "resources | where type =~ 'microsoft.network/natgateways' | project id,name,type,location,resourceGroup,subscriptionId,sku,zones,tags,properties",
    'vnets': "resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand s=properties.subnets | project id,name,location,resourceGroup,subscriptionId,subnetName=tostring(s.name),subnetId=tostring(s.id),prefix=tostring(s.properties.addressPrefix),prefixes=s.properties.addressPrefixes,ipConfigCount=array_length(s.properties.ipConfigurations),delegations=s.properties.delegations,natGateway=s.properties.natGateway",
    'vnetgw': "resources | where type in~ ('microsoft.network/virtualnetworkgateways','microsoft.network/expressroutecircuits','microsoft.network/bastionhosts') | project id,name,type,location,resourceGroup,subscriptionId,sku,zones,tags,properties",
    'rsvaults': "resources | where type in~ ('microsoft.recoveryservices/vaults','microsoft.dataprotection/backupvaults') | project id,name,type,location,resourceGroup,subscriptionId,sku,tags,properties",
    'protecteditems': "recoveryservicesresources | where type in~ ('microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems','microsoft.dataprotection/backupvaults/backupinstances') | project id,name,type,subscriptionId,resourceGroup,properties",
    'disks': "resources | where type =~ 'microsoft.compute/disks' | project id,name,location,resourceGroup,subscriptionId,sku,zones,managedBy=tostring(managedBy),diskSizeGB=toint(properties.diskSizeGB),diskState=tostring(properties.diskState),tags",
    'health': "healthresources | where type =~ 'microsoft.resourcehealth/availabilitystatuses' | extend rid=tolower(tostring(properties.targetResourceId)), rtype=tolower(tostring(properties.targetResourceType)) | where rtype in~ ('microsoft.containerservice/managedclusters','microsoft.compute/virtualmachines','microsoft.dbformysql/flexibleservers','microsoft.dbforpostgresql/flexibleservers','microsoft.cache/redis','microsoft.cache/redisenterprise','microsoft.documentdb/mongoclusters','microsoft.network/applicationgateways','microsoft.network/loadbalancers','microsoft.storage/storageaccounts','microsoft.compute/virtualmachinescalesets','microsoft.network/natgateways') | project id,subscriptionId,rid,rtype,status=tostring(properties.availabilityState),reason=tostring(properties.reasonType),summary=tostring(properties.summary),occurred=tostring(properties.occurredTime),reported=tostring(properties.reportedTime)",
}
# R9 retirements and version end of support (0.6.6). Service Health and Advisor queries follow Microsoft Learn
# (service-health/resource-graph-samples, service-retirement-unified-impact-queries).
_RETIREMENT_EVENTS = ("servicehealthresources | where type =~ 'microsoft.resourcehealth/events' | extend p = parse_json(properties) "
                      "| where tostring(p.EventType) == 'HealthAdvisory' and tostring(p.EventSubType) == 'Retirement'")
ARG_QUERIES.update({
    'retirements': _RETIREMENT_EVENTS + " | project id, subscriptionId, trackingId = tostring(p.TrackingId), title = tostring(p.Title), "
                   "summary = tostring(p.Summary), status = tostring(p.Status), retirementDate = tostring(todatetime(p.ImpactMitigationTime)), "
                   "impactStart = tostring(todatetime(p.ImpactStartTime)), impact = p.Impact",
    'retirement_resources': "servicehealthresources | where type =~ 'microsoft.resourcehealth/events/impactedresources' "
                            "| extend p = parse_json(properties), trackingId = tostring(split(id, '/')[6]) "
                            "| join kind=inner (" + _RETIREMENT_EVENTS + " | distinct trackingId = tostring(p.TrackingId)) on trackingId "
                            "| project id, subscriptionId, trackingId, targetResourceId = tostring(p.targetResourceId), "
                            "targetResourceType = tostring(p.targetResourceType)",
    'retirement_advisor': """advisorresources
| where type == "microsoft.advisor/metadata"
| extend props = parse_json(properties)
| where props.recommendationCategory == "HighAvailability"
| where props.recommendationSubCategory == "ServiceUpgradeAndRetirement"
| where isnotempty(props.sourceProperties.serviceRetirement.serviceHealth.trackingIds)
| mv-expand trackingId = props.sourceProperties.serviceRetirement.serviceHealth.trackingIds
| extend trackingId = tostring(trackingId)
| extend recommendationTypeId = tostring(props.recommendationTypeId)
| distinct trackingId, recommendationTypeId
| join kind=inner (
    advisorresources
    | where type == "microsoft.advisor/recommendations"
    | extend props = parse_json(properties)
    | where props.extendedProperties.recommendationSubCategory == "ServiceUpgradeAndRetirement"
    | where isempty(props.tracked)
    | where tostring(props.platformState) == "New"
    | extend recommendationTypeId = tostring(props.recommendationTypeId)
    | extend resourceId = tolower(tostring(props.resourceMetadata.resourceId))
    | distinct recommendationTypeId, resourceId, subscriptionId
) on recommendationTypeId
| distinct trackingId, resourceId, subscriptionId""",
    'webapps': "resources | where type =~ 'microsoft.web/sites' | project id, name, kind, location, resourceGroup, subscriptionId, tags, "
               "state = tostring(properties.state)",
    # only the stack version fields: web config can also hold machine keys and storage access keys, which are never read
    'webconfig': "appserviceresources | where type =~ 'microsoft.web/sites/config' | extend p = parse_json(properties) "
                 "| project id, subscriptionId, linuxFxVersion = tostring(coalesce(p.LinuxFxVersion, p.linuxFxVersion)), "
                 "windowsFxVersion = tostring(coalesce(p.WindowsFxVersion, p.windowsFxVersion)), "
                 "netFrameworkVersion = tostring(coalesce(p.NetFrameworkVersion, p.netFrameworkVersion)), "
                 "phpVersion = tostring(coalesce(p.PhpVersion, p.phpVersion)), pythonVersion = tostring(coalesce(p.PythonVersion, p.pythonVersion)), "
                 "nodeVersion = tostring(coalesce(p.NodeVersion, p.nodeVersion)), javaVersion = tostring(coalesce(p.JavaVersion, p.javaVersion)), "
                 "powerShellVersion = tostring(coalesce(p.PowerShellVersion, p.powerShellVersion))",
})
RUNTIME_FIELDS = ('linuxFxVersion', 'windowsFxVersion', 'netFrameworkVersion', 'phpVersion', 'pythonVersion', 'nodeVersion', 'javaVersion',
                  'powerShellVersion')
WEB_API = '2023-12-01'


def runtime_fields(config: dict) -> dict:
    """Keep only the stack version fields of a site's web config; everything else is dropped before saving."""
    return {k: config.get(k) for k in RUNTIME_FIELDS if config.get(k) not in (None, '')}


def pmap(fn, items):
    with ThreadPoolExecutor(WORKERS) as ex:
        return list(ex.map(fn, items))


class _Collector:
    def __init__(self, ws, client, window, log):
        self.raw, self.c, self.window, self.log = Raw(ws, 'reliability'), client, window, log
        self.subs = enabled(load_scope(ws))

    def rows(self, name):
        return (self.raw.load(f'arg/{name}.json') or {}).get('rows') or []

    # ------------------------------------------------------------------ Resource Graph
    def arg(self):
        ids = [s['id'] for s in self.subs]
        summary = {}
        for name, q in ARG_QUERIES.items():
            rows, st, err = self.c.arg(q, ids, 'ARG', name)
            self.raw.save(f'arg/{name}.json', {'query': q, 'status': st, 'error': err, 'rows': rows})
            summary[name] = {'status': st, 'error': err, 'rows': None if rows is None else len(rows)}
        self.raw.save('arg/_summary.json', summary)

    # ------------------------------------------------------------------ AKS
    def aks(self):
        c = self.c
        clusters = []
        for s in sorted({r['subscriptionId'] for r in self.rows('aks')}):
            items, st, err = c.get_all(f'/subscriptions/{s}/providers/Microsoft.ContainerService/managedClusters?api-version={AKS_API}', 'R1-R9', f'aks-list {s}')
            if items is None:
                clusters.append({'subscriptionId': s, 'error': err, 'status': st})
            for it in items or []:
                clusters.append({'subscriptionId': s, 'cluster': it})

        def detail(entry):
            if 'cluster' not in entry:
                return entry
            cl, out = entry['cluster'], dict(entry)
            cid = cl['id']
            out['agentPools'], out['agentPoolsStatus'], out['agentPoolsError'] = c.get_all(f'{cid}/agentPools?api-version={AKS_API}', 'R1-R2', cl['name'])
            st, d, e = c.get(f'{cid}/upgradeProfiles/default?api-version={AKS_API}', 'R9', cl['name'])
            out['upgradeProfile'] = {'status': st, 'error': e, 'data': d}
            pup = {}
            for p in out['agentPools'] or []:
                st, d, e = c.get(f"{cid}/agentPools/{p['name']}/upgradeProfiles/default?api-version={AKS_API}", 'R9', f"{cl['name']}/{p['name']}")
                pup[p['name']] = {'status': st, 'error': e, 'data': d}
            out['poolUpgradeProfiles'] = pup
            nrg = cl['properties'].get('nodeResourceGroup')
            vmss, st, e = c.get_all(f"/subscriptions/{entry['subscriptionId']}/resourceGroups/{nrg}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2024-07-01",
                                    'R1-R2', f'{nrg} vmss')
            out['nodeVmss'] = {'status': st, 'error': e, 'items': vmss}
            nics, insts = {}, {}
            for v in vmss or []:
                n, st, e = c.get_all(f"{v['id']}/networkInterfaces?api-version=2018-10-01", 'R1', f"{v['name']} nics")
                nics[v['name']] = {'status': st, 'error': e, 'items': n}
                vi, st, e = c.get_all(f"{v['id']}/virtualMachines?api-version=2024-07-01", 'R2', f"{v['name']} instances")
                insts[v['name']] = {'status': st, 'error': e, 'items': [
                    {'name': x.get('name'), 'instanceId': x.get('instanceId'), 'zones': x.get('zones'),
                     'provisioningState': (x.get('properties') or {}).get('provisioningState'),
                     'latestModelApplied': (x.get('properties') or {}).get('latestModelApplied')} for x in (vi or [])]}
            out['nodeVmssNics'], out['nodeVmssInstances'] = nics, insts
            return out

        detailed = pmap(detail, clusters)
        vnet_ids, locations = set(), set()
        for e in detailed:
            if 'cluster' not in e:
                continue
            locations.add((e['subscriptionId'], e['cluster']['location']))
            for p in e.get('agentPools') or []:
                for k in ('vnetSubnetID', 'podSubnetID'):
                    if p['properties'].get(k):
                        vnet_ids.add(p['properties'][k].split('/subnets/')[0])
        vnets = {}
        for vid in sorted(vnet_ids):
            st, d, e = c.get(f'{vid}?api-version=2024-05-01', 'R1', vid.split('/')[-1])
            vnets[vid] = _vnet_summary(d) if d and st == 200 else {'status': st, 'error': e}
            vnets[vid]['status'] = st
        versions = {}
        for s, loc in sorted(locations):
            st, d, e = c.get(f'/subscriptions/{s}/providers/Microsoft.ContainerService/locations/{loc}/kubernetesVersions?api-version={AKS_API}', 'R9', f'k8s versions {loc}')
            versions[f'{s}/{loc}'] = {'status': st, 'error': e, 'data': d}
        self.raw.save('aks/clusters.json', detailed)
        self.raw.save('aks/vnets.json', vnets)
        self.raw.save('aks/k8s-versions.json', versions)
        usages = {}
        for vid in vnets:
            items, st, e = c.get_all(f'{vid}/usages?api-version=2024-05-01', 'R1', vid.split('/')[-1] + ' usages')
            usages[vid] = {'status': st, 'error': e, 'items': items}
        self.raw.save('aks/vnet-usages.json', usages)

    # ------------------------------------------------------------------ storage
    def storage(self):
        def blob(r):
            st, d, e = self.c.get(f"{r['id']}/blobServices/default?api-version=2023-05-01", 'R6', r['name'])
            return {'id': r['id'], 'name': r['name'], 'status': st, 'error': e, 'blobService': d}

        end = self.window['end']
        start = (datetime.fromisoformat(end.replace('Z', '+00:00')) - timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ')

        def capacity(r):
            q = {'api-version': '2023-10-01', 'metricnames': 'UsedCapacity', 'aggregation': 'Average', 'interval': 'PT1H', 'timespan': f'{start}/{end}'}
            st, d, e = self.c.get(f"{r['id']}/providers/Microsoft.Insights/metrics?" + urllib.parse.urlencode(q), 'R6', r['name'] + ' UsedCapacity')
            pts = [p.get('average') for v in (d or {}).get('value', []) for ts in v.get('timeseries', []) for p in ts.get('data', [])
                   if p.get('average') is not None]
            return {'id': r['id'], 'name': r['name'], 'status': st, 'error': e, 'lastUsedCapacityBytes': pts[-1] if pts else None, 'points': len(pts)}

        rows = self.rows('storage')
        self.raw.save('storage/blobservices.json', pmap(blob, rows))
        self.raw.save('storage/used-capacity.json', pmap(capacity, rows))

    # ------------------------------------------------------------------ databases
    def databases(self):
        c, out = self.c, {'redisenterprise': [], 'redisLinkedServers': [], 'mongo': []}
        for r in self.rows('redisenterprise'):
            st, d, e = c.get(f"{r['id']}?api-version=2025-07-01", 'R5', r['name'])
            dbs, st2, e2 = c.get_all(f"{r['id']}/databases?api-version=2025-07-01", 'R5', r['name'] + '/databases')
            out['redisenterprise'].append({'id': r['id'], 'status': st, 'error': e, 'cluster': d, 'dbStatus': st2, 'dbError': e2, 'databases': dbs})
        for r in self.rows('redis'):
            items, st, e = c.get_all(f"{r['id']}/linkedServers?api-version=2024-11-01", 'R5', r['name'] + '/linkedServers')
            out['redisLinkedServers'].append({'id': r['id'], 'status': st, 'error': e, 'items': items})
        for r in self.rows('mongoclusters'):
            st, d, e = c.get(f"{r['id']}?api-version=2024-07-01", 'R5', r['name'])
            out['mongo'].append({'id': r['id'], 'status': st, 'error': e, 'cluster': d})
        for kind, api in (('mysql', '2023-12-30'), ('postgres', '2024-08-01')):
            servers = []
            for r in self.rows(kind):
                st, d, e = c.get(f"{r['id']}?api-version={api}", 'R5', r['name'])
                servers.append({'id': r['id'], 'status': st, 'error': e, 'server': d})
            out[kind] = servers
        self.raw.save('db/detail.json', out)

    # ------------------------------------------------------------------ backup
    def backup(self):
        c, res = self.c, {'vaultLists': {}, 'rsVaults': [], 'backupVaults': []}

        def vault_lists(s):
            a, st1, e1 = c.get_all(f"/subscriptions/{s['id']}/providers/Microsoft.RecoveryServices/vaults?api-version=2024-04-01", 'R7', f"{s['name']} rsvaults")
            b, st2, e2 = c.get_all(f"/subscriptions/{s['id']}/providers/Microsoft.DataProtection/backupVaults?api-version=2024-04-01", 'R7', f"{s['name']} backupvaults")
            return s['id'], {'rs': {'status': st1, 'error': e1, 'items': a}, 'bv': {'status': st2, 'error': e2, 'items': b}}

        for sid, v in pmap(vault_lists, self.subs):
            res['vaultLists'][sid] = v
            for vault in v['rs']['items'] or []:
                vid = vault['id']
                pi, st, e = c.get_all(f'{vid}/backupProtectedItems?api-version=2024-04-01', 'R7', vault['name'])
                st2, sc, e2 = c.get(f'{vid}/backupstorageconfig/vaultstorageconfig?api-version=2024-04-01', 'R7', vault['name'] + ' storagecfg')
                st3, bc, e3 = c.get(f'{vid}/backupconfig/vaultconfig?api-version=2024-04-01', 'R7', vault['name'] + ' vaultcfg')
                res['rsVaults'].append({'vault': vault, 'protectedItems': {'status': st, 'error': e, 'items': pi},
                                        'storageConfig': {'status': st2, 'error': e2, 'data': sc}, 'vaultConfig': {'status': st3, 'error': e3, 'data': bc}})
            for vault in v['bv']['items'] or []:
                bi, st, e = c.get_all(f"{vault['id']}/backupInstances?api-version=2024-04-01", 'R7', vault['name'])
                res['backupVaults'].append({'vault': vault, 'backupInstances': {'status': st, 'error': e, 'items': bi}})
        self.raw.save('backup/vaults.json', res)

    # ------------------------------------------------------------------ SNAT metrics
    def _metric(self, rid, names, aggregation, flt=None, target=''):
        q = {'api-version': '2023-10-01', 'metricnames': names, 'aggregation': aggregation, 'interval': 'P1D',
             'timespan': f"{self.window['start']}/{self.window['end']}", 'top': '200'}
        if flt:
            q['$filter'] = flt
        st, d, e = self.c.get(f'{rid}/providers/Microsoft.Insights/metrics?' + urllib.parse.urlencode(q, quote_via=urllib.parse.quote), 'R8', target)
        return {'status': st, 'error': e, 'data': d}

    def metrics(self):
        lbs = [lb for lb in self.rows('lbs') if (lb.get('sku') or {}).get('name', '').lower() == 'standard'
               and (lb['properties'].get('outboundRules') or lb['name'].lower() == 'kubernetes')]

        def lb_metrics(lb):
            return {'id': lb['id'], 'name': lb['name'],
                    'snatConn': self._metric(lb['id'], 'SnatConnectionCount', 'Total', "ConnectionState eq '*'", lb['name']),
                    'ports': self._metric(lb['id'], 'UsedSnatPorts,AllocatedSnatPorts', 'Average,Maximum', "BackendIPAddress eq '*'", lb['name'])}

        def nat_metrics(n):
            return {'id': n['id'], 'name': n['name'],
                    'snatConn': self._metric(n['id'], 'SNATConnectionCount', 'Total', "ConnectionState eq '*'", n['name']),
                    'droppedPackets': self._metric(n['id'], 'PacketDropCount', 'Total', target=n['name']),
                    'datapath': self._metric(n['id'], 'DatapathAvailability', 'Average,Minimum', target=n['name'])}

        self.raw.save('metrics/lb-snat.json', pmap(lb_metrics, lbs))
        self.raw.save('metrics/natgw.json', pmap(nat_metrics, self.rows('natgw')))

    # ------------------------------------------------------------------ quota
    def quota(self):
        pairs = {(r['subscriptionId'], r['location'].lower()) for f in ('vms', 'vmss') for r in self.rows(f)}

        def one(p):
            s, loc = p
            items, st, e = self.c.get_all(f'/subscriptions/{s}/providers/Microsoft.Compute/locations/{loc}/usages?api-version=2024-07-01', 'R10', f'{s}/{loc}')
            return {'subscriptionId': s, 'location': loc, 'status': st, 'error': e,
                    'usages': [u for u in items or [] if u.get('currentValue')] if items is not None else None,
                    'regionalTotal': next((u for u in items or [] if u['name']['value'] == 'cores'), None)}

        self.raw.save('quota/compute-usages.json', pmap(one, sorted(pairs)))

    # ------------------------------------------------------------------ Advisor
    def advisor(self):
        def one(s):
            items, st, e = self.c.get_all(f"/subscriptions/{s['id']}/providers/Microsoft.Advisor/recommendations?api-version=2023-01-01", 'R9-advisor', s['name'])
            return {'subscriptionId': s['id'], 'subscriptionName': s['name'], 'status': st, 'error': e, 'recommendations': items}

        res = pmap(one, self.subs)
        self.raw.save('advisor-all.json', {
            'collectedAt': now(), 'apiVersion': '2023-01-01', 'note': 'All Advisor categories for every enabled subscription in scope.',
            'subscriptions': [{k: v for k, v in r.items() if k != 'recommendations'} | {'count': None if r['recommendations'] is None else len(r['recommendations'])} for r in res],
            'recommendations': [dict(x, _subscriptionName=r['subscriptionName']) for r in res for x in (r['recommendations'] or [])],
            'complete': True})

    # ------------------------------------------------------------------ Resource Health
    def health(self):
        targets = [r['id'] for f in ('aks', 'mysql', 'postgres', 'redis', 'redisenterprise', 'mongoclusters', 'appgw') for r in self.rows(f)]

        def one(rid):
            st, d, e = self.c.get(f'{rid}/providers/Microsoft.ResourceHealth/availabilityStatuses/current?api-version=2025-05-01', 'R11', rid.split('/')[-1])
            pr = (d or {}).get('properties') or {}
            return {'id': rid, 'status': st, 'error': e, 'availabilityState': pr.get('availabilityState'), 'reasonType': pr.get('reasonType'),
                    'summary': pr.get('summary'), 'occuredTime': pr.get('occuredTime') or pr.get('occurredTime'),
                    'reportedTime': pr.get('reportedTime'), 'detailedStatus': pr.get('detailedStatus')}

        self.raw.save('health/current-per-resource.json', pmap(one, targets))

    # ------------------------------------------------------------------ App Service stack versions (R9)
    def app_runtime(self):
        """Stack versions of sites that Resource Graph did not return: one ARM GET of config/web per site, version fields only."""
        known = {r['id'].lower().rsplit('/config/', 1)[0] for r in self.rows('webconfig') if runtime_fields(r)}
        missing = [r for r in self.rows('webapps') if r['id'].lower() not in known]

        def one(site):
            try:
                st, d, e = self.c.get(f"{site['id']}/config/web?api-version={WEB_API}", 'R9', site['name'] + ' config/web')
            except Exception as exc:  # a failed read is recorded, never treated as "no old runtime"
                st, d, e = None, None, f'{type(exc).__name__}: {exc}'
            return {'id': site['id'], 'status': st, 'error': e, 'versions': runtime_fields((d or {}).get('properties') or {})}

        self.raw.save('lifecycle/app-config.json', {'collectedAt': now(), 'sites': pmap(one, missing)})

    # ------------------------------------------------------------------ Front Door certificates
    def front_door(self):
        """Custom domains of Front Door profiles that Advisor flags for certificates. Only certificate metadata
        (expiry, subject) is kept from the AFD secret resource, which holds a Key Vault reference, not key material."""
        c = self.c

        def cert_meta(x):
            tls = x['properties'].get('tlsSettings') or {}
            sid = (tls.get('secret') or {}).get('id')
            if not sid or tls.get('certificateType') != 'CustomerCertificate':
                return None
            st, d, e = c.get(f'{sid}?api-version=2024-02-01', 'R9', x['name'] + ' cert metadata')
            prm = ((d or {}).get('properties') or {}).get('parameters') or {}
            return {'status': st, 'error': e, 'expirationDate': prm.get('expirationDate'), 'subject': prm.get('subject'),
                    'useLatestVersion': prm.get('useLatestVersion'), 'certificateAuthority': prm.get('certificateAuthority')}

        recs = (self.raw.load('advisor-all.json') or {}).get('recommendations') or []
        profiles = sorted({r['properties']['resourceMetadata']['resourceId'] for r in recs
                           if 'Front Door customer certificate' in advisor_problem(r)})
        res = []
        for pid in profiles:
            items, st, e = c.get_all(f'{pid}/customDomains?api-version=2024-02-01', 'R9', pid.split('/')[-1] + ' customDomains')
            res.append({'profileId': pid, 'status': st, 'error': e, 'customDomains': [
                {'name': x['name'], 'hostName': x['properties'].get('hostName'),
                 'tlsSettings': {k: v for k, v in (x['properties'].get('tlsSettings') or {}).items() if k != 'secret'},
                 'secretRefName': (((x['properties'].get('tlsSettings') or {}).get('secret') or {}).get('id') or '').split('/')[-1],
                 'domainValidationState': x['properties'].get('domainValidationState'),
                 'deploymentStatus': x['properties'].get('deploymentStatus'), 'provisioningState': x['properties'].get('provisioningState'),
                 'certificateMeta': cert_meta(x)} for x in items or []]})
        self.raw.save('afd/custom-domains.json', res)

    # ------------------------------------------------------------------ activity log (failed operations)
    def activity(self):
        flt = f"eventTimestamp ge '{self.window['start']}' and eventTimestamp le '{self.window['snapshot']}T23:59:59Z' and status eq 'Failed'"
        sel = 'eventTimestamp,operationName,status,subStatus,resourceId,resourceGroupName,resourceProviderName,properties,caller,correlationId,level,resourceType'

        def one(s):
            url = (f"/subscriptions/{s['id']}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01"
                   f'&$filter={urllib.parse.quote(flt)}&$select={sel}')
            items, st, e = self.c.get_all(url, 'R12', s['name'], max_pages=600)
            events = [{'t': x.get('eventTimestamp'), 'op': (x.get('operationName') or {}).get('value'),
                       'status': (x.get('status') or {}).get('value'), 'subStatus': (x.get('subStatus') or {}).get('value'),
                       'resourceId': x.get('resourceId'), 'rg': x.get('resourceGroupName'),
                       'statusCode': (x.get('properties') or {}).get('statusCode'),
                       'statusMessage': ((x.get('properties') or {}).get('statusMessage') or '')[:1500],
                       'caller': x.get('caller'), 'correlationId': x.get('correlationId')} for x in items or []]
            return {'subscriptionId': s['id'], 'subscriptionName': s['name'], 'status': st, 'error': e, 'events': events if items is not None else None}

        self.raw.save('activity/failed-ops.json', pmap(one, self.subs))


def _vnet_summary(d):
    """Subnet summary with ipConfiguration ids only."""
    subnets = []
    for sn in d['properties'].get('subnets', []):
        pr = sn['properties']
        subnets.append({'id': sn['id'], 'name': sn['name'], 'addressPrefix': pr.get('addressPrefix'), 'addressPrefixes': pr.get('addressPrefixes'),
                        'ipConfigurationCount': len(pr.get('ipConfigurations') or []),
                        'ipConfigurations': [x['id'] for x in pr.get('ipConfigurations') or []],
                        'natGateway': pr.get('natGateway'),
                        'delegations': [x.get('properties', {}).get('serviceName') for x in pr.get('delegations') or []]})
    return {'name': d['name'], 'addressSpace': d['properties'].get('addressSpace'), 'subnets': subnets}


PHASES = ['arg', 'aks', 'storage', 'databases', 'backup', 'metrics', 'quota', 'advisor', 'health', 'front_door', 'activity', 'app_runtime']


def collect(ws, cfg, client, window, log=print):
    col = _Collector(ws, client, window, log)
    first_call = len(client.calls)
    log(f'可靠性采集：{len(col.subs)} 个订阅，时间窗 {window["start"][:10]} 至 {window["end"][:10]}')
    for phase in PHASES:
        getattr(col, phase)()
        log(f'  可靠性 {phase} 完成')
    calls = client.calls[first_call:]
    col.raw.save('index.json', {'count': len(calls), 'calls': calls})
    col.raw.save('manifest.json', {'collectedAt': now(), 'window': window})
    failed = sum(1 for x in calls if x['status'] != 200)
    log(f'可靠性采集完成：{len(calls)} 次读取，{failed} 次未成功（已记录，不按无问题处理）')
