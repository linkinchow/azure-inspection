"""Read-only collection for the network security checks (S-N1..S-N8).

Only Resource Graph queries and ARM GET through the ReadOnlyClient; no keys, connection strings or data planes.
Layout under raw/waf/security_network/ (same as earlier inspections, so earlier raw data can be replayed):
  raw/arg/<key>.json        Resource Graph rows per resource type, raw/arg/_errors.json
  raw/arm/<kind>.json       {resourceId: {'http','error','data'}} detail reads (firewall rules, server parameters, ...)
  raw/meta.json             collection time, enabled/disabled subscriptions
  raw/pe-disconnected/      private endpoint connection states and follow-up reads for S-N8
  index.json                call log {'calls': [{check, target, method, url, http, error, elapsed, at}]}
  manifest.json             {'collectedAt', 'window'}
"""
from __future__ import annotations

import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from ..common import Raw, enabled, load_scope, now

ARM = 'https://management.azure.com'
PILLAR = 'security_network'

ARG_TYPES = {
    'vnets': "resources | where type =~ 'microsoft.network/virtualnetworks'",
    'nsgs': "resources | where type =~ 'microsoft.network/networksecuritygroups'",
    'nics': "resources | where type =~ 'microsoft.network/networkinterfaces'",
    'publicips': "resources | where type =~ 'microsoft.network/publicipaddresses'",
    'publicipprefixes': "resources | where type =~ 'microsoft.network/publicipprefixes'",
    'loadbalancers': "resources | where type =~ 'microsoft.network/loadbalancers'",
    'appgateways': "resources | where type =~ 'microsoft.network/applicationgateways'",
    'appgw_wafpolicies': "resources | where type =~ 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies'",
    'fd_wafpolicies': "resources | where type =~ 'microsoft.network/frontdoorwebapplicationfirewallpolicies'",
    'frontdoors_classic': "resources | where type =~ 'microsoft.network/frontdoors'",
    'cdn_profiles': "resources | where type =~ 'microsoft.cdn/profiles'",
    'pls': "resources | where type =~ 'microsoft.network/privatelinkservices'",
    'privateendpoints': "resources | where type =~ 'microsoft.network/privateendpoints'",
    'natgateways': "resources | where type =~ 'microsoft.network/natgateways'",
    'bastions': "resources | where type =~ 'microsoft.network/bastionhosts'",
    'firewalls': "resources | where type =~ 'microsoft.network/azurefirewalls'",
    'vngateways': "resources | where type =~ 'microsoft.network/virtualnetworkgateways'",
    'vms': ("resources | where type =~ 'microsoft.compute/virtualmachines' | project id,name,type,location,resourceGroup,subscriptionId,tags,"
            "properties=pack('networkProfile',properties.networkProfile,'storageProfile',pack('osDisk',pack('osType',properties.storageProfile.osDisk.osType)),"
            "'osProfile',pack('computerName',properties.osProfile.computerName,'linuxConfiguration',"
            "pack('disablePasswordAuthentication',properties.osProfile.linuxConfiguration.disablePasswordAuthentication)),"
            "'powerState',properties.extended.instanceView.powerState.code)"),
    'vmss': ("resources | where type =~ 'microsoft.compute/virtualmachinescalesets' | project id,name,type,location,resourceGroup,subscriptionId,tags,sku,"
             "properties=pack('networkProfile',properties.virtualMachineProfile.networkProfile,'orchestrationMode',properties.orchestrationMode)"),
    'mysql': "resources | where type =~ 'microsoft.dbformysql/flexibleservers'",
    'mysql_single': "resources | where type =~ 'microsoft.dbformysql/servers'",
    'postgres': "resources | where type =~ 'microsoft.dbforpostgresql/flexibleservers'",
    'postgres_single': "resources | where type =~ 'microsoft.dbforpostgresql/servers'",
    'sqlservers': "resources | where type =~ 'microsoft.sql/servers'",
    'redis': "resources | where type =~ 'microsoft.cache/redis'",
    'redisenterprise': "resources | where type =~ 'microsoft.cache/redisenterprise'",
    'cosmos': "resources | where type =~ 'microsoft.documentdb/databaseaccounts'",
    'mongoclusters': "resources | where type =~ 'microsoft.documentdb/mongoclusters'",
    'storage': "resources | where type =~ 'microsoft.storage/storageaccounts'",
    'keyvaults': "resources | where type =~ 'microsoft.keyvault/vaults'",
    'registries': "resources | where type =~ 'microsoft.containerregistry/registries'",
    'cognitive': "resources | where type =~ 'microsoft.cognitiveservices/accounts'",
    'loganalytics': ("resources | where type =~ 'microsoft.operationalinsights/workspaces' | project id,name,type,location,resourceGroup,subscriptionId,tags,"
                     "properties=pack('publicNetworkAccessForIngestion',properties.publicNetworkAccessForIngestion,"
                     "'publicNetworkAccessForQuery',properties.publicNetworkAccessForQuery,'features',properties.features,'sku',properties.sku)"),
    'aks': ("resources | where type =~ 'microsoft.containerservice/managedclusters' | project id,name,type,location,resourceGroup,subscriptionId,tags,"
            "properties=pack('nodeResourceGroup',properties.nodeResourceGroup,'agentPoolProfiles',properties.agentPoolProfiles,"
            "'networkProfile',properties.networkProfile,'apiServerAccessProfile',properties.apiServerAccessProfile)"),
    'eventhubs': "resources | where type =~ 'microsoft.eventhub/namespaces'",
    'servicebus': "resources | where type =~ 'microsoft.servicebus/namespaces'",
    'webapps': ("resources | where type =~ 'microsoft.web/sites' | project id,name,type,kind,location,resourceGroup,subscriptionId,tags,"
                "properties=pack('publicNetworkAccess',properties.publicNetworkAccess,'httpsOnly',properties.httpsOnly,'state',properties.state,"
                "'defaultHostName',properties.defaultHostName,'siteConfig',pack('minTlsVersion',properties.siteConfig.minTlsVersion,"
                "'ipSecurityRestrictions',properties.siteConfig.ipSecurityRestrictions,'ftpsState',properties.siteConfig.ftpsState),"
                "'virtualNetworkSubnetId',properties.virtualNetworkSubnetId)"),
    'subscriptions_visible': "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId,name,properties.state",
}

DETAIL_KINDS = ('mysql_fw', 'mysql_cfg', 'pg_fw', 'pg_cfg', 'redis_fw', 'redisent_db', 'mongo_fw', 'containers', 'afd_secpol',
                'afd_endpoints', 'sql_fw')

PE_QUERY = """resources | where type =~ 'microsoft.network/privateendpoints'
| extend conns = array_concat(coalesce(properties.privateLinkServiceConnections, dynamic([])), coalesce(properties.manualPrivateLinkServiceConnections, dynamic([])))
| mv-expand c = conns
| extend status = tostring(c.properties.privateLinkServiceConnectionState.status), target = tolower(tostring(c.properties.privateLinkServiceId))
| project id, name, subscriptionId, resourceGroup, location, tags, status, target,
  description = tostring(c.properties.privateLinkServiceConnectionState.description),
  groupIds = c.properties.groupIds, subnet = tostring(properties.subnet.id),
  nics = properties.networkInterfaces, customDns = properties.customDnsConfigs, provisioningState = tostring(properties.provisioningState)"""


class _Calls:
    """Thin wrapper: every read goes through the shared client; the call log is kept for coverage."""

    def __init__(self, client):
        self.client, self.start = client, len(client.calls)

    def get(self, url, check, target):
        status, data, error = self.client.request('GET', url, check, target)
        return {'http': status, 'data': data if status == 200 else None, 'error': error}

    def get_all(self, path, check, target, api):
        """ARM GET following nextLink. A single object (no 'value') is returned as is."""
        url, items = f'{ARM}{path}?api-version={api}', []
        status, error = None, None
        while url:
            status, data, error = self.client.request('GET', url, check, target)
            if status != 200 or data is None:
                return None, status, error
            if isinstance(data, dict) and 'value' in data:
                items.extend(data['value'])
                url = data.get('nextLink')
            else:
                return data, status, error
        return items, status, error

    def arg(self, query, subs, check, target):
        rows, status, error = self.client.arg(query, subs, check, target)
        return rows if status == 200 else None, status, error

    def index(self):
        return [{'check': c['check'], 'target': c['target'], 'method': c['method'], 'url': c['url'].replace(ARM, ''),
                 'http': c['status'], 'error': c['error'], 'elapsed': c['elapsed'], 'at': c['at']}
                for c in self.client.calls[self.start:]]


def _detail_jobs(arg_data):
    jobs = []
    for r in arg_data.get('mysql', []):
        jobs.append(('mysql_fw', r['id'], r['id'] + '/firewallRules', '2023-12-30'))
        for p in ('require_secure_transport', 'tls_version'):
            jobs.append(('mysql_cfg', r['id'] + '|' + p, r['id'] + '/configurations/' + p, '2023-12-30'))
    for r in arg_data.get('postgres', []):
        jobs.append(('pg_fw', r['id'], r['id'] + '/firewallRules', '2024-08-01'))
        for p in ('require_secure_transport', 'ssl_min_protocol_version'):
            jobs.append(('pg_cfg', r['id'] + '|' + p, r['id'] + '/configurations/' + p, '2024-08-01'))
    for r in arg_data.get('redis', []):
        jobs.append(('redis_fw', r['id'], r['id'] + '/firewallRules', '2024-11-01'))
    for r in arg_data.get('redisenterprise', []):
        jobs.append(('redisent_db', r['id'], r['id'] + '/databases', '2025-04-01'))
    for r in arg_data.get('mongoclusters', []):
        jobs.append(('mongo_fw', r['id'], r['id'] + '/firewallRules', '2024-07-01'))
    for r in arg_data.get('sqlservers', []):
        jobs.append(('sql_fw', r['id'], r['id'] + '/firewallRules', '2023-08-01'))
    for r in arg_data.get('storage', []):
        p = r.get('properties') or {}
        if p.get('allowBlobPublicAccess') is not False and r.get('kind') != 'FileStorage':
            jobs.append(('containers', r['id'], r['id'] + '/blobServices/default/containers', '2023-05-01'))
    for r in arg_data.get('cdn_profiles', []):
        if 'frontdoor' in str((r.get('sku') or {}).get('name', '')).lower():
            jobs.append(('afd_secpol', r['id'], r['id'] + '/securityPolicies', '2024-02-01'))
            jobs.append(('afd_endpoints', r['id'], r['id'] + '/afdEndpoints', '2024-02-01'))
    return jobs


def _trim_containers(data):
    """Keep only the anonymous-access setting of each container (no data is read)."""
    return [{'id': c.get('id'), 'name': c.get('name'), 'publicAccess': (c.get('properties') or {}).get('publicAccess'),
             'lastModifiedTime': (c.get('properties') or {}).get('lastModifiedTime')} for c in data]


def _collect_private_endpoints(raw, calls, sub_ids, names, log):
    """S-N8 follow-up: endpoints whose connection is Disconnected, whether the target still exists, DNS, deletion time."""
    pe = 'raw/pe-disconnected/'
    rows, status, error = calls.arg(PE_QUERY, sub_ids, 'S-N8', 'ARG:privateendpoints')
    raw.save(pe + 'pe-all.json', {'http': status, 'rows': rows or [], 'error': error})
    if rows is None:
        log(f'私有终结点读取失败（{status} {error}）')
        return
    disc = [r for r in rows if r['status'] == 'Disconnected']
    targets = sorted({r['target'] for r in disc})
    exists = {'http': 200, 'rows': [], 'error': None}
    if targets:
        q = ('resources | where tolower(id) in~ (' + ','.join(json.dumps(t) for t in targets)
             + ') | project id=tolower(id), name, type, location, provisioningState=tostring(properties.provisioningState)')
        t_rows, t_status, t_error = calls.arg(q, sub_ids, 'S-N8', 'ARG:targets')
        exists = {'http': t_status, 'rows': t_rows or [], 'error': t_error}
    raw.save(pe + 'targets-exist.json', exists)
    raw.save(pe + 'approved-same-target.json', [r for r in rows if r['target'] in targets and r['status'] != 'Disconnected'])
    nic_ids = sorted({n['id'].lower() for r in disc for n in (r.get('nics') or [])})
    nics = {'http': 200, 'rows': [], 'error': None}
    if nic_ids:
        q = 'resources | where tolower(id) in~ (' + ','.join(json.dumps(n) for n in nic_ids) + ') | project id=tolower(id), ips=properties.ipConfigurations'
        n_rows, n_status, n_error = calls.arg(q, sub_ids, 'S-N8', 'ARG:nics')
        nics = {'http': n_status, 'rows': n_rows or [], 'error': n_error}
    raw.save(pe + 'nics.json', nics)
    details = {}
    for r in disc:
        query = urllib.parse.urlencode({'$filter': f"name eq '{r['name']}'", '$expand': 'createdTime,changedTime', 'api-version': '2021-04-01'})
        details[r['id']] = {
            'createdTime': calls.get(f'{ARM}/subscriptions/{r["subscriptionId"]}/resourceGroups/{r["resourceGroup"]}/resources?{query}', 'S-N8', r['id']),
            'dnsZoneGroups': calls.get(f'{ARM}{r["id"]}/privateDnsZoneGroups?api-version=2023-09-01', 'S-N8', r['id']),
        }
    raw.save(pe + 'pe-details.json', details)
    zones = sorted({cfg['properties']['privateDnsZoneId'] for d in details.values() if d['dnsZoneGroups']['data']
                    for g in d['dnsZoneGroups']['data'].get('value', []) for cfg in g['properties'].get('privateDnsZoneConfigs', [])})
    raw.save(pe + 'dns-a-records.json', {z: calls.get(f'{ARM}{z}/A?api-version=2018-09-01&$top=1000', 'S-N8', z) for z in zones})
    # Deletion of the target resources in the activity log (kept for 90 days only)
    start = (datetime.now(timezone.utc) - timedelta(days=89)).strftime('%Y-%m-%dT%H:%M:%SZ')
    deletes = {}
    for t in targets:
        params = urllib.parse.urlencode({'api-version': '2015-04-01', '$filter': f"eventTimestamp ge '{start}' and resourceUri eq '{t}'",
                                         '$select': 'eventTimestamp,operationName,status,resourceId'})
        deletes[t] = calls.get(f'{ARM}/subscriptions/{t.split("/")[2]}/providers/Microsoft.Insights/eventtypes/management/values?{params}', 'S-N8', t)
    raw.save(pe + 'target-activity.json', deletes)
    raw.save(pe + 'meta.json', {'collectedAt': now(), 'subscriptions': names, 'targets': targets})
    log(f'私有终结点 {len(rows)} 个，已断开 {len(disc)} 个')


def collect(ws, cfg, client, window, log=print):
    raw, calls = Raw(ws, PILLAR), _Calls(client)
    subs = load_scope(ws)
    active = enabled(subs)
    sub_ids = [s['id'] for s in active]
    arg_data, arg_errors = {}, {}
    for key, query in ARG_TYPES.items():
        rows, status, error = calls.arg(query, sub_ids, 'ARG', f'ARG:{key}')
        if rows is None:
            arg_errors[key] = f'{status} {error}'
        else:
            arg_data[key] = rows
            raw.save(f'raw/arg/{key}.json', rows)
    raw.save('raw/arg/_errors.json', arg_errors)
    log(f'安全-网络：Resource Graph {len(arg_data)}/{len(ARG_TYPES)} 类资源读取成功')

    detail = {k: {} for k in DETAIL_KINDS}

    def job(item):
        kind, rid, path, api = item
        data, status, error = calls.get_all(path, kind, rid, api)
        if kind == 'containers' and data:
            data = _trim_containers(data)
        return kind, rid, {'http': status, 'error': error, 'data': data}

    with ThreadPoolExecutor(max_workers=3) as pool:
        for kind, rid, rec in pool.map(job, _detail_jobs(arg_data)):
            detail[kind][rid] = rec
    for kind, records in detail.items():
        raw.save(f'raw/arm/{kind}.json', records)
    raw.save('raw/meta.json', {'collectedAt': now(),
                               'enabledSubscriptions': [{'name': s['name'], 'id': s['id']} for s in active],
                               'disabledSubscriptions': [{'name': s['name'], 'id': s['id'], 'state': s.get('state')} for s in subs if s not in active],
                               'argErrors': arg_errors})
    _collect_private_endpoints(raw, calls, sub_ids, {s['id']: s['name'] for s in active}, log)
    raw.save('index.json', {'generatedAt': now(), 'calls': calls.index()})
    raw.save('manifest.json', {'collectedAt': now(), 'window': window})
