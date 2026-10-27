"""Operational excellence (O1..O10): read-only collection.

Output under raw/waf/operations/ (same relative layout as earlier inspections' raw/ folder, so it can be replayed):
  arg/<name>.json              Resource Graph snapshots (resources, alert rules, action groups, monitoring, ...)
  subscription-reads.json      per subscription: locks, policy assignments, policy compliance summary, fired alerts, deployments
  deployments-rg.json          deployment history per resource group
  diagnostic-settings.json     diagnostic settings of data/edge resources and the most expensive storage accounts
  vm-dcra.json                 data collection rule associations per VM
  management-groups.json       management group tree and policy assignments at each group
  aks-activity-90d.json        AKS write/upgrade operations in the last 90 days (no caller identities)
  workspace-tables.json        Log Analytics tables with non-default retention
  index.json                   calls made by this pillar (for coverage); manifest.json  collection time and window

Action groups are reduced to receiver-type counts inside the query; no addresses are read.
Depends on raw/cost/resources/storage.json (cost review) to pick the most expensive storage accounts.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from ...core.io import read_json
from ..common import Raw, enabled, load_scope, now

ARM = 'https://management.azure.com'
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
URL_RE = re.compile(r'https?://[^\s"\']+', re.I)
DROP_KEYS = {'emailreceivers', 'smsreceivers', 'webhookreceivers', 'voicereceivers', 'azureapppushreceivers',
             'itsmreceivers', 'logicappreceivers', 'azurefunctionreceivers', 'automationrunbookreceivers',
             'eventhubreceivers', 'incidentreceivers', 'webhookproperties', 'serviceuri', 'callbackurl',
             'parameters', 'outputs', 'caller', 'emailaddress', 'phonenumber'}

ARG_Q = {
    'resources': "resources | project id, name, type=tolower(type), subscriptionId, resourceGroup, location, tags, kind, "
                 "ps=tostring(properties.provisioningState), managedBy",
    'rgs': "resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' | project id, name, "
           "subscriptionId, location, tags, ps=tostring(properties.provisioningState), managedBy",
    'subs': "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name, tags, "
            "state=tostring(properties.state), mgChain=properties.managementGroupAncestorsChain",
    'aks': "resources | where type =~ 'microsoft.containerservice/managedclusters' | project id, name, subscriptionId, "
           "resourceGroup, location, tags, sku, properties",
    'aks_extra': "resources | where type =~ 'microsoft.containerservice/managedclusters' | project id,name,subscriptionId, "
                 "nodeRG=tostring(properties.nodeResourceGroup), podSubnets=properties.agentPoolProfiles, supportPlan=tostring(properties.supportPlan), "
                 "disableLocal=properties.disableLocalAccounts, safeguards=properties.safeguardsProfile, metricsProfile=properties.metricsProfile, "
                 "costAnalysis=properties.metricsProfile.costAnalysis.enabled, workloadAutoScaler=properties.workloadAutoScalerProfile, "
                 "nodeProvisioning=properties.nodeProvisioningProfile, appMonitoring=properties.azureMonitorProfile.appMonitoring, "
                 "ingress=properties.ingressProfile, addons=bag_keys(properties.addonProfiles)",
    'vms': "resources | where type =~ 'microsoft.compute/virtualmachines' | project id, name, subscriptionId, resourceGroup, "
           "location, tags, zones, vmSize=tostring(properties.hardwareProfile.vmSize), osType=tostring(properties.storageProfile.osDisk.osType), "
           "linuxPatch=properties.osProfile.linuxConfiguration.patchSettings, winPatch=properties.osProfile.windowsConfiguration.patchSettings, "
           "dataDisks=array_length(properties.storageProfile.dataDisks), power=tostring(properties.extended.instanceView.powerState.code), "
           "ps=tostring(properties.provisioningState), created=tostring(properties.timeCreated)",
    'vmext': "resources | where type =~ 'microsoft.compute/virtualmachines/extensions' | extend vmId=tolower(substring(id, 0, indexof(id, '/extensions/'))) "
             "| project id, vmId, name, publisher=tostring(properties.publisher), extType=tostring(properties.type), ps=tostring(properties.provisioningState), "
             "ver=tostring(properties.typeHandlerVersion), autoUpgrade=properties.enableAutomaticUpgrade",
    'vmss': "resources | where type =~ 'microsoft.compute/virtualmachinescalesets' | project id, name, subscriptionId, resourceGroup, location, tags, "
            "sku, upgradeMode=tostring(properties.upgradePolicy.mode), autoOs=properties.upgradePolicy.automaticOSUpgradePolicy, "
            "orch=tostring(properties.orchestrationMode), ps=tostring(properties.provisioningState), "
            "exts=properties.virtualMachineProfile.extensionProfile.extensions",
    'dcra': "insightsresources | where type =~ 'microsoft.insights/datacollectionruleassociations' | project id, name, subscriptionId, "
            "dcrId=tostring(properties.dataCollectionRuleId), dceId=tostring(properties.dataCollectionEndpointId)",
    'dcr': "resources | where type =~ 'microsoft.insights/datacollectionrules' | project id, name, subscriptionId, resourceGroup, location, kind, "
           "dataSourceKinds=bag_keys(properties.dataSources), perf=properties.dataSources.performanceCounters, ext=properties.dataSources.extensions, "
           "destinations=properties.destinations, flows=properties.dataFlows",
    'alertrules': "resources | where type in~ ('microsoft.insights/metricalerts','microsoft.insights/scheduledqueryrules',"
                  "'microsoft.insights/activitylogalerts','microsoft.alertsmanagement/prometheusrulegroups',"
                  "'microsoft.alertsmanagement/smartdetectoralertrules') | project id, name, type=tolower(type), subscriptionId, "
                  "resourceGroup, location, kind, tags, properties",
    'actiongroups': "resources | where type =~ 'microsoft.insights/actiongroups' | project id, name, subscriptionId, resourceGroup, location, "
                    "enabled=properties.enabled, shortName=tostring(properties.groupShortName), "
                    "email=array_length(properties.emailReceivers), sms=array_length(properties.smsReceivers), "
                    "webhook=array_length(properties.webhookReceivers), itsm=array_length(properties.itsmReceivers), "
                    "azureAppPush=array_length(properties.azureAppPushReceivers), automationRunbook=array_length(properties.automationRunbookReceivers), "
                    "voice=array_length(properties.voiceReceivers), logicApp=array_length(properties.logicAppReceivers), "
                    "azureFunction=array_length(properties.azureFunctionReceivers), armRole=array_length(properties.armRoleReceivers), "
                    "eventHub=array_length(properties.eventHubReceivers), incident=array_length(properties.incidentReceivers)",
    'monitoring': "resources | where type in~ ('microsoft.monitor/accounts','microsoft.dashboard/grafana','microsoft.operationalinsights/workspaces',"
                  "'microsoft.insights/components','microsoft.insights/datacollectionendpoints') | project id, name, type=tolower(type), subscriptionId, "
                  "resourceGroup, location, sku, tags, retention=properties.retentionInDays, capping=properties.workspaceCapping, "
                  "wsSku=properties.sku, customerId=tostring(properties.customerId), "
                  "grafanaAmw=properties.grafanaIntegrations.azureMonitorWorkspaceIntegrations, amwDefault=properties.defaultIngestionSettings, "
                  "publicAccess=tostring(properties.publicNetworkAccess)",
    'targets': "resources | where type in~ ('microsoft.dbformysql/flexibleservers','microsoft.dbforpostgresql/flexibleservers','microsoft.cache/redis',"
               "'microsoft.cache/redisenterprise','microsoft.documentdb/mongoclusters','microsoft.network/applicationgateways','microsoft.cdn/profiles',"
               "'microsoft.network/frontdoors','microsoft.storage/storageaccounts','microsoft.keyvault/vaults','microsoft.network/virtualnetworks',"
               "'microsoft.containerregistry/registries','microsoft.network/virtualnetworkgateways','microsoft.network/bastionhosts',"
               "'microsoft.eventhub/namespaces','microsoft.network/loadbalancers','microsoft.network/natgateways') "
               "| project id, name, type=tolower(type), subscriptionId, resourceGroup, location, tags, sku, kind, ps=tostring(properties.provisioningState), "
               "state=tostring(properties.state)",
    'vnetgw': "resources | where type =~ 'microsoft.network/virtualnetworkgateways' or type =~ 'microsoft.network/expressroutecircuits' "
              "or type =~ 'microsoft.network/connections' | project id,name,type,subscriptionId,resourceGroup,location,gwType=tostring(properties.gatewayType),"
              "vpnType=tostring(properties.vpnType),sku=tostring(properties.sku.name),connType=tostring(properties.connectionType),"
              "connStatus=tostring(properties.connectionStatus),ps=tostring(properties.provisioningState)",
    'failed_detail': "resources | where tostring(properties.provisioningState) =~ 'Failed' | project id,name,type,subscriptionId,resourceGroup,location,tags,properties",
    'maintconfigs': "resources | where type =~ 'microsoft.maintenance/maintenanceconfigurations' | project id, name, subscriptionId, resourceGroup, "
                    "location, scope=tostring(properties.maintenanceScope), window=properties.maintenanceWindow, install=properties.installPatches, "
                    "visibility=tostring(properties.visibility)",
    'maintassign': "maintenanceresources | where type =~ 'microsoft.maintenance/configurationassignments' | project id, name, subscriptionId, "
                   "mcId=tostring(properties.maintenanceConfigurationId), resId=tostring(properties.resourceId)",
    'agentpools': "resources | where type =~ 'microsoft.containerservice/managedclusters' | mv-expand ap=properties.agentPoolProfiles "
                  "| project clusterId=id, cluster=name, subscriptionId, pool=tostring(ap.name), mode=tostring(ap.mode), ps=tostring(ap.provisioningState), "
                  "power=tostring(ap.powerState.code), ver=tostring(ap.currentOrchestratorVersion), nodeImage=tostring(ap.nodeImageVersion), "
                  "count=toint(ap['count']), zones=ap.availabilityZones, autoscale=tobool(ap.enableAutoScaling), vmSize=tostring(ap.vmSize), "
                  "osSku=tostring(ap.osSKU), maxSurge=tostring(ap.upgradeSettings.maxSurge)",
}

DIAG_TYPES = {'microsoft.dbformysql/flexibleservers', 'microsoft.dbforpostgresql/flexibleservers', 'microsoft.cache/redis',
              'microsoft.cache/redisenterprise', 'microsoft.documentdb/mongoclusters', 'microsoft.network/applicationgateways',
              'microsoft.cdn/profiles', 'microsoft.network/frontdoors'}
TOP_STORAGE_N = 10
ACTIVITY_DAYS = 90


def scrub(o):
    """Drop notification receivers and deployment parameters; mask e-mails and non-ARM URLs."""
    if isinstance(o, dict):
        return {k: ('[REMOVED]' if v not in (None, [], {}) else v) if isinstance(k, str) and k.lower() in DROP_KEYS else scrub(v)
                for k, v in o.items()}
    if isinstance(o, list):
        return [scrub(x) for x in o]
    if isinstance(o, str):
        s = EMAIL_RE.sub('<email-redacted>', o)
        if 'management.azure.com' not in s and '/subscriptions/' not in s:
            s = URL_RE.sub('<url-redacted>', s)
        return s
    return o


def pmap(fn, items, workers=4):
    with ThreadPoolExecutor(workers) as ex:
        return list(ex.map(fn, items))


def slim_dep(x):
    p = x.get('properties') or {}
    tl = p.get('templateLink') or {}
    err = p.get('error') or {}
    return {'name': x.get('name'), 'id': x.get('id'), 'tags': x.get('tags'), 'timestamp': p.get('timestamp'),
            'provisioningState': p.get('provisioningState'), 'mode': p.get('mode'), 'duration': p.get('duration'),
            'templateHash': p.get('templateHash'), 'templateLinkHost': (re.sub(r'^https?://([^/]+)/.*$', r'\1', tl.get('uri') or '') or None),
            'templateLinkId': tl.get('id'),
            'providers': [pr.get('namespace') for pr in (p.get('providers') or [])],
            'resourceTypes': sorted({rt.get('resourceType') for pr in (p.get('providers') or []) for rt in (pr.get('resourceTypes') or [])} - {None}),
            'outputResourcesCount': len(p.get('outputResources') or []),
            'errorCode': err.get('code'), 'errorDetailCodes': [d.get('code') for d in (err.get('details') or [])][:5]}


class _Collector:
    def __init__(self, ws, cfg, client, window, log):
        self.ws, self.cfg, self.client, self.window, self.log = ws, cfg, client, window, log
        self.raw = Raw(ws, 'operations')
        self.subs = load_scope(ws)
        self.enabled = enabled(self.subs)
        self.sub_ids = [s['id'] for s in self.enabled]
        self.subname = {s['id'].lower(): s['name'] for s in self.subs}

    def save(self, rel, obj):
        self.raw.save(rel, scrub(obj))

    def rows(self, name):
        return (self.raw.load(f'arg/{name}.json') or {}).get('rows') or []

    def arg(self):
        summary = {}
        for name, q in ARG_Q.items():
            rows, st, err = self.client.arg(q, self.sub_ids, 'ARG', name)
            self.save(f'arg/{name}.json', {'query': q, 'status': st, 'error': err, 'rows': rows})
            summary[name] = {'status': st, 'error': err, 'rows': None if rows is None else len(rows)}
        self.save('arg/_summary.json', summary)

    def subscription_reads(self):
        """Locks, policy assignments, policy compliance summary, fired alerts and subscription deployments."""
        c = self.client

        def one(s):
            sid, base = s['id'], f"/subscriptions/{s['id']}"
            r = {'subscriptionId': sid, 'subscriptionName': s['name']}
            items, st, err = c.get_all(base + '/providers/Microsoft.Authorization/locks?api-version=2020-05-01', 'O8', s['name'] + ':locks')
            r['locks'] = {'http': st, 'error': err, 'value': None if items is None else
                          [{'id': x.get('id'), 'name': x.get('name'), 'level': (x.get('properties') or {}).get('level')} for x in items]}
            items, st, err = c.get_all(base + '/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01&$filter=atScope()',
                                       'O8', s['name'] + ':policyAssignments')
            r['policyAssignments'] = {'http': st, 'error': err, 'value': None if items is None else [_assignment(x) for x in items]}
            st, data, err = c.request('POST', ARM + base + '/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01',
                                      'O8', s['name'] + ':policySummary')
            r['policySummary'] = {'http': st, 'error': err, 'value': _policy_summary(data) if st == 200 and isinstance(data, dict) else None}
            items, st, err = c.get_all(base + '/providers/Microsoft.AlertsManagement/alerts?api-version=2019-05-05-preview&timeRange=30d&pageCount=250',
                                       'O2', s['name'] + ':firedAlerts', max_pages=20)
            r['firedAlerts'] = {'http': st, 'error': err, 'pages': None, 'value': None if items is None else [_fired(x) for x in items]}
            items, st, err = c.get_all(base + '/providers/Microsoft.Resources/deployments?api-version=2021-04-01', 'O5',
                                       s['name'] + ':subDeployments', max_pages=10)
            r['subDeployments'] = {'http': st, 'error': err, 'value': None if items is None else [slim_dep(x) for x in items]}
            return r
        self.save('subscription-reads.json', pmap(one, self.enabled, 4))

    def deployments(self):
        def one(rg):
            sid = rg['subscriptionId']
            items, st, err = self.client.get_all(
                f"/subscriptions/{sid}/resourcegroups/{rg['name']}/providers/Microsoft.Resources/deployments?api-version=2021-04-01",
                'O5', f"{self.subname.get(sid.lower())}:{rg['name']}", max_pages=10)
            return {'subscriptionId': sid, 'resourceGroup': rg['name'], 'http': st, 'error': err,
                    'value': None if items is None else [slim_dep(x) for x in items]}
        self.save('deployments-rg.json', pmap(one, self.rows('rgs'), 5))

    def diagnostics(self):
        targets_all = self.rows('targets')
        top_ids = top_storage(self.ws)
        if not top_ids:
            self.log('未找到成本巡检的存储账户费用（raw/cost/resources/storage.json），诊断设置只检查数据库、缓存和入口资源')
        targets = [t for t in targets_all if t['type'] in DIAG_TYPES]
        targets += [dict(t, costUSD=top_ids[t['id'].lower()]) for t in targets_all
                    if t['type'] == 'microsoft.storage/storageaccounts' and t['id'].lower() in top_ids]

        def one(t):
            out = {'id': t['id'], 'name': t['name'], 'type': t['type'], 'subscriptionId': t['subscriptionId'], 'resourceGroup': t['resourceGroup']}
            uris = [('self', t['id'])]
            if t['type'] == 'microsoft.storage/storageaccounts':
                uris.append(('blobServices', t['id'] + '/blobServices/default'))
                out['costUSD'] = t.get('costUSD')
            for label, rid in uris:
                st, data, err = self.client.get(rid + '/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview',
                                                'O1', f"{t['name']}:{label}")
                out[label] = {'http': st, 'error': err, 'value': _diag_values(data) if st == 200 and isinstance(data, dict) else None}
            return out
        self.save('diagnostic-settings.json', pmap(one, targets, 4))

    def vm_dcra(self):
        def one(v):
            st, data, err = self.client.get(v['id'] + '/providers/Microsoft.Insights/dataCollectionRuleAssociations?api-version=2022-06-01',
                                            'O1', v['name'] + ':dcra')
            val = None
            if st == 200 and isinstance(data, dict):
                val = [{'name': d.get('name'), 'dcrId': (d.get('properties') or {}).get('dataCollectionRuleId'),
                        'dceId': (d.get('properties') or {}).get('dataCollectionEndpointId')} for d in data.get('value') or []]
            return {'id': v['id'], 'name': v['name'], 'http': st, 'error': err, 'value': val}
        self.save('vm-dcra.json', pmap(one, self.rows('vms'), 5))

    def management_groups(self):
        c = self.client
        items, st, err = c.get_all('/providers/Microsoft.Management/managementGroups?api-version=2021-04-01', 'O8', 'managementGroups')
        out = {'list': {'http': st, 'error': err, 'value': None if items is None else
                        [{'id': x.get('id'), 'name': x.get('name'), 'displayName': (x.get('properties') or {}).get('displayName')} for x in items]},
               'detail': {}}
        for mg in items or []:
            st, data, err = c.get(f"/providers/Microsoft.Management/managementGroups/{mg['name']}?api-version=2021-04-01&$expand=children",
                                  'O8', 'mg:' + mg['name'])
            det = None
            if st == 200 and isinstance(data, dict):
                p = data.get('properties') or {}
                det = {'displayName': p.get('displayName'), 'parent': ((p.get('details') or {}).get('parent') or {}).get('name'),
                       'children': [{'type': ch.get('type'), 'name': ch.get('name'), 'displayName': ch.get('displayName')} for ch in (p.get('children') or [])]}
            out['detail'][mg['name']] = {'http': st, 'error': err, 'value': det}
            pa, st2, err2 = c.get_all(f"/providers/Microsoft.Management/managementGroups/{mg['name']}/providers/Microsoft.Authorization/"
                                      "policyAssignments?api-version=2022-06-01&$filter=atExactScope()", 'O8', 'mgPolicy:' + mg['name'])
            out['detail'][mg['name']]['policyAssignments'] = {'http': st2, 'error': err2, 'value': None if pa is None else [
                {'name': x.get('name'), 'displayName': (x.get('properties') or {}).get('displayName'),
                 'enforcementMode': (x.get('properties') or {}).get('enforcementMode'),
                 'policyDefinitionId': (x.get('properties') or {}).get('policyDefinitionId')} for x in pa]}
        self.save('management-groups.json', out)

    def aks_activity(self):
        """Successful/failed AKS operations in the last 90 days per subscription, without caller identities."""
        end = datetime.strptime(self.window['end'], '%Y-%m-%dT%H:%M:%SZ')
        since = (end - timedelta(days=ACTIVITY_DAYS)).strftime('%Y-%m-%dT%H:%M:%SZ')
        out = []
        for sid in sorted({a['subscriptionId'] for a in self.rows('aks')}):
            flt = f"eventTimestamp ge '{since}' and eventTimestamp le '{self.window['end']}' and resourceProvider eq 'Microsoft.ContainerService'"
            url = (f"/subscriptions/{sid}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01"
                   f"&$filter={flt}&$select=eventTimestamp,operationName,status,subStatus,resourceId,level")
            items, st, err = self.client.get_all(url, 'O4', f"{self.subname.get(sid.lower())}:aksActivity", max_pages=60)
            events = None if items is None else [
                {'t': x.get('eventTimestamp'), 'op': (x.get('operationName') or {}).get('value'), 'status': (x.get('status') or {}).get('value'),
                 'subStatus': (x.get('subStatus') or {}).get('value'), 'resourceId': x.get('resourceId'), 'level': x.get('level')} for x in items]
            out.append({'subscriptionId': sid, 'http': st, 'error': err, 'pages': None, 'events': events})
        self.save('aks-activity-90d.json', out)

    def workspace_tables(self):
        workspaces = [m for m in self.rows('monitoring') if m['type'] == 'microsoft.operationalinsights/workspaces']

        def one(w):
            items, st, err = self.client.get_all(w['id'] + '/tables?api-version=2022-10-01', 'O3', w['name'] + ':tables')
            val = None
            if items is not None:
                val = []
                for t in items:
                    p = t.get('properties') or {}
                    if p.get('retentionInDaysAsDefault') and p.get('totalRetentionInDaysAsDefault') and p.get('plan') in (None, 'Analytics'):
                        continue
                    val.append({'name': t.get('name'), 'retentionInDays': p.get('retentionInDays'), 'totalRetentionInDays': p.get('totalRetentionInDays'),
                                'archiveRetentionInDays': p.get('archiveRetentionInDays'), 'plan': p.get('plan')})
            return {'id': w['id'], 'name': w['name'], 'http': st, 'error': err, 'nonDefaultTables': val,
                    'tablesTotal': len(items) if items is not None else None}
        self.save('workspace-tables.json', pmap(one, workspaces, 4))


def _assignment(x):
    p = x.get('properties') or {}
    prm = p.get('parameters') or {}
    effect = (prm.get('effect') or {}).get('value') if isinstance(prm.get('effect'), dict) else None
    return {'id': x.get('id'), 'name': x.get('name'), 'displayName': p.get('displayName'), 'scope': p.get('scope'),
            'policyDefinitionId': p.get('policyDefinitionId'), 'enforcementMode': p.get('enforcementMode'),
            'effectParam': effect, 'notScopesCount': len(p.get('notScopes') or [])}


def _policy_summary(data):
    v = (data.get('value') or [{}])[0]
    res = v.get('results') or {}
    return {'nonCompliantResources': res.get('nonCompliantResources'), 'nonCompliantPolicies': res.get('nonCompliantPolicies'),
            'resourceDetails': res.get('resourceDetails'), 'policyDetails': res.get('policyDetails'),
            'assignments': [{'policyAssignmentId': a.get('policyAssignmentId'),
                             'nonCompliantResources': (a.get('results') or {}).get('nonCompliantResources'),
                             'resourceDetails': (a.get('results') or {}).get('resourceDetails')} for a in (v.get('policyAssignments') or [])]}


def _fired(x):
    e = ((x.get('properties') or {}).get('essentials')) or {}
    keys = ('severity', 'signalType', 'alertState', 'monitorCondition', 'monitorService', 'targetResource', 'targetResourceType',
            'targetResourceGroup', 'alertRule', 'startDateTime', 'lastModifiedDateTime', 'monitorConditionResolvedDateTime', 'actionStatus')
    return {'id': x.get('id'), 'name': x.get('name'), **{k: e.get(k) for k in keys}}


def _diag_values(data):
    out = []
    for d in data.get('value') or []:
        p = d.get('properties') or {}
        out.append({'name': d.get('name'), 'workspaceId': p.get('workspaceId'), 'storageAccountId': p.get('storageAccountId'),
                    'eventHub': bool(p.get('eventHubAuthorizationRuleId')), 'logAnalyticsDestinationType': p.get('logAnalyticsDestinationType'),
                    'logs': [(l.get('category') or l.get('categoryGroup'), l.get('enabled')) for l in (p.get('logs') or [])],
                    'metrics': [(m.get('category'), m.get('enabled')) for m in (p.get('metrics') or [])]})
    return out


def top_storage(ws) -> dict:
    """{resourceId lower: month cost} of the most expensive storage accounts, from the cost review."""
    path = ws.raw('cost/resources/storage.json')
    if not path.exists():
        return {}
    accounts = read_json(path).get('accounts') or []
    cost = lambda a: a.get('curCostUSD', a.get('sepCostUSD')) or 0  # noqa: E731
    return {a['resourceId'].lower(): cost(a) for a in sorted(accounts, key=lambda a: -cost(a))[:TOP_STORAGE_N]}


PHASES = ['arg', 'subscription_reads', 'deployments', 'diagnostics', 'vm_dcra', 'management_groups', 'aks_activity', 'workspace_tables']


def collect(ws, cfg, client, window, log=print):
    c = _Collector(ws, cfg, client, window, log)
    first_call = len(client.calls)
    log(f'卓越运营：{len(c.enabled)} 个订阅，采集告警、诊断设置、部署历史、治理配置')
    for phase in PHASES:
        getattr(c, phase)()
    calls = client.calls[first_call:]
    c.raw.save('index.json', {'calls': calls, 'count': len(calls)})
    c.raw.save('manifest.json', {'collectedAt': now(), 'window': window})
    denied = sum(1 for x in calls if x.get('status') in (401, 403))
    log(f'卓越运营采集完成：{len(calls)} 次读取，无权限 {denied} 次')
