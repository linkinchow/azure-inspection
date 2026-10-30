"""Security - identity, access, threat protection, AKS, patching and audit (S-I1..S-I10): read-only collection.

Raw layout under raw/waf/security_identity/ (kept identical to earlier inspections so it can be replayed,
and operations reads aks/*.json from here):
  arg/<name>.json                      Resource Graph results {query, http, error, rowCount, rows}
  subscriptions/<id>.json              per-subscription Defender, role assignments, activity log export
  aks/<cluster>.json                   cluster GET, diagnostic settings, upgrade profile
  aks/_kubernetesVersions.json, aks/_maintenanceConfigurations.json
  keyvault/diagnosticSettings.json
  defender/assessments_<id>.json       compact Defender assessments
  vm/instanceView_patchStatus.json
  graph/principals.json                directory metadata of privileged principals (no secrets)
  index.json, manifest.json
Only directory metadata is read from Microsoft Graph: names, types, credential start/end dates. Never secrets.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from ..common import Raw, enabled, load_scope, now

ARM = 'https://management.azure.com'
GRAPH = 'https://graph.microsoft.com'
PILLAR = 'security_identity'
WORKERS = 4

ROLE_IDS = {
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': 'Owner',
    'b24988ac-6180-42a0-ab88-20f7382dd24c': 'Contributor',
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': 'User Access Administrator',
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168': 'Role Based Access Control Administrator',
}

QUERIES = {
    'aks': "resources | where type =~ 'microsoft.containerservice/managedclusters' | project id, name, resourceGroup, subscriptionId, location, tags",
    'vms': "resources | where type =~ 'microsoft.compute/virtualmachines' | project id, name, resourceGroup, subscriptionId, location, tags, identity, zones, plan, "
           "imageReference=properties.storageProfile.imageReference, osName=tostring(properties.extended.instanceView.osName), "
           "osType=tostring(properties.storageProfile.osDisk.osType), vmSize=tostring(properties.hardwareProfile.vmSize), "
           "disablePasswordAuthentication=properties.osProfile.linuxConfiguration.disablePasswordAuthentication, "
           "linuxPatchSettings=properties.osProfile.linuxConfiguration.patchSettings, "
           "windowsPatchSettings=properties.osProfile.windowsConfiguration.patchSettings, "
           "enableAutomaticUpdates=properties.osProfile.windowsConfiguration.enableAutomaticUpdates, "
           "securityProfile=properties.securityProfile, imageReference=properties.storageProfile.imageReference, "
           "powerState=tostring(properties.extended.instanceView.powerState.code), provisioningState=tostring(properties.provisioningState), "
           "nicIds=properties.networkProfile.networkInterfaces",
    'vm_nics': "resources | where type =~ 'microsoft.network/networkinterfaces' | mv-expand ipc=properties.ipConfigurations "
               "| project id, vmId=tolower(tostring(properties.virtualMachine.id)), publicIpId=tostring(ipc.properties.publicIPAddress.id), "
               "nsgId=tostring(properties.networkSecurityGroup.id), subnetId=tostring(ipc.properties.subnet.id)",
    'public_ips': "resources | where type =~ 'microsoft.network/publicipaddresses' "
                  "| project id=tolower(id), ip=tostring(properties.ipAddress), ipConfig=tolower(tostring(properties.ipConfiguration.id))",
    'vm_extensions': "resources | where type =~ 'microsoft.compute/virtualmachines/extensions' | project id, name, subscriptionId, "
                     "publisher=tostring(properties.publisher), extType=tostring(properties.type), provisioningState=tostring(properties.provisioningState)",
    'patch_assessment': "patchassessmentresources | where type =~ 'microsoft.compute/virtualmachines/patchassessmentresults' "
                        "or type =~ 'microsoft.hybridcompute/machines/patchassessmentresults' "
                        "| project id, subscriptionId, status=tostring(properties.status), lastModified=tostring(properties.lastModifiedDateTime), "
                        "osType=tostring(properties.osType), rebootPending=properties.rebootPending, "
                        "available=properties.availablePatchCountByClassification, startedBy=tostring(properties.startedBy)",
    'keyvaults': "resources | where type =~ 'microsoft.keyvault/vaults' | project id, name, resourceGroup, subscriptionId, location, tags, "
                 "enableSoftDelete=properties.enableSoftDelete, softDeleteRetentionInDays=properties.softDeleteRetentionInDays, "
                 "enablePurgeProtection=properties.enablePurgeProtection, enableRbacAuthorization=properties.enableRbacAuthorization, "
                 "publicNetworkAccess=tostring(properties.publicNetworkAccess), networkAclsDefault=tostring(properties.networkAcls.defaultAction), "
                 "sku=tostring(properties.sku.name), accessPolicies=properties.accessPolicies",
    'acr': "resources | where type =~ 'microsoft.containerregistry/registries' | project id, name, resourceGroup, subscriptionId, location, tags, "
           "sku=tostring(sku.name), adminUserEnabled=properties.adminUserEnabled, anonymousPullEnabled=properties.anonymousPullEnabled, "
           "publicNetworkAccess=tostring(properties.publicNetworkAccess), retentionPolicy=properties.policies.retentionPolicy, "
           "quarantinePolicy=properties.policies.quarantinePolicy, trustPolicy=properties.policies.trustPolicy, identity",
    'cognitive': "resources | where type =~ 'microsoft.cognitiveservices/accounts' | project id, name, resourceGroup, subscriptionId, location, tags, kind, "
                 "sku=tostring(sku.name), disableLocalAuth=properties.disableLocalAuth, publicNetworkAccess=tostring(properties.publicNetworkAccess), "
                 "identityType=tostring(identity.type), allowProjectManagement=properties.allowProjectManagement",
    'workspaces': "resources | where type =~ 'microsoft.operationalinsights/workspaces' | project id=tolower(id), name, subscriptionId, location, "
                  "retentionInDays=properties.retentionInDays, sku=tostring(properties.sku.name)",
    'flowlogs': "resources | where type =~ 'microsoft.network/networkwatchers/flowlogs' | project id, name, subscriptionId, location, "
                "targetResourceId=tostring(properties.targetResourceId), enabled=properties.enabled, "
                "retentionDays=properties.retentionPolicy.days, retentionEnabled=properties.retentionPolicy.enabled, "
                "trafficAnalytics=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled",
    'vnets': "resources | where type =~ 'microsoft.network/virtualnetworks' | project id, name, subscriptionId, location, resourceGroup",
    'nsgs': "resources | where type =~ 'microsoft.network/networksecuritygroups' | project id, name, subscriptionId, location",
    'type_counts': "resources | summarize n=count() by subscriptionId, type=tolower(type)",
    'assessments_unhealthy': "securityresources | where type == 'microsoft.security/assessments' "
                             "| extend code=tostring(properties.status.code), sev=tostring(properties.metadata.severity), dn=tostring(properties.displayName), "
                             "rtype=tostring(properties.resourceDetails.ResourceType), rid=tolower(tostring(properties.resourceDetails.Id)) "
                             "| where code == 'Unhealthy' | project subscriptionId, sev, dn, assessmentKey=name, rtype, rid",
    'role_assignments_arg': "authorizationresources | where type =~ 'microsoft.authorization/roleassignments' "
                            "| extend roleDefId=tolower(tostring(properties.roleDefinitionId)), principalType=tostring(properties.principalType), "
                            "principalId=tostring(properties.principalId), scope=tostring(properties.scope) "
                            "| project id, subscriptionId, roleDefId, principalType, principalId, scope, createdOn=tostring(properties.createdOn)",
}
ARG_CHECK = {'aks': 'S-I1', 'vms': 'S-I8', 'vm_nics': 'S-I8', 'public_ips': 'S-I8', 'vm_extensions': 'S-I8', 'patch_assessment': 'S-I8',
             'keyvaults': 'S-I9', 'acr': 'S-I10', 'cognitive': 'S-I10', 'workspaces': 'S-I7', 'flowlogs': 'S-I7', 'vnets': 'S-I7',
             'nsgs': 'S-I7', 'assessments_unhealthy': 'S-I4', 'role_assignments_arg': 'S-I5'}


def safe_name(text):
    return re.sub(r'[^A-Za-z0-9_.\-]+', '_', text)[:150]


def _call(client, check, target, url, method='GET', body=None):
    status, data, error = client.request(method, url, check, target, body=body)
    return {'http': status, 'error': error, 'body': data}


def _get_all(client, check, target, url):
    items, status, error = client.get_all(url, check, target, max_pages=50)
    return {'http': status, 'error': error, 'body': {'value': items} if items is not None else None}


def _arg(raw, client, name, subscription_ids):
    rows, status, error = client.arg(QUERIES[name], subscription_ids, ARG_CHECK.get(name, 'S-I*'), f'ARG:{name}')
    raw.save(f'arg/{name}.json', {'query': QUERIES[name], 'http': status, 'error': error if status != 200 else None,
                                  'rowCount': len(rows or []), 'rows': rows or []})
    return rows or []


def _per_subscription(raw, client, sub):
    sid, base = sub['id'], f'{ARM}/subscriptions/{sub["id"]}'
    calls = {
        'pricings': _call(client, 'S-I4', sid, f'{base}/providers/Microsoft.Security/pricings?api-version=2024-01-01'),
        'secureScores': _call(client, 'S-I4', sid, f'{base}/providers/Microsoft.Security/secureScores?api-version=2020-01-01'),
    }
    contacts = _call(client, 'S-I4', sid, f'{base}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview')
    if contacts['http'] and contacts['http'] >= 400 and contacts['http'] not in (401, 403):
        contacts = _call(client, 'S-I4', sid, f'{base}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview')
    calls['securityContacts'] = contacts
    calls['autoProvisioning'] = _call(client, 'S-I4', sid, f'{base}/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview')
    calls['roleAssignments'] = _get_all(client, 'S-I5', sid, f'{base}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01')
    calls['customRoles'] = _get_all(client, 'S-I5', sid, f"{base}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&$filter=type%20eq%20'CustomRole'")
    calls['classicAdmins'] = _call(client, 'S-I5', sid, f'{base}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01')
    calls['activityLogDiag'] = _call(client, 'S-I7', sid, f'{base}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview')
    raw.save(f'subscriptions/{sid}.json', {'subscriptionId': sid, 'name': sub['name'], 'calls': calls})
    return sid, calls


def _aks_one(raw, client, row):
    cid = row['id']
    cluster = None
    for version in ('2025-07-01', '2024-10-01'):
        cluster = _call(client, 'S-I1', row['name'], f'{ARM}{cid}?api-version={version}')
        if cluster['http'] != 400:
            break
    detail = {'cluster': cluster,
              'diagnosticSettings': _call(client, 'S-I3', row['name'], f'{ARM}{cid}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview'),
              'upgradeProfile': _call(client, 'S-I3', row['name'], f'{ARM}{cid}/upgradeProfiles/default?api-version=2024-10-01')}
    raw.save(f'aks/{safe_name(row["name"])}.json', detail)


def _assessments(raw, client, sub):
    sid = sub['id']
    items, status, error = client.get_all(f'{ARM}/subscriptions/{sid}/providers/Microsoft.Security/assessments?api-version=2021-06-01&$expand=metadata',
                                          'S-I4', sid, max_pages=50)
    compact = None
    if items is not None:
        compact = []
        for i in items:
            p = i.get('properties') or {}
            meta, details = p.get('metadata') or {}, p.get('resourceDetails') or {}
            compact.append({'name': i.get('name'), 'displayName': p.get('displayName'), 'status': (p.get('status') or {}).get('code'),
                            'severity': meta.get('severity'), 'categories': meta.get('categories'),
                            'resourceId': details.get('Id'), 'resourceType': details.get('ResourceType'),
                            'firstEvaluationDate': (p.get('status') or {}).get('firstEvaluationDate'),
                            'statusChangeDate': (p.get('status') or {}).get('statusChangeDate')})
    raw.save(f'defender/assessments_{sid}.json', {'subscriptionId': sid, 'name': sub['name'], 'http': status, 'error': error, 'assessments': compact})


def _vm_instance_view(client, row):
    status, data, error = client.request('GET', f'{ARM}{row["id"]}/instanceView?api-version=2024-07-01', 'S-I8', row['name'])
    data = data or {}
    return row['id'].lower(), {'http': status, 'error': error, 'patchStatus': data.get('patchStatus'),
                               'osName': data.get('osName'), 'osVersion': data.get('osVersion'),
                               'vmAgentVersion': (data.get('vmAgent') or {}).get('vmAgentVersion'),
                               'powerStates': [x.get('code') for x in data.get('statuses', []) if str(x.get('code', '')).startswith('PowerState')]}


def _credential_meta(items):
    """Credential metadata only (dates and descriptions); the secret value is never returned by Graph GET."""
    return [{'displayName': c.get('displayName'), 'startDateTime': c.get('startDateTime'), 'endDateTime': c.get('endDateTime'),
             'type': c.get('type'), 'usage': c.get('usage')} for c in (items or [])]


def _graph(raw, client, cfg, subcalls):
    """Resolve principals of privileged role assignments; credential dates of privileged application service principals."""
    privileged = set()
    for calls in subcalls.values():
        for ra in ((calls['roleAssignments']['body'] or {}).get('value') or []):
            p = ra.get('properties', {})
            if (p.get('roleDefinitionId') or '').rsplit('/', 1)[-1].lower() in ROLE_IDS and p.get('principalId'):
                privileged.add(p['principalId'])
    ids = sorted(privileged)
    result = {'attempted': True, 'objects': {}, 'errors': [], 'spCredentials': {}, 'requestedIds': len(ids)}
    select = '$select=id,displayName,userType,servicePrincipalType,appId,accountEnabled'
    for i in range(0, len(ids), 1000):
        status, data, error = client.request('POST', f'{GRAPH}/v1.0/directoryObjects/getByIds?{select}', 'S-I5', 'graph:getByIds',
                                             body={'ids': ids[i:i + 1000], 'types': ['user', 'group', 'servicePrincipal']})
        if status != 200:
            result['errors'].append({'call': 'getByIds', 'http': status, 'error': error})
            break
        for o in (data or {}).get('value', []):
            result['objects'][o['id']] = {'type': o.get('@odata.type'), 'displayName': o.get('displayName'), 'userType': o.get('userType'),
                                          'servicePrincipalType': o.get('servicePrincipalType'), 'appId': o.get('appId'),
                                          'accountEnabled': o.get('accountEnabled')}
    if not result['errors']:
        sps = [oid for oid, o in result['objects'].items() if o['type'] == '#microsoft.graph.servicePrincipal']
        for oid in sps:
            result['spCredentials'][oid] = _sp_credentials(client, cfg, oid)
    raw.save('graph/principals.json', result)
    return result


def _sp_credentials(client, cfg, oid):
    url = (f'{GRAPH}/v1.0/servicePrincipals/{oid}?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,'
           'passwordCredentials,keyCredentials')
    status, data, error = client.request('GET', url, 'S-I6', 'graph:sp')
    entry = {'http': status, 'error': error}
    if status != 200 or not data:
        return entry
    # Stored as *PwdCredentials: the raw-data sanitizer blanks any key containing "password".
    entry.update(displayName=data.get('displayName'), appId=data.get('appId'), servicePrincipalType=data.get('servicePrincipalType'),
                 homeTenant=str(data.get('appOwnerOrganizationId') or '').lower() == cfg.tenant_id,
                 spPwdCredentials=_credential_meta(data.get('passwordCredentials')), spKeyCredentials=_credential_meta(data.get('keyCredentials')))
    if entry['homeTenant'] and data.get('servicePrincipalType') == 'Application':
        app_url = f"{GRAPH}/v1.0/applications(appId='{data.get('appId')}')?$select=id,appId,displayName,passwordCredentials,keyCredentials"
        status2, app, error2 = client.request('GET', app_url, 'S-I6', 'graph:app')
        entry.update(appHttp=status2, appError=error2)
        if status2 == 200 and app:
            entry.update(appPwdCredentials=_credential_meta(app.get('passwordCredentials')), appKeyCredentials=_credential_meta(app.get('keyCredentials')))
    return entry


def collect(ws, cfg, client, window, log=print):
    raw = Raw(ws, PILLAR)
    first_call, started = len(client.calls), now()
    subs = enabled(load_scope(ws))
    ids = [s['id'] for s in subs]
    log(f'安全-身份采集：{len(subs)} 个订阅')
    rows = {name: _arg(raw, client, name, ids) for name in QUERIES}
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        subcalls = dict(pool.map(lambda s: _per_subscription(raw, client, s), subs))
        list(pool.map(lambda r: _aks_one(raw, client, r), rows['aks']))
        versions = {}
        for sid, loc in sorted({(r['subscriptionId'], r['location']) for r in rows['aks']}):
            url = f'{ARM}/subscriptions/{sid}/providers/Microsoft.ContainerService/locations/{loc}/kubernetesVersions?api-version=2024-10-01'
            versions[f'{sid}|{loc}'] = _call(client, 'S-I3', f'{sid}/{loc}', url)
        raw.save('aks/_kubernetesVersions.json', versions)
        kv_diag = dict(pool.map(lambda r: (r['id'].lower(), _call(client, 'S-I7', r['name'],
                                f'{ARM}{r["id"]}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview')), rows['keyvaults']))
        raw.save('keyvault/diagnosticSettings.json', kv_diag)
        _graph(raw, client, cfg, subcalls)
        list(pool.map(lambda s: _assessments(raw, client, s), subs))
        raw.save('vm/instanceView_patchStatus.json', dict(pool.map(lambda r: _vm_instance_view(client, r), rows['vms'])))
        maintenance = dict(pool.map(lambda r: (r['id'].lower(), _get_all(client, 'S-I3', r['name'], f'{ARM}{r["id"]}/maintenanceConfigurations?api-version=2024-10-01')),
                                    rows['aks']))
        raw.save('aks/_maintenanceConfigurations.json', {k: {'http': v['http'], 'error': v['error'], 'value': (v['body'] or {}).get('value')}
                                                         for k, v in maintenance.items()})
    calls = [{**{k: c.get(k) for k in ('check', 'target', 'method', 'url', 'error', 'elapsed', 'at')}, 'http': c.get('status')}
             for c in client.calls[first_call:]]
    raw.save('index.json', {'startedAt': started, 'finishedAt': now(), 'calls': calls})
    raw.save('manifest.json', {'collectedAt': started, 'window': window})
    failed = sum(1 for c in calls if c['http'] != 200)
    log(f'安全-身份采集完成：{len(calls)} 次读取，{failed} 次未成功（已记录）')
