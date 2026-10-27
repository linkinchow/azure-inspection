"""Operational excellence analysis: load raw data (this pillar and the ones it reuses) and build per-resource rows.

Reused read-only data (no extra calls):
  raw/waf/security_identity/aks/*.json, aks/_maintenanceConfigurations.json   AKS cluster GET + diagnostic settings, maintenance windows
  raw/waf/reliability/advisor-all.json, activity/failed-ops.json            Advisor recommendations, failed operations (30 days)
  raw/waf/performance/index.json                                          403 responses when reading metrics
  raw/cost/resources/logs.json, storage.json, raw/cost/cost-data.json, budgets.json   log usage, storage cost, budgets
Missing files leave the related check unevaluated (recorded in coverage), never "no problem".
"""
from __future__ import annotations

import collections
import re
from datetime import datetime, timezone

from ...core.io import read_json
from ..common import Raw, enabled, env, is_prod, load_scope

TYPE_LABEL = {
    'microsoft.containerservice/managedclusters': 'AKS 集群',
    'microsoft.dbformysql/flexibleservers': 'MySQL 灵活服务器',
    'microsoft.dbforpostgresql/flexibleservers': 'PostgreSQL 灵活服务器',
    'microsoft.documentdb/mongoclusters': 'MongoDB (vCore)',
    'microsoft.cache/redis': 'Azure Cache for Redis',
    'microsoft.cache/redisenterprise': 'Azure Managed Redis',
    'microsoft.network/applicationgateways': '应用网关',
    'microsoft.cdn/profiles': 'Front Door / CDN 配置文件',
    'microsoft.storage/storageaccounts': '存储账户（费用前 10）',
    'microsoft.compute/virtualmachines': '虚拟机（非 AKS）',
    'microsoft.network/virtualnetworkgateways': 'VPN/ExpressRoute 网关',
    'microsoft.network/expressroutecircuits': 'ExpressRoute 线路',
    'microsoft.keyvault/vaults': 'Key Vault',
    'microsoft.network/virtualnetworks': '虚拟网络',
}
DATA_TYPES = ['microsoft.dbformysql/flexibleservers', 'microsoft.dbforpostgresql/flexibleservers', 'microsoft.documentdb/mongoclusters',
              'microsoft.cache/redis', 'microsoft.cache/redisenterprise']
DIAG_TYPES = {'microsoft.dbformysql/flexibleservers', 'microsoft.dbforpostgresql/flexibleservers', 'microsoft.cache/redis',
              'microsoft.cache/redisenterprise', 'microsoft.documentdb/mongoclusters', 'microsoft.network/applicationgateways',
              'microsoft.cdn/profiles', 'microsoft.network/frontdoors'}
# Common names of self-hosted monitoring stacks (namespaces with persistent volumes, dedicated node pools)
SELF_MONITORING_NAMESPACES = ('monitoring', 'logging', 'observability', 'prometheus', 'grafana', 'loki', 'elastic')
SELF_MONITORING_POOLS = ('monitoring', 'logging', 'prometheus', 'grafana', 'loki', 'pmm', 'zabbix', 'dbmon')
# Pools that usually host database monitoring (Percona PMM, Zabbix, ...)
DB_MONITORING_POOLS = ('pmm', 'zabbix', 'dbmon')


def short(rid):
    return (rid or '').rstrip('/').split('/')[-1]


def rg_of(rid):
    m = re.search(r'/resourcegroups/([^/]+)', rid or '', re.I)
    return m.group(1) if m else None


def sub_of(rid):
    m = re.search(r'/subscriptions/([^/]+)', rid or '', re.I)
    return m.group(1).lower() if m else None


def first_existing(raw, *rels, default=None):
    for rel in rels:
        if raw.exists(rel):
            return raw.load(rel)
    return default


class Data:
    """Everything analyze needs, loaded once from raw files."""

    def __init__(self, ws, cfg):
        self.ws, self.cfg = ws, cfg
        self.raw = Raw(ws, 'operations')
        manifest = self.raw.load('manifest.json') or {}
        self.window = manifest.get('window') or {}
        end = self.window.get('end')
        self.today = datetime.strptime(end, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) if end else datetime.now(timezone.utc)
        self.month = int(ws.month[5:7]) if getattr(ws, 'month', None) else None
        self.subs = load_scope(ws)
        self.enabled = enabled(self.subs)
        self.disabled = [s for s in self.subs if s.get('state') != 'Enabled']
        self.sn = {s['id'].lower(): s['name'] for s in self.subs}
        self.missing = []
        self._load_own()
        self._load_reused()

    # ------------------------------------------------------------------ loading
    def rows(self, name):
        return (self.raw.load(f'arg/{name}.json') or {}).get('rows') or []

    def _load_own(self):
        self.res = self.rows('resources')
        self.ridx = {r['id'].lower(): r for r in self.res}
        self.aks = self.rows('aks')
        self.aks_extra = {r['id'].lower(): r for r in self.rows('aks_extra')}
        self.agentpools = self.rows('agentpools')
        self.vms = self.rows('vms')
        self.vmext = self.rows('vmext')
        self.alertrules = self.rows('alertrules')
        self.ags = self.rows('actiongroups')
        self.mon = self.rows('monitoring')
        self.dcr = self.rows('dcr')
        self.targets = self.rows('targets')
        self.subreads = self.raw.load('subscription-reads.json') or []
        self.diag = self.raw.load('diagnostic-settings.json') or []
        self.diag_idx = {d['id'].lower(): d for d in self.diag}
        self.vmdcra = {d['id'].lower(): d for d in (self.raw.load('vm-dcra.json') or [])}
        self.deps = self.raw.load('deployments-rg.json') or []
        self.mg = self.raw.load('management-groups.json') or {}
        self.aksact = self.raw.load('aks-activity-90d.json') or []
        self.wst = self.raw.load('workspace-tables.json') or []
        self.calls = (self.raw.load('index.json') or {}).get('calls') or []

    def _load_reused(self):
        sec = self.raw.other('security_identity')
        self.sec_aks = {}
        for folder in ('aks', 'raw/aks'):
            base = sec.path(folder)
            if not base.exists():
                continue
            for f in base.glob('*.json'):
                if f.name.startswith('_'):
                    continue
                body = ((read_json(f) or {}).get('cluster') or {}).get('body') or {}
                if body.get('id'):
                    self.sec_aks[body['id'].lower()] = read_json(f)
        maint = first_existing(sec, 'aks/_maintenanceConfigurations.json', 'raw/aks/_maintenanceConfigurations.json', default={})
        self.sec_maint = {k.lower(): v for k, v in maint.items()}
        if not self.sec_aks:
            self.missing.append('安全-身份支柱的 AKS 集群原始数据（诊断设置、维护窗口）')
        rel = self.raw.other('reliability')
        self.advisor = first_existing(rel, 'advisor-all.json', 'raw/advisor-all.json', default=None)
        if self.advisor is None:
            self.missing.append('可靠性支柱的 Advisor 建议（advisor-all.json）')
            self.advisor = {}
        self.failed_ops = first_existing(rel, 'activity/failed-ops.json', 'raw/activity/failed-ops.json', default=None)
        if self.failed_ops is None:
            self.missing.append('可靠性支柱的失败操作记录（activity/failed-ops.json）')
            self.failed_ops = []
        perf = self.raw.other('performance')
        self.perf_calls = (first_existing(perf, 'index.json', default={}) or {}).get('calls') or []
        self.logs = self._cost('cost/resources/logs.json') or {}
        storage = self._cost('cost/resources/storage.json') or {}
        self.storage_cost = {a['resourceId'].lower(): month_cost(a) for a in storage.get('accounts', [])}
        self.budgets = self._cost('cost/budgets.json')
        self.cost_index = (self._cost('cost/cost-data.json') or {}).get('index') or []

    def _cost(self, rel):
        path = self.ws.raw(rel)
        if path.exists():
            return read_json(path)
        self.missing.append(f'成本巡检数据 {rel}')
        return None

    # ------------------------------------------------------------------ helpers
    def subname(self, sid):
        return self.sn.get((sid or '').lower())

    def env_of(self, subscription_id, name=None, tags=None):
        return env(self.cfg, self.subname(subscription_id) or '', name or '', tags)

    def sub_env(self, subscription_name):
        return env(self.cfg, subscription_name or '')

    def img_age_days(self, img):
        m = re.search(r'-(\d{4})(\d{2})\.(\d{2})\.', img or '')
        if not m:
            return None
        try:
            d = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
        except ValueError:
            return None
        return (self.today - d).days

    def standard_label(self):
        value = str(self.cfg.standard_tag.get('value') or '').strip()
        return 'Terraform' if value.lower() == 'terraform' else value or '标准方式'


def month_cost(row):
    return row.get('curCostUSD', row.get('sepCostUSD'))


# ---------------------------------------------------------------------- alert rules
def build_rules(d: Data):
    def scopes_of(r):
        return [x.lower() for x in ((r.get('properties') or {}).get('scopes') or [])]

    rules = []
    for r in d.alertrules:
        p, t, en = r.get('properties') or {}, r['type'], (r.get('properties') or {}).get('enabled')
        base = {'id': r['id'], 'name': r['name'], 'type': t, 'scopes': scopes_of(r), 'subscriptionId': r['subscriptionId'], 'resourceGroup': r['resourceGroup']}
        if t == 'microsoft.alertsmanagement/prometheusrulegroups':
            alert_rules = [x for x in (p.get('rules') or []) if x.get('alert')]
            act = [x for x in alert_rules if x.get('enabled', True) is not False and x.get('actions')]
            groups = sorted({short(a.get('actionGroupId') or a.get('actionGroupID') or '') for x in alert_rules for a in (x.get('actions') or [])})
            rules.append({**base, 'kind': 'prometheus-alert' if alert_rules else 'prometheus-recording', 'enabled': True if en is None else bool(en),
                          'clusterName': (p.get('clusterName') or '').lower(), 'alertCount': len(alert_rules),
                          'alertNames': [x.get('alert') for x in alert_rules], 'actionRulesCount': len(act), 'actionGroups': groups})
        elif t == 'microsoft.insights/metricalerts':
            crit = (p.get('criteria') or {}).get('allOf') or []
            rules.append({**base, 'kind': 'metric', 'enabled': bool(en), 'targetResourceType': (p.get('targetResourceType') or '').lower(),
                          'severity': p.get('severity'), 'metrics': [c.get('metricName') for c in crit],
                          'actionGroups': sorted({short(a.get('actionGroupId') or '') for a in (p.get('actions') or [])})})
        elif t == 'microsoft.insights/activitylogalerts':
            cond = (p.get('condition') or {}).get('allOf') or []
            cat = next((c.get('equals') for c in cond if c.get('field') == 'category'), None)
            rules.append({**base, 'kind': 'activity:' + str(cat), 'category': cat, 'enabled': bool(en),
                          'regions': [v for c in cond for v in (c.get('containsAny') or [])],
                          'actionGroups': sorted({short(a.get('actionGroupId') or '') for a in ((p.get('actions') or {}).get('actionGroups') or [])})})
        else:
            rules.append({**base, 'kind': t.split('/')[-1], 'enabled': bool(en)})
    return rules


def alerts_for(rules, rid, rtype):
    """Names of enabled alert rules that watch this resource (directly, or by resource group/subscription scope for its type)."""
    rid = rid.lower()
    rg_id = '/subscriptions/%s/resourcegroups/%s' % (sub_of(rid), (rg_of(rid) or '').lower())
    sub_id = '/subscriptions/%s' % sub_of(rid)
    hit = []
    for ru in rules:
        if not ru['enabled'] or ru['kind'] == 'prometheus-recording':
            continue
        if ru['kind'] == 'prometheus-alert':
            if rid in ru['scopes'] and ru['actionRulesCount'] > 0:
                hit.append(ru['name'])
        elif ru['kind'].startswith('activity:'):
            if ru.get('category') in ('ResourceHealth', 'Administrative') and (rid in ru['scopes'] or rg_id in ru['scopes']):
                hit.append(ru['name'])
        elif rid in ru['scopes'] or ((rg_id in ru['scopes'] or sub_id in ru['scopes']) and ru.get('targetResourceType') == rtype):
            hit.append(ru['name'])
    return hit


# ---------------------------------------------------------------------- resource rows
def build_aks_rows(d: Data, rules):
    pvc_ns = collections.defaultdict(set)
    for r in d.res:
        tags = {str(k).lower(): v for k, v in (r.get('tags') or {}).items()}
        if tags.get('kubernetes.io-created-for-pvc-namespace'):
            pvc_ns[r['resourceGroup'].lower()].add(tags['kubernetes.io-created-for-pvc-namespace'])
    rows = []
    for a in d.aks:
        p = a['properties']
        addons = p.get('addonProfiles') or {}
        oms = addons.get('omsagent') or addons.get('omsAgent') or {}
        amp = p.get('azureMonitorProfile') or {}
        ci = bool(oms.get('enabled')) or bool((amp.get('containerInsights') or {}).get('enabled'))
        ci_ws = (oms.get('config') or {}).get('logAnalyticsWorkspaceResourceID') or (amp.get('containerInsights') or {}).get('logAnalyticsWorkspaceResourceId')
        ext = d.aks_extra.get(a['id'].lower()) or {}
        ns = sorted(pvc_ns.get((ext.get('nodeRG') or '').lower(), set()))
        aps = [ap for ap in d.agentpools if ap['clusterId'].lower() == a['id'].lower()]
        pools = [ap['pool'] for ap in aps]
        sd = d.sec_aks.get(a['id'].lower()) or {}
        diag = sd.get('diagnosticSettings') or {}
        dsv = (diag.get('body') or {}).get('value') if diag.get('http') == 200 else None
        mc = d.sec_maint.get(a['id'].lower()) or {}
        up = p.get('autoUpgradeProfile') or {}
        ages = [x for x in (d.img_age_days(ap['nodeImage']) for ap in aps if ap['nodeImage']) if x is not None]
        net = p.get('networkProfile') or {}
        rows.append({
            'resourceName': a['name'], 'id': a['id'], 'subscriptionName': d.subname(a['subscriptionId']), 'resourceGroup': a['resourceGroup'],
            'location': a['location'], 'environment': d.env_of(a['subscriptionId'], a['name'], a.get('tags')), 'tier': (a.get('sku') or {}).get('tier'),
            'kubernetesVersion': p.get('currentKubernetesVersion') or p.get('kubernetesVersion'),
            'containerInsights': ci, 'containerInsightsWorkspace': short(ci_ws) if ci_ws else None, 'managedPrometheus': bool((amp.get('metrics') or {}).get('enabled')),
            'diagnosticSettingsCount': None if dsv is None else len(dsv),
            'alertRulesTargeting': alerts_for(rules, a['id'], 'microsoft.containerservice/managedclusters'),
            'leftoverContainerInsightsDcr': [x['name'] for x in d.dcr if x['name'].lower() == f"msci-{a['location']}-{a['name']}".lower()] if not ci else [],
            'pvcNamespaces': ns,
            'selfHostedMonitoringSignals': sorted({x for x in ns if x in SELF_MONITORING_NAMESPACES} | {x for x in pools if x in SELF_MONITORING_POOLS}),
            'vendor': vendor_of(d, a, ns), 'nodePools': pools,
            'networkPlugin': net.get('networkPlugin'), 'networkPolicy': net.get('networkPolicy'),
            'networkDataplane': net.get('networkDataplane'), 'outboundType': net.get('outboundType'),
            'podSubnet': any(pp.get('podSubnetID') for pp in (ext.get('podSubnets') or [])),
            'poolsWithoutZones': [ap['pool'] for ap in aps if not ap.get('zones')],
            'upgradeChannel': up.get('upgradeChannel'), 'nodeOSUpgradeChannel': up.get('nodeOSUpgradeChannel'),
            'maintenanceConfigurations': [m.get('name') for m in (mc.get('value') or [])] if mc.get('http') == 200 else None,
            'nodeImageAgeDaysMax': max(ages, default=None), 'nodeImageAgeDaysMin': min(ages, default=None),
            'addons': ext.get('addons'), 'tags': a.get('tags'),
            'createdByStandard': bool(d.cfg.created_by_standard(a.get('tags'))),
        })
    _add_activity(d, rows)
    return rows


def vendor_of(d: Data, cluster, namespaces):
    vendor = d.cfg.vendor(cluster['name'], cluster.get('resourceGroup') or '')
    return vendor or None


def _add_activity(d: Data, rows):
    by_cluster = collections.defaultdict(list)
    for s in d.aksact:
        for e in s.get('events') or []:
            m = re.match(r'(/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft.containerservice/managedclusters/[^/]+)',
                         (e.get('resourceId') or '').lower())
            if m:
                by_cluster[m.group(1)].append(e)
    for r in rows:
        ev = by_cluster.get(r['id'].lower(), [])

        def last(pred):
            xs = sorted((e['t'] for e in ev if pred(e)), reverse=True)
            return xs[0][:10] if xs else None
        op = lambda e: (e['op'] or '').lower()  # noqa: E731
        r['lastNodeImageUpgradeAction'] = last(lambda e: 'upgradenodeimageversion' in op(e))
        r['lastClusterWriteSucceeded'] = last(lambda e: op(e) == 'microsoft.containerservice/managedclusters/write' and e['status'] == 'Succeeded')
        r['lastAgentPoolWriteSucceeded'] = last(lambda e: op(e) == 'microsoft.containerservice/managedclusters/agentpools/write' and e['status'] == 'Succeeded')
        r['agentPoolWriteFailed90d'] = sum(1 for e in ev if op(e) == 'microsoft.containerservice/managedclusters/agentpools/write' and e['status'] == 'Failed')


def build_vm_rows(d: Data, rules):
    ext_by_vm = collections.defaultdict(list)
    for x in d.vmext:
        ext_by_vm[x['vmId']].append(x['extType'])
    vmi_dcr = {x['id'].lower() for x in d.dcr if x['name'].lower().startswith('msvmi-')}
    rows = []
    for v in d.vms:
        exts = ext_by_vm.get(v['id'].lower(), [])
        if v['resourceGroup'].lower().startswith('mc_') or any('aks' in e.lower() for e in exts):
            continue
        rec = d.vmdcra.get(v['id'].lower()) or {}
        dc = rec.get('value')
        vminsights = bool(dc and any((x.get('dcrId') or '').lower() in vmi_dcr or 'vminsights' in (x.get('name') or '').lower()
                                     or 'virtualmachineinsights' in (x.get('name') or '').lower() for x in dc)) or 'DependencyAgentLinux' in exts
        rows.append({'resourceName': v['name'], 'subscriptionName': d.subname(v['subscriptionId']), 'resourceGroup': v['resourceGroup'],
                     'environment': d.env_of(v['subscriptionId'], v['name'], v.get('tags')), 'power': (v.get('power') or '').replace('PowerState/', ''),
                     'dataDisks': v.get('dataDisks'),
                     'amaExtension': any(e in ('AzureMonitorLinuxAgent', 'AzureMonitorWindowsAgent') for e in exts),
                     'legacyAgent': any(e in ('OmsAgentForLinux', 'MicrosoftMonitoringAgent') for e in exts),
                     'dcrAssociations': None if dc is None else len(dc), 'dcraHttp': rec.get('http'), 'vmInsights': vminsights,
                     'patchMode': (v.get('linuxPatch') or v.get('winPatch') or {}).get('patchMode'),
                     'alerts': alerts_for(rules, v['id'], 'microsoft.compute/virtualmachines')})
    return rows


def build_key_rows(d: Data, rules):
    keep = DIAG_TYPES | {'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.network/virtualnetworkgateways',
                         'microsoft.network/virtualnetworks'}
    rows = []
    for t in d.targets:
        if t['type'] not in keep or (t['type'] == 'microsoft.storage/storageaccounts' and t['id'].lower() not in d.diag_idx):
            continue
        rec = d.diag_idx.get(t['id'].lower())
        diag_val, diag_http = None, None
        if rec:
            diag_http = rec['self']['http']
            if rec['self']['value'] is not None:
                vals = (rec['self']['value'] or []) + ((rec.get('blobServices') or {}).get('value') or [])
                diag_val = [{'name': x['name'], 'dest': short(x.get('workspaceId') or x.get('storageAccountId') or '') or ('eventHub' if x.get('eventHub') else None),
                             'logs': [l[0] for l in x['logs'] if l[1]]} for x in vals]
        sku = t.get('sku')
        rows.append({'resourceName': t['name'], 'type': t['type'], 'typeLabel': TYPE_LABEL.get(t['type'], t['type']),
                     'subscriptionName': d.subname(t['subscriptionId']), 'resourceGroup': t['resourceGroup'],
                     'environment': d.env_of(t['subscriptionId'], t['name'], t.get('tags')),
                     'diagnosticSettingsHttp': diag_http, 'diagnosticSettings': diag_val,
                     'hasDiagnosticLogs': None if diag_val is None else any(x['logs'] for x in diag_val),
                     'alerts': alerts_for(rules, t['id'], t['type']), 'monthCostUSD': d.storage_cost.get(t['id'].lower()),
                     'sku': sku.get('name') if isinstance(sku, dict) else sku, 'id': t['id'], 'tags': t.get('tags')})
    for t in d.rows('vnetgw'):
        if t['type'] in ('microsoft.network/virtualnetworkgateways', 'microsoft.network/expressroutecircuits'):
            rows.append({'resourceName': t['name'], 'type': t['type'], 'typeLabel': TYPE_LABEL.get(t['type']),
                         'subscriptionName': d.subname(t['subscriptionId']), 'resourceGroup': t['resourceGroup'],
                         'environment': d.sub_env(d.subname(t['subscriptionId'])), 'diagnosticSettingsHttp': None, 'diagnosticSettings': None,
                         'hasDiagnosticLogs': None, 'alerts': alerts_for(rules, t['id'], t['type']), 'gatewayType': t.get('gwType'),
                         'sku': t.get('sku'), 'id': t['id']})
    return rows


def coverage_by_type(key_rows, aks_rows, vm_rows):
    out = {}
    for t in sorted({k['type'] for k in key_rows}):
        ks = [k for k in key_rows if k['type'] == t]
        kp = [k for k in ks if is_prod(k['environment'])]
        checked = [k for k in ks if k['hasDiagnosticLogs'] is not None]
        with_logs = sum(1 for k in checked if k['hasDiagnosticLogs'])
        out[TYPE_LABEL.get(t, t)] = {'total': len(ks), 'prod': len(kp), 'withDiagnosticLogs': with_logs if checked else None,
                                     'diagnosticChecked': len(checked), 'diagnosticLogsPct': round(100 * with_logs / len(checked), 1) if checked else None,
                                     'withAlert': sum(1 for k in ks if k['alerts']), 'alertPct': round(100 * sum(1 for k in ks if k['alerts']) / len(ks), 1),
                                     'prodWithAlert': sum(1 for k in kp if k['alerts'])}
    if aks_rows:
        out['AKS 集群'] = {'total': len(aks_rows), 'prod': sum(1 for r in aks_rows if is_prod(r['environment'])),
                         'containerInsights': sum(1 for r in aks_rows if r['containerInsights']),
                         'managedPrometheus': sum(1 for r in aks_rows if r['managedPrometheus']),
                         'withDiagnosticSettings': sum(1 for r in aks_rows if r['diagnosticSettingsCount']),
                         'withAlert': sum(1 for r in aks_rows if r['alertRulesTargeting']),
                         'containerInsightsPct': round(100 * sum(1 for r in aks_rows if r['containerInsights']) / len(aks_rows), 1)}
    running = [v for v in vm_rows if v['power'] == 'running']
    out['虚拟机（非 AKS）'] = {'total': len(vm_rows), 'running': len(running), 'prodRunning': sum(1 for v in running if is_prod(v['environment'])),
                            'amaInstalled': sum(1 for v in vm_rows if v['amaExtension']), 'amaRunning': sum(1 for v in running if v['amaExtension']),
                            'withDcrAssociation': sum(1 for v in vm_rows if v['dcrAssociations']),
                            'vmInsights': sum(1 for v in vm_rows if v['vmInsights']), 'withAlert': sum(1 for v in vm_rows if v['alerts']),
                            'amaPct': round(100 * sum(1 for v in vm_rows if v['amaExtension']) / len(vm_rows), 1) if vm_rows else None}
    return out
