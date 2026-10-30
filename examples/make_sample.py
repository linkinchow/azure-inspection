"""Build the sample delivery (00-05) for a fictional customer, offline, with the plugin's own code.

Everything here is invented: the customer, subscriptions, resources, costs and problems. Nothing is read from Azure,
no token is requested and no `az` command runs.

How each report is produced:
- 01 cost: a fake Azure client answers Cost Management queries (query, forecast, budgets, subscription list) from an
  invented daily ledger, so the plugin's real cost collection and supplement code run unchanged; database/storage/log
  usage files are written in the collector's output format.
- 02 VM: invented inventory, 7-day metrics, SKU capabilities and Retail Price cache files, then the real `analyze`.
- 03/04: findings files written with the shared Findings class (one month back as well, to show the month-over-month
  comparison).
- 05: invented Resource Graph rows for storage accounts, MySQL and PostgreSQL, then the real peer `analyze`.
Then the real `build`, `crosscheck` and `package` commands run, and the packaged folder is copied to sample-output/.

Usage: python examples/make_sample.py [--workspace <dir>] [--keep]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import random
import shutil
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlencode, urlparse

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / 'plugins' / 'azure-inspection' / 'skills' / 'azure-monthly-inspection' / 'scripts'
sys.path.insert(0, str(SCRIPTS))
sys.dont_write_bytecode = True

from azinspect.cli import main as cli  # noqa: E402
from azinspect.core import config as config_mod  # noqa: E402
from azinspect.core.http import PRICES  # noqa: E402
from azinspect.core.io import Workspace, write_json  # noqa: E402
from azinspect.core.period import ReportPeriod  # noqa: E402
from azinspect.cost import collect as cost_collect  # noqa: E402
from azinspect.cost import supplement_costs  # noqa: E402
from azinspect.cost.model import build as build_model  # noqa: E402
from azinspect.waf import amba, common  # noqa: E402
from azinspect.waf.checks import type_label  # noqa: E402
from azinspect.waf.landing_zone import TITLES as LZ_TITLES  # noqa: E402
from azinspect.waf.landing_zone import checklist as lz_checklist  # noqa: E402

MONTH, PREV_MONTH = '2026-09', '2026-08'
TENANT = '7b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8'
RNG = random.Random(20260927)

SUBS = [  # id, name, state
    ('5a1e0c01-1111-4c2a-9a10-0000000000a1', 'shop-prod', 'Enabled'),
    ('5a1e0c01-1111-4c2a-9a10-0000000000a2', 'shop-test', 'Enabled'),
    ('5a1e0c01-1111-4c2a-9a10-0000000000a3', 'pay-prod', 'Enabled'),
    ('5a1e0c01-1111-4c2a-9a10-0000000000a4', 'data-prod', 'Enabled'),
    ('5a1e0c01-1111-4c2a-9a10-0000000000a5', 'shared-network', 'Enabled'),
    ('5a1e0c01-1111-4c2a-9a10-0000000000a6', 'old-lab', 'Disabled'),
]
SUB_ID = {name: sid for sid, name, _ in SUBS}
LOCATION = {'japaneast': 'ja east', 'eastus': 'us east', 'westeurope': 'eu west'}

CUSTOMER_YAML = f"""# 虚构客户，仅用于生成样例
customer:
  name: 示例客户
  fileName: Contoso

access:
  tenantId: {TENANT}
  readonlyAccount: inspection-readonly@contoso.example
  tokenSubscription: {SUBS[0][0]}

scope:
  includeSubscriptions: []
  excludeSubscriptions: []

rules:
  environmentTagKeys: [environment, env]
  environments:
    - {{label: test, match: '(^|[-_ ])(test|devtest|stg|staging|uat|qa)\\d*([-_ ]|$)'}}
    - {{label: dev,  match: '(^|[-_])(dev|sandbox|poc|lab)\\d*([-_]|$)'}}
    - {{label: prod, match: '(^|[-_])(prod|prd|production)\\d*([-_]|$)'}}
    - {{label: prod, match: '^shared-', appliesTo: subscription}}
  businessLines:
    - {{label: 电商, match: 'shop'}}
    - {{label: 支付, match: 'pay'}}
    - {{label: 数据平台, match: 'data'}}
    - {{label: 公共网络, match: 'shared'}}
  regionLabels:
    japaneast: 日本东部
    eastus: 美国东部
    westeurope: 西欧
  standardDeploymentTag:
    key: managed_by
    value: terraform

report:
  currency: USD
"""


def rid(sub, rg, rtype, name):
    return f'/subscriptions/{SUB_ID[sub]}/resourceGroups/{rg}/providers/{rtype}/{name}'


# ---------------------------------------------------------------- invented resources and daily ledger

VM_TYPE = 'Microsoft.Compute/virtualMachines'
# name, subscription, rg, region, size, hourly list price used for the ledger, first day (or None), last day (or None)
VMS = [
    ('shop-web-01', 'shop-prod', 'shop-rg', 'japaneast', 'Standard_D4s_v5', .248, None, None),
    ('shop-web-02', 'shop-prod', 'shop-rg', 'japaneast', 'Standard_D4s_v5', .248, None, None),
    ('shop-web-03', 'shop-prod', 'shop-rg', 'japaneast', 'Standard_D4s_v5', .248, None, None),
    ('shop-web-04', 'shop-prod', 'shop-rg', 'japaneast', 'Standard_D4s_v5', .248, None, None),
    ('shop-batch-01', 'shop-prod', 'shop-rg', 'japaneast', 'Standard_D8s_v5', .496, None, None),
    ('shop-search-01', 'shop-prod', 'shop-rg', 'japaneast', 'Standard_E8s_v5', .65, None, None),
    ('shop-web-test-01', 'shop-test', 'shop-test-rg', 'japaneast', 'Standard_D4s_v5', .248, None, None),
    ('shop-web-test-02', 'shop-test', 'shop-test-rg', 'japaneast', 'Standard_D4s_v5', .248, None, '2026-08-20'),
    ('pay-api-01', 'pay-prod', 'pay-rg', 'japaneast', 'Standard_D4s_v5', .248, None, None),
    ('pay-api-02', 'pay-prod', 'pay-rg', 'japaneast', 'Standard_D4s_v5', .248, None, None),
    ('data-etl-01', 'data-prod', 'data-rg', 'eastus', 'Standard_E8s_v5', .504, None, None),
    ('data-worker-01', 'data-prod', 'data-rg', 'eastus', 'Standard_D8s_v5', .384, '2026-09-12', None),
    ('edge-fw-01', 'shop-prod', 'shop-net-rg', 'japaneast', 'Standard_D4s_v5', .248, None, None),   # firewall appliance (Marketplace image)
]
APPLIANCES = {'edge-fw-01': 'paloaltonetworks'}
# name, subscription, rg, region, service, type, meter (category, subcategory, meter, unit), daily cost, daily quantity, first day
FIXED = [
    ('shop-aks', 'shop-prod', 'shop-rg', 'japaneast', 'Azure Kubernetes Service', 'Microsoft.ContainerService/managedClusters',
     ('Azure Kubernetes Service', 'Standard', 'Uptime SLA', '1 Hour'), 2.4, 24, None),
    ('shop-mysql-prod', 'shop-prod', 'shop-rg', 'japaneast', 'Azure Database for MySQL', 'Microsoft.DBforMySQL/flexibleServers',
     ('Azure Database for MySQL', 'Flexible Server General Purpose Dsv4 Series', '4 vCore', '1 Hour'), 23.6, 24, None),
    ('shop-mysql-test', 'shop-test', 'shop-test-rg', 'japaneast', 'Azure Database for MySQL', 'Microsoft.DBforMySQL/flexibleServers',
     ('Azure Database for MySQL', 'Flexible Server Burstable BS Series', 'B2ms', '1 Hour'), 4.1, 24, None),
    ('pay-mysql-prod', 'pay-prod', 'pay-rg', 'japaneast', 'Azure Database for MySQL', 'Microsoft.DBforMySQL/flexibleServers',
     ('Azure Database for MySQL', 'Flexible Server General Purpose Dsv4 Series', '4 vCore', '1 Hour'), 23.6, 24, None),
    ('pay-pg-prod', 'pay-prod', 'pay-rg', 'japaneast', 'Azure Database for PostgreSQL', 'Microsoft.DBforPostgreSQL/flexibleServers',
     ('Azure Database for PostgreSQL', 'Flexible Server General Purpose Ddsv5 Series', '4 vCore', '1 Hour'), 24.9, 24, '2026-09-08'),
    ('data-pg-prod', 'data-prod', 'data-rg', 'eastus', 'Azure Database for PostgreSQL', 'Microsoft.DBforPostgreSQL/flexibleServers',
     ('Azure Database for PostgreSQL', 'Flexible Server General Purpose Ddsv5 Series', '8 vCore', '1 Hour'), 41.5, 24, None),
    ('shop-redis-prod', 'shop-prod', 'shop-rg', 'japaneast', 'Redis Cache', 'Microsoft.Cache/Redis',
     ('Redis Cache', 'Premium', 'P1 Cache Instance', '1 Hour'), 13.2, 24, None),
    ('shop-appgw', 'shop-prod', 'shop-rg', 'japaneast', 'Application Gateway', 'Microsoft.Network/applicationGateways',
     ('Application Gateway', 'WAF v2', 'Standard Fixed Cost', '1 Hour'), 11.8, 24, None),
    ('pay-kv', 'pay-prod', 'pay-rg', 'japaneast', 'Key Vault', 'Microsoft.KeyVault/vaults',
     ('Key Vault', 'Standard', 'Operations', '10K'), .9, 300, None),
    ('shared-vpn', 'shared-network', 'network-rg', 'japaneast', 'VPN Gateway', 'Microsoft.Network/virtualNetworkGateways',
     ('VPN Gateway', 'VpnGw2', 'VpnGw2', '1 Hour'), 11.7, 24, None),
]


def days(month):
    first = dt.date.fromisoformat(month + '-01')
    nxt = (first.replace(day=28) + dt.timedelta(days=4)).replace(day=1)
    return [first + dt.timedelta(days=i) for i in range((nxt - first).days)]


def weekday_factor(d):
    return .7 if d.weekday() >= 5 else 1.0


def ledger():
    """Daily cost lines for Aug, Sep and Oct 1-26 (Oct is the forecast month's actual part)."""
    lines = []
    span = days('2026-08') + days('2026-09') + [d for d in days('2026-10') if d.day <= 26]

    def add(d, sub, rg, region, service, rtype, name, meter, qty, cost):
        lines.append({'sub': sub, 'date': d, 'ServiceName': service, 'ResourceGroupName': rg, 'ResourceId': rid(sub, rg, rtype, name).lower(),
                      'ResourceType': rtype.lower(),
                      'ResourceLocation': LOCATION[region], 'PricingModel': 'OnDemand', 'MeterCategory': meter[0], 'MeterSubcategory': meter[1],
                      'Meter': meter[2], 'UnitOfMeasure': meter[3], 'MeterId': f'{service}|{meter[2]}', 'qty': qty, 'cost': round(cost, 4)})
    for d in span:
        iso = d.isoformat()
        for name, sub, rg, region, size, price, first, last in VMS:
            if (first and iso < first) or (last and iso > last):
                continue
            meter = ('Virtual Machines', size.split('_')[1].upper() + ' Series', size.replace('Standard_', '').replace('_', ' '), '1 Hour')
            add(d, sub, rg, region, 'Virtual Machines', VM_TYPE, name, meter, 24, 24 * price)
            add(d, sub, rg, region, 'Storage', 'Microsoft.Compute/disks', name + '-osdisk', ('Storage', 'Premium SSD Managed Disks', 'P10 LRS Disk', '1/Month'), 1 / 30, 19.71 / 30)
        for name, sub, rg, region, service, rtype, meter, cost, qty, first in FIXED:
            if first and iso < first:
                continue
            add(d, sub, rg, region, service, rtype, name, meter, qty, cost)
        # storage that grows, AI tokens that grow in September, logs, bandwidth
        growth = (d - dt.date(2026, 8, 1)).days
        for name, sub, rg, region, gb0, per_day in (('shopassets', 'shop-prod', 'shop-rg', 'japaneast', 4200, 18),
                                                    ('datalakeraw', 'data-prod', 'data-rg', 'eastus', 18000, 140),
                                                    ('payreceipts', 'pay-prod', 'pay-rg', 'japaneast', 600, 2)):
            gb = gb0 + per_day * growth
            add(d, sub, rg, region, 'Storage', 'Microsoft.Storage/storageAccounts', name, ('Storage', 'Hot LRS', 'Hot LRS Data Stored', '1 GB/Month'),
                gb / 30, gb * .0196 / 30)
        tokens = (1800 if d.month == 8 else 2600 if d.month == 9 else 2900) * weekday_factor(d) * (1 + RNG.uniform(-.06, .06))
        add(d, 'data-prod', 'data-rg', 'eastus', 'Azure OpenAI', 'Microsoft.CognitiveServices/accounts', 'data-openai',
            ('Cognitive Services', 'Azure OpenAI', 'gpt-4o-mini Input Tokens', '1K'), tokens * 10, tokens * .00165 * 10)
        for name, sub, rg, region, gb in (('shop-logs', 'shop-prod', 'shop-rg', 'japaneast', 38), ('data-logs', 'data-prod', 'data-rg', 'eastus', 22)):
            gb *= weekday_factor(d) * (1.25 if name == 'shop-logs' and d >= dt.date(2026, 9, 15) else 1)
            add(d, sub, rg, region, 'Log Analytics', 'Microsoft.OperationalInsights/workspaces', name,
                ('Log Analytics', 'Analytics Logs', 'Data Ingestion', '1 GB'), gb, gb * 2.99)
        out = 900 * weekday_factor(d) * (1 + RNG.uniform(-.1, .1))
        add(d, 'shop-prod', 'shop-rg', 'japaneast', 'Bandwidth', 'Microsoft.Network/applicationGateways', 'shop-appgw',
            ('Bandwidth', 'Inter-Region', 'Data Transfer Out', '1 GB'), out, out * .114)
    return lines


# ---------------------------------------------------------------- fake Azure client (Cost Management, subscriptions, budgets)

class FakeAzure:
    """Answers the read-only calls the cost collector makes, from the invented ledger. No network."""

    def __init__(self, lines):
        self.lines = lines
        self.calls = []
        self.by_sub = defaultdict(list)
        for x in lines:
            self.by_sub[SUB_ID[x['sub']]].append(x)

    def get_all(self, path, check, target='', max_pages=200):
        return [{'subscriptionId': sid, 'displayName': name, 'state': state, 'tenantId': TENANT} for sid, name, state in SUBS], 200, None

    def request(self, method, url, check, target='', body=None, **_kw):
        path = urlparse(url).path
        sid = path.split('/')[2]
        if dict((s, st) for s, _n, st in SUBS).get(sid) != 'Enabled':
            return 404, None, 'SubscriptionNotFound: The subscription is disabled.'
        if 'Microsoft.Consumption/budgets' in path:
            budgets = []
            if sid == SUB_ID['shop-prod']:
                budgets.append({'id': f'/subscriptions/{sid}/providers/Microsoft.Consumption/budgets/shop-monthly', 'name': 'shop-monthly',
                                'properties': {'timeGrain': 'Monthly', 'amount': 15000.0, 'category': 'Cost',
                                               'timePeriod': {'startDate': '2026-01-01T00:00:00Z', 'endDate': '2026-12-31T00:00:00Z'},
                                               'currentSpend': {'amount': 11840.0, 'unit': 'USD'}}})
            return 200, {'value': budgets}, None
        if path.endswith('/forecast'):
            return 200, self.forecast(sid, body), None
        return 200, self.query(sid, body), None

    def query(self, sid, body):
        lo, hi = body['timePeriod']['from'][:10], body['timePeriod']['to'][:10]
        dims = [g['name'] for g in body['dataset'].get('grouping') or []]
        daily = body['dataset']['granularity'] == 'Daily'
        qty = 'totalQuantity' in body['dataset']['aggregation']
        flt = ((body['dataset'].get('filter') or {}).get('dimensions') or {})
        agg = defaultdict(lambda: [0.0, 0.0])
        for x in self.by_sub[sid]:
            iso = x['date'].isoformat()
            if not lo <= iso <= hi or (flt and x[flt['name']] not in flt['values']):
                continue
            key = ((int(iso.replace('-', '')),) if daily else ()) + tuple(x[d] for d in dims)
            agg[key][0] += x['cost']
            agg[key][1] += x['qty']
        columns = [{'name': 'Cost', 'type': 'Number'}] + ([{'name': 'UsageQuantity', 'type': 'Number'}] if qty else []) \
            + ([{'name': 'UsageDate', 'type': 'Number'}] if daily else []) + [{'name': d, 'type': 'String'} for d in dims] + [{'name': 'Currency', 'type': 'String'}]
        rows = [[round(v[0], 6)] + ([round(v[1], 6)] if qty else []) + list(k) + ['USD'] for k, v in sorted(agg.items(), key=lambda kv: str(kv[0]))]
        return {'properties': {'columns': columns, 'rows': rows, 'nextLink': None}}

    def forecast(self, sid, body):
        lo, hi = body['timePeriod']['from'][:10], body['timePeriod']['to'][:10]
        actual = defaultdict(float)
        for x in self.by_sub[sid]:
            iso = x['date'].isoformat()
            if lo <= iso <= hi:
                actual[iso] += x['cost']
        rows, recent = [], [v for _k, v in sorted(actual.items())][-7:]
        level = sum(recent) / len(recent) if recent else None
        for d in (dt.date.fromisoformat(lo) + dt.timedelta(days=i) for i in range((dt.date.fromisoformat(hi) - dt.date.fromisoformat(lo)).days + 1)):
            iso = d.isoformat()
            if iso in actual:
                rows.append([round(actual[iso], 6), int(iso.replace('-', '')), 'Actual', 'USD'])
            elif level is not None:
                rows.append([round(level * weekday_factor(d), 6), int(iso.replace('-', '')), 'Forecast', 'USD'])
        columns = [{'name': n, 'type': t} for n, t in (('Cost', 'Number'), ('UsageDate', 'Number'), ('CostStatus', 'String'), ('Currency', 'String'))]
        return {'properties': {'columns': columns, 'rows': rows, 'nextLink': None}}


def cost_part(ws, cfg, period, lines):
    client = FakeAzure(lines)
    cost_collect.collect(ws, cfg, client, period)
    model = build_model(ws, period)
    supplement_costs.collect(ws, cfg, client, period, model)
    sep = defaultdict(float)
    for x in lines:
        if x['date'].strftime('%Y-%m') == MONTH:
            sep[x['ResourceId']] += x['cost']
    snapshot = '2026-10-26T10:00:00+00:00'
    period_info = {'start': '2026-09-01T00:00:00Z', 'end': '2026-10-01T00:00:00Z', 'days': 30}
    cost_of = lambda sub, rg, rtype, name: round(sep.get(rid(sub, rg, rtype, name).lower(), 0.0), 2) or None

    def db(name, sub, rg, rtype, sku, cpu, mem, storage, used_gib=None, days_valid=30):
        flags = ['LOW_UTILIZATION'] if cpu < 20 and mem < 20 and days_valid == 30 else []
        av = {'cpu': cpu, 'memory': mem, 'storage': storage}
        if used_gib is not None:
            av['usedMemoryBytesGiB'] = used_gib
        return {'subscriptionId': SUB_ID[sub], 'subscriptionName': sub, 'resourceGroup': rg, 'name': name, 'type': rtype.lower(),
                'region': 'japaneast' if sub != 'data-prod' else 'eastus', 'resourceId': rid(sub, rg, rtype, name), 'curCostUSD': cost_of(sub, rg, rtype, name),
                'skuName': sku, 'skuTier': 'GeneralPurpose', 'averages': av, 'validDays': {k: days_valid for k in ('cpu', 'memory', 'storage')},
                'coverage': 'complete' if days_valid == 30 else 'partial', 'flags': flags}
    mysql, pg, redis = 'Microsoft.DBforMySQL/flexibleServers', 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.Cache/Redis'
    dbs = [db('shop-mysql-prod', 'shop-prod', 'shop-rg', mysql, 'Standard_D4ds_v4', 38.2, 61.5, 44.0),
           db('pay-mysql-prod', 'pay-prod', 'pay-rg', mysql, 'Standard_D4ds_v4', 9.4, 16.8, 21.0),
           db('shop-mysql-test', 'shop-test', 'shop-test-rg', mysql, 'Standard_B2ms', 4.1, 12.3, 8.0),
           db('pay-pg-prod', 'pay-prod', 'pay-rg', pg, 'Standard_D4ds_v5', 22.5, 35.1, 12.0, days_valid=23),
           db('data-pg-prod', 'data-prod', 'data-rg', pg, 'Standard_D8ds_v5', 41.0, 58.3, 71.0),
           db('shop-redis-prod', 'shop-prod', 'shop-rg', redis, 'Premium', 7.9, 12.0, None, used_gib=0.71)]
    dbs[-1].update(skuFamily='P', skuCapacity=1)
    for r in dbs:
        r['flags'] = r['flags'] if r['curCostUSD'] else []
    cov = defaultdict(lambda: {'found': 0, 'complete': 0, 'curCostUSD': 0.0})
    for r in dbs:
        c = cov[r['type']]
        c['found'] += 1
        c['complete'] += r['coverage'] == 'complete'
        c['curCostUSD'] = round(c['curCostUSD'] + (r['curCostUSD'] or 0), 2)
    write_json(ws.raw('cost/resources/databases.json'), {'snapshotAt': snapshot, 'period': period_info, 'complete': True, 'coverage': dict(cov), 'resources': dbs})
    st = 'Microsoft.Storage/storageAccounts'
    accounts = []
    for name, sub, rg, first, last, tiers, policy, egress in (
            ('datalakeraw', 'data-prod', 'data-rg', 22340, 26400, {'Hot': 26400}, {'status': '未配置'}, 310),
            ('shopassets', 'shop-prod', 'shop-rg', 4750, 5270, {'Hot': 5100, 'Cool': 170}, {'status': '已配置', 'ruleCount': 1,
                                                                                           'rules': [{'name': 'move-old-images', 'actions': ['tierToCool']}]}, 2400),
            ('payreceipts', 'pay-prod', 'pay-rg', 662, 720, {'Hot': 720}, {'status': '未配置'}, 12)):
        accounts.append({'subscriptionId': SUB_ID[sub], 'subscriptionName': sub, 'resourceGroup': rg, 'name': name, 'region': 'japaneast' if sub != 'data-prod' else 'eastus',
                         'resourceId': rid(sub, rg, st, name), 'kind': 'StorageV2', 'skuName': 'Standard_LRS', 'redundancy': 'LRS', 'accessTier': 'Hot',
                         'createdAt': '2025-03-02T00:00:00Z', 'curCostUSD': cost_of(sub, rg, st, name),
                         'usedCapacity': {'firstBytes': first * 2**30, 'lastGiB': last, 'growthGiB': last - first, 'growthPct': round((last - first) / first * 100, 2), 'validDays': 30},
                         'egressGiBCur': egress, 'tierMixLastDayGiB': tiers, 'lifecyclePolicy': policy, 'coverage': 'complete'})
    accounts.sort(key=lambda a: -(a['curCostUSD'] or 0))
    write_json(ws.raw('cost/resources/storage.json'), {'snapshotAt': snapshot, 'period': period_info, 'complete': True, 'accounts': accounts,
                                                       'coverage': {'found': 3, 'complete': 3, 'curCostGE50': 3, 'curCostUSD': round(sum(a['curCostUSD'] or 0 for a in accounts), 2),
                                                                    'lifecycle': {'已配置': 1, '未配置': 2}}})
    la = 'Microsoft.OperationalInsights/workspaces'
    workspaces = []
    for name, sub, rg, gb, top in (('shop-logs', 'shop-prod', 'shop-rg', 1290, 'ContainerLogV2'), ('data-logs', 'data-prod', 'data-rg', 560, 'AzureDiagnostics')):
        workspaces.append({'subscriptionId': SUB_ID[sub], 'subscriptionName': sub, 'resourceGroup': rg, 'name': name, 'region': 'japaneast' if sub != 'data-prod' else 'eastus',
                           'resourceId': rid(sub, rg, la, name), 'retentionInDays': 30, 'dailyQuotaGb': -1, 'curCostUSD': cost_of(sub, rg, la, name),
                           'billableGB': gb, 'byDataType': [{'DataType': top, 'BillableGB': round(gb * .82, 1)}, {'DataType': 'Perf', 'BillableGB': round(gb * .12, 1)}],
                           'top3': True,
                           'topDataTypeBreakdown': {'dataType': top, 'window': '2026-09-24..2026-10-01（7天）', 'rows': [
                               {'ContainerName': 'checkout-api', 'BilledGB': round(gb * .3, 1)} if top == 'ContainerLogV2' else {'Category': 'PostgreSQLLogs', 'BilledGB': round(gb * .2, 1)},
                               {'ContainerName': 'catalog-sync', 'BilledGB': round(gb * .12, 1)} if top == 'ContainerLogV2' else {'Category': 'QueryStoreRuntimeStatistics', 'BilledGB': 0.4}]}})
    write_json(ws.raw('cost/resources/logs.json'), {'snapshotAt': snapshot, 'complete': True, 'workspaces': workspaces, 'top3ByBillableGB': ['shop-logs', 'data-logs'],
                                                    'period': {**period_info, 'sourceWindow': ['2026-09-24', '2026-10-01']},
                                                    'coverage': {'found': 2, 'curCostGE50': 2, 'diagnosticSettingsChecked': 5, 'resourcesWithDuplicateDestinations': 0,
                                                                 'curCostUSD': round(sum(w['curCostUSD'] or 0 for w in workspaces), 2)}})


# ---------------------------------------------------------------- 02: VM inventory, metrics, SKUs and price cache

SKU_SPEC = {  # vCPUs, memory GiB, uncached IOPS, uncached bytes/s, cached IOPS, cached read bytes/s, max data disks
    'Standard_D2s_v5': (2, 8, 3750, 89128960, 9000, 131072000, 4), 'Standard_D4s_v5': (4, 16, 6400, 152043520, 19000, 262144000, 8),
    'Standard_D8s_v5': (8, 32, 12800, 304087040, 38000, 524288000, 16), 'Standard_E2s_v5': (2, 16, 3750, 89128960, 9000, 131072000, 4),
    'Standard_E4s_v5': (4, 32, 6400, 152043520, 19000, 262144000, 8), 'Standard_E8s_v5': (8, 64, 12800, 304087040, 38000, 524288000, 16),
}
EASTUS_PRICE = {'Standard_D2s_v5': .096, 'Standard_D4s_v5': .192, 'Standard_D8s_v5': .384, 'Standard_E2s_v5': .126, 'Standard_E4s_v5': .252, 'Standard_E8s_v5': .504}
REGION_FACTOR = {'eastus': 1.0, 'japaneast': 1.29}
# cpu %, available memory %, IO % (uncached iops, uncached bw, cached iops, cached bw) over the 7-day window
VM_METRICS = {
    'shop-web-01': (6.5, 72, (4, 6, 3, 2)), 'shop-web-02': (7.1, 70, (4, 6, 3, 2)), 'shop-web-03': (6.2, 71, (4, 5, 3, 2)),
    'shop-web-04': (5.8, 73, (4, 5, 3, 2)), 'shop-batch-01': (86.0, 41, (22, 30, 11, 9)), 'shop-search-01': (14.2, 85, (9, 12, 6, 4)),
    'shop-web-test-01': (3.1, 88, (2, 2, 1, 1)), 'pay-api-01': (24.5, 58, (6, 8, 4, 3)), 'pay-api-02': (23.8, 57, (6, 8, 4, 3)),
    'data-etl-01': (12.4, 84, (14, 21, 7, 5)), 'data-worker-01': (31.0, 62, (11, 16, 7, 5)), 'edge-fw-01': (4.2, 1, (2, 3, 1, 1)),
}


def caps(name):
    c, m, ui, ub, ci, cb, dd = SKU_SPEC[name]
    return [{'name': k, 'value': str(v)} for k, v in (
        ('vCPUs', c), ('vCPUsAvailable', c), ('MemoryGB', m), ('UncachedDiskIOPS', ui), ('UncachedDiskBytesPerSecond', ub),
        ('CombinedTempDiskAndCachedIOPS', ci), ('CombinedTempDiskAndCachedReadBytesPerSecond', cb), ('MaxDataDiskCount', dd),
        ('MaxNetworkInterfaces', 2 if c <= 2 else 4), ('MaxResourceVolumeMB', 0), ('PremiumIO', 'True'), ('CpuArchitectureType', 'x64'),
        ('AcceleratedNetworkingEnabled', 'True'), ('HyperVGenerations', 'V1,V2'), ('EncryptionAtHostSupported', 'True'))]


def metric(avg, window_days):
    daily = [{'timeStamp': d + 'T00:00:00Z', 'average': round(avg * (1 + .03 * ((i % 3) - 1)), 3), 'count': 1440} for i, d in enumerate(window_days)]
    count = sum(x['count'] for x in daily)
    return {'average': sum(x['average'] * x['count'] for x in daily) / count, 'sampleCount': count, 'validDays': 7, 'daily': daily}


def vm_part(ws):
    window_days = [(dt.date(2026, 10, 19) + dt.timedelta(days=i)).isoformat() for i in range(7)]
    rows = []
    for name, sub, rg, region, size, _price, first, last in VMS:
        sid, vid = SUB_ID[sub], rid(sub, rg, VM_TYPE, name)
        state = 'PowerState/deallocated' if last else 'PowerState/running'
        cpu, avail, io = VM_METRICS.get(name, (None, None, (None,) * 4))
        metrics = {}
        if state.endswith('running'):
            for mname, value in zip(('Percentage CPU', 'Available Memory Percentage', 'VM Uncached IOPS Consumed Percentage',
                                     'VM Uncached Bandwidth Consumed Percentage', 'VM Cached IOPS Consumed Percentage',
                                     'VM Cached Bandwidth Consumed Percentage'), (cpu, avail) + io):
                metrics[mname] = metric(value, window_days)
        rows.append({'id': vid, 'name': name, 'metricName': name, 'instanceId': None, 'metricResourceId': vid, 'kind': 'vm', 'subscriptionId': sid,
                     'subscriptionName': sub, 'resourceGroup': rg, 'region': region, 'size': size, 'state': state,
                     'createdAt': (first or '2025-06-01') + 'T00:00:00Z',
                     'osDisk': {'name': name + '-osdisk', 'osType': 'Linux', 'diskSizeGB': 128, 'managedDisk': {'storageAccountType': 'Premium_LRS'}},
                     'dataDisks': [{'name': name + '-data', 'diskSizeGB': 512, 'lun': 0, 'managedDisk': {'storageAccountType': 'Premium_LRS'}}] if 'batch' in name or 'etl' in name or 'search' in name else [],
                     'networkInterfaces': [{'id': rid(sub, rg, 'Microsoft.Network/networkInterfaces', name + '-nic')}], 'securityProfile': {},
                     'licenseType': None, 'priority': 'Regular', 'tags': {'managed_by': 'terraform'} if sub != 'shop-test' else {}, 'metrics': metrics})
    write_json(ws.raw('vm/metrics/vms-average.json'), rows)
    write_json(ws.raw('vm/inventory/resources.json'), [
        {'id': r['id'], 'name': r['name'], 'type': VM_TYPE, 'subscriptionId': r['subscriptionId'], 'resourceGroup': r['resourceGroup'],
         'plan': {'publisher': APPLIANCES[r['name']], 'product': 'vmseries-flex', 'name': 'byol'} if r['name'] in APPLIANCES else None,
         'properties': {'storageProfile': {'imageReference': {'publisher': APPLIANCES.get(r['name'], 'Canonical'), 'offer': 'x', 'sku': 'y'}}}}
        for r in rows])
    envelopes = defaultdict(list)
    for name, sub, _rg, region, *_ in VMS:
        envelopes[(SUB_ID[sub], region)] = [{'name': s, 'capabilities': caps(s), 'restrictions': [], 'locationInfo': [{'location': region, 'zones': ['1', '2', '3']}]}
                                            for s in SKU_SPEC]
    write_json(ws.raw('vm/metrics/sku-capabilities.json'), [{'subscriptionId': s, 'region': r, 'items': items} for (s, r), items in envelopes.items()])
    write_json(ws.raw('vm/inventory/aks-pools.json'), [])
    write_json(ws.raw('vm/inventory/subscriptions.json'), [
        {'id': sid, 'name': name, 'state': state, 'tenantId': TENANT, 'inventoryStatus': 'ok' if state == 'Enabled' else 'unverified',
         'inventoryErrors': [] if state == 'Enabled' else ['订阅未启用，无法读取'], 'vmCount': sum(1 for v in VMS if v[1] == name)} for sid, name, state in SUBS])
    write_json(ws.raw('vm/metrics/manifest.json'), {'start': '2026-10-19T00:00:00Z', 'end': '2026-10-26T00:00:00Z', 'interval': 'P1D', 'aggregation': 'Average,Count',
                                                    'queriedAt': '2026-10-26T09:00:00+00:00', 'inventorySnapshotAt': '2026-10-26T08:55:00+00:00',
                                                    'subscriptionCount': len(SUBS), 'metricNames': list(next(r['metrics'] for r in rows if r['metrics']))})
    for region in ('japaneast', 'eastus'):
        names = list(SKU_SPEC)
        filt = (f"serviceName eq 'Virtual Machines' and armRegionName eq '{region}' and ("
                + ' or '.join(f"armSkuName eq '{n}'" for n in names) + ')')
        source = PRICES + '?' + urlencode({'api-version': '2023-01-01-preview', 'currencyCode': "'USD'", '$filter': filt})
        items = []
        for n in names:
            hourly = round(EASTUS_PRICE[n] * REGION_FACTOR[region], 4)
            base = {'currencyCode': 'USD', 'armRegionName': region, 'armSkuName': n, 'productName': f'Virtual Machines {n.split("_")[1][0]}sv5 Series',
                    'skuName': n.replace('Standard_', '').replace('_', ' '), 'meterName': n.replace('Standard_', '').replace('_', ' '),
                    'unitOfMeasure': '1 Hour', 'effectiveStartDate': '2025-01-01T00:00:00Z', 'tierMinimumUnits': 0, 'meterId': f'{region}-{n}'}
            items.append({**base, 'type': 'Consumption', 'retailPrice': hourly,
                          'savingsPlan': [{'term': '1 Year', 'retailPrice': round(hourly * .68, 4)}, {'term': '3 Years', 'retailPrice': round(hourly * .48, 4)}]})
            items.append({**base, 'type': 'Reservation', 'reservationTerm': '1 Year', 'retailPrice': round(hourly * 8760 * .6, 2)})
            items.append({**base, 'type': 'Reservation', 'reservationTerm': '3 Years', 'retailPrice': round(hourly * 26280 * .4, 2)})
        write_json(ws.raw(f'vm/prices/vm-{region}-sample.json'), {'filter': filt, 'source': source, 'queriedAt': '2026-10-26T09:05:00+00:00',
                                                                  'priceAsOfDate': '2026-10-26', 'items': items})


# ---------------------------------------------------------------- 03/04: findings per pillar (two months)

def waf_part(ws, cfg, month):
    sep = month == MONTH
    snap = '2026-10-26' if sep else '2026-09-26'
    end = dt.date.fromisoformat(snap)
    window = {'start': (end - dt.timedelta(days=30)).isoformat() + 'T00:00:00Z', 'end': snap + 'T00:00:00Z', 'days': 30, 'snapshot': snap}
    write_json(ws.raw('waf/scope.json'), {'collectedAt': snap + 'T08:00:00+00:00',
                                          'subscriptions': [{'id': sid, 'name': name, 'state': state, 'tenantId': TENANT} for sid, name, state in SUBS]})
    e = lambda sub, name='': common.env(cfg, sub, name)
    ok = lambda n=1: {'attempted': n, 'succeeded': n, 'denied': 0, 'otherErrors': 0, 'notes': []}
    vm_t, db_my, db_pg = 'Microsoft.Compute/virtualMachines', 'Microsoft.DBforMySQL/flexibleServers', 'Microsoft.DBforPostgreSQL/flexibleServers'
    aks, st, redis = 'Microsoft.ContainerService/managedClusters', 'Microsoft.Storage/storageAccounts', 'Microsoft.Cache/Redis'

    def m(names, rtype, sub):
        return [{'name': n, 'type': rtype, 'subscription': sub} for n in names]

    def write(pillar, findings, checks, inventory=None):
        findings.write(ws, window=window, coverage={c: ok() for c in checks}, scope={'subscriptions': len(SUBS)}, inventory=inventory or {})

    f = common.Findings('reliability')
    f.add('R5', '高', 'MySQL pay-mysql-prod（生产）没有开启高可用，也没有开启异地备份；所在可用区故障时支付服务不可用，备份也只保存在同一区域。',
          '开启跨可用区高可用，并开启异地冗余备份（需维护窗口）', subscription='pay-prod', resource_group='pay-rg', resource_name='pay-mysql-prod',
          resource_type=db_my, environment=e('pay-prod', 'pay-mysql-prod'), needs_confirmation='确认支付库的恢复时间目标（RTO）和数据丢失容忍度（RPO）。')
    f.add('R5', '中', 'MySQL shop-mysql-prod（生产）已开启同可用区高可用，但没有开启异地备份。', '开启异地冗余备份',
          subscription='shop-prod', resource_group='shop-rg', resource_name='shop-mysql-prod', resource_type=db_my, environment=e('shop-prod', 'shop-mysql-prod'))
    f.add('R7', '中', '2 台保存数据的生产虚拟机没有配置备份：shop-batch-01（512 GiB 数据盘）、shop-search-01（512 GiB 数据盘）。',
          '确认数据是否可以重建；不可重建的配置 Azure Backup，并做一次恢复测试', subscription='shop-prod', resource_name='2 台虚拟机', key='vm-backup',
          members=m(['shop-batch-01', 'shop-search-01'], vm_t, 'shop-prod'), environment=e('shop-prod'))
    f.add('R3', '中', '4 台前端虚拟机 shop-web-01～04 都部署在同一可用区，没有分布到多个可用区。', '新建虚拟机时分布到 3 个可用区，或改用虚拟机规模集',
          subscription='shop-prod', resource_name='4 台虚拟机', key='web-zones', members=m([f'shop-web-0{i}' for i in range(1, 5)], vm_t, 'shop-prod'), environment=e('shop-prod'))
    f.add('R6', '中', '存储账户 datalakeraw（约 26 TiB）为本地冗余（LRS），没有开启 Blob 软删除；误删或机房故障时数据无法恢复。',
          '开启 Blob 与容器软删除；按数据重要性改为 ZRS 或 GRS', subscription='data-prod', resource_group='data-rg', resource_name='datalakeraw',
          resource_type=st, environment=e('data-prod', 'datalakeraw'))
    f.add('R4', '中', 'AKS 集群 shop-aks（生产）使用 Free 层，控制面没有 SLA。', '升级到 Standard 层', subscription='shop-prod', resource_group='shop-rg',
          resource_name='shop-aks', resource_type=aks, environment=e('shop-prod', 'shop-aks'))
    f.add('R9', '低', 'AKS 集群 shop-aks 的 Kubernetes 版本 1.31 将在 3 个月内结束标准支持。', '规划升级到 1.33，并开启自动升级通道',
          subscription='shop-prod', resource_group='shop-rg', resource_name='shop-aks', resource_type=aks, environment=e('shop-prod', 'shop-aks'))
    if sep:  # version end of support and retirement notices are checked from this month
        f.add('R9', '高', '订阅 pay-prod 中的 MySQL 服务器 pay-mysql-prod 使用 MySQL 5.7，标准支持已于 2026-09-30 结束，'
              '已自动进入付费的延长支持（到 2029-03-31），在升级前会持续产生额外费用。',
              '升级到仍在标准支持期内的大版本（先在只读副本或测试环境验证，升级前备份）；升级后不再产生延长支持费用。',
              subscription='pay-prod', resource_group='pay-rg', resource_name='pay-mysql-prod', resource_type='Microsoft.DBforMySQL/flexibleServers',
              environment=e('pay-prod', 'pay-mysql-prod'), key='lifecycle|mysql|5.7|pay-prod')
        f.add('R9', '高', '订阅 data-prod 中的虚拟机 data-worker-01 使用 CentOS 7，标准支持已于 2024-06-30 结束。',
              '升级到仍受支持的系统版本，或用新镜像重建；完成前可启用延长安全更新作为过渡（Windows Server ESU 在 Azure 上免费，Ubuntu Pro 等需购买）。', subscription='data-prod', resource_group='data-rg',
              resource_name='data-worker-01', resource_type=vm_t, environment=e('data-prod', 'data-worker-01'), key='lifecycle|os-centos|7|data-prod')
        f.add('R9', '中', '微软服务退役公告（跟踪 ID SMPL-001）：Retirement notice: Migrate your legacy Azure general-purpose v1 account to a '
              'general-purpose v2 account。将于 2027-03-31 退役（还有 156 天）；本租户 1 个资源受影响（1 个存储账户）。',
              '按公告中的迁移指引在退役日期前完成迁移；公告全文可在 Azure 门户“服务运行状况 > 健康公告”中按跟踪 ID SMPL-001 查看。',
              subscription='shop-prod', resource_name='1 个资源', resource_type=st, environment=e('shop-prod', 'shopassets'),
              members=m(['shopassets'], st, 'shop-prod'), key='retirement|SMPL-001')
        f.add('R9', '中', '应用网关 shop-agw 上的证书 cert-shop（CN=www.contoso.com）将于 2026-11-20 过期（还有 25 天），到期后使用该证书的监听器会出现证书错误。',
              '续期证书并更新到应用网关（建议改为引用 Key Vault 中的证书并开启自动轮换）；确认没有监听器仍在使用旧证书。', subscription='shop-prod',
              resource_group='shop-rg', resource_name='shop-agw/cert-shop', resource_type='Microsoft.Network/applicationGateways',
              environment=e('shop-prod', 'shop-agw'), key='appgw-cert|shop-agw|cert-shop')
    if not sep:
        f.add('R2', '中', 'AKS 集群 shop-aks 的系统节点池只有 1 个节点。', '系统节点池至少 2 个节点并跨可用区', subscription='shop-prod',
              resource_group='shop-rg', resource_name='shop-aks/system', resource_type=aks + '/agentPools', environment=e('shop-prod', 'shop-aks'))
    write('reliability', f, [f'R{i}' for i in range(1, 13)])

    f = common.Findings('aprl')
    f.add('R13', '高', 'PostgreSQL 关闭了存储自动增长，磁盘写满后数据库会变为只读：data-pg-prod（存储已用约 71%）。（APRL 建议 6293a3cc）',
          '开启存储自动增长，并为存储使用率配置告警。', subscription='data-prod', resource_group='data-rg', resource_name='data-pg-prod', resource_type=db_pg,
          environment=e('data-prod', 'data-pg-prod'), key='6293a3cc-6b4a-4c0f-9ea7-b8ae8d7dd3d5')
    f.add('R19', '中', '镜像仓库不是 Premium 层，不支持异地复制和区域冗余，限流也更低：contosoacr。（APRL 建议 eb005943）',
          '生产镜像仓库改为 Premium 层，并按需开启异地复制。', subscription='shop-prod', resource_group='shop-rg', resource_name='contosoacr',
          resource_type='Microsoft.ContainerRegistry/registries', environment=e('shop-prod', 'contosoacr'), key='eb005943-40a8-194b-9db2-474d430046b7')
    write('aprl', f, ['R13', 'R19'])

    f = common.Findings('security_network')
    f.add('S-N4', '高' if sep else '中', 'MySQL pay-mysql-prod 的防火墙规则 AllowAll 放行 0.0.0.0–255.255.255.255，任何地址都能连接数据库端口。',
          '删除全网放行规则，改用私有终结点访问', subscription='pay-prod', resource_group='pay-rg', resource_name='pay-mysql-prod', resource_type=db_my,
          environment=e('pay-prod', 'pay-mysql-prod'))
    f.add('S-N5', '高', '存储账户 shopassets 的 exports 容器允许匿名访问，任何人无需登录即可列出和下载其中文件。', '确认容器内容；不需要公开的关闭匿名访问',
          subscription='shop-prod', resource_group='shop-rg', resource_name='shopassets', resource_type=st, environment=e('shop-prod', 'shopassets'),
          needs_confirmation='确认 exports 容器是否存放对外分发的公开文件。')
    f.add('S-N2', '中', 'NSG shop-web-nsg 允许 Internet 任意来源访问 SSH（22）。', '把来源改为办公网或 VPN 出口 IP，管理访问改用 Bastion',
          subscription='shop-prod', resource_group='shop-rg', resource_name='shop-web-nsg', resource_type='Microsoft.Network/networkSecurityGroups', environment=e('shop-prod'))
    f.add('S-N7', '中', 'Redis shop-redis-prod 开启了非 TLS 端口（6379）。', '关闭非 TLS 端口，客户端改用 6380', subscription='shop-prod', resource_group='shop-rg',
          resource_name='shop-redis-prod', resource_type=redis, environment=e('shop-prod', 'shop-redis-prod'))
    f.add('S-N6', '低', '应用网关 shop-appgw 的 WAF 策略为检测模式，只记录不拦截。', '观察误报一周后切换为阻止模式', subscription='shop-prod', resource_group='shop-rg',
          resource_name='shop-appgw', resource_type='Microsoft.Network/applicationGateways', environment=e('shop-prod', 'shop-appgw'))
    write('security_network', f, [f'S-N{i}' for i in range(1, 9)])

    f = common.Findings('security_identity')
    f.add('S-I1', '高', 'AKS 集群 shop-aks 的 API Server 对公网开放且没有限制来源 IP，本地账号也没有禁用。', '设置授权 IP 范围或改为私有集群；集成 Entra ID 并禁用本地账号',
          subscription='shop-prod', resource_group='shop-rg', resource_name='shop-aks', resource_type=aks, environment=e('shop-prod', 'shop-aks'))
    f.add('S-I4', '中', 'data-prod 订阅的 Defender 服务器和数据库计划为免费层，有 6 条高严重性建议未处理。', '为生产订阅开启服务器和数据库的 Defender 计划',
          subscription='data-prod', resource_name='data-prod', resource_type='Microsoft.Resources/subscriptions', environment=e('data-prod'))
    f.add('S-I5', '中', '2 个来宾账号在 shop-prod 订阅拥有 Owner 权限。', '确认来宾账号是否仍需要；需要的改为最小权限角色并设置到期时间',
          subscription='shop-prod', resource_name='2 个来宾账号', key='guest-owner', members=m(['来宾账号 1', '来宾账号 2'], 'Microsoft.Graph/users#guest', 'shop-prod'),
          environment=e('shop-prod'))
    f.add('S-I9', '低', 'Key Vault pay-kv 没有开启清除保护。', '开启清除保护（开启后不能关闭）', subscription='pay-prod', resource_group='pay-rg',
          resource_name='pay-kv', resource_type='Microsoft.KeyVault/vaults', environment=e('pay-prod', 'pay-kv'))
    f.add('S-I7', '低', '5 个订阅的活动日志都没有导出，只能保留 90 天。', '把活动日志导出到日志工作区或存储账户', subscription='多个订阅（5 个）',
          resource_name='5 个订阅', key='activity-export', members=m([n for _s, n, st_ in SUBS if st_ == 'Enabled'], 'Microsoft.Resources/subscriptions', None),
          environment={'value': 'mixed', 'label': '多个环境（含生产）', 'basis': '见涉及资源'})
    if sep:  # network appliances are recognised from this month: their admin login is reviewed apart
        f.add('S-I8', '中', '订阅 shop-prod 有 1 台网络设备（edge-fw-01）允许管理员用密码登录，其中 1 台绑定了公网 IP。网络设备的管理员通常使用密码，'
              '关闭密码登录不适用，重点是限制管理口的访问。按当前 NSG，edge-fw-01 的 22 端口没有对公网开放，风险在于以后放开端口或从内网横向登录。',
              '管理口（SSH、HTTPS）只允许受信地址访问、不对公网开放（用 NSG 或设备自身的可信主机设置），管理员账号启用多因素认证并定期更换密码；'
              '按厂商建议及时升级设备系统。', subscription='shop-prod', resource_group='shop-net-rg', resource_name='1 台网络设备', key='appliance-admin-login',
              members=m(['edge-fw-01'], vm_t, 'shop-prod'), environment=e('shop-prod', 'edge-fw-01'))
    write('security_identity', f, [f'S-I{i}' for i in range(1, 11)])

    if sep:  # Defender per-recommendation results start this month: shown as a new check, not as new problems
        f = common.Findings('defender')
        f.add('S-I11', '中', 'Defender for Cloud 高严重性建议“Machines should have vulnerability findings resolved”已超过 30 天未处理（最长 74 天），涉及 6 个资源，分布在 2 个订阅',
              '在 Defender for Cloud 中按建议的修复步骤处理；确实不适用的设为豁免并写明原因', subscription='多个订阅（2 个）', resource_name='6 个资源',
              key='defender|vulnerability', members=m(['shop-web-01', 'shop-web-02', 'shop-web-03', 'shop-web-04', 'shop-batch-01', 'data-etl-01'], vm_t, None),
              environment={'value': 'mixed', 'label': '多个环境（含生产）', 'basis': '见涉及资源'})
        write('defender', f, ['S-I11'])

    f = common.Findings('performance')
    f.add('P1', '高', '虚拟机 shop-batch-01（Standard_D8s_v5）过去 30 天 CPU 平均 86%，有 21 天日最高 CPU 超过 95%。', '确认是否为预期负载；是的话升到 16 vCPU 或拆分任务',
          subscription='shop-prod', resource_group='shop-rg', resource_name='shop-batch-01', resource_type=vm_t, environment=e('shop-prod', 'shop-batch-01'))
    f.add('P5', '中', 'Redis shop-redis-prod 内存使用从首周平均 12% 涨到末周 41%，每天约增加 1 个百分点，约 6 周后达到 80%。', '确认增长原因（新业务或未设过期时间的键），必要时提前扩容',
          subscription='shop-prod', resource_group='shop-rg', resource_name='shop-redis-prod', resource_type=redis, environment=e('shop-prod', 'shop-redis-prod'))
    f.add('P4', '低', '虚拟机 data-etl-01 的数据盘带宽在 30 天里有 9 天日最高达到 100%（平均 21%）。', '确认夜间批处理窗口；必要时改用更高吞吐的磁盘',
          subscription='data-prod', resource_group='data-rg', resource_name='data-etl-01', resource_type=vm_t, environment=e('data-prod', 'data-etl-01'))
    f.add('P6', '低', 'AI 账户 data-openai 30 天有 0.8% 的请求被限流（429），集中在工作日上午。', '申请提高配额或增加部署；客户端加重试和退避',
          subscription='data-prod', resource_group='data-rg', resource_name='data-openai', resource_type='Microsoft.CognitiveServices/accounts', environment=e('data-prod', 'data-openai'))
    if sep:
        f.add('P9', '中', '应用网关 shop-appgw 30 天响应中 5xx 占 1.4%，有 6 天超过 2%。', '检查后端健康探测和超时设置', subscription='shop-prod', resource_group='shop-rg',
              resource_name='shop-appgw', resource_type='Microsoft.Network/applicationGateways', environment=e('shop-prod', 'shop-appgw'))
    write('performance', f, [f'P{i}' for i in range(1, 11)])

    f = common.Findings('operations')
    f.add('O1', '高', '生产集群 shop-aks 在 Azure 侧没有任何监控和告警：未启用 Container Insights 和托管 Prometheus，也没有告警规则。', '启用 Container Insights 并配置基础告警',
          subscription='shop-prod', resource_group='shop-rg', resource_name='shop-aks', resource_type=aks, environment=e('shop-prod', 'shop-aks'), key='aks-no-monitoring')
    f.add('O2', '中', '4 个生产数据库和缓存没有任何 Azure 告警规则：pay-mysql-prod、pay-pg-prod、data-pg-prod、shop-redis-prod。', '配置 CPU、内存、存储、连接数和可用性告警',
          subscription='多个订阅（3 个）', resource_name='4 个数据库/缓存实例', key='data-no-alert', environment={'value': 'prod', 'label': '生产', 'basis': '订阅名称'},
          members=[{'name': 'pay-mysql-prod', 'type': db_my, 'subscription': 'pay-prod'}, {'name': 'pay-pg-prod', 'type': db_pg, 'subscription': 'pay-prod'},
                   {'name': 'data-pg-prod', 'type': db_pg, 'subscription': 'data-prod'}, {'name': 'shop-redis-prod', 'type': redis, 'subscription': 'shop-prod'}])
    f.add('O8', '中', '没有任何资源锁，关键生产资源（数据库、存储账户）可能被误删。', '为关键数据资源加删除锁', subscription='多个订阅（5 个）', resource_name='关键生产资源',
          key='locks', environment={'value': 'prod', 'label': '生产', 'basis': '订阅名称'})
    f.add('O3', '低', '2 个日志工作区都只保留 30 天。', '按审计和排障需要延长保留期，或把需要长期保存的日志归档到存储', subscription='多个订阅（2 个）', resource_name='2 个日志工作区',
          key='log-retention', members=m(['shop-logs', 'data-logs'], 'Microsoft.OperationalInsights/workspaces', None), environment={'value': 'prod', 'label': '生产', 'basis': '订阅名称'})
    f.add('O7', '低', '78% 的资源没有负责人标签。', '在 IaC 模块中统一加 owner、cost-center 标签', subscription='多个订阅（5 个）', resource_name='全部订阅', key='tags',
          environment={'value': 'mixed', 'label': '多个环境（含生产）', 'basis': '见涉及资源'})
    if not sep:
        f.add('O9', '低', '4 个有费用的订阅没有预算。', '为每个订阅设置月度预算和 80%、100% 告警', subscription='多个订阅（4 个）', resource_name='4 个订阅', key='budgets',
              environment={'value': 'mixed', 'label': '多个环境（含生产）', 'basis': '见涉及资源'})
    coverage = {'AKS 集群': {'total': 1, 'withAlert': 0}, 'MySQL 灵活服务器': {'total': 3, 'withAlert': 1}, 'PostgreSQL 灵活服务器': {'total': 2, 'withAlert': 0},
                'Azure Cache for Redis': {'total': 1, 'withAlert': 0}, '应用网关': {'total': 1, 'withAlert': 1}, 'Key Vault': {'total': 1, 'withAlert': 0},
                '存储账户（费用前 10）': {'total': 3, 'withAlert': 0}}
    write('operations', f, [f'O{i}' for i in range(1, 11)], {'monitoringCoverageByType': coverage})

    f = common.Findings('amba')
    f.add('O2', '低', '1 个生产MySQL已有部分指标告警，但缺少 AMBA 推荐的核心告警：shop-mysql-prod 缺少 memory_percent、storage_percent、active_connections',
          '按 Excel“推荐告警（AMBA）”补齐核心告警，阈值可先用推荐值', subscription='shop-prod', resource_name='shop-mysql-prod', resource_type=db_my,
          environment=e('shop-prod', 'shop-mysql-prod'), key='amba|microsoft.dbformysql/flexibleservers')
    _meta, core = amba.baseline()
    recommended = [{'resourceType': t, 'label': type_label(t), 'metric': a['metricName'], 'description': a.get('description'),
                    'condition': f'{a.get("aggregation") or ""} {amba.OPERATORS.get(a.get("operator"), a.get("operator") or "")} {a.get("threshold")}'.strip(),
                    'window': a.get('windowSize'), 'severity': a.get('severity')}
                   for t, alerts in core.items() if t in ('microsoft.dbformysql/flexibleservers', 'microsoft.dbforpostgresql/flexibleservers', 'microsoft.cache/redis',
                                                          'microsoft.containerservice/managedclusters') for a in alerts]
    write('amba', f, ['O2'], {'recommendedAlerts': recommended})

    status = ['有不符合项', '全部符合', '不适用（没有相关资源）']
    items = lz_checklist()['items'][:16]
    rows = []
    for i, it in enumerate(items):
        s = status[i % 3]
        rows.append({'guid': it['guid'], 'category': {'Identity and Access Management': '身份与访问', 'Resource Organization': '资源组织', 'Security': '安全',
                                                      'Network Topology and Connectivity': '网络拓扑与连接', 'Management': '管理'}.get(it['category'], it['category']),
                     'title': LZ_TITLES.get(it['guid'][:8], it['text']), 'severity': {'High': '高', 'Medium': '中', 'Low': '低'}.get(it['severity'], it['severity']),
                     'status': s, 'compliant': 3 if s != '不适用（没有相关资源）' else 0, 'nonCompliant': 2 if s == '有不符合项' else 0,
                     'examples': ['shop-vnet', 'data-vnet'] if s == '有不符合项' else [], 'link': it.get('link'), 'text': it['text']})
    if sep:
        common.Findings('landing_zone').write(ws, window=window, coverage={}, scope={'items': len(rows)}, inventory={'landingZone': rows})
    for pillar in common.PILLARS:  # build() checks for raw manifests only in analyze; write them so the workspace looks complete
        common.Raw(ws, pillar).save('manifest.json', {'collectedAt': snap + 'T08:00:00+00:00', 'window': window, 'sample': True})


# ---------------------------------------------------------------- 05: Resource Graph rows for the peer comparison

def peer_part(ws):
    base = 'waf/security_network/raw/arg'
    tf = {'managed_by': 'terraform', 'environment': 'prod'}

    def row(sub, rg, rtype, name, region, tags, props, sku=None):
        return {'id': rid(sub, rg, rtype, name), 'name': name, 'type': rtype.lower(), 'subscriptionId': SUB_ID[sub], 'resourceGroup': rg,
                'location': region, 'tags': tags, 'properties': props, **({'sku': sku} if sku else {})}
    st = 'Microsoft.Storage/storageAccounts'
    storage = [
        row('shop-prod', 'shop-rg', st, 'shopassets', 'japaneast', {}, {'publicNetworkAccess': 'Enabled', 'networkAcls': {'defaultAction': 'Allow'},
                                                                         'allowBlobPublicAccess': True, 'allowSharedKeyAccess': True, 'minimumTlsVersion': 'TLS1_2',
                                                                         'creationTime': '2024-11-05T02:00:00Z'}, {'name': 'Standard_LRS'}),
        row('pay-prod', 'pay-rg', st, 'payreceipts', 'japaneast', tf, {'publicNetworkAccess': 'Disabled', 'networkAcls': {'defaultAction': 'Deny'},
                                                                      'privateEndpointConnections': [{}], 'allowBlobPublicAccess': False, 'allowSharedKeyAccess': False,
                                                                      'minimumTlsVersion': 'TLS1_2', 'creationTime': '2025-04-10T02:00:00Z'}, {'name': 'Standard_ZRS'}),
        row('data-prod', 'data-rg', st, 'datalakeraw', 'eastus', tf, {'publicNetworkAccess': 'Enabled', 'networkAcls': {'defaultAction': 'Allow'},
                                                                      'allowBlobPublicAccess': False, 'allowSharedKeyAccess': True, 'minimumTlsVersion': 'TLS1_0',
                                                                      'creationTime': '2024-08-20T02:00:00Z'}, {'name': 'Standard_LRS'}),
        row('shared-network', 'network-rg', st, 'contosotfstate', 'japaneast', tf, {'publicNetworkAccess': 'Disabled', 'networkAcls': {'defaultAction': 'Deny'},
                                                                                   'privateEndpointConnections': [{}], 'allowBlobPublicAccess': False,
                                                                                   'allowSharedKeyAccess': True, 'minimumTlsVersion': 'TLS1_2',
                                                                                   'creationTime': '2024-06-01T02:00:00Z'}, {'name': 'Standard_GRS'}),
    ]
    write_json(ws.raw(f'{base}/storage.json'), {'rows': storage})
    write_json(ws.raw('waf/reliability/storage/blobservices.json'), [
        {'id': r['id'], 'blobService': {'properties': {'deleteRetentionPolicy': {'enabled': r['name'] in ('payreceipts', 'contosotfstate')}}}} for r in storage])

    def db(sub, rg, rtype, name, tags, private, ha, geo, ret, tier='GeneralPurpose', role='None'):
        props = {'network': {'publicNetworkAccess': 'Disabled' if private else 'Enabled'}, 'privateEndpointConnections': [{}] if private else [],
                 'highAvailability': {'mode': ha}, 'backup': {'geoRedundantBackup': geo, 'backupRetentionDays': ret}, 'replicationRole': role}
        return row(sub, rg, rtype, name, 'japaneast' if sub != 'data-prod' else 'eastus', tags, props, {'tier': tier})
    my, pg = 'Microsoft.DBforMySQL/flexibleServers', 'Microsoft.DBforPostgreSQL/flexibleServers'
    write_json(ws.raw(f'{base}/mysql.json'), {'rows': [
        db('shop-prod', 'shop-rg', my, 'shop-mysql-prod', tf, True, 'SameZone', 'Disabled', 14),
        db('pay-prod', 'pay-rg', my, 'pay-mysql-prod', {}, False, 'Disabled', 'Disabled', 7),
        db('shop-test', 'shop-test-rg', my, 'shop-mysql-test', {}, False, 'Disabled', 'Disabled', 7, tier='Burstable')]})
    write_json(ws.raw(f'{base}/postgres.json'), {'rows': [
        db('data-prod', 'data-rg', pg, 'data-pg-prod', tf, True, 'ZoneRedundant', 'Enabled', 14),
        db('pay-prod', 'pay-rg', pg, 'pay-pg-prod', tf, True, 'ZoneRedundant', 'Enabled', 14)]})
    fw = {rid('pay-prod', 'pay-rg', my, 'pay-mysql-prod'): {'data': [{'name': 'AllowAll_2026-3-14', 'properties': {'startIpAddress': '0.0.0.0', 'endIpAddress': '255.255.255.255'}}]},
          rid('shop-test', 'shop-test-rg', my, 'shop-mysql-test'): {'data': [{'name': 'ClientIPAddress_2026-5-2', 'properties': {'startIpAddress': '203.0.113.10', 'endIpAddress': '203.0.113.10'}}]}}
    write_json(ws.raw('waf/security_network/raw/arm/mysql_fw.json'), fw)
    write_json(ws.raw('waf/security_network/raw/arm/mysql_cfg.json'), {
        rid('pay-prod', 'pay-rg', my, 'pay-mysql-prod') + '|require_secure_transport': {'data': {'properties': {'value': 'OFF'}}},
        rid('shop-prod', 'shop-rg', my, 'shop-mysql-prod') + '|require_secure_transport': {'data': {'properties': {'value': 'ON'}}},
        rid('shop-test', 'shop-test-rg', my, 'shop-mysql-test') + '|require_secure_transport': {'data': {'properties': {'value': 'ON'}}}})
    write_json(ws.raw('waf/operations/deployments-rg.json'), [
        {'subscriptionId': SUB_ID['pay-prod'], 'resourceGroup': 'pay-rg',
         'value': [{'name': 'MySqlFlexibleServer_2026-3-14T02.11.05', 'timestamp': '2026-03-14T02:11:05Z', 'provisioningState': 'Succeeded',
                    'tags': {'primaryResourceId': rid('pay-prod', 'pay-rg', my, 'pay-mysql-prod')}, 'resourceTypes': ['flexibleServers']}]}])
    write_json(ws.raw('peer/manifest.json'), {'collectedAt': '2026-10-26T09:30:00+00:00', 'sample': True})
    inventory = [(sub, rg, 'microsoft.compute/virtualmachines', name, region) for name, sub, rg, region, _s, _p, _f, last in VMS if not last]
    sub_name = {sid: name for name, sid in SUB_ID.items()}
    inventory += [(sub_name[r['subscriptionId']], r['resourceGroup'], r['type'], r['name'], r['location']) for r in storage]
    inventory += [('shop-prod', 'shop-rg', 'microsoft.containerservice/managedclusters', 'shop-aks', 'japaneast'),
                  ('shop-prod', 'shop-rg', my.lower(), 'shop-mysql-prod', 'japaneast'), ('pay-prod', 'pay-rg', my.lower(), 'pay-mysql-prod', 'japaneast'),
                  ('shop-test', 'shop-test-rg', my.lower(), 'shop-mysql-test', 'japaneast'), ('data-prod', 'data-rg', pg.lower(), 'data-pg-prod', 'eastus'),
                  ('pay-prod', 'pay-rg', pg.lower(), 'pay-pg-prod', 'japaneast'), ('shop-prod', 'shop-rg', 'microsoft.cache/redis', 'shop-cache', 'japaneast'),
                  ('shared-network', 'network-rg', 'microsoft.network/virtualnetworks', 'hub-vnet', 'japaneast'),
                  ('shop-prod', 'shop-rg', 'microsoft.network/virtualnetworks', 'shop-vnet', 'japaneast'),
                  ('data-prod', 'data-rg', 'microsoft.network/virtualnetworks', 'data-vnet', 'eastus'),
                  ('shared-network', 'network-rg', 'microsoft.network/virtualnetworkgateways', 'hub-vpngw', 'japaneast'),
                  ('shop-prod', 'shop-rg', 'microsoft.network/applicationgateways', 'shop-appgw', 'japaneast')]
    write_json(ws.raw('waf/operations/arg/resources.json'), {'query': 'sample', 'status': 200, 'error': None, 'rows': [
        {'id': rid(sub, rg, t, n).lower(), 'name': n, 'type': t, 'subscriptionId': SUB_ID[sub], 'resourceGroup': rg, 'location': loc}
        for sub, rg, t, n, loc in inventory]})
    vnet = lambda sub, rg, n: rid(sub, rg, 'Microsoft.Network/virtualNetworks', n)
    write_json(ws.raw('waf/performance/arg/peerings.json'), {'query': 'sample', 'status': 200, 'error': None, 'rows': [
        {'id': vnet('shared-network', 'network-rg', 'hub-vnet'), 'location': 'japaneast', 'remote': vnet('shop-prod', 'shop-rg', 'shop-vnet')},
        {'id': vnet('shared-network', 'network-rg', 'hub-vnet'), 'location': 'japaneast', 'remote': vnet('data-prod', 'data-rg', 'data-vnet')}]})


# ---------------------------------------------------------------- narratives (what the agent writes)

NARRATIVE = {
    '01': {
        'highlights': ['**AI 调用量增长最快**。data-prod 的 Azure OpenAI 9 月费用比 8 月高约 44%，主要是工作日调用量增加，单价没有变化。',
                       '**支付业务新增一台 PostgreSQL**。pay-prod 9 月 8 日起新增 pay-pg-prod，9 月约 USD 570。',
                       '**测试环境费用下降**。shop-test 的 shop-web-test-02 8 月 20 日起已释放，9 月不再计费。'],
        'driverNotes': {'data-prod|Azure OpenAI': '工作日调用量增加约 44%（输入 token 数量增加），单价不变',
                        'shop-prod|Log Analytics': '9 月 15 日起 checkout-api 容器开启调试日志，日志量增加约 25%',
                        'data-prod|Virtual Machines': '9 月 12 日新增 data-worker-01（D8s_v5），用于新的报表任务',
                        'pay-prod|Azure Database for PostgreSQL': '9 月 8 日新增 pay-pg-prod（4 vCore），属于新上线的对账服务',
                        'shop-test|Virtual Machines': 'shop-web-test-02 于 8 月 20 日释放，9 月不再计费'},
        'chartNotes': {'daily': '费用有明显的每周规律：工作日高、周末低；9 月中旬起 AI 调用量上升。'},
        'downsizeExclusions': [{'name': 'shop-redis-prod', 'reason': '10 月内存使用快速增长（见卓越运营与性能效率巡检报告）'}],
        'storageNotes': ['datalakeraw 约 26 TiB 全部在 Hot 层，9 月增长约 18%，没有生命周期策略；建议按访问频率把 90 天前的数据转到 Cool 层。'],
        'logNotes': ['shop-logs 9 月 15 日起日志量增加约 25%，主要来自 checkout-api 容器的调试日志；建议把日志级别调回 INFO。'],
        'actions': [{'topic': '存储', 'scope': 'data-prod / datalakeraw', 'finding': '约 26 TiB 全部在 Hot 层，没有生命周期策略',
                     'recommendation': '确认数据访问频率后，为 90 天前的数据配置转 Cool 层规则', 'saving': None, 'owner': '数据平台负责人', 'status': '待业务确认',
                     'evidencePeriod': '9 月存储容量与当前配置'}]},
    '02': {'crossCheckNotes': [{'subscription': 'data-prod', 'namePrefix': 'data-etl-01',
                                'note': '夜间批处理时数据盘带宽经常打满（见卓越运营与性能效率巡检报告 P4）；降配前先确认新规格的磁盘吞吐上限足够'}]},
    '03': {
        'architecture': ['网店和支付都运行在日本东部：网店前端在 shop-aks 和 shop-web 虚拟机上，经应用网关对外；支付服务在 pay-api 虚拟机上，'
                         '数据库按业务分开。数据分析在美国东部的 data-prod 订阅。shared-network 订阅里的中心网络通过 VPN 网关连接办公网，'
                         '并与网店、数据两个虚拟网络对等。',
                         '与 Landing Zone 设计相比，网络已经按中心辐射结构划分，主要差距在身份和数据保护：生产数据库还有公网入口，管理入口缺少统一的来源限制。'],
        'topIssues': [
            {'title': '支付数据库对全网开放', 'detail': 'pay-mysql-prod 的防火墙规则 AllowAll 放行所有地址，且没有强制加密连接。',
             'impact': '任何人都能连接支付数据库端口，只靠密码防护。',
             'recommendation': {'rootCause': '该库在门户手工创建，并在门户上点了“允许全部”；其他生产库都由 Terraform 模块创建、只走私有终结点。',
                                'fix': '按模块改为私有终结点访问，删除公网规则。', 'shortTerm': '立即删除 AllowAll 规则，只保留办公网出口 IP。'}},
            {'title': '存储容器可匿名访问', 'detail': 'shopassets 的 exports 容器允许匿名列出和下载。', 'impact': '如存放内部文件，可能已对外泄露。',
             'recommendation': '确认容器内容；不需要公开的关闭匿名访问'},
            {'title': '支付数据库没有高可用和异地备份', 'detail': 'pay-mysql-prod 单可用区部署，备份只在本区域。', 'impact': '可用区故障时支付服务中断。',
             'recommendation': '开启跨可用区高可用和异地冗余备份'},
            {'title': 'AKS 管理接口对公网开放', 'detail': 'shop-aks 的 API Server 不限制来源 IP，本地账号未禁用。', 'impact': '拿到凭据的人可从任何地方管理集群。',
             'recommendation': '设置授权 IP 范围；集成 Entra ID 并禁用本地账号'},
            {'title': 'PostgreSQL 关闭了存储自动增长', 'detail': 'data-pg-prod 存储已用约 71%。', 'impact': '写满后数据库变为只读。',
             'recommendation': '开启存储自动增长并配置存储告警'}],
        'checkNotes': {'R5': '支付库 pay-mysql-prod 没有高可用和异地备份', 'R7': '2 台保存数据的虚拟机没有备份', 'S-N4': 'pay-mysql-prod 对全网开放',
                       'S-N5': 'shopassets 的 exports 容器可匿名访问', 'S-I1': 'shop-aks API Server 不限制来源 IP'},
        'actionPlan': {'week': ['删除 pay-mysql-prod 的全网放行规则；确认 shopassets/exports 内容并关闭匿名访问。'],
                       'month': ['为 pay-mysql-prod 开启高可用和异地备份；限制 shop-aks API Server 来源 IP；为保存数据的虚拟机配置备份。'],
                       'quarter': ['把手工创建的数据库按 Terraform 模块对齐；AKS 升级到 Standard 层并规划版本升级。']}},
    '04': {
        'topIssues': [
            {'title': 'shop-batch-01 CPU 长期打满', 'detail': '30 天平均 86%，21 天日最高超过 95%。', 'impact': '批处理任务排队变慢。',
             'recommendation': '确认是否为预期负载；是的话升到 16 vCPU 或拆分任务'},
            {'title': '生产集群没有监控', 'detail': 'shop-aks 没有 Container Insights 和任何告警。', 'impact': '节点或 Pod 故障时没人第一时间知道。',
             'recommendation': '启用 Container Insights 并配置基础告警'},
            {'title': 'Redis 内存快速增长', 'detail': 'shop-redis-prod 内存从 12% 涨到 41%。', 'impact': '约 6 周后达到 80%，可能驱逐数据。',
             'recommendation': '确认增长原因，必要时提前扩容'}],
        'actionPlan': {'week': ['确认 shop-redis-prod 内存增长原因；确认 shop-batch-01 的负载是否正常。'],
                       'month': ['为 shop-aks 和生产数据库补齐监控告警；为关键数据资源加删除锁。'],
                       'quarter': ['统一在 IaC 模块中加负责人和成本中心标签；按需要延长日志保留期。']}},
    '00': {
        'conclusion': ['**最需要先处理的是支付数据库 pay-mysql-prod**：防火墙放行所有地址、没有强制加密，也没有高可用和异地备份。'
                       '问题主要集中在门户手工创建的资源上，按 Terraform 模块创建的同类资源大多已经符合推荐做法。',
                       '**9 月费用 USD 17,350.94，比 8 月增加 7.13%**，增长最快的是 data-prod 的 Azure OpenAI（约 44%），来自工作日调用量增加。'
                       '7 台虚拟机调整规格预计每月节省 USD 760.51（Azure 官网公开列表价），降配稳定后再买 1 年预留实例，合计每月约节省 USD 1,556.42。'],
        'customerQuestions': ['生产和测试环境的划分：本次按订阅和资源名称判断。', 'shopassets/exports 容器是否用于对外分发。',
                              '支付库的恢复时间目标和数据丢失容忍度。', '各资源的负责人和月度预算目标。'],
        'savingsPending': [{'item': 'datalakeraw 存储', 'status': '约 26 TiB 全部在 Hot 层，没有生命周期策略'},
                           {'item': '低使用率数据库', 'status': 'pay-mysql-prod 的 CPU 和内存 9 月平均均低于 20%'}]},
}


# ---------------------------------------------------------------- run

def commitments_part(ws):
    """Invented RI/SP data in the format of cost/commitments.collect: two reserved web VMs, an unused reservation,
    a savings plan close to expiry and a few Azure purchase recommendations."""
    covered = {'shop-web-01', 'shop-web-02'}
    pricing = []
    for name, sub, rg, _region, _size, price, _first, last in VMS:
        if last:
            continue
        cost = round(price * 24 * 30, 2)
        pricing.append({'subscriptionId': SUB_ID[sub], 'resourceId': rid(sub, rg, VM_TYPE, name).lower(),
                        'pricingModel': 'Reservation' if name in covered else 'OnDemand', 'cost': round(cost * 0.6, 2) if name in covered else cost})
    reservations = [
        {'orderId': 'ri-order-1', 'name': 'shop-web-d4sv5', 'sku': 'Standard_D4s_v5', 'description': 'Reserved VM Instance, Standard_D4s_v5, 1 Year',
         'resourceType': 'VirtualMachines', 'quantity': 2, 'term': 'P1Y', 'scope': 'Single', 'expiry': '2027-03-31T00:00:00Z', 'renew': False,
         'state': 'Succeeded', 'utilization': {'trend': 'SAME', 'days7': 99.0, 'days30': 98.5}, 'readStatus': {'ok': True, 'httpStatus': 200}},
        {'orderId': 'ri-order-2', 'name': 'legacy-report-e16sv5', 'sku': 'Standard_E16s_v5', 'description': 'Reserved VM Instance, Standard_E16s_v5, 1 Year',
         'resourceType': 'VirtualMachines', 'quantity': 1, 'term': 'P1Y', 'scope': 'Shared', 'expiry': '2027-05-31T00:00:00Z', 'renew': False,
         'state': 'Succeeded', 'utilization': {'trend': 'SAME', 'days7': 0.0, 'days30': 0.0}, 'readStatus': {'ok': True, 'httpStatus': 200}}]
    plans = [{'orderId': 'sp-order-1', 'name': 'compute-sp-2025', 'commitment': 1.2, 'currency': 'USD', 'grain': 'Hourly', 'term': 'P1Y',
              'scope': 'Shared', 'expiry': '2026-12-15T00:00:00Z', 'renew': False, 'state': 'Succeeded',
              'utilization': {'trend': 'SAME', 'days7': 99.6, 'days30': 99.2}, 'readStatus': {'ok': True, 'httpStatus': 200}}]
    recs = [
        {'kind': '预留实例', 'subscription': 'pay-prod', 'resourceType': 'VirtualMachines', 'sku': 'Standard_D4s_v5', 'region': 'japaneast',
         'term': 'P1Y', 'quantity': 2, 'costWithout': 357.12, 'costWith': 228.5, 'saving': 128.62, 'lookBack': 'Last30Days'},
        {'kind': '预留实例', 'subscription': 'pay-prod', 'resourceType': 'VirtualMachines', 'sku': 'Standard_D4s_v5', 'region': 'japaneast',
         'term': 'P3Y', 'quantity': 2, 'costWithout': 357.12, 'costWith': 146.4, 'saving': 210.72, 'lookBack': 'Last30Days'},
        {'kind': '节省计划', 'subscription': 'shop-prod', 'resourceType': 'Compute_Savings_Plan', 'sku': '每小时承诺 0.95', 'region': None,
         'term': 'P1Y', 'quantity': 0.95, 'costWithout': 1062.0, 'costWith': 873.4, 'saving': 188.6, 'coverage': 71.0, 'utilization': 99.1, 'lookBack': 'Last30Days'}]
    write_json(ws.raw('cost/commitments.json'), {
        'collectedAt': '2026-10-26T12:00:00+00:00', 'month': MONTH, 'subscriptionsQueried': len({p['subscriptionId'] for p in pricing}),
        'pricingByResource': pricing, 'pricingScope': 'machines',
        'pricingByModel': {sid: {m: round(sum(p['cost'] for p in pricing if p['subscriptionId'] == sid and p['pricingModel'] == m), 2)
                                 for m in {p['pricingModel'] for p in pricing if p['subscriptionId'] == sid}} for sid in {p['subscriptionId'] for p in pricing}},
        'pricingStatus': {p['subscriptionId']: {'ok': True, 'error': None, 'models': True, 'machines': True} for p in pricing},
        'reservations': reservations, 'savingsPlans': plans, 'reservationStatus': {'ok': True, 'httpStatus': 200, 'error': None},
        'savingsPlanStatus': {'ok': True, 'httpStatus': 200, 'error': None}, 'recommendations': recs,
        'recommendationStatus': {f'{sid}|x': {'ok': True} for sid in SUB_ID.values()}})


def run(root: Path, log=print):
    root.mkdir(parents=True, exist_ok=True)
    (root / 'customer.yaml').write_text(CUSTOMER_YAML, encoding='utf-8')
    cfg = config_mod.load(root / 'customer.yaml')
    lines = ledger()
    # previous month: 03/04 only, to have something to compare with
    prev = Workspace(root, PREV_MONTH)
    prev.create()
    waf_part(prev, cfg, PREV_MONTH)
    cli(['build', '--workspace', str(root), '--month', PREV_MONTH, '--part', 'waf'])
    ws = Workspace(root, MONTH)
    ws.create()
    period = ReportPeriod.build(MONTH, dt.date(2026, 10, 27))
    cost_part(ws, cfg, period, lines)
    commitments_part(ws)
    vm_part(ws)
    waf_part(ws, cfg, MONTH)
    peer_part(ws)
    for code, data in NARRATIVE.items():
        write_json(ws.month_dir('narrative') / f'{code}.json', data)
    args = ['--workspace', str(root), '--month', MONTH]
    cli(['analyze', *args, '--part', 'cost', '--offline'])
    cli(['analyze', *args, '--part', 'vm', '--offline', '--price-date', '2026-10-26'])
    cli(['analyze', *args, '--part', 'peer', '--offline'])
    cli(['build', *args, '--part', 'all'])
    status = cli(['crosscheck', *args])
    cli(['quality-check', '--path', str(ws.month_dir('reports'))])
    if status:
        raise SystemExit('交叉核对还有未处理的规则，样例没有打包')
    cli(['package', *args])
    return ws


def main():
    ap = argparse.ArgumentParser(description='用虚构客户生成全部 6 份样例报告（离线）')
    ap.add_argument('--workspace', help='工作目录（默认临时目录）')
    ap.add_argument('--keep', action='store_true', help='保留临时工作目录')
    args = ap.parse_args()
    root = Path(args.workspace) if args.workspace else Path(tempfile.mkdtemp(prefix='azinspect-sample-'))
    try:
        ws = run(root)
        package = next(p for p in ws.month_dir('package').iterdir() if p.is_dir())
        dest = HERE / 'sample-output'
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(package, dest / package.name)
        print(f'样例已复制到 {dest / package.name}')
    finally:
        if not args.workspace and not args.keep:
            shutil.rmtree(root, ignore_errors=True)
        elif not args.workspace:
            print(f'工作目录保留在 {root}')


if __name__ == '__main__':
    main()
