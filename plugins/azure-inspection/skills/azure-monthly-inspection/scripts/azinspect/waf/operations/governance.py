"""O7 tags, O8 resource locks / management groups / policy / read access, O9 budgets, O10 Advisor operational excellence."""
from __future__ import annotations

import collections
import re

from ..common import ADVISOR_NO_TEXT, advisor_problem, is_prod, mixed_env
from .data import TYPE_LABEL, rg_of, sub_of
from .monitoring import NO_CHANGE

EXCLUDED_TYPES = ('microsoft.compute/virtualmachines/extensions', 'microsoft.billingbenefits/', 'microsoft.network/networkwatchers',
                  'microsoft.alertsmanagement/', 'microsoft.insights/', 'microsoft.network/privatednszones/virtualnetworklinks')
ENV_KEYS = {'env', 'environment', 'node-env', 'stage'}
OWNER_KEYS = {'owner', 'owners', 'owned_by', 'ownedby', 'owner_email', 'contact', 'team', 'maintainer', 'responsible'}
APP_KEYS = {'app', 'application', 'project', 'business', 'service', 'workload', 'product', 'system'}
COST_KEYS = {'cost-center', 'costcenter', 'cost_center', 'billing', 'department', 'bu', 'business_unit', 'business-unit'}
CRITICAL_TYPES = {'microsoft.containerservice/managedclusters', 'microsoft.dbformysql/flexibleservers', 'microsoft.dbforpostgresql/flexibleservers',
                  'microsoft.documentdb/mongoclusters', 'microsoft.cache/redisenterprise', 'microsoft.keyvault/vaults', 'microsoft.network/virtualnetworks'}
# Governance areas the inspection expects a policy for; matched against assignment display names.
POLICY_AREAS = {'诊断日志': r'diagnostic|诊断', '标签': r'\btags?\b|标记|标签', '资源锁': r'\block|锁', '监控代理': r'monitor(ing)? agent|\bama\b|监视代理|监控代理'}
ADVISOR_COVERED = {
    'Enable VM Insights for virtual machines': '卓越运营 虚拟机监控问题',
    'Enable container monitoring for Azure Kubernetes Service (AKS) clusters': '卓越运营 AKS 监控问题',
    'Enable Trusted Launch foundational excellence, and modern security for Existing Generation 2 VM(s)': '安全检查 S-I8',
    'Configure Connection Monitor for ExpressRoute Gateway': '卓越运营 入口/混合网络告警问题',
    'Configure Connection Monitor for ExpressRoute': '卓越运营 入口/混合网络告警问题',
    'Redis persistence allows you to persist data stored in a cache so you can reload data from an event that caused data loss.': '可靠性检查 R5（同类）'}
ADVISOR_MISC = ('Add explicit outbound method to disable default outbound', 'Use Ephemeral OS disk', 'Configure the Cluster Autoscaler',
                'Use the latest generation VM series such as Ddv5 series',
                'Injecting a cache into a virtual network (VNet) imposes complex requirements on your network configuration. '
                'This is a common source of incidents affecting customer applications')


def has(r, keys):
    return any(k.lower() in keys for k in (r.get('tags') or {}))


def pct(n, total):
    return round(100 * n / total, 1) if total else None


def check_tags(d, out, inventory):
    managed = [r for r in d.res if not r['resourceGroup'].lower().startswith('mc_') and not r['type'].startswith(EXCLUDED_TYPES)
               and r['resourceGroup'].lower() != 'networkwatcherrg']
    by_sub = []
    for s in d.enabled:
        rs = [r for r in managed if r['subscriptionId'].lower() == s['id'].lower()]
        if not rs:
            continue
        n = len(rs)
        by_sub.append({'subscriptionName': s['name'], 'environment': d.sub_env(s['name']), 'resources': n,
                       'noTagsPct': pct(sum(1 for r in rs if not r.get('tags')), n), 'envPct': pct(sum(1 for r in rs if has(r, ENV_KEYS)), n),
                       'ownerPct': pct(sum(1 for r in rs if has(r, OWNER_KEYS)), n), 'appPct': pct(sum(1 for r in rs if has(r, APP_KEYS)), n),
                       'costCenterPct': pct(sum(1 for r in rs if has(r, COST_KEYS)), n)})
    by_type = []
    for t, n in collections.Counter(r['type'] for r in managed).most_common(15):
        rs = [r for r in managed if r['type'] == t]
        by_type.append({'type': t, 'resources': n, 'noTagsPct': pct(sum(1 for r in rs if not r.get('tags')), n),
                        'envPct': pct(sum(1 for r in rs if has(r, ENV_KEYS)), n)})
    rgs = d.rows('rgs')
    owners, costs = sum(1 for r in managed if has(r, OWNER_KEYS)), sum(1 for r in managed if has(r, COST_KEYS))
    inventory['tags'] = {'scopeNote': '排除 AKS 节点资源组（MC_*）、扩展、告警/监控规则、NetworkWatcher、计费权益等系统生成资源。',
                         'resourcesInScope': len(managed), 'allResources': len(d.res), 'allResourcesNoTags': sum(1 for r in d.res if not r.get('tags')),
                         'noTagsPctInScope': pct(sum(1 for r in managed if not r.get('tags')), len(managed)),
                         'ownerTaggedResources': owners, 'costCenterTaggedResources': costs, 'bySubscription': by_sub, 'byType': by_type,
                         'rgTagged': sum(1 for g in rgs if g.get('tags')), 'rgTotal': len(rgs)}
    low = sorted([t for t in by_sub if is_prod(t['environment']) and (t['envPct'] < 50 or t['ownerPct'] < 50)], key=lambda t: t['envPct'])
    if not low:
        return
    lead = ('没有任何资源使用负责人（owner）或成本中心标签' if not owners and not costs else
            f'只有 {owners} 个资源有负责人标签、{costs} 个资源有成本中心标签')
    examples = ', '.join('%s %s%%' % (t['subscriptionName'], t['envPct']) for t in low[:4])
    out.add('O7', '低', f"{lead}；在排除系统生成资源后的 {len(managed)} 个资源中 {inventory['tags']['noTagsPctInScope']}% 完全没有标签，"
            f"{len(low)} 个生产订阅的环境标签覆盖率低于 50%（如 {examples}），告警和费用异常时难以快速找到负责人。",
            '制定最小标签集（environment、owner、project、cost-center），先在资源组级打标签并用 Azure Policy“从资源组继承标签”自动下发，再对新建资源用 Policy 审核缺失标签；'
            '基础设施代码模块中统一默认标签；' + NO_CHANGE,
            subscription=f"{len(low)} 个生产订阅", resource_type='标签', environment=mixed_env([t['environment'] for t in low]),
            evidence={'items': [dict(resourceName=t['subscriptionName'], **{k: v for k, v in t.items() if k not in ('subscriptionName', 'environment')},
                                     environment=t['environment']['label']) for t in low]},
            members=[{'name': t['subscriptionName'], 'type': 'Microsoft.Resources/subscriptions', 'subscription': t['subscriptionName']} for t in low], key='tags')


def check_locks(d, out, aks):
    lock_ids = {lk['id'].lower().split('/providers/microsoft.authorization/locks/')[0]
                for s in d.subreads for lk in (s.get('locks') or {}).get('value') or []}
    prod = lambda t: is_prod(d.env_of(t['subscriptionId'], t['name'], t.get('tags')))  # noqa: E731
    critical = [t for t in d.targets if t['type'] in CRITICAL_TYPES and prod(t)]
    critical += [t for t in d.targets if t['type'] == 'microsoft.storage/storageaccounts' and t['id'].lower() in d.diag_idx]
    critical += [{'id': a['id'], 'name': a['name'], 'type': 'microsoft.containerservice/managedclusters', 'subscriptionId': a['subscriptionId'],
                  'resourceGroup': a['resourceGroup']} for a in aks if prod(a)]
    critical += [t for t in d.res if 'tfstate' in t['name'].lower()]

    def locked(rid):
        rid = rid.lower()
        return any(rid == x or rid.startswith(x + '/') or x == '/subscriptions/' + sub_of(rid)
                   or x == '/subscriptions/%s/resourcegroups/%s' % (sub_of(rid), (rg_of(rid) or '').lower()) for x in lock_ids)
    no_lock = [t for t in critical if not locked(t['id'])]
    total = sum(len((s.get('locks') or {}).get('value') or []) for s in d.subreads)
    readable = sum(1 for s in d.subreads if (s.get('locks') or {}).get('http') == 200)
    if not no_lock:
        return total
    labels = dict(TYPE_LABEL, **{'microsoft.storage/storageaccounts': '存储账户（费用前 10 + tfstate）'})
    bytype = collections.Counter(labels.get(t['type'], t['type']) for t in no_lock)
    out.add('O8', '中', (f"{readable} 个可读订阅中没有任何资源锁" if total == 0 else f"{readable} 个订阅中一共只有 {total} 个资源锁")
            + f"，{len(no_lock)} 个关键生产资源（{'、'.join(f'{k} {v} 个' for k, v in bytype.most_common())}）都没有删除锁，"
            "误操作或脚本错误可能直接删除集群、数据库或存储（备份情况见可靠性检查 R6、R7）。",
            '对生产数据库、存放业务数据的存储账户、Key Vault、核心 VNet 和状态存储账户加 CanNotDelete 锁（不影响日常读写与扩缩容）；AKS 集群锁会阻止节点资源组的部分操作，'
            '建议只对集群资源本身加 CanNotDelete 并先在测试集群验证；基础设施代码管理的资源需在代码中声明锁或在销毁流程中处理；' + NO_CHANGE,
            subscription=f"全部 {readable} 个可读订阅", resource_name=f"{len(no_lock)} 个关键生产资源", resource_type='Microsoft.Authorization/locks',
            environment=mixed_env([d.env_of(t['subscriptionId'], t['name'], t.get('tags')) for t in no_lock]),
            evidence={'items': [{'resourceName': t['name'], 'type': TYPE_LABEL.get(t['type'], t['type']), 'subscriptionName': d.subname(t['subscriptionId']),
                                 'resourceGroup': t['resourceGroup']} for t in sorted(no_lock, key=lambda t: (t['type'], t['name']))],
                      'byType': dict(bytype), 'locksFound': total},
            members=[{'name': t['name'], 'type': t['type'], 'subscription': d.subname(t['subscriptionId'])} for t in no_lock], key='locks')
    return total


def check_management_groups(d, out, inventory, total_locks):
    detail = d.mg.get('detail') or {}
    root_key = next((k for k in detail if k.lower() == d.cfg.tenant_id.lower()), None)
    root = (detail.get(root_key) or {}).get('value') or {}
    direct = [c['displayName'] for c in root.get('children', []) if c['type'] == '/subscriptions']
    empty = [(v.get('value') or {}).get('displayName') or k for k, v in detail.items() if k != root_key and not (v.get('value') or {}).get('children')]
    assignments = collections.Counter()
    for s in d.subreads:
        for p in (s.get('policyAssignments') or {}).get('value') or []:
            assignments[re.sub(r'\(subscription: [0-9a-f-]+\)', '(subscription)', p.get('displayName') or p['name'])] += 1
    mg_assignments = [p.get('displayName') or p.get('name') for v in detail.values() for p in (v.get('policyAssignments') or {}).get('value') or []]
    compliance = [{'subscriptionName': s['subscriptionName'], 'nonCompliantResources': ((s.get('policySummary') or {}).get('value') or {}).get('nonCompliantResources'),
                   'nonCompliantPolicies': ((s.get('policySummary') or {}).get('value') or {}).get('nonCompliantPolicies'),
                   'http': (s.get('policySummary') or {}).get('http')} for s in d.subreads]
    inventory['governance'] = {'managementGroups': [{'name': k, 'displayName': (v.get('value') or {}).get('displayName'),
                                                     'children': [c['displayName'] for c in (v.get('value') or {}).get('children', [])],
                                                     'policyAssignmentsAtScope': [p['displayName'] for p in (v.get('policyAssignments') or {}).get('value') or []]}
                                                    for k, v in detail.items()],
                               'subscriptionsDirectlyUnderRoot': direct, 'emptyManagementGroups': empty,
                               'policyAssignmentsByName': dict(assignments), 'policyCompliance': compliance, 'locksTotal': total_locks}
    if not detail:
        return
    names = list(assignments) + mg_assignments
    missing = [area for area, rx in POLICY_AREAS.items() if not any(re.search(rx, n or '', re.I) for n in names)]
    prod_direct = [n for n in direct if is_prod(d.sub_env(n))]
    existing = '、'.join(f'“{n}”{f"（{c} 个订阅）" if c > 1 else ""}' for n, c in assignments.most_common(3)) or '无'
    structure = (f"管理组结构只有一层：{len(direct)} 个订阅直接挂在根管理组下（含生产订阅 {', '.join(prod_direct) or '无'}）" if direct else '订阅都已归入下级管理组')
    out.add('O8', '低', structure + (f"，{'、'.join(empty)} 管理组为空" if empty else '') + f"；订阅级 Azure Policy 分配主要是 {existing}"
            + (f"，没有针对{'、'.join(missing)}的治理策略，上面这些缺口无法自动发现和纠正。" if missing else '。'),
            '按“平台/生产/非生产/试验”整理管理组，把直挂根下的订阅移入对应管理组；在生产管理组分配 Azure Monitor 基线告警（AMBA）、诊断设置、继承标签、'
            'Azure Monitor 代理自动部署等内置策略（先 Audit 再 DeployIfNotExists）；' + NO_CHANGE,
            subscription='租户', resource_name='管理组与 Azure Policy', resource_type='Microsoft.Management/managementGroups',
            environment=mixed_env([d.sub_env(n) for n in direct]) if direct else None,
            evidence={'items': [{'resourceName': n, 'environment': d.sub_env(n)['label']} for n in direct], 'emptyManagementGroups': empty,
                      'policyAssignments': dict(assignments), 'missingPolicyAreas': missing,
                      'policyNonCompliantTop': sorted([c for c in compliance if c['nonCompliantResources']], key=lambda c: -c['nonCompliantResources'])[:8]},
            members=[{'name': n, 'type': 'Microsoft.Resources/subscriptions', 'subscription': n} for n in direct], key='management-groups')


def check_read_access(d, out, inventory):
    """403s seen by the performance pillar when reading metrics: monitoring read access is not uniform."""
    denied = collections.Counter()
    for c in d.perf_calls:
        if c.get('status') != 403:
            continue
        text = f"{c.get('target') or ''} {c.get('url') or ''}"
        if 'metrics' not in text.lower() and not re.search(r'(?:^|/)(?:vm-daily|ai-[a-z]+)/', c.get('target') or ''):
            continue
        m = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', text, re.I)
        if m:
            denied[(d.subname(m.group(1)) or m.group(1), c.get('check'))] += 1
    inventory['readAccessGaps'] = [{'subscriptionName': k[0], 'check': k[1], 'denied': n} for k, n in denied.items()]
    if not denied:
        return
    subs = sorted({k[0] for k in denied})
    out.add('O8', '低', f"只读巡检账号在 {len(subs)} 个订阅（{'、'.join(subs)}）读取 Azure Monitor 指标时被拒绝（HTTP 403），"
            "说明各订阅的监控读取权限不统一，统一运维视图/集中监控平台也会遇到同样的缺口。",
            '在管理组层面给运维/巡检身份统一分配 Reader + Monitoring Reader，避免逐订阅授权遗漏；' + NO_CHANGE,
            subscription='、'.join(subs), resource_name='巡检只读账号', resource_type='Microsoft.Authorization/roleAssignments',
            environment=mixed_env([d.sub_env(s) for s in subs]),
            evidence={'items': [{'resourceName': k[0], 'check': k[1], 'denied403': n} for k, n in denied.items()]},
            members=[{'name': s, 'type': 'Microsoft.Resources/subscriptions', 'subscription': s} for s in subs], key='read-access')


def check_budgets(d, out, inventory):
    """Budgets from the cost review: subscriptions with cost that have no budget, or only annual ones."""
    queried = [i for i in d.cost_index if i.get('queryKind') == 'budgets' and i.get('ok')]
    if not queried:
        inventory['budgets'] = {'queried': 0, 'note': '未取得成本巡检的预算读取结果，未评估。'}
        return
    budgets = (d.budgets or {}).get('budgets') or []
    by_sub = collections.defaultdict(list)
    for b in budgets:
        by_sub[(b.get('subscriptionName') or d.subname(b.get('subscriptionId')) or '')].append(str((b.get('properties') or {}).get('timeGrain', '')).lower())
    name_of = lambda i: i.get('name') or d.subname(i.get('subscriptionId'))  # noqa: E731
    without = [name_of(i) for i in queried if not by_sub.get(name_of(i)) and not i.get('rowCount')]
    with_budget = [name_of(i) for i in queried if name_of(i) not in without]
    annual_only = [n for n in with_budget if by_sub.get(n) and all(g in ('annually', 'billingannual') for g in by_sub[n])]
    inventory['budgets'] = {'queried': len(queried), 'withoutBudget': without, 'withBudget': with_budget, 'annualOnly': annual_only,
                            'note': '复用成本巡检的预算读取结果。'}
    if not without:
        return
    tail = (f"，另 {len(with_budget)} 个（{'、'.join(with_budget)}）只有年度预算" if with_budget and len(annual_only) == len(with_budget)
            else f"，另 {len(with_budget)} 个（{'、'.join(with_budget)}）已有预算" if with_budget else '')
    out.add('O9', '低', f"有费用的 {len(queried)} 个订阅中 {len(without)} 个没有任何预算或费用告警{tail}，"
            "月内费用突增（如日志量暴涨、误开大规格资源）要到月底看账单才发现。",
            '为每个生产订阅设置月度预算（按近 3 个月平均值的 110%）并配置 80%/100% 实际值和 100% 预测值通知到运维和财务；同时启用成本异常检测通知；' + NO_CHANGE,
            subscription=f"{len(without)} 个订阅", resource_type='Microsoft.Consumption/budgets', environment=mixed_env([d.sub_env(n) for n in without]),
            evidence={'items': [{'resourceName': n, 'environment': d.sub_env(n)['label']} for n in without]},
            members=[{'name': n, 'type': 'Microsoft.Resources/subscriptions', 'subscription': n} for n in without], key='budgets')


def check_advisor(d, out, inventory):
    grouped = collections.defaultdict(list)
    for x in d.advisor.get('recommendations', []):
        p = x['properties']
        if p['category'] == 'OperationalExcellence':
            grouped[(advisor_problem(x, ADVISOR_NO_TEXT), p['impact'])].append({'subscriptionName': x.get('_subscriptionName'), 'resource': p.get('impactedValue'),
                                                                             'type': p.get('impactedField')})
    summary = [{'recommendation': k[0], 'impact': k[1], 'count': len(v), 'bySubscription': dict(collections.Counter(i['subscriptionName'] for i in v)),
                'coveredBy': ADVISOR_COVERED.get(k[0])} for k, v in sorted(grouped.items(), key=lambda kv: -len(kv[1]))]
    inventory['advisorOperationalExcellence'] = summary
    item = lambda a: dict(resourceName=a['recommendation'], **{k: v for k, v in a.items() if k != 'recommendation'})  # noqa: E731

    def impacted(recs):
        seen = {}
        for a in recs:
            for i in grouped[(a['recommendation'], a['impact'])]:
                if i['resource']:
                    seen[(i['subscriptionName'], i['resource'])] = {'name': i['resource'], 'type': i['type'], 'subscription': i['subscriptionName']}
        return list(seen.values())
    ipam = [a for a in summary if 'IP Address Manager' in a['recommendation']]
    if ipam:
        n = sum(a['count'] for a in ipam)
        subnet_full = sum(1 for s in d.failed_ops for e in s.get('events') or [] if 'SubnetIsFull' in (e.get('statusMessage') or ''))
        out.add('O10', '低', f"Advisor 有 {n} 条“用 IP 地址管理器（IPAM）管理虚拟网络地址”的建议"
                + (f"；活动日志中已有 {subnet_full} 次因子网已满导致的操作失败（见可靠性检查 R1），说明地址规划缺少集中管理和用量告警。" if subnet_full else '。'),
                '用 Azure Virtual Network Manager 的 IPAM 池登记各区域地址段，并为 AKS 节点/Pod 子网配置“可用 IP<20%”的检查或告警；' + NO_CHANGE,
                subscription='多个订阅', resource_name=f"{n} 条 Advisor 建议", resource_type='Microsoft.Network/virtualNetworks',
                environment=mixed_env([d.sub_env(s) for a in ipam for s in a['bySubscription'] if s]),
                evidence={'items': [item(a) for a in ipam]}, members=impacted(ipam), key='advisor-ipam')
    redis = [a for a in summary if a['recommendation'] == 'Migrate to Azure Managed Redis']
    misc = [a for a in summary if a['recommendation'] in ADVISOR_MISC]
    if redis or misc:
        subs = sorted({s for a in redis + misc for s in a['bySubscription'] if s})
        out.add('O10', '低', f"Advisor 其余卓越运营建议：{redis[0]['count'] if redis else 0} 个 Azure Cache for Redis 实例被标为高影响“迁移到 Azure Managed Redis”，"
                f"另有 {sum(a['count'] for a in misc)} 条中低影响建议（虚拟机默认出站、AKS 临时 OS 盘/自动扩缩容/新一代机型、Redis VNet 注入）。",
                '把 Redis 迁移纳入明年计划（VNet 注入的实例先评估改为私有终结点）；虚拟机显式配置出站方式（NAT 网关）以免默认出站退役后断网；'
                '其余 AKS 建议在下次节点池轮换时一并处理；' + NO_CHANGE,
                subscription='、'.join(subs[:4]) + (' 等' if len(subs) > 4 else ''), resource_name='Advisor 卓越运营建议（其余）', resource_type='多种',
                environment=mixed_env([d.sub_env(s) for s in subs]), evidence={'items': [item(a) for a in redis + misc]}, members=impacted(redis + misc), key='advisor-other')

