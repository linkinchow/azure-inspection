"""O4 upgrades and maintenance windows, O5 configuration drift and infrastructure as code, O6 failed operations."""
from __future__ import annotations

import collections
import json
import re
from datetime import timedelta

from ..common import is_prod, mixed_env
from .data import TYPE_LABEL, short
from .monitoring import NO_CHANGE, members

AKS_TYPE = 'Microsoft.ContainerService/managedClusters'
DRIFT_KEYS = ['networkPolicy', 'outboundType', 'networkDataplane', 'tier', 'kubernetesVersion', 'podSubnet', 'containerInsights',
              'managedPrometheus', 'upgradeChannel', 'nodeOSUpgradeChannel', 'createdByStandard']
DRIFT_LABEL = {'networkPolicy': '网络策略', 'outboundType': '出站方式', 'networkDataplane': '网络数据面', 'tier': '控制面层级',
               'kubernetesVersion': 'Kubernetes 版本', 'podSubnet': '独立 Pod 子网', 'containerInsights': 'Container Insights',
               'managedPrometheus': '托管 Prometheus', 'upgradeChannel': '自动升级通道', 'nodeOSUpgradeChannel': '节点镜像升级通道',
               'createdByStandard': '标准创建方式标签'}
PORTAL_DEPLOYMENT = re.compile(
    r'^(microsoft\.|serverparameters|mysqlflexibleserver|updatemysqlflexibleserver|postgresqlflexibleserver|dnszonegroup|privatedns|'
    r'createredisenterprise|createprom|createlogsdcr|createazuremonitorworksp|aksclusterput|ciarmtemplate|nicipconfig|updatenetwork|createform|'
    r'virtualnetworklink|firewallrules|restoremysql|createappgw|privatednszonegroup)')
KEY_TYPES = ['microsoft.containerservice/managedclusters', 'microsoft.dbformysql/flexibleservers', 'microsoft.dbforpostgresql/flexibleservers',
             'microsoft.cache/redisenterprise', 'microsoft.documentdb/mongoclusters', 'microsoft.network/virtualnetworks']


def check_upgrades(d, out, aks_rows, inventory):
    if not aks_rows:
        return
    versions = collections.Counter(r['kubernetesVersion'] for r in aks_rows)
    no_auto = [r for r in aks_rows if (r['upgradeChannel'] or 'none') == 'none']
    with_window = [r['resourceName'] for r in aks_rows if r['maintenanceConfigurations']]
    window_text = ('没有集群配置维护窗口' if not with_window else
                   f"只有 {'、'.join(with_window)} 配了维护窗口" if len(with_window) <= 2 else f'{len(with_window)} 个集群配了维护窗口')
    oldest = max((r['nodeImageAgeDaysMax'] or 0) for r in aks_rows)
    stale_node_image = [r for r in aks_rows if r['nodeOSUpgradeChannel'] == 'NodeImage' and (r['nodeImageAgeDaysMin'] or 0) > 120]
    tests = [r['resourceName'] for r in aks_rows if r['environment'].get('value') in ('test', 'dev')]
    out.add('O4', '中', f"AKS 升级没有统一流程：{len(no_auto)}/{len(aks_rows)} 个集群关闭了 Kubernetes 自动升级，节点镜像自动更新 "
            f"{sum(1 for r in aks_rows if r['nodeOSUpgradeChannel'] == 'None')} 个为 None，{window_text}；"
            f"版本分散在 {len(versions)} 个版本（{', '.join(f'{k}×{n}' for k, n in sorted(versions.items(), key=lambda kv: str(kv[0])))}），"
            f"节点镜像最旧约 {oldest} 天" + ('，即使设为 NodeImage 的集群镜像也已超过 120 天未更新' if stale_node_image else '') + '。',
            '制定集群升级节奏：' + (f"测试集群（{'、'.join(tests)}）先行，" if tests else '先在测试集群验证，') +
            '生产集群按业务线分批；为所有集群配置 aksManagedAutoUpgradeSchedule 和 aksManagedNodeOSUpgradeSchedule 维护窗口（业务低峰），'
            '节点镜像通道统一设为 NodeImage 或 SecurityPatch，Kubernetes 至少设为 patch 通道；先解决子网 IP 不足等导致升级失败的问题（见可靠性检查）；' + NO_CHANGE,
            subscription='多个订阅', resource_name=f"{len(aks_rows)} 个 AKS 集群", resource_type=AKS_TYPE,
            environment=mixed_env([r['environment'] for r in aks_rows]),
            evidence={'items': [{k: r[k] for k in ('resourceName', 'subscriptionName', 'kubernetesVersion', 'upgradeChannel', 'nodeOSUpgradeChannel',
                                                    'maintenanceConfigurations', 'nodeImageAgeDaysMax', 'nodeImageAgeDaysMin', 'lastNodeImageUpgradeAction',
                                                    'lastAgentPoolWriteSucceeded', 'agentPoolWriteFailed90d')} for r in aks_rows],
                      'versionSpread': {str(k): v for k, v in versions.items()}, 'relatedChecks': ['R9（逐集群版本/镜像）', 'S-I3（安全补丁）'],
                      'activityWindowDays': 90},
            members=members(aks_rows, AKS_TYPE), key='aks-upgrade')
    patch = collections.Counter((v['patchMode'] or '无 osProfile（附加磁盘迁移）') for v in inventory.get('vmsNonAks', []))
    inventory['vmPatching'] = {'patchModes': dict(patch), 'maintenanceConfigurations': len(d.rows('maintconfigs')),
                               'maintenanceAssignments': len(d.rows('maintassign')), 'note': '虚拟机补丁由安全检查 S-I8 覆盖，此处不再单列问题。'}


def cluster_config(r):
    return {'resourceName': r['resourceName'], 'subscriptionName': r['subscriptionName'], 'location': r['location'], 'tier': r['tier'],
            'kubernetesVersion': r['kubernetesVersion'], 'networkPolicy': r['networkPolicy'], 'networkDataplane': r['networkDataplane'],
            'outboundType': r['outboundType'], 'podSubnet': r['podSubnet'], 'containerInsights': r['containerInsights'],
            'managedPrometheus': r['managedPrometheus'], 'upgradeChannel': r['upgradeChannel'], 'nodeOSUpgradeChannel': r['nodeOSUpgradeChannel'],
            'poolsWithoutZones': r['poolsWithoutZones'], 'createdByStandard': r['createdByStandard']}


def drift_groups(d, aks_rows):
    """Production clusters grouped by purpose: vendor-operated clusters by vendor, the rest by business line."""
    groups = collections.defaultdict(list)
    for r in aks_rows:
        if not is_prod(r['environment']):
            continue
        if r['vendor']:
            groups[('vendor', r['vendor'])].append(r)
        else:
            line = d.cfg.business_line(r['subscriptionName'] or '', r['resourceGroup'] or '', r['resourceName']) or '其他'
            groups[('line', line)].append(r)
    result = {}
    for (kind, name), rows in sorted(groups.items()):
        if len(rows) < 2:
            continue
        diffs = {}
        for key in DRIFT_KEYS:
            vals = {m['resourceName']: m[key] for m in rows}
            if len({json.dumps(v) for v in vals.values()}) > 1:
                diffs[key] = vals
        label = f'{name} 集群' if kind == 'vendor' else f'{name} 生产集群'
        result[label] = {'kind': kind, 'name': name, 'rows': rows, 'members': [cluster_config(m) for m in rows], 'differences': diffs}
    return result


def diff_text(diffs, limit=3):
    keys = [k for k in DRIFT_KEYS if k in diffs][:limit]
    return '；'.join(f"{DRIFT_LABEL[k]} " + ', '.join(f'{n}={v}' for n, v in diffs[k].items()) for k in keys)


def check_drift(d, out, aks_rows, inventory):
    groups = drift_groups(d, aks_rows)
    inventory['aksConfigDrift'] = {g: {'members': v['members'], 'differences': v['differences']} for g, v in groups.items()}
    own = {g: v for g, v in groups.items() if v['kind'] == 'line' and v['differences']}
    if own:
        rows = [r for v in own.values() for r in v['rows']]
        monitoring = any(k in v['differences'] for v in own.values() for k in ('containerInsights', 'managedPrometheus', 'upgradeChannel', 'nodeOSUpgradeChannel'))
        out.add('O5', '中', '同用途集群配置不一致：' + '；'.join(f"{g}（{len(v['rows'])} 个）{diff_text(v['differences'])}" for g, v in own.items())
                + ('；监控和升级通道也各不相同' if monitoring else '') + '；同一套应用在不同区域行为不一致，排障经验和变更脚本无法复用。',
                '定义每条业务线的集群基线（网络策略引擎、出站方式、控制面层级、监控、升级通道、可用区），写入基础设施代码模块，各区域用同一模块不同参数部署；'
                '差异项按维护窗口逐步收敛（网络策略引擎更换需重建节点池/评估，先在测试集群验证）；Azure NPM 将于 2028 年停止支持，可借机统一到 Cilium；' + NO_CHANGE,
                subscription='、'.join(sorted({r['subscriptionName'] for r in rows})), resource_name='与'.join(f"{g}（{len(v['rows'])} 个）" for g, v in own.items()),
                resource_type=AKS_TYPE, environment=mixed_env([r['environment'] for r in rows]),
                evidence={'items': [cluster_config(r) for r in rows], 'differences': {g: v['differences'] for g, v in own.items()}},
                members=members(rows, AKS_TYPE), key='aks-drift', needs_confirmation='部分差异可能是有意为之，请确认。')
    for g, v in groups.items():
        if v['kind'] != 'vendor' or not v['differences']:
            continue
        out.add('O5', '低', f"{len(v['rows'])} 个 {v['name']} 集群整体一致，但存在差异：" + '；'.join(
                    f"{DRIFT_LABEL[k]}: " + ', '.join(f'{n}={x}' for n, x in vals.items()) for k, vals in v['differences'].items()) + '。',
                f"与 {v['name']} 的部署模板对齐：统一使用 Standard 层（有 SLA）和同一受支持的 Kubernetes 版本；" + NO_CHANGE,
                subscription='、'.join(sorted({r['subscriptionName'] for r in v['rows']})), resource_name=f"{v['name']} 集群（{len(v['rows'])} 个）",
                resource_type=AKS_TYPE, environment=mixed_env([r['environment'] for r in v['rows']]),
                evidence={'items': v['members'], 'differences': v['differences']}, members=members(v['rows'], AKS_TYPE), key=f"aks-drift-vendor-{v['name']}")


def deployment_kind(v):
    name = (v.get('name') or '').lower()
    if v.get('templateLinkId'):
        return '模板规格'
    if v.get('templateLinkHost') and 'portal.azure' in v['templateLinkHost']:
        return '门户（模板链接）'
    if PORTAL_DEPLOYMENT.match(name):
        return '门户/服务自动生成'
    return '其他（名称无法判断工具）'


def check_iac(d, out, inventory):
    deployments = [dict(v, subscriptionName=d.subname(x['subscriptionId']), resourceGroup=x['resourceGroup']) for x in d.deps for v in x.get('value') or []]
    deployments += [dict(v, subscriptionName=s['subscriptionName'], resourceGroup=None) for s in d.subreads
                    for v in (s.get('subDeployments') or {}).get('value') or []]
    since = (d.today - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
    recent = [v for v in deployments if (v.get('timestamp') or '') >= since]
    kinds = collections.Counter(deployment_kind(v) for v in recent)
    standard = [r for r in d.res if d.cfg.created_by_standard(r.get('tags'))]
    standard_ids = {r['id'].lower() for r in standard}
    portal_on_std = []
    for v in recent:
        primary = ((v.get('tags') or {}).get('primaryResourceId') or '').lower()
        if deployment_kind(v) == '门户/服务自动生成' and primary and primary in standard_ids:
            portal_on_std.append({'resourceName': short(primary), 'deployment': v['name'], 'timestamp': (v.get('timestamp') or '')[:10],
                                  'subscriptionName': v['subscriptionName']})
    coverage, untagged_examples = {}, []
    for t in KEY_TYPES:
        prod = [r for r in d.res if r['type'] == t and is_prod(d.env_of(r['subscriptionId'], r['name'], r.get('tags')))]
        coverage[TYPE_LABEL.get(t, t)] = {'prod': len(prod), 'standardTagged': sum(1 for r in prod if r['id'].lower() in standard_ids)}
        untagged_examples += [r['name'] for r in prod if r['id'].lower() not in standard_ids][:2]
    tfstate = [r for r in d.res if 'tfstate' in r['name'].lower()]
    inventory['iac'] = {'deploymentsTotalInHistory': len(deployments), 'deploymentsLast90Days': len(recent), 'last90ByKind': dict(kinds),
                        'last90BySubscription': dict(collections.Counter(v['subscriptionName'] for v in recent)),
                        'last90Failed': [{'name': v['name'], 'subscriptionName': v['subscriptionName'], 'errorCode': v.get('errorCode'), 'timestamp': v.get('timestamp')}
                                         for v in recent if v.get('provisioningState') != 'Succeeded'],
                        'standardTaggedResources': len(standard),
                        'standardTaggedBySubscription': dict(collections.Counter(d.subname(r['subscriptionId']) for r in standard)),
                        'standardCoverageOfProdKeyResources': coverage,
                        'terraformStateStorage': [{'name': r['name'], 'subscriptionName': d.subname(r['subscriptionId']), 'resourceGroup': r['resourceGroup']} for r in tfstate],
                        'portalChangesOnStandardResources': portal_on_std,
                        'note': 'Terraform 等工具直接调用资源 API，不在部署历史中留下记录；部署历史只反映门户/ARM 模板/CLI 模板部署。结论为推断。'}
    if not d.cfg.standard_tag:
        return
    tag = f"{d.cfg.standard_tag.get('key')}={d.cfg.standard_tag.get('value')}"
    tool = d.standard_label()
    untagged = {k: v['prod'] - v['standardTagged'] for k, v in coverage.items()}
    portal = kinds.get('门户/服务自动生成', 0) + kinds.get('门户（模板链接）', 0)
    out.add('O5', '中' if portal_on_std else '低',
            f"约 {len(standard)} 个资源带 {tag} 标签" + (f"、状态存储账户 {', '.join(r['name'] for r in tfstate)} 存在" if tfstate else '') + f"，说明部分环境用 {tool} 管理；"
            f"但近 90 天有 {len(recent)} 次门户/模板部署（{portal} 次看起来是门户操作），其中 {len(portal_on_std)} 次直接改了带 {tool} 标签的资源（如数据库参数），"
            f"生产关键资源中仍有 AKS {untagged.get('AKS 集群')} 个、MySQL {untagged.get('MySQL 灵活服务器')} 个、PostgreSQL {untagged.get('PostgreSQL 灵活服务器')} 个没有 {tool} 标签"
            + (f"（如 {'、'.join(untagged_examples[:2])}）" if untagged_examples else '') + f"；门户改动不回写代码会造成配置漂移，下次 {tool} 执行可能把改动覆盖回去。",
            f"约定“生产变更走代码”：门户修改的数据库参数等同步回 {tool} 代码，并在 CI 中定期检测漂移（如 terraform plan）；把未纳管的关键生产资源导入 {tool}；"
            '对状态存储账户开启软删除/版本控制和删除锁；' + NO_CHANGE,
            subscription='多个订阅', resource_name=f'{tool} 与门户混用', resource_type='Microsoft.Resources/deployments',
            environment=mixed_env([d.sub_env(s['name']) for s in d.enabled]),
            evidence={'items': portal_on_std[:40], 'deploymentKinds90d': dict(kinds), 'standardCoverageOfProdKeyResources': coverage,
                      'terraformStateStorage': inventory['iac']['terraformStateStorage']},
            members=[{'name': x['resourceName'], 'type': None, 'subscription': x['subscriptionName']} for x in portal_on_std], key='iac-mixed',
            needs_confirmation=f'标签只能说明资源由 {tool} 创建，是否仍持续由 {tool} 管理需客户确认。')


def error_code(e):
    m = e.get('statusMessage') or ''
    try:
        j = json.loads(m)
        er = j.get('error') or j
        det = [x.get('code') for x in (er.get('details') or []) if isinstance(x, dict)]
        return er.get('code'), (det[0] if det else None)
    except (ValueError, AttributeError, TypeError):
        mm = re.findall(r'"code"\s*:\s*"([A-Za-z]+)"', m)
        return (mm[0] if mm else None), (mm[1] if len(mm) > 1 else None)


def check_failed(d, out, inventory):
    groups = collections.defaultdict(list)
    for s in d.failed_ops:
        for e in s.get('events') or []:
            c1, c2 = error_code(e)
            rtype = '/'.join((e.get('op') or '').split('/')[:-1])
            groups[(s['subscriptionName'], rtype, e.get('op'), c1 or e.get('statusCode'), c2)].append(e)
    recent = (d.today - timedelta(days=8)).strftime('%Y-%m-%d')
    rows = []
    for k, evs in groups.items():
        ts = sorted(x['t'] for x in evs)
        reported = ('R1' if k[3] == 'SubnetIsFull' else 'R12' if (k[4] == 'RequestDisallowedByPolicy' or 'policies/deny' in (k[2] or '').lower())
                    else 'R12' if k[3] == 'PrivateIPAddressIsAllocated' else None)
        rows.append({'subscriptionName': k[0], 'resourceType': k[1], 'operation': k[2], 'errorCode': k[3], 'innerCode': k[4], 'count': len(evs),
                     'first': ts[0][:16], 'last': ts[-1][:16], 'recurringLast7Days': ts[-1] >= recent, 'distinctDays': len({t[:10] for t in ts}),
                     'resources': sorted({short(x['resourceId']) for x in evs})[:6], 'alreadyReported': reported})
    rows.sort(key=lambda x: -x['count'])
    inventory['failedOperations30d'] = {'window': '可靠性检查采集的近 30 天活动日志', 'groups': rows,
                                        'note': 'NSG PreconditionFailedEtagMismatch 与 VMSS“instanceId 不是活动实例”由 AKS 控制器并发更新/缩容竞态产生，会自动重试，判断为无害。'}
    failed = d.rows('failed_detail')
    if failed:
        items = []
        for r in failed:
            props = r.get('properties') or {}
            link = ((props.get('privateLinkServiceConnections') or [{}])[0].get('properties') or {}).get('privateLinkServiceId')
            items.append({'resourceName': r['name'], 'type': r['type'], 'subscriptionName': d.subname(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
                          'provisioningState': props.get('provisioningState'),
                          'privateLinkTarget': short(link) if r['type'] == 'microsoft.network/privateendpoints' else None,
                          'ipPrefix': props.get('ipPrefix') if r['type'] == 'microsoft.network/publicipprefixes' else None})
        pe = [x for x in items if x['type'] == 'microsoft.network/privateendpoints']
        described = '、'.join(f"{TYPE_NAMES.get(x['type'], x['type'].split('/')[-1])} {x['resourceName']}" for x in items[:5])
        out.add('O6', '中', f"{len(failed)} 个资源当前仍处于 Failed 预配状态：{described}；失败状态的资源后续任何修改都可能报错"
                + ('，私有终结点失败还可能导致应用无法经内网访问目标资源' if pe else '') + '。',
                ('确认失败的私有终结点对应的目标当前通过哪个地址被访问；如需私有访问，删除后重建（或对其执行一次无变化的更新让其重新预配）；' if pe else '')
                + '其他失败资源如未被使用则删除，如需要则重新创建或重新执行一次更新；' + NO_CHANGE,
                subscription='、'.join(sorted({x['subscriptionName'] for x in items if x['subscriptionName']})), resource_name='、'.join(x['resourceName'] for x in items),
                resource_type='多种', environment=mixed_env([d.env_of(r['subscriptionId'], r['name'], r.get('tags')) for r in failed]),
                evidence={'items': items}, members=[{'name': x['resourceName'], 'type': x['type'], 'subscription': x['subscriptionName']} for x in items],
                key='failed-provisioning', needs_confirmation='请确认这些资源是否仍需要，以及相关服务的访问方式。')
    inventory['failedOperations30d']['otherRecurringNotReported'] = [
        x for x in rows if not x['alreadyReported'] and x['count'] >= 5 and x['recurringLast7Days']
        and x['innerCode'] != 'PreconditionFailedEtagMismatch' and x['errorCode'] not in ('InvalidParameter',)]


TYPE_NAMES = {'microsoft.network/privateendpoints': '私有终结点', 'microsoft.network/publicipprefixes': '公共 IP 前缀',
              'microsoft.network/publicipaddresses': '公共 IP', 'microsoft.network/networkinterfaces': '网卡',
              'microsoft.compute/virtualmachines': '虚拟机', 'microsoft.compute/disks': '磁盘'}
