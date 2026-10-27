"""O1 monitoring coverage, O2 alerting, O3 log retention and volume."""
from __future__ import annotations

import collections

from ..common import is_prod, mixed_env
from .data import DATA_TYPES, DB_MONITORING_POOLS, short, sub_of

NO_CHANGE = '本次未做任何更改。'
AKS_TYPE = 'Microsoft.ContainerService/managedClusters'
REC_AKS = ('为集群启用 Container Insights（建议只采集 ContainerLogV2 + KubeEvents/KubePodInventory，控制费用）和 Azure Monitor 托管 Prometheus，'
           '并启用 AKS 推荐的 Prometheus 告警规则（节点 NotReady/不可达、CPU/内存、Pod 崩溃重启、Pending、PV 容量），告警发到运维值班组；' + NO_CHANGE)
REC_DB = ('为生产数据库/缓存建立统一的 Azure Monitor 指标告警基线：CPU>80%、内存>85%、存储使用率>80%（MySQL/PG）、连接数接近上限、复制延迟（有只读副本时）、'
          '服务器不可用/资源健康（Resource Health）以及 Redis 的服务器负载/内存/连接错误；可用 Azure Monitor 基线告警（AMBA）策略批量部署，发到运维值班组；'
          '同时为关键 MySQL/PG 开启错误日志/慢查询诊断日志；' + NO_CHANGE)


def members(items, rtype):
    return [{'name': i['resourceName'], 'type': rtype, 'subscription': i.get('subscriptionName')} for i in items]


def subs_text(items):
    return '、'.join(sorted({i['subscriptionName'] for i in items if i.get('subscriptionName')}))


def aks_item(r):
    return {'resourceName': r['resourceName'], 'subscriptionName': r['subscriptionName'], 'resourceGroup': r['resourceGroup'],
            'containerInsights': r['containerInsights'], 'managedPrometheus': r['managedPrometheus'],
            'diagnosticSettingsCount': r['diagnosticSettingsCount'], 'alertRules': r['alertRulesTargeting'],
            'pvcNamespaces': r['pvcNamespaces'], 'selfHostedMonitoringSignals': r['selfHostedMonitoringSignals'],
            'leftoverContainerInsightsDcr': r['leftoverContainerInsightsDcr'] or None}


def kitem(k):
    return {'resourceName': k['resourceName'], 'type': k['typeLabel'], 'subscriptionName': k['subscriptionName'], 'resourceGroup': k['resourceGroup'],
            'diagnosticLogs': k['diagnosticSettings'], 'alertRules': k['alerts']}


def advisor_count(d, text):
    return sum(1 for x in d.advisor.get('recommendations', []) if text in x['properties']['shortDescription']['problem'].lower())


def check_aks(d, out, aks_rows, rules):
    prod = [r for r in aks_rows if is_prod(r['environment'])]
    nomon = [r for r in prod if not r['containerInsights'] and not r['managedPrometheus'] and not r['alertRulesTargeting']]
    none = [r for r in nomon if not r['selfHostedMonitoringSignals'] and not r['vendor']]
    self_hosted = [r for r in nomon if r['selfHostedMonitoringSignals']]
    vendor = [r for r in nomon if not r['selfHostedMonitoringSignals'] and r['vendor']]
    adv = sum(1 for x in d.advisor.get('recommendations', []) if x['properties']['category'] == 'OperationalExcellence'
              and 'container monitoring' in x['properties']['shortDescription']['problem'].lower())
    for r in none:
        diag = '诊断设置未取得' if r['diagnosticSettingsCount'] is None else f"诊断设置 {r['diagnosticSettingsCount']} 个"
        out.add('O1', '高', f"生产集群 {r['resourceName']} 在 Azure 侧没有任何监控和告警：未启用 Container Insights 和托管 Prometheus、{diag}、"
                f"没有任何告警规则，集群里也没发现 monitoring/logging 类自建监控的持久卷；节点故障或 Pod 大面积异常时很可能没人第一时间知道。", REC_AKS,
                subscription=r['subscriptionName'], resource_group=r['resourceGroup'], resource_name=r['resourceName'], resource_type=AKS_TYPE,
                resource_id=r['id'], environment=r['environment'], evidence={'items': [aks_item(r)], 'advisorContainerMonitoringRecs': adv},
                needs_confirmation='如已有 Azure 之外的监控平台覆盖此集群（例如外部 Prometheus 抓取），请说明，可降级。')
    if self_hosted:
        out.add('O1', '中', f"{len(self_hosted)} 个生产集群在 Azure 侧没有 Container Insights、托管 Prometheus 和任何告警规则；集群内有 monitoring/logging 命名空间的持久卷"
                f"或自建监控节点池（{'、'.join(sorted({s for r in self_hosted for s in r['selfHostedMonitoringSignals']}))}），推测使用自建监控，"
                f"但 Azure 平台层事件（节点 NotReady、扩容失败、升级失败）没有告警。",
                '确认自建监控已覆盖节点就绪、Pod 重启/Pending、PV 容量并接入值班告警；在 Azure 侧至少补一组基础告警（节点 NotReady/CPU/内存的平台指标告警，'
                '以及资源健康告警），与自建告警共用同一值班渠道；' + NO_CHANGE,
                subscription=subs_text(self_hosted), resource_name='、'.join(r['resourceName'] for r in self_hosted), resource_type=AKS_TYPE,
                environment=mixed_env([r['environment'] for r in self_hosted]), evidence={'items': [aks_item(r) for r in self_hosted]},
                members=members(self_hosted, AKS_TYPE), key='aks-self-hosted-monitoring', needs_confirmation='请确认自建监控的覆盖范围和告警通知方式。')
    for name in sorted({r['vendor'] for r in vendor}):
        rows = [r for r in vendor if r['vendor'] == name]
        out.add('O1', '中', f"{len(rows)} 个 {name} 集群在 Azure 侧没有 Container Insights、托管 Prometheus 和任何告警规则，集群由 {name} 部署和运维，"
                f"监控可能由 {name} 控制台负责，但客户运维侧看不到节点和 Pod 异常。",
                f'与 {name} 确认其控制台是否提供节点/服务告警并通知到贵方值班；在 Azure 侧补节点 CPU/内存/磁盘和节点就绪的平台指标告警；' + NO_CHANGE,
                subscription=subs_text(rows), resource_name='、'.join(r['resourceName'] for r in rows), resource_type=AKS_TYPE,
                environment=mixed_env([r['environment'] for r in rows]), evidence={'items': [aks_item(r) for r in rows], 'vendor': name},
                members=members(rows, AKS_TYPE), key=f'aks-vendor-{name}', needs_confirmation=f'请确认 {name} 控制台的监控与告警是否已通知到贵方运维。')
    for r in [r for r in prod if (r['containerInsights'] or r['managedPrometheus']) and not r['alertRulesTargeting']]:
        recording = [ru['name'] for ru in rules if r['id'].lower() in ru['scopes'] and ru['kind'] == 'prometheus-recording']
        out.add('O2', '中', f"生产集群 {r['resourceName']} 已采集 Container Insights（工作区 {r['containerInsightsWorkspace']}）和托管 Prometheus 指标，"
                f"但只配置了 {len(recording)} 个 Prometheus 记录规则组，没有任何告警规则，数据有了却不会主动通知。",
                '在该集群启用 AKS 推荐的 Prometheus 告警规则组（集群级、节点级、Pod 级）并绑定运维值班操作组；' + NO_CHANGE,
                subscription=r['subscriptionName'], resource_group=r['resourceGroup'], resource_name=r['resourceName'], resource_type=AKS_TYPE,
                resource_id=r['id'], environment=r['environment'], evidence={'items': [aks_item(r)], 'recordingRuleGroups': recording})


def fired_alerts(d, inventory):
    fired = [dict(a, subscriptionName=s['subscriptionName']) for s in d.subreads for a in (s.get('firedAlerts') or {}).get('value') or []]
    summary = collections.Counter((a['subscriptionName'], short(a.get('alertRule') or '') or a['name'], a.get('severity'), a.get('monitorService'),
                                   a.get('alertState'), a.get('monitorCondition')) for a in fired)
    inventory['firedAlerts30d'] = {
        'window': '近 30 天（timeRange=30d）', 'total': len(fired),
        'bySubscriptionRule': [{'subscriptionName': k[0], 'rule': k[1], 'severity': k[2], 'monitorService': k[3], 'alertState': k[4],
                                'monitorCondition': k[5], 'count': n} for k, n in summary.most_common()],
        'byAlertName': [{'alert': k, 'count': n} for k, n in collections.Counter(a['name'] for a in fired).most_common(20)],
        'stateCounts': dict(collections.Counter(a.get('alertState') for a in fired)),
        'neverAcknowledgedOrClosed': sum(1 for a in fired if a.get('alertState') == 'New'),
        'stillFiring': sum(1 for a in fired if a.get('monitorCondition') == 'Fired')}
    return fired


def check_alert_noise(d, out, fired, rules, aks_rows):
    prom = [a for a in fired if a.get('monitorService') == 'Prometheus']
    if not prom:
        return
    target = collections.Counter(short(a.get('targetResource')) for a in prom).most_common(1)[0][0]
    target_id = next((a.get('targetResource') for a in prom if short(a.get('targetResource')) == target), '') or ''
    top = collections.Counter(a['name'].split('/')[-1] for a in prom).most_common(6)
    ag_info = {a['name']: a for a in d.ags}
    used = sorted({g for ru in rules if ru['kind'] == 'prometheus-alert' and target.lower() in ' '.join(ru['scopes']) for g in ru['actionGroups']})
    receivers = ('email', 'sms', 'webhook', 'voice', 'azureAppPush', 'itsm', 'logicApp', 'azureFunction', 'automationRunbook', 'armRole', 'eventHub')
    agd = [{'actionGroup': g, 'enabled': (ag_info.get(g) or {}).get('enabled'),
            'receivers': {k: (ag_info.get(g) or {}).get(k) for k in receivers if (ag_info.get(g) or {}).get(k)},
            'subscription': d.subname((ag_info.get(g) or {}).get('subscriptionId', ''))} for g in used]
    oncall = sorted({g for ru in rules if ru['kind'] == 'activity:ServiceHealth' and ru['enabled'] for g in ru.get('actionGroups') or []} - set(used))
    new_n = sum(1 for a in prom if a.get('alertState') == 'New')
    firing = sum(1 for a in prom if a.get('monitorCondition') == 'Fired')
    emails = sum((x['receivers'].get('email') or 0) for x in agd)
    cluster = next((r for r in aks_rows if r['resourceName'].lower() == target.lower()), None)
    out.add('O2', '中', f"集群 {target} 近 30 天触发 {len(prom)} 条 Prometheus 告警（其中 {top[0][0]} {top[0][1]} 条），"
            f"{new_n} 条从未被确认或关闭、{firing} 条仍在触发；这些告警只发到操作组 {', '.join(used) or '（无）'}（仅 {emails} 个邮箱）"
            + (f"，没有发到服务运行状况告警使用的值班组 {'、'.join(oncall)}" if oncall else '') + "，大量重复告警容易让真正的故障被淹没。",
            f'先处理反复触发的根因（{top[0][0]} 对应的工作负载），对确实无需处理的规则调高阈值/延长持续时间或按命名空间排除；'
            '把告警同时发到运维值班组（或接入 IM/工单）并约定确认/关闭流程；' + NO_CHANGE,
            subscription=d.subname(sub_of(target_id)) or (cluster or {}).get('subscriptionName'), resource_group=(cluster or {}).get('resourceGroup'),
            resource_name=target, resource_type='Microsoft.AlertsManagement/prometheusRuleGroups',
            environment=(cluster or {}).get('environment') or d.env_of(sub_of(target_id), target),
            evidence={'topAlerts': [{'alert': k, 'count': n} for k, n in top], 'actionGroups': agd, 'onCallGroupsNotUsed': oncall,
                      'severityCounts': dict(collections.Counter(a.get('severity') for a in prom)),
                      'firstFired': min(a['startDateTime'] for a in prom), 'lastFired': max(a['startDateTime'] for a in prom)},
            members=[{'name': target, 'type': AKS_TYPE, 'subscription': (cluster or {}).get('subscriptionName')}], key=f'alert-noise-{target}')


def check_data_resources(d, out, key_rows, aks_rows):
    noalert = [k for k in key_rows if k['type'] in DATA_TYPES and is_prod(k['environment']) and not k['alerts']]
    # Subscriptions whose clusters run a database-monitoring pool: databases there are probably watched by it.
    dbmon = [r for r in aks_rows if set(r['selfHostedMonitoringSignals']) & set(DB_MONITORING_POOLS)]
    pmm_subs = {r['subscriptionName'] for r in dbmon}
    pmm_clusters = sorted(r['resourceName'] for r in dbmon)
    pools = '、'.join(sorted({s for r in dbmon for s in r['selfHostedMonitoringSignals'] if s in DB_MONITORING_POOLS}))
    self_side = [k for k in noalert if k['subscriptionName'] in pmm_subs]
    other = [k for k in noalert if k['subscriptionName'] not in pmm_subs]
    if other:
        bytype = collections.Counter(k['typeLabel'] for k in other)
        lines = sorted({d.cfg.business_line(k['subscriptionName']) for k in other} - {None})
        with_logs = sum(1 for k in other if k['hasDiagnosticLogs'])
        out.add('O2', '高', (f"{'、'.join(lines)} 等业务线的" if lines else '') + f" {len(other)} 个生产数据库和缓存（{'、'.join(f'{t} {n} 个' for t, n in bytype.most_common())}）没有任何 Azure 告警规则，"
                + (f"其中只有 {with_logs} 个开了诊断日志" if with_logs else "也都没有开诊断日志") + "；CPU/存储打满、连接耗尽或实例不可用时不会有人收到通知。",
                REC_DB, subscription=subs_text(other), resource_name=f"{len(other)} 个数据库/缓存实例", resource_type='多种（MySQL/PostgreSQL/Redis/MongoDB）',
                environment=mixed_env([k['environment'] for k in other]), evidence={'items': [kitem(k) for k in other], 'byType': dict(bytype)},
                members=[{'name': k['resourceName'], 'type': k['type'], 'subscription': k['subscriptionName']} for k in other], key='data-no-alert',
                needs_confirmation='如已有 Azure 之外的数据库监控（如 PMM、Zabbix）覆盖这些实例，请说明覆盖范围，可降级。')
    if self_side:
        bytype = collections.Counter(k['typeLabel'] for k in self_side)
        lines = sorted({d.cfg.business_line(k['subscriptionName']) for k in self_side} - {None})
        out.add('O2', '中', (f"{'、'.join(lines)} 业务线的" if lines else '') + f" {len(self_side)} 个生产数据库和缓存（{'、'.join(f'{t} {n} 个' for t, n in bytype.most_common())}）没有任何 Azure 告警规则，"
                f"只有 {sum(1 for k in self_side if k['hasDiagnosticLogs'])} 个开了诊断日志（慢查询/审计）；所在订阅的集群有 {pools} 节点池，推测由自建的数据库监控覆盖，但 Redis 和平台层故障未见告警。",
                REC_DB, subscription=subs_text(self_side), resource_name=f"{len(self_side)} 个数据库/缓存实例", resource_type='多种（MySQL/PostgreSQL/Redis/MongoDB）',
                environment=mixed_env([k['environment'] for k in self_side]),
                evidence={'items': [kitem(k) for k in self_side], 'byType': dict(bytype), 'selfHostedSignal': '、'.join(pmm_clusters) + f' 有 {pools} 节点池'},
                members=[{'name': k['resourceName'], 'type': k['type'], 'subscription': k['subscriptionName']} for k in self_side], key='data-no-alert-self-hosted',
                needs_confirmation='请确认自建监控是否覆盖全部相关数据库并配置了告警通知；Redis 是否有其他监控。')


def check_edge(d, out, key_rows):
    edge_types = ('microsoft.network/applicationgateways', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworkgateways', 'microsoft.network/expressroutecircuits')
    gap = [k for k in key_rows if k['type'] in edge_types and is_prod(k['environment']) and not k['alerts']]
    if not gap:
        return
    er = advisor_count(d, 'connection monitor')
    n = lambda *types: sum(1 for k in gap if k['type'] in types)  # noqa: E731
    fd_logs = sum(1 for k in gap if k['type'] == 'microsoft.cdn/profiles' and k['hasDiagnosticLogs'])
    gw_logs = sum(1 for k in gap if k['type'] == 'microsoft.network/applicationgateways' and k['hasDiagnosticLogs'])
    gw_text = '均未开访问/防火墙日志' if not gw_logs else f'{gw_logs} 个开了日志'
    out.add('O2', '中', f"{len(gap)} 个生产入口和混合网络资源没有任何告警：应用网关 {n('microsoft.network/applicationgateways')} 个（{gw_text}）、"
            f"Front Door {n('microsoft.cdn/profiles')} 个（仅 {fd_logs} 个开了日志）、"
            f"ExpressRoute/VPN 网关和线路 {n('microsoft.network/virtualnetworkgateways', 'microsoft.network/expressroutecircuits')} 个（Advisor 另提示 {er} 处未配置 Connection Monitor），"
            f"后端不健康、5xx 激增或专线中断时不会主动告警。",
            '应用网关：为“不健康后端主机数>0”“失败请求/5xx 比例”“容量单位”配置指标告警并开启访问/防火墙日志；Front Door：为源站健康百分比、5xx 比例、总延迟配置告警；'
            'ExpressRoute/VPN：为 BGP 可用性、ARP 可用性、隧道状态配置告警并启用 Connection Monitor；' + NO_CHANGE,
            subscription=subs_text(gap), resource_name=f"{len(gap)} 个入口/混合网络资源", resource_type='应用网关 / Front Door / ExpressRoute / VPN',
            environment=mixed_env([k['environment'] for k in gap]),
            evidence={'items': [{'resourceName': k['resourceName'], 'type': k['typeLabel'], 'subscriptionName': k['subscriptionName'],
                                 'diagnosticLogs': k['diagnosticSettings'], 'sku': k.get('sku'), 'gatewayType': k.get('gatewayType')} for k in gap],
                      'advisorConnectionMonitorRecs': er},
            members=[{'name': k['resourceName'], 'type': k['type'], 'subscription': k['subscriptionName']} for k in gap], key='edge-no-alert')


def check_vms(d, out, vm_rows, cov_type):
    gap = [v for v in vm_rows if is_prod(v['environment']) and v['power'] == 'running' and not v['amaExtension'] and not v['legacyAgent'] and not v['alerts']]
    if not gap:
        return
    data_vms = [v for v in gap if (v['dataDisks'] or 0) > 0]
    vm_cov = cov_type['虚拟机（非 AKS）']
    stopped = '（且已停机）' if vm_cov['amaInstalled'] and not vm_cov['amaRunning'] else ''
    examples = '、'.join(v['resourceName'] for v in sorted(data_vms, key=lambda v: -(v['dataDisks'] or 0))[:3])
    out.add('O1', '中', f"{len(gap)} 台运行中的生产虚拟机（其中 {len(data_vms)} 台挂有数据盘" + (f"，如 {examples}" if examples else '') + "）没有安装 Azure Monitor 代理、没有 VM Insights、也没有任何告警规则，"
            f"只能看到宿主机层面的 CPU/磁盘 IO，看不到内存和磁盘剩余空间，磁盘写满或进程挂掉不会告警；全部 {len(vm_rows)} 台非 AKS 虚拟机中只有 {vm_cov['amaInstalled']} 台装了代理{stopped}。",
            '先对挂数据盘和承载核心服务的虚拟机安装 Azure Monitor 代理并关联 VM Insights 数据收集规则，'
            '配置“可用内存<10%”“磁盘剩余空间<15%”“CPU>90% 持续 15 分钟”“VM 不可用（资源健康）”告警；可用 Azure Policy 对新 VM 自动部署代理；' + NO_CHANGE,
            subscription=subs_text(gap), resource_name=f"{len(gap)} 台虚拟机", resource_type='Microsoft.Compute/virtualMachines',
            environment=mixed_env([v['environment'] for v in gap]),
            evidence={'items': [{'resourceName': v['resourceName'], 'subscriptionName': v['subscriptionName'], 'resourceGroup': v['resourceGroup'], 'dataDisks': v['dataDisks']}
                                for v in sorted(gap, key=lambda v: (v['subscriptionName'], v['resourceName']))],
                      'withDataDisks': len(data_vms), 'advisorVmInsightsRecs': advisor_count(d, 'vm insights')},
            members=members(gap, 'Microsoft.Compute/virtualMachines'), key='vm-no-agent',
            needs_confirmation='如虚拟机已由 Zabbix/Prometheus node_exporter 等自建监控覆盖，请说明。')


def check_storage(d, out, key_rows):
    gap = [k for k in key_rows if k['type'] == 'microsoft.storage/storageaccounts' and is_prod(k['environment']) and not k['hasDiagnosticLogs'] and not k['alerts']]
    if not gap:
        return
    top = max(gap, key=lambda k: k['monthCostUSD'] or 0)
    month = f'{d.month} 月' if d.month else '上月'
    out.add('O1', '低', f"费用最高的 {len(gap)} 个生产存储账户（包括 {month}费用 USD {top['monthCostUSD'] or 0:,.0f} 的 {top['resourceName']}）没有开启 Blob 诊断日志，"
            "也没有可用性/容量/延迟告警，误删或访问异常时难以追查。",
            '为承载业务数据的账户配置“可用性<99.9%”“成功端到端延迟”“已用容量增长”告警；需要追查删除/覆盖操作的账户开启 blobServices 的 StorageDelete/StorageWrite 日志（注意日志量）；' + NO_CHANGE,
            subscription=subs_text(gap), resource_name=f"{len(gap)} 个存储账户", resource_type='Microsoft.Storage/storageAccounts',
            environment=mixed_env([k['environment'] for k in gap]),
            evidence={'items': [{'resourceName': k['resourceName'], 'subscriptionName': k['subscriptionName'], 'monthCostUSD': k['monthCostUSD']}
                                for k in sorted(gap, key=lambda k: -(k['monthCostUSD'] or 0))]},
            members=members(gap, 'Microsoft.Storage/storageAccounts'), key='storage-no-diag')


def check_service_health(d, out, rules, inventory):
    sh = [ru for ru in rules if ru['kind'] == 'activity:ServiceHealth' and ru['enabled']]
    sh_subs = {sub_of(sc) for ru in sh for sc in ru['scopes']}
    rh = [ru for ru in rules if ru['kind'] == 'activity:ResourceHealth' and ru['enabled']]
    res_count = collections.Counter(d.subname(r['subscriptionId']) for r in d.res)
    missing = sorted([s for s in d.enabled if is_prod(d.sub_env(s['name'])) and s['id'].lower() not in sh_subs],
                     key=lambda s: -res_count.get(s['name'], 0))
    inventory['serviceHealthAlerts'] = [{'name': ru['name'], 'subscriptionName': d.subname(sub_of(ru['scopes'][0])) if ru['scopes'] else None,
                                         'regions': ru.get('regions'), 'actionGroups': ru['actionGroups']} for ru in sh]
    if not missing:
        return
    examples = '、'.join(s['name'] for s in missing[:4])
    groups = sorted({g for ru in sh for g in ru['actionGroups']})
    have = (f"只有 {len(sh_subs)} 个订阅（{'、'.join(sorted(filter(None, (d.subname(x) for x in sh_subs))))}）配了 Azure 服务运行状况告警"
            + ('，且每条只关注一个区域' if sh and all(len(ru.get('regions') or []) <= 1 for ru in sh) else '') if sh_subs else '没有任何订阅配置 Azure 服务运行状况告警')
    out.add('O2', '中', f"{have}；{examples} 等 {len(missing)} 个生产订阅没有服务运行状况告警，" + ('全部订阅都没有' if not rh else f'只有 {len(rh)} 条') + "资源运行状况（Resource Health）告警，"
            "Azure 平台故障、计划维护和安全公告不会主动通知到这些订阅的负责人。",
            '在每个生产订阅创建服务运行状况告警（事件类型：服务问题、计划内维护、运行状况公告、安全公告；区域选该订阅实际使用的全部区域，含 Global），'
            f"并对 AKS、数据库、应用网关等关键资源创建资源运行状况告警，统一发到{('运维值班组（如 ' + '、'.join(groups) + '）') if groups else '运维值班组'}；" + NO_CHANGE,
            subscription=f"多个订阅（{len(missing)} 个生产订阅）", resource_type='Microsoft.Insights/activityLogAlerts',
            environment=mixed_env([d.sub_env(s['name']) for s in missing]),
            evidence={'items': [{'resourceName': s['name'], 'resourceCount': res_count.get(s['name'], 0)} for s in missing],
                      'existingServiceHealthAlerts': inventory['serviceHealthAlerts'], 'resourceHealthAlerts': len(rh),
                      'advisorServiceHealthRecs': advisor_count(d, 'service health alert')},
            members=[{'name': s['name'], 'type': 'Microsoft.Resources/subscriptions', 'subscription': s['name']} for s in missing], key='service-health')


def check_certificates(d, out, rules, related):
    kv = [t for t in d.targets if t['type'] == 'microsoft.keyvault/vaults']
    if not kv:
        return
    from .data import alerts_for
    kv_alert = [t for t in kv if alerts_for(rules, t['id'], t['type'])]
    system_topics = sum(1 for r in d.res if r['type'] == 'microsoft.eventgrid/systemtopics')
    expired = (f"；可靠性检查发现已过期的证书（{related['resourceName']}，见 {related['id']}），说明证书到期目前无人提醒" if related else '')
    out.add('O2', '中', f"没有任何证书或密钥到期告警：{len(kv)} 个 Key Vault 中 {len(kv_alert)} 个配置了告警，"
            + ('Resource Graph 中也没有任何 Event Grid 系统主题（无法订阅到期事件）' if not system_topics else f'Resource Graph 中有 {system_topics} 个 Event Grid 系统主题，需确认是否订阅了到期事件')
            + expired + '。',
            '为存放证书的 Key Vault 开启 AuditEvent 日志，并通过 Event Grid 订阅 CertificateNearExpiry/SecretNearExpiry 事件发到值班渠道，'
            '或建立证书到期清单（含 Front Door 自定义域名证书）每月检查；能改用 Front Door 托管证书的域名改用托管证书；' + NO_CHANGE,
            subscription='、'.join(sorted({d.subname(t['subscriptionId']) for t in kv})), resource_name=f"{len(kv)} 个 Key Vault 与 Front Door 证书",
            resource_type='Microsoft.KeyVault/vaults', environment=mixed_env([d.env_of(t['subscriptionId'], t['name'], t.get('tags')) for t in kv]),
            evidence={'items': [{'resourceName': t['name'], 'subscriptionName': d.subname(t['subscriptionId']), 'resourceGroup': t['resourceGroup']} for t in kv],
                      'relatedFinding': related['id'] if related else None, 'eventGridSystemTopics': system_topics},
            members=[{'name': t['name'], 'type': 'Microsoft.KeyVault/vaults', 'subscription': d.subname(t['subscriptionId'])} for t in kv], key='certificate-expiry')


def check_stale(d, out, rules, aks_rows):
    stale_rules = [{'resourceName': ru['name'], 'type': ru['type'], 'enabled': ru['enabled'], 'missingTarget': short(sc),
                    'subscriptionId': ru['subscriptionId'], 'resourceGroup': ru['resourceGroup']}
                   for ru in rules for sc in ru['scopes']
                   if '/providers/microsoft.containerservice/managedclusters/' in sc and sc not in d.ridx]
    gone = sorted({x['missingTarget'] for x in stale_rules})
    stale_dcr = [{'resourceName': x['name'], 'type': 'dataCollectionRule'} for x in d.dcr if any(g.lower() in x['name'].lower() for g in gone)]
    stale_dce = [{'resourceName': m['name'], 'type': 'dataCollectionEndpoint'} for m in d.mon
                 if m['type'] == 'microsoft.insights/datacollectionendpoints' and any(m['name'].lower().endswith('-' + g.lower()) for g in gone)]
    leftover = [{'resourceName': x, 'type': 'dataCollectionRule', 'note': f"集群 {r['resourceName']} 已关闭 Container Insights"}
                for r in aks_rows for x in r['leftoverContainerInsightsDcr']]
    items = [{k: v for k, v in x.items() if k not in ('subscriptionId', 'resourceGroup')} for x in stale_rules] + stale_dcr + stale_dce + leftover
    if not items:
        return
    enabled_alerts = sum(1 for x in stale_rules if x['enabled'])
    subs = sorted({d.subname(x['subscriptionId']) for x in stale_rules} | {r['subscriptionName'] for r in aks_rows if r['leftoverContainerInsightsDcr']})
    off = [r['resourceName'] for r in aks_rows if r['leftoverContainerInsightsDcr']]
    gone_text = '、'.join(gone) or '（无）'
    out.add('O2', '低', f"有 {len(items)} 个监控配置指向已不存在的集群 {gone_text} 或已关闭监控的集群（{len(stale_rules)} 条告警/记录规则组、{len(stale_dcr)} 个数据收集规则、"
            f"{len(stale_dce)} 个数据收集终结点等），其中 {enabled_alerts} 组规则仍为启用状态，造成配置混乱，也可能让人误以为对应集群有告警。",
            f"确认 {gone_text} 已退役后删除这些告警规则组、指标告警、数据收集规则和终结点"
            + (f"；{'、'.join(off)} 如不再使用 Container Insights，删除遗留的 MSCI 数据收集规则" if off else '') + '；' + NO_CHANGE,
            subscription='、'.join(filter(None, subs)), resource_group=stale_rules[0]['resourceGroup'] if stale_rules else None,
            resource_name=f"已删除集群 {gone_text} 的监控配置" if gone else '遗留的监控配置', resource_type='Microsoft.AlertsManagement/prometheusRuleGroups',
            environment=mixed_env([d.sub_env(s) for s in subs if s]), evidence={'items': items},
            members=[{'name': x['resourceName'], 'type': x['type'], 'subscription': None} for x in items], key='stale-monitoring')


def check_logs(d, out, key_rows, aks_rows, inventory):
    workspaces = [m for m in d.mon if m['type'] == 'microsoft.operationalinsights/workspaces']
    usage = {w['resourceId'].lower(): w for w in d.logs.get('workspaces', [])}
    tables = {w['id'].lower(): w for w in d.wst}
    rows = []
    for w in workspaces:
        u, tb = usage.get(w['id'].lower()) or {}, tables.get(w['id'].lower()) or {}
        rows.append({'resourceName': w['name'], 'subscriptionName': d.subname(w['subscriptionId']), 'resourceGroup': w['resourceGroup'],
                     'retentionInDays': w.get('retention'), 'dailyQuotaGb': (w.get('capping') or {}).get('dailyQuotaGb'),
                     'tablesWithNonDefaultRetentionOrArchive': None if tb.get('nonDefaultTables') is None else len(tb['nonDefaultTables']),
                     'tablesTotal': tb.get('tablesTotal'), 'monthCostUSD': u.get('curCostUSD', u.get('sepCostUSD')), 'billableGBMonth': u.get('billableGB'),
                     'topDataTypes': [x.get('DataType') for x in (u.get('byDataType') or [])[:3]]})
    inventory['logAnalyticsWorkspaces'] = rows
    senders = collections.defaultdict(set)
    for k in key_rows:
        for x in k['diagnosticSettings'] or []:
            if x['logs'] and x['dest']:
                senders[x['dest']].add(f"{k['typeLabel']}:{k['resourceName']}")
    for r in aks_rows:
        if r['containerInsights'] and r['containerInsightsWorkspace']:
            senders[r['containerInsightsWorkspace']].add(f"AKS Container Insights:{r['resourceName']}")
    inventory['logDestinations'] = {k: sorted(v) for k, v in senders.items()}
    prod = [w for w in rows if is_prod(d.sub_env(w['subscriptionName']))]
    if prod and all((w['retentionInDays'] or 0) <= 30 for w in rows):
        kinds = sorted({s.split(':')[0] for w in prod for s in senders.get(w['resourceName'], [])})
        out.add('O3', '中', f"全部 {len(rows)} 个 Log Analytics 工作区保留期都只有 30 天、没有任何表配置长期保留/归档"
                + (f"，其中生产工作区承载 {'、'.join(kinds)} 的日志" if kinds else '') + "；超过 30 天的日志明细无法再查询，故障复盘和审计追溯无法进行。",
                '按日志用途分级：审计类表（数据库审计日志、Front Door WAF 日志、AKS 审计日志）设置总保留期 180–365 天（超出交互期的部分走低价长期保留）；'
                '故障排查类（ContainerLogV2、慢查询）保留 30–90 天；同时确认合规要求的保留时长；' + NO_CHANGE,
                subscription=subs_text(prod), resource_name=f"{len(rows)} 个 Log Analytics 工作区", resource_type='Microsoft.OperationalInsights/workspaces',
                environment=mixed_env([d.sub_env(w['subscriptionName']) for w in prod]),
                evidence={'items': [{'resourceName': w['resourceName'], 'subscriptionName': w['subscriptionName'], 'retentionInDays': w['retentionInDays'],
                                     'dailyQuotaGb': w['dailyQuotaGb'], 'monthCostUSD': w['monthCostUSD'], 'sources': sorted(senders.get(w['resourceName'], []))[:12]}
                                    for w in prod],
                          'tablesWithArchiveOrLongRetention': sum(w['tablesWithNonDefaultRetentionOrArchive'] or 0 for w in rows)},
                members=members(rows, 'Microsoft.OperationalInsights/workspaces'), key='log-retention',
                needs_confirmation='请确认公司/行业对审计日志的保留期要求。')
    nocap = [w for w in rows if (w['dailyQuotaGb'] or -1) < 0]
    if nocap:
        big = sorted([w for w in nocap if w['monthCostUSD']], key=lambda w: -(w['monthCostUSD'] or 0))
        month = f'{d.month} 月' if d.month else '上月'
        text = (f"{len(nocap)} 个工作区都没有设置每日数据上限，也没有数据量告警；{month} {big[0]['resourceName']} 单个工作区费用约 USD {big[0]['monthCostUSD']:,.0f}，日志量突增时只能在账单上发现。"
                if big else f"{len(nocap)} 个工作区都没有设置每日数据上限。")
        out.add('O3', '低', text,
                '对非审计类工作区设置略高于正常峰值的每日上限，并为所有工作区配置“每日引入量超阈值”日志告警（Usage 表）；审计类工作区不设上限但保留告警；' + NO_CHANGE,
                subscription='多个订阅', resource_name=f"{len(nocap)} 个 Log Analytics 工作区", resource_type='Microsoft.OperationalInsights/workspaces',
                environment=mixed_env([d.sub_env(w['subscriptionName']) for w in nocap]),
                evidence={'items': [{'resourceName': w['resourceName'], 'subscriptionName': w['subscriptionName'], 'monthCostUSD': w['monthCostUSD']} for w in big[:5]]},
                members=members(nocap, 'Microsoft.OperationalInsights/workspaces'), key='log-daily-cap')
