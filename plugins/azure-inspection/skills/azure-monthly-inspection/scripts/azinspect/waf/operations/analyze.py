"""Operational excellence analysis (offline): raw/waf/operations + reused raw data -> findings/waf/operations.json."""
from __future__ import annotations

import collections

from ..common import Findings, coverage_entry
from . import change, governance, monitoring
from .data import Data, build_aks_rows, build_key_rows, build_rules, build_vm_rows, coverage_by_type, short

CHECKS = [f'O{i}' for i in range(1, 11)]
ORDER = {'高': 0, '中': 1, '低': 2}


class Pending:
    """Collects findings, then numbers them the way earlier inspections did (severity, check, subscription)."""

    def __init__(self):
        self.items = []

    def add(self, check, severity, finding, recommendation, **kw):
        self.items.append((check, severity, finding, recommendation, kw))

    def into(self, findings: Findings):
        ordered = sorted(self.items, key=lambda x: (ORDER[x[1]], int(x[0][1:]), x[4].get('subscription') or ''))
        for i, (check, severity, finding, recommendation, kw) in enumerate(ordered, 1):
            findings.add(check, severity, finding, recommendation, legacy_id=f'OPS-{i:03d}', **kw)


def related_certificate(ws):
    """An expired-certificate finding from the reliability pillar, if that pillar was analyzed first."""
    path = ws.month_dir('findings') / 'waf' / 'reliability.json'
    if not path.exists():
        return None
    from ...core.io import read_json
    for f in read_json(path).get('findings', []):
        if '证书' in (f.get('finding') or '') and '过期' in (f.get('finding') or ''):
            return {'id': f['id'], 'resourceName': f.get('resourceName')}
    return None


def coverage(d):
    cov = {c: coverage_entry() for c in CHECKS}
    shared = {'attempted': 0, 'succeeded': 0, 'denied': 0, 'otherErrors': 0}
    for c in d.calls:
        target = cov.get(c.get('check')) or shared
        target['attempted'] += 1
        status = c.get('status')
        if status and 200 <= status < 300:
            target['succeeded'] += 1
        elif status in (401, 403):
            target['denied'] += 1
        else:
            target['otherErrors'] += 1
    return cov, shared


def analyze(ws, cfg, log=print):
    d = Data(ws, cfg)
    out, inventory = Pending(), {}
    rules = build_rules(d)
    aks_rows = build_aks_rows(d, rules)
    vm_rows = build_vm_rows(d, rules)
    key_rows = build_key_rows(d, rules)
    cov_type = coverage_by_type(key_rows, aks_rows, vm_rows)
    inventory.update(aks=aks_rows, vmsNonAks=vm_rows, monitoringCoverageByType=cov_type,
                     keyResources=[{k: v for k, v in r.items() if k not in ('id', 'tags')} for r in key_rows],
                     azureMonitorWorkspaces=[{'name': m['name'], 'subscriptionName': d.subname(m['subscriptionId']), 'resourceGroup': m['resourceGroup']}
                                             for m in d.mon if m['type'] == 'microsoft.monitor/accounts'],
                     managedGrafana=[{'name': g['name'], 'subscriptionName': d.subname(g['subscriptionId']),
                                      'linkedAzureMonitorWorkspaces': [short(x.get('azureMonitorWorkspaceResourceId')) for x in (g.get('grafanaAmw') or [])]}
                                     for g in d.mon if g['type'] == 'microsoft.dashboard/grafana'])

    monitoring.check_aks(d, out, aks_rows, rules)
    fired = monitoring.fired_alerts(d, inventory)
    monitoring.check_alert_noise(d, out, fired, rules, aks_rows)
    monitoring.check_data_resources(d, out, key_rows, aks_rows)
    monitoring.check_edge(d, out, key_rows)
    monitoring.check_vms(d, out, vm_rows, cov_type)
    monitoring.check_storage(d, out, key_rows)
    monitoring.check_service_health(d, out, rules, inventory)
    monitoring.check_certificates(d, out, rules, related_certificate(ws))
    monitoring.check_stale(d, out, rules, aks_rows)
    monitoring.check_logs(d, out, key_rows, aks_rows, inventory)
    change.check_upgrades(d, out, aks_rows, inventory)
    change.check_drift(d, out, aks_rows, inventory)
    change.check_iac(d, out, inventory)
    change.check_failed(d, out, inventory)
    governance.check_tags(d, out, inventory)
    locks = governance.check_locks(d, out, d.aks)
    governance.check_management_groups(d, out, inventory, locks)
    governance.check_read_access(d, out, inventory)
    governance.check_budgets(d, out, inventory)
    governance.check_advisor(d, out, inventory)

    findings = Findings('operations')
    out.into(findings)
    cov, shared = coverage(d)
    _notes(cov, d, vm_rows, inventory)
    limitations = ['只读巡检，未执行任何变更；未使用 kubectl，集群内自建监控只能从持久卷和节点池名称推断，未验证其告警配置。',
                   '“告警覆盖”只统计 Azure Monitor 规则（指标、日志查询、活动日志、Prometheus 告警），不含第三方监控平台。',
                   '缺失数据记为 null 并附原因，不按“正常”处理。']
    if d.disabled:
        limitations.append(f'{len(d.disabled)} 个未启用订阅不可读，未纳入。')
    limitations += [f'未取得{m}，相关检查未评估。' for m in d.missing]
    scope = {'subscriptionsTotal': len(d.subs), 'subscriptionsEnabled': len(d.enabled),
             'subscriptionsInspected': [s['name'] for s in d.enabled],
             'notInspected': [{'name': s['name'], 'reason': '订阅未启用，Resource Graph/ARM 不可读'} for s in d.disabled],
             'prodSubscriptionsInferred': sorted(s['name'] for s in d.enabled if d.sub_env(s['name'])['value'] == 'prod'),
             'environmentInference': '按 customer.yaml 的环境规则推断：先看 environment 标签，再看资源名和订阅名。'}
    data = findings.write(ws, window=d.window, coverage=cov, scope=scope, inventory=inventory, limitations=limitations,
                          extra={'sharedResourceGraphCalls': shared})
    sev = collections.Counter(f['severity'] for f in data['findings'])
    log(f"卓越运营：{len(data['findings'])} 条问题（高 {sev['高']}、中 {sev['中']}、低 {sev['低']}）")
    return data


def _notes(cov, d, vm_rows, inventory):
    cov['O1']['notes'] += [f'AKS 监控属性来自 Resource Graph 和安全检查已采集的集群 GET/诊断设置；{len(vm_rows)} 台非 AKS 虚拟机逐台读取 DCR 关联；'
                           f'{len(d.diag)} 个关键资源读取诊断设置。', '数据库/缓存的平台指标默认可用，本检查只看诊断日志和告警。']
    cov['O2']['notes'] += [f'告警规则来自 Resource Graph（{len(d.alertrules)} 条规则、{len(d.ags)} 个操作组；操作组只读取接收人类型计数，未读取地址）。']
    cov['O3']['notes'] += ['工作区保留期/上限来自 Resource Graph，表级保留期逐工作区读取；未执行 Log Analytics 查询，用量与来源复用成本巡检 logs.json。']
    cov['O4']['notes'] += ['AKS 维护配置复用安全检查原始数据；AKS 操作记录为近 90 天活动日志（按订阅和 resourceProvider 过滤）。',
                           '虚拟机补丁与 Update Manager 由安全检查 S-I8 覆盖。']
    cov['O5']['notes'] += [f'{len(d.deps)} 个资源组和 {len(d.subreads)} 个订阅的部署历史；基础设施代码判断基于标签与状态存储账户，属推断。']
    cov['O6']['notes'] += ['失败操作复用可靠性检查的活动日志；当前 Failed 状态资源来自 Resource Graph。']
    cov['O7']['notes'] += ['标签统计基于 Resource Graph 全量资源（共享 Resource Graph 调用）。']
    gaps = inventory.get('readAccessGaps') or []
    cov['O8']['notes'] += ['资源锁、策略分配、合规汇总（POST summarize，只读）逐订阅读取；管理组结构读取。',
                           '性能检查读取指标时的 403：' + ('、'.join(f"{g['subscriptionName']}({g['check']})" for g in gaps) or '无')]
    cov['O9']['notes'] += ['复用成本巡检的预算读取结果，未新增调用。']
    cov['O10']['notes'] += ['复用可靠性检查的 Advisor 建议（全部类别），未新增调用。']
