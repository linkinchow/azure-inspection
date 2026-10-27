"""Reliability (R1-R12): offline analysis of raw/waf/reliability -> findings/waf/reliability.json. No network calls."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from ..common import Findings, Raw, coverage_entry, enabled, env, load_scope, mixed_env

CHECKS = [f'R{i}' for i in range(1, 13)]
SEV_ORDER = {'高': 0, '中': 1, '低': 2}
NONPROD = ('test', 'dev')
SUBNET = 'Microsoft.Network/virtualNetworks/subnets'
POOL = 'Microsoft.ContainerService/managedClusters/agentPools'
CLUSTER = 'Microsoft.ContainerService/managedClusters'
VM = 'Microsoft.Compute/virtualMachines'
# Names that usually mean a VM holds data (in addition to a large data disk). Generic service words only.
STATEFUL_RE = re.compile(r'(bigdata|clickhouse|mysql|postgres|mongo|redis|elastic|kafka|starrocks|hadoop|minio|gitlab|'
                         r'database|-db\d|sql|oracle|cassandra|hbase|hdfs|nfs|fileserver|backup|kms|pki)', re.I)
ADVISOR_RETIREMENTS = {
    'Migrate from DSv3, Dv3, ESv3, Ev3 series virtual machines.': ('Dv3/DSv3/Ev3/ESv3 系列虚拟机将退役', '在退役日期前把这些虚拟机改为 Dv5/Dsv6 等新一代规格（需重启）。'),
    'Migrate Standard HDD OS Disks to SSD': ('标准 HDD 操作系统盘将退役', '把系统盘转换为标准 SSD 或高级 SSD（需停机转换）。'),
    'Support for TLS 1.0 and TLS 1.1 in Azure storage accounts is ending': ('存储账户 TLS 1.0/1.1 支持已结束', '把存储账户最低 TLS 版本设为 1.2，并确认客户端支持 TLS 1.2。'),
    'Migrate to Ubuntu 24.04 or later versions': ('AKS 节点 Ubuntu 22.04 需迁移到 24.04', '升级 Kubernetes 前把节点池 OS 切换到 Ubuntu 24.04（或 AzureLinux），先在测试集群验证。'),
}


def sid_of(rid):
    m = re.search(r'/subscriptions/([^/]+)', rid or '', re.I)
    return m.group(1).lower() if m else None


def rg_of(rid):
    m = re.search(r'/resourceGroups/([^/]+)', rid or '', re.I)
    return m.group(1) if m else None


def member(name, rtype, sub):
    return {'name': name, 'type': rtype, 'subscription': sub}


def nonprod(e):
    return e['value'] in NONPROD


def prodlike(e):
    return e['value'] in ('prod', 'dr')


class _Run:
    """State of one analysis run: raw data, scope, findings, coverage and inventory."""

    def __init__(self, ws, cfg):
        self.cfg, self.raw = cfg, Raw(ws, 'reliability')
        manifest = self.raw.load('manifest.json') or {}
        self.window = manifest.get('window') or {}
        self.now = datetime.fromisoformat((self.window.get('end') or '').replace('Z', '+00:00')) if self.window.get('end') else datetime.now(timezone.utc)
        self.subs = load_scope(ws)
        self.subname_map = {s['id'].lower(): s['name'] for s in self.subs}
        self.enabled = enabled(self.subs)
        self.findings = Findings('reliability')
        self.coverage = {c: coverage_entry() for c in CHECKS}
        self.inventory = {}
        self.calls = (self.raw.load('index.json') or {}).get('calls') or []
        self.clusters = [e for e in (self.raw.load('aks/clusters.json') or []) if 'cluster' in e]
        # Optional customer-specific name pattern for VMs that hold data (customer.yaml, when supported by the config)
        extra = getattr(cfg, 'stateful_vm_names', None)
        self.stateful = re.compile(f'{STATEFUL_RE.pattern}|{extra}', re.I) if extra else STATEFUL_RE
        self.vnets = self.raw.load('aks/vnets.json') or {}
        self.vnet_usage = self.raw.load('aks/vnet-usages.json') or {}

    # -------------------------------------------------------------- helpers
    def rows(self, name):
        return (self.raw.load(f'arg/{name}.json') or {}).get('rows') or []

    def subname(self, rid_or_sid):
        s = rid_or_sid.lower() if '/' not in rid_or_sid else sid_of(rid_or_sid)
        return self.subname_map.get(s, s)

    def env(self, sub_name, name=None, tags=None, rg=None):
        """Tags, then resource name, then resource group, then subscription name."""
        e = env(self.cfg, '', name or '', tags)
        if e['value'] == 'unknown' and rg:
            e = env(self.cfg, '', rg)
            if e['value'] != 'unknown':
                e['basis'] = '资源组名称'
        if e['value'] == 'unknown':
            e = env(self.cfg, sub_name or '')
        return e

    def cluster_env(self, cl):
        return self.env(self.subname(cl['id']), cl['name'], cl.get('tags'), cl['properties'].get('nodeResourceGroup'))

    def add(self, check, sev, rid_or_sub, rtype, name, environment, finding, evidence, rec, confirm=None, rg=None, sub=None,
            members=None, key=None):
        sub = sub or (self.subname(rid_or_sub) if rid_or_sub else None)
        rid = rid_or_sub if rid_or_sub and '/' in rid_or_sub else None
        if members is None and name:
            members = [member(name, rtype, sub)]
        return self.findings.add(check, sev, finding, rec, subscription=sub, resource_group=rg if rg is not None else rg_of(rid_or_sub or ''),
                                 resource_name=name, resource_type=rtype, resource_id=rid, environment=environment, evidence=evidence,
                                 needs_confirmation=confirm, members=members, key=key)

    def cover(self, prefixes, check):
        """Coverage of a check from the saved call records."""
        sel = [c for c in self.calls if any(c['check'] == p or c['check'].startswith(p + '-') for p in prefixes)]
        cv = self.coverage[check]
        cv['attempted'] += len(sel)
        cv['succeeded'] += sum(1 for c in sel if c['status'] == 200)
        cv['denied'] += sum(1 for c in sel if c['status'] in (401, 403))
        other = Counter((c['status'], (c['error'] or '')[:80]) for c in sel if c['status'] not in (200, 401, 403))
        cv['otherErrors'] += sum(other.values())
        for (st, er), n in other.items():
            cv['notes'].append(f'{n} calls HTTP {st}: {er}')

    # -------------------------------------------------------------- AKS helpers
    @staticmethod
    def pool_vmss(entry, pool_name):
        for v in (entry.get('nodeVmss') or {}).get('items') or []:
            if (v.get('tags') or {}).get('aks-managed-poolName') == pool_name or v['name'].startswith(f'aks-{pool_name}-'):
                return v
        return None

    def pool_actual_nodes(self, entry, pool):
        p = pool['properties']
        if p.get('type') == 'VirtualMachines':
            return sum(x.get('count') or 0 for x in p.get('virtualMachineNodesStatus') or []), 'virtualMachineNodesStatus'
        v = self.pool_vmss(entry, pool['name'])
        if not v:
            return None, 'vmss not found'
        insts = (entry.get('nodeVmssInstances') or {}).get(v['name'], {}).get('items')
        return (len(insts) if insts is not None else v['sku']['capacity']), f"vmss {v['name']} capacity={v['sku']['capacity']}"

    def pool_ips_per_node(self, entry, pool):
        p = pool['properties']
        if p.get('podSubnetID'):
            return 1, 'pod subnet in use: node subnet holds 1 IP per node'
        v = self.pool_vmss(entry, pool['name'])
        if v:
            nics = (entry.get('nodeVmssNics') or {}).get(v['name'], {}).get('items') or []
            counts = [len(n['properties'].get('ipConfigurations') or []) for n in nics]
            if counts:
                return Counter(counts).most_common(1)[0][0], f'observed from {len(counts)} node NICs (ipConfigurations per NIC: {sorted(set(counts))})'
        mp = p.get('maxPods') or 30
        return mp - 1, f'no running node; estimated as maxPods-1={mp - 1}'

    @staticmethod
    def surge_nodes(pool):
        p = pool['properties']
        ms = ((p.get('upgradeSettings') or {}).get('maxSurge') or '10%').strip()
        cnt = p.get('count') or 0
        if p.get('type') == 'VirtualMachines':
            cnt = sum(x.get('count') or 0 for x in p.get('virtualMachineNodesStatus') or [])
        if ms.endswith('%'):
            return max(1, math.ceil(cnt * float(ms[:-1]) / 100.0)), ms
        try:
            return max(1, int(ms)), ms
        except ValueError:
            return 1, ms

    def subnet_info(self, subnet_id):
        vid, name = subnet_id.split('/subnets/')[0], subnet_id.split('/subnets/')[1]
        sn = next((s for s in (self.vnets.get(vid) or {}).get('subnets', []) if s['name'].lower() == name.lower()), None)
        usage = next((u for u in (self.vnet_usage.get(vid) or {}).get('items') or [] if u['id'].lower().endswith('/subnets/' + name.lower())), None)
        prefix = (sn.get('addressPrefix') or (sn.get('addressPrefixes') or [None])[0]) if sn else None
        usable = ipaddress.ip_network(prefix).num_addresses - 5 if prefix else None
        used = usage['currentValue'] if usage else (sn or {}).get('ipConfigurationCount')
        return {'subnet': name, 'vnet': vid.split('/')[-1], 'prefix': prefix, 'usable': usable, 'usageApiLimit': usage['limit'] if usage else None,
                'used': used, 'ipConfigurationCount': (sn or {}).get('ipConfigurationCount'),
                'free': (usable - used) if (usable is not None and used is not None) else None,
                'natGateway': ((sn or {}).get('natGateway') or {}).get('id', '').split('/')[-1] or None}

    def cluster_by_name(self, name):
        return next(e['cluster'] for e in self.clusters if e['cluster']['name'] == name)


# ====================================================================== R1 AKS network capacity
def r1(run):
    run.cover(['R1', 'R1-R2', 'R1-R9'], 'R1')
    subnets, podsubnets = defaultdict(list), defaultdict(list)
    for e in run.clusters:
        cl = e['cluster']
        for pool in e.get('agentPools') or []:
            p = pool['properties']
            actual, basis = run.pool_actual_nodes(e, pool)
            ipn, ipbasis = run.pool_ips_per_node(e, pool)
            auto = bool(p.get('enableAutoScaling'))
            desired = p.get('count') if p.get('type') != 'VirtualMachines' else actual
            target_max = p.get('maxCount') if auto else desired
            sn, sm = run.surge_nodes(pool)
            rec = {'cluster': cl['name'], 'clusterId': cl['id'], 'pool': pool['name'], 'mode': p.get('mode'),
                   'vmSize': p.get('vmSize') or (((p.get('virtualMachinesProfile') or {}).get('scale') or {}).get('manual') or [{}])[0].get('size'),
                   'maxPods': p.get('maxPods'), 'desiredCount': desired, 'actualNodes': actual, 'actualBasis': basis,
                   'autoscale': auto, 'minCount': p.get('minCount'), 'maxCount': p.get('maxCount'), 'ipsPerNode': ipn, 'ipsPerNodeBasis': ipbasis,
                   'ipsToReachDesired': max(0, (desired or 0) - (actual or 0)) * ipn,
                   'ipsToReachMax': max(0, (target_max or 0) - (actual or 0)) * ipn,
                   'maxSurge': sm, 'surgeNodes': sn, 'ipsForUpgradeSurge': sn * ipn,
                   'podSubnet': (p.get('podSubnetID') or '').split('/subnets/')[-1] or None}
            subnets[p.get('vnetSubnetID')].append(rec)
            if p.get('podSubnetID'):
                podsubnets[p['podSubnetID']].append(rec)
    inv = []
    for sid, pools in subnets.items():
        info = run.subnet_info(sid)
        need_desired = sum(x['ipsToReachDesired'] for x in pools)
        need_max = sum(x['ipsToReachMax'] for x in pools)
        need_surge = max(x['ipsForUpgradeSurge'] for x in pools)
        clusters = sorted({x['cluster'] for x in pools})
        inv.append(dict(info, subnetId=sid, clusters=clusters, pools=pools, ipsNeededToReachDesired=need_desired,
                        ipsNeededToReachAllMaxCount=need_max, ipsNeededForLargestUpgradeSurge=need_surge))
        free = info['free']
        if free is None:
            run.coverage['R1']['notes'].append(f'{sid}: subnet size/usage unknown')
            continue
        blocked_surge = [x for x in pools if x['ipsForUpgradeSurge'] > free]
        blocked_desired = [x for x in pools if x['ipsToReachDesired'] > 0 and x['ipsToReachDesired'] > free]
        blocked_max = [x for x in pools if x['ipsToReachMax'] > free]
        e = run.cluster_env(run.cluster_by_name(clusters[0]))
        name = f"{info['vnet']}/{info['subnet']}"
        ev = {'subnet': name, 'prefix': info['prefix'], 'usableIPs': info['usable'], 'usedIPs': info['used'], 'freeIPs': free,
              'ipsNeededToReachDesired': need_desired, 'ipsNeededToReachAllMaxCount': need_max, 'ipsNeededForLargestUpgradeSurge': need_surge,
              'pools': [{k: x[k] for k in ('cluster', 'pool', 'mode', 'maxPods', 'desiredCount', 'actualNodes', 'minCount', 'maxCount',
                                           'ipsPerNode', 'ipsToReachMax', 'surgeNodes', 'ipsForUpgradeSurge')} for x in pools],
              'envBasis': e['basis']}
        if blocked_surge or blocked_desired:
            names = ', '.join(sorted({f"{x['cluster']}/{x['pool']}" for x in blocked_surge + blocked_desired}))
            run.add('R1', '高', sid, SUBNET, name, e,
                    f"子网 {info['subnet']}（{info['prefix']}，可用 {info['usable']} 个 IP）已用 {info['used']} 个、只剩 {free} 个，"
                    f"不够节点池 {names} 新增 1 个节点或做 1 个升级缓冲节点（单节点需 {max(x['ipsPerNode'] for x in blocked_surge + blocked_desired)} 个 IP），扩容和升级会失败；"
                    f'全部节点池扩到上限共需 {need_max} 个 IP。',
                    ev, '尽快给集群换用更大的节点子网或改用 Azure CNI Overlay / 独立 Pod 子网（不再按 maxPods 为每个节点预占 IP）；短期可降低新节点池的 maxPods、或把部分负载迁到其他节点池以腾出 IP。所有改动需在变更窗口内由客户执行。',
                    '确认集群是否为生产集群，以及近期是否计划扩容或升级 Kubernetes 版本。')
        elif blocked_max:
            names = ', '.join(f"{x['cluster']}/{x['pool']}（需 {x['ipsToReachMax']}）" for x in blocked_max)
            run.add('R1', '中', sid, SUBNET, name, e,
                    f"子网 {info['subnet']}（{info['prefix']}，可用 {info['usable']} 个 IP）剩余 {free} 个，自动扩缩容扩到上限共需 {need_max} 个 IP，节点池 {names} 无法扩到 maxCount；升级缓冲节点（最多需 {need_surge} 个）目前还放得下。",
                    ev, '把节点池 maxCount 调到子网实际能容纳的数量，避免自动扩容时反复失败；长期规划更大的子网或改用 Azure CNI Overlay。',
                    '确认业务高峰是否真的需要扩到当前 maxCount。')
    pod_inv = []
    for sid, pools in podsubnets.items():
        info = run.subnet_info(sid)
        worst_now = sum((x['actualNodes'] or 0) * (x['maxPods'] or 0) for x in pools)
        worst_max = sum(max(x['actualNodes'] or 0, (x['maxCount'] or x['desiredCount'] or 0)) * (x['maxPods'] or 0) for x in pools)
        pod_inv.append(dict(info, subnetId=sid, clusters=sorted({x['cluster'] for x in pools}), reportedUsed=info['used'],
                            note='Azure CNI 动态 Pod IP 分配不在 ARM 子网用量中显示（报告值为 0），用 节点数×maxPods 作为最坏情况估算',
                            worstCasePodIPsNow=worst_now, worstCasePodIPsAtMax=worst_max,
                            fitsWorstCaseAtMax=(info['usable'] is not None and worst_max <= info['usable'])))
        if info['usable'] is not None and worst_max > info['usable']:
            e = run.cluster_env(run.cluster_by_name(pools[0]['cluster']))
            run.add('R1', '低', sid, SUBNET, f"{info['vnet']}/{info['subnet']}", e,
                    f"Pod 子网 {info['subnet']}（{info['prefix']}，可用 {info['usable']} 个 IP）在最坏情况下（节点扩到上限且每节点 Pod 数达到 maxPods）需要 {worst_max} 个 IP，超过子网容量。",
                    {'podSubnet': info, 'worstCaseAtMax': worst_max}, '实际 Pod IP 按需分配，短期风险低；扩容前在 Azure 门户核对 Pod 子网实际分配量。',
                    '确认 Pod 子网实际已分配 IP 数。')
    run.inventory['R1'] = {'nodeSubnets': inv, 'podSubnets': pod_inv}
    run.coverage['R1']['notes'].append('Node-subnet usage from VNet usages API (matches subnet ipConfigurations). Pod-subnet usage for dynamic Azure CNI is not exposed via ARM; worst-case estimated.')


# ====================================================================== R2 system node pools
def r2(run):
    run.cover(['R1-R2', 'R2'], 'R2')
    inv = []
    for e in run.clusters:
        cl = e['cluster']
        ce = run.cluster_env(cl)
        sys_pools = [p for p in e.get('agentPools') or [] if p['properties'].get('mode') == 'System']
        total_actual = 0
        for pool in sys_pools:
            p = pool['properties']
            actual, _ = run.pool_actual_nodes(e, pool)
            total_actual += actual or 0
            v = run.pool_vmss(e, pool['name'])
            inst = (e.get('nodeVmssInstances') or {}).get(v['name'], {}).get('items') if v else None
            row = {'cluster': cl['name'], 'pool': pool['name'], 'count': p.get('count'), 'actualNodes': actual,
                   'vmssCapacity': v['sku']['capacity'] if v else None, 'autoscale': p.get('enableAutoScaling'),
                   'minCount': p.get('minCount'), 'maxCount': p.get('maxCount'), 'zonesConfigured': p.get('availabilityZones'),
                   'zonesOfRunningNodes': sorted({z for i in inst or [] for z in (i.get('zones') or [])}), 'vmSize': p.get('vmSize'),
                   'env': ce['value'], 'envBasis': ce['basis']}
            inv.append(row)
            if actual == 0 or (actual is not None and p.get('count') is not None and actual < p.get('count')):
                run.add('R2', '高', cl['id'], POOL, f"{cl['name']}/{pool['name']}", ce,
                        f"系统节点池 {pool['name']} 配置节点数为 {p.get('count')}，但对应 VMSS 实际只有 {actual} 台节点（VMSS 容量 {row['vmssCapacity']}），系统组件（CoreDNS、metrics-server 等）只能挤在用户节点池上或无法调度。",
                        row, '先解决节点子网 IP 不足（见 R1），让系统节点池至少恢复到 2 台、分布在不同可用区；恢复后在系统节点池保留 CriticalAddonsOnly 污点，避免业务 Pod 挤占。',
                        '确认系统 Pod 当前运行在哪些节点上，以及是否有人为把系统池缩到 0。', key=f"{cl['id']}/{pool['name']}")
        if sys_pools and 0 < total_actual < 2:
            names = ', '.join(p['name'] for p in sys_pools)
            run.add('R2', '低' if nonprod(ce) else '中', cl['id'], POOL, f"{cl['name']}/{names}", ce,
                    f"集群 {cl['name']} 的系统节点池只有 {total_actual} 台节点，这台节点重启、升级或故障时 CoreDNS 等系统组件会中断。",
                    {'systemPools': [r for r in inv if r['cluster'] == cl['name']], 'envBasis': ce['basis']},
                    '把系统节点池调整为至少 2 台（生产建议 3 台、跨 3 个可用区），可开启自动扩缩容并设置 minCount≥2。',
                    '确认该集群是否承载生产业务。' if ce['value'] == 'unknown' else None,
                    members=[member(f"{cl['name']}/{p['name']}", POOL, run.subname(cl['id'])) for p in sys_pools], key=f"{cl['id']}|system-pool-size")
    run.inventory['R2'] = inv


# ====================================================================== R3 availability zones
def r3(run):
    types = ('aks', 'vms', 'mysql', 'postgres', 'redis', 'redisenterprise', 'mongoclusters', 'appgw', 'lbs', 'pips', 'natgw', 'vnetgw')
    ok = len([x for x in types if (run.raw.load(f'arg/{x}.json') or {}).get('status') == 200])
    run.coverage['R3'].update(attempted=len(types), succeeded=ok)
    run.coverage['R3']['notes'].append('Resource Graph queries (one per resource type) + ARM AKS agentPools; counted per query.')
    inv = {'aksPools': [], 'vms': [], 'appgw': [], 'natgw': [], 'publicIpsNoZone': {}, 'gateways': []}
    for e in run.clusters:
        cl = e['cluster']
        ce = run.cluster_env(cl)
        nozone, pools = [], []
        for pool in e.get('agentPools') or []:
            p = pool['properties']
            actual, _ = run.pool_actual_nodes(e, pool)
            z = p.get('availabilityZones') or []
            inv['aksPools'].append({'cluster': cl['name'], 'pool': pool['name'], 'mode': p.get('mode'), 'zones': z, 'actualNodes': actual})
            if len(z) < 2 and (actual or 0) >= 1:
                nozone.append(f"{pool['name']}({actual}台,zones={z or '无'})")
                pools.append(member(f"{cl['name']}/{pool['name']}", POOL, run.subname(cl['id'])))
        if nozone:
            run.add('R3', '低' if nonprod(ce) else '中', cl['id'], POOL, cl['name'], ce,
                    f"集群 {cl['name']} 有 {len(nozone)} 个节点池没有跨可用区部署：{', '.join(nozone)}，单个可用区故障时这些池的节点会同时不可用。",
                    {'poolsWithoutZoneRedundancy': nozone, 'envBasis': ce['basis']},
                    '新建跨 1/2/3 可用区的节点池并迁移工作负载后删除旧池（节点池的可用区创建后不能修改）；有状态负载需同时确认磁盘为 ZRS 或应用自带多副本。',
                    None if nonprod(ce) else '确认这些节点池上的工作负载是否有多副本，以及区域故障时可接受的影响。', members=pools, key=f"{cl['id']}|pool-zones")
    by_sub = defaultdict(list)
    for r in run.rows('vms'):
        if (r['resourceGroup'] or '').lower().startswith('mc_'):
            continue
        p = r['properties']
        ps = ((p.get('extended') or {}).get('instanceView') or {}).get('powerState', {}).get('code', '').replace('PowerState/', '')
        ve = run.env(run.subname(r['id']), r['name'], r.get('tags'), r['resourceGroup'])
        row = {'name': r['name'], 'sub': run.subname(r['id']), 'rg': r['resourceGroup'], 'zones': r.get('zones'), 'power': ps, 'env': ve['value']}
        inv['vms'].append(row)
        if not r.get('zones') and not nonprod(ve) and ps == 'running':
            by_sub[row['sub']].append((row, ve))
    for s, lst in by_sub.items():
        run.add('R3', '低', None, VM, ', '.join(x['name'] for x, _ in lst), mixed_env([ve for _, ve in lst]),
                f'订阅 {s} 有 {len(lst)} 台运行中的虚拟机没有指定可用区（区域型部署），同类多台机器无法保证分布在不同可用区。',
                {'vms': [x for x, _ in lst]}, '对需要多台冗余的服务（调度、DNS、大数据节点等）在重建或扩容时按可用区 1/2/3 分开部署；单台服务器指定可用区本身不提升可用性，应结合多实例。',
                '确认这些服务器中哪些需要高可用。', sub=s, rg=None, members=[member(x['name'], VM, s) for x, _ in lst], key='vm-no-zone')
    for r in run.rows('appgw'):
        p = r['properties']
        ae = run.env(run.subname(r['id']), r['name'], r.get('tags'), r['resourceGroup'])
        auto, cap = p.get('autoscaleConfiguration'), (p.get('sku') or {}).get('capacity')
        row = {'name': r['name'], 'sku': (p.get('sku') or {}).get('name'), 'capacity': cap, 'autoscale': auto, 'zones': r.get('zones'),
               'env': ae['value'], 'envBasis': ae['basis']}
        inv['appgw'].append(row)
        min_inst = (auto or {}).get('minCapacity') if auto else cap
        if (min_inst or 0) < 2:
            run.add('R3', '低' if nonprod(ae) else '中', r['id'], 'Microsoft.Network/applicationGateways', r['name'], ae,
                    f"应用网关 {r['name']}（{row['sku']}）固定只有 {cap} 个实例、未开启自动扩缩容，也未显式配置可用区，实例维护或故障时会中断。",
                    row, '把实例数下限调到至少 2（建议开启自动扩缩容，最小 2），并在支持的区域使用跨可用区部署。',
                    '确认该应用网关是否承载生产流量。' if ae['value'] == 'unknown' else None)
        elif not r.get('zones'):
            run.add('R3', '低', r['id'], 'Microsoft.Network/applicationGateways', r['name'], ae,
                    f"应用网关 {r['name']} 有 {min_inst} 个实例，但资源上没有显示可用区配置。",
                    row, '在 Azure 门户确认该网关是否为跨可用区部署；如不是，计划在下次重建时选择可用区 1/2/3。', '确认该网关的可用区设置。')
    for r in run.rows('natgw'):
        ne = run.env(run.subname(r['id']), r['name'], r.get('tags'), r['resourceGroup'])
        row = {'name': r['name'], 'sku': (r.get('sku') or {}).get('name'), 'zones': r.get('zones'),
               'subnets': [s['id'].split('/')[-1] for s in r['properties'].get('subnets') or []], 'env': ne['value']}
        inv['natgw'].append(row)
        if (not r.get('zones') or len(r['zones']) < 2) and not nonprod(ne) and row['subnets']:
            run.add('R3', '低', r['id'], 'Microsoft.Network/natGateways', r['name'], ne,
                    f"NAT 网关 {r['name']}（{row['sku']}，可用区：{r.get('zones') or '未指定'}）为 {len(row['subnets'])} 个子网提供出站，它所在的可用区故障时这些子网的出站会中断。",
                    row, '评估使用 StandardV2（区域冗余）NAT 网关替换，或按可用区拆分出站方案；Azure Advisor 也给出了同样建议。')
    no_zone = defaultdict(int)
    for r in run.rows('pips'):
        if not r.get('zones'):
            no_zone[run.subname(r['id'])] += 1
    inv['publicIpsNoZone'] = dict(no_zone)
    inv['publicIpSku'] = dict(Counter((r.get('sku') or {}).get('name') for r in run.rows('pips')))
    inv['loadBalancerSku'] = dict(Counter((r.get('sku') or {}).get('name') for r in run.rows('lbs')))
    for r in run.rows('vnetgw'):
        inv['gateways'].append({'name': r['name'], 'type': r['type'], 'sku': (r.get('sku') or r['properties'].get('sku') or {}).get('name'), 'zones': r.get('zones')})
    run.inventory['R3'] = inv


# ====================================================================== R4 control plane tier
def r4(run):
    run.coverage['R4'].update(attempted=len(run.clusters), succeeded=len(run.clusters))
    inv = []
    for e in run.clusters:
        cl = e['cluster']
        ce = run.cluster_env(cl)
        tier = (cl.get('sku') or {}).get('tier')
        inv.append({'cluster': cl['name'], 'tier': tier, 'env': ce['value'], 'envBasis': ce['basis']})
        if tier == 'Free' and not nonprod(ce):
            run.add('R4', '中', cl['id'], CLUSTER, cl['name'], ce,
                    f"集群 {cl['name']} 控制平面为 Free 层，没有 SLA（Standard 层提供 99.95% 可用区 SLA），API Server 也没有为大规模集群放大的资源。",
                    {'tier': tier, 'envBasis': ce['basis'], 'kubernetesVersion': cl['properties'].get('kubernetesVersion')},
                    '把生产集群升级到 Standard 层（可在线切换，不重建集群，按集群小时计费）。',
                    None if prodlike(ce) else '确认该集群是否为生产集群。')
    run.inventory['R4'] = inv


# ====================================================================== R5 databases and caches
def r5(run):
    run.cover(['R5'], 'R5')
    run.coverage['R5']['notes'].append('MySQL/PG HA/backup from Resource Graph + ARM GET; AMR clusters/databases and Mongo vCore via ARM GET.')
    inv = {'mysql': [], 'postgres': [], 'redis': [], 'amr': [], 'mongo': []}
    geo_off = []
    for kind in ('mysql', 'postgres'):
        label = 'MySQL' if kind == 'mysql' else 'PostgreSQL'
        rtype = 'Microsoft.DBforMySQL/flexibleServers' if kind == 'mysql' else 'Microsoft.DBforPostgreSQL/flexibleServers'
        for r in run.rows(kind):
            p = r['properties']
            ha, bk = p.get('highAvailability') or {}, p.get('backup') or {}
            role = p.get('replicationRole') or (p.get('replica') or {}).get('role')
            de = run.env(run.subname(r['id']), r['name'], r.get('tags'), r['resourceGroup'])
            tier = (r.get('sku') or {}).get('tier')
            row = {'name': r['name'], 'sub': run.subname(r['id']), 'sku': (r.get('sku') or {}).get('name'), 'tier': tier,
                   'haMode': ha.get('mode'), 'haState': ha.get('state'), 'zone': p.get('availabilityZone'),
                   'standbyZone': ha.get('standbyAvailabilityZone'), 'backupRetentionDays': bk.get('backupRetentionDays'),
                   'geoRedundantBackup': bk.get('geoRedundantBackup'), 'replicationRole': role, 'env': de['value'], 'envBasis': de['basis'],
                   'state': p.get('state'), 'type': rtype}
            inv[kind].append(row)
            if (role or '').lower() == 'replica':
                continue
            if ha.get('mode') in (None, 'Disabled'):
                if prodlike(de):
                    run.add('R5', '中', r['id'], rtype, r['name'], de,
                            f"生产 {label} 主库 {r['name']}（{row['sku']}）未开启高可用，所在可用区或主机故障时需要从备份恢复，停机时间较长。",
                            row, '开启高可用（建议同区域跨可用区 ZoneRedundant）；Burstable 规格不支持高可用，需要先升级到通用型。', key=f"{r['id']}|ha")
                elif de['value'] == 'unknown':
                    run.add('R5', '低', r['id'], rtype, r['name'], de, f"{label} 服务器 {r['name']}（{row['sku']}，{tier}）未开启高可用。",
                            row, '如承载生产数据，开启跨可用区高可用（Burstable 规格需先升级到通用型）。', '确认该数据库是否为生产库。', key=f"{r['id']}|ha")
            elif ha.get('mode') == 'SameZone' and not nonprod(de):
                run.add('R5', '低', r['id'], rtype, r['name'], de,
                        f"{label} 服务器 {r['name']} 的高可用为同可用区模式（主库在可用区 {row['zone']}，备库在同一可用区），整个可用区故障时主备会同时不可用。",
                        row, '如区域支持，改为跨可用区高可用（ZoneRedundant）：需先关闭再重新开启高可用，安排在维护窗口内。',
                        None if prodlike(de) else '确认该数据库是否为生产库。', key=f"{r['id']}|ha")
            if ha.get('state') not in (None, 'Healthy', 'NotEnabled'):
                run.add('R5', '高', r['id'], rtype, r['name'], de, f"{label} 服务器 {r['name']} 高可用状态为 {ha.get('state')}，当前不能保证故障切换。",
                        row, '检查服务器高可用状态并联系 Azure 支持。', key=f"{r['id']}|ha-state")
            if (bk.get('backupRetentionDays') or 0) < 7:
                run.add('R5', '低' if nonprod(de) else '中', r['id'], rtype, r['name'], de, f"{label} 主库 {r['name']} 备份只保留 {bk.get('backupRetentionDays')} 天。",
                        row, '把备份保留期调到至少 7 天（生产建议 14–35 天）。', key=f"{r['id']}|retention")
            if (bk.get('geoRedundantBackup') or '').lower() != 'enabled' and prodlike(de):
                geo_off.append(row)
    if geo_off:
        run.add('R5', '低', None, 'Microsoft.DBforMySQL|DBforPostgreSQL/flexibleServers', ', '.join(x['name'] for x in geo_off),
                {'value': 'prod', 'label': '生产', 'basis': '见涉及资源'},
                f'{len(geo_off)} 个生产 MySQL/PostgreSQL 主库都没有开启异地冗余备份，整个 Azure 区域不可用时无法在配对区域恢复。',
                {'servers': [{k: x[k] for k in ('name', 'sub', 'sku', 'backupRetentionDays', 'geoRedundantBackup')} for x in geo_off]},
                '按业务对区域级容灾的要求选择：对关键库开启异地冗余备份（多数情况下只能在创建服务器时选择，已有服务器需要通过还原到新服务器实现），或建立跨区域只读副本。',
                '确认哪些数据库需要区域级容灾（RPO/RTO 目标）。', sub='(多个订阅)', rg=None,
                members=[member(x['name'], x['type'], x['sub']) for x in geo_off], key='db-geo-backup')
    for r in run.rows('redis'):
        p = r['properties']
        re_ = run.env(run.subname(r['id']), r['name'], r.get('tags'), r['resourceGroup'])
        sku = (p.get('sku') or {}).get('name')
        persist = {k: v for k, v in (p.get('redisConfiguration') or {}).items() if 'backup' in k or 'aof' in k or 'rdb' in k}
        row = {'name': r['name'], 'sku': sku, 'capacity': (p.get('sku') or {}).get('capacity'), 'zones': r.get('zones'),
               'zonalAllocationPolicy': p.get('zonalAllocationPolicy'), 'replicasPerMaster': p.get('replicasPerMaster'),
               'persistence': persist or None, 'env': re_['value']}
        inv['redis'].append(row)
        if sku == 'Basic':
            run.add('R5', '低' if nonprod(re_) else '中', r['id'], 'Microsoft.Cache/redis', r['name'], re_, f"Redis {r['name']} 为 Basic 层，单节点、无 SLA。",
                    row, '生产使用至少 Standard 层（主从）或迁移到 Azure Managed Redis。')
    detail = run.raw.load('db/detail.json') or {}
    for x in detail.get('redisenterprise', []):
        cl = x.get('cluster') or {}
        p = cl.get('properties') or {}
        ae = run.env(run.subname(x['id']), x['id'].split('/')[-1], cl.get('tags'), rg_of(x['id']))
        dbs = x.get('databases') or []
        pers = [((d.get('properties') or {}).get('persistence') or {}) for d in dbs]
        row = {'name': x['id'].split('/')[-1], 'sub': run.subname(x['id']), 'sku': (cl.get('sku') or {}).get('name'),
               'highAvailability': p.get('highAvailability'), 'redundancyMode': p.get('redundancyMode'), 'persistence': pers,
               'geoReplication': any((d.get('properties') or {}).get('geoReplication') for d in dbs), 'env': ae['value'], '_env': ae}
        inv['amr'].append(row)
        if p.get('highAvailability') == 'Disabled':
            run.add('R5', '低' if nonprod(ae) else '中', x['id'], 'Microsoft.Cache/redisEnterprise', row['name'], ae,
                    f"Azure Managed Redis {row['name']}（{row['sku']}）关闭了高可用（单副本，无 SLA）。", {k: v for k, v in row.items() if k != '_env'},
                    '生产实例开启高可用；测试实例可保持现状。')
    amr_noper = [r for r in inv['amr'] if prodlike(r['_env']) and not any(pp.get('aofEnabled') or pp.get('rdbEnabled') for pp in r['persistence'])]
    if amr_noper:
        run.add('R5', '低', None, 'Microsoft.Cache/redisEnterprise', ', '.join(r['name'] for r in amr_noper), {'value': 'prod', 'label': '生产', 'basis': '见涉及资源'},
                f'{len(amr_noper)} 个生产 Azure Managed Redis 实例没有开启持久化（RDB/AOF），实例整体重启或故障时缓存数据会全部丢失。',
                {'instances': [{k: r[k] for k in ('name', 'sub', 'sku', 'highAvailability', 'redundancyMode')} for r in amr_noper]},
                '如果 Redis 里存的是只能从 Redis 读到的数据（会话、队列、计数器等），开启 RDB 或 AOF 持久化；纯缓存可保持现状。',
                '确认每个实例是纯缓存还是存放了业务数据。', sub='(多个订阅)', rg=None,
                members=[member(r['name'], 'Microsoft.Cache/redisEnterprise', r['sub']) for r in amr_noper], key='amr-persistence')
    for r in inv['amr']:
        r.pop('_env', None)
    for x in detail.get('mongo', []):
        cl = x.get('cluster') or {}
        p = cl.get('properties') or {}
        name = x['id'].split('/')[-1]
        me = run.env(run.subname(x['id']), name, cl.get('tags'), rg_of(x['id']))
        ha = (p.get('highAvailability') or {}).get('targetMode')
        row = {'name': name, 'sub': run.subname(x['id']), 'tier': (p.get('compute') or {}).get('tier'), 'haTargetMode': ha,
               'storageGB': (p.get('storage') or {}).get('sizeGb'), 'earliestRestore': (p.get('backup') or {}).get('earliestRestoreTime'), 'env': me['value']}
        inv['mongo'].append(row)
        if ha in (None, 'Disabled') and not nonprod(me):
            run.add('R5', '中', x['id'], 'Microsoft.DocumentDB/mongoClusters', name, me,
                    f"生产 MongoDB（vCore）集群 {name}（{row['tier']}）未开启高可用，节点故障时数据库不可用直到恢复。",
                    row, '开启高可用（建议 ZoneRedundantPreferred），可在线开启，费用约为计算部分翻倍。')
    run.inventory['R5'] = inv


# ====================================================================== R6 storage redundancy and recovery
def r6(run):
    run.cover(['R6'], 'R6')
    blob = {x['id'].lower(): x for x in (run.raw.load('storage/blobservices.json') or [])}
    cap = {x['id'].lower(): x for x in (run.raw.load('storage/used-capacity.json') or [])}
    inv = []
    for r in run.rows('storage'):
        b = blob.get(r['id'].lower()) or {}
        bp = (b.get('blobService') or {}).get('properties') or {}
        used = (cap.get(r['id'].lower()) or {}).get('lastUsedCapacityBytes')
        se = run.env(run.subname(r['id']), r['name'], r.get('tags'), r['resourceGroup'])
        red = (r.get('sku') or {}).get('name', '').split('_')[-1]
        sd = bp.get('deleteRetentionPolicy') or {}
        read = b.get('status') == 200
        row = {'name': r['name'], 'sub': run.subname(r['id']), 'rg': r['resourceGroup'], 'kind': r.get('kind'), 'sku': (r.get('sku') or {}).get('name'),
               'redundancy': red, 'usedGiB': round(used / 2**30, 1) if used is not None else None,
               'blobSoftDelete': sd.get('enabled') if read else None, 'blobSoftDeleteDays': sd.get('days'),
               'containerSoftDelete': (bp.get('containerDeleteRetentionPolicy') or {}).get('enabled') if read else None,
               'versioning': bp.get('isVersioningEnabled') if read else None,
               'pointInTimeRestore': (bp.get('restorePolicy') or {}).get('enabled') if read else None,
               'blobServiceStatus': b.get('status'), 'blobServiceError': b.get('error'), 'hns': r['properties'].get('isHnsEnabled'),
               'env': se['value'], 'envBasis': se['basis']}
        inv.append(row)
        if not read or used is None:
            continue
        gib = used / 2**30
        no_sd = not sd.get('enabled')
        if no_sd and gib >= 100:
            sev = '中' if (red == 'LRS' and not nonprod(se)) else '低'
            run.add('R6', sev, r['id'], 'Microsoft.Storage/storageAccounts', r['name'], se,
                    f"存储账户 {r['name']} 存有约 {gib:,.0f} GiB 数据，冗余方式为 {red}，没有开启 Blob 软删除{'' if row['containerSoftDelete'] else '和容器软删除'}，误删或被覆盖后无法找回{'（异地复制会把删除同步到副本）' if red != 'LRS' else ''}。",
                    row, '开启 Blob 软删除（建议 7–14 天）和容器软删除；关键数据再考虑开启版本控制；仅有 LRS 的重要数据评估改为 ZRS。'
                    + ('（启用分层命名空间 HNS 的账户不支持版本控制，只开软删除即可。）' if row['hns'] else ''),
                    '确认该账户中数据是否可从其他来源重建。')
        elif no_sd and red == 'LRS' and gib >= 10 and not nonprod(se):
            run.add('R6', '低', r['id'], 'Microsoft.Storage/storageAccounts', r['name'], se, f"存储账户 {r['name']}（{gib:,.0f} GiB，LRS）没有开启 Blob 软删除。",
                    row, '开启 Blob 软删除和容器软删除；如为迁移遗留的临时账户，确认后清理。', '确认该账户是否仍在使用。')
    run.inventory['R6'] = inv
    run.coverage['R6']['notes'].append(f"UsedCapacity from Azure Monitor (last hourly value in the 2 days before {run.window.get('snapshot')}); "
                                       'FileStorage accounts do not support blobServices (HTTP 400 expected).')


# ====================================================================== R7 VM backup
def r7(run):
    run.cover(['R7'], 'R7')
    bk = run.raw.load('backup/vaults.json') or {}
    rs_count = sum(len(v['rs'].get('items') or []) for v in bk.get('vaultLists', {}).values())
    bv_count = sum(len(v['bv'].get('items') or []) for v in bk.get('vaultLists', {}).values())
    protected = {((it.get('properties') or {}).get('sourceResourceId') or '').lower()
                 for v in bk.get('rsVaults', []) for it in (v['protectedItems'].get('items') or [])} - {''}
    disks = {d['id'].lower(): d for d in run.rows('disks')}
    inv, by_sub = [], defaultdict(list)
    for r in run.rows('vms'):
        if (r['resourceGroup'] or '').lower().startswith('mc_'):
            continue
        p = r['properties']
        dd = (p.get('storageProfile') or {}).get('dataDisks') or []
        dsize = sum((d.get('diskSizeGB') or (disks.get(((d.get('managedDisk') or {}).get('id') or '').lower()) or {}).get('diskSizeGB') or 0) for d in dd)
        ps = ((p.get('extended') or {}).get('instanceView') or {}).get('powerState', {}).get('code', '').replace('PowerState/', '')
        ve = run.env(run.subname(r['id']), r['name'], r.get('tags'), r['resourceGroup'])
        row = {'name': r['name'], 'sub': run.subname(r['id']), 'rg': r['resourceGroup'], 'size': (p.get('hardwareProfile') or {}).get('vmSize'),
               'dataDisks': len(dd), 'dataDiskGB': dsize, 'power': ps, 'protected': r['id'].lower() in protected,
               'statefulHeuristic': bool(run.stateful.search(r['name'])) or dsize >= 128, 'env': ve['value'], 'envBasis': ve['basis']}
        inv.append(row)
        if not row['protected'] and row['statefulHeuristic'] and not nonprod(ve):
            by_sub[row['sub']].append((row, ve))
    sub_ids = {s['name']: s['id'] for s in run.enabled}
    for s, lst in sorted(by_sub.items()):
        total = sum(x['dataDiskGB'] for x, _ in lst)
        vaults = (bk.get('vaultLists', {}).get(sub_ids.get(s, ''), {}).get('rs', {}).get('items')) or []
        run.add('R7', '中', None, VM, ', '.join(x['name'] for x, _ in lst), mixed_env([ve for _, ve in lst]),
                f'订阅 {s} 有 {len(lst)} 台看起来存有数据的虚拟机（名称显示为数据类服务或数据盘较大，数据盘合计 {total:,} GB）没有任何 Azure 备份，磁盘损坏、误删或勒索时无法恢复。',
                {'vms': [{k: x[k] for k in ('name', 'size', 'dataDisks', 'dataDiskGB', 'power', 'env')} for x, _ in lst],
                 'recoveryServicesVaultsInSubscription': len(vaults)},
                '为这些服务器创建恢复服务保管库并开启 Azure 虚拟机备份（每日备份、保留 7–30 天），或至少对数据盘做定期快照；数据库类服务优先使用应用自身的备份。',
                '确认这些服务器上的数据是否已有应用层备份（如数据库或大数据集群自带副本或导出），以及是否为生产。', sub=s, rg=None,
                members=[member(x['name'], VM, s) for x, _ in lst], key='vm-backup')
    run.inventory['R7'] = {'recoveryServicesVaults': rs_count, 'backupVaults': bv_count, 'protectedItems': len(protected), 'nonAksVms': len(inv), 'vms': inv,
                           'note': f'{len(run.enabled)} 个可读订阅中发现 {rs_count} 个恢复服务保管库、{bv_count} 个备份保管库；AKS 节点（MC_ 资源组）不在此统计。'}
    run.coverage['R7']['notes'].append(f'Vault lists: {rs_count} Recovery Services vaults, {bv_count} Backup vaults, {len(protected)} protected items.')


# ====================================================================== R8 outbound connectivity
def metric_series(block):
    out = []
    for v in ((block or {}).get('data') or {}).get('value', []):
        for ts in v.get('timeseries', []):
            md = {mv['name']['value']: mv['value'] for mv in ts.get('metadatavalues', [])}
            out.append((v['name']['value'], md, ts.get('data', [])))
    return out


def _states(block):
    states = defaultdict(float)
    for _, md, pts in metric_series(block):
        states[md.get('ConnectionState', 'all')] += sum(p.get('total') or 0 for p in pts)
    return states


def r8(run):
    run.cover(['R8'], 'R8')
    lbm = {x['id'].lower(): x for x in (run.raw.load('metrics/lb-snat.json') or [])}
    natm = {x['id'].lower(): x for x in (run.raw.load('metrics/natgw.json') or [])}
    span = f"{run.window.get('start', '')[:10]}..{run.window.get('end', '')[:10]} (P1D)"
    inv = []
    for e in run.clusters:
        cl = e['cluster']
        np = cl['properties'].get('networkProfile') or {}
        ce = run.cluster_env(cl)
        lbp = np.get('loadBalancerProfile') or {}
        row = {'cluster': cl['name'], 'outboundType': np.get('outboundType'), 'managedOutboundIPs': (lbp.get('managedOutboundIPs') or {}).get('count'),
               'allocatedOutboundPorts': lbp.get('allocatedOutboundPorts'), 'idleTimeoutInMinutes': lbp.get('idleTimeoutInMinutes'), 'env': ce['value']}
        node_subnets = {p['properties'].get('vnetSubnetID') for p in e.get('agentPools') or []}
        row['nodeSubnetNatGateways'] = sorted({run.subnet_info(s)['natGateway'] for s in node_subnets if s and run.subnet_info(s)['natGateway']})
        nrg = cl['properties'].get('nodeResourceGroup', '').lower()
        lb = next((x for k, x in lbm.items() if f'/resourcegroups/{nrg}/' in k and x['name'] == 'kubernetes'), None)
        if lb:
            states = _states(lb['snatConn'])
            ports = metric_series(lb['ports'])
            alloc = {md.get('BackendIPAddress'): max([p.get('maximum') or 0 for p in pts] or [0]) for n, md, pts in ports if n == 'AllocatedSnatPorts'}
            used_alloc = []
            for n, md, pts in ports:
                if n != 'UsedSnatPorts':
                    continue
                ip = md.get('BackendIPAddress')
                mx = max([p.get('maximum') or 0 for p in pts] or [0])
                avg = [p.get('average') for p in pts if p.get('average') is not None]
                a = alloc.get(ip)
                used_alloc.append({'backendIP': ip, 'usedMax': mx, 'usedAvg': round(sum(avg) / len(avg), 2) if avg else None,
                                   'allocatedMax': a, 'ratioMax': round(mx / a, 4) if a else None})
            row['lbSnat'] = {'window': span, 'connectionsByState': dict(states), 'backendCount': len(used_alloc),
                             'maxUsedOverAllocated': max([u['ratioMax'] or 0 for u in used_alloc] or [0]),
                             'maxUsedPorts': max([u['usedMax'] for u in used_alloc] or [0]), 'perBackend': used_alloc}
            failed, total = states.get('Failed', 0), sum(states.values())
            ratio = row['lbSnat']['maxUsedOverAllocated']
            if np.get('outboundType') == 'loadBalancer' and row['nodeSubnetNatGateways']:
                row['note'] = 'outboundType=loadBalancer 但节点子网挂了 NAT 网关，实际出站优先走 NAT 网关'
            lb_name = f"{cl['name']}/kubernetes"
            if ratio > 0.8:
                run.add('R8', '高', cl['id'], 'Microsoft.Network/loadBalancers', lb_name, ce,
                        f"集群 {cl['name']} 出站负载均衡单节点 SNAT 端口使用峰值达到分配量的 {ratio:.0%}。", row, '增加出站公网 IP 数量或改用 NAT 网关。',
                        key=f"{cl['id']}|snat")
            elif failed > 0:
                run.add('R8', '高' if total and failed / total >= 0.001 else '低', cl['id'], 'Microsoft.Network/loadBalancers', lb_name, ce,
                        f"集群 {cl['name']} 的出站负载均衡在 30 天内有 {int(failed)} 次 SNAT 连接失败（总连接 {int(total):,} 次，占 {failed / total:.4%}），单节点 SNAT 端口使用峰值仅 {row['lbSnat']['maxUsedPorts']} / 2048，不是端口耗尽造成。",
                        {k: v for k, v in row.items() if k != 'lbSnat'} | {'lbSnat': {k: v for k, v in row['lbSnat'].items() if k != 'perBackend'}},
                        '失败比例很低，暂不需要调整出站配置；如应用侧出现外呼超时，再结合失败时间点排查目标服务。'
                        + (' 另外该集群 outboundType 为 loadBalancer 但节点子网挂了 NAT 网关，建议把 outboundType 改为 userAssignedNATGateway，让配置与实际出站路径一致。' if row.get('note') else ''),
                        key=f"{cl['id']}|snat")
            elif row.get('note'):
                run.add('R8', '低', cl['id'], CLUSTER, cl['name'], ce,
                        f"集群 {cl['name']} 的 outboundType 为 loadBalancer，但节点子网挂有 NAT 网关（{', '.join(row['nodeSubnetNatGateways'])}），配置与实际出站路径不一致。",
                        {k: v for k, v in row.items() if k != 'lbSnat'}, '把 outboundType 改为 userAssignedNATGateway（需按 AKS 文档执行出站类型迁移），便于排障和容量规划。',
                        key=f"{cl['id']}|outbound-type")
        inv.append(row)
    nat_inv = []
    for x in natm.values():
        states = _states(x['snatConn'])
        drops = sum(p.get('total') or 0 for _, _, pts in metric_series(x['droppedPackets']) for p in pts)
        dp = [p.get('minimum') for _, _, pts in metric_series(x['datapath']) for p in pts if p.get('minimum') is not None]
        row = {'name': x['name'], 'sub': run.subname(x['id']), 'connectionsByState': dict(states), 'packetDrops30d': drops,
               'datapathAvailabilityMin': min(dp) if dp else None}
        nat_inv.append(row)
        if states.get('Failed', 0) > 0:
            run.add('R8', '中', x['id'], 'Microsoft.Network/natGateways', x['name'], run.env(row['sub'], x['name'], rg=rg_of(x['id'])),
                    f"NAT 网关 {x['name']} 30 天内有 {int(states['Failed'])} 次 SNAT 连接失败。", row, '检查 SNAT 端口使用并考虑增加公网 IP。')
    run.inventory['R8'] = {'clusters': inv, 'natGateways': nat_inv}


# ====================================================================== R9 versions, retirements, certificates
def img_date(v):
    m = re.search(r'-(\d{4})(\d{2})\.(\d{2})', v or '')
    return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc) if m else None


def _version_key(s):
    return [int(x) for x in s.split('.')]


def r9(run):
    run.cover(['R9', 'R1-R9'], 'R9')
    versions = run.raw.load('aks/k8s-versions.json') or {}
    inv = {'clusters': [], 'advisor': {}}
    for e in run.clusters:
        cl = e['cluster']
        ce = run.cluster_env(cl)
        pr = cl['properties']
        key = f"{sid_of(cl['id'])}/{cl['location']}"
        vd = next((v for k, v in versions.items() if k.lower() == key.lower()), {}) or {}
        vals = (vd.get('data') or {}).get('values') or []
        ver = pr.get('kubernetesVersion')
        vinfo = next((v for v in vals if v['version'] == '.'.join(ver.split('.')[:2])), None)
        plans = (vinfo or {}).get('capabilities', {}).get('supportPlan') or []
        official = sorted([v['version'] for v in vals if 'KubernetesOfficial' in (v.get('capabilities', {}).get('supportPlan') or []) and not v.get('isPreview')],
                          key=_version_key)
        aup = pr.get('autoUpgradeProfile') or {}
        tier = (cl.get('sku') or {}).get('tier')
        pools = []
        for pool in e.get('agentPools') or []:
            p = pool['properties']
            cur = p.get('nodeImageVersion')
            latest = (((e.get('poolUpgradeProfiles') or {}).get(pool['name']) or {}).get('data') or {}).get('properties', {}).get('latestNodeImageVersion')
            d = img_date(cur)
            pools.append({'pool': pool['name'], 'nodeImageVersion': cur, 'latestNodeImageVersion': latest,
                          'imageAgeDays': (run.now - d).days if d else None, 'osSKU': p.get('osSKU'), 'orchestratorVersion': p.get('currentOrchestratorVersion')})
        row = {'cluster': cl['name'], 'location': cl['location'], 'version': ver, 'tier': tier, 'supportPlansForMinor': plans,
               'officialMinorsInRegion': official, 'upgradeChannel': aup.get('upgradeChannel'), 'nodeOSUpgradeChannel': aup.get('nodeOSUpgradeChannel'),
               'pools': pools, 'env': ce['value'], 'envBasis': ce['basis']}
        inv['clusters'].append(row)
        if vinfo is None or 'KubernetesOfficial' not in plans:
            lts_note = f'该小版本只剩 LTS 长期支持，而 LTS 需要 Premium 层，集群当前为 {tier} 层' if 'AKSLongTermSupport' in plans else '该小版本已不在区域可用版本列表中'
            run.add('R9', '低' if nonprod(ce) else '中', cl['id'], CLUSTER, cl['name'], ce,
                    f"集群 {cl['name']} 运行 Kubernetes {ver}，已超出社区支持范围（{lts_note}；当前区域正式支持 {', '.join(official)}），出现问题时 Azure 支持有限，且下次升级需要连续跨多个小版本。",
                    row, f"按小版本逐级升级到 {official[0] if official else '受支持版本'} 或更高（先在测试集群验证，注意已弃用 API）；升级前先确认节点子网有足够 IP 容纳升级缓冲节点（见 R1）。",
                    '确认该集群是否为生产集群。' if ce['value'] == 'unknown' else None, key=f"{cl['id']}|k8s-version")
        old = [p for p in pools if (p['imageAgeDays'] or 0) > 120]
        if old:
            oldest = max(old, key=lambda p: p['imageAgeDays'])
            run.add('R9', '中' if (oldest['imageAgeDays'] > 180 and not nonprod(ce)) else '低', cl['id'], CLUSTER, cl['name'], ce,
                    f"集群 {cl['name']} 节点操作系统自动更新通道为 {aup.get('nodeOSUpgradeChannel')}，{len(old)} 个节点池的节点镜像超过 120 天未更新（最旧 {oldest['pool']} 为 {oldest['nodeImageVersion']}，约 {oldest['imageAgeDays']} 天），缺少内核和安全修复，且越久不升级、一次升级的变化越大。",
                    {'nodeOSUpgradeChannel': aup.get('nodeOSUpgradeChannel'), 'upgradeChannel': aup.get('upgradeChannel'), 'pools': old, 'envBasis': ce['basis']},
                    '把节点操作系统升级通道设为 NodeImage（或 SecurityPatch）并配置维护窗口，先在测试集群执行；同时规划 Ubuntu 22.04 到 24.04 的迁移（Kubernetes 1.35 起节点不再支持 22.04）。',
                    key=f"{cl['id']}|node-image")
    _advisor(run, inv)
    basic_pip = [r['name'] for r in run.rows('pips') if (r.get('sku') or {}).get('name') == 'Basic']
    basic_lb = [r['name'] for r in run.rows('lbs') if (r.get('sku') or {}).get('name') == 'Basic']
    inv['basicSku'] = {'basicPublicIPs': basic_pip, 'basicLoadBalancers': basic_lb,
                       'note': '未发现 Basic SKU 公网 IP 或负载均衡（Basic 已于 2025-09-30 退役）' if not basic_pip and not basic_lb else None}
    run.inventory['R9'] = inv


def _advisor(run, inv):
    adv = run.raw.load('advisor-all.json') or {'recommendations': [], 'subscriptions': []}
    recs = adv['recommendations']
    run.coverage['R9']['notes'].append(f"Advisor: {len(recs)} recommendations across {len(adv['subscriptions'])} subscriptions (all categories saved to advisor-all.json).")
    ha = [r for r in recs if r['properties']['category'] == 'HighAvailability']
    inv['advisor'] = {'total': len(recs), 'byCategory': dict(Counter(r['properties']['category'] for r in recs)),
                      'highAvailabilityByProblem': dict(Counter(r['properties']['shortDescription']['problem'] for r in ha).most_common()),
                      'highAvailabilityBySubscription': dict(Counter(r['_subscriptionName'] for r in ha).most_common())}
    retire = []
    for r in recs:
        p = r['properties']
        ep = p.get('extendedProperties') or {}
        problem = p['shortDescription']['problem']
        if ep.get('recommendationSubCategory') == 'ServiceUpgradeAndRetirement' or ep.get('retirementDate') or 'expired' in problem.lower() or 'is ending' in problem:
            retire.append({'sub': r['_subscriptionName'], 'resource': p.get('impactedValue'), 'type': p.get('impactedField'), 'problem': problem,
                           'retirementDate': ep.get('retirementDate'), 'retirementFeature': ep.get('retirementFeatureName'),
                           'impact': p.get('impact'), 'lastUpdated': p.get('lastUpdated')})
    inv['advisor']['retirementRelated'] = retire
    # Front Door certificates, verified from the AFD secret metadata
    for prof in run.raw.load('afd/custom-domains.json') or []:
        pname = prof['profileId'].split('/')[-1]
        for d in prof['customDomains']:
            cm = d.get('certificateMeta') or {}
            exp = cm.get('expirationDate')
            if not exp:
                continue
            days = (datetime.fromisoformat(exp.replace('Z', '+00:00')) - run.now).days
            name = f"{pname}/{d['hostName']}"
            if days < 0:
                run.add('R9', '高', prof['profileId'], 'Microsoft.Cdn/profiles/customDomains', name, run.env(run.subname(prof['profileId']), pname),
                        f"Front Door {pname} 上的自定义域名 {d['hostName']} 使用的客户证书（{cm.get('subject')}）已于 {exp[:10]} 过期（已过期 {-days} 天），如果该域名仍解析到此 Front Door，访问者会看到证书错误。",
                        {'hostName': d['hostName'], 'certificateType': d['tlsSettings'].get('certificateType'), 'expirationDate': exp,
                         'subject': cm.get('subject'), 'useLatestVersion': cm.get('useLatestVersion'), 'issuer': cm.get('certificateAuthority'),
                         'domainValidationState': d.get('domainValidationState'), 'advisor': 'Renew the expired Azure Front Door customer certificate'},
                        '在 Key Vault 中导入续期后的证书新版本（该域名已设置为自动使用最新版本），或改用 Front Door 托管证书；如该域名已不再使用此 Front Door，删除这个自定义域名配置。',
                        f"确认 {d['hostName']} 当前 DNS 是否指向这个 Front Door。", key=name)
            elif days < 30:
                run.add('R9', '中', prof['profileId'], 'Microsoft.Cdn/profiles/customDomains', name, run.env(run.subname(prof['profileId']), pname),
                        f"Front Door {pname} 自定义域名 {d['hostName']} 的证书将在 {days} 天后（{exp[:10]}）过期。", {'expirationDate': exp}, '提前续期证书。', key=name)
    groups = defaultdict(list)
    for x in retire:
        if not x['problem'].startswith(('Upgrade your AKS cluster', 'Unsupported Kubernetes', 'Renew the expired')):
            groups[x['problem']].append(x)
    for problem, lst in groups.items():
        text = ADVISOR_RETIREMENTS.get(problem)
        if not text:
            continue
        dates = sorted({x['retirementDate'] for x in lst if x['retirementDate']})
        run.add('R9', '低', None, lst[0]['type'], ', '.join(sorted({x['resource'] for x in lst})), None,
                f"Azure Advisor 提示 {len(lst)} 个资源受影响：{text[0]}{'（退役日期 ' + ', '.join(dates) + '）' if dates else ''}。",
                {'advisorProblem': problem, 'resources': lst}, text[1], sub=', '.join(sorted({x['sub'] for x in lst})), rg=None,
                members=[member(x['resource'], x['type'], x['sub']) for x in lst], key=f'advisor|{problem}')


# ====================================================================== R10 quota
def r10(run):
    run.cover(['R10'], 'R10')
    q = run.raw.load('quota/compute-usages.json') or []
    inv = []
    for x in q:
        for u in x.get('usages') or []:
            lim = u.get('limit') or 0
            if lim and u.get('currentValue'):
                inv.append({'sub': run.subname(x['subscriptionId']), 'location': x['location'], 'name': u['name']['value'],
                            'current': u['currentValue'], 'limit': lim, 'pct': round(u['currentValue'] / lim * 100, 1)})
    inv.sort(key=lambda r: -r['pct'])
    for r in inv:
        if r['pct'] >= 80 and ('cores' in r['name'].lower() or 'family' in r['name'].lower()):
            run.add('R10', '中' if r['pct'] < 95 else '高', None, 'Microsoft.Compute/locations/usages', f"{r['location']}/{r['name']}", None,
                    f"订阅 {r['sub']} 在 {r['location']} 的 {r['name']} 配额已用 {r['current']}/{r['limit']}（{r['pct']}%），扩容可能因配额不足失败。",
                    r, '提前提交配额提升申请。', sub=r['sub'], rg=None)
    run.inventory['R10'] = {'pairsChecked': len(q), 'top20': inv[:20], 'maxPct': inv[0]['pct'] if inv else None}


# ====================================================================== R11 resource health
def r11(run):
    run.cover(['R11'], 'R11')
    h = run.rows('health')
    per = run.raw.load('health/current-per-resource.json') or []

    def kind(rid):
        parts = rid.split('/providers/')[1].split('/')
        return f'{parts[0]}/{parts[1]}'

    run.inventory['R11'] = {'argVmVmss': dict(Counter(f"{r['rtype']}|{r['status']}" for r in h)),
                            'perResource': dict(Counter(kind(x['id']) + '|' + (x['availabilityState'] or f"HTTP {x['status']}") for x in per))}
    run.coverage['R11']['attempted'] += 1
    run.coverage['R11']['succeeded'] += 1
    run.coverage['R11']['notes'].append(f'Resource Graph healthresources returned {len(h)} VM/VMSS statuses; other types queried per resource. '
                                        'Mongo vCore returns HTTP 422 (resource type not supported by Resource Health).')
    for r in h:
        if r['status'] != 'Available':
            run.add('R11', '中', r['rid'], r['rtype'], r['rid'].split('/')[-1], None, f"资源当前健康状态为 {r['status']}：{r['summary'][:120]}", r, '检查资源运行状态。')
    for x in per:
        if x['availabilityState'] not in (None, 'Available'):
            run.add('R11', '中', x['id'], 'resource', x['id'].split('/')[-1], None, f"资源当前健康状态为 {x['availabilityState']}：{(x['summary'] or '')[:120]}",
                    x, '检查资源运行状态。')


# ====================================================================== R12 failed operations
def r12(run):
    run.cover(['R12'], 'R12')
    act = run.raw.load('activity/failed-ops.json') or []
    cnt, sample = Counter(), {}
    for s in act:
        for e in s.get('events') or []:
            m = re.search(r'"code"\s*:\s*"([^"]+)"', e.get('statusMessage') or '')
            code = m.group(1) if m else (e.get('subStatus') or e.get('statusCode'))
            key = (s['subscriptionName'], e.get('resourceId') or '', e.get('op'), code)
            cnt[key] += 1
            if key not in sample or e['t'] > sample[key]['last']:
                sample[key] = {'last': e['t'], 'msg': (e.get('statusMessage') or '')[:400], 'first': sample.get(key, {}).get('first', e['t'])}
            sample[key]['first'] = min(sample[key]['first'], e['t'])
    summary = [{'sub': k[0], 'resource': k[1].split('/')[-1], 'resourceId': k[1], 'operation': k[2], 'code': k[3], 'count': n,
                'first': sample[k]['first'], 'last': sample[k]['last'], 'sampleMessage': sample[k]['msg']} for k, n in cnt.most_common()]
    by_code = Counter()
    for x in summary:
        by_code[x['code']] += x['count']
    run.inventory['R12'] = {'window': f"{run.window.get('start')}..{run.window.get('snapshot')}",
                            'subscriptions': [{k: s.get(k) for k in ('subscriptionName', 'status', 'error', 'pages')} | {'events': None if s['events'] is None else len(s['events'])} for s in act],
                            'byCode': dict(by_code.most_common()), 'top': summary[:40]}
    full = [x for x in summary if x['code'] == 'SubnetIsFull']
    if full:
        vmss = 'Microsoft.Compute/virtualMachineScaleSets'
        run.add('R12', '高', full[0]['resourceId'], vmss, ', '.join(x['resource'] for x in full),
                run.env(full[0]['sub'], full[0]['resource'], rg=rg_of(full[0]['resourceId'])),
                f"近 30 天有 {sum(x['count'] for x in full)} 次节点扩容/更新操作因子网 IP 不足（SubnetIsFull）失败，涉及 {len(full)} 个节点池，最近一次在 {max(x['last'] for x in full)[:16].replace('T', ' ')} UTC。",
                {'events': [{k: x[k] for k in ('sub', 'resource', 'operation', 'count', 'first', 'last', 'sampleMessage')} for x in full]},
                '与 R1 同一问题：扩大节点子网或改用 Overlay 网络后，这类失败才会停止。', sub=full[0]['sub'],
                members=[member(x['resource'], vmss, x['sub']) for x in full], key='subnet-full')
    for x in [x for x in summary if x['code'] == 'PrivateIPAddressIsAllocated']:
        recent = (run.now - datetime.fromisoformat(x['last'][:19] + '+00:00')).days <= 7
        run.add('R12', '中' if recent else '低', x['resourceId'], 'Microsoft.Network/loadBalancers', x['resource'],
                run.env(x['sub'], x['resource'], rg=rg_of(x['resourceId'])),
                f"{x['resource']}（{rg_of(x['resourceId'])}）在 {x['first'][:10]} 至 {x['last'][:10]} 有 {x['count']} 次更新失败，原因是请求的内网 IP 已被其他资源占用，对应的 Kubernetes 内部负载均衡服务可能一直拿不到 IP。",
                {k: x[k] for k in ('sub', 'operation', 'count', 'first', 'last', 'sampleMessage')},
                '在集群中找出指定了固定内网 IP（loadBalancerIP 或 azure-load-balancer-ipv4 注解）的 Service，改用未占用的 IP 或删除冲突配置。',
                '确认是否有内部服务处于 Pending 状态。', sub=x['sub'], key=f"{x['resourceId']}|ip-allocated")
    policy = [x for x in summary if x['code'] in ('RequestDisallowedByPolicy', 'InvalidTemplateDeployment') or 'policies/deny' in (x['operation'] or '')]
    if policy:
        names = sorted({x['resource'] for x in policy})
        run.add('R12', '低', None, 'Microsoft.Resources/deployments', ', '.join(names), None,
                f"近 30 天有 {sum(x['count'] for x in policy)} 次部署被 Azure Policy 拒绝（如 {names[0]}），新服务上线可能被阻塞。",
                {'events': policy}, '与部署人员核对被拒原因，按策略要求调整模板（不建议为此放宽策略）。', '确认这些资源是否仍需创建。', sub=policy[0]['sub'],
                members=[member(n, 'Microsoft.Resources/deployments', policy[0]['sub']) for n in names], key='policy-denied')
    capacity_codes = ('SkuNotAvailable', 'AllocationFailed', 'ZonalAllocationFailed', 'OverconstrainedAllocationRequest', 'QuotaExceeded', 'OperationNotAllowed')
    for x in summary:
        text = (x['sampleMessage'] or '').lower() + (x['code'] or '').lower() + ('capacity' if x['code'] == 'SkuNotAvailable' else '')
        if x['code'] in capacity_codes and 'quota' in text:
            run.add('R12', '低', x['resourceId'], x['operation'].split('/write')[0], x['resource'], None,
                    f"{x['resource']} 在 {x['last'][:10]} 创建失败：{x['code']}（所需规格在该区域暂时没有容量或配额不足）。",
                    {k: x[k] for k in ('sub', 'operation', 'count', 'sampleMessage')}, '如需在该区域使用此规格，选择替代规格或提前申请容量预留。',
                    sub=x['sub'], key=f"{x['resourceId']}|{x['code']}")


# ====================================================================== entry point
def analyze(ws, cfg, log=print):
    run = _Run(ws, cfg)
    for check in (r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12):
        check(run)
    items = run.findings.items
    items.sort(key=lambda f: (SEV_ORDER[f['severity']], f['check'], f['subscriptionName'] or '', f['resourceName'] or ''))
    for i, f in enumerate(items, 1):
        f['legacyId'] = f'REL-{i:03d}'
    disabled = [s for s in run.subs if s.get('state') != 'Enabled']
    scope = {'subscriptions': len(run.subs), 'enabled': len(run.enabled),
             'notInspected': [{'name': s['name'], 'id': s['id'], 'reason': '订阅未启用，无法读取'} for s in disabled]}
    limitations = ['只读巡检，未执行任何变更；未使用 kubectl，无法检查 Pod 副本数、PDB、探针等集群内部配置。',
                   'Azure CNI 动态 Pod IP 分配占用的 Pod 子网 IP 不在 ARM 子网用量中显示，Pod 子网只做最坏情况估算。',
                   '活动日志只取 Failed 状态事件；Mongo vCore 不支持 Resource Health（HTTP 422）。']
    if disabled:
        limitations.append(f'{len(disabled)} 个未启用订阅不可读，未纳入。')
    data = run.findings.write(ws, window=run.window, coverage=run.coverage, scope=scope, inventory=run.inventory, limitations=limitations,
                              extra={'summary': {'bySeverity': dict(Counter(f['severity'] for f in items)),
                                                 'byCheck': {c: dict(Counter(f['severity'] for f in items if f['check'] == c))
                                                             for c in CHECKS if any(f['check'] == c for f in items)}}})
    sev = Counter(f['severity'] for f in items)
    log(f"可靠性分析：{len(items)} 项问题（高 {sev['高']}、中 {sev['中']}、低 {sev['低']}）")
    return data
