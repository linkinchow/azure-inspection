"""Performance efficiency (P1..P10) offline analysis of raw/waf/performance/ (no network calls).

Sustained load = Count-weighted window average sum(avg*count)/sum(count); peaks = number of days whose daily Maximum
reaches a threshold, plus the highest daily Maximum. Missing data stays null with a reason.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from ...core.io import read_json
from ..common import ADVISOR_NO_TEXT, Findings, Raw, advisor_problem, env, is_prod, load_scope, mixed_env
from .lib import Data, first, fmt, rg_of

SEV_ORDER = {'高': 0, '中': 1, '低': 2}
UNCHANGED = '本次未做任何变更。'
VM_DISK = ['VM Cached IOPS Consumed Percentage', 'VM Uncached IOPS Consumed Percentage',
           'VM Cached Bandwidth Consumed Percentage', 'VM Uncached Bandwidth Consumed Percentage',
           'OS Disk IOPS Consumed Percentage', 'OS Disk Bandwidth Consumed Percentage',
           'Data Disk IOPS Consumed Percentage', 'Data Disk Bandwidth Consumed Percentage']
DISK_CN = {'VM Cached IOPS Consumed Percentage': '虚拟机缓存 IOPS 上限', 'VM Uncached IOPS Consumed Percentage': '虚拟机非缓存 IOPS 上限',
           'VM Cached Bandwidth Consumed Percentage': '虚拟机缓存带宽上限', 'VM Uncached Bandwidth Consumed Percentage': '虚拟机非缓存带宽上限',
           'OS Disk IOPS Consumed Percentage': '系统盘 IOPS', 'OS Disk Bandwidth Consumed Percentage': '系统盘带宽',
           'Data Disk IOPS Consumed Percentage': '数据盘 IOPS', 'Data Disk Bandwidth Consumed Percentage': '数据盘带宽'}
VM_TYPE = 'Microsoft.Compute/virtualMachines'
POOL_TYPE = 'Microsoft.ContainerService/managedClusters/agentPools'
AKS_TYPE = 'Microsoft.ContainerService/managedClusters'
CROSS_CONTINENT_MIN_USD = 10


def member(name, rtype, sub):
    return {'name': name, 'type': rtype, 'subscription': sub}


def one_or_many(values, many='多个订阅'):
    values = {v for v in values if v}
    return values.pop() if len(values) == 1 else many


def double_vcpu(size):
    m = re.search(r'[A-Za-z]+(\d+)', (size or '').replace('Standard_', ''))
    return f'（例如同系列 {int(m.group(1)) * 2} vCPU）' if m else ''


def span(values, unit=''):
    values = [v for v in values if v is not None]
    if not values:
        return '-'
    lo, hi = min(values), max(values)
    return f'{lo}{unit}' if lo == hi else f'{lo}–{hi}{unit}'


class Analyzer:
    def __init__(self, ws, cfg, log=print):
        self.ws, self.cfg, self.log = ws, cfg, log
        self.raw = Raw(ws, 'performance')
        self.rel = self.raw.other('reliability')
        manifest = self.raw.load('manifest.json')
        if not manifest:
            raise RuntimeError('缺少 raw/waf/performance/manifest.json，请先运行 collect')
        self.window = manifest['window']
        self.days = self.window.get('days') or 30
        self.subs = load_scope(ws)
        self.data = Data(self.raw, self.window['start'], self.window['end'], self.subs)
        self.F = Findings('performance')
        self.cov = {f'P{i}': {'attempted': 0, 'succeeded': 0, 'denied': 0, 'notes': []} for i in range(1, 11)}
        self.inv, self.limits = {}, []

    # ------------------------------------------------------------------ helpers
    def env_of(self, rid, name=None, tags=None):
        return env(self.cfg, self.data.subname(rid) or '', name or '', tags)

    def add(self, check, sev, rid, rtype, name, environment, finding, evidence, rec, confirm=None, sub=None, rg=None,
            members=None, key=None):
        self.F.add(check, sev, finding, rec, subscription=sub if sub is not None else self.data.subname(rid),
                   resource_group=rg if rg is not None else rg_of(rid), resource_name=name, resource_type=rtype, resource_id=rid,
                   environment=environment, evidence=evidence, needs_confirmation=confirm, members=members, key=key)

    def rel_load(self, *paths):
        """Reliability raw data; accepts both 'x' and 'raw/x' layouts."""
        for p in paths:
            for candidate in (p, f'raw/{p}'):
                data = self.rel.load(candidate)
                if data is not None:
                    return data
        return None

    def metric(self, *a, **kw):
        return self.data.metric(*a, **kw)

    # ------------------------------------------------------------------ coverage
    def coverage_from_index(self):
        calls = (self.raw.load('index.json') or {}).get('calls') or []
        mapping = {'P1': ('P1', 'P1/P4'), 'P2': ('P2',), 'P4': ('P1/P4', 'P4/P5'), 'P5': ('P5', 'P4/P5'), 'P6': ('P6',),
                   'P7': ('P7',), 'P8': ('P8',), 'P9': ('P9',)}
        for k, checks in mapping.items():
            sel = [c for c in calls if c.get('check') in checks]
            c = self.cov[k]
            c['attempted'] = len(sel)
            c['succeeded'] = sum(1 for x in sel if x.get('status') == 200)
            c['denied'] = sum(1 for x in sel if x.get('status') in (401, 403))
            other = Counter(f"HTTP {x.get('status')}" for x in sel if x.get('status') not in (200, 401, 403))
            if other:
                c['notes'].append('非 200 响应（不含 401/403）：' + '，'.join(f'{a} ×{b}' for a, b in other.items())
                                  + '（400 表示该指标或粒度不支持，已逐个指标重试；429/5xx 为限流或服务端错误，已重试）。')
        arg = [c for c in calls if c.get('check') == 'ARG']
        self.cov['P8']['attempted'] += len(arg)
        self.cov['P8']['succeeded'] += sum(1 for c in arg if c.get('status') == 200)
        return calls

    # ------------------------------------------------------------------ P1 / P4 virtual machines
    def month_vm_usage(self):
        """Review-month VM averages from the 01 cost review, when it was run for this month."""
        path = self.ws.raw('cost/review/results.json')
        if not path.exists():
            return {}
        return {(m.get('name') or '').lower(): m for m in read_json(path).get('vmMetrics', []) if m.get('kind') == 'vm'}

    def p1_p4_vms(self):
        d = self.data
        vms = d.rows('vms')
        running = [v for v in vms if v.get('power') == 'PowerState/running']
        month = self.month_vm_usage()
        inv, nodata, p1_hits, p4_hits = [], [], [], []
        for v in running:
            rid = v['id']
            e = self.env_of(rid, v['name'], v.get('tags'))
            cpu = self.metric('vm-daily', rid, 'Percentage CPU', 95, 80)
            mem = self.metric('vm-daily', rid, 'Available Memory Percentage')
            mem_used = None if mem.get('avg') is None else 100 - mem['avg']
            s, _ = d.series('vm-daily', rid, 'Available Memory Percentage')
            dd = [x for x in d.daily(first(s)) if 'avg' in x]
            mem_peak_day = 100 - min(x['avg'] for x in dd) if dd else None
            rec = {'resourceName': v['name'], 'subscriptionName': d.subname(rid), 'vmSize': v.get('vmSize'), 'region': v['location'],
                   'environment': e, 'cpuAvgPct': fmt(cpu.get('avg')), 'cpuMaxDailyMaxPct': fmt(cpu.get('maxDailyMax')),
                   'cpuDaysMaxGE95': cpu.get('daysMaxGE'), 'memUsedAvgPct': fmt(mem_used),
                   'memUsedHighestDailyAvgPct': fmt(mem_peak_day), 'daysWithData': cpu.get('days'),
                   'error': cpu.get('error') or mem.get('error')}
            if cpu.get('error') and mem.get('error'):
                nodata.append({'resourceName': v['name'], 'subscriptionName': d.subname(rid), 'reason': cpu['error'][:200]})
            disk = {}
            for m in VM_DISK:
                x = self.metric('vm-daily', rid, m, 95, 80)
                if not x.get('error'):
                    disk[m] = {'avgPct': fmt(x.get('avg')), 'maxDailyMaxPct': fmt(x.get('maxDailyMax')), 'daysMaxGE95': x.get('daysMaxGE')}
            rec['disk'] = disk
            inv.append(rec)
            sustained_cpu = (cpu.get('avg') or 0) >= 80
            sustained_mem = mem_used is not None and mem_used >= 85
            peaks = (cpu.get('daysMaxGE') or 0) >= 7
            if sustained_cpu or sustained_mem or peaks:
                p1_hits.append((v, rec, sustained_cpu, sustained_mem))
            hot = {m: x for m, x in disk.items() if (x['avgPct'] or 0) >= 80 or (x['daysMaxGE95'] or 0) >= 7}
            if hot:
                p4_hits.append((v, rec, hot))
        self.inv['vms'] = {'total': len(vms), 'running': len(running), 'deallocated': len(vms) - len(running),
                           'noMetricData': nodata, 'perVm': inv}
        for v, rec, sc, sm in p1_hits:
            self.p1_finding(v, rec, sc, sm, month.get(v['name'].lower()) or {})
        self.p4_vm_findings(p4_hits)
        self.cov['P1']['notes'].append(f'评估 {len(running)} 台运行中的虚拟机（{len(vms) - len(running)} 台已停止，未评估）；'
                                       f'{len(nodata)} 台没有指标数据。')
        self.cov['P1']['notes'].append('AKS 节点所在的规模集已读取实例级 CPU 和可用内存；节点层面的饱和度在 P2 用 AKS 平台指标（工作集占可分配内存）判断。')

    def p1_finding(self, v, rec, sustained_cpu, sustained_mem, month):
        e = rec['environment']
        prod = is_prod(e)
        if sustained_cpu and prod:
            sev = '高'
        elif sustained_mem and prod and (rec['memUsedAvgPct'] or 0) >= 95:
            sev = '高'
        else:
            sev = '中' if prod else '低'
        D = self.days
        ev = {'window': f"{self.window['start'][:10]}..{self.window['end'][:10]}", 'vmSize': rec['vmSize'], 'region': rec['region'],
              'cpuAvgPct_countWeighted': rec['cpuAvgPct'], 'cpuHighestDailyMaxPct': rec['cpuMaxDailyMaxPct'],
              'daysCpuDailyMaxGE95': rec['cpuDaysMaxGE95'], 'daysWithData': rec['daysWithData'],
              'memUsedAvgPct': rec['memUsedAvgPct'], 'memUsedHighestDailyAvgPct': rec['memUsedHighestDailyAvgPct'],
              'reviewMonthCpuAvgPct': fmt(month.get('cpuAverage')), 'reviewMonthMemUsedAvgPct': fmt(month.get('memoryAverage')),
              'thresholds': f'持续：{D}天加权平均CPU≥80% 或 平均内存使用≥85%；频繁峰值：日最高CPU≥95%的天数≥7天。与成本降配检查方向相反。',
              'disk': {DISK_CN[k]: x for k, x in rec['disk'].items() if (x['daysMaxGE95'] or 0) >= 3}}
        if sustained_cpu:
            f = (f"虚拟机 {v['name']}（{rec['vmSize']}）过去 {D} 天 CPU 加权平均 {rec['cpuAvgPct']}%，"
                 f"{rec['cpuDaysMaxGE95']} 天的日最高 CPU ≥95%（最高 {rec['cpuMaxDailyMaxPct']}%），处于长期满负荷状态。")
            r = (f'确认该机上运行的进程是否为预期负载；若是业务负载，建议升到更高 vCPU 规格{double_vcpu(rec["vmSize"])}或拆分到多台/改为可横向扩展的部署；'
                 '若是异常进程（死循环、挖矿、日志风暴）先处理进程。' + UNCHANGED)
        elif sustained_mem:
            f = f"虚拟机 {v['name']} 过去 {D} 天平均内存使用 {rec['memUsedAvgPct']}%，长期接近上限。"
            r = '确认应用内存配置（如 JVM、数据库或缓存的内存上限）；若属正常增长，建议升到更大内存规格（E 系列）。' + UNCHANGED
        else:
            f = (f"虚拟机 {v['name']}（{rec['vmSize']}）CPU 平均 {rec['cpuAvgPct']}%，但有 {rec['cpuDaysMaxGE95']} 天日最高 CPU ≥95%"
                 f"（最高 {rec['cpuMaxDailyMaxPct']}%），存在频繁的短时打满。")
            r = '在峰值时段（可用 1 分钟粒度指标或 OS 监控）确认是哪个进程打满 CPU；若峰值影响响应时间，考虑错峰执行批任务或升一档规格。' + UNCHANGED
        self.add('P1', sev, v['id'], VM_TYPE, v['name'], e, f, ev, r,
                 '需业务方确认该机用途与负载是否正常' if sustained_cpu else '是否为预期负载（批处理/计算任务）需业务方确认')

    def p4_vm_findings(self, hits):
        groups = defaultdict(list)
        for v, rec, hot in hits:
            e = rec['environment']
            worst_avg = max((x['avgPct'] or 0) for x in hot.values())
            if is_prod(e) and worst_avg >= 80:
                sev = '高'
            elif is_prod(e) and worst_avg >= 10:
                sev = '中'
            else:
                sev = '低'
            item = {'resourceName': v['name'], 'subscriptionName': rec['subscriptionName'], 'vmSize': rec['vmSize'],
                    'environment': e, 'limits': {DISK_CN[m]: x for m, x in hot.items()}}
            groups[(sev, 'prod' if is_prod(e) else 'nonprod')].append((v, item))
        for (sev, kind), its in sorted(groups.items(), key=lambda x: SEV_ORDER[x[0][0]]):
            names = [i['resourceName'] for _, i in its]
            worst = max(its, key=lambda t: max((x['daysMaxGE95'] or 0) for x in t[1]['limits'].values()))
            wl = max(worst[1]['limits'].items(), key=lambda kv: kv[1]['daysMaxGE95'] or 0)
            f = (f"{len(its)} 台虚拟机的磁盘/虚拟机 IO 上限在 {self.days} 天里频繁被打满（日最高≥95% 的天数≥7 天），"
                 f"最多的是 {worst[1]['resourceName']} 的{wl[0]}：{wl[1]['daysMaxGE95']} 天达到 {wl[1]['maxDailyMaxPct']}%（平均 {wl[1]['avgPct']}%）。")
            r = ('确认这些峰值对应的作业（备份、数据导入、合并/compaction、编译）；若峰值期间应用变慢，'
                 '可把数据盘升到更高性能档（Premium SSD 更大容量档/开启按需突发，或迁移到 Premium SSD v2 单独设定 IOPS/吞吐），'
                 '或换成单机磁盘吞吐上限更高的虚拟机规格；若只是夜间批任务且无人受影响，可接受。' + UNCHANGED)
            self.add('P4', sev, its[0][0]['id'], VM_TYPE, ', '.join(names), mixed_env([i['environment'] for _, i in its]), f,
                     {'items': [i for _, i in its],
                      'thresholds': '平均≥80% 视为持续瓶颈；日最高≥95% 的天数≥7 天视为频繁限流（1 分钟粒度的日最大值）。数据盘指标未按 LUN 拆分，取所有数据盘的合并值。',
                      'severityBasis': '生产且平均≥10% 定为中；平均很低、只是短时突发或非生产定为低。'},
                     r, '峰值是否影响业务需业务方确认', sub=one_or_many(i['subscriptionName'] for _, i in its),
                     rg=rg_of(its[0][0]['id']) if len(its) == 1 else None,
                     members=[member(i['resourceName'], VM_TYPE, i['subscriptionName']) for _, i in its], key=f'vm-disk-{kind}-{sev}')

    # ------------------------------------------------------------------ P2 AKS
    def p2_aks(self):
        d = self.data
        aks = d.rows('aks')
        pools = {c['cluster']: c for c in (d.load('aks/agentpools.json') or [])}
        vmss = {((s.get('resourceGroup') or '').lower(), s.get('poolName')): s for s in d.rows('vmss')}
        la = {w['workspace']: w for w in (d.load('la/container-insights.json') or []) if 'results' in w}
        clusters, mem_high, mem_mid, apisrv = [], [], [], []
        for c in aks:
            rec = self.cluster_record(c, pools, vmss, mem_high, mem_mid)
            apic = rec['apiserver_cpu_usage_percentage']
            if is_prod(rec['environment']) and (apic.get('daysMaxGE') or 0) >= 3:
                apisrv.append((c, apic))
            clusters.append(rec)
        self.inv['aksClusters'] = clusters
        self.p2_memory(mem_high, mem_mid, clusters)
        for c in aks:
            rec = next(r for r in clusters if r['cluster'] == c['name'])
            self.p2_scheduling(c, rec, la)
        for c, apic in apisrv:
            self.p2_apiserver(c, apic)
        ci = [r['cluster'] for r in clusters if r['containerInsights']]
        self.cov['P2']['notes'].append(f'已读取全部 {len(aks)} 个集群的 AKS 平台指标（平台指标最粗 12 小时粒度，汇总为日）。'
                                       f'启用 Container Insights（Pod 级历史）的集群 {len(ci)} 个' + (f'：{", ".join(ci)}' if ci else '')
                                       + f'；其余 {len(aks) - len(ci)} 个集群没有按命名空间的等待/OOM 历史。')
        at_max = [f"{r['cluster']}/{p['pool']}" for r in clusters for p in r['pools'] if p.get('atMaxCountNow')]
        if at_max:
            self.cov['P2']['notes'].append('当前停在自动缩放上限的节点池：' + '，'.join(at_max) + '（按每小时上报 CPU 的实例数近似，包含节点替换）。')

    def cluster_record(self, c, pools, vmss, mem_high, mem_mid):
        d = self.data
        rid = c['id']
        e = self.env_of(rid, c['name'], c.get('tags'))
        rec = {'cluster': c['name'], 'subscriptionName': d.subname(rid), 'region': c['location'], 'environment': e,
               'tier': (c.get('sku') or {}).get('tier'),
               'containerInsights': bool(((c.get('addons') or {}).get('omsagent') or {}).get('enabled')), 'pools': []}
        nrg = (c.get('nodeRG') or '').lower()
        per_pool = {}
        for m in ('node_cpu_usage_percentage', 'node_memory_working_set_percentage'):
            s, err = d.series('aks-nodepool', rid, m)
            for x in s:
                per_pool.setdefault(x['dims'].get('nodepool'), {})[m] = d.summarize(x['data'], 95, 80)
            if err:
                rec.setdefault('errors', {})[m] = err
        for p in (pools.get(c['name']) or {}).get('pools', []):
            pm = per_pool.get(p['name'], {})
            cpu, mem = pm.get('node_cpu_usage_percentage', {}), pm.get('node_memory_working_set_percentage', {})
            pr = {'pool': p['name'], 'mode': p.get('mode'), 'vmSize': p.get('vmSize'), 'count': p.get('count'),
                  'autoscale': p.get('enableAutoScaling'), 'minCount': p.get('minCount'), 'maxCount': p.get('maxCount'),
                  'atMaxCountNow': bool(p.get('enableAutoScaling') and p.get('count') is not None and p.get('count') == p.get('maxCount')),
                  'cpuAvgPct': fmt(cpu.get('avg')), 'cpuHighestDailyMaxPct': fmt(cpu.get('maxDailyMax')), 'cpuDaysMaxGE95': cpu.get('daysMaxGE'),
                  'memWorkingSetAvgPct': fmt(mem.get('avg')), 'memHighestDailyMaxPct': fmt(mem.get('maxDailyMax')),
                  'memDaysMaxGE95': mem.get('daysMaxGE'), 'memDaysAvgGE80': mem.get('daysAvgGE')}
            self.node_history(pr, p, vmss.get((nrg, p['name'])))
            rec['pools'].append(pr)
            if is_prod(e) and mem.get('avg') is not None:
                item = {'resourceName': f"{c['name']}/{p['name']}", 'cluster': c['name'], 'pool': p['name'],
                        'subscriptionName': d.subname(rid), 'vmSize': p.get('vmSize'), 'nodes': p.get('count'),
                        'autoscale': p.get('enableAutoScaling'), 'mode': p.get('mode'), 'environment': e,
                        'memWorkingSetAvgPct': fmt(mem['avg']), 'memHighestDailyMaxPct': fmt(mem.get('maxDailyMax')),
                        'memDaysMaxGE95': mem.get('daysMaxGE'), 'cpuAvgPct': fmt(cpu.get('avg'))}
                if mem['avg'] >= 90 or (mem['avg'] >= 80 and (mem.get('daysMaxGE') or 0) >= 7):
                    mem_high.append((c, item))
                elif mem['avg'] >= 80:
                    mem_mid.append((c, item))
        for m in ('cluster_autoscaler_unschedulable_pods_count', 'apiserver_cpu_usage_percentage',
                  'apiserver_memory_usage_percentage', 'etcd_database_usage_percentage'):
            s, err = d.series('aks-autoscaler', rid, m)
            x = d.summarize(first(s), 95 if 'percentage' in m else 1) if s else {}
            rec[m] = {'avg': fmt(x.get('avg'), 2), 'highestDailyMax': x.get('maxDailyMax'), 'daysMaxGE': x.get('daysMaxGE'),
                      'daysWithData': x.get('days'),
                      'note': None if x.get('days') else ('autoscaler not enabled on any pool (no data)' if 'autoscaler' in m else err)}
        s, err = d.series('aks-nodecond', rid, 'kube_node_status_condition')
        conds = {}
        for x in s:
            dims = x['dims']
            bad = (dims.get('condition') == 'Ready' and dims.get('status') != 'true') or (dims.get('condition') != 'Ready' and dims.get('status') == 'true')
            if bad:
                sx = d.summarize(x['data'], 1)
                if (sx.get('maxDailyMax') or 0) > 0:
                    conds[f"{dims.get('condition')}={dims.get('status')}"] = {'daysObserved': sx.get('daysMaxGE'), 'maxNodes': sx.get('maxDailyMax')}
        rec['nodeConditionsObserved'] = conds if not err else {'error': err}
        s, _ = d.series('aks-podphase', rid, 'kube_pod_status_phase')
        byday = defaultdict(lambda: defaultdict(float))
        for x in s:
            ph = x['dims'].get('phase')
            if ph in ('Pending', 'Failed'):
                for day in d.daily(x['data']):
                    byday[ph][day['date']] += day.get('avg') or 0
        rec['podPhase'] = {ph: {'avgPodsPerDay': fmt(sum(v.values()) / max(len(v), 1), 2),
                                'daysAvgGE1': sum(1 for a in v.values() if a >= 1)} for ph, v in byday.items()}
        return rec

    def node_history(self, pr, pool, scale_set):
        """Node count history of an autoscaled pool, approximated from instances reporting CPU per hour."""
        if not scale_set:
            return
        ser, _ = self.data.series('vmss-instance-hourly-cpu', scale_set['id'], 'Percentage CPU')
        per = Counter()
        for x in ser:
            for pt in x['data']:
                if pt.get('average') is not None and self.data.in_window(pt['timeStamp']):
                    per[pt['timeStamp']] += 1
        pr['distinctInstances'] = len(ser)
        if per and pool.get('enableAutoScaling') and pool.get('maxCount'):
            pr['hoursWithInstancesGEmaxCount'] = sum(1 for n in per.values() if n >= pool['maxCount'])
            pr['daysReachingMaxCount'] = len({k[:10] for k, n in per.items() if n >= pool['maxCount']})
            pr['maxInstancesInAnHour'] = max(per.values())

    def p2_memory(self, mem_high, mem_mid, clusters):
        if mem_high:
            items = [i for _, i in mem_high]
            worst = max(items, key=lambda i: i['memWorkingSetAvgPct'])
            names = sorted({i['cluster'] for i in items})
            pressure = [r['cluster'] for r in clusters if r['cluster'] in names
                        and any(k.startswith('MemoryPressure=true') for k in (r.get('nodeConditionsObserved') or {}))]
            related = []
            if pressure:
                related.append(f'{"、".join(pressure)} 在窗口内出现过 MemoryPressure=true')
            if not any(i['autoscale'] for i in items):
                related.append('这些池均未开启自动缩放（固定节点数）')
            self.add('P2', '高', mem_high[0][0]['id'], POOL_TYPE, ', '.join(i['resourceName'] for i in items),
                     mixed_env([i['environment'] for i in items]),
                     f"{len(items)} 个生产节点池的节点内存工作集长期接近或超过可分配内存：最高的 {worst['resourceName']} {self.days} 天平均 {worst['memWorkingSetAvgPct']}%、"
                     f"日最高 {worst['memHighestDailyMaxPct']}%，{worst['memDaysMaxGE95']} 天日最高≥95%，容易触发内存驱逐或 OOM。",
                     {'items': [{k: v for k, v in i.items() if k != 'environment'} for i in items],
                      'metric': 'AKS 平台指标 node_memory_working_set_percentage（相对节点“可分配内存”，不是整机内存；>100% 表示工作集已超过 kubelet 可分配量），12 小时粒度汇总为日。',
                      'thresholds': f'持续：{self.days} 天平均≥80%；高：平均≥90% 或 日最高≥95% 的天数≥7 天。',
                      'related': '；'.join(related) or None},
                     '为这些池的工作负载核对内存 requests/limits（requests 偏低会让过多 Pod 挤在同一节点）；把节点池换成更大内存规格（如 E 系列内存优化规格）'
                     '或增加节点数并开启集群自动缩放；系统池建议至少 D4 级别并只跑系统组件。' + UNCHANGED,
                     '需确认是否已有 OOM/驱逐告警，以及 requests/limits 设置', sub=one_or_many(i['subscriptionName'] for i in items), rg=None,
                     members=[member(i['resourceName'], POOL_TYPE, i['subscriptionName']) for i in items], key='nodepool-memory-high')
        for c, item in mem_mid:
            self.add('P2', '中', c['id'], POOL_TYPE, item['resourceName'], item['environment'],
                     f"节点池 {item['resourceName']}（{item['vmSize']} × {item['nodes']}）内存工作集 {self.days} 天平均 {item['memWorkingSetAvgPct']}%，"
                     f"日最高 {item['memHighestDailyMaxPct']}%，长期偏高。",
                     {**{k: v for k, v in item.items() if k != 'environment'}, 'metric': 'node_memory_working_set_percentage（相对可分配内存）',
                      'thresholds': f'{self.days} 天平均≥80%'},
                     '若该池为系统池，建议改用至少 4 vCPU/16 GiB 的规格并加 CriticalAddonsOnly 污点，只运行系统组件；用户负载迁到用户池。' + UNCHANGED,
                     None, key=f"nodepool-memory|{item['resourceName']}")

    def p2_scheduling(self, c, rec, la):
        """Pods that cannot be scheduled on most days: autoscaler cannot add nodes or pools are at their limit."""
        us = rec['cluster_autoscaler_unschedulable_pods_count']
        days, with_data = us.get('daysMaxGE') or 0, us.get('daysWithData') or 0
        if days < 7:
            return
        e = rec['environment']
        sev = ('高' if days >= 0.8 * with_data else '中') if is_prod(e) else '低'
        ev = {'unschedulablePods': us, 'pools': rec['pools']}
        parts = []
        w = next((v for v in la.values() if c['name'] in v['clusters']), None)
        if w:
            r_ = w['results']
            failed = [x for x in r_['events']['rows'] if x['Reason'] == 'FailedScheduling' and x.get('ClusterName') in (None, c['name'])]
            pending = [x for x in r_['pending10m']['rows'] if x.get('ClusterName') in (None, c['name'])]
            ev['failedSchedulingEvents'] = failed
            ev['podsPendingOver10min'] = pending
            ev['otherEvents'] = [x for x in r_['events']['rows'] if x['Reason'] in ('NodeNotReady', 'OOMKilling', 'Evicted', 'FailedCreatePodSandBox')
                                 and x.get('ClusterName') in (None, c['name'])]
            ev['oomKilledContainers'] = [{k: v for k, v in x.items() if k != 'sampleStatus'} for x in r_['oomkilled']['rows']
                                         if x.get('ClusterName') in (None, c['name'])]
            ev['logAnalyticsWorkspace'] = w['workspace'] + f"（保留 {w.get('retentionDays')} 天）"
            if failed:
                top = max(failed, key=lambda x: x.get('events') or 0)
                parts.append(f"{top['Namespace']} 命名空间 {top.get('events', 0):,} 次 FailedScheduling（{top.get('objects', 0):,} 个 Pod）")
            if pending:
                top = max(pending, key=lambda x: x.get('pods') or 0)
                parts.append(f"{top['Namespace']} 有 {top.get('pods')} 个 Pod 等待超过 10 分钟（平均 {top.get('avgDurMin') or 0:.0f} 分钟、"
                             f"最长约 {(top.get('maxDurMin') or 0) / 60:.0f} 小时）")
        for p in rec['pools']:
            if p.get('atMaxCountNow') and (p.get('daysReachingMaxCount') or 0) >= 0.8 * self.days:
                parts.append(f"{p['pool']} 池一直停在上限 {p.get('count')}/{p.get('maxCount')}")
        churn = [p for p in rec['pools'] if (p.get('distinctInstances') or 0) >= 5 * max(p.get('maxCount') or p.get('count') or 1, 1)]
        if churn:
            p = max(churn, key=lambda x: x['distinctInstances'])
            parts.append(f"{p['pool']} 池 {self.days} 天内换了 {p['distinctInstances']} 台节点")
        ev['related'] = '如同一集群在可靠性检查中有节点子网 IP 不足或扩容失败，属于同一根因。'
        every = '每天都有' if days >= with_data else f'有 {days} 天出现'
        self.add('P2', sev, c['id'], AKS_TYPE, c['name'], e,
                 f"集群 {c['name']} {self.days} 天里{every}无法调度的 Pod（自动缩放器统计平均 {us['avg']} 个、最高 {us['highestDailyMax']} 个）"
                 + ('：' + '；'.join(parts) if parts else '') + '。',
                 ev,
                 '先确认自动缩放能否扩容（节点子网可用 IP、vCPU 配额、maxCount），否则新节点无法加入；'
                 '然后提高停在上限的节点池的 maxCount，并检查等待最多的命名空间中工作负载的 requests 是否过大、是否限定了只能落到某个池（nodeSelector/亲和性）；'
                 '评估频繁增删节点的池的缩容参数（scale-down-unneeded-time 等）。' + UNCHANGED,
                 '需确认等待调度是否影响业务任务时效', key=f"scheduling|{c['name']}")

    def cluster_tier(self, c):
        tier = (c.get('sku') or {}).get('tier')
        if tier:
            return tier
        for r in (self.rel_load('arg/aks.json') or {}).get('rows') or []:
            if r.get('id', '').lower() == c['id'].lower():
                return (r.get('sku') or {}).get('tier')
        return None

    def p2_apiserver(self, c, apic):
        tier = self.cluster_tier(c)
        free = tier == 'Free'
        self.add('P2', '中', c['id'], AKS_TYPE, c['name'], self.env_of(c['id'], c['name'], c.get('tags')),
                 f"集群 {c['name']} 的 API Server CPU 平均 {apic['avg']}%，有 {apic['daysMaxGE']} 天日最高≥95%（最高 {apic['highestDailyMax']}%），"
                 + ('控制平面为 Free 层，' if free else '') + '资源受限时 kubectl、控制器和 CI/CD 部署会变慢或超时。',
                 {'apiserver_cpu_usage_percentage': apic, 'controlPlaneTier': tier},
                 ('升级到 Standard 层（控制平面可随负载扩展）；' if free else '')
                 + '排查频繁 LIST/WATCH 的组件（如集群管理代理、监控采集）并降低频率。' + UNCHANGED, None, key=f"apiserver|{c['name']}")

    # ------------------------------------------------------------------ P3 SNAT (reliability metrics)
    def p3_snat(self):
        out = []
        for fn in ('lb-snat.json', 'natgw.json'):
            for x in self.rel_load(f'metrics/{fn}') or []:
                values = ((x.get('snatConn') or {}).get('data') or {}).get('value') or []
                tot = defaultdict(float)
                for v in values:
                    for ts in v.get('timeseries') or []:
                        state = next((m.get('value') for m in ts.get('metadatavalues') or []), 'all')
                        for pt in ts.get('data') or []:
                            tot[state] += pt.get('total') or 0
                out.append({'resource': x['name'], 'resourceGroup': rg_of(x['id']), 'subscriptionName': self.data.subname(x['id']),
                            'kind': 'LB' if fn.startswith('lb') else 'NATGW', 'byState': {k: int(v) for k, v in tot.items()}})
        self.inv['snat'] = out
        notes = self.cov['P3']['notes']
        if not out:
            notes.append('未找到可靠性检查的 SNAT 指标，本项未检查。')
            return
        worst = sorted(((sum(v for k, v in o['byState'].items() if 'fail' in k.lower()), sum(o['byState'].values()), o)
                        for o in out if sum(o['byState'].values())), key=lambda t: -(t[0] / t[1]))
        notes.append('复用可靠性检查已读取的 SNAT 指标，未新增调用。')
        if worst:
            failed, total, o = worst[0]
            notes.append(f"SNAT 失败比例最高：{o['resource']}（{o['resourceGroup']}）{failed:,}/{total:,}（{failed / total * 100:.4f}%）。")
            if failed / total < 0.01:
                notes.append('所有负载均衡和 NAT 网关的出站 SNAT 失败可忽略，没有端口耗尽。')
            else:
                o_env = env(self.cfg, o['subscriptionName'] or '', o['resource'])
                self.add('P3', '中' if is_prod(o_env) else '低', None, 'Microsoft.Network/loadBalancers' if o['kind'] == 'LB' else 'Microsoft.Network/natGateways',
                         o['resource'], o_env, f"{o['resource']} 出站 SNAT 连接失败占 {failed / total * 100:.2f}%（{failed:,}/{total:,}），可能存在端口耗尽。",
                         {'snat': o}, '为出站流量使用 NAT 网关或增加出站 IP/端口分配，并检查应用是否复用连接。' + UNCHANGED, None,
                         sub=o['subscriptionName'], rg=o['resourceGroup'])

    # ------------------------------------------------------------------ P4 / P5 databases and caches
    def p45_db(self):
        d = self.data
        maxconn = {x['id'].lower(): x for x in (d.load('db/max_connections.json') or [])}
        inv, hits, io_hits = [], [], []
        for kind, metrics in (('mysql', ['cpu_percent', 'memory_percent', 'io_consumption_percent', 'storage_percent',
                                         'active_connections', 'aborted_connections', 'total_connections', 'replication_lag']),
                              ('postgres', ['cpu_percent', 'memory_percent', 'storage_percent', 'disk_iops_consumed_percentage',
                                            'disk_bandwidth_consumed_percentage', 'active_connections', 'connections_failed',
                                            'connections_succeeded', 'physical_replication_delay_in_seconds'])):
            for r in d.rows(kind):
                rec = self.db_record(r, kind, metrics, maxconn)
                inv.append(rec)
                for m in ('cpu_percent', 'memory_percent'):
                    x = rec[m]
                    if (x['avg'] or 0) >= 80 or (x['daysMaxGE95'] or 0) >= 7:
                        hits.append(('load', r, rec, m))
                if (rec['storage_percent']['avg'] or 0) >= 80:
                    hits.append(('storage', r, rec, 'storage_percent'))
                if rec.get('peakConnPctOfMax') and rec['peakConnPctOfMax'] >= 80:
                    hits.append(('conn', r, rec, 'active_connections'))
                for m in ('io_consumption_percent', 'disk_iops_consumed_percentage', 'disk_bandwidth_consumed_percentage'):
                    x = rec.get(m)
                    if x and ((x['avg'] or 0) >= 80 or (x['daysMaxGE95'] or 0) >= 7):
                        io_hits.append((r, rec, m))
        self.inv['databases'] = inv
        for kind, r, rec, m in hits:
            self.db_finding(kind, r, rec, m)
        for r, rec, m in io_hits:
            self.db_io_finding(r, rec, m)
        self.p5_caches()
        self.cov['P5']['notes'].append(f"评估 MySQL {len(d.rows('mysql'))} 台、PostgreSQL {len(d.rows('postgres'))} 台、旧版 Redis {len(d.rows('redis'))} 个、"
                                       f"Azure Managed Redis {len(d.rows('redisenterprise'))} 个、MongoDB vCore {len(d.rows('mongoclusters'))} 个。")
        read = sum(1 for x in maxconn.values() if x.get('status') == 200)
        self.cov['P5']['notes'].append(f'max_connections 通过每台服务器一次配置读取取得：{read}/{len(maxconn)} 成功。')

    def db_record(self, r, kind, metrics, maxconn):
        d = self.data
        rid = r['id']
        rec = {'resourceName': r['name'], 'kind': kind, 'subscriptionName': d.subname(rid), 'sku': (r.get('sku') or {}).get('name'),
               'role': r.get('replicationRole'), 'environment': self.env_of(rid, r['name'], r.get('tags'))}
        for m in metrics:
            x = self.metric(kind, rid, m, 95, 80)
            rec[m] = {'avg': fmt(x.get('avg'), 2), 'highestDailyMax': fmt(x.get('maxDailyMax'), 2), 'daysMaxGE95': x.get('daysMaxGE'),
                      'total': x.get('total'), 'error': x.get('error')}
        try:
            limit = int((maxconn.get(rid.lower()) or {}).get('value'))
        except (TypeError, ValueError):
            limit = None
        rec['max_connections'] = limit
        s, _ = d.series(kind, rid, 'active_connections')
        days = d.daily(first(s))
        if limit and days:
            rec['daysActiveConnGE80pctOfMax'] = sum(1 for x in days if (x.get('max') or 0) >= 0.8 * limit)
            rec['peakConnPctOfMax'] = fmt(max((x.get('max') or 0) for x in days) / limit * 100)
        return rec

    def db_finding(self, kind, r, rec, m):
        rid, e = r['id'], rec['environment']
        db_type = f"Microsoft.DBfor{'MySQL' if rec['kind'] == 'mysql' else 'PostgreSQL'}/flexibleServers"
        if kind == 'conn':
            days = rec.get('daysActiveConnGE80pctOfMax')
            pool = ('连接数接近上限时新连接会被拒绝。建议在应用侧使用连接池并限制每实例连接数，或启用 PgBouncer（PostgreSQL 内置）；'
                    if rec['kind'] == 'postgres' else '连接数接近上限时新连接会被拒绝。建议检查应用连接池上限与空闲连接回收；')
            small = 'B1ms 规格 max_connections 只有 50，若负载持续增长建议升到 B2s/通用型。' if (rec['sku'] or '').startswith('Standard_B1') else ''
            self.add('P5', '中' if is_prod(e) and (days or 0) >= 7 else '低', rid, db_type, r['name'], e,
                     f"数据库 {r['name']}（{rec['sku']}）活动连接峰值达到 {rec['active_connections']['highestDailyMax']:.0f}，"
                     f"为 max_connections={rec['max_connections']} 的 {rec['peakConnPctOfMax']}%，{self.days} 天中有 {days} 天日峰值≥80%。",
                     {'active_connections': rec['active_connections'], 'max_connections': rec['max_connections'],
                      'daysActiveConnGE80pctOfMax': days, 'cpu_percent': rec['cpu_percent'], 'memory_percent': rec['memory_percent'],
                      'thresholds': '连接数日峰值≥ max_connections 的 80%；≥7 天且为生产定为中，偶发一天定为低。'},
                     pool + small + UNCHANGED, '峰值来源（批任务/连接泄漏）需业务方确认', key=f'conn|{rid}')
        elif kind == 'load':
            x = rec[m]
            self.add('P5', '中' if is_prod(e) else '低', rid, db_type, r['name'], e,
                     f"数据库 {r['name']} 的 {m} 平均 {x['avg']}%，{x['daysMaxGE95']} 天日最高≥95%。",
                     {m: x}, '评估升级计算规格或优化慢查询。' + UNCHANGED, None, key=f'{m}|{rid}')
        elif kind == 'storage':
            self.add('P5', '中' if is_prod(e) else '低', rid, db_type, r['name'], e,
                     f"数据库 {r['name']} 存储使用率平均 {rec['storage_percent']['avg']}%。", {'storage_percent': rec['storage_percent']},
                     '开启存储自动增长或扩容。' + UNCHANGED, None, key=f'storage|{rid}')

    def db_io_finding(self, r, rec, m):
        e, x = rec['environment'], rec[m]
        others = {k: rec[k] for k in ('disk_iops_consumed_percentage', 'disk_bandwidth_consumed_percentage', 'io_consumption_percent') if rec.get(k)}
        self.add('P4', '中' if is_prod(e) else '低', r['id'],
                 'Microsoft.DBforPostgreSQL/flexibleServers' if rec['kind'] == 'postgres' else 'Microsoft.DBforMySQL/flexibleServers', r['name'], e,
                 f"数据库 {r['name']}（{rec['sku']}）磁盘 IOPS 消耗在 {self.days} 天中有 {x['daysMaxGE95']} 天的日最高达到 {x['highestDailyMax']:.0f}%"
                 f"（{self.days} 天平均仅 {x['avg']}%），每天都有时段 IO 被限流。",
                 {**others, 'storage_percent': rec['storage_percent'], 'cpu_percent': rec['cpu_percent'], 'thresholds': '日最高≥95% 的天数≥7 天视为频繁限流。'},
                 '找出 IO 峰值时段的查询/作业（Query Store、pg_stat_statements）；若峰值影响业务，可调高存储 IOPS（Premium SSD 更大容量档、开启按需 IOPS 或改 Premium SSD v2 单独设 IOPS），'
                 '或把批量任务改到低峰并分批提交。' + UNCHANGED, '峰值作业是否影响业务需确认', key=f'db-io|{m}|{r["id"]}')

    def p5_caches(self):
        d = self.data
        inv, latency = [], []
        for kind, label, metrics in (('redis', 'redis', ['serverLoad', 'percentProcessorTime', 'usedmemorypercentage', 'evictedkeys', 'errors',
                                                         'connectedclients', 'cacheLatency']),
                                     ('redisenterprise', 'redisenterprise', ['serverLoad', 'percentProcessorTime', 'usedmemorypercentage', 'evictedkeys',
                                                                             'connectedclients', 'cacheLatency', 'operationsPerSecond']),
                                     ('mongoclusters', 'mongo', ['CpuPercent', 'MemoryPercent', 'StoragePercent', 'IOPS'])):
            for r in d.rows(kind):
                rid = r['id']
                e = self.env_of(rid, r['name'], r.get('tags'))
                rec = {'resourceName': r['name'], 'kind': kind, 'subscriptionName': d.subname(rid), 'environment': e,
                       'sku': (r.get('sku') or {}).get('name') if isinstance(r.get('sku'), dict) else None}
                for m in metrics:
                    x = self.metric(label, rid, m, 95, 80)
                    rec[m] = {'avg': fmt(x.get('avg'), 2), 'highestDailyMax': fmt(x.get('maxDailyMax'), 2), 'daysMaxGE95': x.get('daysMaxGE'),
                              'total': x.get('total'), 'error': x.get('error')}
                trend_metric = 'usedmemorypercentage' if kind != 'mongoclusters' else 'StoragePercent'
                s, _ = d.series(label, rid, trend_metric)
                days = [x for x in d.daily(first(s)) if 'avg' in x]
                if len(days) >= 14:
                    a, b = sum(x['avg'] for x in days[:7]) / 7, sum(x['avg'] for x in days[-7:]) / 7
                    slope = (b - a) / (len(days) - 7)
                    rec['trend'] = {'metric': trend_metric, 'firstWeekAvg': fmt(a), 'lastWeekAvg': fmt(b), 'perDay': fmt(slope, 2),
                                    'daysTo80pct': round((80 - b) / slope) if slope > 0 and b < 80 else None}
                inv.append(rec)
                for m in ('serverLoad', 'usedmemorypercentage', 'CpuPercent', 'MemoryPercent', 'StoragePercent'):
                    x = rec.get(m)
                    if x and ((x['avg'] or 0) >= 80 or (x['daysMaxGE95'] or 0) >= 7):
                        self.add('P5', '中' if is_prod(e) else '低', rid, kind, r['name'], e,
                                 f"{r['name']} 的 {m} 平均 {x['avg']}%，{x['daysMaxGE95']} 天日最高≥95%。", {m: x},
                                 '评估扩容或分片。' + UNCHANGED, None, key=f'{m}|{rid}')
                evicted = rec.get('evictedkeys')
                if evicted and (evicted['total'] or 0) > 0 and is_prod(e):
                    self.add('P5', '中', rid, kind, r['name'], e, f"生产缓存 {r['name']} {self.days} 天内驱逐了 {evicted['total']:.0f} 个键。",
                             {'evictedkeys': evicted}, '内存不足导致驱逐，建议扩容或调整 TTL/maxmemory 策略。' + UNCHANGED, None, key=f'evicted|{rid}')
                lat = rec.get('cacheLatency')
                if kind != 'mongoclusters' and lat and lat.get('avg') is not None:
                    latency.append((r, rec))
        self.inv['caches'] = inv
        for r, rec in latency:
            self.cache_latency_finding(r, rec)

    def cache_latency_finding(self, r, rec):
        lat, tr = rec['cacheLatency'], rec.get('trend') or {}
        if not is_prod(rec['environment']):
            return
        grow = tr.get('daysTo80pct') is not None and tr['daysTo80pct'] <= 30
        if not ((lat['avg'] or 0) >= 10000 or grow):
            return
        s, _ = self.data.series('redisenterprise' if rec['kind'] == 'redisenterprise' else 'redis', r['id'], 'cacheLatency')
        days = self.data.daily(first(s))
        fw = sum(x['avg'] for x in days[:7]) / 7 / 1000 if len(days) >= 14 else None
        lw = sum(x['avg'] for x in days[-7:]) / 7 / 1000 if len(days) >= 14 else None
        sev = '高' if grow and lw and fw and lw >= 5 * fw else ('中' if grow else '低')
        if grow:
            f = (f"生产缓存 {r['name']}（{rec['sku']}）内存使用从首周平均 {tr['firstWeekAvg']}% 涨到末周 {tr['lastWeekAvg']}%（每天约 +{tr['perDay']} 个百分点，"
                 f"按此速度约 {tr['daysTo80pct']} 天到 80%）")
            if fw is not None and lw is not None:
                f += f"，同期平台延迟指标从约 {fw:.1f} ms 升到 {lw:.1f} ms（单日最高 {lat['highestDailyMax'] / 1000:.0f} ms）"
            cc = rec.get('connectedclients') or {}
            if cc.get('avg') is not None:
                f += f"，连接数 {cc['avg']:.0f}→峰值 {cc['highestDailyMax']:.0f}"
            f += '。'
            rc = ('尽快确认内存增长来源（是否有键未设置过期时间、大键或新业务写入）；在内存到 80% 前扩容到更大规格或增加分片，并为键设置 TTL；'
                  '同时用客户端侧延迟（应用 P99）核对平台延迟升高是否已影响业务。' + UNCHANGED)
        else:
            f = f"缓存 {r['name']} 平台延迟指标 {self.days} 天平均 {lat['avg'] / 1000:.1f} ms（单日最高 {lat['highestDailyMax'] / 1000:.0f} ms），明显高于同类实例（通常 <1 ms）。"
            rc = '用客户端侧延迟核对；检查大键/慢命令（SLOWLOG）、连接数与网络路径。' + UNCHANGED
        self.add('P5', sev, r['id'], 'Microsoft.Cache/redisEnterprise' if rec['kind'] == 'redisenterprise' else 'Microsoft.Cache/Redis',
                 r['name'], rec['environment'], f,
                 {'cacheLatency_us': lat, 'cacheLatencyFirstWeekAvg_ms': fmt(fw), 'cacheLatencyLastWeekAvg_ms': fmt(lw),
                  'usedmemorypercentage': rec['usedmemorypercentage'], 'trend': tr, 'connectedclients': rec.get('connectedclients'),
                  'serverLoad': rec.get('serverLoad'), 'operationsPerSecond': rec.get('operationsPerSecond'), 'evictedkeys': rec.get('evictedkeys'),
                  'note': 'cacheLatency 为平台预览指标（单位微秒），反映服务端测得的延迟，不等同于客户端延迟。'},
                 rc, '需用应用侧延迟确认影响；内存增长是否为预期需业务方确认', key=f'cache-latency|{r["id"]}')

    # ------------------------------------------------------------------ P6 AI services
    def p6_ai(self):
        d = self.data
        deps = {x['id'].lower(): x for x in (d.load('ai/deployments.json') or [])}
        inv, throttled, idle = [], [], []
        for r in d.rows('ai'):
            rec, err = self.ai_record(r, deps)
            inv.append(rec)
            if rec['requests'] == 0 and not err:
                idle.append(r['name'])
            for x in rec['byDeployment']:
                if x['requests'] >= 1000 and ((x['pct429'] or 0) >= 1 or x['daysWith429GE1pct'] >= 1 and (x['worstDay429Pct'] or 0) >= 10):
                    throttled.append((r, rec, x))
        self.inv['aiAccounts'] = inv
        quota = self.ai_quota()
        if throttled:
            self.ai_throttling(throttled, quota)
        if quota:
            self.ai_quota_finding(quota)
        denied = sorted({d.subname(c.get('sub') or '') or c.get('sub') for c in (d.load('metrics/ai-requests.json') or {}).get('calls', [])
                         if c.get('status') == 403 and c.get('sub')})
        self.cov['P6']['notes'].append(f"评估 {len(d.rows('ai'))} 个 AI 账户（按状态码和部署拆分的请求数、按部署的响应时间、部署和区域配额）。"
                                       + (f"getBatch 对 {len(denied)} 个订阅返回 403，已改用逐资源读取：{', '.join(denied)}。" if denied else ''))
        if idle:
            self.cov['P6']['notes'].append(f"{len(idle)} 个账户在窗口内没有模型调用：{', '.join(idle)}。")

    def ai_record(self, r, deps):
        d = self.data
        rid = r['id']
        rec = {'resourceName': r['name'], 'subscriptionName': d.subname(rid), 'kind': r.get('kind'), 'region': r['location'],
               'environment': self.env_of(rid, r['name'], r.get('tags')),
               'deployments': [{'name': x['name'], 'model': (x.get('model') or {}).get('name'), 'sku': (x.get('sku') or {}).get('name'),
                                'capacityK_TPM': (x.get('sku') or {}).get('capacity')} for x in (deps.get(rid.lower()) or {}).get('deployments', [])]}
        ser, err = d.series('ai-requests', rid, 'ModelRequests')
        if err:
            rec['error'] = err
        by_dep = defaultdict(lambda: defaultdict(float))
        by_day = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
        for x in ser:
            code, name = x['dims'].get('statuscode'), x['dims'].get('modeldeploymentname')
            for p in x['data']:
                if p.get('total') and d.in_window(p['timeStamp']):
                    by_dep[name][code] += p['total']
                    by_day[name][p['timeStamp'][:10]][code] += p['total']
        lat, _ = d.series('ai-latency', rid, 'TimeToResponse')
        latency = {x['dims'].get('modeldeploymentname'): d.summarize(x['data']) for x in lat}
        rows = []
        for name, codes in by_dep.items():
            total = sum(codes.values())
            n429 = codes.get('429', 0)
            n5 = sum(v for k, v in codes.items() if str(k).startswith('5'))
            days = {day: cc for day, cc in by_day[name].items() if sum(cc.values()) >= 100}
            worst = max(((cc.get('429', 0) / sum(cc.values()), day) for day, cc in days.items()), default=(0, None))
            lt = latency.get(name) or {}
            rows.append({'deployment': name, 'requests': int(total), 'r429': int(n429), 'pct429': fmt(n429 / total * 100, 2) if total else None,
                         'r5xx': int(n5), 'pct5xx': fmt(n5 / total * 100, 2) if total else None,
                         'pct400': fmt(codes.get('400', 0) / total * 100, 1) if total else None,
                         'daysWith429GE1pct': sum(1 for cc in days.values() if cc.get('429', 0) / sum(cc.values()) >= 0.01),
                         'worstDay429Pct': fmt(worst[0] * 100, 1), 'worstDay': worst[1],
                         'timeToResponseAvgMs': fmt(lt.get('avg'), 0), 'timeToResponseHighestDailyAvgMs': fmt(lt.get('maxDailyAvg'), 0)})
        rec['byDeployment'] = sorted(rows, key=lambda x: -x['requests'])
        rec['requests'] = sum(x['requests'] for x in rows)
        return rec, err

    def ai_quota(self):
        quota, seen, odd = [], set(), 0
        for u in self.data.load('ai/usages.json') or []:
            for x in u['usages']:
                n = x['name']['value']
                if 'AccountCount' in n or not x.get('limit'):
                    continue
                key = (u['subscriptionId'], n) if '.GlobalStandard.' in n else (u['subscriptionId'], n, u['location'])
                if key in seen:
                    continue
                seen.add(key)
                if x['currentValue'] > x['limit']:
                    odd += 1
                    continue
                if x['currentValue'] / x['limit'] >= 0.8:
                    quota.append({'subscriptionName': self.data.subname(u['subscriptionId']),
                                  'location': u['location'] if '.GlobalStandard.' not in n else 'global（各区域报告相同的值）',
                                  'quota': n, 'allocated': x['currentValue'], 'limit': x['limit'], 'pct': round(x['currentValue'] / x['limit'] * 100)})
        self.inv['aiQuotaAllocatedGE80pct'] = quota
        if odd:
            self.cov['P6']['notes'].append(f'已分配量超过上限的配额行按单位不一致处理并排除：{odd} 行。')
        return quota

    def ai_throttling(self, throttled, quota):
        items = [{'resourceName': r['name'], 'subscriptionName': rec['subscriptionName'], 'region': rec['region'], **x,
                  'deploymentCapacityK_TPM': next((y['capacityK_TPM'] for y in rec['deployments'] if y['name'] == x['deployment']), None)}
                 for r, rec, x in throttled]
        top = max(items, key=lambda i: i['pct429'] or 0)
        models = sorted({i['deployment'] for i in items})
        accounts = sorted({i['resourceName'] for i in items})
        e = mixed_env([rec['environment'] for _, rec, _ in throttled])
        self.add('P6', '中', throttled[0][0]['id'], 'Microsoft.CognitiveServices/accounts', ', '.join(accounts), e,
                 f"{', '.join(models)} 部署在 {len(items)} 个账户上出现集中限流：最高的 {top['resourceName']} {self.days} 天 {top['requests']:,} 次请求中 {top['r429']} 次 429（{top['pct429']}%），"
                 f"单日最高 {top['worstDay429Pct']}%（{top['worstDay']}），同时 5xx 占 {top['pct5xx']}%，明显高于同账户其它模型（429 基本为 0）。",
                 {'items': items, 'quotaAllocatedForTheseModels': [x for x in quota if any(m in x['quota'] for m in models)],
                  'thresholds': '429 占比≥1% 或单日≥10%（日请求≥100 才计入）；其它部署 429 均 <1%。',
                  'note': '配额“已分配”指部署容量之和占订阅配额的比例，不是实际消耗。'},
                 '在调用网关或客户端上为该模型配置跨账户/跨区域的负载均衡与 429 重试退避；对比峰值分钟的 Token 用量与部署容量（TPM），必要时申请提高该模型配额或在更多账户上分摊；'
                 '把批量/离线调用改到 Batch 或低峰。' + UNCHANGED, '需确认这些限流是否造成用户可见的失败（网关是否已自动切换）',
                 sub=one_or_many(i['subscriptionName'] for i in items), rg=None,
                 members=[member(a, 'Microsoft.CognitiveServices/accounts', next(i['subscriptionName'] for i in items if i['resourceName'] == a)) for a in accounts],
                 key='ai-throttling')

    def ai_quota_finding(self, quota):
        subs = sorted({x['subscriptionName'] for x in quota if x['subscriptionName']})
        full = sorted([x for x in quota if x['pct'] >= 100], key=lambda x: -x['allocated'])
        models = {}
        for x in full:
            models.setdefault(x['quota'].split('.', 2)[-1], x['allocated'])
        examples = '、'.join(f'{m} {v:,.0f}' for m, v in list(models.items())[:3])
        self.add('P6', '低', None, 'Microsoft.CognitiveServices/locations/usages', '模型 TPM 配额',
                 mixed_env([env(self.cfg, s) for s in subs]) if subs else None,
                 f"{len(subs)} 个 AI 订阅中共 {len(quota)} 项模型配额的已分配量≥80%（其中 {len(full)} 项为 100%"
                 + (f"，如 {examples} 千 TPM 已全部分配给部署" if examples else '') + "），现有部署已无法在原订阅内再加容量。",
                 {'items': quota, 'note': '配额用量=部署容量之和/订阅配额，是“预留”而非实际消耗；实际消耗看部署的 Token 指标。'},
                 '对实际增长较快的模型提前申请配额提升，或保留部分配额作为突发余量；同时清理零调用账户上占用配额的部署。' + UNCHANGED,
                 '是否计划扩容需业务方确认', sub=one_or_many(subs), rg=None,
                 members=[member(x['quota'], 'Microsoft.CognitiveServices/locations/usages', x['subscriptionName']) for x in quota], key='ai-quota')

    # ------------------------------------------------------------------ P7 storage
    def p7_storage(self):
        d = self.data
        inv, gap = [], []
        for r in d.rows('storage'):
            rid = r['id']
            ser, err = d.series('storage-tx', rid, 'Transactions')
            t = defaultdict(float)
            for x in ser:
                for p in x['data']:
                    if p.get('total') and d.in_window(p['timeStamp']):
                        t[x['dims'].get('responsetype')] += p['total']
            tot = sum(t.values())
            thr = t.get('ServerBusyError', 0) + t.get('ClientThrottlingError', 0)
            e2e, srv = self.metric('storage-lat', rid, 'SuccessE2ELatency'), self.metric('storage-lat', rid, 'SuccessServerLatency')
            av = self.metric('storage-lat', rid, 'Availability')
            e = self.env_of(rid, r['name'], r.get('tags'))
            rec = {'resourceName': r['name'], 'subscriptionName': d.subname(rid), 'region': r['location'], 'sku': (r.get('sku') or {}).get('name'),
                   'kind': r.get('kind'), 'transactions': int(tot), 'throttled': int(thr), 'throttledPct': fmt(thr / tot * 100, 4) if tot else None,
                   'serverTimeout': int(t.get('ServerTimeoutError', 0)), 'networkError': int(t.get('NetworkError', 0)),
                   'e2eLatencyAvgMs': fmt(e2e.get('avg')), 'serverLatencyAvgMs': fmt(srv.get('avg')),
                   'availabilityAvgPct': fmt(av.get('avg'), 3), 'error': err}
            inv.append(rec)
            if (tot >= 100000 and rec['e2eLatencyAvgMs'] and rec['serverLatencyAvgMs'] is not None
                    and rec['e2eLatencyAvgMs'] - rec['serverLatencyAvgMs'] >= 100 and rec['e2eLatencyAvgMs'] >= 5 * max(rec['serverLatencyAvgMs'], 1)):
                gap.append((r, rec, e))
            if tot and thr / tot > 0.001:
                self.add('P7', '高' if is_prod(e) else '中', rid, 'Microsoft.Storage/storageAccounts', r['name'], e,
                         f"存储账户 {r['name']} 有 {thr / tot * 100:.2f}% 的请求被限流。", rec, '分散分区键/前缀，或拆分账户。' + UNCHANGED, None,
                         key=f'storage-throttle|{rid}')
        self.inv['storage'] = inv
        if gap:
            items = [{**rec, 'gapMs': fmt(rec['e2eLatencyAvgMs'] - rec['serverLatencyAvgMs'])} for _, rec, _ in gap]
            top = max(items, key=lambda i: i['transactions'])
            self.add('P7', '低', gap[0][0]['id'], 'Microsoft.Storage/storageAccounts', ', '.join(i['resourceName'] for i in items),
                     mixed_env([e for _, _, e in gap]),
                     f"{len(items)} 个高流量存储账户的端到端延迟远高于服务端处理时间，例如 {top['resourceName']}（{self.days} 天 {top['transactions']:,} 次请求）"
                     f"端到端平均 {top['e2eLatencyAvgMs']} ms、服务端仅 {top['serverLatencyAvgMs']} ms，差值主要花在客户端与网络传输上；存储本身没有限流。",
                     {'items': items, 'thresholds': f'端到端-服务端≥100 ms 且端到端≥服务端 5 倍，{self.days} 天请求≥10 万。',
                      'note': '大文件下载、客户端在公网/跨区域、客户端处理慢都会拉大差值；服务端延迟与可用性均正常。'},
                     '确认主要调用方位置：若为客户端经公网下载大文件，可考虑用 Front Door/CDN 缓存热点对象；若为 Azure 内同区域服务，检查客户端并发与重试设置、是否走了公网而非私有终结点。' + UNCHANGED,
                     '调用方位置与文件大小需业务方确认', sub=one_or_many(i['subscriptionName'] for i in items), rg=None,
                     members=[member(i['resourceName'], 'Microsoft.Storage/storageAccounts', i['subscriptionName']) for i in items], key='storage-latency-gap')
        shares = d.load('storage/premium-shares.json') or []
        self.cov['P7']['notes'].append(f"评估 {len(d.rows('storage'))} 个存储账户（按响应类型的事务数、端到端/服务端延迟、可用性）。")
        if shares:
            self.cov['P7']['notes'].append('Premium 文件共享：' + '；'.join(
                f"{a['account']}：{a['shareCount']} 个共享，配额 {sum((s.get('quotaGiB') or 0) for s in a['shares'])} GiB，"
                f"已用 {sum((s.get('usageBytes') or 0) for s in a['shares']) / 2**30:.2f} GiB" for a in shares) + '（预配过多属于成本问题，不是性能问题）。')

    # ------------------------------------------------------------------ P8 placement
    def bandwidth(self):
        data = self.data.load('cost/bandwidth-month.json')
        if data is None:
            return None, []
        return data.get('month'), data.get('results') or []

    def p8_placement(self):
        d = self.data
        month, cost = self.bandwidth()
        inter, by_res, total_inter = [], [], 0.0
        for x in cost:
            for r in x['rows']:
                meter, sub = r.get('Meter') or '', r.get('MeterSubCategory') or ''
                if x['grouping'][0] == 'MeterSubCategory' and ('Inter-Region' in sub or 'Inter Continent' in meter or 'Intra Continent' in meter or 'Global' in sub):
                    total_inter += r['Cost']
                    inter.append({'subscription': x['subscription'], 'meterSubCategory': sub, 'meter': meter,
                                  'costUSD': round(r['Cost'], 2), 'quantityGB': round(r['UsageQuantity'], 1)})
                if x['grouping'][0] == 'ResourceId' and ('Inter Continent' in meter or 'Intra Continent' in meter) and r['Cost'] >= 1:
                    by_res.append({'subscription': x['subscription'], 'resourceId': r.get('ResourceId') or '',
                                   'resource': (r.get('ResourceId') or '').split('/')[-1], 'meter': meter,
                                   'costUSD': round(r['Cost'], 2), 'quantityGB': round(r['UsageQuantity'], 1)})
        self.inv['interRegionTransfer'] = {'month': month, 'totalUSD': round(total_inter, 2), 'rows': sorted(inter, key=lambda r: -r['costUSD']),
                                           'byResource': sorted(by_res, key=lambda r: -r['costUSD'])}
        loc = {r['id']: r['location'] for r in d.rows('alllocs')}
        vloc = {r['id']: r['location'] for r in d.rows('vnetloc')}
        xpe = [p['name'] for p in d.rows('pe') if loc.get((p['target'] or '').lower()) and loc[(p['target'] or '').lower()] != p['location']]
        xpeer = [f"{pr['name']}/{pr['peering']}" for pr in d.rows('peerings')
                 if vloc.get((pr['remote'] or '').lower()) and vloc[(pr['remote'] or '').lower()] != pr['location']]
        dangling = [p['name'] for p in d.rows('pe') if p['target'] and p['target'].lower() not in loc]
        app = defaultdict(set)
        for a in d.rows('aks'):
            app[a['subscriptionId']].add(a['location'])
        for v in d.rows('vms'):
            if v.get('power') == 'PowerState/running':
                app[v['subscriptionId']].add(v['location'])
        mism = [{'resource': r['name'], 'type': t, 'region': r['location'], 'appRegions': sorted(app[r['subscriptionId']])}
                for t in ('mysql', 'postgres', 'redis', 'redisenterprise', 'mongoclusters', 'storage') for r in d.rows(t)
                if app.get(r['subscriptionId']) and r['location'] not in app[r['subscriptionId']]]
        ai_regions = Counter(r['location'] for r in d.rows('ai'))
        self.inv['placement'] = {'crossRegionPrivateEndpoints': xpe, 'crossRegionPeerings': xpeer, 'privateEndpointsToDeletedResources': dangling,
                                 'dataServicesWithoutSameRegionCompute': mism, 'aiAccountRegions': dict(ai_regions),
                                 'appRegionsBySubscription': {d.subname(k): sorted(v) for k, v in app.items()}}
        self.p8_cross_continent_vms(by_res, month, ai_regions)
        notes = self.cov['P8']['notes']
        if month is None:
            notes.append('未取得带宽费用数据，跨区域传输费用未检查。')
        else:
            notes.append(f'{len(cost) // 2} 个带宽/虚拟网络费用最高的订阅在 {month} 的跨区域/跨洲传输费用合计 USD {total_inter:,.2f}。')
        notes.append(f'跨区域对等 {len(xpeer)} 个，跨区域私有终结点 {len(xpe)} 个，没有同订阅同区域计算资源的数据服务 {len(mism)} 个。')
        if dangling:
            notes.append(f'{len(dangling)} 个私有终结点指向已不存在的资源（清理项，不影响性能）。')

    def p8_cross_continent_vms(self, by_res, month, ai_regions):
        vms = {v['id'].lower(): v for v in self.data.rows('vms')}
        hits = [x for x in by_res if 'Inter Continent' in x['meter'] and x['costUSD'] >= CROSS_CONTINENT_MIN_USD
                and '/microsoft.compute/virtualmachines/' in x['resourceId'].lower()]
        if not hits:
            return
        names = [x['resource'] for x in hits]
        codes = sorted({(vms.get(x['resourceId'].lower()) or {}).get('location') or '-' for x in hits})
        regions = [self.cfg.region(c) for c in codes]
        gb, usd = sum(x['quantityGB'] for x in hits), sum(x['costUSD'] for x in hits)
        month_text = f'{int(month[5:7])} 月' if month else '本月'
        far = [self.cfg.region(k) for k in sorted(ai_regions) if k not in codes]
        f = f"虚拟机 {', '.join(names)}（{', '.join(regions)}）{month_text}跨洲出站 {gb:,.0f} GB（约 USD {usd:,.0f}）"
        if far:
            f += f"；AI 账户位于 {', '.join(far)}，如这些虚拟机是调用 AI 账户或其他远端服务的网关，每次调用多一段跨洲往返（估计 150–250 ms）"
        f += '。'
        self.add('P8', '低', hits[0]['resourceId'], VM_TYPE, ', '.join(names),
                 mixed_env([self.env_of(x['resourceId'], x['resource'], (vms.get(x['resourceId'].lower()) or {}).get('tags')) for x in hits]),
                 f, {'interContinentEgress': hits, 'aiAccountRegions': dict(ai_regions),
                     'note': '往返时延为公开网络经验值估计，未实测；费用来自 Cost Management 实际费用。'},
                 '若对首字节延迟敏感，可把这些虚拟机部署到与主要被调用服务同区域，或把常用模型部署到离调用方更近且可用的区域；否则维持现状即可。' + UNCHANGED,
                 '调用方对延迟的敏感程度需业务方确认', sub=one_or_many(x['subscription'] for x in hits), rg=None,
                 members=[member(x['resource'], VM_TYPE, x['subscription']) for x in hits], key='cross-continent-vms')

    # ------------------------------------------------------------------ P9 entry points
    def status_counts(self, label, rid, dim, metric):
        g, by_day = defaultdict(float), defaultdict(lambda: defaultdict(float))
        ser, _ = self.data.series(label, rid, metric)
        for x in ser:
            for p in x['data']:
                if p.get('total') and self.data.in_window(p['timeStamp']):
                    g[x['dims'].get(dim)] += p['total']
                    by_day[p['timeStamp'][:10]][x['dims'].get(dim)] += p['total']
        return g, by_day

    def p9_edge(self):
        inv = {'appGateways': [], 'frontDoors': [], 'loadBalancers': []}
        self.p9_appgw(inv)
        self.p9_frontdoor(inv)
        self.p9_lb(inv)
        self.inv['edge'] = inv
        self.cov['P9']['notes'].append('AKS 负载均衡在 externalTrafficPolicy=Local 时 DipAvailability 低于 100% 属正常，改用按前端拆分的 VipAvailability 判断。')

    def p9_appgw(self, inv):
        d = self.data
        single = []
        for r in d.rows('appgw'):
            rid = r['id']
            e = self.env_of(rid, r['name'], r.get('tags'))
            cu = self.metric('appgw', rid, 'CapacityUnits', 8)
            g, by_day = self.status_counts('appgw-status', rid, 'httpstatusgroup', 'ResponseStatus')
            tot = sum(g.values())
            uh, _ = d.series('appgw-health', rid, 'UnhealthyHostCount')
            hh, _ = d.series('appgw-health', rid, 'HealthyHostCount')
            healthy = {x['dims'].get('backendsettingspool'): d.summarize(x['data']) for x in hh}
            unhealthy = [{'backend': x['dims'].get('backendsettingspool'), 'unhealthyAvg': fmt(d.summarize(x['data']).get('avg'), 2),
                          'daysWithUnhealthy': d.summarize(x['data'], 1).get('daysMaxGE'),
                          'healthyAvg': fmt((healthy.get(x['dims'].get('backendsettingspool')) or {}).get('avg'), 2),
                          'healthyMax': (healthy.get(x['dims'].get('backendsettingspool')) or {}).get('maxDailyMax')}
                         for x in uh if (d.summarize(x['data']).get('maxDailyMax') or 0) > 0]
            rec = {'resourceName': r['name'], 'subscriptionName': d.subname(rid), 'sku': (r.get('sku') or {}).get('name'),
                   'fixedCapacity': (r.get('sku') or {}).get('capacity'), 'autoscale': r.get('autoscale'),
                   'capacityUnitsAvg': fmt(cu.get('avg'), 2), 'capacityUnitsHighestDailyMax': fmt(cu.get('maxDailyMax'), 2),
                   'daysCUGE8': cu.get('daysMaxGE'), 'requests': int(tot), 'statusGroups': {k: int(v) for k, v in g.items()},
                   'pct5xx': fmt(g.get('5xx', 0) / tot * 100, 2) if tot else None, 'unhealthyBackends': unhealthy,
                   'days5xxGE1pct': sum(1 for c in by_day.values() if sum(c.values()) >= 100 and c.get('5xx', 0) / sum(c.values()) >= 0.01)}
            inv['appGateways'].append(rec)
            if tot and g.get('5xx', 0) / tot >= 0.01 and is_prod(e):
                worst = max(by_day.items(), key=lambda kv: kv[1].get('5xx', 0) / max(sum(kv[1].values()), 1))
                self.add('P9', '中', rid, 'Microsoft.Network/applicationGateways', r['name'], e,
                         f"应用网关 {r['name']} {self.days} 天 {int(tot):,} 个响应中 5xx 占 {rec['pct5xx']}%（{int(g.get('5xx', 0)):,} 个），{rec['days5xxGE1pct']} 天 5xx≥1%，"
                         f"最高一天 {worst[0]} 为 {worst[1].get('5xx', 0) / sum(worst[1].values()) * 100:.1f}%；另外 4xx 占 {g.get('4xx', 0) / tot * 100:.0f}%。",
                         {**rec, 'thresholds': '5xx≥1% 为需关注。'},
                         '用访问日志（ApplicationGatewayAccessLog）按后端与 URL 定位 5xx 来源（后端超时 502/504 还是后端返回 500）；同时核对大量 4xx 是否为 WAF 拦截或扫描流量。' + UNCHANGED,
                         '5xx 是否被用户感知需确认', key=f'appgw-5xx|{rid}')
            if rec['fixedCapacity'] == 1 and not r.get('autoscale') and (cu.get('daysMaxGE') or 0) >= 1:
                single.append((r, rec, e))
            dead = [u for u in unhealthy if (u['daysWithUnhealthy'] or 0) >= 7 and not u['healthyMax']]
            if dead:
                backends = ', '.join(u['backend'] for u in dead)
                self.add('P9', '中' if is_prod(e) else '低', rid, 'Microsoft.Network/applicationGateways', r['name'], e,
                         f"应用网关 {r['name']} 的后端 {backends} 在 {self.days} 天里一直没有健康实例（健康 0、不健康 {dead[0]['unhealthyAvg']:.0f}，持续 {dead[0]['daysWithUnhealthy']} 天），"
                         f"经该监听器/规则的请求无法被正常转发。",
                         {'unhealthyBackends': dead, 'gateway': rec['resourceName'], 'requests': rec['requests'], 'statusGroups': rec['statusGroups'],
                          'thresholds': f'后端健康实例数 {self.days} 天内始终为 0 且不健康实例≥1 持续≥7 天。'},
                         f'确认后端设置 {backends} 对应的监听器是否仍在使用：不用则删除监听器/规则/后端设置；仍在使用则检查后端服务端口、证书和健康探测配置。' + UNCHANGED,
                         '该监听器是否仍有业务流量需确认', key=f'appgw-dead-backend|{rid}')
            elif unhealthy:
                self.cov['P9']['notes'].append(f"{r['name']}：后端偶发不健康 {unhealthy}")
        if single:
            items = [rec for _, rec, _ in single]
            busiest = max(items, key=lambda i: i['daysCUGE8'])
            self.add('P9', '低', single[0][0]['id'], 'Microsoft.Network/applicationGateways', ', '.join(i['resourceName'] for i in items),
                     mixed_env([e for _, _, e in single]),
                     f"{len(items)} 台固定 1 个实例的应用网关容量单位在峰值时达到 {span([fmt(i['capacityUnitsHighestDailyMax']) for i in items])}（单实例约可承载 10 个容量单位），"
                     f"其中 {busiest['resourceName']} 有 {busiest['daysCUGE8']} 天峰值≥8；平时平均仅 {span([fmt(i['capacityUnitsAvg']) for i in items])}。",
                     {'items': items, 'thresholds': 'v2 单实例约 10 个容量单位；日最高≥8（80%）计为接近上限。',
                      'related': '可靠性检查中单实例应用网关的建议（开启自动缩放、至少 2 个实例）与此一致。'},
                     '改为自动缩放（最小 2、最大按峰值留余量），可同时解决单实例故障与峰值容量问题。' + UNCHANGED, None,
                     sub=one_or_many(i['subscriptionName'] for i in items), rg=None,
                     members=[member(i['resourceName'], 'Microsoft.Network/applicationGateways', i['subscriptionName']) for i in items],
                     key='appgw-single-instance-capacity')

    def p9_frontdoor(self, inv):
        d = self.data
        for r in d.rows('frontdoor'):
            rid = r['id']
            e = self.env_of(rid, r['name'], r.get('tags'))
            g, by_day = self.status_counts('afd-req', rid, 'httpstatusgroup', 'RequestCount')
            tot = sum(g.values())
            oh, _ = d.series('afd-originhealth', rid, 'OriginHealthPercentage')
            origins = [{'origin': x['dims'].get('origin'), 'avgHealthPct': fmt(d.summarize(x['data']).get('avg'), 2),
                        'daysAvgBelow99': sum(1 for day in d.daily(x['data']) if day.get('avg') is not None and day['avg'] < 99)} for x in oh]
            tl, ol = self.metric('afd-lat', rid, 'TotalLatency'), self.metric('afd-lat', rid, 'OriginLatency')
            rec = {'resourceName': r['name'], 'subscriptionName': d.subname(rid), 'sku': (r.get('sku') or {}).get('name'), 'requests': int(tot),
                   'statusGroups': {k: int(v) for k, v in g.items()}, 'pct5xx': fmt(g.get('5XX', 0) / tot * 100, 2) if tot else None,
                   'days5xxGE1pct': sum(1 for c in by_day.values() if sum(c.values()) >= 100 and c.get('5XX', 0) / sum(c.values()) >= 0.01),
                   'totalLatencyAvgMs': fmt(tl.get('avg')), 'originLatencyAvgMs': fmt(ol.get('avg')), 'origins': origins}
            inv['frontDoors'].append(rec)
            bad = [o for o in origins if o['avgHealthPct'] is not None and o['avgHealthPct'] < 99 and o['daysAvgBelow99'] >= 7]
            if tot < 10000:
                continue
            has5 = g.get('5XX', 0) / tot >= 0.01
            if not (has5 or bad):
                continue
            if 'test' in r['name'].lower() and is_prod(e):
                e = {**e, 'basis': f"{e.get('basis')}，但名称含 test，需确认"}
            parts, ev = [], dict(rec)
            if has5:
                worst = sorted(((day, c.get('5XX', 0), sum(c.values())) for day, c in by_day.items() if c.get('5XX', 0) / max(sum(c.values()), 1) >= 0.01),
                               key=lambda t: -t[1])
                ev['worstDays'] = [{'date': day, 'r5xx': int(n), 'requests': int(t)} for day, n, t in worst[:10]]
                if len(worst) <= 3:
                    parts.append(f"{self.days} 天 {int(tot):,} 个请求中 5xx 占 {rec['pct5xx']}%，主要集中在 "
                                 + '、'.join(f'{day}（{int(n):,}/{int(t):,}）' for day, n, t in worst[:2]) + '，其余日期基本正常')
                else:
                    parts.append(f"{self.days} 天 {int(tot):,} 个请求中 5xx 占 {rec['pct5xx']}%，有 {len(worst)} 天 5xx≥1%")
            if bad:
                parts.append('源站健康探测长期不足 100%：' + '；'.join(f"{o['origin']} 平均 {o['avgHealthPct']}%（{o['daysAvgBelow99']} 天<99%）" for o in bad)
                             + ('' if has5 else f"，同期 {int(tot):,} 个请求中 5xx 仅 {rec['pct5xx']}%"))
            ev['thresholds'] = '5xx≥1%（日请求≥100 才计入单日）；源站健康平均<99% 且≥7 天。'
            recs = []
            if has5:
                recs.append('对照 5xx 集中日期的变更/发布与后端网关、源站日志确认原因，并为源站组配置至少两个源以便单源故障时自动切换')
            if bad:
                recs.append('检查健康探测路径/协议/主机头是否与源站匹配（探测失败但业务正常多为探测配置问题），若源站确实间歇不可用，检查后端容量与 Private Link 连接')
            self.add('P9', '中' if is_prod(e) else '低', rid, 'Microsoft.Cdn/profiles', r['name'], e, f"Front Door {r['name']} " + '；'.join(parts) + '。', ev,
                     '；'.join(recs) + '。' + UNCHANGED, '这些日期是否有已知事件、探测失败是否影响业务需确认', key=f'afd|{rid}')
        idle = [x['resourceName'] for x in inv['frontDoors'] if x['requests'] == 0]
        if idle:
            self.cov['P9']['notes'].append(f"窗口内没有请求的 Front Door：{', '.join(idle)}（未使用的配置，属于清理/成本问题）。")

    def p9_lb(self, inv):
        d = self.data
        zero, partial = [], []
        cluster_of = {(a.get('nodeRG') or '').lower(): a['name'] for a in d.rows('aks')}
        for r in d.rows('lbs'):
            if ((r.get('sku') or {}).get('name') or '').lower() != 'standard':
                continue
            rid = r['id']
            e = self.env_of(rid, r['name'], r.get('tags'))
            ser, _ = d.series('lb-vip', rid, 'VipAvailability')
            fes = []
            for x in ser:
                s = d.summarize(x['data'])
                if s.get('avg') is not None:
                    fes.append({'frontend': f"{x['dims'].get('frontendipaddress')}:{x['dims'].get('frontendport')}", 'avgPct': fmt(s['avg'], 1), 'days': s.get('days')})
            bad = [f for f in fes if f['avgPct'] < 99]
            cluster = cluster_of.get((r.get('resourceGroup') or '').lower(), r.get('resourceGroup'))
            if cluster_of.get((r.get('resourceGroup') or '').lower()):
                # AKS-managed load balancer: the cluster decides the environment
                aks = next(a for a in d.rows('aks') if a['name'] == cluster)
                e = self.env_of(aks['id'], aks['name'], aks.get('tags'))
            inv['loadBalancers'].append({'resourceName': r['name'], 'resourceGroup': r.get('resourceGroup'), 'subscriptionName': d.subname(rid),
                                         'frontends': len(fes), 'frontendsBelow99': bad})
            for f in bad:
                item = {'loadBalancer': r['name'], 'resourceGroup': r.get('resourceGroup'), 'cluster': cluster, 'subscriptionName': d.subname(rid),
                        'environment': e, 'resourceName': f"{cluster}/{r['name']}", **f}
                (zero if f['avgPct'] == 0 else partial).append((r, item))
        prod_zero = [(r, i) for r, i in zero if is_prod(i['environment'])]
        other = [(r, i) for r, i in zero if not is_prod(i['environment'])] + partial
        lb_type = 'Microsoft.Network/loadBalancers'
        if prod_zero:
            items = [i for _, i in prod_zero]
            ports = Counter(i['frontend'].rsplit(':', 1)[-1] for i in items)
            self.add('P9', '中', prod_zero[0][0]['id'], lb_type, ', '.join(sorted({i['cluster'] for i in items})), mixed_env([i['environment'] for i in items]),
                     f"{len({i['cluster'] for i in items})} 个生产集群的负载均衡器上有 {len(items)} 个前端端口 {self.days} 天可用性一直为 0%"
                     f"（端口：{'、'.join(f'{p} ×{n}' for p, n in ports.most_common())}），说明这些 Service 后面没有任何健康的 Pod 在响应。",
                     {'items': [{k: v for k, v in i.items() if k != 'environment'} for i in items],
                      'metric': f'VipAvailability（数据路径可用性）按前端 IP/端口拆分，{self.days} 天平均。',
                      'note': 'DipAvailability（后端探测）在 externalTrafficPolicy=Local 的 Service 上低于 100% 属正常，未据此判断。'},
                     '逐个核对对应的 Kubernetes Service（按这些 IP/端口找到 Service）：若端口已不再使用，删除该端口或 Service，避免客户端误连失败并减少公网暴露；'
                     '若仍在使用，检查对应 Pod 是否在监听该端口以及健康探测配置。' + UNCHANGED,
                     '这些端口是否仍有客户端使用需确认', sub=one_or_many(i['subscriptionName'] for i in items), rg=None,
                     members=[member(n, lb_type, s) for n, s in sorted({(i['loadBalancer'], i['subscriptionName']) for i in items})], key='lb-zero-prod')
        if other:
            items = [i for _, i in other]
            nonprod_zero = sum(1 for i in items if i['avgPct'] == 0)
            low = [i for i in items if i['avgPct'] > 0]
            text = f"另有 {len(items)} 个负载均衡前端可用性低于 99%"
            if nonprod_zero:
                text += f"：非生产集群 {nonprod_zero} 个为 0%"
            if low:
                text += ('，' if nonprod_zero else '：') + '；'.join(f"{i['cluster']} 的 {i['frontend']} 平均 {i['avgPct']}%" for i in low[:3])
            self.add('P9', '低', other[0][0]['id'], lb_type, ', '.join(sorted({i['cluster'] for i in items})), mixed_env([i['environment'] for i in items]),
                     text + '。', {'items': [{k: v for k, v in i.items() if k != 'environment'} for i in items]},
                     '同上，清理不用的 Service 端口；仍在使用的端口检查对应 ingress/Pod 的就绪情况。' + UNCHANGED, None,
                     sub=one_or_many(i['subscriptionName'] for i in items), rg=None,
                     members=[member(n, lb_type, s) for n, s in sorted({(i['loadBalancer'], i['subscriptionName']) for i in items})], key='lb-low-other')

    # ------------------------------------------------------------------ P10 Advisor
    def p10_advisor(self):
        advisor = self.rel_load('advisor-all.json')
        notes = self.cov['P10']['notes']
        if advisor is None:
            notes.append('未找到可靠性检查读取的 Advisor 建议，本项未检查。')
            return
        perf = [a for a in advisor.get('recommendations', []) if a['properties']['category'] == 'Performance']
        groups = defaultdict(list)
        for a in perf:
            p = a['properties']
            groups[advisor_problem(a, ADVISOR_NO_TEXT)].append({
                'subscriptionName': a.get('_subscriptionName'), 'impact': p.get('impact'), 'resourceType': p.get('impactedField'),
                'resourceName': p.get('impactedValue'),
                'extended': {k: v for k, v in (p.get('extendedProperties') or {}).items()
                             if k in ('K8sVersion', 'Reason', 'language', 'CurrentVersion', 'recommendationSubCategory')}})
        self.inv['advisorPerformance'] = dict(groups)
        notes.append(f'复用可靠性检查读取的 Advisor 建议：性能类 {len(perf)} 条，{len(groups)} 种，未新增调用。')
        for problem, items in groups.items():
            names = sorted({i['resourceName'] for i in items})
            subs = one_or_many(i['subscriptionName'] for i in items)
            if 'Kubernetes version' in problem:
                notes.append(f"“{problem}” ×{len(items)}（{', '.join(names)}）：与可靠性检查的版本问题重复，不重复列出。")
            elif 'SDK version' in problem:
                notes.append(f"“{problem}” ×{len(items)}：管理工具使用的 SDK/API 版本，不影响运行性能，不列为问题。")
            elif 'table stats reset' in problem:
                i = items[0]
                pg = next((r for r in self.data.rows('postgres') if r['name'] == i['resourceName']), None)
                self.add('P10', '低', pg['id'] if pg else None, 'Microsoft.DBforPostgreSQL/flexibleServers', i['resourceName'],
                         self.env_of(pg['id'], pg['name'], pg.get('tags')) if pg else env(self.cfg, i['subscriptionName'] or '', i['resourceName']),
                         f"Azure Advisor（高影响）提示 PostgreSQL {i['resourceName']} 的表统计信息被重置，可能导致自动 VACUUM/ANALYZE 判断失准、执行计划变差。",
                         {'advisor': items}, '在低峰对主要库执行 ANALYZE，并确认没有定期调用 pg_stat_reset；观察慢查询是否改善。' + UNCHANGED, None,
                         sub=i['subscriptionName'], rg=rg_of(pg['id']) if pg else None, key=f"advisor-pg-stats|{i['resourceName']}")
            elif 'current generation virtual machines' in problem:
                examples = '、'.join(names[:4])
                self.add('P10', '低', None, VM_TYPE, ', '.join(names), mixed_env([env(self.cfg, i['subscriptionName'] or '', i['resourceName']) for i in items]),
                         f"Azure Advisor 建议 {len(items)} 台虚拟机（{len(names)} 个名称，如 {examples}）从 v3 等旧代规格换到当前代规格，同价位性能更好。",
                         {'advisor': items}, '结合下一次维护窗口把 D*s_v3 换成 D*s_v5/v6（需重启）；先在一台上验证。' + UNCHANGED, None,
                         sub=subs, rg=None, members=[member(i['resourceName'], VM_TYPE, i['subscriptionName']) for i in items], key='advisor-vm-generation')
            elif 'Premium SSD v2' in problem:
                self.add('P10', '低', None, 'Microsoft.Compute/disks', ', '.join(f"{i['subscriptionName']}/{i['resourceName']}" for i in items),
                         mixed_env([env(self.cfg, i['subscriptionName'] or '', i['resourceName']) for i in items]),
                         f"Azure Advisor 建议 {len(items)} 块数据盘改用 Premium SSD v2（可单独设定 IOPS/吞吐，通常更便宜）。",
                         {'advisor': items}, '对 IO 峰值经常打满的数据盘优先评估（见 P4）；迁移需快照+新建盘。' + UNCHANGED, None,
                         sub=subs, rg=None, members=[member(i['resourceName'], 'Microsoft.Compute/disks', i['subscriptionName']) for i in items],
                         key='advisor-premium-ssd-v2')
            else:
                notes.append(f"“{problem}” ×{len(items)}：仅供参考。")

    # ------------------------------------------------------------------ run
    def run(self):
        self.coverage_from_index()
        self.p1_p4_vms()
        self.p2_aks()
        self.p3_snat()
        self.p45_db()
        self.p6_ai()
        self.p7_storage()
        self.p8_placement()
        self.p9_edge()
        self.p10_advisor()
        self.F.items.sort(key=lambda f: (SEV_ORDER[f['severity']], int(f['check'][1:]), f['resourceName'] or ''))
        for i, f in enumerate(self.F.items, 1):
            f['legacyId'] = f'PERF-{i:03d}'
        disabled = [s['name'] for s in self.subs if s.get('state') != 'Enabled']
        self.limits = [
            '按日粒度汇总：日最大值是当天最高的 1 分钟值，峰值天数表示触到上限的频率，不表示持续时长。',
            'AKS 平台指标最粗 12 小时粒度；Pod 级历史（等待调度、OOM）只在启用 Container Insights 的集群上有，且受工作区保留期限制。',
            '自动缩放节点池的节点数历史按每小时上报 CPU 的实例数近似（同一小时内替换节点会使数量偏大）。',
            '数据盘消耗百分比未按 LUN 拆分（取合并值）。',
            'AI 配额“用量”是部署容量占配额的比例，不是实际消耗。',
            'Azure Managed Redis 的 cacheLatency 是平台预览指标（微秒），不等于客户端观测到的延迟。',
            '未做压测，也未连接客户的任何业务端点；未修改任何配置。']
        if disabled:
            self.limits.append(f'{len(disabled)} 个未启用的订阅无法读取，未检查。')
        manifest = self.raw.load('manifest.json')
        scope = {'subscriptions': len(self.subs), 'enabled': len(self.subs) - len(disabled), 'notInspected': disabled}
        data = self.F.write(self.ws, window={**self.window, 'collectedAt': manifest.get('collectedAt'),
                                             'method': '持续负载=窗口内按样本数加权的平均值；峰值=日最大值达到阈值的天数及最高日最大值。'},
                            coverage=self.cov, scope=scope, inventory=self.inv, limitations=self.limits)
        counts = Counter(f['severity'] for f in self.F.items)
        self.log(f"性能效率：{len(self.F.items)} 条问题（高 {counts['高']}、中 {counts['中']}、低 {counts['低']}）")
        return data


def analyze(ws, cfg, log=print):
    return Analyzer(ws, cfg, log).run()
