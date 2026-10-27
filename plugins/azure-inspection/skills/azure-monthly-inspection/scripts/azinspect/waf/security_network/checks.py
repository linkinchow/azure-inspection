"""S-N1..S-N7 rules over the offline network model and the saved PaaS configuration.

Each rule appends a draft row to Draft; analyze.py merges repetitive rows, sorts them and emits the shared format.
"""
from __future__ import annotations

import ipaddress

from ..common import env as env_of
from .network import (ADMIN_PORTS, DB_PORTS, INFRA_SUBNETS, MGMT_PORTS, NSG_UNSUPPORTED_DELEGATIONS, RISKY, endpoint_label,
                      exposure_text, lid, parts, port_match, range_size, rule_dsts, rule_ports, rule_srcs, src_is_internet)

MULTI_ENV = {'value': 'mixed', 'label': '多个环境', 'basis': '见涉及资源'}
NSG = 'Microsoft.Network/networkSecurityGroups'
SUBNET = 'Microsoft.Network/virtualNetworks/subnets'


def member(name, rtype, subscription):
    return {'name': name, 'type': rtype, 'subscription': subscription}


def is_test(e):
    return bool(e) and e.get('value') in ('test', 'dev')


class Draft:
    """Draft findings in the order the rules produce them."""

    def __init__(self, c, cfg):
        self.c, self.cfg, self.items = c, cfg, []

    def env(self, sub_id, name='', tags=None):
        return env_of(self.cfg, self.c.sub(sub_id) or '', name or '', tags)

    def add(self, check, sev, res, rtype, finding, evidence, rec, confirm=False, name=None, rg=None, sub=None, members=None, key=None):
        res = res or {}
        sub_id = sub or res.get('subscriptionId')
        rgv = rg if rg is not None else res.get('resourceGroup')
        nm = name if name is not None else res.get('name')
        sub_name = self.c.sub(sub_id) or sub_id if sub_id else '(多个订阅)'
        if members is None and nm:
            members = [member(nm, rtype, sub_name)]
        self.items.append({'check': check, 'severity': sev, 'subscriptionId': sub_id, 'subscriptionName': sub_name,
                           'resourceGroup': rgv, 'resourceName': nm, 'resourceType': rtype, 'resourceId': res.get('id'),
                           'environment': self.env(sub_id, nm, res.get('tags')) if sub_id else MULTI_ENV,
                           'finding': finding, 'evidence': evidence, 'recommendation': rec, 'needsConfirmation': confirm,
                           'members': members or [], 'key': key})


# ---------------------------------------------------------------- S-N1 subnets
def _subnet_owners(c, sp):
    o = {'vmNics': [], 'vmssCustomer': set(), 'vmssPlatform': 0, 'privateEndpoints': 0, 'pls': 0,
         'internalLb': set(), 'appGw': set(), 'other': []}
    nic_without_nsg = []
    for ic in sp.get('ipConfigurations') or []:
        i = lid(ic['id'])
        seg = parts(i)
        if '/virtualmachinescalesets/' in i:
            vmss_id = i.split('/virtualmachines/')[0]
            if vmss_id in c.vmss:
                o['vmssCustomer'].add(c.vmss[vmss_id]['name'])
            else:
                o['vmssPlatform'] += 1
        elif 'networkinterfaces' in seg:
            ep = c.ipcfg.get(i)
            if ep and ep.get('privateEndpoint'):
                o['privateEndpoints'] += 1
            elif ep and ep.get('pls'):
                o['pls'] += 1
            elif ep:
                o['vmNics'].append(endpoint_label(c, ep))
                if not ep.get('nicNsg'):
                    nic_without_nsg.append(endpoint_label(c, ep))
            else:
                o['other'].append(seg.get('networkinterfaces'))
        elif 'loadbalancers' in seg:
            o['internalLb'].add(seg['loadbalancers'])
        elif 'privatelinkservices' in seg:
            o['pls'] += 1
        elif 'applicationgateways' in seg:
            o['appGw'].add(seg['applicationgateways'])
        else:
            o['other'].append(i.split('/providers/')[-1][:120])
    return o, nic_without_nsg


def _subnet_content(oo, dele, sp):
    dp = []
    if oo['vmNics']:
        dp.append(f"VM 网卡 {len(oo['vmNics'])} 个")
    if oo['vmssCustomer']:
        dp.append(f"VMSS {', '.join(oo['vmssCustomer'])}")
    if oo['privateEndpoints']:
        dp.append(f"私有终结点 {oo['privateEndpoints']} 个")
    if oo['pls']:
        dp.append('Private Link Service')
    if oo['internalLb']:
        dp.append(f"内部负载均衡 {', '.join(oo['internalLb'])}")
    if oo['vmssPlatform']:
        dp.append(f"平台托管实例 {oo['vmssPlatform']} 个（VNet 注入的 Redis/应用网关/AGC 等）")
    if dele:
        dp.append(f"委派给 {', '.join(dele)}")
    if sp.get('serviceAssociationLinks') and not sp.get('ipConfigurations'):
        dp.append('服务关联(serviceAssociationLinks)')
    return '、'.join(dp) or '无'


def check_subnets(c, F):
    inventory, empty_by_vnet, low_by_vnet = [], {}, {}
    vmss_by_name = {(lid(v['subscriptionId']), v['name']): k for k, v in c.vmss.items()}
    for sid, s in c.subnet.items():
        sp = s.get('properties') or {}
        v = s['_vnet']
        dele = [d['properties']['serviceName'] for d in sp.get('delegations') or []]
        o, nic_without_nsg = _subnet_owners(c, sp)
        vmss_without_nsg = [nm for nm in o['vmssCustomer']
                            if not any(ep.get('nicNsg') for ep in c.vmss_eps.get(vmss_by_name.get((lid(v['subscriptionId']), nm), ''), []))]
        has_nsg = bool(c.subnet_nsg.get(sid))
        oo = {k: (sorted(x) if isinstance(x, set) else x) for k, x in o.items()}
        rec = {'vnet': v['name'], 'subnet': s['name'], 'subscription': c.sub(v['subscriptionId']),
               'resourceGroup': v['resourceGroup'], 'addressPrefix': sp.get('addressPrefix') or sp.get('addressPrefixes'),
               'nsg': (c.nsg.get(c.subnet_nsg.get(sid)) or {}).get('name') if has_nsg else None,
               'delegations': dele, 'ipConfigurationCount': len(sp.get('ipConfigurations') or []),
               'owners': {**oo, 'vmNics': oo['vmNics'][:40], 'vmNicCount': len(oo['vmNics'])},
               'vmNicsWithoutNicNsg': nic_without_nsg[:40], 'customerVmssWithoutNicNsg': vmss_without_nsg,
               'routeTable': ((sp.get('routeTable') or {}).get('id') or '').split('/')[-1] or None}
        inventory.append(rec)
        if has_nsg or s['name'].lower() in INFRA_SUBNETS or any(d.lower() in NSG_UNSUPPORTED_DELEGATIONS for d in dele):
            continue
        if not sp.get('ipConfigurations') and not sp.get('serviceAssociationLinks'):
            label = s['name'] + (f'(委派 {",".join(dele)})' if dele else '')
            empty_by_vnet.setdefault(lid(v['id']), (v, []))[1].append((s['name'], label))
            continue
        e_ = F.env(v['subscriptionId'], f'{v["name"]}-{s["name"]}', v.get('tags'))
        unprotected = nic_without_nsg + vmss_without_nsg
        content = _subnet_content(oo, dele, sp)
        if unprotected and not is_test(e_):
            F.add('S-N1', '中', None, SUBNET,
                  f'子网 {v["name"]}/{s["name"]} 未关联 NSG，子网内有 {content}；其中 {len(unprotected)} 个实例的网卡上也没有 NSG'
                  f'（如 {", ".join(unprotected[:5])}），进出这些实例的流量完全不受过滤。',
                  rec, '为该子网关联 NSG（先按现有业务端口放行，再逐步收紧）：数据库/中间件端口只允许应用子网访问，并拒绝来自 Internet 的入站。',
                  name=f'{v["name"]}/{s["name"]}', rg=v['resourceGroup'], sub=v['subscriptionId'], key=sid)
            continue
        if unprotected:
            txt = (f'子网 {v["name"]}/{s["name"]} 未关联 NSG，子网内有 {content}；其中 {len(unprotected)} 个实例的网卡上也没有 NSG'
                   f'（如 {", ".join(unprotected[:5])}），进出这些实例的流量完全不受过滤。')
        elif oo['vmNics'] or oo['vmssCustomer']:
            txt = f'子网 {v["name"]}/{s["name"]} 未关联 NSG，子网内有 {content}；这些实例在网卡层已有 NSG，风险较低，但缺少子网级的统一边界。'
        else:
            txt = f'子网 {v["name"]}/{s["name"]} 未关联 NSG，子网内为 {content}，没有普通 VM。'
        low_by_vnet.setdefault(lid(v['id']), (v, []))[1].append({'subnet': s['name'], 'contents': content, 'detail': txt, 'inventory': rec})
    for key in dict.fromkeys(list(low_by_vnet) + list(empty_by_vnet)):
        v = (low_by_vnet.get(key) or empty_by_vnet.get(key))[0]
        lows = (low_by_vnet.get(key) or (v, []))[1]
        empties = (empty_by_vnet.get(key) or (v, []))[1]
        parts_ = []
        if lows:
            parts_.append(f'{len(lows)} 个在用子网（' + '；'.join(f"{x['subnet']}：{x['contents']}" for x in lows[:8]) + ('…' if len(lows) > 8 else '') + '）')
        if empties:
            labels = [label for _, label in empties]
            parts_.append(f'{len(empties)} 个空子网（{", ".join(labels[:12])}{"…" if len(empties) > 12 else ""}）')
        sub_name = c.sub(v['subscriptionId'])
        names = [x['subnet'] for x in lows] + [n for n, _ in empties]
        F.add('S-N1', '低', None, SUBNET,
              f'VNet {v["name"]} 有 ' + '，以及 '.join(parts_) + ' 未关联 NSG；这些子网里没有“既无子网 NSG 也无网卡 NSG”的普通 VM，当前风险较低，但缺少统一的子网边界。',
              {'subnetsInUse': lows, 'emptySubnets': [label for _, label in empties]},
              '按统一基线为这些子网关联 NSG（私有终结点子网要让 NSG 生效还需开启私有终结点网络策略）；空子网投入使用前先关联 NSG，不再使用的可删除。',
              name=f'{v["name"]}（{len(lows) + len(empties)} 个子网）', rg=v['resourceGroup'], sub=v['subscriptionId'],
              members=[member(f'{v["name"]}/{n}', SUBNET, sub_name) for n in names], key=key)
    return inventory


# ---------------------------------------------------------------- S-N2 NSG rules
def _open_rules(p):
    open_rules, broad_vnet = [], []
    for r in p.get('securityRules') or []:
        q = r['properties']
        if q.get('direction') != 'Inbound' or q.get('access') != 'Allow':
            continue
        ports = rule_ports(q)
        if src_is_internet(q) and (q.get('protocol') or '*').lower() != 'icmp':
            hit = {}
            for s_ in ports:
                s_ = str(s_)
                if s_ == '*':
                    hit['*'] = '任意端口'
                    continue
                lo, hi_ = s_.split('-', 1) if '-' in s_ else (s_, s_)
                lo, hi_ = int(lo), int(hi_)
                wide = hi_ - lo + 1 > 100
                for prt, label in (RISKY if wide else {**RISKY, **ADMIN_PORTS}).items():
                    if lo <= prt <= hi_:
                        hit[prt] = label
                if wide:
                    hit[s_] = f'大范围端口({hi_ - lo + 1} 个)'
            open_rules.append({'name': r['name'], 'priority': q.get('priority'), 'protocol': q.get('protocol'),
                               'ports': ports, 'sources': rule_srcs(q), 'destination': rule_dsts(q), 'riskyPorts': hit,
                               'aksManaged': r['name'].startswith('k8s-azure-lb_')})
        elif any(s.lower() == 'virtualnetwork' for s in rule_srcs(q)) and any(str(s) == '*' for s in ports):
            broad_vnet.append(r['name'])
    return open_rules, broad_vnet


def _reachable(c, nid, n, risky_rules, exposures):
    wide_specs = [k for r in risky_rules for k in r['riskyPorts'] if isinstance(k, str) and '-' in k]
    reach = []
    for e in exposures:
        ep = e['ep']
        layer_ids = {x for x in (c.subnet_nsg.get(ep.get('subnet') or '', ''), ep.get('nicNsg')) if x}
        if nid not in layer_ids:
            continue
        # the allow must come from one of this NSG's risky rules
        if not any(f"{n['name']}/{r['name']}=Allow" in e['detail'] for r in risky_rules):
            continue
        prt = e['port']
        if prt == '*' or prt in RISKY or prt in ADMIN_PORTS or (isinstance(prt, int) and any(port_match(w, prt) for w in wide_specs)):
            reach.append(e)
    return reach


def check_nsg(c, F, exposures):
    inventory, latent, mgmt_direct, widerange = [], {}, {}, {}
    review = '请确认这些端口的用途；管理控制台、调试、代理或注册中心端口应限制为固定来源 IP 或只允许内网访问；大范围端口应收窄到实际使用的端口。'
    for nid, n in c.nsg.items():
        p = n.get('properties') or {}
        open_rules, broad_vnet = _open_rules(p)
        assoc_subnets = [x['id'] for x in p.get('subnets') or []]
        assoc_nics = [x['id'] for x in p.get('networkInterfaces') or []]
        inventory.append({'name': n['name'], 'subscription': c.sub(n['subscriptionId']), 'resourceGroup': n['resourceGroup'],
                          'subnets': [s.split('/')[-1] for s in assoc_subnets], 'nicCount': len(assoc_nics),
                          'internetAllowRules': open_rules, 'vnetWideAnyPortAllowRules_info': broad_vnet})
        risky_rules = [r for r in open_rules if r['riskyPorts']]
        if not risky_rules:
            continue
        reach = _reachable(c, nid, n, risky_rules, exposures)
        hi = [e for e in reach if e['port'] == '*' or e['port'] in RISKY]
        mid = [e for e in reach if e not in hi]
        orphan = not assoc_subnets and not assoc_nics
        ev_reach = sorted({exposure_text(c, e) for e in reach})
        aks = any(r['aksManaged'] for r in risky_rules)
        rule_desc = '；'.join(f"{r['name']}(优先级{r['priority']}，端口{','.join(map(str, r['ports']))}：{'/'.join(str(v) for v in r['riskyPorts'].values())})"
                             for r in risky_rules)
        evidence = {'riskyInternetRules': risky_rules, 'associatedSubnets': assoc_subnets, 'associatedNicCount': len(assoc_nics),
                    'reachableFromInternet': ev_reach[:60], 'reachableCount': len(ev_reach), 'orphanNsg': orphan}
        aks_tip = (' 该规则由 AKS 根据 Kubernetes Service 自动生成，应在 Service 上设置 loadBalancerSourceRanges 或改为内部负载均衡，而不是直接改 NSG。'
                   if aks else '')

        def mid_txt(xs):
            return ', '.join(sorted({f"{e['port']}({ADMIN_PORTS.get(e['port'], '大范围端口规则内')})" for e in xs}))

        mgmt_only_direct = bool(hi) and all(e['port'] in MGMT_PORTS and e['path']['type'] in ('nic-pip', 'vmss-pip') for e in hi)
        # wide business port ranges only (e.g. UDP media ranges) -> low, aggregated per subscription
        wide_only = [e for e in mid if e['port'] not in ADMIN_PORTS]
        if wide_only:
            widerange.setdefault(n['subscriptionId'], []).append({
                'nsg': n['name'], 'resourceGroup': n['resourceGroup'],
                'rules': [f"{r['name']}:{','.join(map(str, r['ports']))}" for r in risky_rules if any(isinstance(k, str) and '-' in k for k in r['riskyPorts'])],
                'reachable': sorted({exposure_text(c, e) for e in wide_only})[:20]})
        mid = [e for e in mid if e['port'] in ADMIN_PORTS]
        # admin ports exposed only via public LB rules are reported once under S-N6 (per load balancer)
        if mid and all(e['path']['type'] in ('lb-rule', 'lb-nat') for e in mid):
            mid = []
            if not hi:
                continue
        if orphan or (not hi and not mid):
            if not orphan and wide_only:
                continue
            latent.setdefault(n['subscriptionId'], []).append({'nsg': n['name'], 'resourceGroup': n['resourceGroup'], 'orphan': orphan,
                                                               'rules': rule_desc, 'associatedSubnets': [x.split('/')[-1] for x in assoc_subnets],
                                                               'associatedNicCount': len(assoc_nics)})
        elif mgmt_only_direct:
            # counted once in the S-N3 per-subscription finding (VM with direct public IP + management port open)
            for e in hi:
                mgmt_direct.setdefault(n['subscriptionId'], {}).setdefault(endpoint_label(c, e['ep']), set()).add(
                    n['name'] + '/' + ','.join(r['name'] for r in risky_rules if e['port'] in r['riskyPorts'] or '*' in r['riskyPorts']))
            if mid:
                F.add('S-N2', '中', n, NSG,
                      f'NSG {n["name"]} 除 SSH/RDP 外，还对 Internet 开放了疑似管理/调试端口或大范围端口 {mid_txt(mid)}，且公网实际可达'
                      f'（如 {"; ".join(sorted({exposure_text(c, e) for e in mid})[:3])}）。',
                      evidence, review + aks_tip, confirm=True)
        elif hi:
            ports_hit = sorted({str(e['port']) for e in hi}, key=lambda x: int(x) if x.isdigit() else -1)
            inst = sorted({endpoint_label(c, e['ep']) for e in hi})
            labels = sorted({RISKY.get(e['port'], '任意端口') for e in hi})
            F.add('S-N2', '高', n, NSG,
                  f'NSG {n["name"]} 允许 Internet 任意来源访问高风险端口，离线评估两层 NSG 后公网实际可达的是 {", ".join(ports_hit)}（{"、".join(labels)}），'
                  f'涉及 {len(inst)} 个实例（如 {"; ".join(sorted({exposure_text(c, e) for e in hi})[:3])}）。相关规则：{rule_desc}。',
                  evidence, '把来源从 Any/Internet 改为办公网/VPN 出口固定 IP；数据库/中间件端口（Kafka、ZooKeeper、ES、MinIO 等）只允许应用所在子网访问；'
                            '运维登录改走 Azure Bastion 或按需开放（JIT）。' + aks_tip)
        else:
            F.add('S-N2', '中', n, NSG,
                  f'NSG {n["name"]} 对 Internet 开放了疑似管理/调试端口或大范围端口 {mid_txt(mid)}，且公网实际可达（如 {"; ".join(ev_reach[:3])}）。',
                  evidence, review + aks_tip, confirm=True)
    for sub, items in widerange.items():
        F.add('S-N2', '低', None, NSG,
              f'该订阅有 {len(items)} 个 NSG 对 Internet 开放了大范围业务端口（成段开放的端口），公网可达：'
              + '；'.join(f"{i['nsg']}（{', '.join(i['rules'])}）" for i in items[:10]) + '。不属于管理或数据库端口，但范围越大暴露面越大。',
              {'nsgs': items}, '确认这些端口段确为业务所需，并尽量收窄到实际使用的端口；不再使用的规则删除。', confirm=True,
              name=f'{len(items)} 个 NSG', rg='(多个)', sub=sub, members=[member(i['nsg'], NSG, c.sub(sub)) for i in items], key='nsg-wide-range')
    for sub, items in latent.items():
        orphan_n = sum(1 for i in items if i['orphan'])
        F.add('S-N2', '低', None, NSG,
              f'该订阅有 {len(items)} 个 NSG 含对 Internet 开放的高风险规则（22/数据库端口/任意端口等），但目前没有公网 IP 或负载均衡规则能把这些端口暴露出去'
              + (f'（其中 {orphan_n} 个 NSG 未关联任何资源）' if orphan_n else '') + '，属于潜在风险：' + '、'.join(i['nsg'] for i in items[:15])
              + ('…' if len(items) > 15 else '') + '。',
              {'nsgs': items}, '把这些规则的来源收窄为固定 IP 或内网网段；不再使用的 NSG 直接删除。否则一旦相关子网/网卡加上公网 IP 或负载均衡规则，端口会立即暴露。',
              name=f'{len(items)} 个 NSG', rg='(多个)', sub=sub, members=[member(i['nsg'], NSG, c.sub(sub)) for i in items], key='nsg-latent')
    return inventory, mgmt_direct


# ---------------------------------------------------------------- S-N3 public IPs
PIP_OWNERS = [('loadbalancers', '负载均衡前端'), ('applicationgateways', '应用网关'), ('bastionhosts', 'Bastion'),
              ('azurefirewalls', 'Azure 防火墙'), ('virtualnetworkgateways', 'VPN/ER 网关'),
              ('privatelinkservices', 'PLS'), ('virtualhubs', 'Route Server/虚拟中心')]


def _pip_owner(c, pp):
    owner = (pp.get('ipConfiguration') or {}).get('id')
    seg = parts(owner) if owner else {}
    if 'networkinterfaces' in seg:
        ep = c.ipcfg.get(lid(owner))
        return ('VM 网卡' if ep and ep.get('vm') else '网卡(未挂 VM)'), (endpoint_label(c, ep) if ep else seg.get('networkinterfaces'))
    if seg:
        for k, label in PIP_OWNERS:
            if k in seg:
                return label, seg[k]
        return '其他', owner
    if pp.get('natGateway'):
        return 'NAT 网关', pp['natGateway']['id'].split('/')[-1]
    return '未关联', None


def _direct_vms(c, paths, exposures):
    vm_direct = {}
    for pth in paths:
        if pth['type'] not in ('nic-pip', 'vmss-pip'):
            continue
        ep = pth['ep']
        owner = ep.get('nic') or ep.get('vmss')
        ex = [e for e in exposures if e['path'] is pth]
        powered = None
        if ep.get('vm') and ep['vm'] in c.vm:
            powered = (c.vm[ep['vm']].get('properties') or {}).get('powerState')
        vm_direct.setdefault(owner['subscriptionId'], []).append({
            'endpoint': endpoint_label(c, ep), 'publicIp': pth.get('publicIp'), 'pipName': pth.get('pipName'),
            'resourceGroup': owner['resourceGroup'], 'powerState': powered,
            'internetReachableMgmtPorts': sorted({e['port'] for e in ex if e['port'] in MGMT_PORTS}),
            'internetReachableDbPorts': sorted({e['port'] for e in ex if e['port'] in DB_PORTS}),
            'internetReachableAdminPorts': sorted({e['port'] for e in ex if e['port'] in ADMIN_PORTS}),
            'anyPortOpen': any(e['port'] == '*' for e in ex),
            'internetReachablePorts': sorted({f"{e['port']}/{e['proto']}" for e in ex if isinstance(e['port'], int)})[:80],
            'nsgLayers': {'subnet': (c.nsg.get(c.subnet_nsg.get(ep.get('subnet') or '', '')) or {}).get('name'),
                          'nic': (c.nsg.get(ep.get('nicNsg') or '') or {}).get('name')}})
    return vm_direct


def _vm_member(c, sub, item):
    label = item['endpoint'] or ''
    kind, _, name = label.partition(' ')
    rtype = {'VM': 'Microsoft.Compute/virtualMachines', 'VMSS': 'Microsoft.Compute/virtualMachineScaleSets'}.get(kind, 'Microsoft.Network/networkInterfaces')
    return member(name or label, rtype, c.sub(sub))


def _subscription_env(F, sub, items):
    """Environment of a per-subscription row: the subscription decides; VM names only when it is unknown."""
    e_ = F.env(sub)
    if e_['value'] != 'unknown':
        return e_
    names = [(i['endpoint'] or '').partition(' ')[2] for i in items]
    return next((e for e in (F.env(sub, n) for n in names) if is_test(e)), e_)


def check_public_ips(c, F, paths, exposures, mgmt_direct):
    inv = []
    for pip in c.pip.values():
        pp = pip.get('properties') or {}
        kind, tgt = _pip_owner(c, pp)
        item = {'name': pip['name'], 'subscription': c.sub(pip['subscriptionId']), 'resourceGroup': pip['resourceGroup'],
                'ipAddress': pp.get('ipAddress'), 'sku': (pip.get('sku') or {}).get('name'), 'tier': (pip.get('sku') or {}).get('tier'),
                'attachedTo': kind, 'target': tgt, 'ddosProtectionMode': (pp.get('ddosSettings') or {}).get('protectionMode')}
        inv.append(item)
        if item['sku'] == 'Basic':
            F.add('S-N3', '中', pip, 'Microsoft.Network/publicIPAddresses',
                  f'公网 IP {pip["name"]} 为 Basic SKU（默认对入站开放，且 Basic 公网 IP 已停用）。', {'pip': item},
                  '升级为 Standard SKU 并确认关联资源上有 NSG。')
    vm_direct = _direct_vms(c, paths, exposures)
    for sub, items in vm_direct.items():
        md = mgmt_direct.get(sub, {})
        for i in items:
            i['allowingNsgRules'] = sorted(md.get(i['endpoint'], []))
        mg = [i for i in items if i['internetReachableMgmtPorts']]
        dbonly = [i for i in items if not i['internetReachableMgmtPorts'] and (i['internetReachableDbPorts'] or i['anyPortOpen'])]
        e_ = _subscription_env(F, sub, items)
        members = [_vm_member(c, sub, i) for i in items]
        if mg:
            names = '; '.join(f"{i['endpoint']}({i['publicIp']})" for i in mg[:8])
            nsgs = sorted({x.split('/')[0] for i in mg for x in i['allowingNsgRules']})
            F.add('S-N3', '中' if is_test(e_) else '高', None, 'VM 直连公网 IP + 管理端口',
                  f'该订阅有 {len(items)} 个 VM 网卡直接绑定公网 IP，其中 {len(mg)} 个的 SSH/RDP 管理端口对整个 Internet 开放（来源为 Any/Internet），'
                  f'如 {names}{"…" if len(mg) > 8 else ""}；放行的 NSG：{", ".join(nsgs[:12])}{"…" if len(nsgs) > 12 else ""}。',
                  {'vmsWithDirectPublicIp': items, 'mgmtExposedCount': len(mg)},
                  '优先把这些 NSG 中 22/3389 的来源改为办公网/VPN 固定出口 IP，或启用 Defender for Cloud 的 JIT 按需开放；中期去掉不必要的直连公网 IP，'
                  '运维改走 Azure Bastion/VPN，对外服务改由应用网关/负载均衡/Front Door 暴露。',
                  name=f'{len(mg)} 台 VM（共 {len(items)} 个直连公网 IP）', rg='(多个)', sub=sub, members=members, key='vm-direct-public-ip')
        elif dbonly:
            F.add('S-N3', '中', None, 'VM 直连公网 IP',
                  f'该订阅有 {len(items)} 个 VM 网卡直接绑定公网 IP，其中 {len(dbonly)} 个的数据库/任意端口可从 Internet 访问（端口明细见 S-N2）。',
                  {'vmsWithDirectPublicIp': items}, '去掉不必要的直连公网 IP，数据库端口只允许内网访问。', confirm=True,
                  name=f'{len(items)} 个直连公网 IP', rg='(多个)', sub=sub, members=members, key='vm-direct-public-ip')
        else:
            F.add('S-N3', '低', None, 'VM 直连公网 IP',
                  f'该订阅有 {len(items)} 个 VM 网卡直接绑定公网 IP，按当前 NSG 未发现管理或数据库端口对 Internet 开放。',
                  {'vmsWithDirectPublicIp': items}, '确认这些公网 IP 仍有必要；对外服务尽量统一经应用网关/负载均衡/Front Door 暴露。',
                  name=f'{len(items)} 个直连公网 IP', rg='(多个)', sub=sub, members=members, key='vm-direct-public-ip')
    return inv, vm_direct


# ---------------------------------------------------------------- S-N4 / S-N7 databases and caches
def _db_open(F, r, rtype, kind, e_, rules, item):
    allopen, azure, wide, mid_rng, other = [], [], [], [], []
    for x in rules:
        a, b = x['properties'].get('startIpAddress'), x['properties'].get('endIpAddress')
        if (a, b) == ('0.0.0.0', '255.255.255.255'):
            allopen.append(x['name'])
            continue
        if (a, b) == ('0.0.0.0', '0.0.0.0'):
            azure.append(x['name'])
            continue
        sz = range_size(a, b) or 0
        rr = {'name': x['name'], 'start': a, 'end': b, 'addresses': sz, 'private': ipaddress.ip_address(a).is_private}
        (wide if (not rr['private'] and sz >= 65536) else mid_rng if (not rr['private'] and sz > 256) else other).append(rr)
    ev = {'server': item, 'allowAllRules': allopen, 'allowAzureServicesRules': azure, 'wideRanges': wide,
          'mediumRanges': mid_rng, 'otherRules': other}
    pub_single = [x for x in other if not x['private']]
    if allopen:
        F.add('S-N4', '高', r, rtype,
              f'{kind} {r["name"]} 开启公网访问，防火墙规则 {", ".join(allopen)} 放行 0.0.0.0–255.255.255.255，等于对整个 Internet 开放数据库端口。',
              ev, '立即删除该全放行规则；应用访问改为私有终结点或 VNet 集成，运维访问只保留办公网/VPN 固定出口 IP。')
    elif wide:
        F.add('S-N4', '中' if is_test(e_) else '高', r, rtype,
              f'{kind} {r["name"]} 开启公网访问，防火墙规则 '
              + ', '.join(f'{w["name"]}({w["start"]}–{w["end"]}，约 {w["addresses"]:,} 个地址)' for w in wide) + ' 放行了超大公网地址段，接近对公网开放。',
              ev, '删除或收窄这些大网段，只保留确需访问的具体出口 IP；生产库建议改为私有终结点访问并关闭公网访问。', confirm=True)
    elif rules:
        extra = '；另有“允许 Azure 服务访问”(0.0.0.0) 规则，任何 Azure 租户内的资源都能尝试连接' if azure else ''
        midtxt = ('；含较大网段 ' + ', '.join(f'{m["name"]}({m["start"]}–{m["end"]})' for m in mid_rng)) if mid_rng else ''
        F.add('S-N4', '低' if is_test(e_) else '中', r, rtype,
              f'{kind} {r["name"]} 开启公网访问，按 IP 白名单限制（{len(pub_single) + len(mid_rng)} 条公网 IP 规则{midtxt}{extra}）；生产库通常应只走私网。',
              ev, '应用访问切到私有终结点/VNet 集成后关闭公网访问；过渡期先清理临时添加的 ClientIPAddress_* 规则，并删除“允许 Azure 服务”规则。')
    else:
        F.add('S-N4', '低', r, rtype, f'{kind} {r["name"]} 公网访问开关为开启，但没有任何防火墙规则，公网实际无法连接。', ev,
              '如不需要公网访问，建议显式关闭，避免日后误加规则造成暴露。')


def check_db_servers(c, F, arm, pecount, kind, argkey, fwkey, cfgkey, rst_name, tls_name, rtype):
    fw_all, cfg_all = arm(fwkey), arm(cfgkey)
    inv = []
    for r in c.rows(argkey):
        p = r.get('properties') or {}
        net = p.get('network') or {}
        pna = net.get('publicNetworkAccess')
        fwrec = fw_all.get(r['id'], {})
        rules = fwrec.get('data')
        cfg = {}
        for prm in (rst_name, tls_name):
            cr = cfg_all.get(r['id'] + '|' + prm) or {}
            cfg[prm] = ((cr.get('data') or {}).get('properties') or {}).get('value') if cr.get('http') == 200 else None
        e_ = F.env(r['subscriptionId'], r['name'], r.get('tags'))
        item = {'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
                'publicNetworkAccess': pna, 'vnetIntegratedSubnet': net.get('delegatedSubnetResourceId'),
                'privateEndpoints': pecount(r), 'firewallRuleCount': len(rules) if rules is not None else None,
                'firewallHttp': fwrec.get('http'), rst_name: cfg[rst_name], tls_name: cfg[tls_name], 'environment': e_}
        inv.append(item)
        if pna == 'Enabled' and rules is None:
            F.add('S-N4', '中', r, rtype, f'{kind} {r["name"]} 开启了公网访问，但防火墙规则读取失败（HTTP {fwrec.get("http")}），无法判断是否对全网开放。',
                  {'server': item, 'error': fwrec.get('error')}, '请在门户人工确认防火墙规则。', confirm=True)
        elif pna == 'Enabled':
            _db_open(F, r, rtype, kind, e_, rules, item)
        rst = (cfg[rst_name] or '').upper() or None
        if rst == 'OFF':
            F.add('S-N7', '中' if (pna == 'Enabled' and not is_test(e_)) else '低', r, rtype,
                  f'{kind} {r["name"]} 的 require_secure_transport=OFF，允许不加密连接' + ('，且该库开启了公网访问。' if pna == 'Enabled' else '（当前不开放公网）。'),
                  {'server': item}, '确认所有客户端都用 TLS 连接后，把服务器参数 require_secure_transport 改为 ON（动态参数，建议在变更窗口执行）。', confirm=True)
        tv = cfg[tls_name] or ''
        if any(x in tv.replace(' ', '').split(',') for x in ('TLSv1', 'TLSv1.1')):
            F.add('S-N7', '低', r, rtype, f'{kind} {r["name"]} 的 {tls_name}={tv}，仍允许旧版 TLS。', {'server': item}, '改为仅 TLSv1.2/TLSv1.3。')
    return inv


def check_redis(c, F, arm, pecount):
    rfw = arm('redis_fw')
    inv = []
    rtype = 'Microsoft.Cache/redis'
    for r in c.rows('redis'):
        p = r.get('properties') or {}
        e_ = F.env(r['subscriptionId'], r['name'], r.get('tags'))
        rules = rfw.get(r['id'], {}).get('data')
        item = {'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
                'sku': (p.get('sku') or {}).get('name'), 'publicNetworkAccess': p.get('publicNetworkAccess'),
                'vnetInjectedSubnet': p.get('subnetId'), 'privateEndpoints': pecount(r),
                'firewallRules': [{'name': x['name'], **(x.get('properties') or {})} for x in rules or []],
                'enableNonSslPort': p.get('enableNonSslPort'), 'minimumTlsVersion': p.get('minimumTlsVersion'),
                'disableAccessKeyAuthentication': p.get('disableAccessKeyAuthentication'), 'environment': e_}
        inv.append(item)
        if not p.get('subnetId') and p.get('publicNetworkAccess') == 'Enabled':
            if rules is None:
                F.add('S-N4', '中', r, rtype, f'Redis {r["name"]} 公网访问开启，防火墙规则读取失败。', {'redis': item}, '人工确认防火墙规则。', confirm=True)
            elif not rules:
                F.add('S-N4', '中' if is_test(e_) else '高', r, rtype,
                      f'Redis {r["name"]}（{item["sku"]}）开启公网访问、没有私有终结点、也没有任何防火墙规则，任何 Internet IP 都能连到 6380 端口，只靠访问密钥保护。',
                      {'redis': item}, '为其创建私有终结点并关闭公网访问；短期内至少添加防火墙规则只允许应用出口 IP，并考虑改用 Entra ID 认证、禁用访问密钥。', confirm=True)
            else:
                F.add('S-N4', '中', r, rtype, f'Redis {r["name"]} 开启公网访问，按 {len(rules)} 条 IP 规则限制。', {'redis': item}, '改为私有终结点访问并关闭公网访问。')
        if p.get('enableNonSslPort'):
            F.add('S-N7', '中', r, rtype, f'Redis {r["name"]} 开启了非 TLS 端口 6379。', {'redis': item}, '关闭非 SSL 端口。')
        if p.get('minimumTlsVersion') not in (None, '1.2', '1.3'):
            F.add('S-N7', '低', r, rtype, f'Redis {r["name"]} 最低 TLS 版本为 {p.get("minimumTlsVersion")}。', {'redis': item}, '改为 1.2。')
    return inv


def check_amr(c, F, arm, pecount):
    rdb = arm('redisent_db')
    inv = []
    rtype = 'Microsoft.Cache/redisEnterprise'
    for r in c.rows('redisenterprise'):
        p = r.get('properties') or {}
        e_ = F.env(r['subscriptionId'], r['name'], r.get('tags'))
        dbrec = rdb.get(r['id'], {})
        dbsum = [{'name': d.get('name'), 'clientProtocol': (d.get('properties') or {}).get('clientProtocol'),
                  'port': (d.get('properties') or {}).get('port'),
                  'accessKeysAuthentication': (d.get('properties') or {}).get('accessKeysAuthentication')} for d in dbrec.get('data') or []]
        pe = pecount(r)
        item = {'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
                'sku': (r.get('sku') or {}).get('name'), 'publicNetworkAccess': p.get('publicNetworkAccess'),
                'privateEndpoints': pe, 'minimumTlsVersion': p.get('minimumTlsVersion'), 'databases': dbsum,
                'databasesHttp': dbrec.get('http'), 'environment': e_}
        inv.append(item)
        plain = [d for d in dbsum if (d['clientProtocol'] or '').lower() == 'plaintext']
        keys = any((d['accessKeysAuthentication'] or '').lower() == 'enabled' for d in dbsum)
        public = p.get('publicNetworkAccess') == 'Enabled'
        if public:
            F.add('S-N4', '中' if is_test(e_) else '高', r, rtype,
                  f'Azure Managed Redis {r["name"]} 开启了公网访问（该服务不支持 IP 防火墙，任何 Internet IP 都能连到端口 10000）'
                  + ('，数据库为明文协议(Plaintext)' if plain else '') + ('，并启用访问密钥认证' if keys else '')
                  + (f'；已有 {pe} 个私有终结点，公网入口属于多余暴露' if pe else '；没有私有终结点') + '。',
                  {'redis': item}, ('已有私有终结点：确认应用都走私网后直接关闭公网访问。' if pe else '先创建私有终结点并切换应用连接，再关闭公网访问。')
                  + '同时建议启用 Entra ID 认证并禁用访问密钥。', confirm=not pe)
        if plain:
            F.add('S-N7', '中' if public else '低', r, rtype,
                  f'Azure Managed Redis {r["name"]} 的数据库 {", ".join(d["name"] for d in plain)} 使用明文协议(Plaintext)，访问密钥和数据都不加密传输'
                  + ('，且公网可达。' if public else '（当前仅私网）。'),
                  {'redis': item}, '确认客户端支持 TLS 后把 clientProtocol 改为 Encrypted（需同步修改应用连接配置）。', confirm=True)
    return inv


def check_mongo(c, F, arm, pecount):
    mfw = arm('mongo_fw')
    inv = []
    rtype = 'Microsoft.DocumentDB/mongoClusters'
    for r in c.rows('mongoclusters'):
        p = r.get('properties') or {}
        e_ = F.env(r['subscriptionId'], r['name'], r.get('tags'))
        rec = mfw.get(r['id']) or {}
        rules = rec.get('data')
        item = {'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
                'publicNetworkAccess': p.get('publicNetworkAccess'), 'privateEndpoints': pecount(r),
                'firewallRules': [{'name': x['name'], 'start': x['properties'].get('startIpAddress'), 'end': x['properties'].get('endIpAddress')}
                                  for x in rules or []],
                'firewallHttp': rec.get('http'), 'environment': e_}
        inv.append(item)
        if p.get('publicNetworkAccess') != 'Enabled':
            continue
        if rules is None:
            F.add('S-N4', '中', r, rtype, f'MongoDB(vCore) {r["name"]} 公网开启，防火墙规则读取失败。', {'mongo': item}, '人工确认。', confirm=True)
        elif any((x['properties'].get('startIpAddress'), x['properties'].get('endIpAddress')) == ('0.0.0.0', '255.255.255.255') for x in rules):
            F.add('S-N4', '高', r, rtype, f'MongoDB(vCore) {r["name"]} 防火墙对全部 IP 开放。', {'mongo': item}, '删除全放行规则，改用私有终结点。')
        elif rules:
            F.add('S-N4', '低' if is_test(e_) else '中', r, rtype, f'MongoDB(vCore) {r["name"]} 公网开启，按 {len(rules)} 条 IP 规则限制。',
                  {'mongo': item}, '改为仅私有终结点访问。')
        else:
            F.add('S-N4', '低', r, rtype,
                  f'MongoDB(vCore) {r["name"]} 的公网访问开关为开启，但没有任何防火墙规则，公网实际无法连接；已有 {pecount(r)} 个私有终结点。',
                  {'mongo': item}, '建议显式关闭公网访问，避免以后误加 IP 规则造成暴露。')
    return inv


# ---------------------------------------------------------------- S-N4 / S-N5 / S-N7 storage
STORAGE = 'Microsoft.Storage/storageAccounts'


def _storage_open(F, r, p, e_, pe, item):
    pna = p.get('publicNetworkAccess')
    aks_managed = r['resourceGroup'].lower().startswith('mc_')
    tf = 'tfstate' in r['name'].lower()
    sev = '中' if tf else ('低' if (aks_managed or is_test(e_)) else '中')
    note = ''
    if tf:
        note += '；该账户存放 Terraform 状态文件，状态里通常含有资源密钥/密码'
    if pe:
        note += f'；已有 {pe} 个私有终结点，但公网入口仍对所有网络开放'
    if aks_managed:
        note += '；位于 AKS 托管资源组（由 AKS CSI 驱动自动创建）'
    F.add('S-N4', sev, r, STORAGE,
          f'存储账户 {r["name"]} 允许从所有网络访问（公网访问={pna or "未设置(默认开启)"}，默认动作=Allow，无 IP/VNet 限制），共享密钥认证'
          f'{"开启" if p.get("allowSharedKeyAccess") in (None, True) else "关闭"}{note}。',
          {'storage': item}, ('AKS 托管账户应在 StorageClass 中配置私有终结点/网络规则；' if aks_managed else '')
          + '把默认动作改为 Deny，只放行需要的 VNet/私有终结点和固定出口 IP；已有私有终结点的账户确认后可直接关闭公网访问。'
          + ('Terraform 状态账户建议只允许 CI/CD 出口或私网访问，并关闭共享密钥改用 Entra ID。' if tf else ''),
          confirm=sev != '低')


def _public_container(F, r, x, pna, default_action):
    nm = x['name']
    sens = any(k in nm.lower() for k in ('backup', 'bak', 'dump', 'secret', 'private', 'config', 'log'))
    named_public = 'public' in nm.lower()
    level = x['publicAccess']
    sev = '高' if (sens or (level == 'Container' and not named_public)) else '中'
    F.add('S-N5', sev, r, 'Microsoft.Storage/storageAccounts/blobServices/containers',
          f'存储账户 {r["name"]} 的容器 "{nm}" 允许匿名访问（publicAccess={level}，'
          + ('匿名用户可列出并下载全部文件' if level == 'Container' else '知道文件地址即可匿名下载') + '）'
          + ('，容器名显示可能存放备份/敏感数据。' if sens else ('；从名称看可能是有意公开的分发容器，需确认其中没有敏感文件。' if named_public else '。')),
          {'storageAccount': r['name'], 'container': x, 'accountPublicNetworkAccess': pna, 'accountDefaultAction': default_action},
          ('立即核对容器内容；如非必须公开，把容器访问级别改为 Private 并在账户上关闭 allowBlobPublicAccess；确需对外分发时改用短期 SAS 或 Front Door + 私有源。'
           if sev == '高' else '确认容器内容确需公开且不含敏感文件；能改为 Front Door/CDN 分发或短期 SAS 的建议改掉。'),
          confirm=True, key=f'{r["id"]}/{nm}')


def _hygiene(p, pub_cont):
    issues = []
    if p.get('allowBlobPublicAccess') and not pub_cont:
        issues.append('allowBlobPublicAccess=true（当前无匿名容器）')
    if p.get('allowSharedKeyAccess') in (None, True):
        issues.append('允许共享密钥访问')
    if p.get('allowCrossTenantReplication'):
        issues.append('允许跨租户复制')
    if p.get('defaultToOAuthAuthentication') in (None, False):
        issues.append('门户默认未用 Entra ID 认证')
    return issues


def check_storage(c, F, arm, pecount):
    cont = arm('containers')
    inv, hyg, tls_old = [], {}, {}
    for r in c.rows('storage'):
        p = r.get('properties') or {}
        na = p.get('networkAcls') or {}
        e_ = F.env(r['subscriptionId'], r['name'], r.get('tags'))
        pna = p.get('publicNetworkAccess')
        open_all = pna in (None, 'Enabled') and na.get('defaultAction', 'Allow') == 'Allow'
        crec = cont.get(r['id'])
        pub_cont = [x for x in (crec or {}).get('data') or [] if x.get('publicAccess') not in (None, 'None')]
        pe = pecount(r)
        item = {'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
                'kind': r.get('kind'), 'publicNetworkAccess': pna, 'defaultAction': na.get('defaultAction'),
                'ipRules': len(na.get('ipRules') or []), 'vnetRules': len(na.get('virtualNetworkRules') or []),
                'bypass': na.get('bypass'), 'privateEndpoints': pe,
                'allowBlobPublicAccess': p.get('allowBlobPublicAccess'), 'allowSharedKeyAccess': p.get('allowSharedKeyAccess'),
                'minimumTlsVersion': p.get('minimumTlsVersion'), 'supportsHttpsTrafficOnly': p.get('supportsHttpsTrafficOnly'),
                'allowCrossTenantReplication': p.get('allowCrossTenantReplication'),
                'defaultToOAuthAuthentication': p.get('defaultToOAuthAuthentication'),
                'containersListed': crec is not None, 'containersHttp': (crec or {}).get('http'),
                'containerCount': len((crec or {}).get('data') or []) if crec else None,
                'publicContainers': pub_cont, 'environment': e_}
        inv.append(item)
        if open_all:
            _storage_open(F, r, p, e_, pe, item)
        for x in pub_cont:
            _public_container(F, r, x, pna, na.get('defaultAction'))
        issues = _hygiene(p, pub_cont)
        if issues:
            hyg.setdefault(r['subscriptionId'], []).append({'account': r['name'], 'resourceGroup': r['resourceGroup'], 'issues': issues})
        if p.get('minimumTlsVersion') in ('TLS1_0', 'TLS1_1'):
            tls_old.setdefault(r['subscriptionId'], []).append({'account': r['name'], 'resourceGroup': r['resourceGroup'],
                                                                'minimumTlsVersion': p.get('minimumTlsVersion')})
        if p.get('supportsHttpsTrafficOnly') is False:
            F.add('S-N7', '中', r, STORAGE, f'存储账户 {r["name"]} 允许 HTTP 明文访问。', {'storage': item}, '开启“仅 HTTPS”。')
    for sub, items in hyg.items():
        F.add('S-N5', '低', None, STORAGE,
              f'该订阅 {len(items)} 个存储账户有加固项未设置：' + '；'.join(f"{i['account']}（{'、'.join(i['issues'])}）" for i in items[:10])
              + ('…' if len(items) > 10 else '') + '。',
              {'accounts': items}, '无匿名容器的账户直接关闭 allowBlobPublicAccess；应用改用托管身份/Entra ID 后关闭共享密钥访问，并把 defaultToOAuthAuthentication 设为 true。',
              name=f'{len(items)} 个存储账户', rg='(多个)', sub=sub, members=[member(i['account'], STORAGE, c.sub(sub)) for i in items],
              key='storage-hardening')
    for sub, items in tls_old.items():
        F.add('S-N7', '低', None, STORAGE,
              f'该订阅 {len(items)} 个存储账户的最低 TLS 版本仍为 TLS1_0：{", ".join(i["account"] for i in items)}。',
              {'accounts': items}, '把 minimumTlsVersion 改为 TLS1_2（Azure 存储正在停止支持 TLS1.0/1.1，修改前确认没有老客户端）。',
              name=f'{len(items)} 个存储账户', rg='(多个)', sub=sub, members=[member(i['account'], STORAGE, c.sub(sub)) for i in items],
              key='storage-tls')
    return inv


# ---------------------------------------------------------------- S-N4 other PaaS
def _key_vaults(c, F, pecount):
    inv, purge = [], []
    rtype = 'Microsoft.KeyVault/vaults'
    for r in c.rows('keyvaults'):
        p = r.get('properties') or {}
        na = p.get('networkAcls') or {}
        e_ = F.env(r['subscriptionId'], r['name'], r.get('tags'))
        item = {'name': r['name'], 'subscriptionId': r['subscriptionId'], 'subscription': c.sub(r['subscriptionId']),
                'resourceGroup': r['resourceGroup'], 'publicNetworkAccess': p.get('publicNetworkAccess'),
                'defaultAction': na.get('defaultAction'), 'ipRules': len(na.get('ipRules') or []), 'privateEndpoints': pecount(r),
                'enableSoftDelete': p.get('enableSoftDelete'), 'enablePurgeProtection': p.get('enablePurgeProtection'),
                'enableRbacAuthorization': p.get('enableRbacAuthorization'), 'environment': e_}
        inv.append(item)
        if (p.get('publicNetworkAccess') or 'Enabled') == 'Enabled' and na.get('defaultAction') in (None, 'Allow'):
            F.add('S-N4', '低' if is_test(e_) else '中', r, rtype,
                  f'Key Vault {r["name"]} 允许从所有网络访问（无防火墙、无私有终结点），只靠 Entra ID 权限控制。',
                  {'keyvault': item}, '开启防火墙（默认拒绝），只放行需要的 VNet/固定 IP，并勾选“允许受信任的 Microsoft 服务”（Front Door 读取证书需要）；或使用私有终结点。',
                  confirm=True)
        if not p.get('enablePurgeProtection'):
            purge.append(item)
    if purge:
        soft = all(i['enableSoftDelete'] is not False for i in purge)
        rbac = all(i['enableRbacAuthorization'] for i in purge)
        note = '，'.join(x for x in ('软删除均已开启' if soft else '', '均使用 RBAC 授权' if rbac else '') if x)
        F.add('S-N4', '低', None, rtype,
              f'{len(purge)} 个 Key Vault 未开启清除保护：{", ".join(i["name"] for i in purge)}' + (f'（{note}）' if note else '') + '。',
              {'vaults': purge}, '开启清除保护（开启后不可关闭），防止误删或恶意删除后被立即永久清除。',
              name=f'{len(purge)} 个 Key Vault', rg='(多个)', sub=None, members=[member(i['name'], rtype, i['subscription']) for i in purge],
              key='keyvault-purge')
    return inv


def _registries(c, F, pecount):
    inv, acr_public = [], []
    rtype = 'Microsoft.ContainerRegistry/registries'
    for r in c.rows('registries'):
        p = r.get('properties') or {}
        item = {'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
                'sku': (r.get('sku') or {}).get('name'), 'publicNetworkAccess': p.get('publicNetworkAccess'),
                'adminUserEnabled': p.get('adminUserEnabled'), 'anonymousPullEnabled': p.get('anonymousPullEnabled'),
                'networkRuleSet': p.get('networkRuleSet'), 'privateEndpoints': pecount(r),
                'environment': F.env(r['subscriptionId'], r['name'], r.get('tags'))}
        inv.append(item)
        if p.get('anonymousPullEnabled'):
            F.add('S-N4', '高', r, rtype, f'容器镜像仓库 {r["name"]} 允许匿名拉取。', {'acr': item}, '关闭匿名拉取。')
        if p.get('adminUserEnabled'):
            F.add('S-N4', '中', r, rtype,
                  f'容器镜像仓库 {r["name"]}（{item["sku"]}）启用了管理员账号（共享用户名/密码，可推送和拉取镜像），且仓库对所有网络开放。',
                  {'acr': item}, 'AKS 拉取镜像改用 kubelet 托管身份（AcrPull 角色），CI/CD 推送改用服务主体/工作负载身份；确认无依赖后关闭管理员账号。', confirm=True)
        if p.get('publicNetworkAccess') == 'Enabled' and not (p.get('networkRuleSet') or {}).get('ipRules'):
            acr_public.append(item)
    if acr_public:
        F.add('S-N4', '低', None, rtype,
              f'{len(acr_public)} 个容器镜像仓库对所有网络开放：' + ', '.join(f'{i["name"]}({i["sku"]})' for i in acr_public)
              + '；Basic/Standard SKU 不支持 IP 防火墙和私有终结点。',
              {'registries': acr_public}, '生产仓库如需网络隔离需升级 Premium 后配置私有终结点/IP 规则；否则至少确保只用 Entra ID 身份访问。',
              name=f'{len(acr_public)} 个镜像仓库', rg='(多个)', sub=None, members=[member(i['name'], rtype, i['subscription']) for i in acr_public],
              key='acr-public')
    return inv


def _cognitive(c, F, pecount):
    rtype = 'Microsoft.CognitiveServices/accounts'
    inv = []
    for r in c.rows('cognitive'):
        p = r.get('properties') or {}
        na = p.get('networkAcls') or {}
        inv.append({'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
                    'kind': r.get('kind'), 'publicNetworkAccess': p.get('publicNetworkAccess'),
                    'defaultAction': na.get('defaultAction'), 'ipRules': len(na.get('ipRules') or []),
                    'privateEndpoints': pecount(r), 'disableLocalAuth': p.get('disableLocalAuth'),
                    'openToAll': (p.get('publicNetworkAccess') or 'Enabled') == 'Enabled' and na.get('defaultAction') in (None, 'Allow')})
    open_keys = [i for i in inv if i['openToAll'] and not i['disableLocalAuth']]
    if open_keys:
        subs_ = sorted({i['subscription'] for i in open_keys})
        F.add('S-N4', '中', None, rtype,
              f'{len(open_keys)} 个 AI Foundry/OpenAI/认知服务账户（分布在 {len(subs_)} 个订阅）对所有网络开放且允许 API 密钥认证，密钥一旦泄露即可从任何地方调用模型并产生费用。',
              {'accounts': open_keys, 'subscriptions': subs_},
              '能确定调用来源的账户开启网络 ACL（默认拒绝 + 固定出口 IP）或私有终结点；调用方改用 Entra ID 后设置 disableLocalAuth=true；定期轮换密钥并监控异常用量。',
              confirm=True, name=f'{len(open_keys)} 个 AI 账户', rg='(多个)', sub=None,
              members=[member(i['name'], rtype, i['subscription']) for i in open_keys], key='cognitive-open-keys')
    return inv


def _log_analytics(c, F):
    rtype = 'Microsoft.OperationalInsights/workspaces'
    inv = [{'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
            'publicNetworkAccessForIngestion': (r.get('properties') or {}).get('publicNetworkAccessForIngestion'),
            'publicNetworkAccessForQuery': (r.get('properties') or {}).get('publicNetworkAccessForQuery')} for r in c.rows('loganalytics')]
    both = [i for i in inv if i['publicNetworkAccessForIngestion'] == 'Enabled' and i['publicNetworkAccessForQuery'] == 'Enabled']
    if both:
        F.add('S-N4', '低', None, rtype,
              f'{len(both)}/{len(inv)} 个 Log Analytics 工作区的数据接收和查询都允许公网访问（Azure 默认设置，访问仍需 Entra ID 权限）。',
              {'workspaces': both}, '一般可保持默认；如有合规要求，可通过 Azure Monitor Private Link Scope (AMPLS) 改为私网接收/查询。',
              name=f'{len(both)} 个工作区', rg='(多个)', sub=None, members=[member(i['name'], rtype, i['subscription']) for i in both],
              key='log-analytics-public')
    return inv


def check_misc_paas(c, F, pecount):
    out = {'keyVaults': _key_vaults(c, F, pecount), 'containerRegistries': _registries(c, F, pecount),
           'cognitiveServices': _cognitive(c, F, pecount), 'logAnalytics': _log_analytics(c, F)}
    out['eventHubs'] = [{'name': r['name'], 'subscription': c.sub(r['subscriptionId']),
                         'publicNetworkAccess': (r.get('properties') or {}).get('publicNetworkAccess'),
                         'minimumTlsVersion': (r.get('properties') or {}).get('minimumTlsVersion'),
                         'disableLocalAuth': (r.get('properties') or {}).get('disableLocalAuth'),
                         'privateEndpoints': pecount(r)} for r in c.rows('eventhubs')]
    out['cosmosDb'] = {'count': len(c.rows('cosmos'))}
    out['sqlServers'] = {'count': len(c.rows('sqlservers'))}
    out['webApps'] = {'count': len(c.rows('webapps'))}
    return out


# ---------------------------------------------------------------- S-N6 / S-N7 ingress
def _app_gateway(c, F, r, wafpol):
    rtype = 'Microsoft.Network/applicationGateways'
    p = r.get('properties') or {}
    e_ = F.env(r['subscriptionId'], r['name'], r.get('tags'))
    public = any((f.get('properties') or {}).get('publicIPAddress') for f in p.get('frontendIPConfigurations') or [])
    tier = (p.get('sku') or {}).get('tier') or ''
    pol = wafpol.get(lid((p.get('firewallPolicy') or {}).get('id')))
    ps = ((pol or {}).get('properties') or {}).get('policySettings') or {}
    wcfg = p.get('webApplicationFirewallConfiguration') or {}
    fports = {lid(x['id']): (x.get('properties') or {}).get('port') for x in p.get('frontendPorts') or []}
    redirect_listeners = {lid(((rr.get('properties') or {}).get('httpListener') or {}).get('id'))
                          for rr in p.get('requestRoutingRules') or [] if (rr.get('properties') or {}).get('redirectConfiguration')}
    listeners = []
    for listener in p.get('httpListeners') or []:
        q = listener.get('properties') or {}
        listeners.append({'name': listener['name'], 'protocol': q.get('protocol'), 'port': fports.get(lid((q.get('frontendPort') or {}).get('id'))),
                          'hostNames': q.get('hostNames') or ([q.get('hostName')] if q.get('hostName') else []),
                          'redirectToHttps': lid(listener['id']) in redirect_listeners})
    ssl = p.get('sslPolicy')
    item = {'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
            'sku': p.get('sku'), 'publicFrontend': public, 'wafPolicy': (pol or {}).get('name'),
            'wafPolicyState': ps.get('state'), 'wafPolicyMode': ps.get('mode'),
            'legacyWafConfig': {'enabled': wcfg.get('enabled'), 'mode': wcfg.get('firewallMode')} if wcfg else None,
            'sslPolicy': ssl, 'listeners': listeners, 'environment': e_}
    ports_txt = ', '.join(sorted({str(x['port']) for x in listeners}, key=lambda x: int(x) if x.isdigit() else 0))
    if public and 'WAF' not in tier:
        F.add('S-N6', '低' if is_test(e_) else '中', r, rtype,
              f'应用网关 {r["name"]} 为 {tier}（不带 WAF），公网前端直接对外提供 {len(listeners)} 个监听（端口 {ports_txt}），入口没有 Web 应用防火墙防护。',
              {'appGateway': item}, '评估升级到 WAF_v2 并关联 WAF 策略（先 Detection 观察 1–2 周再切 Prevention），或在前面加 Front Door + WAF；'
                                    '若这些端口承载的是非 HTTP 协议，需先确认 WAF 规则的适用性。', confirm=True)
    elif public and 'WAF' in tier:
        if pol is None and not (wcfg and wcfg.get('enabled')):
            F.add('S-N6', '中', r, rtype, f'应用网关 {r["name"]} 是 WAF_v2，但没有关联启用的 WAF 策略。', {'appGateway': item}, '关联 WAF 策略并启用 Prevention。')
        elif ps and (ps.get('state') != 'Enabled' or ps.get('mode') != 'Prevention'):
            F.add('S-N6', '中', r, rtype,
                  f'应用网关 {r["name"]}（WAF_v2）关联的 WAF 策略 {pol["name"]} 状态为 {ps.get("state")}、模式为 {ps.get("mode")}，'
                  + ('WAF 实际没有生效（按 WAF_v2 计费却没有防护）。' if ps.get('state') != 'Enabled' else '只记录不拦截。'),
                  {'appGateway': item, 'wafPolicy': {'name': pol['name'], 'policySettings': ps}},
                  '先把策略状态改为 Enabled（Detection）观察误报并加排除项，然后切换到 Prevention 模式。')
    http_noredir = [x for x in listeners if (x['protocol'] or '').lower() == 'http' and not x['redirectToHttps']]
    if public and http_noredir:
        F.add('S-N7', '低', r, rtype,
              f'应用网关 {r["name"]} 有 {len(http_noredir)} 个明文 HTTP 监听直接转发到后端、没有跳转到 HTTPS：' + ', '.join(f"{x['name']}:{x['port']}" for x in http_noredir) + '。',
              {'listeners': http_noredir}, '确认这些 HTTP 端口是否仍需要；网页流量应改为 HTTP→HTTPS 重定向，非 HTTP 协议评估改用 TLS。', confirm=True)
    has_https = any((x['protocol'] or '').lower() == 'https' for x in listeners)
    if public and has_https and not ssl:
        F.add('S-N7', '低', r, rtype,
              f'应用网关 {r["name"]} 未显式配置 SSL 策略，实际最低 TLS 取决于创建时的 API 默认值（较早创建的网关可能仍允许 TLS1.0/1.1）。',
              {'appGateway': item}, '显式设置预定义策略 AppGwSslPolicy20220101（最低 TLS1.2）或更严格的 20220101S。', confirm=True)
    elif ssl and (ssl.get('policyName') in ('AppGwSslPolicy20150501', 'AppGwSslPolicy20170401') or ssl.get('minProtocolVersion') in ('TLSv1_0', 'TLSv1_1')):
        F.add('S-N7', '中', r, rtype, f'应用网关 {r["name"]} 的 SSL 策略允许 TLS1.0/1.1：{ssl}。', {'appGateway': item}, '改为 AppGwSslPolicy20220101 或更严格。')
    return item


def _front_door(c, F, r, fdwaf, sp_all, ep_all):
    rtype = 'Microsoft.Cdn/profiles'
    sku = (r.get('sku') or {}).get('name') or ''
    e_ = F.env(r['subscriptionId'], r['name'], r.get('tags'))
    sps = (sp_all.get(r['id']) or {}).get('data')
    eps = (ep_all.get(r['id']) or {}).get('data') or []
    pols = []
    for sp in sps or []:
        prm = (sp.get('properties') or {}).get('parameters') or {}
        w = fdwaf.get(lid((prm.get('wafPolicy') or {}).get('id'))) or {}
        wp = w.get('properties') or {}
        ps = wp.get('policySettings') or {}
        pols.append({'securityPolicy': sp.get('name'), 'wafPolicy': w.get('name'),
                     'enabledState': ps.get('enabledState'), 'mode': ps.get('mode'),
                     'managedRuleSets': [m.get('ruleSetType') + '_' + m.get('ruleSetVersion') for m in (wp.get('managedRules') or {}).get('managedRuleSets') or []],
                     'customRuleCount': len((wp.get('customRules') or {}).get('rules') or []),
                     'domains': [d['id'].split('/')[-1] for a in prm.get('associations') or [] for d in a.get('domains') or []]})
    item = {'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'], 'sku': sku,
            'endpoints': [{'name': x.get('name'), 'hostName': (x.get('properties') or {}).get('hostName')} for x in eps],
            'securityPolicies': pols, 'securityPoliciesHttp': (sp_all.get(r['id']) or {}).get('http'), 'environment': e_}
    if sps is None:
        F.add('S-N6', '中', r, rtype, f'Front Door {r["name"]} 的安全策略读取失败。', {'frontDoor': item}, '人工确认。', confirm=True)
    elif not sps:
        F.add('S-N6', '低' if is_test(e_) else '中', r, rtype,
              f'Front Door {r["name"]}（{sku}）没有关联任何 WAF 安全策略，端点 {", ".join(i["hostName"] or "" for i in item["endpoints"])} 直接对外。',
              {'frontDoor': item}, '创建 WAF 策略并通过安全策略关联到所有域名（Standard 只支持自定义规则，托管规则集需 Premium）。', confirm=True)
    else:
        weak = [x for x in pols if x['enabledState'] != 'Enabled' or x['mode'] != 'Prevention']
        if weak:
            std = 'Standard' in sku
            F.add('S-N6', '中', r, rtype,
                  f'Front Door {r["name"]}（{sku}）的 WAF 策略 {", ".join(x["wafPolicy"] or "?" for x in weak)} 为 {"/".join(sorted({str(x["mode"]) for x in weak}))} 模式，'
                  f'只记录不拦截，覆盖 {sum(len(x["domains"]) for x in weak)} 个域名/端点' + ('；Standard SKU 没有托管规则集，只有自定义规则。' if std else '。'),
                  {'frontDoor': item}, '查看 WAF 日志确认误报并添加排除项后，把策略切换到 Prevention 模式' + ('；需要 OWASP 托管规则则升级 Premium。' if std else '。'))
    return item


def _public_lbs(c, F, paths):
    lb_inv = []
    for pth in paths:
        if pth['type'] not in ('lb-rule', 'lb-nat'):
            continue
        lb = pth['lb']
        ev = pth.get('memberEval') or []
        lb_inv.append({'loadBalancer': lb['name'], 'subscriptionId': lb['subscriptionId'], 'subscription': c.sub(lb['subscriptionId']),
                       'resourceGroup': lb['resourceGroup'], 'rule': pth['rule'], 'type': pth['type'], 'publicIp': pth['publicIp'],
                       'frontendPort': pth['frontendPort'], 'backendPort': pth['backendPort'], 'protocol': pth['protocol'],
                       'backendMembers': len(pth['members']), 'unresolvedMembers': pth['unresolvedMembers'], 'poolFound': pth['poolFound'],
                       'nsgAllowsFromInternet': any(m['allowed'] for m in ev) if ev else None, 'memberEvaluation': ev[:5]})
    by_lb = {}
    for x in lb_inv:
        by_lb.setdefault(lid(f"{x['subscriptionId']}/{x['resourceGroup']}/{x['loadBalancer']}"), []).append(x)
    for key, rows in by_lb.items():
        lbobj = next(lb for lb in c.lb.values() if lid(f"{lb['subscriptionId']}/{lb['resourceGroup']}/{lb['name']}") == key)
        sens = [x for x in rows if x['nsgAllowsFromInternet'] is not False and any(
            pt in ADMIN_PORTS or pt in RISKY for pt in (x['backendPort'], x['frontendPort']))]
        if not sens:
            continue
        hi = [x for x in sens if x['backendPort'] in RISKY or x['frontendPort'] in RISKY]
        desc = ', '.join(sorted({f"{x['publicIp']}:{x['frontendPort']}/{x['protocol']}→{x['backendPort']}"
                                 f"（{ADMIN_PORTS.get(x['backendPort']) or RISKY.get(x['backendPort']) or ADMIN_PORTS.get(x['frontendPort']) or ''}）" for x in sens}))
        aks = lbobj['resourceGroup'].lower().startswith('mc_')
        F.add('S-N6', '高' if hi else '中', lbobj, 'Microsoft.Network/loadBalancers',
              f'公网负载均衡 {lbobj["name"]}（{lbobj["resourceGroup"]}）把敏感端口暴露到 Internet 且 NSG 放行：{desc}。',
              {'sensitiveRules': sens, 'allPublicRules': rows},
              ('这些规则来自 AKS Service(type=LoadBalancer)：' if aks else '')
              + '请确认端口用途；管理/调试类端口应改为内部负载均衡，或在 Service 上设置 loadBalancerSourceRanges 只允许固定 IP。', confirm=True)
    return lb_inv


def _private_link_services(c, F):
    rtype = 'Microsoft.Network/privateLinkServices'
    inv = []
    for r in c.rows('pls'):
        p = r.get('properties') or {}
        vis = (p.get('visibility') or {}).get('subscriptions') or []
        auto = (p.get('autoApproval') or {}).get('subscriptions') or []
        conns = []
        for x in p.get('privateEndpointConnections') or []:
            q = x.get('properties') or {}
            peid = (q.get('privateEndpoint') or {}).get('id') or ''
            conns.append({'peSubscription': peid.split('/')[2] if peid.count('/') > 2 else None,
                          'status': (q.get('privateLinkServiceConnectionState') or {}).get('status')})
        item = {'name': r['name'], 'subscription': c.sub(r['subscriptionId']), 'resourceGroup': r['resourceGroup'],
                'visibility': vis, 'autoApproval': auto, 'connections': conns}
        inv.append(item)
        if '*' in auto:
            F.add('S-N6', '中', r, rtype,
                  f'Private Link Service {r["name"]} 的可见性和自动批准都设为 "*"，任何 Azure 订阅都能创建私有终结点并被自动接入后端服务（绕过 Front Door/WAF）。',
                  {'pls': item}, '清空自动批准（改为人工批准，Front Door 私有源本来就需要人工批准一次），可见性按需收窄；现有已批准连接不受影响。', confirm=True)
        elif '*' in vis:
            F.add('S-N6', '低', r, rtype,
                  f'Private Link Service {r["name"]} 对所有订阅可见（visibility="*"），但连接需要人工批准。',
                  {'pls': item}, '任何订阅都能提交连接请求；建议定期核对待批准/已批准连接，只批准 Front Door 的连接。')
    return inv


def check_edge(c, F, arm, paths):
    wafpol = {lid(x['id']): x for x in c.rows('appgw_wafpolicies')}
    agw_inv = [_app_gateway(c, F, r, wafpol) for r in c.rows('appgateways')]
    fdwaf = {lid(x['id']): x for x in c.rows('fd_wafpolicies')}
    sp_all, ep_all = arm('afd_secpol'), arm('afd_endpoints')
    afd_inv = [_front_door(c, F, r, fdwaf, sp_all, ep_all) for r in c.rows('cdn_profiles')
               if 'frontdoor' in ((r.get('sku') or {}).get('name') or '').lower()]
    lb_inv = _public_lbs(c, F, paths)
    pls_inv = _private_link_services(c, F)
    return {'appGateways': agw_inv, 'frontDoors': afd_inv, 'publicLoadBalancerRules': lb_inv, 'privateLinkServices': pls_inv}
