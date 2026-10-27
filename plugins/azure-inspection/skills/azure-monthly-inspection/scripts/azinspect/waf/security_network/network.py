"""Offline network model: NSG first-match evaluation, Internet-facing paths and reachable ports.

Reachability is judged from configuration only (two NSG layers, direct public IPs, public load balancer rules).
No port scanning or connection attempt is ever made.
"""
from __future__ import annotations

import ipaddress

MGMT_PORTS = {22: 'SSH', 3389: 'RDP', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS'}
DB_PORTS = {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'SQL Server', 6379: 'Redis', 6380: 'Redis-TLS',
            27017: 'MongoDB', 9200: 'Elasticsearch/OpenSearch HTTP', 9300: 'Elasticsearch/OpenSearch 传输',
            8123: 'ClickHouse HTTP', 9000: 'ClickHouse 原生/MinIO', 2181: 'ZooKeeper', 9092: 'Kafka'}
ADMIN_PORTS = {5005: 'Java 远程调试(JDWP)常用端口', 18083: 'EMQX 管理控制台', 8300: 'Consul RPC',
               8500: 'Consul UI/API', 8848: 'Nacos', 5601: 'Kibana',
               9090: 'Prometheus', 15672: 'RabbitMQ 管理', 2375: 'Docker API', 2376: 'Docker API(TLS)',
               10250: 'kubelet', 6443: 'Kubernetes API', 3128: 'HTTP 代理', 9600: 'OpenSearch 性能分析',
               5540: 'RedisInsight', 8080: 'HTTP 管理/控制台(常见)'}
RISKY = {**MGMT_PORTS, **DB_PORTS}
INET_SRC = {'*', 'internet', '0.0.0.0/0', 'any'}
INFRA_SUBNETS = {'gatewaysubnet', 'azurefirewallsubnet', 'azurefirewallmanagementsubnet', 'azurebastionsubnet', 'routeserversubnet'}
NSG_UNSUPPORTED_DELEGATIONS = {'microsoft.netapp/volumes'}


def lid(x):
    return (x or '').lower()


def parts(rid):
    seg = (rid or '').split('/')
    return {seg[i].lower(): seg[i + 1] for i in range(1, len(seg) - 1, 2)}


def port_match(spec, port):
    spec = str(spec).strip()
    if spec in ('*', ''):
        return True
    if '-' in spec:
        a, b = spec.split('-', 1)
        return int(a) <= port <= int(b)
    return int(spec) == port


def rule_ports(q):
    return [p for p in [q.get('destinationPortRange')] + list(q.get('destinationPortRanges') or []) if p]


def rule_srcs(q):
    return [s for s in [q.get('sourceAddressPrefix')] + list(q.get('sourceAddressPrefixes') or []) if s]


def rule_dsts(q):
    return [s for s in [q.get('destinationAddressPrefix')] + list(q.get('destinationAddressPrefixes') or []) if s]


def src_is_internet(q):
    return any(s.lower() in INET_SRC for s in rule_srcs(q))


def dst_match(q, ips):
    if q.get('destinationApplicationSecurityGroups'):
        return True  # conservative: an ASG target may contain the instance
    ips = [ip for ip in ips if ip]
    for d in rule_dsts(q):
        dl = d.lower()
        if dl in ('*', 'any', 'internet'):
            return True
        if dl == 'virtualnetwork':
            if any(ipaddress.ip_address(ip).is_private for ip in ips):
                return True
            continue
        try:
            net = ipaddress.ip_network(d, strict=False)
        except ValueError:
            continue
        if any(ipaddress.ip_address(ip) in net for ip in ips):
            return True
    return False


def proto_match(q, proto):
    p = (q.get('protocol') or '*').lower()
    return p in ('*', 'any') or p == proto.lower()


def nsg_eval(nsg, port, proto, ips):
    """First-match evaluation of Internet -> port inbound. Returns (access, ruleName)."""
    p = nsg.get('properties') or {}
    rules = list(p.get('securityRules') or []) + list(p.get('defaultSecurityRules') or [])
    rules = [r for r in rules if (r.get('properties') or {}).get('direction') == 'Inbound']
    rules.sort(key=lambda r: r['properties'].get('priority', 99999))
    for r in rules:
        q = r['properties']
        if not proto_match(q, proto) or not src_is_internet(q):
            continue
        if not any(port_match(s, port) for s in rule_ports(q)):
            continue
        if not dst_match(q, ips):
            continue
        return q.get('access'), r.get('name')
    return 'Deny', '(no match)'


def range_size(a, b):
    try:
        return int(ipaddress.ip_address(b)) - int(ipaddress.ip_address(a)) + 1
    except ValueError:
        return None


class Ctx:
    """Indexes over the Resource Graph rows."""

    def __init__(self, arg, subname):
        self.A = arg
        self.subname = subname
        self.nsg = {lid(n['id']): n for n in self.rows('nsgs')}
        self.nic = {lid(n['id']): n for n in self.rows('nics')}
        self.pip = {lid(p['id']): p for p in self.rows('publicips')}
        self.vmss = {lid(v['id']): v for v in self.rows('vmss')}
        self.vm = {lid(v['id']): v for v in self.rows('vms')}
        self.lb = {lid(x['id']): x for x in self.rows('loadbalancers')}
        self.subnet = {}
        for v in self.rows('vnets'):
            for s in (v.get('properties') or {}).get('subnets') or []:
                s['_vnet'] = v
                self.subnet[lid(s['id'])] = s
        self._index_nics()
        self._index_vmss()
        self.subnet_nsg = {k: lid(((s.get('properties') or {}).get('networkSecurityGroup') or {}).get('id')) for k, s in self.subnet.items()}

    def rows(self, key):
        return self.A(key) or []

    def _index_nics(self):
        self.ipcfg, self.ip_to_ipcfg = {}, {}
        for n in self.nic.values():
            np_ = n.get('properties') or {}
            for ic in np_.get('ipConfigurations') or []:
                q = ic.get('properties') or {}
                ep = {'kind': 'nic', 'nic': n, 'ipcfgId': ic['id'], 'subnet': lid((q.get('subnet') or {}).get('id')),
                      'nicNsg': lid((np_.get('networkSecurityGroup') or {}).get('id')),
                      'pip': lid((q.get('publicIPAddress') or {}).get('id')), 'privateIp': q.get('privateIPAddress'),
                      'vm': lid((np_.get('virtualMachine') or {}).get('id')),
                      'privateEndpoint': bool(np_.get('privateEndpoint')), 'pls': bool(np_.get('privateLinkService'))}
                self.ipcfg[lid(ic['id'])] = ep
                if q.get('privateIPAddress'):
                    self.ip_to_ipcfg[q['privateIPAddress']] = lid(ic['id'])

    def _index_vmss(self):
        self.vmss_eps = {}
        for v in self.vmss.values():
            eps = []
            for nc in ((v.get('properties') or {}).get('networkProfile') or {}).get('networkInterfaceConfigurations') or []:
                ncp = nc.get('properties') or {}
                for ic in ncp.get('ipConfigurations') or []:
                    q = ic.get('properties') or {}
                    eps.append({'kind': 'vmss', 'vmss': v, 'subnet': lid((q.get('subnet') or {}).get('id')),
                                'nicNsg': lid((ncp.get('networkSecurityGroup') or {}).get('id')),
                                'publicIpConfig': q.get('publicIPAddressConfiguration'), 'privateIp': None,
                                'pools': [lid(p['id']) for p in q.get('loadBalancerBackendAddressPools') or []]})
            self.vmss_eps[lid(v['id'])] = eps

    def sub(self, sub_id):
        return self.subname.get(lid(sub_id))


def resolve_member(c, ipcfg_id=None, ip=None):
    k = lid(ipcfg_id)
    if k and k in c.ipcfg:
        return c.ipcfg[k]
    if k and '/virtualmachinescalesets/' in k:
        eps = c.vmss_eps.get(k.split('/virtualmachines/')[0]) or []
        return eps[0] if eps else None
    if ip and ip in c.ip_to_ipcfg:
        return c.ipcfg[c.ip_to_ipcfg[ip]]
    return None


def endpoint_label(c, ep):
    if ep is None:
        return None
    if ep['kind'] == 'nic':
        vmname = parts(ep['vm']).get('virtualmachines') if ep.get('vm') else None
        return f'VM {vmname}' if vmname else f"NIC {ep['nic']['name']}"
    if ep['kind'] == 'vmss':
        return f"VMSS {ep['vmss']['name']}"
    return ep.get('id')


def effective(c, ep, port, proto, ips):
    """Evaluate both NSG layers (Standard SKU: no NSG = deny inbound). Returns (allowed, detail)."""
    layers = []
    sn = c.subnet_nsg.get(ep.get('subnet') or '', '')
    if sn:
        layers.append(('subnet', sn))
    if ep.get('nicNsg'):
        layers.append(('nic', ep['nicNsg']))
    if not layers:
        return False, 'no NSG on subnet/NIC: Standard SKU denies inbound by default'
    detail = []
    for kind, nid in layers:
        n = c.nsg.get(nid)
        if not n:
            return None, f'{kind} NSG {nid} not readable'
        acc, rule = nsg_eval(n, port, proto, ips)
        detail.append(f"{kind}:{n['name']}/{rule}={acc}")
        if acc != 'Allow':
            return False, '; '.join(detail)
    return True, '; '.join(detail)


def _pool_members(c, pool):
    out = []
    if not pool:
        return out
    bp = pool.get('properties') or {}
    for bic in bp.get('backendIPConfigurations') or []:
        out.append(resolve_member(c, ipcfg_id=bic.get('id')))
    if not bp.get('backendIPConfigurations'):
        for ba in bp.get('loadBalancerBackendAddresses') or []:
            bap = ba.get('properties') or {}
            if bap.get('networkInterfaceIPConfiguration'):
                out.append(resolve_member(c, ipcfg_id=bap['networkInterfaceIPConfiguration'].get('id')))
            elif bap.get('ipAddress'):
                out.append(resolve_member(c, ip=bap.get('ipAddress')))
    return out


def _lb_paths(c, lb):
    p = lb.get('properties') or {}
    fe_pub = {}
    for f in p.get('frontendIPConfigurations') or []:
        pid = lid(((f.get('properties') or {}).get('publicIPAddress') or {}).get('id'))
        if pid:
            fe_pub[lid(f['id'])] = ((c.pip.get(pid) or {}).get('properties') or {}).get('ipAddress')
    if not fe_pub:
        return []
    pools = {lid(b['id']): b for b in p.get('backendAddressPools') or []}
    paths = []
    for r in p.get('loadBalancingRules') or []:
        q = r.get('properties') or {}
        fe = lid((q.get('frontendIPConfiguration') or {}).get('id'))
        if fe not in fe_pub:
            continue
        pool = pools.get(lid((q.get('backendAddressPool') or {}).get('id')))
        members = _pool_members(c, pool)
        uniq = {}
        for m in members:
            if m is not None:
                uniq.setdefault((m.get('subnet'), m.get('nicNsg'), endpoint_label(c, m)), m)
        paths.append({'type': 'lb-rule', 'lb': lb, 'rule': r.get('name'), 'publicIp': fe_pub[fe],
                      'frontendPort': q.get('frontendPort'), 'backendPort': q.get('backendPort'),
                      'protocol': q.get('protocol'), 'floating': q.get('enableFloatingIP'),
                      'members': list(uniq.values()), 'unresolvedMembers': sum(1 for m in members if m is None),
                      'poolFound': pool is not None})
    for r in p.get('inboundNatRules') or []:
        q = r.get('properties') or {}
        fe = lid((q.get('frontendIPConfiguration') or {}).get('id'))
        if fe not in fe_pub:
            continue
        if q.get('backendIPConfiguration'):
            ms = [resolve_member(c, ipcfg_id=q['backendIPConfiguration'].get('id'))]
        else:
            ms = _pool_members(c, pools.get(lid((q.get('backendAddressPool') or {}).get('id'))))
        paths.append({'type': 'lb-nat', 'lb': lb, 'rule': r.get('name'), 'publicIp': fe_pub[fe],
                      'frontendPort': q.get('frontendPort') or q.get('frontendPortRangeStart'),
                      'backendPort': q.get('backendPort'), 'protocol': q.get('protocol'),
                      'floating': q.get('enableFloatingIP'), 'members': [m for m in ms if m],
                      'unresolvedMembers': sum(1 for m in ms if m is None), 'poolFound': True})
    return paths


def public_paths(c):
    """Internet-facing paths: direct NIC public IP, VMSS instance public IP, public LB rules and NAT rules."""
    paths = []
    for ep in c.ipcfg.values():
        if ep['pip']:
            pip = c.pip.get(ep['pip']) or {}
            paths.append({'type': 'nic-pip', 'ep': ep, 'publicIp': (pip.get('properties') or {}).get('ipAddress'),
                          'pipName': pip.get('name'), 'pipSku': (pip.get('sku') or {}).get('name')})
    for eps in c.vmss_eps.values():
        for ep in eps:
            if ep.get('publicIpConfig'):
                paths.append({'type': 'vmss-pip', 'ep': ep, 'publicIp': None, 'pipName': 'instance-level',
                              'pipSku': (ep['publicIpConfig'].get('sku') or {}).get('name')})
    for lb in c.lb.values():
        paths.extend(_lb_paths(c, lb))
    return paths


def candidate_ports(c, ep):
    ports = set(RISKY) | set(ADMIN_PORTS)
    for nid in (c.subnet_nsg.get(ep.get('subnet') or '', ''), ep.get('nicNsg')):
        n = c.nsg.get(nid or '')
        if not n:
            continue
        for r in (n.get('properties') or {}).get('securityRules') or []:
            q = r['properties']
            if q.get('direction') == 'Inbound' and q.get('access') == 'Allow' and src_is_internet(q):
                for s in rule_ports(q):
                    s = str(s)
                    if s != '*':
                        ports.add(int(s.split('-', 1)[0]))
    return ports


def evaluate_exposures(c, paths):
    exposures = []
    for pth in paths:
        if pth['type'] in ('nic-pip', 'vmss-pip'):
            ep = pth['ep']
            ips = [pth.get('publicIp'), ep.get('privateIp')]
            for port in sorted(candidate_ports(c, ep)):
                for proto in ('Tcp', 'Udp'):
                    ok, det = effective(c, ep, port, proto, ips)
                    if ok:
                        exposures.append({'path': pth, 'ep': ep, 'port': port, 'publicPort': port, 'proto': proto, 'detail': det})
            ok, det = effective(c, ep, 64999, 'Tcp', ips)  # probe for any-port rules
            if ok:
                exposures.append({'path': pth, 'ep': ep, 'port': '*', 'publicPort': '*', 'proto': 'Tcp', 'detail': det})
            continue
        for m in pth['members']:
            proto = 'Udp' if (pth.get('protocol') or '').lower() == 'udp' else 'Tcp'
            ips = [pth.get('publicIp'), m.get('privateIp')]
            ok, det = effective(c, m, int(pth['backendPort'] or 0), proto, ips)
            pth.setdefault('memberEval', []).append({'member': endpoint_label(c, m), 'allowed': ok, 'detail': det})
            if ok:
                exposures.append({'path': pth, 'ep': m, 'port': pth['backendPort'], 'publicPort': pth['frontendPort'],
                                  'proto': proto, 'detail': det})
    return exposures


def exposure_text(c, e):
    p = e['path']
    return f"{endpoint_label(c, e['ep'])} 公网 {p.get('publicIp') or p.get('pipName')}:{e['publicPort']}→{e['port']}/{e['proto']}"
