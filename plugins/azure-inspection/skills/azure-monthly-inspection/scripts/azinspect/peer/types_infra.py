"""Peer comparison for Application Gateway, Front Door, virtual machines, VNets and database/cache diagnostics."""
from __future__ import annotations

import collections

from .engine import TypeReport, std_root_cause
from .types_platform import SN, _diag_counts

SPECIAL_SUBNETS = {'gatewaysubnet', 'azurebastionsubnet', 'azurefirewallsubnet', 'azurefirewallmanagementsubnet', 'routeserversubnet'}


def appgw_type(ctx):
    T = TypeReport(ctx, 'appgw', '应用网关（Application Gateway）')
    policies = {r['id'].lower(): r for r in ctx.rows(f'{SN}/arg/appgw_wafpolicies.json')}
    for r in ctx.rows(f'{SN}/arg/appgateways.json'):
        it = T.basic(r)
        p = r.get('properties') or {}
        fp = ((p.get('firewallPolicy') or {}).get('id') or '').lower()
        ps = ((policies.get(fp) or {}).get('properties') or {}).get('policySettings') or {}
        sku = p.get('sku') or {}
        it.update({'sku': sku.get('tier'), 'cap': sku.get('capacity'), 'auto': p.get('autoscaleConfiguration'), 'zones': r.get('zones'),
                   'wafOn': bool(fp) and ps.get('state') == 'Enabled' and ps.get('mode') == 'Prevention',
                   'waf': f'策略 {ps.get("state")}/{ps.get("mode")}' if fp else '无 WAF',
                   'http': sum(1 for x in p.get('httpListeners') or [] if (x.get('properties') or {}).get('protocol') == 'Http')})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}
    T.baseline_rationale = ('目标做法：WAF_v2（WAF 启用并为防护模式）或前置 Front Door WAF、自动扩缩最少 2 实例、跨可用区；'
                            f'当前 {sum(r["wafOn"] for r in T.items)}/{n} 个网关有有效 WAF。')
    T.attr('waf', 'WAF', 'WAF 启用且为防护（Prevention）模式', lambda r: f'{r["sku"]}，{r["waf"]}', lambda r: not r['wafOn'],
           rec=lambda r: ('把 WAF 策略启用并在观察误报后切到防护模式' if r['sku'] == 'WAF_v2'
                          else '把 SKU 从 Standard_v2 原地升级为 WAF_v2 并关联 WAF 策略（或把入口放到已有的 Front Door Premium WAF 后面）'),
           feas='原地修改（需维护窗口或应用配合）', major=True)
    T.attr('capacity', '实例数/扩缩', '自动扩缩，最少 2 实例', lambda r: f'固定 {r["cap"]} 实例' if not r['auto'] else '自动扩缩',
           lambda r: not r['auto'] and (r['cap'] or 0) < 2, rec='改为自动扩缩（最小 2）', feas='原地修改')
    T.attr('zones', '可用区', '跨可用区（1/2/3）', lambda r: '未配置', lambda r: not r['zones'],
           rec='新建跨可用区的应用网关并切换公网 IP/DNS（可用区不能在现有网关上修改）', feas='新建节点池/新实例替换（不重建整体）',
           short='先把实例数提到 2 以上，降低单实例维护中断')

    def rc(r):
        notes = []
        if r['sku'] == 'WAF_v2' and not r['wafOn']:
            notes.append(f'按 WAF_v2 计费，但关联的 WAF 策略为“{r["waf"]}”，等于没有有效防护')
        if r['http']:
            notes.append(f'有 {r["http"]} 个 HTTP 明文监听')
        return std_root_cause(ctx, r, notes)
    T.run(rc)
    return T, {'sku': 'WAF_v2（WAF Prevention）或前置 Front Door WAF', 'autoscaleMin': 2, 'zones': '1,2,3'}


def afd_type(ctx):
    T = TypeReport(ctx, 'frontdoor', 'Front Door')
    waf = {r['id'].lower(): r for r in ctx.rows(f'{SN}/arg/fd_wafpolicies.json')}
    secpol = ctx.load(f'{SN}/arm/afd_secpol.json', {}) or {}
    for r in ctx.rows(f'{SN}/arg/cdn_profiles.json'):
        it = T.basic(r)
        pols = []
        for x in (secpol.get(r['id']) or {}).get('data') or []:
            wid = ((((x.get('properties') or {}).get('parameters') or {}).get('wafPolicy') or {}).get('id') or '').lower()
            w = waf.get(wid) or {}
            wp = w.get('properties') or {}
            pols.append({'name': w.get('name'), 'state': (wp.get('policySettings') or {}).get('enabledState'),
                         'mode': (wp.get('policySettings') or {}).get('mode'),
                         'managed': [m.get('ruleSetType') for m in (wp.get('managedRules') or {}).get('managedRuleSets', [])]})
        it.update({'sku': (r.get('sku') or {}).get('name'), 'pols': pols})
        T.items.append(it)
    n = len(T.items)
    if not n:
        return T, {}
    managed = sum(1 for r in T.items if any(p['managed'] for p in r['pols']))
    T.baseline_rationale = f'{managed}/{n} 个 Front Door 启用了微软托管规则集（Premium）；以此为标准。'
    T.attr('waf', 'WAF 托管规则', f'Premium + 默认规则集 + Bot 规则（{managed}/{n} 个）',
           lambda r: f'{r["sku"]}，' + ('；'.join(f'{p["name"]}：托管规则 {p["managed"] or "无"}' for p in r['pols']) if r['pols'] else '未关联任何 WAF 策略'),
           lambda r: not r['pols'] or not any(p['managed'] for p in r['pols']),
           rec=lambda r: ('关联 WAF 策略；' if not r['pols'] else '') + '把 SKU 原地升级为 Premium 并启用默认规则集 + Bot 规则（Standard 不支持托管规则）',
           feas='原地修改', major=True)
    T.run(lambda r: std_root_cause(ctx, r))
    prevention = sum(1 for r in T.items if any(p['mode'] == 'Prevention' for p in r['pols']))
    if prevention == 0:
        T.uniform_gaps.append({'attribute': 'WAF 模式', 'followedBy': 0, 'of': n, 'note': '全部为检测（Detection）模式，只记录不拦截；观察误报后原地切到防护模式。'})
    return T, {'sku': 'Premium', 'managedRules': 'DefaultRuleSet + BotManager', 'mode': 'Prevention（目标）'}


def vm_type(ctx):
    T = TypeReport(ctx, 'vm', '虚拟机（按订阅分组）')
    vms = ctx.rows('security_identity/arg/vms.json')
    nics = ctx.rows('security_identity/arg/vm_nics.json')
    ext = ctx.rows('security_identity/arg/vm_extensions.json')
    ops = {x['id'].lower(): x for x in ctx.rows('operations/arg/vms.json')}
    pips, exts = collections.defaultdict(list), collections.defaultdict(list)
    for n in nics:
        if n.get('vmId'):
            pips[n['vmId'].lower()].append(n)
    for e in ext:
        exts['/'.join(e['id'].lower().split('/')[:9])].append(e.get('extType') or '')
    per_vm = []
    for v in vms:
        if str(v.get('resourceGroup') or '').lower().startswith('mc_'):
            continue
        vid, sub = v['id'].lower(), ctx.sub_name(v.get('subscriptionId') or v['id'].split('/')[2])
        o = ops.get(vid, {})
        tags = o.get('tags') if isinstance(o.get('tags'), dict) else (v.get('tags') if isinstance(v.get('tags'), dict) else {})
        per_vm.append({'name': v['name'], 'sub': sub, 'rg': v.get('resourceGroup'), 'tf': ctx.standard(tags),
                       'zones': bool(v.get('zones')), 'pip': any(x.get('publicIpId') for x in pips.get(vid, [])),
                       'pwd': v.get('osType') == 'Linux' and v.get('disablePasswordAuthentication') is False,
                       'noOsProfile': v.get('osType') == 'Linux' and v.get('disablePasswordAuthentication') is None,
                       'ama': any('AzureMonitor' in t for t in exts.get(vid, [])),
                       'created': (o.get('created') or '')[:10] or ctx.created(v['id']),
                       'portal': bool(ctx.creation_deploy(v['name'], sub, 'virtualMachines'))})
    groups = collections.defaultdict(list)
    for v in per_vm:
        groups[v['sub']].append(v)
    for sub, vs in sorted(groups.items()):
        e = ctx.env(sub)
        it = {'id': None, 'name': f'{sub}：{len(vs)} 台虚拟机', 'sub': sub, 'rg': ','.join(sorted({v['rg'] for v in vs}))[:120],
              'tf': all(v['tf'] for v in vs), 'tfCount': sum(v['tf'] for v in vs), 'env': e['label'], 'prod': e['value'] == 'prod',
              'line': ctx.line(sub), 'vendor': None, 'created': min((v['created'] for v in vs if v['created']), default=None), 'vms': vs,
              'pipVms': [v['name'] for v in vs if v['pip']], 'pwdVms': [v['name'] for v in vs if v['pwd']],
              'noZoneVms': [v['name'] for v in vs if not v['zones']], 'noOsProfileVms': [v['name'] for v in vs if v['noOsProfile']]}
        T.items.append(it)
    total = len(per_vm)
    if not total:
        return T, {}
    n_pip = sum(v['pip'] for v in per_vm)
    n_key = sum(1 for v in per_vm if not v['pwd'] and not v['noOsProfile'])
    T.population_note = f'共 {total} 台（不含 AKS 节点）；按订阅分成 {len(groups)} 组列出偏差，组内列出具体机器名'
    T.baseline_rationale = (f'{n_pip}/{total} 台虚拟机直接绑定公网 IP。以不带公网 IP、经 Bastion 或跳板机访问的机器为标准；'
                            f'SSH 只用密钥（{n_key}/{total} 台已是如此或为 Windows）；生产机指定可用区（{sum(v["zones"] for v in per_vm)}/{total}）。')
    T.attr('publicIp', '直接绑定公网 IP', '不绑定，经 Bastion/跳板机访问',
           lambda r: f'{len(r["pipVms"])}/{len(r["vms"])} 台：' + ', '.join(r['pipVms'][:12]) + ('…' if len(r['pipVms']) > 12 else ''),
           lambda r: bool(r['pipVms']),
           rec='把管理入口收敛到 Bastion（可通过 VNet 对等复用已有的 Bastion）或跳板机，解除业务机上的公网 IP；对外服务改由负载均衡或应用网关发布',
           feas='原地修改（需维护窗口或应用配合）', short='先把 NSG 中 22/3389 的来源从 Any 改为办公网或跳板机 IP',
           confirm='部分机器可能确实需要公网直连业务端口，请确认后只保留业务端口', major=True)
    T.attr('sshPassword', 'SSH 密码登录', '禁用（只用密钥）', lambda r: f'{len(r["pwdVms"])} 台允许密码：' + ', '.join(r['pwdVms'][:12]),
           lambda r: bool(r['pwdVms']),
           rec='在系统内把 sshd 的 PasswordAuthentication 设为 no 并分发密钥；模板把 disable_password_authentication 默认改为 true（已有机器改此参数会触发重建，应在系统内改）',
           feas='原地修改', major=True)
    T.attr('zones', '可用区（生产）', '指定可用区，同类多台分散到不同可用区', lambda r: f'{len(r["noZoneVms"])} 台未指定可用区',
           lambda r: r['prod'] and len(r['noZoneVms']) >= 2,
           rec='同类多台按可用区重建，或用 Azure 的“区域到可用区迁移”功能迁移，分散到 1/2/3 区', feas='需重建并迁移',
           short='为关键机器补上 Azure 备份，降低单可用区故障时的恢复时间')

    def rc(r):
        notes = []
        if r['noOsProfileVms']:
            notes.append(f'{len(r["noOsProfileVms"])} 台在管理面没有 osProfile（由已有磁盘创建或整机迁移而来）：{", ".join(r["noOsProfileVms"][:12])}')
        portal = [v['name'] for v in r['vms'] if v['portal']]
        if portal:
            notes.append(f'{len(portal)} 台有门户“创建虚拟机”向导部署记录（门户默认会给新机器分配公网 IP 并开放 SSH）')
        pwd_tf = [v['name'] for v in r['vms'] if v['tf'] and v['pwd']]
        nz_tf = [v['name'] for v in r['vms'] if v['tf'] and not v['zones']]
        if pwd_tf:
            notes.append(f'{len(pwd_tf)} 台按 {ctx.standard_name} 创建的机器仍允许 SSH 密码登录，属于模板默认值问题')
        if nz_tf:
            notes.append(f'{len(nz_tf)} 台按 {ctx.standard_name} 创建的机器未指定可用区，同样是模板参数问题')
        return {'standardTagged': f'{r["tfCount"]}/{len(r["vms"])}', 'earliestCreated': r['created'], 'businessLine': r['line'], 'notes': notes}
    T.run(rc, lambda r, d: d.update({'linkedFindingIds': ctx.linked(r['sub'], checks={'S-N3', 'S-I8', 'R3', 'R7'})[:12]}))
    T.uniform_gaps = [
        {'attribute': 'Azure 备份', 'followedBy': None, 'of': total, 'note': '见可靠性检查 R7（虚拟机备份）。'},
        {'attribute': 'Azure Monitor 代理', 'followedBy': sum(v['ama'] for v in per_vm), 'of': total, 'note': '安装了 Azure Monitor 代理的机器数。'}]
    return T, {'publicIp': '无', 'sshAuth': '仅密钥', 'zones': '指定并分散', 'backup': 'Azure 备份', 'monitoring': 'Azure Monitor 代理'}


def vnet_type(ctx):
    T = TypeReport(ctx, 'vnet', '虚拟网络与子网（NSG 关联）')
    in_use = with_nsg = 0
    for v in ctx.rows(f'{SN}/arg/vnets.json'):
        it = T.basic(v)
        subnets = []
        for s in (v.get('properties') or {}).get('subnets') or []:
            sp = s.get('properties') or {}
            if s['name'].lower() in SPECIAL_SUBNETS:
                continue
            ipc = len(sp.get('ipConfigurations') or [])
            subnets.append({'name': s['name'], 'prefix': sp.get('addressPrefix') or (sp.get('addressPrefixes') or [None])[0],
                            'nsg': bool(sp.get('networkSecurityGroup')), 'inUse': ipc > 0, 'ipc': ipc})
        it['subnets'] = subnets
        it['inUseNoNsg'] = [f'{s["name"]}({s["ipc"]})' for s in subnets if s['inUse'] and not s['nsg']]
        in_use += sum(s['inUse'] for s in subnets)
        with_nsg += sum(1 for s in subnets if s['inUse'] and s['nsg'])
        T.items.append(it)
    if not T.items:
        return T, {}
    T.baseline_rationale = f'以每个在用业务子网都关联 NSG 的 VNet 为标准；在用子网中 {with_nsg}/{in_use} 已关联 NSG。'

    def vendor_subnets(r):
        hits = [x for x in r['inUseNoNsg'] if ctx.vendor(x.split('(')[0])]
        return f'{"、".join(hits)} 由供应商使用，加 NSG 前请与供应商确认所需端口' if hits else None
    T.attr('nsg', '在用子网关联 NSG', '每个在用业务子网都关联 NSG',
           lambda r: '未关联 NSG 的在用子网（括号内为 IP 配置数）：' + ', '.join(r['inUseNoNsg']), lambda r: bool(r['inUseNoNsg']),
           rec='为这些子网关联与同类 VNet 相同的子网 NSG（先以“允许现有流量”的规则上线，再逐步收紧）', feas='原地修改', confirm=vendor_subnets)
    T.run(lambda r: std_root_cause(ctx, r))
    return T, {'nsg': '每个在用业务子网关联 NSG'}


def diag_type(ctx):
    T = TypeReport(ctx, 'dbdiag', '数据库与缓存的诊断日志/告警（生产）')
    diag = _diag_counts(ctx)
    rows = []
    for kind in ('mysql', 'postgres', 'redisenterprise', 'redis', 'mongoclusters'):
        for r in ctx.rows(f'{SN}/arg/{kind}.json'):
            it = T.basic(r)
            if not it['prod']:
                continue
            it['diag'] = diag.get(r['id'].lower(), 0)
            rows.append(it)
    if not rows:
        return T, {}
    by_line = collections.defaultdict(list)
    for r in rows:
        by_line[r['line']].append(r)
    with_diag = [r['name'] for r in rows if r['diag']]
    for line, rs in sorted(by_line.items()):
        T.items.append({'id': None, 'name': f'{line}：{len(rs)} 个生产数据库/缓存', 'sub': ','.join(sorted({r['sub'] for r in rs})), 'rg': None,
                        'tf': all(r['tf'] for r in rs), 'env': '生产', 'prod': True, 'line': line, 'vendor': None, 'created': None,
                        'members': rs, 'noDiag': [r['name'] for r in rs if not r['diag']]})
    T.baseline_rationale = (f'以已把慢查询、审计等日志导出到 Log Analytics 的实例为标准（{len(with_diag)}/{len(rows)} 个：{", ".join(with_diag[:6])}'
                            + ('…' if len(with_diag) > 6 else '') + '）。' if with_diag else '没有内部范例，按微软推荐导出关键日志。')
    T.attr('diag', '诊断日志导出', '慢查询/审计等日志导出到 Log Analytics', lambda r: f'{len(r["noDiag"])}/{len(r["members"])} 个未导出',
           lambda r: bool(r['noDiag']),
           rec='为同类资源补诊断设置（MySQL 慢查询/审计、PostgreSQL 日志、Redis 连接/审计），并配置 CPU、内存、存储、连接数、可用性告警',
           feas='原地修改')
    T.run(lambda r: {'notes': [f'未导出日志的资源：{", ".join(r["noDiag"][:20])}' + ('…' if len(r['noDiag']) > 20 else '')]},
          lambda r, d: d.update({'linkedFindingIds': ctx.linked(*[m['name'] for m in r['members'][:3]], checks={'O2'})}))
    T.uniform_gaps = [{'attribute': 'Azure 告警规则', 'followedBy': None, 'of': len(rows), 'note': '告警覆盖见卓越运营检查 O2（告警）。'}]
    return T, {'diagnostics': '关键日志进 Log Analytics', 'alerts': 'CPU/内存/存储/连接/可用性'}
