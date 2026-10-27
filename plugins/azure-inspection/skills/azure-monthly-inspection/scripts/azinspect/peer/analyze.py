"""Run the peer comparison over all resource types and write findings/peer/{baseline,links}.json (offline)."""
from __future__ import annotations

import collections
from datetime import datetime, timezone

from ..core.io import write_json
from . import links as links_mod
from .context import METHOD_PORTAL, METHOD_UNKNOWN, METHOD_VENDOR, Context
from .types_data import acr_type, ai_type, kv_type, la_type, storage_type
from .types_infra import afd_type, appgw_type, diag_type, vm_type, vnet_type
from .types_platform import aks_type, db_type, mongo_type, redis_type

BUILDERS = [aks_type, lambda c: db_type(c, 'mysql'), lambda c: db_type(c, 'postgres'), redis_type, mongo_type, storage_type,
            kv_type, acr_type, ai_type, appgw_type, afd_type, vm_type, vnet_type, la_type, diag_type]
# Types counted in the high-impact statistics (resource-level, with risk attributes)
HIGH_IMPACT_SCOPE_EXCLUDE = ('vm', 'dbdiag', 'keyvault', 'ai', 'loganalytics', 'vnet')
DEVIATION_SCOPE_EXCLUDE = ('vm', 'dbdiag', 'keyvault', 'ai', 'loganalytics')


def _pct(pair):
    return round(100 * pair[1] / pair[0], 1) if pair[0] else None


def cross_stats(ctx, types):
    major = {k: collections.defaultdict(lambda: [0, 0]) for k in ('byMethod', 'byLine', 'byRegion')}
    for T in types:
        if T.key in HIGH_IMPACT_SCOPE_EXCLUDE:
            continue
        for r in T.items:
            for k, v in (('byMethod', r.get('_method') or METHOD_UNKNOWN), ('byLine', r['line']), ('byRegion', r.get('region') or '其他/全局')):
                major[k][v][0] += 1
                major[k][v][1] += int(r.get('_major', False))
    by_type = collections.defaultdict(lambda: {'tf': [0, 0], 'nontf': [0, 0]})
    lines, months, vendor = collections.defaultdict(lambda: [0, 0]), collections.defaultdict(lambda: [0, 0]), [0, 0]
    for T in types:
        if T.key in DEVIATION_SCOPE_EXCLUDE:
            continue
        for r in T.items:
            dev = int(r.get('_deviated', False))
            k = 'tf' if r.get('tf') else 'nontf'
            by_type[T.label][k][0] += 1
            by_type[T.label][k][1] += dev
            lines[r['line']][0] += 1
            lines[r['line']][1] += dev
            if r.get('created'):
                months[r['created'][:7]][0] += 1
                months[r['created'][:7]][1] += dev
            if r.get('vendor'):
                vendor[0] += 1
                vendor[1] += dev
    tf = [sum(v['tf'][0] for v in by_type.values()), sum(v['tf'][1] for v in by_type.values())]
    nontf = [sum(v['nontf'][0] for v in by_type.values()), sum(v['nontf'][1] for v in by_type.values())]
    return {
        'standardVsOther': {
            'standardName': ctx.standard_name,
            'standard': {'resources': tf[0], 'deviating': tf[1], 'deviationPct': _pct(tf)},
            'other': {'resources': nontf[0], 'deviating': nontf[1], 'deviationPct': _pct(nontf)},
            'byType': {k: {'standard': {'n': v['tf'][0], 'deviating': v['tf'][1]}, 'other': {'n': v['nontf'][0], 'deviating': v['nontf'][1]}}
                       for k, v in by_type.items()}},
        'byBusinessLine': {k: {'resources': v[0], 'deviating': v[1], 'deviationPct': _pct(v)} for k, v in sorted(lines.items())},
        'byCreationMonth': {k: {'resources': v[0], 'deviating': v[1], 'deviationPct': _pct(v)} for k, v in sorted(months.items())},
        'vendorManaged': {'resources': vendor[0], 'deviating': vendor[1]},
        'highImpactDeviations': {
            'definition': '高风险偏差 = 直接对应安全风险或故障的属性偏差：AKS 节点子网分配 Pod IP 或公网 API；数据库有公网规则或无私有终结点；'
                          'Redis 无私有终结点或明文；业务存储对全网开放或 TLS 低于 1.2；镜像仓库开着管理员账号；应用网关或 Front Door 没有有效 WAF',
            **{k: {kk: {'resources': vv[0], 'highImpact': vv[1], 'pct': _pct(vv)} for kk, vv in sorted(v.items())} for k, v in major.items()}},
    }


def auto_insights(ctx, stats):
    """Default cross-type insights from the statistics (the agent can replace them in narrative/05.json)."""
    out = []
    by_method = stats['highImpactDeviations']['byMethod']
    if by_method:
        parts = '、'.join(f'{k} {v["highImpact"]}/{v["resources"]}（{v["pct"]}%）' for k, v in sorted(by_method.items(), key=lambda kv: -(kv[1]['pct'] or 0)))
        out.append({'title': '高风险偏差与创建方式的关系', 'detail': f'按创建方式统计有高风险偏差的资源：{parts}。'})
    by_line = {k: v for k, v in stats['highImpactDeviations']['byLine'].items() if v['resources'] >= 5}
    if by_line:
        parts = '、'.join(f'{k} {v["highImpact"]}/{v["resources"]}（{v["pct"]}%）' for k, v in sorted(by_line.items(), key=lambda kv: -(kv[1]['pct'] or 0)))
        out.append({'title': '高风险偏差按业务线的分布', 'detail': f'资源数不少于 5 个的业务线：{parts}。'})
    vendor = stats['vendorManaged']
    if vendor['resources']:
        out.append({'title': '供应商创建的资源', 'detail': f'供应商创建的资源 {vendor["resources"]} 个，其中 {vendor["deviating"]} 个与标准做法不同，需与供应商一起对齐。'})
    return out


COVERAGE_GAPS = [
    '没有读取具体创建人账号（活动日志只保留 90 天且含个人信息），只按部署历史判断创建方式。',
    '部署历史每个资源组最多保留 800 条，IaC 工具（如 Terraform）不留部署记录，因此“查不到部署记录”不能证明不是门户创建。',
    'AKS 节点资源组（MC_*）内的资源和 AKS 自动创建的存储账户由平台管理，没有参与比较。',
    '没有比较：NAT 网关和负载均衡（可靠性报告单独检查）、Event Hubs、Private Link Service、VPN 网关；数据库参数只比较了强制 TLS。',
    '虚拟机系统内的配置（sshd、防火墙）无法从 Azure 读取；由磁盘创建的虚拟机无法判断是否允许密码登录。',
]


def analyze(ws, cfg, log=print):
    ctx = Context(ws, cfg)
    types, out_types = [], []
    for build in BUILDERS:
        T, base = build(ctx)
        if not T.items:
            continue
        types.append(T)
        out_types.append(T.to_json(base))
    stats = cross_stats(ctx, types)
    collected = (ctx.created_meta or {}).get('collectedAt')
    snapshot = ((ctx.load('security_network/manifest.json') or {}).get('window') or {}).get('snapshot')
    gaps = list(COVERAGE_GAPS)
    if not ctx.created_map:
        gaps.insert(0, '资源创建时间未取得（没有 raw/peer 的采集数据），原因分析只用了标签和部署历史，创建时间显示为“未取得”。')
    data = {'collectedAt': collected, 'configSnapshot': snapshot, 'analyzedAt': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'method': {'summary': '对每类资源，按业务线和环境分组，找出环境中已在使用、且符合微软推荐的做法作为标准；多数做法本身不合规时，以少数已合规资源的做法为目标并注明覆盖率。'
                                  '逐资源列出与标准不同的属性，再用标准创建标签、创建时间、部署历史（门户向导部署名）、门户规则命名、供应商等证据推断原因，并给出对齐建议和可行性。',
                       'standardDetection': f'标签 {ctx.standard_label}' if ctx.standard_label else '未配置标准创建标签',
                       'creationMethodDetection': '资源组部署历史中的创建类部署名视为门户向导创建；IaC 工具不产生部署记录',
                       'readOnly': True},
            'methodLabels': {'standard': ctx.standard_name, 'portal': METHOD_PORTAL, 'unknown': METHOD_UNKNOWN, 'vendor': METHOD_VENDOR},
            'types': out_types, 'crossTypeInsights': auto_insights(ctx, stats), 'crossTypeStatistics': stats,
            'coverageGaps': gaps, 'createdTimeAvailable': bool(ctx.created_map), 'complete': True}
    fdir = ws.month_dir('findings') / 'peer'
    write_json(fdir / 'baseline.json', data)
    write_json(fdir / 'links.json', links_mod.build_links(ctx, data))
    n = sum(t['deviationCount'] for t in out_types)
    log(f'同类对比：{len(out_types)} 类资源，{n} 处偏差，其中高风险 '
        f'{sum(1 for t in out_types for d in t["deviations"] if d["impact"].startswith("高"))} 处')
    return data
