"""Offline analysis of the security identity raw data -> findings/waf/security_identity.json."""
from __future__ import annotations

from collections import Counter

from ..common import coverage_entry
from . import checks_access, checks_aks, checks_resources
from .context import Ctx

CHECKS = [f'S-I{i}' for i in range(1, 11)]
LIMITATIONS = [
    '只读取管理面配置和目录元数据，未获取集群凭据、未执行 kubectl，集群内 RoleBinding 未检查。',
    '只读取凭据的名称、开始和到期时间，未读取任何密钥、密码或连接字符串。',
    '网络暴露（NSG、公网 IP、PaaS 防火墙、存储加固、WAF）由网络安全检查负责。',
]


def _coverage(ctx):
    index = ctx.raw.load('index.json') or {}
    coverage = {k: coverage_entry() for k in CHECKS}
    for call in index.get('calls', []):
        c = coverage.get(call.get('check'))
        if c is None:
            continue
        status = call.get('http', call.get('status')) or 0
        c['attempted'] += 1
        if 200 <= status < 300 and not call.get('error'):
            c['succeeded'] += 1
        elif status in (401, 403):
            c['denied'] += 1
        else:
            c['otherErrors'] += 1
    for k, notes in ctx.notes.items():
        coverage.setdefault(k, coverage_entry())['notes'].extend(notes)
    for c in coverage.values():
        c['succeededRatio'] = round(c['succeeded'] / c['attempted'], 3) if c['attempted'] else None
    return index, coverage


def analyze(ws, cfg, log=print):
    ctx = Ctx(ws, cfg)
    checks_aks.run(ctx)
    assessments = checks_access.defender(ctx)
    app_priv = checks_access.roles(ctx, assessments)
    checks_access.credentials(ctx, app_priv)
    checks_resources.audit(ctx)
    checks_resources.vms(ctx)
    checks_resources.keyvaults(ctx)
    checks_resources.registries_and_ai(ctx)
    index, coverage = _coverage(ctx)
    scope = {'subscriptionsTotal': len(ctx.subs), 'enabled': len(ctx.enabled), 'inspected': [s['name'] for s in ctx.enabled],
             'notInspectedDisabled': [s['name'] for s in ctx.disabled],
             'environmentInference': {s['name']: ctx.sub_env(s['name']) for s in ctx.enabled}}
    severity = Counter((f['check'], f['severity']) for f in ctx.findings.items)
    data = ctx.findings.write(ws, window=ctx.window, coverage=coverage, scope=scope, inventory=ctx.inventory, limitations=LIMITATIONS,
                              extra={'collectedAt': index.get('startedAt'),
                                     'severityCounts': {c: {s: severity[(c, s)] for s in ('高', '中', '低')} for c in CHECKS}})
    totals = Counter(f['severity'] for f in ctx.findings.items)
    log(f'安全-身份分析：{len(ctx.findings.items)} 条问题（高 {totals["高"]}、中 {totals["中"]}、低 {totals["低"]}）')
    return data
