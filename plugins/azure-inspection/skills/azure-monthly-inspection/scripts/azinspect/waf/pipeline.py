"""Run order for the four WAF pillars.

collect and analyze: reliability -> security_network -> security_identity -> performance -> operations
(performance reuses reliability raw data; operations reuses security_identity, reliability and performance data,
and the cost review's storage and log data when `--part all` collected it first).
A pillar that fails is reported and skipped; the others still run.
"""
from __future__ import annotations

import importlib
import traceback

from .common import PILLARS, Raw, save_scope, window


def _module(pillar):
    return importlib.import_module(f'{__package__}.{pillar}')


def collect(ws, cfg, client, log=print, pillars=None):
    if not pillars or not (ws.raw('waf/scope.json')).exists():
        save_scope(ws, cfg, client, log)
    w, failed = window(), []
    log(f'指标和活动日志时间窗：{w["start"][:10]} 至 {w["end"][:10]}（{w["days"]} 天）')
    for pillar in pillars or PILLARS:
        try:
            _module(pillar).collect(ws, cfg, client, w, log)
        except Exception as e:  # keep the other pillars running; the error is shown to the user
            failed.append(pillar)
            log(f'{pillar} 采集失败：{type(e).__name__}: {e}')
            log(traceback.format_exc(limit=3))
    return failed


def analyze(ws, cfg, log=print, pillars=None):
    done = []
    for pillar in pillars or PILLARS:
        if not Raw(ws, pillar).exists('manifest.json'):
            log(f'{pillar}：没有原始数据，跳过分析')
            continue
        data = _module(pillar).analyze(ws, cfg, log)
        done.append(pillar)
        log(f'{pillar}：{len(data["findings"])} 项问题')
    resolve_ssh_exposure(ws, log)
    return done


SSH_PENDING = '（NSG 是否放行 22 端口以网络检查结果为准）。'


def resolve_ssh_exposure(ws, log=print):
    """S-I8 (SSH password login on a VM with a public IP) leaves port 22 to the network check. Write the network result into the
    finding, so nobody has to join the two and nobody reports 'reachable from the Internet' when the NSG does not open 22."""
    from ..core.io import read_json, write_json
    fdir = ws.month_dir('findings') / 'waf'
    net_path, ident_path = fdir / 'security_network.json', fdir / 'security_identity.json'
    if not (net_path.exists() and ident_path.exists()):
        return
    reach = {}
    for f in read_json(net_path).get('findings', []):
        for v in (f.get('evidence') or {}).get('vmsWithDirectPublicIp') or [] if f['check'] == 'S-N3' else []:
            if str(v.get('endpoint', '')).startswith('VM '):
                reach[v['endpoint'][3:].lower()] = 22 in (v.get('internetReachableMgmtPorts') or [])
    ident = read_json(ident_path)
    changed = 0
    for f in ident.get('findings', []):
        vms = (f.get('evidence') or {}).get('vms')
        if f['check'] != 'S-I8' or SSH_PENDING not in f.get('finding', '') or not isinstance(vms, list):
            continue
        names = [str(v.get('name', '')) for v in vms if isinstance(v, dict)]
        opened = [n for n in names if reach.get(n.lower()) is True]
        closed = [n for n in names if reach.get(n.lower()) is False]
        unknown = [n for n in names if n.lower() not in reach]
        parts = ([f'{"、".join(opened)} 的 22 端口对公网开放，风险最高'] if opened else []) +                 ([f'按当前 NSG，{"、".join(closed)} 的 22 端口没有对公网开放，风险在于以后放开端口或从内网横向登录'] if closed else []) +                 ([f'{"、".join(unknown)} 的 22 端口是否对公网开放未能核对'] if unknown else [])
        f['finding'] = f['finding'].replace(SSH_PENDING, '。' + '；'.join(parts) + '。')
        f['evidence']['port22OpenToInternet'] = {n: reach.get(n.lower()) for n in names}
        changed += 1
    if changed:
        write_json(ident_path, ident)
        log(f'SSH 密码登录：已按网络检查结果写明 22 端口是否对公网开放（{changed} 条）')


def parse(text):
    """'aprl,defender' -> ['aprl', 'defender'] (validated), None for all."""
    if not text:
        return None
    names = [x.strip() for x in text.split(',') if x.strip()]
    unknown = [x for x in names if x not in PILLARS]
    if unknown:
        raise SystemExit(f'未知的支柱：{"、".join(unknown)}；可选：{"、".join(PILLARS)}')
    return names


def build(ws, cfg, narratives, log=print):
    from . import report
    from .. import tracking
    tracking.update(ws, log)
    for code in ('03', '04'):
        if report.build(ws, cfg, code, narratives.get(code), log):
            report.audit(ws, cfg, code, log)
