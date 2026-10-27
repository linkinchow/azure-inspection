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
    return done


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
