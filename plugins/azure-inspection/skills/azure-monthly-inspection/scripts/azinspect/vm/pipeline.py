"""VM stage entry points used by the CLI: collect -> analyze -> build (+ audit)."""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from ..core.io import read_json, write_json
from . import rules
from .prices import ensure_prices


def analyze(ws, client=None, price_date=None, fetch_prices=True, log=print):
    raw_inv, raw_avg = ws.raw('vm/inventory'), ws.raw('vm/metrics')
    vms = read_json(raw_avg / 'vms-average.json')
    sku_envelopes = read_json(raw_avg / 'sku-capabilities.json')
    clusters = read_json(raw_inv / 'aks-pools.json')
    subscriptions = read_json(raw_inv / 'subscriptions.json')
    manifest = read_json(raw_avg / 'manifest.json')
    price_date = price_date or datetime.now(timezone.utc).date().isoformat()
    skus = rules.sku_lookup(sku_envelopes)
    planning = copy.deepcopy(vms)
    rules.add_coverage(planning)
    needed = {(v['region'], v.get('size')) for v in planning if v.get('size')}
    for v in planning:
        needed.update((v['region'], s['name']) for s, _rc, _rm in rules.sizes_for(v, skus))
    if fetch_prices and client is None:
        raise ValueError('需要联网查询官网价格时必须提供客户端')
    canonical = {i['name'].lower(): i['name'] for record in sku_envelopes for i in record.get('items') or [] if i.get('name')}
    catalog = ensure_prices(client, ws.raw('vm/prices'), needed, price_date, fetch_prices, log, canonical)
    updated, records, trials, pools, summary = rules.analyze(vms, sku_envelopes, clusters, catalog, subscriptions, manifest, price_date)
    out = ws.month_dir('findings') / 'vm'
    for name, data in [('vms-analyzed.json', updated), ('recommendations.json', records), ('candidate-checks.json', trials),
                       ('pools.json', pools), ('summary.json', summary), ('subscriptions.json', subscriptions), ('collection-manifest.json', manifest)]:
        write_json(out / name, data)
    log(f'分析完成：{summary["recordCount"]} 台机器，建议调整 {summary["recommendedVMCount"]} 台，'
        f'预计每月节省 USD {summary["monthlyPotentialSavingsUSD"]:,.2f}（官网列表价，价格日期 {price_date}）')
    return summary
