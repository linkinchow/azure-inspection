"""VM stage entry points used by the CLI: collect -> analyze -> build (+ audit)."""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from ..core.io import read_json, write_json
from . import rules, scalesets
from .prices import ensure_prices, queried_dates


def keep_line(label, count, saving, pooled, others=0, others_saving=0.0):
    return (f'02 说明文件：keep {label} 让 {count} 台建议调整的机器暂不调整，每月少计 USD {saving:,.2f}'
            + (f'；另有同池 {others} 台因此不再整池调整，每月少计 USD {others_saving:,.2f}' if others
               else '（同池其他节点也不再整池调整）' if pooled else '')
            + ('；只想保留有冲突的机器时，请写完整机器名' if count > 1 else ''))


def analyze(ws, client=None, price_date=None, fetch_prices=True, log=print):
    raw_inv, raw_avg = ws.raw('vm/inventory'), ws.raw('vm/metrics')
    # Flexible scale set instances are also VM resources: count each machine once (see scalesets.py)
    inventory = read_json(raw_inv / 'resources.json') if (raw_inv / 'resources.json').exists() else []
    vms, duplicates, missing = scalesets.drop_flexible_duplicates(read_json(raw_avg / 'vms-average.json'), inventory)
    names = None
    if ws.config_path.exists():
        from ..core import config as config_mod
        names = config_mod.load(ws.config_path).appliance_names()
    devices = scalesets.mark_appliances(vms, inventory, names)   # network appliances get no downsizing advice
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
    narrative_path = ws.month_dir('narrative') / '02.json'   # crossCheckNotes marked keep: those machines stay as they are
    keep = (read_json(narrative_path).get('crossCheckNotes') or []) if narrative_path.exists() else []
    updated, records, trials, pools, summary = rules.analyze(vms, sku_envelopes, clusters, catalog, subscriptions, manifest, price_date,
                                                             keep=keep)
    for effect in rules.keep_effect(records, keep):
        log(keep_line(*effect))
    summary.update({'networkAppliances': devices, 'flexibleDuplicatesRemoved': len(duplicates), 'flexibleInstancesMissing': len(missing),
                    'flexibleInstancesMissingIds': [v['id'] for v in missing]})
    if duplicates or missing:
        log(scalesets.note(len(duplicates), len(missing)))
    out = ws.month_dir('findings') / 'vm'
    for name, data in [('vms-analyzed.json', updated), ('recommendations.json', records), ('candidate-checks.json', trials),
                       ('pools.json', pools), ('summary.json', summary), ('subscriptions.json', subscriptions), ('collection-manifest.json', manifest)]:
        write_json(out / name, data)
    days = queried_dates(ws.raw('vm/prices'), price_date)
    read_on = ('、'.join(days) if len(days) <= 2 else f'{days[0]} 至 {days[-1]}') if days else price_date
    log(f'分析完成：{summary["recordCount"]} 台机器，建议调整 {summary["recommendedVMCount"]} 台，'
        f'预计每月节省 USD {summary["monthlyPotentialSavingsUSD"]:,.2f}（官网列表价，价格读取于 {read_on}）')
    return summary
