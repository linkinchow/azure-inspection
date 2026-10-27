"""Run order for the monthly cost review.

collect (online, read-only): cost queries -> draft model -> region/forecast/drivers -> databases/storage/logs -> VM month usage.
The VM month usage step reuses the VM inventory from `collect --part vm`, so collect vm first (`--part all` does this).
analyze (offline): rebuild the model from raw data into findings/cost/model.json.
"""
from __future__ import annotations

from ..core.io import read_json, write_json
from . import collect as cost_collect
from . import orphan, resources, review, supplement_costs
from .model import build as build_model


def collect(ws, cfg, client, period, log=print):
    cost_collect.collect(ws, cfg, client, period, log)
    model = build_model(ws, period)
    supplement_costs.collect(ws, cfg, client, period, model, log)
    subscriptions = [{**s, 'state': s.get('state') or s.get('stateAtCollection')} for s in read_json(ws.raw('cost/cost-data.json'))['subscriptions']]
    resources.collect(ws, client, period, model, subscriptions, log)
    orphan.collect(ws, client, [s['id'] for s in subscriptions if s.get('state') == 'Enabled'], log)
    if ws.raw('vm/inventory/vms.json').exists():
        review.collect(ws, client, period, log)
    else:
        log('未找到虚拟机清单（raw/vm/inventory），跳过本月虚拟机使用情况；请先运行 collect --part vm')


def analyze(ws, period, log=print):
    model = build_model(ws, period)
    write_json(ws.month_dir('findings') / 'cost' / 'model.json', model)
    t = model['comparableTotals']
    log(f'01 模型：{model["totals"]["comparableSubscriptionCount"]} 个订阅可比，本月 USD {t["cur"]:,.2f}，上月 USD {t["prev"]:,.2f}')
    return model
