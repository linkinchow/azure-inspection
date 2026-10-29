"""Run order for the monthly cost review.

collect (online, read-only): cost queries -> draft model -> region/forecast/drivers -> databases/storage/logs -> orphaned resources
-> RI/SP coverage, orders and recommendations -> VM month usage.
The VM month usage step reuses the VM inventory from `collect --part vm`, so collect vm first (`--part all` does this).
analyze (offline): rebuild the model from raw data into findings/cost/model.json.
"""
from __future__ import annotations

from ..core.io import read_json, write_json
from ..core.reuse import Reuse, signature
from . import collect as cost_collect
from . import commitments, orphan, resources, review, supplement_costs
from .model import build as build_model
from .model import save as save_model

# steps without per-query files: with --resume a step is skipped when an identical earlier run finished it
STEP_OUTPUTS = {'resources': ['cost/resources/inventory.json', 'cost/resources/databases.json', 'cost/resources/storage.json',
                              'cost/resources/logs.json'],
                'orphan': ['cost/orphan.json'], 'review': ['cost/review/results.json']}


def _step(ws, reuse, name, sig, run, log):
    marker = ws.raw(f'cost/_steps/{name}.json')
    if reuse.load(marker, sig, lambda r: all(ws.raw(o).exists() for o in r['outputs'])) is not None:
        log(f'  {name}：复用上次已完成的结果')
        return
    run()
    write_json(marker, reuse.stamp({'step': name, 'outputs': STEP_OUTPUTS[name]}, sig))


def collect(ws, cfg, client, period, log=print, resume=False):
    reuse = Reuse(resume)
    if resume:
        log(f'续采：复用 {period.current.key} 已成功保存、且在 7 天内读取的结果，只读取缺少或失败的部分')
    cost_collect.collect(ws, cfg, client, period, log, reuse)
    model = build_model(ws, period)
    supplement_costs.collect(ws, cfg, client, period, model, log, reuse)
    subscriptions = [{**s, 'state': s.get('state') or s.get('stateAtCollection')} for s in read_json(ws.raw('cost/cost-data.json'))['subscriptions']]
    enabled = [s['id'] for s in subscriptions if s.get('state') == 'Enabled']
    sig = lambda name: signature('cost-step', cost_collect.COLLECTOR_VERSION, name, period.current.key, sorted(enabled))  # noqa: E731
    _step(ws, reuse, 'resources', sig('resources'), lambda: resources.collect(ws, client, period, model, subscriptions, log), log)
    _step(ws, reuse, 'orphan', sig('orphan'), lambda: orphan.collect(ws, client, enabled, log), log)
    commitments.collect(ws, client, period, log, reuse)
    if ws.raw('vm/inventory/vms.json').exists():
        _step(ws, reuse, 'review', sig('review'), lambda: review.collect(ws, client, period, log), log)
    else:
        log('未找到虚拟机清单（raw/vm/inventory），跳过本月虚拟机使用情况；请先运行 collect --part vm')
    if resume:
        log('续采：' + reuse.summary())


def analyze(ws, period, log=print):
    model = build_model(ws, period)
    save_model(ws.month_dir('findings') / 'cost', model)
    t = model['comparableTotals']
    log(f'01 模型：{model["totals"]["comparableSubscriptionCount"]} 个订阅可比，本月 USD {t["cur"]:,.2f}，上月 USD {t["prev"]:,.2f}')
    return model
