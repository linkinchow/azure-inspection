"""Read-only collection for the peer comparison: creation and last-change time of every resource.

ARM resource list with $expand=createdTime,changedTime per enabled subscription (no secrets). Everything else the
comparison needs is already collected by the WAF pillars (raw/waf/...).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ..core.io import sanitize, write_json
from ..waf.common import enabled, load_scope, now


def collect(ws, cfg, client, window, log=print):
    subs = enabled(load_scope(ws))
    started = now()

    def one(s):
        path = f'/subscriptions/{s["id"]}/resources?$expand=createdTime,changedTime&api-version=2021-04-01'
        items, status, error = client.get_all(path, 'peer', s['name'])
        rows = [{'id': r.get('id'), 'name': r.get('name'), 'type': r.get('type'),
                 'resourceGroup': (r.get('id') or '').split('/')[4] if r.get('id') else None,
                 'createdTime': r.get('createdTime'), 'changedTime': r.get('changedTime')} for r in items or []]
        return {'subscriptionId': s['id'], 'subscriptionName': s['name'], 'http': status, 'error': error, 'count': len(rows), 'resources': rows}

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(one, subs))
    write_json(ws.raw('peer/resources-createdTime.json'), sanitize(
               {'collectedAt': started, 'api': 'ARM resources list $expand=createdTime,changedTime (2021-04-01)', 'subscriptions': results}))
    write_json(ws.raw('peer/manifest.json'), {'collectedAt': started, 'window': window})
    failed = [r['subscriptionName'] for r in results if r['http'] != 200]
    log(f'同类对比：读取 {len(results)} 个订阅的资源创建时间，共 {sum(r["count"] for r in results)} 个资源'
        + (f'；{len(failed)} 个订阅读取失败（{"、".join(failed[:5])}）' if failed else ''))
