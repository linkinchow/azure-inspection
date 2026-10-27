"""Supplement data for the monthly report: loading, labels and the supplement Excel sheets."""
from __future__ import annotations

import math

from ..core.io import read_json

# Cost Management ResourceLocation values -> Chinese (Azure-wide, not customer specific)
REGION_LABELS = {'us east': '美国东部', 'us east 2': '美国东部 2', 'us west': '美国西部', 'us west 2': '美国西部 2', 'us west 3': '美国西部 3',
                 'us central': '美国中部', 'us north central': '美国中北部', 'us south central': '美国中南部', 'us west central': '美国中西部',
                 'ae north': '阿联酋北部', 'ae central': '阿联酋中部', 'se central': '瑞典中部', 'fr central': '法国中部', 'de west central': '德国中西部',
                 'eu west': '西欧', 'eu north': '北欧', 'uk south': '英国南部', 'uk west': '英国西部', 'ch north': '瑞士北部', 'no east': '挪威东部',
                 'ap southeast': '东南亚（新加坡）', 'ap east': '东亚（香港）', 'ja east': '日本东部', 'ja west': '日本西部', 'kr central': '韩国中部',
                 'au east': '澳大利亚东部', 'in central': '印度中部', 'ca central': '加拿大中部', 'br south': '巴西南部',
                 'cn north 3': '中国北部 3', 'cn east 3': '中国东部 3', 'global': '全球服务（无具体区域）', 'unassigned': '未标注区域', '(blank)': '未标注区域'}
TYPE_LABELS = {'microsoft.dbformysql/flexibleservers': 'MySQL 灵活服务器', 'microsoft.dbforpostgresql/flexibleservers': 'PostgreSQL 灵活服务器',
               'microsoft.cache/redis': 'Azure Cache for Redis（旧版）', 'microsoft.cache/redisenterprise': 'Azure Managed Redis',
               'microsoft.documentdb/mongoclusters': 'Cosmos DB for MongoDB（vCore）'}


def _read(path):
    data = read_json(path)
    if not data.get('complete'):
        raise RuntimeError(f'{path} 未完成')
    return data


def load(ws):
    base = ws.raw('cost')
    sup = {'region': _read(base / 'supplement/region.json'), 'forecast': _read(base / 'supplement/forecast.json'),
           'drivers': _read(base / 'supplement/drivers.json'), 'databases': _read(base / 'resources/databases.json'),
           'storage': _read(base / 'resources/storage.json'), 'logs': _read(base / 'resources/logs.json')}
    assert sup['region']['reconciliation']['allOk'], '区域费用合计与订阅费用不一致'
    for p in sup['drivers']['pairs']:
        assert p.get('status') != 'success' or p['reconciliation']['ok'], p['subscriptionName']
    return sup


def region_label(code, cfg=None):
    label = REGION_LABELS.get(code) or (cfg.region(code) if cfg else None)
    return f'{label}（{code}）' if label and label != code else code


def min_days(r):
    days = [v for v in (r.get('validDays') or {}).values() if v is not None]
    return min(days) if days else None


def sku_text(r):
    if r['type'] == 'microsoft.cache/redis' and r.get('skuFamily') and r.get('skuCapacity') is not None:
        return f'{r["skuName"]} {r["skuFamily"]}{r["skuCapacity"]}'
    return r.get('skuName') or r.get('skuTier') or '未取得'


def is_low(r):
    return any(str(f).startswith('LOW') for f in r.get('flags') or [])


def db_note(r, days, cur_label):
    d, notes = min_days(r), []
    if is_low(r):
        notes.append(f'CPU和内存{cur_label}平均均低于20%，建议容量评审')
    if d is None:
        notes.append(f'{cur_label}无指标（可能是月后创建）')
    elif d < days:
        notes.append(f'只有{d}个有效日')
    if r['type'] in ('microsoft.cache/redis', 'microsoft.cache/redisenterprise'):
        notes.append('内存百分比按整数上报，低于1%显示为0，请看实际内存使用')
    if r.get('replicationRole') and r['replicationRole'] not in ('None', None):
        notes.append('复制角色：' + r['replicationRole'])
    return '；'.join(notes)


def driver_auto_text(p):
    """Default 'main reason' when the narrative has none: the split computed from the bill."""
    c = p.get('decomposition') or {}
    if not c:
        return '变化原因拆解未取得'
    parts = [(c.get('newMeters', 0), '新增计量或资源'), (c.get('removedMeters', 0), '停用计量或资源'),
             (c.get('dailyRateQuantityEffect', 0), '日均用量变化'), (c.get('calendarEffect', 0), '天数差异'), (c.get('unitCostChange', 0), '单位费用变化')]
    parts = sorted([x for x in parts if abs(x[0]) >= 1], key=lambda x: -abs(x[0]))[:3]
    text = '；'.join(f'{label} USD {v:+,.0f}' for v, label in parts) or '各项变化都很小'
    res = p.get('resources') or {}
    if res.get('newCount'):
        text += f'；新增 {res["newCount"]} 个资源'
    return text + '（按账单拆分，业务原因待确认）'


def driver_text(p, narrative):
    return (narrative.get('driverNotes') or {}).get(f'{p["subscriptionName"]}|{p["serviceName"]}') or driver_auto_text(p)


def add_sheets(sheet, formula, sup, model, labels, narrative, cfg):
    """Region, forecast, drivers, meters, databases, storage and logs sheets. Returns [(sheet, percent columns)]."""
    L_prev, L_cur, L_next = labels['prev'], labels['cur'], labels['next']
    dp, dc = model['scope']['days']['prev'], model['scope']['days']['cur']
    r, out = sup['region'], []
    rs = sheet('区域对比', f'按资源所在区域：{L_cur}与{L_prev}实际费用', f'区域为Azure费用数据中的资源位置；与订阅业务分组不同。{len(model["comparableSubscriptionIds"])}个可读取订阅。',
               ['区域', f'{L_prev}USD', f'{L_cur}USD', '增减USD', f'{L_cur}占比', f'{L_prev}日均USD', f'{L_cur}日均USD', '日均变化率', '主要服务变化'])
    services = {}
    for x in r['overall']['byLocationService']:
        services.setdefault(x['location'], []).append(x)
    total_cur, rows = r['overall']['totals']['cur'], r['overall']['byLocation']
    for i, x in enumerate(rows, 4):
        top = sorted(services.get(x['location'], []), key=lambda s: -abs(s['delta']))[:3]
        rs.append([region_label(x['location'], cfg), x['prev'], x['cur'], None, None, None, None, None,
                   '；'.join(f'{s["serviceName"]} {s["delta"]:+,.0f}' for s in top if abs(s['delta']) >= 1)])
        formula(rs, i, 4, f'=C{i}-B{i}', x['cur'] - x['prev'])
        formula(rs, i, 5, f'=C{i}/C{len(rows) + 4}', x['cur'] / total_cur)
        formula(rs, i, 6, f'=B{i}/{dp}', x['prev'] / dp)
        formula(rs, i, 7, f'=C{i}/{dc}', x['cur'] / dc)
        if x['prev'] > 0:
            formula(rs, i, 8, f'=G{i}/F{i}-1', (x['cur'] / dc) / (x['prev'] / dp) - 1)
    n = len(rows) + 4
    rs.append(['合计', None, None, None, None, None, None, None, '与订阅对比合计一致'])
    formula(rs, n, 2, f'=SUM(B4:B{n - 1})', r['overall']['totals']['prev'])
    formula(rs, n, 3, f'=SUM(C4:C{n - 1})', total_cur)
    formula(rs, n, 4, f'=C{n}-B{n}', total_cur - r['overall']['totals']['prev'])
    out.append((rs, [5, 8]))
    f = sup['forecast']
    nx = f['overall']['next']
    dn = labels['nextDays']
    fs = sheet(f'{L_next}费用预测', f'{L_next}费用预测（Azure Cost Management）',
               f'查询日期{f["queriedOn"]}；已发生的日期为实际费用，其余为Azure预测值，不是账单金额。{L_cur}无费用的订阅预测接口不返回结果。',
               ['业务组', '订阅', f'{L_next}截至查询日实际USD', f'{L_next}其余日期预测USD', f'{L_next}全月预计USD', f'{L_cur}实际USD', f'日均变化率（较{L_cur}）', '下下月预测USD', '说明'])
    cur_by = {s['id']: s['cur'] for s in model['subscriptions']}
    subs = sorted(f['subscriptions'], key=lambda s: -((s['next'] or {}).get('actualToDate') or 0) - ((s['next'] or {}).get('forecastRemainder') or 0))
    for i, s in enumerate(subs, 4):
        o, n2 = s['next'], s.get('next2') or {}
        ok = o.get('fullMonthEstimate') is not None
        note = '' if ok else (f'{L_cur}无费用，预测接口未返回结果' if (cur_by.get(s['subscriptionId']) or 0) == 0 else '预测接口未返回结果：' + str(o.get('reason')))
        fs.append([s['group'], s['name'], o['actualToDate'] if ok else None, o['forecastRemainder'] if ok else None, None, cur_by.get(s['subscriptionId']), None,
                   n2.get('fullMonthEstimate'), note])
        if ok:
            full = o['actualToDate'] + o['forecastRemainder']
            formula(fs, i, 5, f'=C{i}+D{i}', full)
            cur = cur_by.get(s['subscriptionId'])
            if cur:
                formula(fs, i, 7, f'=(E{i}/{dn})/(F{i}/{dc})-1', (full / dn) / (cur / dc) - 1)
    n = len(subs) + 4
    fs.append(['合计', '有预测的订阅', None, None, None, None, None, None, '只合计有预测结果的订阅'])
    cur_sum = sum(v for v in cur_by.values() if v)
    totals = [(3, nx['actualToDate']), (4, nx['forecastRemainder']), (5, nx['fullMonthEstimate']), (6, cur_sum)]
    if 'next2' in f['overall']:
        totals.append((8, f['overall']['next2']['fullMonthEstimate']))
    for col, val in totals:
        formula(fs, n, col, f'=SUM({chr(64 + col)}4:{chr(64 + col)}{n - 1})', val)
    if cur_sum:
        formula(fs, n, 7, f'=(E{n}/{dn})/(F{n}/{dc})-1', (nx['fullMonthEstimate'] / dn) / (cur_sum / dc) - 1)
    out.append((fs, [7]))
    d = sup['drivers']
    ds = sheet('变化原因拆解', '主要增长和下降：按资源和计量拆解',
               f'按资源和计量比较{L_prev}与{L_cur}的费用与用量。“天数差异”是两个月天数不同的影响；“单位费用变化”按实际费用计算，可能来自价格调整或折扣，账单数据无法区分。',
               ['订阅', '服务', f'{L_prev}USD', f'{L_cur}USD', '增减USD', '新增计量或资源USD', '停用计量或资源USD', '日均用量变化USD', '天数差异USD', '单位费用变化USD', '核对：各项合计USD', '主要原因'])
    ok_pairs = [p for p in d['pairs'] if p.get('status') == 'success']
    for i, p in enumerate(ok_pairs, 4):
        c = p['decomposition']
        ds.append([p['subscriptionName'], p['serviceName'], p['totals']['prev'], p['totals']['cur'], None, c['newMeters'], c['removedMeters'],
                   c['dailyRateQuantityEffect'], c['calendarEffect'], c['unitCostChange'], None, driver_text(p, narrative)])
        formula(ds, i, 5, f'=D{i}-C{i}', p['totals']['delta'])
        formula(ds, i, 11, f'=SUM(F{i}:J{i})', c['newMeters'] + c['removedMeters'] + c['dailyRateQuantityEffect'] + c['calendarEffect'] + c['unitCostChange'] + c['residual'])
    out.append((ds, []))
    ms = sheet('主要计量变化', '各变化项中费用变化最大的计量', '数量为计费数量；同一计量内比较，不同单位不相加。',
               ['订阅', '服务', '计量类别', '计量', '单位', f'{L_prev}USD', f'{L_cur}USD', f'{L_prev}用量', f'{L_cur}用量', f'{L_prev}单位费用USD', f'{L_cur}单位费用USD'])
    for p in ok_pairs:
        for m in p['topMeters'][:5]:
            ms.append([p['subscriptionName'], p['serviceName'], m.get('MeterSubcategory'), m.get('Meter'), m.get('UnitOfMeasure'),
                       m['prev'], m['cur'], m['prevQty'], m['curQty'], m['prevUnitCost'], m['curUnitCost']])
    out.append((ms, []))
    db = sup['databases']
    dbs = sheet('数据库与缓存用量', f'数据库与缓存：{L_cur}平均使用率',
                f'按每日平均值计算{L_cur}加权平均。规格为{int(db["snapshotAt"][5:7])}月{int(db["snapshotAt"][8:10])}日的当前配置，不一定是{L_cur}配置。CPU和内存都低于20%只表示可做容量评审，不代表可以直接降配。',
                ['订阅', '资源组', '名称', '类型', '规格', '区域', f'{L_cur}费用USD', 'CPU平均%', '内存平均%', '实际内存使用GiB', '存储使用平均%', '有效日', '说明'])
    for r_ in sorted(db['resources'], key=lambda r: (-(r['curCostUSD'] or 0), r['name'])):
        av = r_['averages'] or {}
        dbs.append([r_['subscriptionName'], r_['resourceGroup'], r_['name'], TYPE_LABELS.get(r_['type'].lower(), r_['type']), sku_text(r_), r_['region'],
                    r_['curCostUSD'], av.get('cpu'), av.get('memory'), av.get('usedMemoryBytesGiB'), av.get('storage'), min_days(r_), db_note(r_, dc, L_cur)])
    out.append((dbs, []))
    st = sup['storage']
    ss = sheet('存储容量与层级', f'存储账户：{L_cur}容量、层级和生命周期策略',
               f'容量来自{L_cur}每日平均值；冗余、层级和生命周期策略为{int(st["snapshotAt"][5:7])}月{int(st["snapshotAt"][8:10])}日的当前配置。“未配置”表示查询明确返回没有策略。',
               ['订阅', '资源组', '存储账户', '冗余', '默认层级', f'{L_cur}初容量GiB', f'{L_cur}底容量GiB', f'{L_cur}增长GiB', '增长率%', f'各层容量GiB（{L_cur}底）',
                f'{L_cur}出站GiB', '生命周期策略', f'{L_cur}费用USD'])
    for a in sorted(st['accounts'], key=lambda a: (-(a['curCostUSD'] or 0), a['name'])):
        u, lc = a.get('usedCapacity') or {}, a.get('lifecyclePolicy') or {}
        first = u.get('firstBytes') / 2**30 if u.get('firstBytes') is not None else None
        rules = '；'.join(f'{x["name"]}（{"/".join(x.get("actions", []))}）' for x in lc.get('rules', []) or [])
        ss.append([a['subscriptionName'], a['resourceGroup'], a['name'], a.get('redundancy'), a.get('accessTier'), first, u.get('lastGiB'), u.get('growthGiB'),
                   u.get('growthPct'), '，'.join(f'{k} {v:,.0f}' for k, v in (a.get('tierMixLastDayGiB') or {}).items()), a.get('egressGiBCur'),
                   lc.get('status', '未取得') + ('：' + rules if rules else ''), a['curCostUSD']])
    out.append((ss, []))
    lg = sup['logs']
    tail = lg['period'].get('sourceWindow') or ['', '']
    ls = sheet('日志摄取与保留', f'Log Analytics：{L_cur}摄取量和保留设置',
               f'{L_cur}费用USD 50以上的工作区查询了摄取量；来源明细只查询{L_cur}最后7天（{tail[0]}至{model["scope"]["months"]["cur"]}-{dc:02d}）。',
               ['订阅', '工作区', f'{L_cur}费用USD', f'{L_cur}可计费GB', '主要数据类型', '保留天数', '每日上限', '月末一周主要来源'])
    for w in sorted(lg['workspaces'], key=lambda w: (-(w['curCostUSD'] or 0), w['name'])):
        rows_ = (w.get('topDataTypeBreakdown') or {}).get('rows') or []
        src = '；'.join(f'{(x.get("Category") or x.get("ContainerName") or "")} {x.get("BilledGB", 0):,.1f} GB'
                       + (f'（{x["ResourceId"].split("/")[-1]}）' if x.get('ResourceId') else '') for x in rows_[:3])
        ls.append([w['subscriptionName'], w['name'], w['curCostUSD'], w.get('billableGB'),
                   '，'.join(f'{b["DataType"]} {b["BillableGB"]:,.1f} GB' for b in (w.get('byDataType') or [])[:3]),
                   w.get('retentionInDays'), '未设置' if w.get('dailyQuotaGb') in (-1, -1.0, None) else w.get('dailyQuotaGb'), src])
    out.append((ls, []))
    return out


def coverage_rows(sup, model, labels):
    r, f, d, db, st, lg = sup['region'], sup['forecast'], sup['drivers'], sup['databases'], sup['storage'], sup['logs']
    n = len(model['comparableSubscriptionIds'])
    nx = f['overall']['next']
    rows = [['按区域费用', f'{n}个可读取订阅的{labels["prev"]}、{labels["cur"]}区域费用' + ('全部读取成功，合计与订阅费用一致' if r['reconciliation']['allOk'] else '有差异，见区域对比')],
            [f'{labels["next"]}费用预测', f'查询日期{f["queriedOn"]}；{nx["subscriptionsWithEstimate"]}个订阅有预测结果，其余{nx["subscriptionsPlanned"] - nx["subscriptionsWithEstimate"]}个订阅接口未返回预测；预测为Azure模型结果，不是账单'],
            ['费用变化原因', f'前10项增长、前5项下降按资源和计量拆解，{d["coverage"]["reconciled"]}/{d["coverage"]["pairs"]}项与费用变化完全对上'],
            ['数据库与缓存', f'读取时间{db["snapshotAt"][:16].replace("T", " ")} UTC；' + '；'.join(f'{TYPE_LABELS[k]} {v["found"]}个（完整{model["scope"]["days"]["cur"]}日{v.get("complete", 0)}个）' for k, v in db['coverage'].items())],
            ['存储账户', f'{st["coverage"]["found"]}个存储账户；{model["scope"]["days"]["cur"]}日容量完整{st["coverage"]["complete"]}个；生命周期策略：' + '，'.join(f'{k}{v}个' for k, v in st['coverage']['lifecycle'].items())],
            ['日志工作区', f'{lg["coverage"]["found"]}个工作区；费用USD 50以上的{lg["coverage"]["curCostGE50"]}个已查询摄取量；检查{lg["coverage"]["diagnosticSettingsChecked"]}个资源的诊断设置，'
             + (f'{lg["coverage"]["resourcesWithDuplicateDestinations"]}个资源有同一类日志发送到多个工作区' if lg['coverage']['resourcesWithDuplicateDestinations'] else '未发现同一类日志重复发送')],
            ['资源配置时间', f'数据库、缓存、存储和日志的规格及配置为{int(db["snapshotAt"][5:7])}月{int(db["snapshotAt"][8:10])}日读取的当前状态，不一定是{labels["cur"]}配置']]
    return rows


def money_total(values):
    return math.fsum(v for v in values if v is not None)
