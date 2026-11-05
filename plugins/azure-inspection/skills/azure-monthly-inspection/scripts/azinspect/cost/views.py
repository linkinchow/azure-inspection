"""Supplement data for the monthly report: loading, labels and the supplement Excel sheets."""
from __future__ import annotations

import math

from ..core.charts import signed_amount
from ..core.config import region_name
from ..core.io import read_json
from . import forecast_scope

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
           'storage': _read(base / 'resources/storage.json'), 'logs': _read(base / 'resources/logs.json'),
           'lustre': load_lustre(ws)}
    assert sup['region']['reconciliation']['allOk'], '区域费用合计与订阅费用不一致'
    for p in sup['drivers']['pairs']:
        assert p.get('status') != 'success' or p['reconciliation']['ok'], p['subscriptionName']
    return sup


def load_lustre(ws, model=None):
    path = ws.raw('cost/resources/lustre.json')
    data = read_json(path) if path.exists() else {'status': None, 'resources': [], 'error': '没有采集 Azure Managed Lustre 配置记录'}
    return lustre_comparison(data, model) if model else data


def lustre_comparison(data, model):
    billing = model.get('lustreCosts')
    if not billing:
        return data
    inventory = {resource['resourceId'].lower(): resource for resource in data.get('resources') or []}
    rows = {}
    for bill in billing['resources']:
        key = bill['resourceId'].lower()
        configuration = inventory.get(key) or {}
        rows[key] = {**configuration, **bill, 'name': configuration.get('name') or bill['name'],
                     'configurationStatus': 'read' if configuration else 'not_in_current_inventory'}
    for key, configuration in inventory.items():
        if key in rows:
            continue
        subscription_id = key.split('/')[2]
        values, statuses = {}, {}
        for month in ('prev', 'cur'):
            source = billing['coverage'][month].get(subscription_id) or {}
            values[month] = 0.0 if source.get('reconciled') and not source.get('hasUnattributedCharges') else None
            statuses[month] = source.get('status') or 'not-collected'
        rows[key] = {**configuration, 'prevCostUSD': values['prev'], 'curCostUSD': values['cur'],
                     'deltaUSD': values['cur'] - values['prev'] if all(value is not None for value in values.values()) else None,
                     'changeRate': None, 'dailyChangeRate': None, 'prevStatus': statuses['prev'], 'curStatus': statuses['cur'],
                     'prevDailyUSD': values['prev'] / billing['days']['prev'] if values['prev'] is not None else None,
                     'curDailyUSD': values['cur'] / billing['days']['cur'] if values['cur'] is not None else None,
                     'billingStatus': 'unknown_previous' if values['prev'] is None else 'unknown_current' if values['cur'] is None else 'not_billed',
                     'configurationStatus': 'read'}
    return {**data, 'resources': list(rows.values()), 'billingComparison': {key: value for key, value in billing.items() if key != 'resources'}}


def lustre_billing_label(status):
    return {'continuing': '两月均有账单记录', 'previous_only': '仅上月有账单记录', 'current_only': '仅本月有账单记录',
            'unknown_previous': '上月账单未能核对', 'unknown_current': '本月账单未能核对', 'not_billed': '两月均未匹配账单记录'}.get(status, '未能核对')


LUSTRE_ADVICE = ('结合容量与 inode 峰值、作业周期和重建耗时评审规格及生命周期；'
                 '按留存、恢复和召回要求评审可选 Blob 归档。低吞吐量仅作观察，不作为闲置或缩容依据；暂不估算节省金额。')


def lustre_note(resource):
    notes = [resource.get('telemetryNote') or '未取得成本月份的 Lustre 容量、inode 和吞吐指标。']
    if resource.get('configurationError'):
        notes.append('完整配置读取失败：' + str(resource['configurationError']))
    if resource.get('curCostUSD') is None:
        notes.append('账单未匹配完整资源 ID 或金额未取得，费用未知')
    if 'prevCostUSD' in resource and resource['prevCostUSD'] is None:
        notes.append('上月费用未知，未按0处理')
    if resource.get('configurationStatus') == 'not_in_current_inventory':
        notes.append('当前清单未匹配到配置，不据此判断资源已删除')
    return '；'.join(notes)


def lustre_coverage(data):
    if data.get('status') is None:
        if data.get('billingComparison'):
            return f'当前配置清单未取得；费用比较仅依据两月账单，匹配 {len(data.get("resources") or [])} 个文件系统。'
        return '没有采集记录，本月未检查 Azure Managed Lustre。'
    count = sum(resource.get('configurationStatus') != 'not_in_current_inventory' for resource in data.get('resources') or [])
    if data.get('status') != 200 or data.get('errors'):
        return f'已取得 {count} 个文件系统；清单或完整配置读取不完整，见原始记录。'
    return f'已读取 {count} 个文件系统；配置为当前快照，成本月份的容量、inode 和吞吐指标未采集。'


def lustre_sheet(sheet, data, cur_label, prev_label=None):
    paired = data.get('billingComparison')
    prev_label = prev_label or ((paired or {}).get('months') or {}).get('prev') or '上月'
    paired_columns = [f'{prev_label}实际费用USD', '增减USD', '月费用变化率', '日均变化率', f'{prev_label}读取情况', f'{cur_label}读取情况', '账单记录范围',
                      '原始计费服务', f'{prev_label}日均USD', f'{cur_label}日均USD'] if paired else []
    result = sheet('Lustre容量与费用', f'Azure Managed Lustre：{cur_label}实际费用与当前配置',
                   lustre_coverage(data) + '按完整 ARM ID 匹配既有账单，费用已包含在总计中；依赖存储费用另按各自资源计费。' + LUSTRE_ADVICE,
                   ['订阅', '资源组', '文件系统', '完整资源ID', 'SKU', 'Tier', 'Tier来源', '配置容量TiB', '区域', '可用区', f'{cur_label}实际费用USD'] + paired_columns + ['配置读取时间UTC', '用量与读取限制', '评审建议'])
    for resource in sorted(data.get('resources') or [], key=lambda item: (-(item.get('curCostUSD') or 0), item['resourceId'].lower())):
        compared = [resource.get('prevCostUSD'), resource.get('deltaUSD'), resource.get('changeRate'), resource.get('dailyChangeRate'),
                    resource.get('prevStatus'), resource.get('curStatus'), lustre_billing_label(resource.get('billingStatus')),
                    '、'.join(resource.get('rawServiceNames') or []), resource.get('prevDailyUSD'), resource.get('curDailyUSD')] if paired else []
        result.append([resource.get('subscriptionName'), resource.get('resourceGroup'), resource['name'], resource['resourceId'],
                       resource.get('skuName'), resource.get('tier'), resource.get('tierSource'), resource.get('capacityTiB'),
                       resource.get('region'), '、'.join(resource.get('zones') or []), resource.get('curCostUSD')] + compared +
                       [data.get('snapshotAt') if resource.get('configurationStatus') != 'not_in_current_inventory' else None, lustre_note(resource), LUSTRE_ADVICE])
    return result


def region_label(code, cfg=None):
    label = REGION_LABELS.get(code) or (cfg.region(code) if cfg else region_name(code))
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
    text = '；'.join(f'{label} USD {signed_amount(v)}' for v, label in parts) or '各项变化都很小'
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
               ['业务组', '订阅', f'{L_next}截至查询日实际USD', f'{L_next}其余日期预测USD', f'{L_next}全月预计USD', f'{L_cur}实际USD', f'日均变化率（较{L_cur}）', '说明'])
    cur_by = {s['id']: s['cur'] for s in model['subscriptions']}
    subs = sorted(f['subscriptions'], key=lambda s: -((s['next'] or {}).get('actualToDate') or 0) - ((s['next'] or {}).get('forecastRemainder') or 0))
    for i, s in enumerate(subs, 4):
        o = s['next']
        ok = o.get('fullMonthEstimate') is not None
        note = '' if ok else forecast_scope.note_cell(o, cur_by.get(s['subscriptionId']) or 0, L_cur)
        fs.append([s['group'], s['name'], o['actualToDate'] if ok else None, o['forecastRemainder'] if ok else None, None, cur_by.get(s['subscriptionId']), None,
                   note])
        if ok:
            full = o['actualToDate'] + o['forecastRemainder']
            formula(fs, i, 5, f'=C{i}+D{i}', full)
            cur = cur_by.get(s['subscriptionId'])
            if cur:
                formula(fs, i, 7, f'=(E{i}/{dn})/(F{i}/{dc})-1', (full / dn) / (cur / dc) - 1)
    n = len(subs) + 4
    fs.append(['合计', '有预测的订阅', None, None, None, None, None, '只合计有预测结果的订阅'])
    # this month's costs of the subscriptions with a forecast only, so the total row compares like with like
    fcov = forecast_scope.coverage(f, model, dn, dc)
    totals = [(3, nx['actualToDate']), (4, nx['forecastRemainder']), (5, nx['fullMonthEstimate'])]
    for col, val in totals:
        formula(fs, n, col, f'=SUM({chr(64 + col)}4:{chr(64 + col)}{n - 1})', val)
    formula(fs, n, 6, f'=SUMIFS(F4:F{n - 1},E4:E{n - 1},"<>")', fcov['curWith'])
    if fcov['dailyChange'] is not None:
        formula(fs, n, 7, f'=(E{n}/{dn})/(F{n}/{dc})-1', fcov['dailyChange'])
    if fcov.get('adjustedChange') is not None:   # the report compares without large single days; say why this row differs
        fs.cell(n, 8, f'只合计有预测结果的订阅；日均变化率含特别大的单日费用（{L_next} {len(fcov["bigDays"])} 天、{L_cur} {len(fcov["bigCurDays"])} 天），'
                      f'不计这些天为 {fcov["adjustedChange"]:.2%}，见报告第 1 节')
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
    if sup.get('lustre') is not None:
        out.append((lustre_sheet(sheet, sup['lustre'], L_cur, L_prev), [14, 15] if sup['lustre'].get('billingComparison') else []))
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
    if sup.get('lustre') is not None:
        rows.append(['Azure Managed Lustre', lustre_coverage(sup['lustre'])])
    return rows


def money_total(values):
    return math.fsum(v for v in values if v is not None)
