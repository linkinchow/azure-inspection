"""How much of the month the next-month forecast covers, and how 01 and 00 say it.

The forecast API can leave subscriptions out (throttled, or no forecast returned). The forecast is then compared only
with the same subscriptions' costs this month; when those cover less than FULL_SHARE of this month's costs, 01 and 00
say the forecast is incomplete instead of giving a tenant-wide figure.

A one-off purchase (a reservation bought mid-month) or a large day in Azure's forecast can make a month's daily average
read as a jump in everyday costs (seen: more than twice this month's daily average while everyday costs were lower). Days above
BIG_DAY times the month's median day are named and left out of the daily comparison, in both months.
"""
from __future__ import annotations

import math
import re
import statistics
from collections import defaultdict

FULL_SHARE = 0.95   # subscriptions with a forecast cover at least this share of this month's costs
BIG_DAY = 5         # a day above this many times the month's median day is a large single day


def coverage(forecast, model, dn, dc):
    cur = {s['id']: s.get('cur') or 0.0 for s in model['subscriptions']}
    subs = forecast['subscriptions']
    has = [s for s in subs if s['next'].get('fullMonthEstimate') is not None]
    ids = {s['subscriptionId'] for s in has}
    cur_all = math.fsum(cur.get(s['subscriptionId'], 0.0) for s in subs)
    cur_with = math.fsum(cur.get(sid, 0.0) for sid in ids)
    missed = [s for s in subs if s['subscriptionId'] not in ids and cur.get(s['subscriptionId'], 0.0) > 0]
    est = math.fsum(s['next']['fullMonthEstimate'] for s in has) if has else None
    share = cur_with / cur_all if cur_all else (1.0 if has else None)
    out = {'subscriptions': len(has), 'planned': len(subs), 'estimate': est,
            'actualToDate': math.fsum(s['next'].get('actualToDate') or 0.0 for s in has),
            'forecastRemainder': math.fsum(s['next'].get('forecastRemainder') or 0.0 for s in has),
            'curWith': cur_with, 'curAll': cur_all, 'share': share, 'missed': len(missed),
            'complete': est is not None and (share or 0) >= FULL_SHARE}
    # next month's daily average against this month's, over the subscriptions with a forecast
    out['dailyChange'] = (est / dn) / (cur_with / dc) - 1 if est is not None and cur_with else None
    _big_days(out, has, model, share)
    return out


def _big(days):
    """{day: cost} -> the days above BIG_DAY times the median day (a month needs a week of days to tell)."""
    if len(days) < 7:
        return []
    median = statistics.median(days.values())
    return sorted(d for d, v in days.items() if median > 0 and v > BIG_DAY * median)


def _big_days(out, has, model, share):
    nxt = defaultdict(lambda: [0.0, 0.0])   # date -> [actual, forecast]
    for s in has:
        for p in s['next'].get('daily') or []:
            nxt[p['date']][0 if str(p['costStatus']).lower() == 'actual' else 1] += p['cost']
    totals = {d: a + f for d, (a, f) in nxt.items()}
    cur = {r['day']: r['cur'] for r in model.get('daily') or [] if r.get('cur') is not None}
    big, big_cur = _big(totals), _big(cur)
    out['bigDays'] = [{'date': d, 'cost': totals[d], 'kind': 'actual' if nxt[d][0] > nxt[d][1] else 'forecast',
                       'forecastShare': nxt[d][1] / out['forecastRemainder'] if out['forecastRemainder'] else None} for d in big]
    out['bigCurDays'] = [{'day': d, 'cost': cur[d]} for d in big_cur]
    out['adjustedChange'] = out['adjustedDaily'] = None
    if (big or big_cur) and len(totals) > len(big) and len(cur) > len(big_cur) and out['complete']:
        nxt_daily = math.fsum(v for d, v in totals.items() if d not in big) / (len(totals) - len(big))
        cur_daily = math.fsum(v for d, v in cur.items() if d not in big_cur) / (len(cur) - len(big_cur)) * (share or 1)
        out['adjustedDaily'] = nxt_daily
        out['adjustedChange'] = nxt_daily / cur_daily - 1 if cur_daily else None


def _money(x):
    return f'{x:,.2f}'


def _higher(rate):
    return f'{"高" if rate >= 0 else "低"}{abs(rate):.2%}'


def line_01(fc, labels):
    """01's forecast bullet (section 1), or None when there is nothing to say (no costs, no forecast)."""
    Ln, Lc, dn, dc = labels['Ln'], labels['Lc'], labels['dn'], labels['dc']
    rate, est = fc['dailyChange'], fc['estimate']
    if est is None:
        return (f'- **{Ln}预测没有读到**：{fc["missed"]} 个有费用的订阅都没有读到预测（如接口限流），本报告不给出{Ln}预计费用。'
                if fc['missed'] else None)
    if fc['complete']:
        text = (f'- **{Ln}预计约USD {_money(est)}**（Azure预测）：截至查询日实际USD {_money(fc["actualToDate"])}，'
                f'其余日期预测USD {_money(fc["forecastRemainder"])}。')
        if fc.get('adjustedChange') is not None:
            return text + _big_text(fc, labels) + f'预测需在{Ln}结束后核对。'
        if rate is not None:
            text += f'全月日均约USD {_money(est / dn)}，比{Lc}日均{_higher(rate)}'
            text += (f'（{fc["missed"]} 个订阅没有读到预测，占{Lc}费用的 {1 - fc["share"]:.1%}，没有计入，比较时也只用有预测的订阅）'
                     if fc['missed'] else '')
            text += '；'
        return text + f'预测需在{Ln}结束后核对。'
    return (f'- **{Ln}预测不完整**：只读到 {fc["subscriptions"]} 个订阅的预测，占{Lc}费用的 {fc["share"]:.1%}；'
            f'另有 {fc["missed"]} 个有费用的订阅没有读到预测（如接口限流），所以不给出全部订阅的{Ln}预计。'
            f'有预测的订阅{Ln}预计约USD {_money(est)}' + (f'，日均比同一批订阅的{Lc}日均{_higher(rate)}' if rate is not None else '') + '。')


def _day(date):
    return f'{int(date[5:7])}月{int(date[8:10])}日'


def _big_text(fc, labels):
    """Large single days in next month (actual or forecast) and the daily comparison without them."""
    Ln, Lc = labels['Ln'], labels['Lc']
    big, cur_big = fc['bigDays'], fc['bigCurDays']
    actual = [b for b in big if b['kind'] == 'actual']
    text = ''
    if actual:
        text += (f'其中 {"、".join(_day(b["date"]) for b in actual)}单日费用特别大（合计USD {_money(math.fsum(b["cost"] for b in actual))}），'
                 '可能是一次性购买（如预留实例），请确认；')
    for b in big:
        if b['kind'] == 'forecast':
            text += (f'Azure 预测在{_day(b["date"])}有一笔约USD {_money(b["cost"])}的费用'
                     + (f'，约占其余日期预测的 {b["forecastShare"]:.1%}' if b['forecastShare'] else '') + '，是否会发生请核对；')
    if big:
        which = '这一天' if len(big) == 1 else f'这 {len(big)} 天'
        text += (f'去掉{which}后日均约USD {_money(fc["adjustedDaily"])}，比{Lc}日均' + (f'（{Lc}也去掉 {len(cur_big)} 天大额单日）' if cur_big else '')
                 + f'{_higher(fc["adjustedChange"])}。')
    else:
        text += (f'{Lc}有 {len(cur_big)} 天单日费用特别大（可能是一次性购买），不计{"这一天" if len(cur_big) == 1 else "这几天"}时，'
                 f'{Ln}全月日均约USD {_money(fc["adjustedDaily"])}，比{Lc}日均{_higher(fc["adjustedChange"])}。')
    return text


def row_00(fc, next_label, cur_label):
    """00's key-figures row for the forecast, or None."""
    label = f'{next_label}预计费用'
    if fc['estimate'] is None:
        return [label, f'预测没有读到（{fc["missed"]} 个有费用的订阅读取失败，如接口限流），不给出'] if fc['missed'] else None
    if fc['complete']:
        big = fc.get('bigDays') or []
        note = (f'；含 {len(big)} 天特别大的单日费用（合计 USD {_money(math.fsum(b["cost"] for b in big))}，可能是一次性购买或 Azure 预测的大额费用），请核对'
                if big else '')
        return [label, f'约 USD {_money(fc["estimate"])}（Azure 预测）{note}']
    return [label, f'预测不完整：只覆盖{cur_label}费用的 {fc["share"]:.1%}（{fc["subscriptions"]} 个订阅），这部分约 USD {_money(fc["estimate"])}；'
                   '全部订阅的预计无法给出']


def note_cell(nxt, cur, cur_label):
    """The 说明 cell of a subscription without a forecast, in plain Chinese (not the API's error text)."""
    m = re.match(r'HTTP (\d+)', str(nxt.get('reason') or ''))
    http = nxt.get('httpStatus') or (int(m.group(1)) if m else None)
    if nxt.get('status') in ('success', 'empty', 'noForecastRows', None) or not http:
        return '预测接口未返回结果' if cur else f'{cur_label}无费用，预测接口未返回结果'
    failed = '预测接口限流（429），未读到' if http == 429 else f'预测读取失败（HTTP {http}）'
    return failed + ('' if cur else f'（{cur_label}无费用）')
