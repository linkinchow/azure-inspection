"""Per-VM rows for the report (prices for each plan, notes) and the portfolio totals."""
from __future__ import annotations

import math
from decimal import ROUND_HALF_UP, Decimal

from .prices import KEYS, monthly, os_price_basis, quote_for
from .rules import IO
from .wording import customer_note, direction_text, status_text

PLAN_LABELS = {'payg': '调整后：按需，不用RI/SP', 'ri1': '调整后：1年RI', 'ri3': '调整后：3年RI', 'sp1': '调整后：1年SP', 'sp3': '调整后：3年SP'}


def extra_note(vm, notes):
    """Notes from the narrative file (cross-checks), matched by subscription and machine-name prefix."""
    out = []
    for n in notes or []:
        if vm.get('subscriptionName') == n.get('subscription') and str(vm.get('name', '')).startswith(n.get('namePrefix', '\0')):
            out.append(n['note'])
    return out


COVERED_SHARE = 0.5   # at least half of the month's amortized cost under RI/SP


def committed_share(record, coverage):
    """Share of the review month's amortized cost covered by RI/SP: VMSS instances are billed on the scale set."""
    if coverage is None:
        return None
    rid = str(record.get('pool') or record['vmId']).lower()
    item = coverage.get(rid)
    return item['share'] if item else 0.0


def combined_rows(vms, recommendations, pools, catalog, extra_notes=None, coverage=None, month_label='巡检月份'):
    lookup = {v['id'].lower(): v for v in vms}
    if len(lookup) != len(vms):
        raise ValueError('Duplicate case-insensitive VM ARM IDs in inventory')
    pool_lookup = {p['id'].lower(): p for p in pools}
    rows = []
    for record in recommendations:
        vm = lookup[record['vmId'].lower()]
        changing = record['status'] == '建议试点调整'
        running = str(record.get('state', '')).lower() == 'powerstate/running'
        deallocated = str(record.get('state', '')).lower() == 'powerstate/deallocated'
        candidate = record.get('candidate') or {}
        effective_sku = record['targetSKU'] if changing else record['currentSKU']
        quotes = {k: quote_for(catalog, vm, effective_sku, k) for k in KEYS}
        costs = {k: monthly(q) for k, q in quotes.items()}
        if deallocated:
            costs = {k: 0 if k == 'payg' else None for k in KEYS}
        elif not running:
            costs = {k: None for k in KEYS}
        current_io = {m: vm.get('metrics', {}).get(m, {}).get('average') for m, _, _ in IO}
        after_io = {m: candidate.get('projectedIO', {}).get(m) if changing else current_io[m] for m, _, _ in IO}
        current_month = monthly(quote_for(catalog, vm)) if running else 0 if deallocated else None
        pool_name = None
        if record.get('pool'):
            pool_name = pool_lookup.get(record['pool'].lower(), {}).get('name', record['pool'].split('/')[-1])
        missing = [label for k, label in (('payg', '按需'), ('ri1', '1年RI'), ('ri3', '3年RI'), ('sp1', '1年SP'), ('sp3', '3年SP'))
                   if running and costs[k] is None]
        note = customer_note(record, vm, pool_name)
        if missing:
            note += '；' + '/'.join(missing) + '无对应官网报价'
        share = committed_share(record, coverage)
        if changing and share is not None and share >= COVERED_SHARE:
            note += (f'；{month_label}该机器 {share:.0%} 的费用由 RI/SP 覆盖：降配不会直接减少预付费用，'
                     '需先交换预留或调整覆盖范围，节省在此之后才能实现')
        for extra in extra_note(vm, extra_notes):
            note += '；' + extra
        rows.append({
            'subscriptionName': record.get('subscriptionName', vm.get('subscriptionName')),
            'subscriptionId': record.get('subscriptionId', vm.get('subscriptionId')),
            'resourceGroup': record.get('resourceGroup', vm.get('resourceGroup')),
            'vmId': record['vmId'], 'name': record['name'], 'region': record['region'],
            'currentSKU': record['currentSKU'], 'effectiveSKU': effective_sku, 'running': running, 'changing': changing,
            'status': status_text(record, vm), 'direction': direction_text(candidate.get('direction')) if changing else '保持原规格',
            'cpuCurrent': record['cpuAverage'], 'memoryCurrent': record['memoryAverage'],
            'cpuAfter': candidate['projectedCPUPercent'] if changing else record['cpuAverage'],
            'memoryAfter': candidate['projectedMemoryPercent'] if changing else record['memoryAverage'],
            'currentCores': record.get('currentCores'), 'currentMemoryGiB': record.get('currentMemoryGiB'),
            'currentIO': current_io, 'afterIO': after_io,
            'currentMonthlyPAYG': current_month, 'costs': costs, 'quotes': quotes,
            'monthlyRightsizingSavings': record['monthlySavingsUSD'], 'note': note, 'poolName': pool_name, 'committedShare': share,
            'state': '运行中' if running else '已释放计算资源' if deallocated else '未确认释放（' + str(record.get('state', 'Unknown')) + '）',
            'rawPowerState': record.get('state', 'Unknown'), 'deallocated': deallocated, 'osPriceBasis': os_price_basis(vm),
            'licenseType': vm.get('licenseType'), 'metricsSource': vm.get('metricsSource'),
        })
    return rows


def portfolio_totals(rows):
    running = [r for r in rows if r.get('running')]
    if any(r['currentMonthlyPAYG'] is None or r['costs']['payg'] is None for r in running):
        raise ValueError('有运行中的机器缺少按需报价，不能汇总方案总价')
    baseline = math.fsum(r['currentMonthlyPAYG'] for r in running)
    plans = []
    for key in KEYS:
        missing = [r for r in running if r['costs'][key] is None]
        amount = math.fsum(r['costs'][key] if r['costs'][key] is not None else r['costs']['payg'] for r in running)
        saving = baseline - amount
        plans.append({'key': key, 'label': PLAN_LABELS[key], 'monthlyCost': amount, 'annualCost': amount * 12,
                      'monthlySaving': saving, 'annualSaving': saving * 12, 'fallbackCount': len(missing),
                      'fallbackMonthly': math.fsum(r['costs']['payg'] for r in missing),
                      'note': f'{len(missing)}台无对应报价，仍按调整后按需价计算' if missing else '全部运行机器均有对应报价'})
    return {'currentMonthly': baseline, 'currentAnnual': baseline * 12, 'runningCount': len(running),
            'deallocatedCount': sum(r.get('deallocated', False) for r in rows), 'plans': plans}


def money(value):
    # Excel's TEXT() rounds the value as shown with 15 significant digits; do the same so cents match on .xx5 edges
    return format(Decimal(format(value, '.15g')).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP), ',.2f')


def price_and_saving(row, key):
    if row.get('deallocated'):
        return '0.00（省 0.00）' if key == 'payg' else '不建议购买'
    value = row['costs'][key]
    if value is None:
        return '无报价' if row.get('running') else '暂不判断'
    baseline = row['currentMonthlyPAYG']
    if baseline is None:
        return f'{money(value)}（节省待确认）'
    saving = baseline - value
    return f'{money(value)}（{"省" if saving >= 0 else "增加"} {money(abs(saving))}）'
