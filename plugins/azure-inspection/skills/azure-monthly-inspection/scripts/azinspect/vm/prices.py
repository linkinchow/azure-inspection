"""Azure public Retail Prices for VMs (list prices, USD): pay-as-you-go, 1/3-year RI, 1/3-year Savings Plan.

Price files are kept under <workspace>/<month>/raw/vm/prices/ and reused for the whole review; a file
queried after `price_date` is never used silently. A completed query that returns no quote is evidence
of absence, not a reason to retry. Missing quotes stay missing (never replaced by another price type).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from ..core.http import PRICES
from ..core.io import write_json

KEYS = ('payg', 'ri1', 'ri3', 'sp1', 'sp3')
HOURS_PER_MONTH = 730


def now():
    return datetime.now(timezone.utc).isoformat()


def os_price_basis(vm):
    """Windows with Azure Hybrid Benefit uses compute-only prices; an unknown OS never becomes Linux."""
    os_type = (vm.get('osDisk') or {}).get('osType') or vm.get('osType')
    if not os_type:
        os_type = ((vm.get('properties') or {}).get('storageProfile') or {}).get('osDisk', {}).get('osType')
    if str(os_type).lower() == 'linux':
        return 'linux'
    if str(os_type).lower() == 'windows':
        return 'linux' if vm.get('licenseType') in ('Windows_Server', 'Windows_Client') else 'windows'
    return 'unknown'


def _official(url):
    p = urlparse(url or '')
    return p.scheme == 'https' and p.hostname == 'prices.azure.com' and p.path.startswith('/api/retail/prices')


def _valid_cache(data, date):
    if not isinstance(data, dict) or not _official(data.get('source')) or not isinstance(data.get('items'), list):
        return False
    queried = data.get('queriedAt', '')
    if not queried or queried[:10] > date:
        return False
    query = parse_qs(urlparse(data['source']).query)
    if query.get('currencyCode', ["'USD'"])[0].strip("'") != 'USD':
        return False
    return query.get('$filter', [data.get('filter')])[0] == data.get('filter')


def _filter_pairs(data):
    filt = data.get('filter', '')
    regions = re.findall(r"armRegionName eq '([^']+)'", filt)
    names = re.findall(r"armSkuName eq '([^']+)'", filt)
    return {(r.lower(), n.lower()) for r in regions for n in names}


def ensure_prices(client, directory: Path, needed, date: str, fetch: bool = True, log=print):
    """`needed`: iterable of (region, ARM SKU name). Reuses valid files, queries only what is missing."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    wanted = {(r.lower(), n.lower()): n for r, n in needed if r and n}
    covered = set()
    for path in sorted(directory.glob('*.json')):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if _valid_cache(data, date):
            covered.update(_filter_pairs(data) & wanted.keys())
    missing = sorted(wanted.keys() - covered)
    jobs = []
    if fetch:
        esc = lambda s: s.replace("'", "''")
        for region in sorted({r for r, _ in missing}):
            names = [wanted[(r, n)] for r, n in missing if r == region]
            for offset in range(0, len(names), 8):
                batch = names[offset:offset + 8]
                filt = ("serviceName eq 'Virtual Machines' and armRegionName eq '" + esc(region) + "' and ("
                        + ' or '.join("armSkuName eq '" + esc(n) + "'" for n in batch) + ')')
                digest = hashlib.sha256(filt.encode()).hexdigest()[:20]
                jobs.append((directory / f'vm-{region}-{digest}.json', filt))

    def fetch_job(job):
        path, filt = job
        source = PRICES + '?' + urlencode({'api-version': '2023-01-01-preview', 'currencyCode': "'USD'", '$filter': filt})
        items, url, visited = [], source, set()
        while url:
            if not _official(url) or url in visited:
                return {'filter': filt, 'error': 'Non-public or cyclic Retail API pagination URL'}
            visited.add(url)
            status, payload, error = client.request('GET', url, 'prices')
            if status != 200:
                return {'filter': filt, 'source': source, 'error': f'HTTP {status}: {error}'}
            items.extend(payload['Items'])
            url = payload.get('NextPageLink')
        write_json(path, {'filter': filt, 'source': source, 'queriedAt': now(), 'priceAsOfDate': date, 'items': items})
        return None

    with ThreadPoolExecutor(max_workers=3) as pool:
        errors = [e for e in pool.map(fetch_job, jobs) if e]
    if jobs:
        log(f'官网价格：查询 {len(jobs)} 批，失败 {len(errors)} 批')
    write_json(directory.parent / 'metrics' / 'price-availability.json', {
        'priceAsOfDate': date, 'neededRegionSKUCount': len(wanted), 'reusedRegionSKUCount': len(covered & wanted.keys()),
        'queriedBatchCount': len(jobs), 'fetchEnabled': fetch, 'queryErrors': errors,
        'unqueriedRegionSKUs': [list(k) for k in missing] if not fetch else []})
    return price_catalog(directory, date)


def price_catalog(directory: Path, date: str):
    """All genuine quotes keyed (region, lower SKU, OS basis, kind)."""
    records = {}
    for path in sorted(Path(directory).glob('*.json')):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if not _valid_cache(data, date):
            continue
        pairs = _filter_pairs(data)
        for item in data['items']:
            product = item.get('productName', '')
            text = ' '.join(str(item.get(k, '')) for k in ('productName', 'skuName', 'meterName')).lower()
            if (not product.startswith('Virtual Machines ') or 'cloud services' in text
                    or any(t in text for t in ('spot', 'low priority', 'devtest'))
                    or item.get('currencyCode') != 'USD' or item.get('unitOfMeasure') != '1 Hour'
                    or not item.get('effectiveStartDate') or item['effectiveStartDate'][:10] > date
                    or item.get('tierMinimumUnits', 0) != 0):
                continue
            basis = 'windows' if 'windows' in product.lower() else 'linux'
            if item.get('type') == 'Consumption':
                quotes = [('payg', item.get('retailPrice'), 'hour')]
                # RI/SP discount compute only; never label them as a full Windows price.
                if basis == 'linux':
                    quotes.extend(('sp1' if sp['term'] == '1 Year' else 'sp3', sp.get('retailPrice'), 'hour')
                                  for sp in item.get('savingsPlan', []) if sp.get('term') in ('1 Year', '3 Years'))
            elif item.get('type') == 'Reservation' and basis == 'linux' and item.get('reservationTerm') in ('1 Year', '3 Years'):
                quotes = [('ri1' if item['reservationTerm'] == '1 Year' else 'ri3', item.get('retailPrice'), 'term')]
            else:
                continue
            for kind, value, unit in quotes:
                if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                    continue
                key = (str(item.get('armRegionName', '')).lower(), str(item.get('armSkuName', '')).lower(), basis, kind)
                if not key[0] or not key[1] or key[:2] not in pairs:
                    continue
                quote = {'kind': kind, 'retailPrice': value, 'unit': unit, 'currencyCode': 'USD',
                         'sourceFile': path.name, 'sourceUrl': data['source'], 'queriedAt': data['queriedAt'], 'priceAsOfDate': date,
                         'effectiveStartDate': item['effectiveStartDate'], 'meterId': item.get('meterId'),
                         'productName': product, 'skuName': item.get('skuName'), 'region': item.get('armRegionName'),
                         'armSkuName': item.get('armSkuName'), 'reservationTerm': item.get('reservationTerm'), 'osPriceBasis': basis}
                if kind.startswith('sp'):
                    quote['savingsPlanTerm'] = '1 Year' if kind == 'sp1' else '3 Years'
                if key not in records or quote['effectiveStartDate'] > records[key]['effectiveStartDate']:
                    records[key] = quote
    return records


def quote_for(catalog, vm, sku=None, kind='payg'):
    return catalog.get((vm.get('region', '').lower(), str(sku or vm.get('size', '')).lower(), os_price_basis(vm), kind))


def monthly(quote):
    if quote is None:
        return None
    if quote['kind'] == 'ri1':
        return quote['retailPrice'] / 12
    if quote['kind'] == 'ri3':
        return quote['retailPrice'] / 36
    return quote['retailPrice'] * HOURS_PER_MONTH
