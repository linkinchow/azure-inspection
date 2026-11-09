"""Read-only HTTP client for Azure.

Every request goes through `ReadOnlyClient.request`, which refuses anything that is not a read:
- GET is allowed on Azure Resource Manager, Microsoft Graph (v1.0) and the public Retail Prices API.
- POST is allowed only for query endpoints that return data: Resource Graph, Cost Management
  query/forecast, Azure Monitor metrics:getBatch, Log Analytics query and Graph getByIds.
- Endpoints that return keys, credentials or SAS tokens are refused even if the method looks harmless.
- Redirects are refused; 429/5xx are retried with the server's Retry-After; 401/403/404 are returned
  (recorded, not raised) so a collector can note "无权限/不存在" and move on.
"""
from __future__ import annotations

import http.client
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime

from .auth import ARM, GRAPH, LOG_ANALYTICS, METRICS, TokenProvider

ARM_HOST = 'management.azure.com'
PRICES = 'https://prices.azure.com/api/retail/prices'
ARG_URL = f'https://{ARM_HOST}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'

_FORBIDDEN = re.compile(
    r'/(list\w*keys|list\w*credentials?|listaccountsas|listservicesas|listconnectionstrings|listsecrets|'
    r'regenerate\w*|getaccesstoken|listclusteradmincredential|listclusterusercredential|'
    r'listclustermonitoringusercredential|secrets(/|$))', re.I)
_POST_ALLOWED = [
    (ARM_HOST, re.compile(r'^/providers/Microsoft\.ResourceGraph/resources$', re.I)),
    (ARM_HOST, re.compile(r'^(/[^?]*)?/providers/Microsoft\.CostManagement/(query|forecast)$', re.I)),
    (ARM_HOST, re.compile(r'^/subscriptions/[0-9a-f-]{36}(/resourceGroups/[^/]+)?/providers/Microsoft\.PolicyInsights/policyStates/latest/summarize$', re.I)),
    ('*.metrics.monitor.azure.com', re.compile(r'^/subscriptions/[0-9a-f-]{36}/metrics:getBatch$', re.I)),
    ('api.loganalytics.io', re.compile(r'^/v1/workspaces/[0-9a-f-]{36}/query$', re.I)),
    ('graph.microsoft.com', re.compile(r'^/v1\.0/directoryObjects/getByIds$', re.I)),
]
# Front Door 'secrets' are certificate references: GET returns expiry, subject and the Key Vault id, never key material.
_AFD_CERT_REF = re.compile(r'^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Microsoft\.Cdn/profiles/[^/]+/secrets/[^/]+$', re.I)
_URL_SAFE = ":/?#[]@!$&'()*+,;=%~"
_REDACT_URL = re.compile(r'([?&](sig|code|token|\$skipToken)=)[^&]+', re.I)


class BlockedRequest(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BlockedRequest(f'redirect refused ({code})')


def _host_match(pattern: str, host: str) -> bool:
    return host.endswith(pattern[1:]) if pattern.startswith('*.') else host == pattern


def classify(method: str, url: str) -> str | None:
    """Return the token audience for an allowed request (None = no token, public API); raise if not allowed."""
    method = method.upper()
    p = urllib.parse.urlsplit(url)
    if p.scheme != 'https':
        raise BlockedRequest('only https is allowed')
    if p.username or p.password or p.port not in (None, 443):
        raise BlockedRequest(f'unexpected port or credentials in URL: {p.netloc}')
    host = (p.hostname or '').lower()   # next links sometimes carry the default ':443'
    if _FORBIDDEN.search(p.path) and not (method == 'GET' and _AFD_CERT_REF.match(p.path)):
        raise BlockedRequest(f'secret-returning endpoint refused: {p.path[:120]}')
    if method == 'POST':
        if not any(_host_match(h, host) and rx.match(p.path) for h, rx in _POST_ALLOWED):
            raise BlockedRequest(f'POST not in read-only allow-list: {host}{p.path[:120]}')
    elif method != 'GET':
        raise BlockedRequest(f'{method} is not a read')
    if host == ARM_HOST:
        return ARM
    if host.endswith('.metrics.monitor.azure.com'):
        return METRICS
    if host == 'api.loganalytics.io':
        return LOG_ANALYTICS
    if host == 'graph.microsoft.com' and p.path.startswith('/v1.0/'):
        return GRAPH
    if method == 'GET' and url.startswith(PRICES):
        return None
    raise BlockedRequest(f'host not allowed: {host}')


def _error_text(status, raw) -> str:
    """'code: message' from an error answer, whatever the key case ({"error": {...}}, {"Code": ..., "Message": ...});
    the plain text otherwise, never 'None: None'."""
    try:
        body = json.loads(raw) if raw else None
    except ValueError:
        text = raw.decode('utf-8', 'replace').strip() if isinstance(raw, bytes) else str(raw or '').strip()
        return f'HTTP {status}: {text[:300]}' if text else f'HTTP {status}'
    if isinstance(body, dict):
        err = body['error'] if isinstance(body.get('error'), dict) else body
        low = {str(k).lower(): v for k, v in err.items()}
        if low.get('code') or low.get('message'):
            return f"{low.get('code') or f'HTTP {status}'}: {str(low.get('message') or '')[:300]}"
        if isinstance(body.get('error'), str):
            return f"HTTP {status}: {body['error'][:300]}"
    return f'HTTP {status}'


def _retry_wait(headers, attempt: int) -> float:
    waits = []
    for key, value in (headers or {}).items():
        if 'retry-after' not in key.lower():
            continue
        try:
            waits.append(float(value) / (1000 if key.lower().endswith('-ms') else 1))
        except ValueError:
            try:
                waits.append(max(0.0, parsedate_to_datetime(value).timestamp() - time.time()))
            except (TypeError, ValueError):
                pass
    return min(max(waits) if waits else 2 ** attempt, 120)


class ReadOnlyClient:
    def __init__(self, tokens: TokenProvider, user_agent: str = 'azure-inspection-readonly/0.1', opener=None):
        self.tokens = tokens
        self.user_agent = user_agent
        self.calls: list[dict] = []
        self._lock = threading.Lock()
        self._opener = opener or urllib.request.build_opener(_NoRedirect)

    def request(self, method: str, url: str, check: str, target: str = '', body=None,
                max_attempts: int = 6, timeout: int = 120):
        """Returns (status, data, error). Never raises for HTTP errors; raises BlockedRequest for non-reads."""
        url = urllib.parse.quote(url, safe=_URL_SAFE)   # e.g. spaces in $filter; existing %-escapes are kept
        audience = classify(method, url)
        headers = {'User-Agent': self.user_agent, 'Content-Type': 'application/json'}
        started, status, data, error = time.time(), None, None, None
        waited, throttled, attempt = 0.0, 0, 0
        for attempt in range(1, max_attempts + 1):
            if audience:
                headers['Authorization'] = 'Bearer ' + self.tokens.get(audience)
            req = urllib.request.Request(url, method=method.upper(), headers=headers,
                                         data=json.dumps(body).encode() if body is not None else None)
            try:
                with self._opener.open(req, timeout=timeout) as resp:
                    status, raw = resp.status, resp.read()
                    data, error = (json.loads(raw) if raw else None), None
                    break
            except urllib.error.HTTPError as e:
                status, raw = e.code, e.read()
                if status == 429 or status >= 500:
                    error = _error_text(status, raw) if raw else f'HTTP {status}'   # the server's reason, when it gives one
                    throttled += status == 429 or 'throttl' in error.lower()   # e.g. 529 "The metrics backend reported 'Throttled'"
                    if attempt < max_attempts:   # no wait after the last attempt
                        pause = _retry_wait(e.headers, attempt)
                        waited += pause
                        time.sleep(pause)
                    continue
                error = _error_text(status, raw)
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.IncompleteRead) as e:
                status, error = None, type(e).__name__
                if attempt < max_attempts:
                    waited += min(30, 2 ** attempt)
                    time.sleep(min(30, 2 ** attempt))
        record = {'check': check, 'target': target, 'method': method.upper(), 'url': _REDACT_URL.sub(r'\1REDACTED', url)[:600],
                  'status': status, 'error': error, 'elapsed': round(time.time() - started, 2),
                  'attempts': attempt, 'waited': round(waited, 2), 'throttled': throttled,   # retries hidden by the final status
                  'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        with self._lock:
            self.calls.append(record)
        return status, data, error

    def get(self, path_or_url: str, check: str, target: str = '', **kw):
        url = path_or_url if path_or_url.startswith('http') else f'https://{ARM_HOST}{path_or_url}'
        return self.request('GET', url, check, target, **kw)

    def record(self, check: str, target: str, url: str, status, error: str):
        """A failed read that is not one HTTP answer (e.g. paging cut off), so coverage counts it."""
        with self._lock:
            self.calls.append({'check': check, 'target': target, 'method': 'GET', 'url': _REDACT_URL.sub(r'\1REDACTED', url)[:600],
                               'status': status, 'error': error, 'elapsed': 0, 'attempts': 0, 'waited': 0, 'throttled': 0,
                               'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})

    def get_all(self, path_or_url: str, check: str, target: str = '', max_pages: int = 200, report_truncation: bool = True,
                deadline: float | None = None):
        """Follow nextLink. Returns (items or None if the first page failed, status, error). Paging cut off at max_pages
        (or, after the first page, at `deadline` on time.monotonic()) returns what was read with the error 'truncated after
        N pages' and, unless the caller handles it, adds a failed read to the call log (the 200 answers alone would make an
        incomplete read look complete)."""
        url = path_or_url if path_or_url.startswith('http') else f'https://{ARM_HOST}{path_or_url}'
        items, pages, status, error = [], 0, None, None
        timed_out = False
        while url and pages < max_pages:
            if pages and deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                break
            status, data, error = self.get(url, check, target)
            pages += 1
            if status != 200 or not isinstance(data, dict):
                return (items or None), status, error
            items.extend(data.get('value') or [])
            url = data.get('nextLink') or data.get('@odata.nextLink')
        if url:
            error = f'truncated after {pages} pages' + (' (time limit)' if timed_out else '')
            if report_truncation:
                self.record(check, target, path_or_url, None, error)
        return items, status, error

    def arg(self, query: str, subscriptions: list[str], check: str, target: str = '', chunk: int = 500):
        """Resource Graph query with paging. Returns (rows or None if nothing could be read, status, error)."""
        rows, status, error = [], None, None
        for i in range(0, len(subscriptions), chunk):
            skip = None
            while True:
                options = {'resultFormat': 'objectArray', '$top': 1000}
                if skip:
                    options['$skipToken'] = skip
                status, data, error = self.request('POST', ARG_URL, check, target,
                                                   body={'subscriptions': subscriptions[i:i + chunk], 'query': query, 'options': options})
                if status != 200:
                    return (rows or None), status, error
                rows.extend(data.get('data') or [])
                skip = data.get('$skipToken')
                if not skip:
                    break
        return rows, status, error
