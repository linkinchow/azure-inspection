"""Shared pieces for the WAF pillars (03 reliability + security, 04 operational excellence + performance).

Every pillar is a subpackage waf/<pillar>/ with two entry points:

    collect(ws, cfg, client, window, log=print)   online, read-only; writes raw/waf/<pillar>/...
    analyze(ws, cfg, log=print) -> dict            offline; reads raw only; writes findings/waf/<pillar>.json

Rules that apply to every pillar:
- Network access only through the ReadOnlyClient passed in (it enforces the read-only allow-list and the account check).
- Raw responses are saved through Raw.save (sanitized). analyze() must not make network calls.
- A failed read is recorded in coverage and never turns into "no problem" or 0.
- Environment comes from customer.yaml via env(); vendor-managed resources via cfg.vendor(); no customer names in code.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone

from ..core.io import read_json, sanitize, write_json

# Run order: operations reads performance call records and the reliability findings, so it goes last.
PILLARS = ['reliability', 'aprl', 'security_network', 'security_identity', 'defender', 'performance', 'operations', 'amba', 'landing_zone']
REPORT_OF = {'reliability': '03', 'aprl': '03', 'defender': '03', 'amba': '04', 'landing_zone': '03', 'security_network': '03', 'security_identity': '03', 'operations': '04', 'performance': '04'}
PILLAR_LABEL = {'reliability': '可靠性', 'aprl': '可靠性', 'defender': '安全', 'amba': '卓越运营', 'landing_zone': '架构', 'security_network': '安全', 'security_identity': '安全', 'operations': '卓越运营', 'performance': '性能效率'}
SEVERITIES = ('高', '中', '低')
ENV_LABELS = {'prod': '生产', 'test': '测试', 'dev': '开发', 'dr': '灾备', 'mixed': '多个环境', 'unknown': '未知'}
LOOKBACK_DAYS = 30
# Group name for Advisor recommendations returned without a description
ADVISOR_NO_TEXT = 'Advisor 未返回说明'
# Pillars whose keyed rows are tenant-wide categories (one row per problem type): ids ignore the subscription list
TENANT_WIDE = {'operations'}
# subscription labels of rows merged across subscriptions: '(多个订阅)', '多个订阅（4 个）', '全部 3 个可读订阅', '1 个订阅'
AGGREGATE_SUBSCRIPTION = re.compile(r'多个订阅|\d+\s*个(?:可读|生产)?订阅|^[（(]')


# rows about the tenant itself ('租户', '租户根管理组（继承到全部订阅）'): checked tenant-wide whatever the subscription scope
TENANT_LABEL = re.compile(r'^租户')


def is_tenant_label(label) -> bool:
    return bool(label) and bool(TENANT_LABEL.match(str(label)))


def subs_phrase(names, unit='订阅', then='') -> str:
    """'订阅 core' for one subscription, '3 个订阅' for several (unit: '订阅', '生产订阅', ...); `then` follows with a
    space after a name ('订阅 core 的', '3 个订阅的')."""
    names = list(names)
    return (f'{unit} {names[0]}' + (f' {then}' if then else '')) if len(names) == 1 else f'{len(names)} 个{unit}{then}'


def none_have(names, unit='订阅') -> str:
    """'订阅 core 没有' for one subscription, '3 个订阅都没有' for several."""
    names = list(names)
    return f'{unit} {names[0]} 没有' if len(names) == 1 else f'{len(names)} 个{unit}都没有'


def is_aggregate_subscription(label) -> bool:
    return bool(label) and bool(AGGREGATE_SUBSCRIPTION.search(str(label)))


def now():
    return datetime.now(timezone.utc).isoformat()


def window(days: int = LOOKBACK_DAYS, end: datetime | None = None) -> dict:
    """Lookback window for metrics and activity logs, ending at the start of the collection day (UTC)."""
    end = (end or datetime.now(timezone.utc)).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)
    return {'start': start.strftime('%Y-%m-%dT%H:%M:%SZ'), 'end': end.strftime('%Y-%m-%dT%H:%M:%SZ'), 'days': days,
            'snapshot': end.date().isoformat()}


def advisor_problem(rec: dict, default: str = '') -> str:
    """Problem text of an Advisor recommendation; some come without properties.shortDescription."""
    return ((rec.get('properties') or {}).get('shortDescription') or {}).get('problem') or default


def env(cfg, subscription_name: str = '', resource_name: str = '', tags: dict | None = None) -> dict:
    """{'value': prod|test|dev|dr|unknown, 'label': 中文, 'basis': 依据}. Tag first, then resource name, then subscription."""
    value, basis = cfg.environment(subscription_name or '', resource_name or '', tags)
    return {'value': value, 'label': ENV_LABELS.get(value, value), 'basis': basis}


def mixed_env(envs: list[dict]) -> dict:
    """Environment for a merged finding covering several resources."""
    values = {e['value'] for e in envs if e}
    if len(values) == 1:
        return envs[0]
    if 'prod' in values:
        return {'value': 'mixed', 'label': '多个环境（含生产）', 'basis': '见涉及资源'}
    return {'value': 'mixed', 'label': ENV_LABELS['mixed'], 'basis': '见涉及资源'}


def is_prod(e: dict | None) -> bool:
    return bool(e) and (e.get('value') == 'prod' or (e.get('value') == 'mixed' and '生产' in e.get('label', '')))


def env_text(e) -> str:
    if not e:
        return '未知'
    if isinstance(e, str):
        return e
    basis = e.get('basis')
    return f'{e.get("label")}（推断：{basis}）' if basis and basis not in ('无法判断', '见涉及资源') else e.get('label', '未知')


class Raw:
    """raw/waf/<pillar>/..., sanitized on write."""

    def __init__(self, ws, pillar: str):
        self.ws, self.pillar = ws, pillar
        self.root = ws.raw(f'waf/{pillar}')

    def path(self, rel: str):
        return self.root / rel

    def save(self, rel: str, obj):
        return write_json(self.root / rel, sanitize(obj))

    def load(self, rel: str, default=None):
        p = self.root / rel
        return read_json(p) if p.exists() else default

    def exists(self, rel: str) -> bool:
        return (self.root / rel).exists()

    def other(self, pillar: str) -> 'Raw':
        """Read another pillar's raw data (e.g. performance reuses reliability inventory)."""
        return Raw(self.ws, pillar)


def save_scope(ws, cfg, client, log=print) -> list[dict]:
    """Subscriptions visible to the read-only account, shared by all pillars: raw/waf/scope.json."""
    from ..vm.collect import subscriptions_in_scope
    subs = subscriptions_in_scope(client, cfg)
    write_json(ws.raw('waf/scope.json'), {'collectedAt': now(), 'subscriptions': subs})
    enabled = [s for s in subs if s.get('state') == 'Enabled']
    log(f'订阅：{len(subs)} 个纳入范围，其中 {len(enabled)} 个已启用可读取')
    return subs


def load_scope(ws) -> list[dict]:
    """[{'id','name','state',...}] in scope. Disabled subscriptions stay listed so reports can say they were not read."""
    return read_json(ws.raw('waf/scope.json'))['subscriptions']


def enabled(subs: list[dict]) -> list[dict]:
    return [s for s in subs if s.get('state') == 'Enabled']


# API error codes in plain Chinese for the coverage page; the original text follows in brackets
ERROR_MEANINGS = [
    (r'FeatureNotSupported|NotSupported', '资源不支持这项功能，不适用这一检查'),
    (r'ResourceNotFound|NotFound', '资源不存在或已删除'),
    (r'AuthorizationFailed|Forbidden|LinkedAuthorizationFailed', '没有读取权限'),
    (r'NoRegisteredProviderFound|SubscriptionNotRegistered|MissingSubscriptionRegistration', '订阅没有注册相关的资源提供程序'),
    (r'InvalidResourceType', '接口不认这种资源类型'),
]


def plain_error(status, error, count=1) -> str:
    """'n 次读取：<Chinese meaning>（HTTP status：original）' for a coverage note."""
    text = str(error or '')
    meaning = next((m for rx, m in ERROR_MEANINGS if re.search(rx, text)), None)
    if not meaning:
        meaning = ('接口限流' if status == 429 else '服务端错误' if isinstance(status, int) and status >= 500 else
                   '资源不存在或已删除' if status == 404 else '没有读取权限' if status in (401, 403) else '接口报错')
    detail = '' if not text or text == f'HTTP {status}' or re.fullmatch(r'None(: ?None)?', text.strip()) else text   # 'None: None': no text kept (before 0.10.4)
    return f'{count} 次读取：{meaning}（HTTP {status}' + (f'：{detail}' if detail else '') + '）'


def coverage_entry() -> dict:
    return {'attempted': 0, 'succeeded': 0, 'denied': 0, 'otherErrors': 0, 'notes': []}


def not_applicable(call: dict) -> bool:
    """A saved call whose answer means 'not applicable', not a failed read: Blob settings of a FileStorage account,
    the retired classic administrators API (calls recorded before 0.10.7 skipped them), a resource type an API does not
    support (e.g. resource health of MongoDB vCore: 422 UnsupportedResourceType), Defender settings of a subscription
    without the Microsoft.Security provider (404 Subscription Not Registered: S-I4 reports it as a problem)."""
    url, error = str(call.get('url') or ''), str(call.get('error') or '')
    status = call.get('status', call.get('http'))
    return ('/classicadministrators' in url.lower() or (status == 400 and 'FeatureNotSupportedForAccount' in error)
            or (status == 422 and error.startswith('UnsupportedResourceType'))
            or (status in (401, 404) and 'not registered' in error.lower() and '/providers/microsoft.security/' in url.lower()))


def tally(coverage: dict, check: str, status) -> None:
    c = coverage.setdefault(check, coverage_entry())
    c['attempted'] += 1
    if status == 200:
        c['succeeded'] += 1
    elif status in (401, 403):
        c['denied'] += 1
    else:
        c['otherErrors'] += 1


class Findings:
    """Collects findings in the shared format.

    Finding fields: id, check, severity, subscriptionName, resourceGroup, resourceName, resourceType, resourceId,
    environment {value,label,basis}, finding, recommendation, needsConfirmation (str or None), evidence,
    members [{'name','type','subscription'}] (resources this row covers, for 涉及资源数), legacyId (optional).

    id is '<check>-<6 hex>' from a stable key (subscription + resource id/name or an explicit key), so the same
    problem keeps its id from month to month.
    """

    def __init__(self, pillar: str):
        self.pillar, self.items, self._ids, self._previous, self._bases = pillar, [], set(), set(), {}

    @staticmethod
    def _unique(check, stable, taken):
        fid = f'{check}-{hashlib.sha1(stable.encode()).hexdigest()[:6]}'
        n = 2
        while fid in taken:
            fid = f'{check}-{hashlib.sha1(f"{stable}|{n}".encode()).hexdigest()[:6]}'
            n += 1
        taken.add(fid)
        return fid

    def add(self, check, severity, finding, recommendation, *, subscription=None, resource_group=None, resource_name=None,
            resource_type=None, resource_id=None, environment=None, evidence=None, needs_confirmation=None, members=None,
            key=None, legacy_id=None, acceptance=None, rule=None) -> dict:
        """acceptance: this finding's own criterion, when the check's default (checks.ACCEPTANCE) does not fit it.
        rule: the rule of the check that found it (the check lists the rules it ran in coverage 'rules'); tracking tells a
        rule added this month from a new problem."""
        assert severity in SEVERITIES, severity
        # a row merged across subscriptions keeps its id when the subscription list or the count changes
        multi = bool(key) and (self.pillar in TENANT_WIDE or any(x in str(subscription or '') for x in ('、', ',', '多个订阅')))
        before = f'{check}|{"*" if multi else (subscription or "").lower()}|{(key or resource_id or resource_name or "").lower()}'
        # a per-resource row with a fixed key (S-I1 'api-server' per cluster): the resource tells the rows apart; before 0.9.0
        # the order of processing did, so a new resource could take an old one's id (previousId keeps that id for narratives)
        stable = f'{before}|{resource_id.lower()}' if key and resource_id and not multi else before
        fid = self._unique(check, stable, self._ids)
        previous = self._unique(check, before, self._previous)
        self._bases[before] = self._bases.get(before, 0) + 1
        if members is None:
            members = [{'name': resource_name, 'type': resource_type, 'subscription': subscription}] if resource_name else []
        if isinstance(needs_confirmation, list):
            needs_confirmation = '；'.join(map(str, needs_confirmation))
        item = {'id': fid, 'check': check, 'severity': severity, 'subscriptionName': subscription, 'resourceGroup': resource_group,
                'resourceName': resource_name, 'resourceType': resource_type, 'resourceId': resource_id,
                'environment': environment or {'value': 'unknown', 'label': '未知', 'basis': '无法判断'},
                'finding': finding, 'recommendation': recommendation, 'needsConfirmation': needs_confirmation or None,
                'evidence': evidence or {}, 'members': members}
        if legacy_id:
            item['legacyId'] = legacy_id
        if previous != fid:
            item['previousId'], item['_previousBase'] = previous, before
        if acceptance:
            item['acceptance'] = acceptance
        if rule:
            item['rule'] = rule
        self.items.append(item)
        return item

    def write(self, ws, *, window: dict | None, coverage: dict, scope: dict, inventory: dict | None = None,
              limitations: list | None = None, extra: dict | None = None) -> dict:
        for f in self.items:
            # the old scheme told rows under one key apart by processing order: its id says which resource only when alone
            if self._bases.get(f.pop('_previousBase', None), 0) > 1:
                f.pop('previousId', None)
        try:   # a merged row over one subscription reads as that subscription (wording only: the id does not change)
            only = [s['name'] for s in load_scope(ws) if s.get('state') == 'Enabled']
        except FileNotFoundError:
            only = []
        for f in self.items:
            if not is_aggregate_subscription(f.get('subscriptionName')):
                continue
            subs = {m.get('subscription') for m in f.get('members') or [] if m.get('subscription') and not is_aggregate_subscription(m['subscription'])}
            if len(subs) == 1:
                f['subscriptionName'] = subs.pop()
            elif not subs and len(only) == 1:
                f['subscriptionName'] = only[0]
        data = {'pillar': self.pillar, 'report': REPORT_OF[self.pillar], 'analyzedAt': now(), 'window': window,
                'scope': scope, 'coverage': coverage, 'findings': self.items, 'inventory': inventory or {},
                'limitations': limitations or [], 'complete': True, **(extra or {})}
        write_json(ws.month_dir('findings') / 'waf' / f'{self.pillar}.json', sanitize(data))
        return data


def load_findings(ws, pillar: str) -> dict:
    data = read_json(ws.month_dir('findings') / 'waf' / f'{pillar}.json')
    assert data.get('complete'), pillar
    return data
