"""Offline analysis context: raw data loaders, environment inference and the finding writer for S-I1..S-I10."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

from ..common import Findings, Raw, enabled, env, load_scope

PILLAR = 'security_identity'
NON_PROD = ('test', 'dev')
# Names that look like a shared or functional account rather than a person (shown in findings; person names are not).
SHARED_ACCOUNT = re.compile(r'(?i)(^|[\s_.-])(admin|administrator|root|ops|team|shared|service|svc|common|public|support|运维|管理员|共享)($|[\s_.\d-])')


def parse_dt(value):
    if not value:
        return None
    text = re.sub(r'\.(\d{6})\d+', r'.\1', str(value).replace('Z', '+00:00'))
    try:
        d = datetime.fromisoformat(text)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def is_test(e):
    return bool(e) and e.get('value') in NON_PROD


def is_prod(e):
    return bool(e) and e.get('value') == 'prod'


class Ctx:
    def __init__(self, ws, cfg):
        self.ws, self.cfg, self.raw = ws, cfg, Raw(ws, PILLAR)
        self.subs = load_scope(ws)
        self.sub_by_id = {s['id']: s for s in self.subs}
        self.enabled = enabled(self.subs)
        self.disabled = [s for s in self.subs if s.get('state') != 'Enabled']
        manifest = self.raw.load('manifest.json') or {}
        self.window = manifest.get('window')
        self.today = parse_dt((self.window or {}).get('end')) or datetime.now(timezone.utc)
        self.findings = Findings(PILLAR)
        self.seq = Counter()
        self.notes = defaultdict(list)
        self.inventory = {}
        self.subcalls = {s['id']: (self.raw.load(f'subscriptions/{s["id"]}.json') or {}).get('calls', {}) for s in self.enabled}
        self.graph = self.raw.load('graph/principals.json') or {}
        self.gobj = self.graph.get('objects') or {}
        self.graph_ok = bool(self.graph) and not self.graph.get('errors')
        self.type_counts = defaultdict(dict)
        for r in self.rows('type_counts'):
            self.type_counts[r['subscriptionId']][r['type']] = r['n']
        self.pricing = {sid: self._pricing(c) for sid, c in self.subcalls.items()}

    def rows(self, name):
        return (self.raw.load(f'arg/{name}.json') or {}).get('rows') or []

    def name_of(self, sid):
        return self.sub_by_id.get(sid, {}).get('name', sid)

    def env(self, subscription_name, resource_name='', tags=None):
        return env(self.cfg, subscription_name, resource_name, tags)

    def sub_env(self, subscription_name):
        return env(self.cfg, subscription_name)

    def plan_tier(self, sid, plan):
        return ((self.pricing.get(sid) or {}).get(plan) or {}).get('tier')

    @staticmethod
    def _pricing(calls):
        p = calls.get('pricings', {})
        if p.get('http') != 200 or not p.get('body'):
            return None
        return {x['name']: {'tier': x['properties'].get('pricingTier'), 'subPlan': x['properties'].get('subPlan')} for x in p['body'].get('value', [])}

    def add(self, check, severity, sub, rg, name, rtype, environment, finding, evidence, recommendation, confirm=None, *,
            rid=None, members=None, key=None):
        """sub is a subscription id, or a label such as '多个订阅（3 个）' for merged rows (then key keeps the id stable)."""
        self.seq[check] += 1
        legacy = f'{check}-{self.seq[check]:03d}'
        real = sub in self.sub_by_id
        label = self.name_of(sub) if real else sub
        item = self.findings.add(check, severity, finding, recommendation, subscription=label if real else None, resource_group=rg,
                                 resource_name=name, resource_type=rtype, resource_id=rid, environment=environment, evidence=evidence,
                                 needs_confirmation=confirm, members=members, key=key, legacy_id=legacy)
        if not real:
            item['subscriptionName'] = label
        return item


def member(name, rtype, subscription=None):
    return {'name': name, 'type': rtype, 'subscription': subscription}


def subscription_members(names):
    return [member(n, 'Microsoft.Resources/subscriptions', n) for n in names]
