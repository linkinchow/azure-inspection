"""Shared data and helpers for the peer comparison: subscriptions, creation times, deployment history, findings index.

Inputs (all offline, written by other parts):
  raw/peer/resources-createdTime.json          creation timestamps (peer.collect); optional
  raw/waf/security_network/raw/{arg,arm}/...    resource configuration
  raw/waf/security_identity/{aks,arg}/...       AKS clusters, VMs
  raw/waf/operations/...                        deployment history, diagnostic settings
  raw/waf/reliability/...                       storage blob services, capacity, AKS node VMSS
  raw/waf/performance/arg/workspaces.json       Log Analytics retention
  findings/waf/*.json                           inspection findings (for links)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..core.io import read_json
from ..waf.common import PILLARS, env, load_scope

# Deployment names that Azure portal wizards leave in resource-group deployment history (Terraform leaves none).
CREATE_PAT = re.compile(r'^(CreateRedisEnterprise-|MySqlFlexibleServer_|MySQLFlexibleServer_|PostgreSqlFlexibleServer_|'
                        r'microsoft\.aks-|CreateVm-|AIFoundryCreate-|Microsoft\.[A-Za-z]+-|NoMarketplace-|'
                        r'CreateNetworkSecurityGroupBladeV2-|CreateAppGwForContainers-|CreateForm-|RestoreMySQLFlexibleServer_)', re.I)
PORTAL_LABEL = [
    (re.compile(r'^microsoft\.aks-', re.I), 'Azure 门户“创建 Kubernetes 集群”向导'),
    (re.compile(r'^CreateRedisEnterprise-', re.I), 'Azure 门户“创建 Azure Managed Redis”向导'),
    (re.compile(r'^(MySqlFlexibleServer_|MySQLFlexibleServer_)', re.I), 'Azure 门户“创建 MySQL 灵活服务器”向导'),
    (re.compile(r'^PostgreSqlFlexibleServer_', re.I), 'Azure 门户“创建 PostgreSQL 灵活服务器”向导'),
    (re.compile(r'^CreateVm-', re.I), 'Azure 门户“创建虚拟机”向导'),
    (re.compile(r'^RestoreMySQLFlexibleServer_', re.I), 'Azure 门户还原 MySQL'),
]
UPDATE_PAT = re.compile(r'^(Update|Upgrade|MySQLFlexibleServerParameters|PostgreSQLFlexibleServerParameters|updateNetwork)', re.I)
METHOD_PORTAL, METHOD_UNKNOWN, METHOD_VENDOR = '门户向导', '未知（无标签、无部署记录）', '供应商'


class Context:
    def __init__(self, ws, cfg, narrative=None):
        self.ws, self.cfg = ws, cfg
        self.narrative = narrative or {}
        self.raw = ws.raw('waf')
        scope = load_scope(ws)
        self.subs = {s['id'].lower(): s['name'] for s in scope if s.get('state') == 'Enabled'}
        self.created_map, self.created_meta = self._created()
        self.deploys = self._deploys()
        self.findings = self._findings()
        self.public_storage = re.compile(cfg.public_storage_names, re.I) if getattr(cfg, 'public_storage_names', None) else None
        self.standard_label = self._standard_label()

    # ------------------------------------------------------------- loading
    def load(self, rel, default=None):
        p = self.raw / rel
        return read_json(p) if p.exists() else default

    def rows(self, rel):
        """Resource Graph result files are either a list or {'rows': [...]}."""
        data = self.load(rel, [])
        return data.get('rows') or [] if isinstance(data, dict) else data

    def _created(self):
        path = self.ws.raw('peer/resources-createdTime.json')
        if not path.exists():
            return {}, None
        data = read_json(path)
        out = {}
        for s in data.get('subscriptions') or []:
            for r in s.get('resources') or []:
                if r.get('id'):
                    out[r['id'].lower()] = r.get('createdTime')
        return out, data

    def _deploys(self):
        out = []
        for e in self.load('operations/deployments-rg.json', []) or []:
            for v in e.get('value') or []:
                tags = v.get('tags') or {}
                out.append({'sub': self.sub_name(e['subscriptionId']), 'rg': e.get('resourceGroup'), 'name': v.get('name') or '',
                            'ts': (v.get('timestamp') or '')[:10], 'primary': (tags.get('primaryResourceId') or '').rstrip('/').split('/')[-1],
                            'market': tags.get('marketplaceItemId'), 'types': v.get('resourceTypes') or [], 'state': v.get('provisioningState')})
        return out

    def _findings(self):
        out = []
        for p in PILLARS:
            path = self.ws.month_dir('findings') / 'waf' / f'{p}.json'
            if not path.exists():
                continue
            for f in read_json(path)['findings']:
                text = ' '.join(str(f.get(k) or '') for k in ('resourceName', 'finding')) + ' ' + json.dumps(f.get('evidence'), ensure_ascii=False)
                out.append((f['id'], f.get('check'), text.lower(), f.get('legacyId')))
        return out

    def _standard_label(self):
        tag = self.cfg.standard_tag or {}
        return f'{tag.get("key")}={tag.get("value")}' if tag else None

    @property
    def standard_name(self):
        """How the standard creation method is called in the report, e.g. 'Terraform' for managed_by=terraform."""
        value = str((self.cfg.standard_tag or {}).get('value') or '')
        return value[:1].upper() + value[1:] if value.isalpha() else (value or '标准方式')

    # ------------------------------------------------------------- facts per resource
    def sub_name(self, sid):
        return self.subs.get(str(sid or '').lower(), sid)

    def created(self, rid):
        t = self.created_map.get(str(rid or '').lower())
        return t[:10] if t else None

    def standard(self, tags):
        """Created the customer's standard way (IaC tag from customer.yaml); None when no standard tag is configured."""
        return bool(self.cfg.created_by_standard(tags))

    def vendor(self, name, rg=''):
        return self.cfg.vendor(name or '', rg or '')

    def line(self, sub, rg='', name=''):
        vendor = self.vendor(name, rg)
        if vendor:
            return f'{vendor}（供应商）'
        return self.cfg.business_line(sub or '', rg or '', name or '') or '其他'

    def env(self, sub, name='', tags=None):
        return env(self.cfg, sub or '', name or '', tags)

    def region(self, location):
        return self.cfg.region(location or '') or '其他/全局'

    def creation_deploy(self, name, sub=None, rtype=None):
        """Earliest create-style deployment whose primary resource (or name) is this resource."""
        nl, want = name.lower(), (rtype or '').split('/')[-1].lower()
        hits = []
        for d in self.deploys:
            if sub and d['sub'] != sub:
                continue
            if not (CREATE_PAT.match(d['name']) or d.get('market')):
                continue
            if want and not any(t.lower() == want for t in d['types']):
                continue
            if d['primary'].lower() == nl or re.search(r'(?<![a-z0-9])' + re.escape(nl) + r'(?![a-z0-9-])', d['name'].lower()):
                hits.append(d)
        if not hits:
            return None
        hits.sort(key=lambda d: (d['ts'], d['name']))
        d = ([h for h in hits if h['state'] == 'Succeeded'] or hits)[0]
        label = next((lab for p, lab in PORTAL_LABEL if p.match(d['name'])),
                     f'Azure 门户向导（{d["market"]}）' if d.get('market') else 'Azure 门户/模板部署')
        return {'deployment': d['name'], 'date': d['ts'], 'method': label, 'attempts': len(hits)}

    def portal_changes(self, name, sub=None):
        out = {f'{d["ts"]} {re.sub(r"_[0-9a-f]{20,}$", "", d["name"])}' for d in self.deploys
               if (not sub or d['sub'] == sub) and d['primary'].lower() == name.lower() and UPDATE_PAT.match(d['name'])}
        return sorted(out)

    def linked(self, *names, checks=None):
        """Finding ids whose resource name, text or evidence mentions one of the names."""
        ids = []
        for fid, chk, text, _legacy in self.findings:
            if checks and chk not in checks:
                continue
            if any(nm and re.search(r'(?<![a-z0-9_.-])' + re.escape(nm.lower()) + r'(?![a-z0-9_-])', text) for nm in names):
                ids.append(fid)
        return ids

    def notes_for(self, type_key, name):
        """Customer-specific explanations written by the agent in narrative/05.json (resourceNotes)."""
        notes = (self.narrative.get('resourceNotes') or {})
        return list(notes.get(f'{type_key}|{name}') or notes.get(name) or [])


def load_narrative(ws):
    path = ws.month_dir('narrative') / '05.json'
    return json.loads(Path(path).read_text(encoding='utf-8')) if Path(path).exists() else {}
