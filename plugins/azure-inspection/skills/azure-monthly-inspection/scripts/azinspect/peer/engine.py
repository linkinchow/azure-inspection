"""Generic peer-comparison engine: per resource type, attributes with a baseline, deviations and their root cause."""
from __future__ import annotations

import collections

from ..waf.common import env_text
from .context import METHOD_PORTAL, METHOD_UNKNOWN, METHOD_VENDOR

FEAS_RANK = {'原地修改': 1, '原地修改（需维护窗口或应用配合）': 2, '新建节点池/新实例替换（不重建整体）': 3,
             '需重建并迁移': 4, '需供应商确认': 5}


def worst(feas_list):
    return max(feas_list, key=lambda x: FEAS_RANK.get(x, 0)) if feas_list else None


def _call(value, r):
    return value(r) if callable(value) else value


def count_label(n, total, unit='个'):
    return f'{n}/{total} {unit}' if total else '0'


class TypeReport:
    def __init__(self, ctx, key, label):
        self.ctx, self.key, self.label = ctx, key, label
        self.items, self.attrs, self.deviations = [], [], []
        self.insights, self.uniform_gaps = [], []
        self.baseline_rationale, self.population_note = '', ''
        self.attr_stats, self.full_followers = {}, []

    def attr(self, key, label, baseline, value_fn, deviates_fn, applies_fn=lambda r: True, rec='', feas='原地修改',
             short=None, confirm=None, follower_note='', major=False):
        self.attrs.append(dict(key=key, label=label, baseline=baseline, value=value_fn, dev=deviates_fn, applies=applies_fn,
                               rec=rec, feas=feas, short=short, confirm=confirm, note=follower_note, major=major))

    def basic(self, r, name=None):
        """Normalised item for an ARM/Resource Graph row: subscription, environment, business line, standard tag, vendor."""
        ctx = self.ctx
        sub = ctx.sub_name(r.get('subscriptionId'))
        name = name or r['name']
        tags = r.get('tags') if isinstance(r.get('tags'), dict) else {}
        e = ctx.env(sub, name, tags)
        return {'id': r.get('id'), 'name': name, 'sub': sub, 'rg': r.get('resourceGroup'), 'tags': tags, 'rtype': r.get('type') or '',
                'region': ctx.region(r.get('location')), 'tf': ctx.standard(tags), 'env': env_text(e), 'prod': e['value'] == 'prod',
                'line': ctx.line(sub, r.get('resourceGroup'), name), 'created': ctx.created(r.get('id')),
                'vendor': ctx.vendor(name, r.get('resourceGroup'))}

    def run(self, root_cause_fn, extra_fn=None):
        ctx = self.ctx
        for a in self.attrs:
            app = [r for r in self.items if a['applies'](r)]
            dev = [r for r in app if a['dev'](r)]
            self.attr_stats[a['key']] = {'label': a['label'], 'baseline': a['baseline'], 'applicable': len(app),
                                         'followedBy': len(app) - len(dev),
                                         'followedPct': round(100 * (len(app) - len(dev)) / len(app), 1) if app else None}
            if a['note']:
                self.attr_stats[a['key']]['note'] = a['note']
        self.full_followers = [r['name'] for r in self.items
                               if all(not a['dev'](r) for a in self.attrs if a['applies'](r))]
        for r in self.items:
            diffs, recs, feas, shorts, confirms, major = {}, [], {}, [], [], False
            for a in self.attrs:
                if not (a['applies'](r) and a['dev'](r)):
                    continue
                major = major or bool(_call(a['major'], r))
                diffs[a['key']] = {'label': a['label'], 'value': a['value'](r), 'baseline': a['baseline']}
                for bucket, value in ((recs, _call(a['rec'], r)), (shorts, _call(a['short'], r)), (confirms, _call(a['confirm'], r))):
                    if value:
                        bucket.append(value)
                feas[a['key']] = _call(a['feas'], r)
            r['_deviated'], r['_major'] = bool(diffs), major
            if r.get('id') and r.get('rtype'):
                cd = ctx.creation_deploy(r['name'], r['sub'], r['rtype'])
                r['_method'] = (METHOD_VENDOR if r.get('vendor') else ctx.standard_name if r.get('tf')
                                else METHOD_PORTAL if cd else METHOD_UNKNOWN)
            if not diffs:
                continue
            d = {'resourceName': r['name'], 'subscriptionName': r['sub'], 'resourceGroup': r.get('rg'),
                 'environment': r['env'], 'businessLine': r['line'], 'impact': '高（直接对应风险或故障）' if major else '一般',
                 'differingAttributes': diffs, 'rootCauseEvidence': root_cause_fn(r),
                 'linkedFindingIds': r.get('_links') or ctx.linked(r['name']),
                 'recommendation': '；'.join(dict.fromkeys(recs)), 'feasibility': worst(list(feas.values())),
                 'feasibilityByAttribute': feas, 'shortTermMitigation': '；'.join(dict.fromkeys(shorts)) or None,
                 'needsConfirmation': '；'.join(dict.fromkeys(confirms)) or None}
            if extra_fn:
                extra_fn(r, d)
            self.deviations.append(d)

    def population(self):
        pop = {'total': len(self.items),
               'byEnvironment': dict(collections.Counter(r['env'].split('（')[0] for r in self.items)),
               'byBusinessLine': dict(collections.Counter(r['line'] for r in self.items)),
               'bySubscription': dict(collections.Counter(r['sub'] for r in self.items)),
               'standardTagged': sum(1 for r in self.items if r.get('tf'))}
        if self.population_note:
            pop['note'] = self.population_note
        return pop

    def to_json(self, baseline_attrs=None):
        n = len(self.items)
        baseline_attrs = baseline_attrs or {a['key']: a['baseline'] for a in self.attrs}
        return {'type': self.label, 'typeKey': self.key, 'population': self.population(),
                'baseline': {'attributes': baseline_attrs, 'attributeAdoption': self.attr_stats,
                             'followedBy': len(self.full_followers) if self.attrs else None,
                             'followedPct': (round(100 * len(self.full_followers) / n, 1) if n else None) if self.attrs else None,
                             'fullyCompliantResources': self.full_followers if self.attrs else [],
                             'rationale': self.baseline_rationale},
                'deviations': self.deviations, 'deviationCount': len(self.deviations),
                'uniformGaps': self.uniform_gaps, 'patternInsights': self.insights}


def std_root_cause(ctx, r, extra_notes=None, peers_dates=None):
    """Evidence for why a resource differs: standard tag, creation time, portal wizard record, later portal changes."""
    cd = ctx.creation_deploy(r['name'], r['sub'], r.get('rtype'))
    if cd:
        method = f'{cd["method"]}（部署 {cd["deployment"]}，{cd["date"]}）'
    elif r['tf']:
        method = f'{ctx.standard_name}（带 {ctx.standard_label} 标签）'
    else:
        method = '未知：没有标准创建标签，部署历史中也没有创建记录'
    rc = {'standardTag': r['tf'], 'createdTime': r['created'], 'businessLine': r['line'], 'vendorManaged': bool(r.get('vendor')),
          'creationMethod': method, 'portalChangesAfterCreation': ctx.portal_changes(r['name'], r['sub'])[:8]}
    notes = list(extra_notes or [])
    if peers_dates and r['created']:
        dates = [d for d in peers_dates.values() if d]
        if dates and all(d > r['created'] for d in dates):
            notes.append(f'创建时间 {r["created"]} 早于全部按标准方式创建的同类（{min(dates)} 起）')
    if r['tf'] and rc['portalChangesAfterCreation']:
        notes.append(f'虽由 {ctx.standard_name} 管理，但创建后有门户直接修改记录（配置可能已与代码不一致）')
    rc['notes'] = notes
    return rc


def most_common(values):
    values = [v for v in values if v not in (None, '')]
    return collections.Counter(values).most_common(1)[0][0] if values else None
