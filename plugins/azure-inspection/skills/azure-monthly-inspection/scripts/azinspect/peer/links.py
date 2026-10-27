"""Link 03/04 findings to the peer comparison: how the resource differs from its peers, why, and how to align.

Output findings/peer/links.json: {finding id: {'difference', 'rootCause', 'alignment'}}; the 03/04 report fills the
matching columns of the issue list from it (a finding's own fields take precedence).
"""
from __future__ import annotations

from collections import defaultdict

NL = '\n'
# Which compared attributes matter for which check; checks without a mapping show the first few differing attributes.
CHECK_ATTRIBUTES = {'R1': {'ipam'}, 'R12': {'ipam'}, 'P2': {'ipam'}, 'R2': {'systemPool'}, 'R3': {'zones'}, 'R4': {'tier'},
                    'R9': {'version', 'nodeOS'}, 'S-I1': {'apiServer'}, 'S-I3': {'version', 'nodeOS', 'networkPolicy'}, 'O1': {'monitoring'}}


def _keys(d, check):
    attrs = d.get('differingAttributes') or {}
    return [k for k in attrs if k in CHECK_ATTRIBUTES.get(check, set())] or list(attrs)[:4]


def difference(devs, check):
    parts = []
    for _, d in devs[:4]:
        attrs = d.get('differingAttributes') or {}
        items = '；'.join(f'{attrs[k].get("label", k)}：{attrs[k].get("value")}（同类标准：{attrs[k].get("baseline")}）' for k in _keys(d, check))
        if items:
            parts.append(f'{d["resourceName"]}——{items}')
    return NL.join(parts)[:1500] or None


def root_cause(devs):
    out = []
    for _, d in devs[:3]:
        e = d.get('rootCauseEvidence') or {}
        bits = [e.get('creationMethod')]
        if e.get('createdTime'):
            bits.append(f'创建于 {e["createdTime"]}')
        if e.get('businessLine'):
            bits.append(f'业务线：{e["businessLine"]}')
        if e.get('vendorManaged'):
            bits.append('由供应商创建，需与供应商一起对齐')
        out.append(f'{d["resourceName"]}：' + '，'.join(b for b in bits if b))
    return NL.join(out)[:1200] or None


def alignment(devs, check):
    out = []
    for _, d in devs[:3]:
        attrs = list((d.get('differingAttributes') or {}).keys())
        recs = (d.get('recommendation') or '').split('；')
        per = dict(zip(attrs, recs)) if len(recs) == len(attrs) else {}
        feas = d.get('feasibilityByAttribute') or {}
        keys = _keys(d, check)
        items = [f'{per[k]}（{feas[k]}）' if feas.get(k) else per[k] for k in keys if per.get(k)] or [d.get('recommendation') or '']
        text = '；'.join(items)
        if d.get('shortTermMitigation') and any(w in feas.get(k, '') for k in keys for w in ('重建', '迁移')):
            text += f'。短期：{d["shortTermMitigation"]}'
        out.append(f'{d["resourceName"]}：{text}')
    return NL.join(out)[:1500] or None


def build_links(ctx, data):
    by_finding = defaultdict(list)
    for t in data['types']:
        for d in t['deviations']:
            for fid in d.get('linkedFindingIds') or []:
                by_finding[fid].append((t['type'], d))
    checks = {fid: chk for fid, chk, _text, _legacy in ctx.findings}
    out = {}
    for fid, devs in by_finding.items():
        check = checks.get(fid)
        if check != 'S-N1':   # NSG rows only explain subnet-NSG findings
            devs = [(t, d) for t, d in devs if 'NSG' not in t] or devs
        out[fid] = {'difference': difference(devs, check), 'rootCause': root_cause(devs), 'alignment': alignment(devs, check)}
    return out
