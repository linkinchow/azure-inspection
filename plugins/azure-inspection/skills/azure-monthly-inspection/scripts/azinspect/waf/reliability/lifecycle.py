"""R9 version end of support and service retirements: Service Health retirement notices, database and cache engine
versions, App Service stack versions, VM operating systems and Application Gateway certificates.

Support dates come from <skill>/vendor/lifecycle/lifecycle.json, checked by hand against the source page of each entry;
no date is written in code. Everything here reads data the reliability collection already saved (Resource Graph and ARM
GET only); a value that was not read is reported as not judged, never as "still supported".
"""
from __future__ import annotations

import base64
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..checks import count_text, type_label

CALENDAR = Path(__file__).resolve().parents[4] / 'vendor' / 'lifecycle' / 'lifecycle.json'
REVIEW_DAYS = 180            # remind to re-check the calendar after this many days
CERT_WARN_DAYS = 30          # same threshold as the Front Door certificate check
VM_TYPE, VMSS_TYPE = 'Microsoft.Compute/virtualMachines', 'Microsoft.Compute/virtualMachineScaleSets'
APPGW_TYPE, SITE_TYPE = 'Microsoft.Network/applicationGateways', 'Microsoft.Web/sites'
FAMILY_REC = {
    'mysql': '升级到仍在标准支持期内的大版本（先在只读副本或测试环境验证，升级前备份）；升级后不再产生延长支持费用。',
    'postgres': '升级到仍在标准支持期内的大版本（先在测试环境用大版本升级验证，升级前备份）；升级后不再产生延长支持费用。',
    'redis': '把实例升级到 Redis 6（门户中可直接升级，先在测试实例验证客户端兼容性）。',
    'redis-tier': '规划迁移到 Azure Managed Redis：先确认客户端兼容性、网络（私有终结点或 VNet）和持久化配置，在退役日期前完成切换。',
    'os': '升级到仍受支持的系统版本，或用新镜像重建；完成前可启用延长安全更新作为过渡（Windows Server ESU 在 Azure 上免费，Ubuntu Pro 等需购买）。',
    'runtime': '在应用的“配置 > 常规设置”中把运行时升级到受支持版本，先在部署槽位或测试环境验证。',
}
FAMILY_NOUN = {'mysql': 'MySQL 服务器', 'postgres': 'PostgreSQL 服务器', 'redis': 'Redis 实例', 'redis-tier': 'Redis 实例', 'os': '虚拟机',
               'runtime': '应用'}


# ---------------------------------------------------------------------------------------------- calendar
def load_calendar(path: Path = CALENDAR):
    """(file contents, {(product, version): entry})."""
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    return data, {(e['product'], str(e['version'])): e for e in data.get('entries') or []}


def parse_date(value):
    """Aware UTC datetime from 'YYYY-MM-DD', ISO text or epoch milliseconds; None when absent or unreadable."""
    if value in (None, ''):
        return None
    if isinstance(value, (int, float)) or re.fullmatch(r'\d{10,13}', str(value)):
        n = float(value)
        return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, tz=timezone.utc)
    try:
        d = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def grade(end, now):
    """Severity by date: passed -> 高, within 180 days -> 中, within 365 days -> 低, later -> None (inventory only)."""
    if end is None:
        return None
    days = (end - now).days
    return '高' if days < 0 else '中' if days <= 180 else '低' if days <= 365 else None


def when_text(end, now):
    days = (end - now).days
    return f'已于 {end.date()} 结束' if days < 0 else f'将于 {end.date()} 结束（还有 {days} 天）'


# ---------------------------------------------------------------------------------------------- version keys
def mysql_key(version):
    m = re.match(r'(\d+)\.(\d+)', str(version or ''))
    return f'{m.group(1)}.{m.group(2)}' if m else None


def major_key(version):
    m = re.match(r'(\d+)', str(version or ''))
    return m.group(1) if m else None


def redis_tier(rtype, sku_name):
    """Azure Cache for Redis tiers being retired; Azure Managed Redis (also microsoft.cache/redisenterprise) is not."""
    rtype, sku = str(rtype or '').lower(), str(sku_name or '')
    if rtype == 'microsoft.cache/redis':
        return 'basic-standard-premium'
    if rtype == 'microsoft.cache/redisenterprise' and sku.lower().startswith('enterprise'):
        return 'enterprise'
    return None


_UBUNTU_CODENAMES = {'xenial': '16.04', 'bionic': '18.04', 'focal': '20.04', 'jammy': '22.04', 'noble': '24.04'}


def os_key(name='', version='', image=None):
    """(calendar product, version) for a VM operating system from instanceView osName/osVersion or the image reference."""
    image = image or {}
    text = ' '.join(str(x or '') for x in (name, version)).lower()
    ref = ' '.join(str(image.get(k) or '') for k in ('publisher', 'offer', 'sku')).lower()
    for src in (text, ref):
        if not src.strip():
            continue
        if 'windows' in src:
            m = re.search(r'20(08|12|16|19|22|25)[\s_-]*(r2)?', src)
            if m:
                return 'os-windows-server', f"20{m.group(1)}" + (' R2' if m.group(2) else '')
        if 'ubuntu' in src or 'canonical' in src:
            m = re.search(r'(\d{2})[._](04|10)', src)
            if m:
                return 'os-ubuntu', f'{m.group(1)}.{m.group(2)}'
            for code, ver in _UBUNTU_CODENAMES.items():
                if code in src:
                    return 'os-ubuntu', ver
        if 'centos' in src or 'openlogic' in src:
            m = re.search(r'centos\S*\s+(\d+)|(?:^|\s)(\d+)[._]\d', src)
            # appliances based on CentOS sometimes report their own product version (e.g. 14.7): not guessed
            if m and 5 <= int(m.group(1) or m.group(2)) <= 10:
                return 'os-centos', m.group(1) or m.group(2)
        if 'rhel' in src or 'redhat' in src or 'red hat' in src:
            # versions read 7.9, 8_6, 9-lvm-gen2 or 94_gen2 (= 9.4)
            m = re.search(r'(?<!\d)(\d{1,2})[._](\d)', src) or re.search(r'(?<!\d)([1-9])\d(?=[_-]|$)', src) or re.search(r'(?<!\d)(\d{1,2})(?!\d)', src)
            if m:
                return 'os-rhel', m.group(1)
        # recognised so they can be counted, even when the calendar has no dates for them
        plain = re.sub(r'x86_64|amd64|arm64|aarch64', ' ', src)
        for word, product in (('rocky', 'os-rocky'), ('alma', 'os-almalinux'), ('debian', 'os-debian'), ('sles', 'os-sles'), ('suse', 'os-sles'),
                              ('oracle', 'os-oracle-linux')):
            if word in plain:
                m = re.search(r'(?<!\d)(\d{1,2})(?!\d)', plain[plain.index(word):])
                if m:
                    return product, m.group(1)
    return None


_FX = {'python': 'runtime-python', 'node': 'runtime-node', 'dotnetcore': 'runtime-dotnet', 'dotnet': 'runtime-dotnet', 'php': 'runtime-php',
       'java': 'runtime-java'}


def runtime_keys(config: dict):
    """[(calendar product, version, setting)] for the stack versions of one site."""
    out = []
    fx = str(config.get('linuxFxVersion') or config.get('windowsFxVersion') or '')
    if '|' in fx:
        stack, ver = fx.split('|', 1)
        product = _FX.get(stack.strip().lower())
        m = re.match(r'v?(\d+(?:\.\d+)?)', ver.strip())
        if product and m:
            v = m.group(1)
            if product in ('runtime-node', 'runtime-java'):
                v = v.split('.')[0]
            elif product == 'runtime-dotnet' and '.' not in v:
                v += '.0'
            out.append((product, v, fx))
    net = str(config.get('netFrameworkVersion') or '')
    m = re.fullmatch(r'v(\d+)\.(\d+)', net)
    if m and int(m.group(1)) >= 5:            # v4.0 is .NET Framework 4.x, supported with Windows
        out.append(('runtime-dotnet', f'{m.group(1)}.{m.group(2)}', net))
    for field, product in (('phpVersion', 'runtime-php'), ('pythonVersion', 'runtime-python'), ('nodeVersion', 'runtime-node'),
                           ('javaVersion', 'runtime-java')):
        value = str(config.get(field) or '')
        m = re.search(r'(\d+)(?:\.(\d+))?', value)
        if not m or value.upper() == 'OFF':
            continue
        if product == 'runtime-java':
            v = m.group(2) if m.group(1) == '1' else m.group(1)    # 1.8 is Java 8
        elif product == 'runtime-node':
            v = m.group(1)
        else:
            v = f'{m.group(1)}.{m.group(2) or 0}'
        out.append((product, v, f'{field}={value}'))
    return list(dict.fromkeys(out))


def cert_expiry(public_cert_data):
    """(not-after, subject) of the earliest-expiring certificate in base64 public data (PKCS#7 or X.509); None if unreadable."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7
    try:
        raw = base64.b64decode(public_cert_data)
    except (ValueError, TypeError):
        return None
    certs = []
    for load in (pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates, lambda b: [x509.load_der_x509_certificate(b)],
                 lambda b: [x509.load_pem_x509_certificate(b)]):
        try:
            certs = load(raw)
        except (ValueError, TypeError):
            continue
        if certs:
            break
    if not certs:
        return None
    cert = min(certs, key=lambda c: c.not_valid_after_utc)
    return cert.not_valid_after_utc, cert.subject.rfc4514_string()


# ---------------------------------------------------------------------------------------------- analysis
def check(run, inv, member, calendar_path: Path = CALENDAR):
    """Add the R9 findings; inv receives the inventory under inv['lifecycle']."""
    data, cal = load_calendar(calendar_path)
    reviewed = parse_date(data.get('reviewedAt'))
    out = inv.setdefault('lifecycle', {'calendarReviewedAt': data.get('reviewedAt'), 'versions': [], 'notJudged': [], 'retirements': []})
    limits = run.coverage['R9'].setdefault('limits', [])
    if reviewed is None or (run.now - reviewed).days > REVIEW_DAYS:
        limits.append(f"版本支持日历最后核对于 {data.get('reviewedAt')}，已超过 {REVIEW_DAYS} 天，部分到期日期可能已调整，请更新后重新分析。")
    limits.append('Key Vault 中证书的到期日期只能通过数据面读取，本次未检查；Azure Functions 运行时版本只保存在应用设置中，本次未读取。')
    _versions(run, cal, out, member)
    _app_gateway(run, out, member)
    _retirements(run, out, member, limits)


def _versions(run, cal, out, member):
    items = []      # (family, product, version, resource row, resource type, setting)
    for name, family, key in (('mysql', 'mysql', lambda r: mysql_key((r.get('properties') or {}).get('version'))),
                              ('postgres', 'postgres', lambda r: major_key((r.get('properties') or {}).get('version')))):
        for r in run.rows(name):
            v = key(r)
            items.append((family, family, v, r, r.get('type') or name, (r.get('properties') or {}).get('version')))
    for name in ('redis', 'redisenterprise'):
        for r in run.rows(name):
            p = r.get('properties') or {}
            if name == 'redis':
                items.append(('redis', 'redis', major_key(p.get('redisVersion')), r, 'Microsoft.Cache/Redis', p.get('redisVersion')))
            tier = redis_tier(r.get('type') or f'microsoft.cache/{name}', ((r.get('sku') or p.get('sku') or {}).get('name')))
            if tier:
                items.append(('redis-tier', 'redis-tier', tier, r, r.get('type') or name, tier))
    for r in run.rows('vms'):
        p = r.get('properties') or {}
        iv = (p.get('extended') or {}).get('instanceView') or {}
        k = os_key(iv.get('osName'), iv.get('osVersion'), (p.get('storageProfile') or {}).get('imageReference'))
        items.append(('os', k[0] if k else None, k[1] if k else None, r, VM_TYPE, ' '.join(str(x) for x in (iv.get('osName'), iv.get('osVersion')) if x)))
    for r in run.rows('vmss'):
        if str(r.get('resourceGroup') or '').lower().startswith('mc_') or 'aks-managed-poolname' in {k.lower() for k in r.get('tags') or {}}:
            continue    # AKS node pools: node images are checked with the cluster
        ref = ((((r.get('properties') or {}).get('virtualMachineProfile') or {}).get('storageProfile') or {}).get('imageReference')) or {}
        k = os_key(image=ref)
        items.append(('os', k[0] if k else None, k[1] if k else None, r, VMSS_TYPE, ' '.join(str(ref.get(x) or '') for x in ('offer', 'sku')).strip()))
    sites = {s['id'].lower(): s for s in run.rows('webapps')}
    configs = {r['id'].lower().rsplit('/config/', 1)[0]: r for r in run.rows('webconfig')}
    configs.update({x['id'].lower(): x['versions'] for x in (run.raw.load('lifecycle/app-config.json') or {}).get('sites') or [] if x.get('versions')})
    for sid, site in sites.items():
        keys = runtime_keys(configs.get(sid) or {})
        if not keys and sid not in configs:
            out['notJudged'].append({'name': site['name'], 'type': SITE_TYPE, 'reason': '未取得运行时版本'})
        for product, v, setting in keys:
            items.append(('runtime', product, v, site, SITE_TYPE, setting))

    groups = defaultdict(list)
    for family, product, version, r, rtype, setting in items:
        entry = cal.get((product, version)) if product and version else None
        row = {'name': r.get('name'), 'type': rtype, 'subscription': run.subname(r.get('id') or r.get('subscriptionId') or ''),
               'resourceGroup': r.get('resourceGroup'), 'setting': setting, 'product': product, 'version': version, 'id': r.get('id'),
               'tags': r.get('tags')}
        out['versions'].append({k: row[k] for k in ('name', 'type', 'subscription', 'setting', 'product', 'version')})
        if family == 'os' and not product:
            out['notJudged'].append({'name': row['name'], 'type': rtype, 'reason': '未识别操作系统版本'})
        elif product and version and not entry and family != 'redis':   # the calendar lists only the retired Redis versions
            out['notJudged'].append({'name': row['name'], 'type': rtype, 'reason': '支持日历中没有该版本', 'version': f'{product} {version}'})
        if entry:   # virtual machines and scale sets are counted separately
            groups[(family, product, version, row['subscription'], rtype if family == 'os' else '')].append(row)

    for (family, product, version, sub, _t), rows in sorted(groups.items(), key=lambda kv: (kv[0][3] or '', kv[0][1], kv[0][2], kv[0][4])):
        entry = cal[(product, version)]
        end, ext = parse_date(entry.get('end')), parse_date(entry.get('extendedEnd'))
        sev = grade(end, run.now)
        if sev is None:
            continue
        label, n = entry.get('label') or f'{product} {version}', len(rows)
        noun = type_label(rows[0]['type']) if family == 'os' else FAMILY_NOUN[family]
        subject = f"中的{noun} {rows[0]['name']}" if n == 1 else f'有 {count_text(n, noun)}'
        text = f"订阅 {sub} {subject}使用 {label}，标准支持{when_text(end, run.now)}"
        confirm = None
        if ext and end < run.now and family in ('mysql', 'postgres') and entry.get('extendedPaid'):
            text += f"，已自动进入付费的延长支持（到 {ext.date()}），在升级前会持续产生额外费用"
        elif ext and end < run.now and family == 'os':
            if ext < run.now:
                text += f"，延长安全更新也已于 {ext.date()} 结束"
            else:
                # Windows Server ESU is free on Azure VMs, Debian LTS is free; Ubuntu Pro, RHEL ELS and SLES LTSS are bought
                free = '在 Azure 上可免费获得的' if product == 'os-windows-server' else '可免费获得的'
                text += f"，{'可购买的' if entry.get('extendedPaid') else free}延长安全更新到 {ext.date()}"
                confirm = '确认这些机器是否已启用延长安全更新（如 Windows Server ESU 或 Ubuntu Pro）。'
        text += '。'
        envs = [run.env(sub, r['name'], r.get('tags'), r.get('resourceGroup')) for r in rows]
        run.add('R9', sev, rows[0]['id'] if n == 1 else None, rows[0]['type'], rows[0]['name'] if n == 1 else f'{n} 个资源',
                envs[0] if n == 1 else _mixed(envs), text,
                {'calendar': {k: entry.get(k) for k in ('label', 'end', 'extendedEnd', 'source', 'checkedAt')},
                 'resources': [{k: r[k] for k in ('name', 'type', 'resourceGroup', 'setting')} for r in rows]},
                FAMILY_REC['os' if family == 'os' else 'runtime' if family == 'runtime' else family], confirm, sub=sub,
                rg=rows[0]['resourceGroup'] if n == 1 else None, members=[member(r['name'], r['type'], sub) for r in rows],
                key=f'lifecycle|{product}|{version}|{sub}' + ('|vmss' if rows[0]['type'] == VMSS_TYPE else ''))
    unjudged = Counter((x['reason'], x['type']) for x in out['notJudged'])
    if unjudged:
        phrase = {'未识别操作系统版本': '未识别操作系统版本', '未取得运行时版本': '未取得运行时版本'}
        parts = [count_text(n, type_label(t)) + phrase.get(reason, '的系统版本不在支持日历中' if t in (VM_TYPE, VMSS_TYPE) else '的版本不在支持日历中')
                 for (reason, t), n in sorted(unjudged.items(), key=lambda kv: -kv[1])]
        run.coverage['R9'].setdefault('limits', []).append('、'.join(parts) + '，这些资源没有判断是否到期。')


def _mixed(envs):
    from ..common import mixed_env
    return mixed_env(envs)


def _app_gateway(run, out, member):
    unread = 0
    for gw in run.rows('appgw'):
        sub = run.subname(gw['id'])
        for c in (gw.get('properties') or {}).get('sslCertificates') or []:
            p = c.get('properties') or {}
            got = cert_expiry(p['publicCertData']) if isinstance(p.get('publicCertData'), str) and p['publicCertData'] else None
            if got is None:
                unread += 1
                continue
            exp, subject = got
            days = (exp - run.now).days
            name = f"{gw['name']}/{c.get('name')}"
            out['versions'].append({'name': name, 'type': APPGW_TYPE, 'subscription': sub, 'setting': subject, 'product': 'certificate',
                                    'version': exp.date().isoformat()})
            if days >= CERT_WARN_DAYS:
                continue
            sev = '高' if days < 0 else '中'
            when = f'已于 {exp.date()} 过期（已过期 {-days} 天）' if days < 0 else f'将于 {exp.date()} 过期（还有 {days} 天）'
            run.add('R9', sev, gw['id'], APPGW_TYPE, name, run.env(sub, gw['name'], gw.get('tags'), gw.get('resourceGroup')),
                    f"应用网关 {gw['name']} 上的证书 {c.get('name')}（{subject}）{when}，到期后使用该证书的监听器会出现证书错误。",
                    {'certificate': c.get('name'), 'subject': subject, 'notAfter': exp.isoformat(), 'keyVaultReference': bool(p.get('keyVaultSecretId'))},
                    '续期证书并更新到应用网关（建议改为引用 Key Vault 中的证书并开启自动轮换）；确认没有监听器仍在使用旧证书。', None,
                    key=f"appgw-cert|{gw['id']}|{c.get('name')}")
    if unread:
        run.coverage['R9']['notes'].append(f'{unread} 个应用网关证书未取得到期日期（接口没有返回公钥证书数据，常见于引用 Key Vault 的证书）。')


def _retirements(run, out, member, limits):
    events = defaultdict(lambda: {'subs': set()})
    for e in run.rows('retirements'):
        ev = events[e.get('trackingId') or e.get('id')]
        ev.update({k: e.get(k) for k in ('trackingId', 'title', 'summary', 'status', 'retirementDate') if e.get(k)})
        ev['subs'].add(run.subname(e.get('subscriptionId') or ''))
    impacted = defaultdict(dict)
    for r in run.rows('retirement_resources') + run.rows('retirement_advisor'):
        rid = r.get('targetResourceId') or r.get('resourceId')
        if rid and r.get('trackingId'):
            impacted[r['trackingId']][rid.lower()] = r.get('targetResourceType') or '/'.join(rid.split('/providers/')[-1].split('/')[:2])
    advisor_names = {m['name'].lower() for f in run.findings.items if f['check'] == 'R9' and 'advisorProblem' in (f.get('evidence') or {})
                     for m in f.get('members') or [] if m.get('name')}
    unlinked = []
    for tid, ev in sorted(events.items(), key=lambda kv: (parse_date(kv[1].get('retirementDate')) or run.now, kv[0])):
        date = parse_date(ev.get('retirementDate'))
        res = impacted.get(tid) or {}
        record = {'trackingId': tid, 'title': ev.get('title'), 'retirementDate': ev.get('retirementDate'), 'status': ev.get('status'),
                  'subscriptions': sorted(s for s in ev['subs'] if s), 'impactedResources': len(res)}
        out['retirements'].append(record)
        sev = grade(date, run.now) if date else '低'
        if sev is None or str(ev.get('status') or 'Active').lower() not in ('active', ''):
            continue
        if not res:
            unlinked.append(record)
            continue
        names = {rid.rsplit('/', 1)[-1] for rid in res}
        if names <= advisor_names:
            run.coverage['R9']['notes'].append(f"退役公告 {tid} 涉及的资源已由 Advisor 退役建议列出，不重复列出。")
            continue
        kinds = '、'.join(count_text(v, k) for k, v in Counter(type_label(t) for t in res.values()).most_common())
        subs = sorted({run.subname(rid) for rid in res})
        days = (date - run.now).days if date else None
        when = '退役日期未取得' if date is None else f'已于 {date.date()} 退役' if days < 0 else f'将于 {date.date()} 退役（还有 {days} 天）'
        run.add('R9', sev, None, next(iter(res.values())), f'{len(res)} 个资源',
                _mixed([run.env(run.subname(rid), rid.rsplit('/', 1)[-1]) for rid in res]),
                f"微软服务退役公告（跟踪 ID {tid}）：{ev.get('title')}。{when}；本租户 {len(res)} 个资源受影响（{kinds}）。",
                {'notice': record, 'resources': sorted(res)},
                f'按公告中的迁移指引在退役日期前完成迁移；公告全文可在 Azure 门户“服务运行状况 > 健康公告”中按跟踪 ID {tid} 查看。', None,
                sub='、'.join(subs[:3]) + (' 等' if len(subs) > 3 else ''), rg=None,
                members=[member(rid.rsplit('/', 1)[-1], t, run.subname(rid)) for rid, t in sorted(res.items())], key=f'retirement|{tid}')
    if unlinked:
        lines = '；'.join(f"{x['title']}（{(x['retirementDate'] or '')[:10] or '日期未取得'}）" for x in unlinked[:5])
        run.add('R9', '低', None, '多种', f'{len(unlinked)} 条退役公告', None,
                f"另有 {len(unlinked)} 条涉及本租户订阅的微软退役公告未能关联到具体资源，例如：{lines}{' 等' if len(unlinked) > 5 else ''}。",
                {'notices': unlinked}, '在 Azure 门户“服务运行状况 > 健康公告”中按跟踪 ID 查看公告，确认是否在使用相关服务或功能。',
                '确认这些服务或功能是否在使用。', sub='多个订阅', rg=None, members=[], key='retirement|unlinked')
    if events:
        limits.append('微软退役公告的受影响资源只覆盖部分服务，且公告发布后最长约两周才会出现；未关联到资源的公告单独列出。')
