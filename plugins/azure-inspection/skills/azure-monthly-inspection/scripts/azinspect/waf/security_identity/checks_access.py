"""S-I4 Defender for Cloud, S-I5 privileged role assignments, S-I6 credential lifetime of privileged service principals."""
from __future__ import annotations

from collections import defaultdict

from ..common import mixed_env
from .collect import ROLE_IDS
from .context import SHARED_ACCOUNT, is_prod, is_test, member, parse_dt, subscription_members

NO_CHANGE = '本次未做任何更改。'
KEY_PLANS = ['VirtualMachines', 'Containers', 'SqlServers', 'SqlServerVirtualMachines', 'OpenSourceRelationalDatabases', 'StorageAccounts',
             'KeyVaults', 'Arm', 'CosmosDbs', 'AI', 'CloudPosture', 'AppServices', 'Api']
WORKLOAD_TYPES = (('vms', 'microsoft.compute/virtualmachines'), ('aks', 'microsoft.containerservice/managedclusters'),
                  ('postgresFlex', 'microsoft.dbforpostgresql/flexibleservers'), ('mysqlFlex', 'microsoft.dbformysql/flexibleservers'),
                  ('storage', 'microsoft.storage/storageaccounts'), ('keyVaults', 'microsoft.keyvault/vaults'),
                  ('cognitive', 'microsoft.cognitiveservices/accounts'), ('acr', 'microsoft.containerregistry/registries'))
OWNER_ASSESSMENT = 'A maximum of 3 owners should be designated for subscriptions'
SP_TYPE = 'Microsoft.Graph/servicePrincipals'
RA_TYPE = 'Microsoft.Authorization/roleAssignments'


def _many(n):
    return f'多个订阅（{n} 个）'


# ---------------------------------------------------------------------------------------------- S-I4
def _defender_row(ctx, sub, assessments, top):
    sid, calls = sub['id'], ctx.subcalls[sub['id']]
    pricing = ctx.pricing.get(sid)
    score = None
    for x in ((calls.get('secureScores') or {}).get('body') or {}).get('value', []):
        sc = (x.get('properties') or {}).get('score') or {}
        score = {'current': sc.get('current'), 'max': sc.get('max'), 'percentage': sc.get('percentage')}
    contacts = calls.get('securityContacts') or {}
    contact_values = (contacts.get('body') or {}).get('value', []) if contacts.get('body') else []
    provisioning = ((calls.get('autoProvisioning') or {}).get('body') or {}).get('value', [])
    items = assessments[sid].get('assessments')
    high = [x for x in (items or []) if x.get('status') == 'Unhealthy' and x.get('severity') == 'High']
    by_rec = defaultdict(set)
    for x in high:
        by_rec[x['displayName']].add((x.get('resourceId') or '').lower())
        top[x['displayName']]['subs'].add(sub['name'])
        top[x['displayName']]['resources'].add((x.get('resourceId') or '').lower())
    counts = ctx.type_counts.get(sid, {})
    paid = [k for k, v in (pricing or {}).items() if v['tier'] == 'Standard' and k not in ('Discovery', 'FoundationalCspm')]
    return {'subscription': sub['name'], 'environment': ctx.sub_env(sub['name']), 'pricingsHttp': (calls.get('pricings') or {}).get('http'),
            'registered': pricing is not None, 'plans': {k: (pricing.get(k) or {}).get('tier') for k in KEY_PLANS} if pricing else None,
            'standardWorkloadPlans': paid if pricing is not None else None, 'secureScore': score,
            'securityContactsConfigured': (len(contact_values) > 0) if contacts.get('http') == 200 else None,
            'autoProvisioning': [(x.get('name'), (x.get('properties') or {}).get('autoProvision')) for x in provisioning] or None,
            'assessmentsHttp': assessments[sid].get('http'), 'assessmentsTotal': len(items) if items is not None else None,
            'unhealthyHigh': len(high) if items is not None else None,
            'unhealthyHighTop': sorted([{'recommendation': k, 'affectedResources': len(v)} for k, v in by_rec.items()], key=lambda x: -x['affectedResources'])[:8],
            'workloadCounts': {k: counts.get(t, 0) for k, t in WORKLOAD_TYPES}}


def _brief(row):
    return {'subscription': row['subscription'], 'secureScore': row['secureScore'], 'unhealthyHigh': row['unhealthyHigh'],
            'workloadCounts': {k: v for k, v in row['workloadCounts'].items() if v}, 'top': row['unhealthyHighTop'][:4]}


def defender(ctx):
    assessments = {s['id']: (ctx.raw.load(f'defender/assessments_{s["id"]}.json') or {}) for s in ctx.enabled}
    top = defaultdict(lambda: {'subs': set(), 'resources': set()})
    matrix, no_reg, prod_off, unk_off, test_off = [], [], [], [], []
    for s in ctx.enabled:
        row = _defender_row(ctx, s, assessments, top)
        matrix.append(row)
        if not row['registered']:
            no_reg.append(row)
        elif not row['standardWorkloadPlans']:
            e = row['environment']
            (prod_off if is_prod(e) else test_off if is_test(e) else unk_off).append(row)

    def bucket(rows):
        return dict(environment=mixed_env([r['environment'] for r in rows]), members=subscription_members([r['subscription'] for r in rows]))

    rt = 'Microsoft.Security/pricings'
    if prod_off:
        with_high = [r for r in prod_off if (r['unhealthyHigh'] or 0) > 0]
        ctx.add('S-I4', '高' if with_high else '中', _many(len(prod_off)), None, None, rt,
                finding=f'{len(prod_off)} 个生产（推断）订阅的 Defender for Cloud 工作负载保护计划全部是免费层（仅基础 CSPM），其中 {len(with_high)} 个订阅共有 '
                        f'{sum(r["unhealthyHigh"] or 0 for r in prod_off)} 条高严重性未修复建议，VM、AKS、数据库和存储都没有威胁检测。',
                evidence={'subscriptions': [_brief(r) for r in prod_off]},
                recommendation='至少在生产订阅为实际承载的工作负载启用对应计划：有 AKS 的启用 Defender for Containers，有 VM 的启用 Defender for Servers P1，'
                               '有 PostgreSQL/MySQL 的启用开源关系数据库计划，并启用 Defender for Resource Manager；启用前用 Defender 成本估算评估费用，'
                               '并优先处理高严重性建议。' + NO_CHANGE,
                confirm='确认这些订阅承载的工作负载，以及启用 Defender 计划的预算。', key='defender-free-prod', **bucket(prod_off))
    if unk_off:
        ctx.add('S-I4', '中', _many(len(unk_off)), None, None, rt,
                finding=f'{len(unk_off)} 个环境不明的订阅 Defender 工作负载保护全部是免费层，共有 {sum(r["unhealthyHigh"] or 0 for r in unk_off)} 条高严重性未修复建议。',
                evidence={'subscriptions': [_brief(r) for r in unk_off]},
                recommendation='先确认这些订阅是否承载生产或敏感数据（如 AI 服务、客户数据）；如是，按生产标准启用对应 Defender 计划。' + NO_CHANGE,
                confirm='确认这些订阅是否承载生产或敏感数据。', key='defender-free-unknown', **bucket(unk_off))
    if test_off:
        ctx.add('S-I4', '低', _many(len(test_off)), None, None, rt,
                finding=f'{len(test_off)} 个测试/开发订阅 Defender 工作负载保护全部是免费层。',
                evidence={'subscriptions': [_brief(r) for r in test_off]},
                recommendation='测试环境可保持免费层，但建议处理高严重性建议，并确保测试环境与生产网络和凭据隔离。' + NO_CHANGE,
                key='defender-free-test', **bucket(test_off))
    if no_reg:
        ctx.add('S-I4', '中', _many(len(no_reg)), None, None, 'Microsoft.Security',
                finding=f'{len(no_reg)} 个订阅未注册 Microsoft.Security 资源提供程序，Defender for Cloud 对这些订阅没有任何安全评估和安全分数，'
                        f'这些订阅中共有 {sum(r["workloadCounts"]["cognitive"] for r in no_reg)} 个 AI/认知服务账户。',
                evidence={'subscriptions': [{'subscription': r['subscription'], 'pricingsHttp': r['pricingsHttp'],
                                             'workloadCounts': {k: v for k, v in r['workloadCounts'].items() if v}} for r in no_reg]},
                recommendation='在这些订阅注册 Microsoft.Security 资源提供程序（免费基础 CSPM 即可获得安全建议）；如承载生产 AI 服务，可评估启用 Defender for AI 服务。' + NO_CHANGE,
                confirm='确认这些订阅是否承载生产 AI 服务或敏感数据。', key='defender-not-registered', **bucket(no_reg))
    no_contact = [r for r in matrix if r['securityContactsConfigured'] is False]
    if no_contact:
        ctx.add('S-I4', '低', _many(len(no_contact)), None, None, 'Microsoft.Security/securityContacts',
                finding=f'{len(no_contact)} 个订阅都没有配置 Defender for Cloud 安全联系人和告警邮件通知，出现高危告警时没有人会收到邮件。',
                evidence={'subscriptions': [r['subscription'] for r in no_contact]},
                recommendation='为所有订阅配置安全联系人（运维/安全值班邮件组）并开启高严重性告警通知，可用 Azure Policy 批量配置。' + NO_CHANGE,
                key='security-contacts', **bucket(no_contact))
    zero = [r['subscription'] for r in matrix if r['registered'] and r['assessmentsTotal'] == 0]
    ctx.inventory['defenderMatrix'] = matrix
    ctx.inventory['defenderTopHighRecommendations'] = sorted(
        [{'recommendation': k, 'subscriptions': len(v['subs']), 'affectedResources': len(v['resources'])} for k, v in top.items()],
        key=lambda x: -x['affectedResources'])[:20]
    if no_reg:
        ctx.notes['S-I4'].append(f'{len(no_reg)} 个订阅未注册 Microsoft.Security（pricings 返回 {sorted({r["pricingsHttp"] for r in no_reg}, key=str)}），不是权限拒绝。')
    ctx.notes['S-I4'].append('安全评估按订阅用 ARM 列出 assessments。' + (f'已注册但评估数为 0 的订阅：{"、".join(zero)}（可能未完成评估或无适用资源，需确认）。' if zero else ''))
    return assessments


# ---------------------------------------------------------------------------------------------- S-I5
def _scope_level(scope, sid):
    s = scope.lower()
    if '/managementgroups/' in s:
        return 'managementGroup'
    if s == '/':
        return 'root'
    if s == f'/subscriptions/{sid}':
        return 'subscription'
    return 'resourceGroup' if s.count('/') == 4 else 'resource'


def roles(ctx, assessments):
    tenant = ctx.cfg.tenant_id.lower()
    inventory, root_owner, root_uaa, orphans, guests, app_priv = [], {}, {}, defaultdict(list), {}, {}
    custom_wild, classic = [], {}
    for s in ctx.enabled:
        sid, calls = s['id'], ctx.subcalls[s['id']]
        assignments = ((calls.get('roleAssignments') or {}).get('body') or {}).get('value')
        ch = calls.get('classicAdmins') or {}
        classic[s['name']] = {'http': ch.get('http'), 'count': len((ch.get('body') or {}).get('value', [])) if ch.get('http') == 200 else None,
                              'note': ch.get('error')}
        for rd in ((calls.get('customRoles') or {}).get('body') or {}).get('value') or []:
            actions = [a for pm in rd['properties'].get('permissions', []) for a in pm.get('actions', [])]
            if '*' in actions or any(a.strip() in ('*/write', '*/delete', 'Microsoft.Authorization/*') for a in actions):
                custom_wild.append({'subscription': s['name'], 'roleName': rd['properties'].get('roleName'), 'actions': actions[:20]})
        if assignments is None:
            inventory.append({'subscription': s['name'], 'http': (calls.get('roleAssignments') or {}).get('http'),
                              'error': (calls.get('roleAssignments') or {}).get('error')})
            continue
        counts, owners, direct_owner_users = {'total': len(assignments)}, set(), set()
        for ra in assignments:
            p = ra['properties']
            role = ROLE_IDS.get(p['roleDefinitionId'].rsplit('/', 1)[-1].lower())
            if not role:
                continue
            scope, pid = p['scope'], p['principalId']
            level = _scope_level(scope, sid)
            obj = ctx.gobj.get(pid)
            kind = 'Unknown(orphan)' if ctx.graph_ok and not obj else (p.get('principalType') or '?')
            if obj and obj.get('userType') == 'Guest':
                kind = 'GuestUser'
            counts[f'{role}|{level}|{kind}'] = counts.get(f'{role}|{level}|{kind}', 0) + 1
            if role == 'Owner' and level in ('managementGroup', 'root', 'subscription'):
                owners.add(pid)
                if level == 'subscription' and p.get('principalType') == 'User':
                    direct_owner_users.add(pid)
            if level in ('managementGroup', 'root'):
                if scope.lower().endswith('/' + tenant) or scope == '/':
                    if role == 'Owner':
                        root_owner.setdefault(pid, set()).add(scope)
                    elif role == 'User Access Administrator':
                        root_uaa.setdefault(pid, set()).add(scope)
                continue
            if ctx.graph_ok and not obj:
                orphans[sid].append({'role': role, 'scopeLevel': level, 'principalType': p.get('principalType'), 'principalIdPrefix': pid[:8]})
            if obj and obj.get('userType') == 'Guest':
                guests.setdefault(pid, []).append({'subscription': s['name'], 'role': role, 'scopeLevel': level})
            if obj and obj.get('type') == '#microsoft.graph.servicePrincipal' and obj.get('servicePrincipalType') == 'Application':
                app_priv.setdefault(pid, []).append({'subscription': s['name'], 'subscriptionId': sid, 'role': role, 'scopeLevel': level,
                                                     'scope': '/'.join(scope.split('/')[3:]) if level != 'subscription' else 'subscription'})
        e = ctx.sub_env(s['name'])
        inventory.append({'subscription': s['name'], 'environment': e, 'counts': counts,
                          'effectiveOwnerPrincipals': len(owners), 'directSubscriptionOwnerUsers': len(direct_owner_users)})
        if direct_owner_users and len(owners) > 3:   # Microsoft: at most 3 owners per subscription
            ctx.add('S-I5', '中' if is_prod(e) else '低', sid, None, s['name'], RA_TYPE, e,
                    finding=f'订阅 {s["name"]} 在订阅范围直接给 {len(direct_owner_users)} 个用户账户分配了 Owner，加上从管理组继承的 Owner 共有 {len(owners)} 个 Owner 主体，超过建议的 3 个。',
                    evidence={'directSubscriptionOwnerUsers': len(direct_owner_users), 'effectiveOwnerPrincipals': len(owners),
                              'defenderOwnerRecommendationUnhealthy': any(x.get('displayName') == OWNER_ASSESSMENT and x.get('status') == 'Unhealthy'
                                                                          for x in (assessments[sid].get('assessments') or []))},
                    recommendation='将日常运维账户降为 Contributor 或更细的角色；Owner 只保留给少数管理员，并通过 Entra 组 + PIM（按需激活）授予，不再给个人用户永久 Owner。' + NO_CHANGE,
                    confirm='确认这些用户是否都需要 Owner 权限。', key='subscription-owners', members=subscription_members([s['name']]))
    _root(ctx, root_owner, root_uaa)
    _guests(ctx, guests)
    for sid, items in orphans.items():
        name = ctx.name_of(sid)
        ctx.add('S-I5', '低', sid, None, name, RA_TYPE, ctx.sub_env(name),
                finding=f'订阅 {name} 有 {len(items)} 条特权角色分配指向已删除的主体（孤立分配，门户显示为 Unknown）。',
                evidence={'orphanedAssignments': items},
                recommendation='删除这些孤立角色分配，保持权限清单干净、便于审计。' + NO_CHANGE,
                key='orphaned-assignments', members=subscription_members([name]))
    _app_principals(ctx, app_priv)
    ctx.inventory.update(roleAssignments=inventory, customRolesWithWildcard=custom_wild, classicAdministrators=classic)
    resolved = len(ctx.gobj)
    ctx.notes['S-I5'].append(f'Graph directoryObjects/getByIds 请求 {ctx.graph.get("requestedIds", 0)} 个特权主体，解析 {resolved} 个，未解析的视为孤立分配。'
                             if ctx.graph_ok else 'Graph 目录对象读取失败，无法判断孤立分配和来宾账号。')
    classic_http = sorted({v['http'] for v in classic.values()}, key=str)
    ctx.notes['S-I5'].append(f'classicAdministrators API 返回 {classic_http}（经典管理员已于 2024 年退役）。')
    ctx.notes['S-I5'].append(f'未展开 Entra 组成员。包含 \'*\' 通配动作的自定义角色：{len(custom_wild)} 个。')
    return app_priv


def _root(ctx, root_owner, root_uaa):
    if not (root_owner or root_uaa):
        return
    shared = [ctx.gobj.get(p, {}).get('displayName') for p in root_owner]
    shared = [n for n in shared if n and SHARED_ACCOUNT.search(n)]
    kinds = sorted({(ctx.gobj.get(p) or {}).get('type', '').split('.')[-1] or '未解析' for p in list(root_owner) + list(root_uaa)})
    like = f'（其中有名称像共享账户的 {"、".join(repr(n) for n in shared)}）' if shared else ''
    ctx.add('S-I5', '高', f'租户根管理组（继承到全部 {len(ctx.enabled)} 个已启用订阅）', None, 'Tenant Root Group', 'Microsoft.Management/managementGroups',
            {'value': 'prod', 'label': '生产', 'basis': '根管理组覆盖所有订阅'},
            finding=f'租户根管理组直接给 {len(root_owner)} 个用户账户分配了 Owner{like}，另有 {len(root_uaa)} 个用户在根范围 \'/\' 持有 User Access Administrator'
                    '（通常是全局管理员“提升访问”后未撤销），这些账户可以控制全部订阅。',
            evidence={'rootMgOwnerCount': len(root_owner), 'sharedLikeOwnerNames': shared, 'rootScopeUserAccessAdministratorCount': len(root_uaa),
                      'principalTypes': kinds},
            recommendation='确认这些账户是否多人共用；共用账户应改为个人账户 + Entra 组授权并强制 MFA。根管理组 Owner 收敛到 2-3 个管理员/紧急账户并纳入 PIM；'
                           '全局管理员完成操作后撤销根范围 \'/\' 的提升访问。' + NO_CHANGE,
            confirm='确认这些账户的用途，以及是否多人共用。', key='root-management-group',
            members=[member('Tenant Root Group', 'Microsoft.Management/managementGroups')])


def _guests(ctx, guests):
    if not guests:
        return
    labeled = {f'来宾账号 {i}': v for i, v in enumerate(guests.values(), 1)}
    ctx.add('S-I5', '中', '多个订阅', None, f'{len(guests)} 个来宾账户', RA_TYPE, None,
            finding=f'{len(guests)} 个外部来宾（Guest）用户在 {len({x["subscription"] for v in guests.values() for x in v})} 个订阅持有 Contributor 等特权角色'
                    f'{"（未发现来宾持有 Owner）" if not any(x["role"] == "Owner" for v in guests.values() for x in v) else ""}。',
            evidence={'guests': labeled},
            recommendation='核实这些来宾是否仍需访问；需要的改为最小权限角色并纳入定期访问评审（Access Reviews），不需要的删除角色分配和来宾账户。' + NO_CHANGE,
            confirm='确认这些来宾是否仍需访问。', key='guests', members=[member(k, 'Microsoft.Graph/users#guest') for k in labeled])


def _app_principals(ctx, app_priv):
    creds = ctx.graph.get('spCredentials') or {}
    for pid, items in app_priv.items():
        obj, meta = ctx.gobj.get(pid) or {}, creds.get(pid) or {}
        owner_subs = sorted({x['subscription'] for x in items if x['role'] == 'Owner'})
        home = meta.get('homeTenant')
        if not (owner_subs or home is False):
            continue
        subs = sorted({x['subscription'] for x in items})
        prod_hit = [x['subscription'] for x in items if is_prod(ctx.sub_env(x['subscription']))]
        name = obj.get('displayName')
        if owner_subs:
            text = (f'服务主体 {name} 在 {len(owner_subs)} 个订阅持有 Owner（{"、".join(owner_subs)}），另有 {sum(1 for x in items if x["role"] == "Contributor")} 处 Contributor'
                    f'（共覆盖 {len(subs)} 个订阅），使用客户端密码认证，密码一旦泄露即可接管这些订阅并再授权他人。')
            rec = '将该服务主体的 Owner 降为 Contributor 或自定义最小角色，按用途拆分成多个专用服务主体，并改用工作负载身份联合（federated credentials）替代客户端密码。'
            confirm = '确认该服务主体的用途和需要的最小权限。'
        else:
            text = f'外部租户的第三方应用 {name} 持有 Contributor（{"、".join(sorted({x["subscription"] + ":" + x["scope"] for x in items}))}）。'
            rec = '确认该第三方应用的用途和授权范围，将权限限制在所需资源组，并纳入定期评审。'
            confirm = '确认该第三方应用的用途和授权范围。'
        ctx.add('S-I5', '中', _many(len(subs)) if len(subs) > 1 else items[0]['subscriptionId'], None, name, SP_TYPE,
                {'value': 'prod' if prod_hit else 'unknown', 'label': '生产' if prod_hit else '未知', 'basis': '所授权订阅的环境'},
                finding=text, recommendation=rec + NO_CHANGE, confirm=confirm, key=f'service-principal-{pid}',
                evidence={'assignments': [{k: x[k] for k in ('subscription', 'role', 'scopeLevel', 'scope')} for x in items], 'homeTenant': home},
                members=[member(name, SP_TYPE)])


# ---------------------------------------------------------------------------------------------- S-I6
CRED_SOURCES = (('spPasswordCredentials', 'spPwdCredentials'), ('spKeyCredentials', 'spKeyCredentials'),
                ('appPasswordCredentials', 'appPwdCredentials'), ('appKeyCredentials', 'appKeyCredentials'))


def _credentials(ctx, meta):
    out = []
    for label, stored in CRED_SOURCES:
        values = meta.get(stored) if isinstance(meta.get(stored), list) else meta.get(label)
        for c in values if isinstance(values, list) else []:
            start, end = parse_dt(c.get('startDateTime')), parse_dt(c.get('endDateTime'))
            status = None if not end else ('expired' if end < ctx.today else ('expiring<=60d' if (end - ctx.today).days <= 60 else 'valid'))
            out.append({'source': label, 'displayName': c.get('displayName'), 'startDateTime': c.get('startDateTime'),
                        'endDateTime': c.get('endDateTime'), 'status': status, 'lifetimeDays': (end - start).days if (start and end) else None})
    return out


def credentials(ctx, app_priv):
    inventory = []
    if not ctx.graph_ok:
        ctx.notes['S-I6'].append('Graph 目录读取失败，未检查服务主体凭据。')
        ctx.inventory['privilegedServicePrincipalCredentials'] = inventory
        return
    for pid, meta in (ctx.graph.get('spCredentials') or {}).items():
        if meta.get('servicePrincipalType') != 'Application':
            continue
        creds, items = _credentials(ctx, meta), app_priv.get(pid, [])
        inventory.append({'displayName': meta.get('displayName'), 'homeTenant': meta.get('homeTenant'), 'appRead': meta.get('appHttp'),
                          'privileged': [{k: x[k] for k in ('subscription', 'role', 'scopeLevel')} for x in items], 'credentials': creds})
        bad = [c for c in creds if c['status'] in ('expired', 'expiring<=60d') or (c['lifetimeDays'] or 0) > 732]
        if not bad:
            continue
        prod_hit = any(is_prod(ctx.sub_env(x['subscription'])) for x in items)
        subs = sorted({x['subscription'] for x in items})
        name = meta.get('displayName')
        expired = [c for c in bad if c['status'] == 'expired']
        expiring = [c for c in bad if c['status'] == 'expiring<=60d']
        long_lived = [c for c in bad if c['status'] not in ('expired', 'expiring<=60d')]
        ends = lambda cs: '、'.join(f'{c["source"]} 于 {(c["endDateTime"] or "")[:10]} 到期' for c in cs)  # noqa: E731
        parts, steps, confirm = [], [], []
        if expired:
            parts.append(f'{len(expired)} 个凭据已过期（{ends(expired)}）')
            steps.append('删除已过期的凭据（服务主体对象上的密码凭据通常不是应用注册里创建的，需确认来源）')
            confirm.append('过期凭据的来源，以及是否仍在使用')
        if expiring:
            parts.append(f'{len(expiring)} 个凭据将在 60 天内到期（{ends(expiring)}）')
            steps.append('到期前创建新凭据并更新使用方，确认切换后再删除旧凭据')
            confirm.append('即将到期的凭据由哪些系统使用')
        if long_lived:
            years = sorted({round(c['lifetimeDays'] / 365) for c in long_lived})
            span = f'{years[0]}' if len(years) == 1 else f'{years[0]}–{years[-1]}'
            parts.append(f'{len(long_lived)} 个凭据有效期长达约 {span} 年（{ends(long_lived)}），长期不轮换，泄露后可被长期使用')
            steps.append('为长期有效的密码凭据创建有效期较短的新凭据，使用方切换后删除旧凭据')
            confirm.append('长期凭据由哪些系统使用，轮换时需要同步更新哪里')
        valid = [c for c in creds if c['status'] == 'valid']
        replacement = f'目前有 {len(valid)} 个未过期的凭据；' if expired or expiring else ''
        ctx.add('S-I6', '中' if prod_hit and expiring else '低',
                _many(len(subs)) if len(subs) > 1 else (items[0]['subscriptionId'] if items else None), None, name, SP_TYPE,
                {'value': 'prod' if prod_hit else 'unknown', 'label': '生产' if prod_hit else '未知', 'basis': '所授权订阅的环境'},
                finding=f'服务主体 {name}：' + '；'.join(parts) + f'。{replacement}该主体持有 {len(items)} 条特权角色分配。',
                evidence={'credentials': creds, 'privilegedAssignments': len(items)},
                recommendation='；'.join(steps) + '；保留的密码凭据按 6-12 个月轮换并存入 Key Vault，优先改用证书或工作负载身份联合。' + NO_CHANGE,
                confirm='确认' + '；'.join(confirm) + '。', key=f'credentials-{pid}', members=[member(name, SP_TYPE)])
    ctx.inventory['privilegedServicePrincipalCredentials'] = inventory
    ctx.notes['S-I6'].append('只读取持有特权角色的应用型服务主体及其应用注册的凭据元数据（名称、开始和到期时间）；托管身份由平台自动轮换，不纳入。')
