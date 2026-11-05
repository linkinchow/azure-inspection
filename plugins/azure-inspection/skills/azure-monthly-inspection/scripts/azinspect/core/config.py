"""customer.yaml: everything that differs between customers lives here, never in the scripts."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

GUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
FILE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$')
REPORTS = ('01', '02', '03', '04', '05')   # optional reports; 00 always summarises the chosen ones
GROUPS = {'可靠性': '03', '安全': '03', '卓越运营': '04', '性能效率': '04'}   # WAF pillars of 03/04, each can be chosen alone
ENVIRONMENTS = {'prod': '生产', 'test': '测试', 'dev': '开发', 'dr': '灾备', 'unknown': '未知'}


class ConfigError(ValueError):
    pass


@dataclass
class Rule:
    label: str
    pattern: re.Pattern
    applies_to: str = 'any'   # any | subscription | resource (environment rules only)


# Chinese names for common public regions; customer.yaml regionLabels overrides or adds to these.
REGION_LABELS = {
    'eastasia': '中国香港', 'southeastasia': '新加坡', 'japaneast': '日本东部', 'japanwest': '日本西部', 'koreacentral': '韩国中部',
    'koreasouth': '韩国南部', 'centralindia': '印度中部', 'southindia': '印度南部', 'westindia': '印度西部', 'indonesiacentral': '印度尼西亚中部',
    'malaysiawest': '马来西亚西部', 'australiaeast': '澳大利亚东部', 'australiasoutheast': '澳大利亚东南部', 'newzealandnorth': '新西兰北部',
    'uaenorth': '阿联酋北部', 'uaecentral': '阿联酋中部', 'qatarcentral': '卡塔尔中部', 'israelcentral': '以色列中部',
    'saudiarabiaeast': '沙特阿拉伯东部', 'southafricanorth': '南非北部', 'westeurope': '西欧', 'northeurope': '北欧',
    'uksouth': '英国南部', 'ukwest': '英国西部', 'francecentral': '法国中部', 'germanywestcentral': '德国中西部',
    'swedencentral': '瑞典中部', 'switzerlandnorth': '瑞士北部', 'norwayeast': '挪威东部', 'polandcentral': '波兰中部',
    'italynorth': '意大利北部', 'spaincentral': '西班牙中部', 'eastus': '美国东部', 'eastus2': '美国东部 2', 'centralus': '美国中部',
    'northcentralus': '美国中北部', 'southcentralus': '美国中南部', 'westcentralus': '美国中西部', 'westus': '美国西部',
    'westus2': '美国西部 2', 'westus3': '美国西部 3', 'canadacentral': '加拿大中部', 'canadaeast': '加拿大东部',
    'brazilsouth': '巴西南部', 'mexicocentral': '墨西哥中部', 'chinaeast2': '中国东部 2', 'chinaeast3': '中国东部 3',
    'chinanorth2': '中国北部 2', 'chinanorth3': '中国北部 3',
}
# Cost Management names locations by area code and direction ('JA East', 'US East 2', 'EU West'): the country part
# of the region name, before or after the direction
BILLING_AREAS = {'us': 'us', 'eu': 'europe', 'ap': 'asia', 'in': 'india', 'my': 'malaysia', 'ja': 'japan', 'jp': 'japan',
                 'au': 'australia', 'uk': 'uk', 'ae': 'uae', 'kr': 'korea', 'ca': 'canada', 'br': 'brazil', 'de': 'germany',
                 'fr': 'france', 'se': 'sweden', 'ch': 'switzerland', 'no': 'norway', 'za': 'southafrica', 'qa': 'qatar',
                 'il': 'israel', 'pl': 'poland', 'it': 'italy', 'es': 'spain', 'mx': 'mexico', 'nz': 'newzealand',
                 'id': 'indonesia', 'sa': 'saudiarabia', 'cn': 'china'}


def region_key(location) -> str:
    """The region name ('japaneast') of a location given as a region name or as Cost Management's ('JA East')."""
    words = str(location or '').lower().split()
    key = ''.join(words)
    if key in REGION_LABELS or len(words) < 2 or words[0] not in BILLING_AREAS:
        return key
    area, rest = BILLING_AREAS[words[0]], words[1:]
    number = rest.pop() if rest[-1].isdigit() else ''
    for candidate in (''.join(rest) + area + number, area + ''.join(rest) + number):
        if candidate in REGION_LABELS:
            return candidate
    return key


def region_name(location) -> str:
    """Chinese name of a region, else the location as given."""
    return REGION_LABELS.get(region_key(location), location)


@dataclass
class CustomerConfig:
    name: str
    file_name: str
    tenant_id: str
    readonly_account: str
    token_subscription: str
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    business_lines: list[Rule] = field(default_factory=list)
    environments: list[Rule] = field(default_factory=list)
    environment_tag_keys: list[str] = field(default_factory=lambda: ['environment', 'env'])
    region_labels: dict[str, str] = field(default_factory=dict)
    standard_tag: dict[str, str] = field(default_factory=dict)
    vendor_managed: list[Rule] = field(default_factory=list)
    stateful_vm_names: str | None = None
    network_appliance_names: str | None = None   # customer name rule for appliances on custom images
    extra_risky_ports: dict = field(default_factory=dict)
    public_storage_names: str | None = None
    managed_lustre: dict = field(default_factory=dict)
    currency: str = 'USD'
    vm_detail_max_rows: int = 500   # 02 Markdown attaches the per-machine table up to this many machines
    reports: tuple = REPORTS        # report.include: the reports this customer gets
    groups: tuple = tuple(GROUPS)   # the pillars of 03/04 they get ('03' in report.include = 可靠性 and 安全)
    path: Path | None = None

    # ---------------------------------------------------------------- scope
    def in_scope(self, subscription_id: str, subscription_name: str) -> bool:
        def hit(patterns):
            return any(p.lower() == subscription_id.lower() or fnmatch.fnmatch(subscription_name.lower(), p.lower()) for p in patterns)
        if self.include and not hit(self.include):
            return False
        return not hit(self.exclude)

    # ---------------------------------------------------------------- inference
    def environment(self, subscription_name: str = '', resource_name: str = '', tags: dict | None = None) -> tuple[str, str]:
        """Returns (env code, basis). Tag first, then resource name, then subscription name; unknown otherwise."""
        for key, value in (tags or {}).items():
            if key.lower() in self.environment_tag_keys and value:
                for rule in self.environments:
                    if rule.applies_to != 'subscription' and rule.pattern.search(str(value)):
                        return rule.label, f'标签 {key}={value}'
        for source, text, scope in (('资源名称', resource_name, 'resource'), ('订阅名称', subscription_name, 'subscription')):
            for rule in self.environments:
                if text and rule.applies_to in ('any', scope) and rule.pattern.search(text):
                    return rule.label, f'{source}'
        return 'unknown', '无法判断'

    def business_line(self, subscription_name: str = '', resource_group: str = '', resource_name: str = '') -> str | None:
        for rule in self.business_lines:
            if any(t and rule.pattern.search(t) for t in (subscription_name, resource_group, resource_name)):
                return rule.label
        return None

    def appliance_names(self):
        """Compiled customer name rule for network appliances, or None."""
        return re.compile(self.network_appliance_names, re.I) if self.network_appliance_names else None

    def vendor(self, resource_name: str = '', resource_group: str = '') -> str | None:
        for rule in self.vendor_managed:
            if any(t and rule.pattern.search(t) for t in (resource_name, resource_group)):
                return rule.label
        return None

    def region(self, location: str) -> str:
        key = (location or '').lower()
        return self.region_labels.get(key) or self.region_labels.get(region_key(location)) or region_name(location)

    def created_by_standard(self, tags: dict | None) -> bool | None:
        if not self.standard_tag:
            return None
        # tag keys are written inconsistently (managed_by, managedBy, Managed-By): compare without case, '_' and '-'
        norm = lambda text: re.sub(r'[_\-\s]', '', str(text)).lower()
        key, value = norm(self.standard_tag.get('key', '')), str(self.standard_tag.get('value', '')).lower()
        return any(norm(k) == key and str(v).lower() == value for k, v in (tags or {}).items())


def _rules(items, what: str) -> list[Rule]:
    out = []
    for i, item in enumerate(items or []):
        if not isinstance(item, dict) or 'label' not in item or 'match' not in item:
            raise ConfigError(f'{what}[{i}] 需要 label 和 match 两个字段')
        applies_to = str(item.get('appliesTo') or 'any')
        if applies_to not in ('any', 'subscription', 'resource'):
            raise ConfigError(f'{what}[{i}] 的 appliesTo 只能是 any、subscription 或 resource')
        try:
            out.append(Rule(str(item['label']), re.compile(str(item['match']), re.I), applies_to))
        except re.error as e:
            raise ConfigError(f'{what}[{i}] 的 match 不是有效的正则表达式：{e}') from e
    return out


def _pattern(value, what: str, errors: list) -> str | None:
    if not value:
        return None
    try:
        re.compile(str(value))
    except re.error as e:
        errors.append(f'{what} 不是有效的正则表达式：{e}')
    return str(value)


def load(path: str | Path) -> CustomerConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f'找不到 {path}。先运行 init 生成模板并填写。')
    raw = yaml.safe_load(path.read_text(encoding='utf-8')) or {}
    customer, access = raw.get('customer') or {}, raw.get('access') or {}
    scope, rules, report = raw.get('scope') or {}, raw.get('rules') or {}, raw.get('report') or {}
    errors = []
    if not str(customer.get('name') or '').strip():
        errors.append('customer.name 不能为空')
    if not FILE_NAME.match(str(customer.get('fileName') or '')):
        errors.append('customer.fileName 只能用字母、数字、- 和 _（用于文件名）')
    for key in ('tenantId', 'tokenSubscription'):
        if not GUID.match(str(access.get(key) or '')):
            errors.append(f'access.{key} 必须是 GUID')
    if not str(access.get('readonlyAccount') or '').strip():
        errors.append('access.readonlyAccount 不能为空（只读账号的 UPN，或服务主体的 appId）')
    envs = _rules(rules.get('environments'), 'rules.environments')
    if any(r.label not in ENVIRONMENTS for r in envs):
        errors.append('rules.environments 的 label 只能是 ' + '、'.join(ENVIRONMENTS))
    stateful = _pattern(rules.get('statefulVmNames'), 'rules.statefulVmNames', errors)
    appliances = _pattern(rules.get('networkAppliances'), 'rules.networkAppliances', errors)
    ports = {}
    for port, label in (rules.get('extraRiskyPorts') or {}).items():
        if not str(port).isdigit() or not 0 < int(port) < 65536:
            errors.append(f'rules.extraRiskyPorts 的端口 {port} 无效')
        else:
            ports[int(port)] = str(label)
    public_storage = _pattern(rules.get('publicStorageAccounts'), 'rules.publicStorageAccounts', errors)
    from .lustre import DEFAULT_POLICY, number
    managed_lustre = rules.get('managedLustre', {})
    if not isinstance(managed_lustre, dict):
        errors.append('rules.managedLustre 必须是配置字典')
        managed_lustre = {}
    unknown = set(managed_lustre) - set(DEFAULT_POLICY)
    if unknown:
        errors.append('rules.managedLustre 不支持：' + '、'.join(sorted(unknown)))
    lustre_policy = {**DEFAULT_POLICY, **managed_lustre}
    for key in ('warningPct', 'criticalPct', 'minCoveragePct'):
        if not number(lustre_policy[key]) or not 0 < lustre_policy[key] <= 100:
            errors.append(f'rules.managedLustre.{key} 必须大于 0 且不超过 100')
    if all(number(lustre_policy[key]) for key in ('warningPct', 'criticalPct')) and lustre_policy['warningPct'] >= lustre_policy['criticalPct']:
        errors.append('rules.managedLustre.warningPct 必须小于 criticalPct')
    if type(lustre_policy['sustainedHours']) is not int or not 1 <= lustre_policy['sustainedHours'] <= 720:
        errors.append('rules.managedLustre.sustainedHours 必须是 1–720 的整数')
    for key in ('requireRootSquash', 'requireCmk'):
        if not isinstance(lustre_policy[key], bool):
            errors.append(f'rules.managedLustre.{key} 必须是 true 或 false')
    detail_rows = report.get('vmDetailMaxRows', 500)
    if isinstance(detail_rows, bool) or not isinstance(detail_rows, int) or detail_rows < 0:
        errors.append('report.vmDetailMaxRows 必须是不小于 0 的整数')
    chosen = report.get('include')
    if chosen is None:
        chosen = list(REPORTS)
    chosen = [str(x).strip() if str(x).strip() in GROUPS else str(x).strip().zfill(2) for x in chosen] if isinstance(chosen, list) else None
    if not chosen or any(x not in REPORTS and x not in GROUPS for x in chosen):
        errors.append('report.include 是要做的报告编号或支柱列表，可选 ' + '、'.join(REPORTS) + ' 或 ' + '、'.join(GROUPS)
                      + "，例如 ['01', '03'] 或 ['可靠性']；不写等于全部")
        chosen = []
    # a report number means all its pillars; a pillar name means its report with that pillar only
    groups = tuple(g for g, code in GROUPS.items() if g in chosen or code in chosen)
    if errors:
        raise ConfigError('customer.yaml 有误：\n- ' + '\n- '.join(errors))
    return CustomerConfig(
        name=str(customer['name']).strip(), file_name=str(customer['fileName']),
        tenant_id=str(access['tenantId']).lower(), readonly_account=str(access['readonlyAccount']).strip(),
        token_subscription=str(access['tokenSubscription']).lower(),
        include=[str(x) for x in scope.get('includeSubscriptions') or []],
        exclude=[str(x) for x in scope.get('excludeSubscriptions') or []],
        business_lines=_rules(rules.get('businessLines'), 'rules.businessLines'),
        environments=envs,
        environment_tag_keys=[k.lower() for k in rules.get('environmentTagKeys') or ['environment', 'env']],
        region_labels={str(k).lower(): str(v) for k, v in (rules.get('regionLabels') or {}).items()},
        standard_tag=dict(rules.get('standardDeploymentTag') or {}),
        vendor_managed=_rules(rules.get('vendorManaged'), 'rules.vendorManaged'), stateful_vm_names=stateful, network_appliance_names=appliances, extra_risky_ports=ports,
        public_storage_names=public_storage, managed_lustre=managed_lustre,
        currency=str(report.get('currency') or 'USD'), vm_detail_max_rows=detail_rows,
        reports=tuple(x for x in REPORTS if x in chosen or x in {GROUPS[g] for g in groups}), groups=groups, path=path)
