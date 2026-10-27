"""customer.yaml: everything that differs between customers lives here, never in the scripts."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

GUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
FILE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$')
ENVIRONMENTS = {'prod': '生产', 'test': '测试', 'dev': '开发', 'dr': '灾备', 'unknown': '未知'}


class ConfigError(ValueError):
    pass


@dataclass
class Rule:
    label: str
    pattern: re.Pattern
    applies_to: str = 'any'   # any | subscription | resource (environment rules only)


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
    extra_risky_ports: dict = field(default_factory=dict)
    public_storage_names: str | None = None
    currency: str = 'USD'
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

    def vendor(self, resource_name: str = '', resource_group: str = '') -> str | None:
        for rule in self.vendor_managed:
            if any(t and rule.pattern.search(t) for t in (resource_name, resource_group)):
                return rule.label
        return None

    def region(self, location: str) -> str:
        return self.region_labels.get((location or '').lower(), location)

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
    ports = {}
    for port, label in (rules.get('extraRiskyPorts') or {}).items():
        if not str(port).isdigit() or not 0 < int(port) < 65536:
            errors.append(f'rules.extraRiskyPorts 的端口 {port} 无效')
        else:
            ports[int(port)] = str(label)
    public_storage = _pattern(rules.get('publicStorageAccounts'), 'rules.publicStorageAccounts', errors)
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
        vendor_managed=_rules(rules.get('vendorManaged'), 'rules.vendorManaged'), stateful_vm_names=stateful, extra_risky_ports=ports,
        public_storage_names=public_storage,
        currency=str(report.get('currency') or 'USD'), path=path)
