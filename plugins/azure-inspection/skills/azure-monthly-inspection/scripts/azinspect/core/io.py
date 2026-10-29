"""Customer workspace layout and safe file writes.

<workspace>/customer.yaml
<workspace>/access/                 access check results
<workspace>/<YYYY-MM>/raw/          sanitized API responses
<workspace>/<YYYY-MM>/findings/     analysis results (findings.json per area)
<workspace>/<YYYY-MM>/narrative/    text written by the agent (one JSON per report)
<workspace>/<YYYY-MM>/reports/      generated Markdown, Excel, charts
<workspace>/<YYYY-MM>/package/      the folder handed to the customer, plus the zip
<workspace>/state/issues.json       issue tracking across months
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

_SECRET_KEY = re.compile(r'(password|secret|connectionstring|connection_string|accesskey|primarykey|secondarykey|'
                         r'sastoken|sasurl|accesstoken|refreshtoken|^token$|kubeconfig|privatekey|clientsecret|'
                         r'sharedkey|authkey|^keys?$|^sig$|keydata|publickeys|customdata|^hint$)', re.I)
# Graph passwordCredentials/keyCredentials lists hold expiry metadata, not secrets: keep the list and sanitize
# each entry (secretText, hint and key are still removed by the key rules above).
_CREDENTIAL_METADATA = re.compile(r'^(password|key)credentials$', re.I)
# Feature switches whose names contain 'secret' (e.g. the AKS add-on azureKeyvaultSecretsProvider): settings, not secrets.
_FEATURE_KEY = re.compile(r'(secretsprovider|secretrotation)', re.I)
_SECRET_VALUE = re.compile(r'(AccountKey=|SharedAccessSignature|[?&]sig=|SharedAccessKey=|-----BEGIN|Password=|eyJ[A-Za-z0-9_-]{20,}\.)', re.I)
_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
# Contact fields only (phoneNumber, mobilePhone, businessPhones, smsReceivers), not names that merely contain 'phone'.
_PHONE_KEY = re.compile(r'(phone(number)?s?|^mobile(phone|number)?s?|^sms\w*)$', re.I)
# Key Vault access policies list permission names per object type ({'keys': ['get', 'list'], 'secrets': ['all']}):
# names, not secrets. Only lists of plain words are kept; anything else still goes through the key rules.
_PERMISSION_NAME = re.compile(r'[A-Za-z]{1,40}')
_PERMISSION_TYPES = {'keys', 'secrets', 'certificates', 'storage'}
# Dictionaries keyed by resource ID (e.g. metrics results): such a key is data, not a field name, so the key
# rules do not apply to it; its value is still sanitized.
_RESOURCE_ID_KEY = re.compile(r'^/subscriptions/', re.I)


def _permission_names(key, value) -> bool:
    return key.lower() == 'permissions' and isinstance(value, dict) and all(
        str(k).lower() in _PERMISSION_TYPES and isinstance(v, list) and all(isinstance(x, str) and _PERMISSION_NAME.fullmatch(x) for x in v)
        for k, v in value.items())


def sanitize(obj, keep_emails: bool = False):
    """Drop secrets, tokens, e-mail addresses and phone numbers before anything is written to disk."""
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            field = isinstance(key, str) and not _RESOURCE_ID_KEY.match(key)
            if field and _permission_names(key, value):
                out[key] = {k: list(v) for k, v in value.items()}
                continue
            credential_list = field and ((_CREDENTIAL_METADATA.match(key) and isinstance(value, list))
                                         or (_FEATURE_KEY.search(key) and isinstance(value, dict)))
            if field and value is not None and not isinstance(value, (bool, int, float)) and not credential_list \
                    and (_SECRET_KEY.search(key) or _PHONE_KEY.search(key)):
                out[key] = '[REDACTED]'
            else:
                out[key] = sanitize(value, keep_emails)
        return out
    if isinstance(obj, list):
        return [sanitize(x, keep_emails) for x in obj]
    if isinstance(obj, str):
        if _SECRET_VALUE.search(obj):
            return '[REDACTED]'
        return obj if keep_emails else _EMAIL.sub('[email]', obj)
    return obj


def write_json(path: Path, obj) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1, default=str), encoding='utf-8')
    os.replace(tmp, path)
    return path


def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


class Workspace:
    def __init__(self, root: str | Path, month: str | None = None):
        self.root = Path(root).resolve()
        self.month = month

    @property
    def config_path(self) -> Path:
        return self.root / 'customer.yaml'

    @property
    def access_dir(self) -> Path:
        return self.root / 'access'

    @property
    def state_dir(self) -> Path:
        return self.root / 'state'

    def month_dir(self, part: str = '') -> Path:
        if not self.month:
            raise ValueError('需要指定月份（--month YYYY-MM）')
        return self.root / self.month / part if part else self.root / self.month

    def raw(self, rel: str) -> Path:
        return self.month_dir('raw') / rel

    def save_raw(self, rel: str, obj) -> Path:
        return write_json(self.raw(rel), sanitize(obj))

    def create(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for d in (self.access_dir, self.state_dir):
            d.mkdir(exist_ok=True)
        if self.month:
            for part in ('raw', 'findings', 'narrative', 'reports', 'package'):
                self.month_dir(part).mkdir(parents=True, exist_ok=True)

    def save_calls(self, stage: str, calls: list[dict]) -> Path:
        """Per-stage call log used for coverage ("读取了多少、成功多少、无权限多少")."""
        base = self.month_dir('raw') if self.month else self.access_dir
        return write_json(base / '_calls' / f'{stage}.json', {'stage': stage, 'count': len(calls), 'calls': calls})
