"""Access tokens for the customer's read-only account.

Rules enforced here (not left to the agent):
- The only Azure CLI command ever run is `az account get-access-token --subscription <id> --resource <aud>`.
  No login, logout, account set or config change: the user's default account is never touched.
- Every token is decoded and checked before use: account (upn / unique_name / appid), tenant,
  audience and expiry must match customer.yaml. A mismatch stops the run.
- Tokens stay in memory. They are never printed, logged or written to disk.
"""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import threading
import time

ARM = 'https://management.azure.com/'
GRAPH = 'https://graph.microsoft.com'
METRICS = 'https://metrics.monitor.azure.com'
LOG_ANALYTICS = 'https://api.loganalytics.io'

# Audience claim values Azure issues for each resource.
_AUD_ALIASES = {
    ARM: {'https://management.azure.com', 'https://management.core.windows.net'},
    GRAPH: {'https://graph.microsoft.com', '00000003-0000-0000-c000-000000000000'},
    METRICS: {'https://metrics.monitor.azure.com'},
    LOG_ANALYTICS: {'https://api.loganalytics.io'},
}


class IdentityMismatch(SystemExit):
    """Raised when a token does not belong to the configured read-only account; stops the run."""


def decode_claims(token: str) -> dict:
    part = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))


def check_claims(claims: dict, account: str, tenant: str, audience: str) -> None:
    who = {str(claims.get(k) or '').lower() for k in ('upn', 'unique_name', 'appid')} - {''}
    if account.lower() not in who:
        raise IdentityMismatch('令牌不属于 customer.yaml 中的只读账号，已停止。')
    if str(claims.get('tid', '')).lower() != tenant.lower():
        raise IdentityMismatch('令牌的租户与 customer.yaml 不一致，已停止。')
    if str(claims.get('aud', '')).rstrip('/') not in _AUD_ALIASES.get(audience, {audience.rstrip('/')}):
        raise IdentityMismatch('令牌的受众与请求的服务不一致，已停止。')
    if float(claims.get('exp', 0)) <= time.time():
        raise IdentityMismatch('令牌已过期，请重新登录只读账号后再运行。')


class TokenProvider:
    """Thread-safe token cache keyed by audience."""

    def __init__(self, account: str, tenant: str, subscription: str, runner=None):
        self.account, self.tenant, self.subscription = account, tenant, subscription
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._runner = runner or self._run_az

    @staticmethod
    def _run_az(subscription: str, audience: str) -> str:
        az = shutil.which('az') or shutil.which('az.cmd')
        if not az:
            raise SystemExit('找不到 Azure CLI（az），请先安装并用只读账号登录。')
        args = [az, 'account', 'get-access-token', '--subscription', subscription, '--resource', audience, '-o', 'json']
        assert args[1:3] == ['account', 'get-access-token'], 'only token acquisition is allowed'
        proc = subprocess.run(args, capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            # stderr may contain account details; do not echo it
            raise SystemExit('无法取得只读账号的令牌：请确认已用只读账号执行过 az login，且该账号能访问 tokenSubscription。')
        return json.loads(proc.stdout)['accessToken']

    def get(self, audience: str = ARM) -> str:
        with self._lock:
            cached = self._cache.get(audience)
            if cached and cached[1] - time.time() > 300:
                return cached[0]
            token = self._runner(self.subscription, audience)
            claims = decode_claims(token)
            check_claims(claims, self.account, self.tenant, audience)
            self._cache[audience] = (token, float(claims['exp']))
            return token

    def identity(self) -> dict:
        """Non-secret facts about the ARM token, for the access check report."""
        claims = decode_claims(self.get(ARM))
        return {'account': claims.get('upn') or claims.get('unique_name') or claims.get('appid'),
                'objectId': claims.get('oid'), 'tenant': claims.get('tid'), 'expiresAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(float(claims['exp'])))}
