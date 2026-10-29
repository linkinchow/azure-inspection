"""Reuse of saved read results for `collect --resume`.

Large tenants need many hours for the cost collection; a restart or sleep used to mean starting again. With --resume a
saved result is reused only when all of these hold, otherwise the read runs again:
- the same request: a signature over the collector version, query kind, URL and body (the body carries the month);
- the saved read succeeded and passed validation (failed or denied reads are always repeated);
- it was saved within REUSE_DAYS (a closed month's costs are stable for that long).
Reused records keep their own query times, so reports still state when each piece of data was read.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

REUSE_DAYS = 7


def signature(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str, ensure_ascii=False).encode('utf-8')).hexdigest()


class Reuse:
    def __init__(self, enabled: bool, now: datetime | None = None):
        self.enabled = enabled
        self.now = now or datetime.now(timezone.utc)
        self.checked = self.reused = 0

    def load(self, path: Path, sig: str, valid=lambda record: True):
        """The saved record at `path` when it may be reused, else None."""
        self.checked += 1
        path = Path(path)
        if not self.enabled or not path.exists():
            return None
        try:
            record = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return None
        meta = record.get('_resume') if isinstance(record, dict) else None
        if not meta or meta.get('signature') != sig:
            return None
        try:
            saved = datetime.fromisoformat(str(meta.get('savedAt')).replace('Z', '+00:00'))
        except ValueError:
            return None
        if (self.now - saved).days >= REUSE_DAYS or not valid(record):
            return None
        self.reused += 1
        return record

    def stamp(self, record: dict, sig: str) -> dict:
        record['_resume'] = {'signature': sig, 'savedAt': datetime.now(timezone.utc).isoformat()}
        return record

    def summary(self) -> str:
        return f'复用已保存的结果 {self.reused} 个，重新读取 {self.checked - self.reused} 个' if self.enabled else ''
