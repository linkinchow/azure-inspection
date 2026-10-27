"""Report month arithmetic. No hard-coded month names or day counts."""
from __future__ import annotations

import calendar
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone


def _month(year: int, month: int) -> tuple[int, int]:
    year, month = year + (month - 1) // 12, (month - 1) % 12 + 1
    return year, month


@dataclass(frozen=True)
class Month:
    year: int
    month: int

    @classmethod
    def parse(cls, text: str) -> 'Month':
        m = re.fullmatch(r'(\d{4})-(\d{1,2})', text.strip())
        if not m or not 1 <= int(m.group(2)) <= 12:
            raise ValueError('月份格式应为 YYYY-MM，例如 2026-09')
        return cls(int(m.group(1)), int(m.group(2)))

    @classmethod
    def last_complete(cls, today: date | None = None) -> 'Month':
        today = today or datetime.now(timezone.utc).date()
        return cls(*_month(today.year, today.month - 1))

    def shift(self, n: int) -> 'Month':
        return Month(*_month(self.year, self.month + n))

    @property
    def days(self) -> int:
        return calendar.monthrange(self.year, self.month)[1]

    @property
    def first(self) -> date:
        return date(self.year, self.month, 1)

    @property
    def last(self) -> date:
        return date(self.year, self.month, self.days)

    @property
    def key(self) -> str:
        return f'{self.year:04d}-{self.month:02d}'

    @property
    def label(self) -> str:
        return f'{self.year}年{self.month}月'

    @property
    def short_label(self) -> str:
        return f'{self.month}月'

    def cost_range(self) -> dict:
        """timePeriod for Cost Management queries."""
        return {'from': f'{self.first.isoformat()}T00:00:00Z', 'to': f'{self.last.isoformat()}T23:59:59Z'}


@dataclass(frozen=True)
class ReportPeriod:
    """The month being reviewed, the month it is compared with, and the metric windows."""
    current: Month
    run_date: date

    @classmethod
    def build(cls, month: str | None = None, run_date: date | None = None) -> 'ReportPeriod':
        run_date = run_date or datetime.now(timezone.utc).date()
        current = Month.parse(month) if month else Month.last_complete(run_date)
        if current.last >= run_date:
            raise ValueError(f'{current.label} 尚未结束，月度巡检应选择已结束的月份。')
        return cls(current, run_date)

    @property
    def previous(self) -> Month:
        return self.current.shift(-1)

    @property
    def following(self) -> Month:
        return self.current.shift(1)

    def metric_window(self, days: int) -> tuple[str, str]:
        """Last `days` full days before the run date (UTC), as ISO timestamps for Azure Monitor."""
        end = datetime.combine(self.run_date, datetime.min.time(), tzinfo=timezone.utc)
        start = end - timedelta(days=days)
        return start.strftime('%Y-%m-%dT%H:%M:%SZ'), end.strftime('%Y-%m-%dT%H:%M:%SZ')
