"""Shared chart style: one palette, one CJK font, recessive axes (see the dataviz rules in references/report-structure.md)."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402

SURFACE, INK, INK2, GRID = '#fcfcfb', '#0b0b0b', '#52514e', '#e6e5e0'
BLUE, ORANGE, GRAY = '#2a78d6', '#eb6834', '#a09f98'
SEVERITY = {'高': '#184f95', '中': '#3987e5', '低': '#86b6ef'}
INCREASE, DECREASE = '#e34948', '#2a78d6'
CJK_FONTS = ['Microsoft YaHei', 'PingFang SC', 'Noto Sans CJK SC', 'Source Han Sans SC', 'SimHei', 'Heiti SC']


def setup_fonts() -> str | None:
    names = {f.name for f in font_manager.fontManager.ttflist}
    available = [f for f in CJK_FONTS if f in names]
    plt.rcParams['font.family'] = available + ['sans-serif']
    plt.rcParams['axes.unicode_minus'] = False
    return available[0] if available else None


def style(ax, grid_axis: str = 'y') -> None:
    ax.set_facecolor(SURFACE)
    ax.grid(axis=grid_axis, color=GRID, lw=1)
    ax.set_axisbelow(True)
    for side in ('top', 'right', 'left', 'bottom'):
        ax.spines[side].set_visible(False)
    ax.tick_params(colors=INK2, labelsize=9, length=0)


def figure(width: float = 10, height: float = 4):
    fig, ax = plt.subplots(figsize=(width, height), facecolor=SURFACE)
    return fig, ax


def _trim(x: float) -> str:
    text = f'{x:,.2f}'.rstrip('0').rstrip('.')
    return '0' if text == '-0' else text


def amount_tick(x, _=None) -> str:
    """Amount axis tick: thousands as K, with only the decimals the step needs, so 500-steps read 1K, 1.5K, 2K (not 2K, 2K)."""
    return f'{_trim(x / 1000)}K' if abs(x) >= 1000 else _trim(x)


def bar_limits(values):
    """x limits of a change chart: room for labels on the side that has bars; no empty half when all go one way."""
    span = max([abs(v) for v in values] or [1]) or 1
    lo, hi = min([0.0] + list(values)), max([0.0] + list(values))
    return (lo - span * 0.3 if lo < 0 else -span * 0.05), (hi + span * 0.3 if hi > 0 else span * 0.05)


def signed_amount(v) -> str:
    """A change label with its sign, whole units; one that rounds to 0 reads 0, not -0."""
    return '0' if round(v) == 0 else f'{v:+,.0f}'


def clear(chart_dir: Path, report: str) -> None:
    """Remove this report's charts from an earlier build, so a chart that is no longer drawn does not linger in the package."""
    for old in Path(chart_dir).glob(f'{report}_*.png'):
        old.unlink()


def save(fig, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, facecolor=SURFACE, bbox_inches='tight', dpi=160)
    plt.close(fig)
    return path


setup_fonts()
