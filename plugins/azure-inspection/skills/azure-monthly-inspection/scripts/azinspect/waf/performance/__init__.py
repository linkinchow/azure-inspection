"""Performance efficiency pillar (P1..P10): read-only collection and offline analysis."""
from .analyze import analyze
from .collect import collect

__all__ = ['analyze', 'collect']
