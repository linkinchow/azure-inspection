"""可靠性（R1–R12）：只读采集和离线分析。"""
from .analyze import analyze
from .collect import collect

__all__ = ['analyze', 'collect']
