"""安全-网络（S-N1..S-N8）：子网与 NSG、公网暴露、数据服务公网访问、存储、入口防护、传输加密、已断开的私有终结点。"""
from .analyze import analyze
from .collect import collect

__all__ = ['analyze', 'collect']
