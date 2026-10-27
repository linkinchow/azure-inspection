"""安全-身份：AKS 访问与补丁、Defender、高权限角色、凭据、审计日志、虚拟机基线、Key Vault、镜像仓库与 AI 服务认证（S-I1..S-I10）。"""
from .analyze import analyze
from .collect import collect

__all__ = ['analyze', 'collect']
