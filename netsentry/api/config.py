"""配置只来自可信启动环境；HTTP 不接受模型或数据库路径。"""
from dataclasses import dataclass, field
import os
from pathlib import Path
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    runtime: Path=ROOT/'outputs/m3/runtime'
    alert_db: Path=ROOT/'outputs/m3/alerts.sqlite'
    token: str | None=field(default=None,repr=False)
    origins: tuple[str,...]=('http://127.0.0.1:5173','http://localhost:5173')

    def __post_init__(self) -> None:
        if self.token is not None and len(self.token)<24:raise ValueError('开发令牌至少24字符')
        for origin in self.origins:
            parsed=urlparse(origin)
            if parsed.scheme!='http' or parsed.hostname not in ('localhost','127.0.0.1') or parsed.username or parsed.path not in ('','/'):
                raise ValueError('CORS仅接受明确的本地HTTP来源')
        runtime=Path(self.runtime).resolve();target=Path(self.alert_db).resolve()
        if target==runtime or runtime in target.parents:raise ValueError('告警写库不得位于只读运行包内')
        protected=target.is_relative_to(ROOT) and any(part in ('data','artifacts','models') for part in target.relative_to(ROOT).parts)
        if protected:
            raise ValueError('告警写库不得覆盖原件或模型目录')

    @classmethod
    def from_env(cls) -> 'Settings':
        # 不开放HTTP路径选择，也不从请求头读取任何配置。
        origins=tuple(filter(None,os.environ.get('NETSENTRY_CORS_ORIGINS','http://127.0.0.1:5173,http://localhost:5173').split(',')))
        from netsentry.runtime_paths import RuntimePaths
        paths=RuntimePaths.resolve()
        return cls(runtime=paths.runtime,token=os.environ.get('NETSENTRY_API_TOKEN'),origins=origins)
