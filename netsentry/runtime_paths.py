"""Separate code, immutable assets/archive, and writable runtime paths."""
from dataclasses import dataclass
import os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

@dataclass(frozen=True)
class RuntimePaths:
    code: Path
    runtime: Path
    work: Path
    archive: Path

    @classmethod
    def resolve(cls,code: Path=ROOT) -> 'RuntimePaths':
        code=code.resolve()
        def path(name: str,default: str) -> Path:
            value=Path(os.environ.get(name) or default)
            return (value if value.is_absolute() else code/value).resolve()
        return cls(code,path('NETSENTRY_RUNTIME_DIR','outputs/m3/runtime'),path('NETSENTRY_WORK_DIR','outputs/local_runs'),path('NETSENTRY_ARCHIVE_DIR','outputs'))

    def require_runtime(self) -> None:
        if not (self.runtime/'runtime_manifest.json').is_file():raise FileNotFoundError('Missing approved runtime: '+str(self.runtime))
