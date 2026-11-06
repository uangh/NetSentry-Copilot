"""公开源码启动预检：只检查批准资产及摘要，不加载模型，不生成内容。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def main() -> int:
    from netsentry.runtime_paths import RuntimePaths
    from netsentry.services.prediction_service import ASSETS, verify_runtime
    runtime = RuntimePaths.resolve(ROOT).runtime
    missing = sorted(name for name in ASSETS | {'runtime_manifest.json'} if not (runtime / name).is_file())
    if missing:
        print('Runtime assets are missing: ' + ', '.join(missing), file=sys.stderr)
        print('See docs/RUNTIME_ASSETS.md. No model was loaded; no mock runtime was created.', file=sys.stderr)
        return 2
    try:
        verify_runtime(runtime)
    except (OSError, ValueError, KeyError) as exc:
        print('Runtime verification failed: ' + str(exc), file=sys.stderr)
        return 2
    print('Runtime manifest and file hashes verified. This does not establish model/data licensing or safety of untrusted weights.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
