"""在公开副本运行不拟合模型、不访问私有运行包、不调用真实LLM的测试。"""
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DEFERRED = {
    'test_m6_gemini.GeminiTests.test_frontend_child_never_receives_backend_secrets': 'requires approved runtime manifest and installed frontend',
    'test_m7a_release.ModelConfigTests.test_port_conflict_before_spawning': 'requires approved runtime manifest and built frontend',
}

def flattened(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flattened(test)
        else:
            yield test

def main() -> int:
    for name in ('GEMINI_API_KEY', 'GOOGLE_API_KEY', 'LANGSMITH_API_KEY', 'NETSENTRY_API_TOKEN'):
        os.environ.pop(name, None)
    os.environ['LANGSMITH_TRACING'] = 'false'
    selected = unittest.TestSuite()
    deferred = []
    for test in flattened(unittest.defaultTestLoader.discover(str(ROOT / 'tests'))):
        identity = test.id()
        reason = 'synthetic model fitting group; not run in this no-training task' if identity.startswith('test_m2b_models.') else DEFERRED.get(identity)
        if reason:
            deferred.append({'test': identity, 'reason': reason})
        else:
            selected.addTest(test)
    original = socket.socket.connect
    def local_only(sock, address):
        if isinstance(address, tuple):
            host = address[0]
            if host != 'localhost':
                try:
                    allowed = ipaddress.ip_address(host).is_loopback
                except ValueError:
                    allowed = False
                if not allowed:
                    raise RuntimeError('Public test runner blocks external network connections')
        return original(sock, address)
    with patch.object(socket.socket, 'connect', local_only):
        result = unittest.TextTestRunner(verbosity=2).run(selected)
    summary = {'executed': result.testsRun, 'passed': result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
               'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
               'not_selected': deferred, 'real_gemini_generations': 0}
    target = ROOT / 'outputs/public-tests.json'
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary))
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    raise SystemExit(main())
