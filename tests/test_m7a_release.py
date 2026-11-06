"""M7A: synthetic configuration/static tests; never constructs a live Gemini client."""
import os,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from netsentry.agent.model_config import resolve_model
from netsentry.agent.gemini_adapter import GeminiAdapter,connection_status
from netsentry.static_console import mount_console
from netsentry.runtime_paths import RuntimePaths
from test_m6_gemini import FakeModels

class ModelConfigTests(unittest.TestCase):
    def test_default_exact_stable_id(self):
        with patch.dict(os.environ,{},clear=True):self.assertEqual(resolve_model(),('gemini-3.1-flash-lite','default'))
    def test_explicit_over_env(self):
        with patch.dict(os.environ,{'NETSENTRY_GEMINI_MODEL':'gemini-3.5-flash-lite'}):
            self.assertEqual(resolve_model(),('gemini-3.5-flash-lite','environment:NETSENTRY_GEMINI_MODEL'))
            self.assertEqual(resolve_model('gemini-3.1-flash-lite'),('gemini-3.1-flash-lite','explicit'))
    def test_no_key_still_exposes_default(self):
        with patch.dict(os.environ,{},clear=True):
            s=connection_status();self.assertFalse(s['ready']);self.assertEqual(s['requested_model'],'gemini-3.1-flash-lite');self.assertEqual(s['config_source'],'default')
    def test_fake_request_uses_new_default(self):
        with patch.dict(os.environ,{},clear=True):
            m=FakeModels();m.list=lambda **k:[NS(name='models/gemini-3.1-flash-lite',supported_actions=['generateContent'])]
            a=GeminiAdapter(client=NS(models=m,close=lambda:None));a.probe();a.plan({},time.time()+5)
            self.assertEqual(m.requests[0]['model'],'gemini-3.1-flash-lite');a.close()
    def test_no_silent_fallback(self):
        with patch.dict(os.environ,{},clear=True):
            m=FakeModels();a=GeminiAdapter(client=NS(models=m,close=lambda:None))
            self.assertFalse(a.probe()['ready']);self.assertEqual(m.requests,[]);a.close()
    def test_explicit_historical_model_retained(self):
        m=FakeModels();a=GeminiAdapter(model='gemini-3.5-flash-lite',client=NS(models=m,close=lambda:None))
        self.assertEqual(a.probe()['model'],'gemini-3.5-flash-lite');a.close()
    def test_default_factory_resume_pins_checkpoint_model(self):
        from netsentry.agent.recovery_engine import RecoveryEngine,ResumeRequest
        from netsentry.agent.gemini_adapter import GeminiError
        from test_m6_3_1_registry import RegistryFake
        from m6_3_fixture import fixture,AID
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);t=tmp.name
        tools,_,_=fixture(Path(t));fake=RegistryFake(fail_at=1);fake.model='gemini-3.5-flash-lite'
        e=RecoveryEngine(Path(t)/'cp',tools,recovery_enabled=True,adapter_factory=lambda:fake)
        self.addCleanup(e.close);s=e.start(AID,'gemini_multistep');e.adapter_factory=GeminiAdapter;seen=[]
        def probe(a):
            seen.append((a.requested,a.connection['config_source']));a.model=a.requested;a.connection.update(ready=True);return a.connection
        with patch.dict(os.environ,{'GEMINI_API_KEY':'synthetic','NETSENTRY_GEMINI_MODEL':'gemini-3.1-flash-lite'}),patch.object(GeminiAdapter,'probe',probe),patch.object(GeminiAdapter,'generate',side_effect=GeminiError('synthetic-stop')):
            e.resume_failed_investigation(s['investigation_id'],ResumeRequest(request_id='a'*32,expected_checkpoint=s['recovery']['checkpoint_id']))
        self.assertEqual(seen,[('gemini-3.5-flash-lite','checkpoint')])

    def test_port_conflict_before_spawning(self):
        import socket,sys
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
        import start_netsentry_dev as launcher
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));sock.listen();port=sock.getsockname()[1]
            with patch.object(launcher.subprocess,'Popen') as spawn,self.assertRaises(RuntimeError):
                with launcher.running_services(backend_port=port,serving='static'):pass
            spawn.assert_not_called()

class StaticTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        (self.root/'index.html').write_text('<html>synthetic console</html>');(self.root/'assets').mkdir();(self.root/'assets/main.js').write_text('synthetic')
        app=FastAPI();app.get('/health')(lambda:{'status':'ok'});mount_console(app,self.root);self.client=TestClient(app);self.addCleanup(self.client.close)
    def test_deep_link(self):self.assertIn('synthetic console',self.client.get('/investigations/'+'a'*32+'/report').text)
    def test_api_404_never_html(self):
        r=self.client.get('/api/v1/missing');self.assertEqual(r.status_code,404);self.assertIn('application/json',r.headers['content-type'])
    def test_health_and_openapi_preserved(self):
        self.assertEqual(self.client.get('/health').json(),{'status':'ok'});self.assertEqual(self.client.get('/openapi.json').status_code,200)
    def test_assets_and_missing(self):
        self.assertEqual(self.client.get('/assets/main.js').status_code,200);self.assertEqual(self.client.get('/assets/missing.js').status_code,404)
    def test_no_source_or_database_exposure(self):
        for path in ('/README.md','/outputs/a.sqlite','/.env','/assets/%2e%2e/%2e%2e/secret'):
            self.assertEqual(self.client.get(path).status_code,404,path)
    def test_missing_dist_fails(self):
        with self.assertRaises(FileNotFoundError):mount_console(FastAPI(),self.root/'absent')

class PathsTests(unittest.TestCase):
    def test_release_sqlite_backup_includes_committed_wal(self):
        import sqlite3,sys
        from contextlib import closing
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
        from freeze_v0_1 import sqlite_payload
        with tempfile.TemporaryDirectory() as t:
            original=Path(t)/'source.sqlite';target=Path(t)/'snapshot.sqlite'
            db=sqlite3.connect(original)
            try:
                db.execute('PRAGMA journal_mode=WAL');db.execute('CREATE TABLE evidence(value TEXT)');db.execute("INSERT INTO evidence VALUES('committed historical observation')");db.commit()
                sqlite_payload(original,target)
                with closing(sqlite3.connect(target)) as result:self.assertEqual(result.execute('SELECT value FROM evidence').fetchone()[0],'committed historical observation')
            finally:db.close()
    def test_relative_config_resolves_from_code_not_cwd(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{'NETSENTRY_RUNTIME_DIR':'bundle','NETSENTRY_WORK_DIR':'runs'}):
            p=RuntimePaths.resolve(Path(t));self.assertEqual(p.runtime,Path(t).resolve()/'bundle');self.assertEqual(p.work,Path(t).resolve()/'runs')
    def test_missing_runtime_never_falls_back(self):
        with tempfile.TemporaryDirectory() as t,patch.dict(os.environ,{},clear=True):
            with self.assertRaises(FileNotFoundError):RuntimePaths.resolve(Path(t)).require_runtime()
