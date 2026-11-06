import unittest
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import patch
from types import SimpleNamespace as NS
import time
from netsentry.services.evidence_service import EvidenceService
from netsentry.agent.gemini_adapter import GeminiAdapter
from netsentry.agent.gemini_engine import GeminiInvestigationEngine
from m4_fixture import make_tools,AID
from test_m6_gemini import FakeModels

class SemanticsTests(unittest.TestCase):
    def test_selected_endpoint_filters_before_pagination_and_closed_time_boundary(self):
        import sqlite3,json
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'events.sqlite';c=sqlite3.connect(db)
            c.execute('CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT)');c.execute('INSERT INTO metadata VALUES(?,?)',('contract',json.dumps({'schema_version':'netsentry.labeled.v1','store_kind':'events_only','labels_present':False})))
            c.execute('CREATE TABLE events(record_id TEXT PRIMARY KEY,source_ip TEXT,destination_ip TEXT,timestamp TEXT,record TEXT)')
            base={'record_id':'a'*64,'source_ip':'192.0.2.1','destination_ip':'192.0.2.2','source_port':1,'destination_port':2,'protocol':6,'timestamp':'2017-01-01T10:00:00.000000','flow_duration':1.,'dataset_id':'synthetic','source_sha256':'c'*64}
            rows=[base,base|{'record_id':'b'*64,'source_ip':'192.0.2.2','destination_ip':'192.0.2.3'},base|{'record_id':'d'*64,'source_ip':'192.0.2.4','destination_ip':'192.0.2.1','timestamp':'2017-01-01T10:00:30.000000'},base|{'record_id':'e'*64,'timestamp':'2017-01-01T10:00:30.000001'}]
            for r in rows:c.execute('INSERT INTO events VALUES(?,?,?,?,?)',(r['record_id'],r['source_ip'],r['destination_ip'],r['timestamp'],json.dumps(r)))
            c.commit();c.close();service=EvidenceService(db)
            source=service.evidence(base['record_id'],30,10,0,endpoint='source');destination=service.evidence(base['record_id'],30,10,0,endpoint='destination')
            self.assertEqual([r['related_record_id'] for r in source['records']],['a'*64,'d'*64]);self.assertEqual([r['related_record_id'] for r in destination['records']],['a'*64,'b'*64])
            self.assertEqual(service.evidence(base['record_id'],30,1,1,endpoint='source')['records'][0]['related_record_id'],'d'*64)
    def test_endpoint_is_sent_on_real_tool_path(self):
        from netsentry.agent.schemas import Choice
        tools,_=make_tools();models=FakeModels();a=GeminiAdapter(model='gemini-3.5-flash-lite',client=NS(models=models,close=lambda:None));a.probe()
        a.plan=lambda *args:{'actions':[{'tool':'query_related_evidence','endpoint':'source','window_seconds':60,'limit':5}],'reason':'inspect_candidate_relations'}
        with tempfile.TemporaryDirectory() as tmp,patch.dict('os.environ',{'NETSENTRY_GEMINI_PLAN_LIMIT':'1'}):
            e=GeminiInvestigationEngine(Path(tmp)/'c',tools,adapter_factory=lambda:a)
            try:
                seen=[];original=tools.query_related_evidence
                def call(*args,**kwargs):seen.append(kwargs.copy());return original(*args,**kwargs)
                tools.query_related_evidence=call
                s=e.start(AID,'gemini_llm');self.assertEqual(seen[0]['endpoint'],'source')
                trace=next(t for t in s['report']['tool_call_trace'] if t['tool']=='query_related_evidence')
                self.assertEqual(trace['parameters']['endpoint'],'source')
            finally:e.close()
    def test_actual_http_radius_and_endpoint(self):
        import httpx
        tools,_=make_tools();transport=tools.client._transport;requests=[]
        tools.client.close()
        tools.client=httpx.Client(base_url=tools.base_url,transport=httpx.MockTransport(lambda request:(requests.append(request) or transport.handle_request(request))))
        try:
            tools.query_related_evidence(AID,'b'*64,endpoint='destination',window_seconds=60,limit=5,offset=0,deadline=time.time()+3)
            self.assertEqual(requests[0].url.params['endpoint'],'destination');self.assertEqual(requests[0].url.params['window_seconds'],'30')
        finally:tools.close()
