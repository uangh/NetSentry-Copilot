"""Synthetic SQLite -> actual deterministic service -> HTTP response, reactive Fake planner."""
import json,sqlite3,time
from pathlib import Path
from datetime import datetime,timedelta
import httpx
from netsentry.agent.multistep_engine import MultiStepEngine,baseline_decision
from netsentry.agent.gemini_adapter import GeminiError
from netsentry.services.flow_analysis import AnalysisRequest,FlowAnalysisService
from netsentry.services.evidence_service import EvidenceService
from m4_fixture import make_tools,AID,RID


def fixture(folder: Path, count=30, ports=8, side='both', mutation=None, step_seconds=.1):
    tools,_=make_tools('dest_only' if side=='destination' else 'source_only' if side=='source' else 'no_ip' if side=='none' else 'complete')
    original=tools.client._transport
    flow=tools.get_anchor_flow(RID,deadline=time.time()+5)
    db=folder/'events.sqlite';conn=sqlite3.connect(db)
    conn.execute('CREATE TABLE metadata(name TEXT PRIMARY KEY,value TEXT)')
    conn.execute('INSERT INTO metadata VALUES(?,?)',('contract',json.dumps({'schema_version':'netsentry.labeled.v1','store_kind':'events_only','labels_present':False})))
    conn.execute('CREATE TABLE events(record_id TEXT PRIMARY KEY,source_ip TEXT,destination_ip TEXT,timestamp TEXT,record TEXT)')
    rows=[flow]
    for i in range(1,count):
        rows.append(flow|{'record_id':f'{i:064x}','destination_port':80+i%ports,
                         'timestamp':(datetime.fromisoformat(flow['timestamp'])+timedelta(seconds=i*step_seconds)).isoformat(timespec='microseconds')})
    for r in rows:conn.execute('INSERT INTO events VALUES(?,?,?,?,?)',(r['record_id'],r['source_ip'],r['destination_ip'],r['timestamp'],json.dumps(r)))
    conn.commit();conn.close();service=FlowAnalysisService(EvidenceService(db));requests=[]
    def handle(request):
        requests.append(str(request.url))
        if request.url.path.endswith('/analysis'):
            data=service.run(RID,AnalysisRequest.model_validate(dict(request.url.params)))
            if mutation:mutation(data)
            return httpx.Response(200,json=data,headers={'X-Trace-ID':'synthetic_analysis'})
        return original.handle_request(request)
    tools.client.close();tools.client=httpx.Client(base_url=tools.base_url,transport=httpx.MockTransport(handle))
    return tools,service,requests


class ReactiveFake:
    live_provider=False
    model='synthetic_fake_gemini'
    max_requests=4
    def __init__(self, alter=None, fail_at=None):
        self.calls=[];self.inputs=[];self.alter=alter;self.fail_at=fail_at
        self.connection={'ready':True,'generation_verified':False,'model':self.model,'status':'synthetic'}
    def probe(self):return self.connection.copy()
    def close(self):pass
    def generate(self,task,ctx,schema,deadline):
        self.inputs.append(ctx)
        self.calls.append({'request_number':len(self.calls)+1,'purpose':task,'status':'validated','total_tokens':None,
                           'duration_ms':1,'execution_source':'synthetic_reactive_fake','live_provider':False})
        if self.fail_at==len(self.calls):
            self.calls[-1].update(status='provider_unavailable',http_status=503);raise GeminiError('provider_unavailable')
        self.connection['generation_verified']=True
        plan=baseline_decision(ctx)
        if self.alter:plan=self.alter(plan,ctx)
        return plan
    def narrate(self,ctx,deadline):
        self.calls.append({'request_number':len(self.calls)+1,'purpose':'narrative','status':'validated','total_tokens':None,'duration_ms':1})
        if self.fail_at==len(self.calls):
            self.calls[-1].update(status='provider_unavailable',http_status=503);raise GeminiError('provider_unavailable')
        return {'paragraphs':[{'lead':'已取得以下可追溯观察。','fact_ids':[f['fact_id'] for f in ctx['facts'][:2]]}]}
