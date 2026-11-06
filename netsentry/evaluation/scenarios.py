"""Synthetic boundary scenarios and deterministic metadata-only real case freezing."""
from contextlib import closing
from datetime import datetime,timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import httpx
from netsentry.agent.tools import M3Tools
from netsentry.api.config import ROOT
from netsentry.services.prediction_service import PredictionService
from netsentry.services.evidence_service import EvidenceService
from netsentry.repositories.alert_repository import AlertRepository

SCENARIOS=('complete','source_only','destination_only','no_ips','no_related','many','http_timeout',
           'unavailable','invalid_output','invalid_reference','uncalibrated_score','untrusted_rag')

def sha(path: Path) -> str:
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def synthetic_tools(name: str) -> tuple[M3Tools,list]:
    if name not in SCENARIOS:raise ValueError('unknown scenario')
    flow={'record_id':'b'*64,'source_ip':'192.0.2.1','destination_ip':'192.0.2.2','source_port':1234,'destination_port':80,
          'protocol':6,'timestamp':'2017-03-15T10:00:00.000000','flow_duration':1.,'dataset_id':'synthetic','source_sha256':'c'*64}
    if name in ('destination_only','no_ips'):flow['source_ip']=None
    if name in ('source_only','no_ips'):flow['destination_ip']=None
    alert={'alert_id':'a'*32,'record_id':flow['record_id'],'prediction_id':'synthetic','predicted_label':'attack-related',
        'attack_related_score':.8,'threshold':.5,'model_id':'F2_logistic','model_version':'synthetic','model_status':'DEV_ONLY',
        'feature_contract_version':'synthetic.F2','source_dataset':'synthetic','source_sha256':flow['source_sha256'],
        'alert_status':'candidate','created_at':'2026-11-05T00:00:00Z','updated_at':'2026-11-05T00:00:00Z','trigger_rule_version':'synthetic'}
    requests=[]
    def handler(request):
        requests.append({'path':request.url.path,'parameters':dict(request.url.params)})
        if name=='http_timeout':raise httpx.ReadTimeout('synthetic timeout')
        if name=='unavailable':return httpx.Response(503,json={})
        if '/alerts/' in request.url.path and not request.url.path.endswith('/evidence'):body={'alert':alert,'flow':flow}
        elif request.url.path.endswith('/evidence'):
            radius=int(request.url.params['window_seconds']);stamp=datetime.fromisoformat(flow['timestamp'])
            records=[EvidenceService.item(flow,flow,None,True)]
            if name!='no_related' and (flow['source_ip'] or flow['destination_ip']):
                related=flow|{'record_id':'d'*64};window={'start':(stamp-timedelta(seconds=radius)).isoformat(timespec='microseconds'),
                    'end':(stamp+timedelta(seconds=radius)).isoformat(timespec='microseconds'),'boundary':'closed','time_basis':'source_local_unverified'}
                records.append(EvidenceService.item(flow,related,window,False))
            limit=int(request.url.params['limit']);offset=int(request.url.params['offset']);total=5000 if name=='many' else len(records)
            body={'anchor':flow,'association_status':'candidate_unverified','records':records[offset:offset+limit],
                'total':total,'limit':limit,'offset':offset,'has_more':offset+len(records[offset:offset+limit])<total}
        elif request.url.path=='/api/v1/flows':
            body={'records':[flow],'total':1,'limit':int(request.url.params['limit']),'offset':int(request.url.params['offset']),'has_more':False}
        else:body=flow
        if name=='invalid_output':body=body|{'attackID':'forbidden synthetic field'}
        return httpx.Response(200,json=body,headers={'X-Trace-ID':'synthetic'})
    return M3Tools('http://127.0.0.1:8000',transport=httpx.MockTransport(handler)),requests

def freeze_real_cases(out: Path) -> dict:
    """One-time immutable manifest: sorted metadata candidates; model score used only for alert eligibility."""
    out.mkdir(parents=True,exist_ok=False)
    runtime=ROOT/'outputs/m3/runtime';database=runtime/'events.sqlite'
    prediction=PredictionService(runtime);evidence=EvidenceService(database);repository=AlertRepository(out/'alerts.sqlite')
    approved=set(json.loads((runtime/'development_ids.json').read_text()))
    conditions={'complete':'source_ip IS NOT NULL AND destination_ip IS NOT NULL',
        'source_only':'source_ip IS NOT NULL AND destination_ip IS NULL','destination_only':'source_ip IS NULL AND destination_ip IS NOT NULL'}
    cases=[];availability={};historical='000859ca2d8ad5957ba9cb8ee30f394af17d63f2b4cc9275e4777c13989facdb'
    with closing(sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True)) as c:
        for condition,where in conditions.items():
            rows=c.execute('SELECT record_id FROM events WHERE '+where+' ORDER BY record_id LIMIT 400').fetchall()
            checked=0;selected=None
            for (rid,) in rows:
                if rid==historical:continue
                if rid not in approved:raise ValueError('record outside approved split')
                checked+=1;p=prediction.predict(record_id=rid,model_id='F2_logistic')
                if p['prediction']!='attack-related':continue
                f=evidence.flow(rid);alert,_=repository.create(p,f);page=evidence.evidence(rid,30,5,0)
                selected={'case_id':condition,'record_id':rid,'alert_id':alert['alert_id'],'flow':f,'model_score':p['attack_related_score'],
                    'related_total_including_anchor':page['total'],'source_sha256':f['source_sha256']};cases.append(selected);break
            availability[condition]={'metadata_candidates_checked':checked,'available':selected is not None}
        availability['no_ips']={'available':False,'metadata_rows':c.execute('SELECT COUNT(*) FROM events WHERE source_ip IS NULL AND destination_ip IS NULL').fetchone()[0]}
    manifest={'version':'netsentry.agent.evaluation.m6_2.v1','provenance':'real_CIDDS_Week1_Train_Validation',
        'selection':'first F2_logistic candidate in sorted record_id, at most 400 per metadata group; no true labels read; exclude M6.1 anchor',
        'events_sha256':sha(database),'approved_ids_sha256':sha(runtime/'development_ids.json'),
        'runtime_manifest_sha256':sha(runtime/'runtime_manifest.json'),'alert_db_sha256':sha(out/'alerts.sqlite'),
        'cases':cases,'availability':availability,'unselected_conditions':{'no_related':'not searched exhaustively; synthetic only','many':'see actual frozen counts'}}
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,sort_keys=True,indent=2),encoding='utf-8')
    (out/'manifest.sha256').write_text(sha(out/'manifest.json'),encoding='ascii');return manifest
