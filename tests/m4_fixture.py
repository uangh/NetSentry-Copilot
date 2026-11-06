"""构造合成HTTP响应，不涉及真实标签或模型性能。"""
from datetime import datetime,timedelta
import json
import httpx
from netsentry.agent.tools import M3Tools

AID='a'*32
RID='b'*64


def make_tools(scenario='complete',mutate=None):
    flow={'record_id':RID,'source_ip':'192.0.2.1','destination_ip':'192.0.2.2','source_port':1234,
          'destination_port':80,'protocol':6,'timestamp':'2017-03-15T10:00:00.000000','flow_duration':1.,
          'dataset_id':'synthetic','source_sha256':'c'*64}
    if scenario in ('no_ip','dest_only'):flow['source_ip']=None
    if scenario in ('no_ip','source_only'):flow['destination_ip']=None
    alert={'alert_id':AID,'record_id':RID,'prediction_id':'p1','predicted_label':'attack-related','attack_related_score':0.8,
           'threshold':0.5,'model_id':'F2_logistic','model_version':'synthetic','model_status':'DEV_ONLY',
           'feature_contract_version':'synthetic.F2','source_dataset':'synthetic','source_sha256':'c'*64,
           'alert_status':'candidate','created_at':'2026-11-04T00:00:00Z','updated_at':'2026-11-04T00:00:00Z','trigger_rule_version':'synthetic'}
    calls=[]
    def handler(request):
        path=request.url.path;calls.append(path)
        if scenario=='unavailable':return httpx.Response(503,json={'error':'unavailable'})
        if scenario=='timeout':raise httpx.ReadTimeout('synthetic timeout')
        if path==f'/api/v1/alerts/{AID}':
            body={'alert':alert,'flow':flow}
            if scenario=='invalid_fields':body['attackID']='forbidden'
        elif path==f'/api/v1/flows/{RID}':body=flow
        elif path.endswith('/evidence'):
            window=int(request.url.params['window_seconds']);stamp=datetime.fromisoformat(flow['timestamp'])
            evidence={'evidence_id':'real_returned_evidence','evidence_type':'record_identity','source_record_id':RID,
                'related_record_id':RID,'match_reason':'same record','query_window':None,'source_sha256':'c'*64,
                'association_status':'exact_record','limitations':['synthetic'],'flow':flow}
            body={'anchor':flow,'association_status':'candidate_unverified','records':[] if scenario=='empty' else [evidence],
                  'total':0 if scenario=='empty' else 1,'limit':int(request.url.params['limit']),
                  'offset':int(request.url.params['offset']),'has_more':False}
            if scenario=='many':body['total']=5000;body['has_more']=True
        elif path=='/api/v1/flows':
            body={'records':[] if scenario=='empty' else [flow],'total':0 if scenario=='empty' else 1,
                  'limit':int(request.url.params['limit']),'offset':int(request.url.params['offset']),'has_more':False}
        else:return httpx.Response(404,json={})
        if mutate:mutate(path,body)
        return httpx.Response(200,json=body,headers={'X-Trace-ID':'synthetic_trace'})
    return M3Tools('http://127.0.0.1:8000',transport=httpx.MockTransport(handler)),calls
