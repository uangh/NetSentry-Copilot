"""确定性事实及引用校验：存在性与字段语义逐项匹配，拒绝自由填造。"""
import json
from .schemas import Report, Narrative

UNCERTAINTY=['DEV_ONLY模型未完成正式最终验收','模型分数不是校准攻击概率',
             'candidate_unverified不等于已确认攻击','公开系统抽样、匿名IP和未知时区限制关联完整性']
MISSING=['没有认证日志，不能推断登录失败次数或登录成功','没有独立服务健康或主机取证，不能确认攻击成功']
NEXT=['由人工复核证据与业务背景','按授权流程补充独立日志或服务健康证据；本Agent不自动处置']


def facts_and_references(state: dict) -> tuple[list[dict],list[dict]]:
    facts=[];refs=[]
    def add(field,value,ref,scope):
        facts.append({'fact_id':'f'+str(len(facts)),'field':field,'value':value,'reference_id':ref,'scope':scope})
    for observation in state['observations']:
        result=observation['result'];tool=observation['tool'];call=observation['call_id'];ref='call:'+call
        if tool=='get_alert_detail':
            alert=result['alert'];flow=result['flow']
            refs.append({'reference_id':ref,'kind':'alert_response','record_id':alert['record_id'],
                         'source_sha256':alert['source_sha256'],'call_id':call,'evidence_id':None})
            add('model_score',alert['attack_related_score'],ref,'M3候选告警分数；非校准概率')
        elif tool=='get_anchor_flow':
            refs.append({'reference_id':ref,'kind':'flow_response','record_id':result['record_id'],
                         'source_sha256':result['source_sha256'],'call_id':call,'evidence_id':None})
            for key in ('source_ip','destination_ip','source_port','destination_port','protocol','timestamp','flow_duration'):
                add(key,result[key],ref,'锚点流量记录')
        elif tool=='query_related_evidence':
            refs.append({'reference_id':ref,'kind':'flow_query','record_id':result['anchor']['record_id'],
                         'source_sha256':result['anchor']['source_sha256'],'call_id':call,'evidence_id':None})
            scope=json.dumps(observation['parameters'],sort_keys=True,ensure_ascii=False)
            add('query_total_including_anchor',result['total'],ref,scope)
            add('returned_evidence_rows',len(result['records']),ref,scope)
            for item in result['records']:
                if any(r['reference_id']==item['evidence_id'] for r in refs):continue
                refs.append({'reference_id':item['evidence_id'],'kind':'evidence','record_id':item['related_record_id'],
                    'source_sha256':item['source_sha256'],'call_id':call,'evidence_id':item['evidence_id']})
        elif tool=='query_host_flows':
            refs.append({'reference_id':ref,'kind':'flow_query','record_id':None,'source_sha256':None,'call_id':call,'evidence_id':None})
            add('host_query_total',result['total'],ref,json.dumps(result['query'],sort_keys=True))
            add('host_returned_rows',len(result['records']),ref,json.dumps(result['query'],sort_keys=True))
        elif tool in ('summarize_host_behavior','analyze_port_distribution','analyze_temporal_bursts','build_flow_timeline','expand_evidence_page'):
            refs.append({'reference_id':ref,'kind':'flow_query','record_id':result['anchor_record_id'],
                         'source_sha256':result['source_sha256'],'call_id':call,'evidence_id':None})
            scope='bounded_analysis:'+tool+':'+json.dumps(result['query'],sort_keys=True)
            for key in ('total','analyzed_count','scan_truncated','sampled_source','has_more'):
                add(key,result[key],ref,scope)
            for key,value in result['statistics'].items():
                add(key,json.dumps(value,ensure_ascii=False,sort_keys=True) if isinstance(value,(list,dict)) else value,ref,scope)
            for item in result['records']:
                if not any(r['reference_id']==item['evidence_id'] for r in refs):
                    refs.append({'reference_id':item['evidence_id'],'kind':'evidence','record_id':item['related_record_id'],
                        'source_sha256':item['source_sha256'],'call_id':call,'evidence_id':item['evidence_id']})
    return facts,refs


def render_summary(facts: list[dict], narrative: dict | None) -> str:
    if narrative is None:
        narrative={'paragraphs':[{'lead':'已取得以下可追溯观察。','fact_ids':[f['fact_id'] for f in facts[:8]]}]}
    validated=Narrative.model_validate(narrative)
    by_id={f['fact_id']:f for f in facts};paragraphs=[]
    for paragraph in validated.paragraphs:
        text=paragraph.lead
        for fid in paragraph.fact_ids:
            if fid not in by_id:raise ValueError('LLM引用不存在的事实')
            fact=by_id[fid];text+=f" {fact['field']}={fact['value']}（{fact['scope']}）。"
        paragraphs.append(text)
    return '\n'.join(paragraphs)+'\n证据不足以确认攻击，等待或遵循人工审核；模型状态为DEV_ONLY。'


def build_report(state: dict) -> dict:
    if not state.get('alert_detail'):raise ValueError('告警未实际取得，禁止生成报告')
    alert=state['alert_detail']['alert'];facts,refs=facts_and_references(state)
    return Report.model_validate({'investigation_id':state['investigation_id'],'alert_id':alert['alert_id'],
        'model_id':alert['model_id'],'model_status':alert['model_status'],'prediction_score':alert['attack_related_score'],
        'model_version':alert['model_version'],'feature_contract_version':alert['feature_contract_version'],
        'predicted_class':alert['predicted_label'],
        'score_is_calibrated_probability':False,'investigation_summary':render_summary(facts,state.get('narrative')),
        'observed_facts':facts,'candidate_relations':state['candidate_relations'],
        'evidence_references':refs,'knowledge_references':state['knowledge_references'],
        'hypothesis':'insufficient_evidence','uncertainty':UNCERTAINTY+state['confidence_limitations'],
        'missing_evidence':MISSING+state['missing_information'],'recommended_next_steps':NEXT,
        'reasoning_mode':'deterministic_offline' if state['mode']=='offline' else state['mode'],
        'tool_call_trace':state['tool_call_history'],'review_status':state['review_status'],
        'generated_at':state['generated_at'],'report_version':state['report_version']}).model_dump()


def validate_report(report: dict, state: dict) -> dict:
    checked=Report.model_validate(report).model_dump()
    expected=build_report(state)
    # 不是仅检查ID存在：IP/时间/端口/数量/状态/限定语也必须逐项等于真实工具结果的投影。
    if checked!=expected:raise ValueError('报告事实、引用或限定语与实际工具结果不一致')
    if checked['alert_id']!=state['alert_id']:raise ValueError('告警作用域不一致')
    return checked
