"""Agent仅通过M3 HTTP获得分析结果；验证请求作用域及证据身份。"""
from datetime import datetime,timedelta
from netsentry.services.flow_analysis import AnalysisArguments,AnalysisRequest,AnalysisResult
from .tools import ToolError,ValidatedEvidence


def run_analysis(tools, anchor: dict, tool: str, arguments: dict, deadline: float) -> dict:
    args=AnalysisArguments.model_validate(arguments)
    request=AnalysisRequest(tool=tool,**args.model_dump())
    ip=anchor.get(args.endpoint+'_ip')
    if not ip or not anchor.get('timestamp'):raise ToolError('insufficient_metadata')
    result=tools._get('/api/v1/flows/'+anchor['record_id']+'/analysis',AnalysisResult,
                      params=request.model_dump(),deadline=deadline)
    if result['query']!=args.model_dump() or result['tool']!=tool or result['anchor_record_id']!=anchor['record_id']:
        raise ToolError('analysis_request_mismatch')
    if result['source_sha256']!=anchor['source_sha256']:raise ToolError('analysis_source_mismatch')
    center=datetime.fromisoformat(anchor['timestamp'])+timedelta(seconds=args.center_offset_seconds)
    low=center-timedelta(seconds=args.window_seconds/2);high=center+timedelta(seconds=args.window_seconds/2)
    expected={'start':low.isoformat(timespec='microseconds'),'end':high.isoformat(timespec='microseconds'),
              'boundary':'half_open','time_basis':'source_local_unverified'}
    if result['query_window']!=expected:raise ToolError('analysis_window_mismatch')
    if result['limit']!=args.limit or result['offset']!=args.offset or len(result['records'])>args.limit:
        raise ToolError('analysis_page_mismatch')
    n=result['analyzed_count']
    if n>result['total'] or result['scan_truncated']!=(n<result['total']) or result['has_more']!=(args.offset+len(result['records'])<result['total']):
        raise ToolError('analysis_coverage_mismatch')
    stats=result['statistics']
    if tool=='summarize_host_behavior' and stats.get('flow_count')!=n:raise ToolError('analysis_count_mismatch')
    if tool=='analyze_temporal_bursts' and sum(b['flow_count'] for b in stats['buckets'])!=n:raise ToolError('analysis_bucket_mismatch')
    ids=set()
    for item in result['records']:
        ValidatedEvidence.model_validate(item);flow=item['flow']
        if flow['record_id'] in ids:raise ToolError('duplicate_response_record')
        ids.add(flow['record_id'])
        if item['source_record_id']!=anchor['record_id'] or item['related_record_id']!=flow['record_id']:raise ToolError('analysis_identity_mismatch')
        if item['source_sha256']!=anchor['source_sha256'] or flow['source_sha256']!=anchor['source_sha256'] or flow['dataset_id']!=anchor['dataset_id']:raise ToolError('analysis_source_mismatch')
        if ip not in (flow['source_ip'],flow['destination_ip']) or not flow['timestamp'] or not low<=datetime.fromisoformat(flow['timestamp'])<high:raise ToolError('analysis_row_scope_mismatch')
        if (item['association_status']=='exact_record')!=(flow['record_id']==anchor['record_id']):raise ToolError('analysis_false_exact')
        if item['association_status']=='exact_record' and flow!=anchor:raise ToolError('analysis_anchor_changed')
    return result
