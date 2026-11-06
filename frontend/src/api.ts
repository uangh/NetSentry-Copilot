import type {Alert,AlertPage,Flow,Model,Prediction,EvidencePage,Investigation,InvestigationList,Report,ReviewInput,EvidenceView,Runtime,ModelId,GeminiStatus,InvestigationMode} from './types';
let token='';
export function setToken(value:string){token=value;}
const messages:Record<number,string>={401:'令牌无效或未提供，请检查本地开发令牌。',404:'没有找到该记录。',409:'报告版本已改变或审核冲突，请刷新后核对。',413:'请求过大，请缩短输入。',422:'输入不符合接口要求，请检查 ID、时间及版本。',429:'调查服务忙，请稍后手动重试。',500:'后端内部错误，请查看服务日志。',503:'服务或写权限未就绪，请检查后端配置。'};
export class ApiError extends Error {constructor(public status:number,message:string,public trace?:string){super(message);}}
function protect(value:unknown):void {if(value && typeof value==='object'){for(const [key,item] of Object.entries(value)){if(['label','attackType','attackID','attackDescription'].includes(key))throw new ApiError(0,'响应包含禁止的离线标签字段，已拒绝显示。');protect(item);}}}
export async function request<T>(path:string,body?:unknown,write=false):Promise<T>{
  if(typeof location!=='undefined'&&!['localhost','127.0.0.1','[::1]'].includes(location.hostname))throw new ApiError(0,'Web Console 仅允许在本地地址运行。');
  if(!/^\/(api\/v1\/|health(?:$|\?))/.test(path)||path.includes('://')||path.includes('..'))throw new ApiError(0,'仅允许本地固定 API 路径。');
  if(write&&!token)throw new ApiError(401,'请先在右上角输入本地开发令牌。');
  const geminiStart=path==='/api/v1/investigations'&&typeof body==='object'&&body!==null&&'mode' in body&&body.mode==='gemini_llm';
  const longInvestigation=path.endsWith('/resume')||(path==='/api/v1/investigations'&&typeof body==='object'&&body!==null&&'mode' in body&&body.mode==='gemini_multistep');
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),longInvestigation?300000:geminiStart?170000:body?55000:15000);
  try {const response=await fetch(path,{method:body?'POST':'GET',headers:{...(body?{'Content-Type':'application/json'}:{}),...(write?{'X-API-Token':token}:{})},body:body?JSON.stringify(body):undefined,signal:controller.signal,credentials:'omit'});
    const data=await response.json().catch(()=>null);
    if(!response.ok)throw new ApiError(response.status,messages[response.status]||'请求失败，请重试。',data?.error?.trace_id);
    if(data===null)throw new ApiError(0,'后端未返回有效 JSON。');protect(data);return data as T;
  }catch(error){if(error instanceof ApiError)throw error;throw new ApiError(0,controller.signal.aborted?'请求超时。写入可能已完成，请先刷新核对；不要重复创建调查。':'无法连接本地后端，请检查服务是否启动。');}finally{clearTimeout(timer);}
}
export function id(value:string,length=32){if(!new RegExp(`^[0-9a-f]{${length}}$`).test(value))throw new ApiError(422,'ID 格式无效。');return value;}
export const api={
  health:()=>request<{status:string;model_status:string;write_enabled:boolean}>('/health'),
  models:()=>request<{models:Model[]}>('/api/v1/models'),runtime:()=>request<Runtime>('/api/v1/console/runtime'),
  alerts:(query='')=>request<AlertPage>('/api/v1/alerts?'+query),
  alert:(aid:string)=>request<{alert:Alert;flow:Flow}>('/api/v1/alerts/'+id(aid)),
  flow:(rid:string)=>request<Flow>('/api/v1/flows/'+id(rid,64)),
  evidence:(aid:string,offset=0)=>request<EvidencePage>(`/api/v1/alerts/${id(aid)}/evidence?window_seconds=30&limit=10&offset=${offset}`),
  predict:(record_id:string,model_id:ModelId)=>request<Prediction>('/api/v1/predictions/by-record',{record_id:id(record_id,64),model_id}),
  investigations:(aid?:string)=>request<InvestigationList>('/api/v1/console/investigations'+(aid?'?alert_id='+id(aid):'')),
  gemini:()=>request<GeminiStatus>('/api/v1/console/gemini'),
  start:(alert_id:string,mode:InvestigationMode='offline')=>request<Investigation>('/api/v1/investigations',{alert_id:id(alert_id),mode},true),
  investigation:(iid:string)=>request<Investigation>('/api/v1/investigations/'+id(iid)),
  resume:(iid:string,body:{request_id:string;expected_checkpoint:string})=>request<Investigation>(`/api/v1/investigations/${id(iid)}/resume`,body,true),
  report:(iid:string)=>request<Report>(`/api/v1/investigations/${id(iid)}/report`),
  investigationEvidence:(iid:string)=>request<EvidenceView>(`/api/v1/console/investigations/${id(iid)}/evidence`),
  review:(iid:string,body:ReviewInput)=>request<Investigation>(`/api/v1/investigations/${id(iid)}/review`,body,true)
};
