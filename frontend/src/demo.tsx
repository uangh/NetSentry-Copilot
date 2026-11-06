import {useQuery} from '@tanstack/react-query';
import {api} from './api';
export function DemoBanner(){
 const {data}=useQuery({queryKey:['runtime'],queryFn:api.runtime});
 const names:Record<string,string>={enhanced_rules:'enhanced_rules · 本地真实数据规则调查 · 不调用 Gemini',saved_live_replay:'saved_live_replay · 历史真实记录只读回放 · 不发起新生成',live_gemini:'live_gemini · 本次显式启动的真实模型调查'};
 const title=data?.demo_mode&&names[data.demo_mode];
 return title?<section role="status" aria-label="演示执行模式" className="notice"><strong>{title}</strong><p>{data?.demo_origin}</p></section>:null;
}
