import {render,screen} from '@testing-library/react';
import {it,expect,vi} from 'vitest';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {GeminiTelemetry,ModeSelector} from '../gemini';
import {api} from '../api';
it('does not report unavailable while provider status is loading',()=>{
 vi.spyOn(api,'gemini').mockImplementation(()=>new Promise(()=>{}));
 render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><ModeSelector mode="offline" onChange={()=>{}}/></QueryClientProvider>);
 expect(screen.getByText(/正在读取后端连接状态/)).toBeInTheDocument();expect(screen.queryByText(/Gemini 当前不可用/)).not.toBeInTheDocument();
});
it('discloses partially verified synthetic execution without a validated report',()=>{
 render(<GeminiTelemetry execution={{provider:'Google Gemini',model:'synthetic',status:'failed',verification_status:'PARTIALLY_VERIFIED',live_provider_verified:false,generation_verified:true,report_validated:false,duration_ms:400,calls:[{request_number:2,purpose:'narrative',model:'synthetic',status:'gateway_timeout',duration_ms:200,input_tokens:null,output_tokens:null,total_tokens:null,http_attempt_count:1,http_status:504,provider_message:'synthetic timeout'}],decisions:[{iteration:1,reason:'inspect_candidate_relations',actions:[{tool:'query_related_evidence'}]}],step_timings:[{step:'execute_tool',duration_ms:20}]}}/>);
 expect(screen.getByText('PARTIALLY_VERIFIED')).toBeInTheDocument();expect(screen.getByText(/仅部分步骤通过/)).toBeInTheDocument();expect(screen.getByText(/尚不能宣称完整调查成功/)).toBeInTheDocument();expect(screen.getByText(/HTTP尝试 1/)).toHaveTextContent('HTTP 504');expect(screen.getByText(/报告引用校验/)).toHaveTextContent('未通过');
});
