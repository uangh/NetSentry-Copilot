import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {it,expect,vi} from 'vitest';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {RecoveryPanel} from '../recovery';
import {api} from '../api';
import {GeminiTelemetry} from '../gemini';
import type {GeminiExecution} from '../types';
import type {Investigation} from '../types';
const state={investigation_id:'a'.repeat(32),recovery:{checkpoint_id:'checkpoint',eligible:true,can_resume:true,read_only:false,failure:{source:'provider',stage:'planning',code:'provider_unavailable',http_status:503},last_completed_step:'validate_context',saved_observations:2,calls_used:1,generation_limit:6,known_total_tokens:0,unknown_usage_requests:1,active_seconds_remaining:268,attempts:[]}} as unknown as Investigation;
function show(s=state){render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false},mutations:{retry:false}}})}><RecoveryPanel state={s}/></QueryClientProvider>)}
it('shows provider failure separately with saved observations and unknown usage',()=>{show();expect(screen.getByText(/Provider unavailable/)).toHaveTextContent('503');expect(screen.getByText(/Saved observations/)).toHaveTextContent('2');expect(screen.getByText(/次用量未知/)).toHaveTextContent('1')});
it('read-only mode disables recovery',()=>{show({...state,recovery:{...state.recovery!,read_only:true,can_resume:false}});expect(screen.getByRole('button',{name:'Resume Investigation'})).toBeDisabled()});
it('does not offer recovery for a completed investigation',()=>{show({...state,recovery:{...state.recovery!,eligible:false,can_resume:false}});expect(screen.queryByRole('button',{name:'Resume Investigation'})).toBeNull()});
it('posts same investigation and checkpoint, then disables repeated pending clicks',async()=>{let finish:(s:Investigation)=>void=()=>{};const fn=vi.spyOn(api,'resume').mockImplementation(()=>new Promise(resolve=>{finish=resolve}));show();fireEvent.click(screen.getByRole('button',{name:'Resume Investigation'}));await waitFor(()=>expect(fn).toHaveBeenCalledOnce());expect(fn.mock.calls[0][0]).toBe(state.investigation_id);expect(fn.mock.calls[0][1].expected_checkpoint).toBe('checkpoint');expect(screen.getByRole('button')).toBeDisabled();finish(state);await waitFor(()=>expect(screen.getByRole('button')).not.toBeDisabled());fn.mockRestore()});
it('does not mislabel a current local contract failure using an older503',()=>{const execution={status:'failed',failure:'multistep_plan_failed',model:'synthetic',duration_ms:2,decisions:[],calls:[{request_number:1,status:'provider_unavailable',http_status:503,total_tokens:null},{request_number:2,status:'validated',total_tokens:2}]} as unknown as GeminiExecution;render(<GeminiTelemetry execution={execution}/>);expect(screen.getByText(/本地契约校验失败/)).not.toHaveTextContent('HTTP 503')});
