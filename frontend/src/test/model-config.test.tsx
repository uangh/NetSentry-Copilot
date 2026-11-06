import {render,screen} from '@testing-library/react';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {it,expect,vi} from 'vitest';
import {api} from '../api';
import {ModeSelector} from '../gemini';
it.each([['gemini-3.1-flash-lite','default'],['gemini-3.5-flash-lite','environment:NETSENTRY_GEMINI_MODEL']])('reads %s and source from backend',async(model,source)=>{
 vi.spyOn(api,'gemini').mockResolvedValue({provider:'Google Gemini',configured:false,ready:false,generation_verified:false,model:null,requested_model:model,config_source:source,status:'missing_api_key',models:[]});
 render(<QueryClientProvider client={new QueryClient()}><ModeSelector mode="offline" onChange={()=>{}}/></QueryClientProvider>);
 expect(await screen.findByText(new RegExp(model.replaceAll('.','\\.')))).toHaveTextContent(source);
 expect(screen.getByRole('option',{name:'Gemini LLM Agent'})).toBeDisabled();vi.restoreAllMocks();
});
