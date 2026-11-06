import {render,screen} from '@testing-library/react';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {test,expect,vi} from 'vitest';
import {DemoBanner} from '../demo';
import {api} from '../api';
test.each(['saved_live_replay','enhanced_rules','live_gemini'])('shows actual %s mode',async(mode)=>{
 vi.spyOn(api,'runtime').mockResolvedValue({demo_mode:mode,demo_origin:'synthetic test / not real API'} as Awaited<ReturnType<typeof api.runtime>>);
 render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><DemoBanner/></QueryClientProvider>);
 expect(await screen.findByRole('status',{name:'演示执行模式'})).toHaveTextContent(mode);
 vi.restoreAllMocks();
});
