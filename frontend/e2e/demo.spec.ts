import {test,expect} from '@playwright/test';
test('explicit demo mode and saved actual investigation without browser writes',async({page,request})=>{
 const iid=process.env.NETSENTRY_DEMO_IID!;
 const runtime=await (await request.get('/api/v1/console/runtime')).json();
 const state=await (await request.get('/api/v1/investigations/'+iid)).json();
 let writes=0;page.on('request',r=>{if(r.method()==='POST')writes++});
 await page.goto('/investigations/'+iid);
 await expect(page.getByRole('status',{name:'演示执行模式'})).toContainText(runtime.demo_mode);
 if(state.gemini?.model)await expect(page.getByText(state.gemini.model,{exact:false}).first()).toBeVisible();
 if(state.report){await page.getByRole('link',{name:'打开报告与审核'}).click();await expect(page.getByRole('button',{name:'Approve Report',exact:true})).toBeEnabled()}
 else await expect(page.getByText('PARTIALLY_VERIFIED',{exact:false}).first()).toBeVisible();
 await page.screenshot({path:process.env.NETSENTRY_E2E_OUT+'/demo.png',fullPage:true});
 expect(writes).toBe(0);
});
