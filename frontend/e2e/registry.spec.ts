import {test,expect} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
test('scoped observation registry and evidence feedback replay without writes',async({page,request})=>{
 const cases=JSON.parse(process.env.NETSENTRY_M631_CASES||'[]');expect(cases.length).toBeGreaterThan(0);
 const out=process.env.NETSENTRY_E2E_OUT!;mkdirSync(out,{recursive:true});let writes=0;
 page.on('request',r=>{if(r.method()==='POST')writes++});
 for(const item of cases){
  const state=await (await request.get('/api/v1/investigations/'+item.investigation_id)).json();
  await page.goto('/investigations/'+item.investigation_id);
  await expect(page.getByText('观察引用注册表与真实来源映射')).toBeVisible();
  expect(state.observation_registry.length).toBeGreaterThanOrEqual(2);
  for(const d of state.decision_trace){
   await expect(page.getByText(/本轮合法观察引用/).filter({hasText:d.observation_ids_used[0]}).first()).toBeVisible();
   expect(d.observation_ids_used.every((id:string)=>state.observation_registry.some((o:{observation_id:string})=>o.observation_id===id))).toBeTruthy();
  }
  await page.screenshot({path:join(out,item.case_id+'_registry.png'),fullPage:true});
  if(state.report){expect(state.review_status).toBe('pending_review');expect(state.interrupted).toBeTruthy();await page.getByRole('link',{name:'打开报告与审核'}).click();await expect(page.getByRole('button',{name:'Approve Report',exact:true})).toBeEnabled();await page.screenshot({path:join(out,item.case_id+'_report.png'),fullPage:true})}
 }
 expect(writes).toBe(0);
});
