import {test,expect} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
test('persisted multistep decisions and source-backed tool cards stay read only',async({page,request})=>{
 const cases=JSON.parse(process.env.NETSENTRY_M63_CASES||'[]');expect(cases.length).toBeGreaterThan(0);
 const out=process.env.NETSENTRY_E2E_OUT!;mkdirSync(out,{recursive:true});const writes:string[]=[];
 page.on('request',r=>{if(r.method()==='POST')writes.push(r.url())});
 for(const item of cases){
  const state=await (await request.get('/api/v1/investigations/'+item.investigation_id)).json();
  await page.goto('/investigations/'+item.investigation_id);
  await expect(page.getByRole('heading',{name:'Investigation Decision Timeline'})).toBeVisible();
  for(const d of state.decision_trace)await expect(page.getByRole('heading',{name:`Round ${d.iteration} · ${d.question}`,exact:true})).toBeVisible();
  expect(await page.locator('.decision-round').count()).toBe(state.decision_trace.length);
  await expect(page.getByText(/持久化决策回放/)).toBeVisible();
  await page.screenshot({path:join(out,item.case_id+'_'+item.mode+'_decisions.png'),fullPage:true});
  if(state.report){await page.getByRole('link',{name:'打开报告与审核'}).click();await expect(page.getByRole('heading',{name:'人工审核',exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'Approve Report',exact:true})).toBeEnabled();await page.screenshot({path:join(out,item.case_id+'_'+item.mode+'_report.png'),fullPage:true})}
 }
 expect(writes).toEqual([]);
});
