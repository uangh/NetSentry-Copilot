import {test,expect} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
test('frozen real cases show evidence coverage and readable pending reports',async({page,request})=>{
 const cases=JSON.parse(process.env.NETSENTRY_M62_CASES||'[]');expect(cases.length).toBeGreaterThan(0);
 const out=process.env.NETSENTRY_E2E_OUT!;mkdirSync(out,{recursive:true});const writes:string[]=[];page.on('request',r=>{if(r.method()==='POST')writes.push(r.url())});
 for(const item of cases){
   await page.goto('/investigations/'+item.investigation_id);
   const evidence=await (await request.get('/api/v1/console/investigations/'+item.investigation_id+'/evidence')).json();
   await expect(page.getByRole('heading',{name:'Evidence 覆盖与记录'})).toBeVisible();
   if(evidence.records.length||evidence.queried_flows?.length)await expect(page.getByText('记录标识与来源详情').first()).toBeVisible();
   await page.screenshot({path:join(out,item.case_id+'_'+item.mode+'_evidence.png'),fullPage:true});
   const state=await (await request.get('/api/v1/investigations/'+item.investigation_id)).json();
   if(state.gemini?.verification_status==='PARTIALLY_VERIFIED')await expect(page.getByText('PARTIALLY_VERIFIED',{exact:true})).toBeVisible();
   if(state.report){await page.getByRole('link',{name:'打开报告与审核'}).click();await expect(page.getByRole('heading',{name:'证据不足以确认攻击，等待人工复核'})).toBeVisible();await page.screenshot({path:join(out,item.case_id+'_'+item.mode+'_report.png'),fullPage:true})}
 }
 expect(writes).toEqual([]);
});
