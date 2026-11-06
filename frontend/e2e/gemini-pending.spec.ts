import {test,expect} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
test('real Gemini report remains pending review after read-only browser inspection',async({page,request})=>{
 const iid=process.env.NETSENTRY_M61_INVESTIGATION;expect(iid).toMatch(/^[a-f0-9]{32}$/);
 const url='/api/v1/investigations/'+iid;const before=await (await request.get(url)).json();
 expect(before.gemini.live_provider_verified).toBe(true);expect(before.gemini.verification_status).toBe('VERIFIED');expect(before.review_status).toBe('pending_review');expect(before.review_history).toEqual([]);
 const writes:string[]=[];page.on('request',r=>{if(r.method()==='POST')writes.push(r.url())});
 await page.goto('/investigations/'+iid);await expect(page.getByRole('heading',{name:'Gemini 实际执行'})).toBeVisible();
 await expect(page.getByText(before.gemini.model,{exact:true}).first()).toBeVisible();await expect(page.getByText('VERIFIED',{exact:true})).toBeVisible();
 await expect(page.getByText(/已知 Tokens/)).toBeVisible();await expect(page.getByRole('heading',{name:'真实工具调用轨迹'})).toBeVisible();
 const out=process.env.NETSENTRY_E2E_OUT!;mkdirSync(out,{recursive:true});await page.screenshot({path:join(out,'gemini-pending-workspace.png'),fullPage:true});
 await page.getByRole('link',{name:'打开报告与审核'}).click();await expect(page.getByText('gemini_llm',{exact:true}).first()).toBeVisible();await expect(page.getByText('insufficient_evidence',{exact:true})).toBeVisible();
 await expect(page.getByRole('button',{name:'查看来源 ↗',exact:true}).first()).toBeVisible();await page.screenshot({path:join(out,'gemini-pending-report.png'),fullPage:true});
 expect(writes).toEqual([]);const after=await (await request.get(url)).json();expect(after.review_status).toBe('pending_review');expect(after.review_history).toEqual([]);
});
