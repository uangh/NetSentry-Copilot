import {test,expect} from '@playwright/test';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
// Only selected explicitly by the real smoke driver after a real Gemini investigation.
test('view real Gemini investigation and submit browser review',async({page,request})=>{
 const iid=process.env.NETSENTRY_GEMINI_INVESTIGATION;expect(iid,'real smoke investigation required').toMatch(/^[0-9a-f]{32}$/);
 const out=process.env.NETSENTRY_E2E_OUT!;mkdirSync(out,{recursive:true});
 const s=await (await request.get('/api/v1/investigations/'+iid)).json();
 expect(s.gemini.generation_verified).toBe(true);expect(s.gemini.status).toBe('completed');expect(s.review_status).toBe('pending_review');
 await page.goto('/investigations/'+iid);await expect(page.getByRole('heading',{name:'Gemini 实际执行'})).toBeVisible();
 await expect(page.getByText(s.gemini.model,{exact:true}).first()).toBeVisible();
 await page.screenshot({path:join(out,'gemini-workspace.png'),fullPage:true});
 await page.getByRole('button',{name:'本地开发令牌',exact:true}).click();await page.getByLabel('写操作令牌').fill(process.env.NETSENTRY_TEST_TOKEN!);await page.getByRole('button',{name:'保存到内存'}).click();
 await page.getByRole('link',{name:'打开报告与审核'}).click();await page.getByLabel('Reviewer Note / 审核意见').fill('AUTOMATED GEMINI BROWSER TEST: approve presentation only; not a human security conclusion.');
 await page.getByRole('button',{name:'Approve Report',exact:true}).click();await page.getByRole('button',{name:'确认并提交',exact:true}).click();
 await expect(page.getByText('报告已批准',{exact:true}).first()).toBeVisible();await page.reload();await expect(page.getByText('报告已批准',{exact:true}).first()).toBeVisible();
 const reviewed=await (await request.get('/api/v1/investigations/'+iid)).json();expect(reviewed.review_status).toBe('approved');expect(reviewed.report.hypothesis).toBe('insufficient_evidence');
 expect(reviewed.gemini.calls).toHaveLength(s.gemini.calls.length);writeFileSync(join(out,'review.json'),JSON.stringify(reviewed,null,2));
 await page.screenshot({path:join(out,'gemini-reviewed.png'),fullPage:true});
});
