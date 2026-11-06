import {test,expect} from '@playwright/test';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';

test('checkpoint recovery preserves identity and saved observations, or remains read-only',async({page,request})=>{
 test.setTimeout(310000);
 const iid=process.env.NETSENTRY_RECOVERY_IID!;const out=process.env.NETSENTRY_E2E_OUT!;mkdirSync(out,{recursive:true});
 const before=await (await request.get('/api/v1/investigations/'+iid)).json();let writes=0;page.on('request',r=>{if(r.method()==='POST')writes++});
 await page.goto('/investigations/'+iid);await expect(page.getByText('Checkpoint Recovery',{exact:true})).toBeVisible();
 if(process.env.NETSENTRY_RECOVERY_WRITE==='1'){
  await page.getByRole('button',{name:'本地开发令牌',exact:true}).click();
  await page.getByLabel('写操作令牌').fill(process.env.NETSENTRY_TEST_TOKEN!);
  await page.getByRole('button',{name:'保存到内存',exact:true}).click();
  const response=page.waitForResponse(r=>r.url().endsWith('/'+iid+'/resume')&&r.request().method()==='POST',{timeout:290000});
  await page.getByRole('button',{name:'Resume Investigation',exact:true}).click();
  const result=await response;expect(result.status()).toBe(200);
  writeFileSync(join(out,'resume_response.json'),JSON.stringify(await result.json(),null,2));
  await expect(page.getByText('正在恢复已保存调查…')).toHaveCount(0,{timeout:10000});
  expect(writes).toBe(1);
 }else{expect(writes).toBe(0);await expect(page.getByText('只读演示：恢复操作不可用。')).toBeVisible()}
 const after=await (await request.get('/api/v1/investigations/'+iid)).json();expect(after.investigation_id).toBe(before.investigation_id);
 expect(after.observation_registry.slice(0,before.observation_registry.length)).toEqual(before.observation_registry);
 expect(after.gemini.calls.slice(0,before.gemini.calls.length)).toEqual(before.gemini.calls);
 await page.screenshot({path:join(out,'recovery_workspace.png'),fullPage:true});
 if(after.report){expect(after.review_status).toBe('pending_review');expect(after.interrupted).toBeTruthy();await page.getByRole('link',{name:'打开报告与审核'}).click();await expect(page.getByRole('button',{name:'Approve Report',exact:true})).toBeEnabled();await page.screenshot({path:join(out,'pending_report.png'),fullPage:true})}
 expect(writes).toBe(process.env.NETSENTRY_RECOVERY_WRITE==='1'?1:0);
});
