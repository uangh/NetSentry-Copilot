import {test,expect} from '@playwright/test';
test('portable real data, model identity, evidence, deep links, and no writes',async({page,request})=>{
 const iid=process.env.NETSENTRY_DEMO_IID!;
 const state=await (await request.get('/api/v1/investigations/'+iid)).json();
 const runtime=await (await request.get('/api/v1/console/runtime')).json();
 const provider=await (await request.get('/api/v1/console/gemini')).json();
 expect(provider.ready).toBe(false);expect(provider.requested_model).toBe('gemini-3.1-flash-lite');
 expect(state.gemini.model).toBe(process.env.NETSENTRY_EXPECTED_MODEL);
 const writes:string[]=[];page.on('request',r=>{if(r.method()!=='GET')writes.push(r.url())});
 await page.goto('/');await expect(page.getByRole('heading',{name:'让每一次判断，都有证据。'})).toBeVisible();
 await expect(page.getByText(runtime.rows.toLocaleString('en-US'),{exact:true})).toBeVisible();
 await page.goto('/alerts/'+state.alert_id);await expect(page.getByText('F2_logistic',{exact:false}).first()).toBeVisible();
 await page.goto('/investigations/'+iid);
 await expect(page.getByRole('status',{name:'演示执行模式'})).toContainText('saved_live_replay');
 await expect(page.getByRole('heading',{name:'Investigation Decision Timeline'})).toBeVisible();
 expect(await page.locator('.decision-round').count()).toBe(state.decision_trace.length);
 await expect(page.getByText(state.gemini.model,{exact:false}).first()).toBeVisible();
 for(const d of state.decision_trace){
  expect(d.observation_ids_used.every((id:string)=>state.observation_registry.some((o:{observation_id:string})=>o.observation_id===id))).toBeTruthy();
  await expect(page.getByRole('heading',{name:`Round ${d.iteration} · ${d.question}`,exact:true})).toBeVisible();
 }
 const evidence=await (await request.get('/api/v1/console/investigations/'+iid+'/evidence')).json();
 expect(evidence.anchor.record_id.length).toBe(64);expect(evidence.tool_call_trace.length).toBeGreaterThan(2);
 if(state.report){
  expect(state.decision_trace.length).toBe(3);expect(state.review_status).toBe('pending_review');expect(state.interrupted).toBeTruthy();
  expect(state.report.score_is_calibrated_probability).toBe(false);
  await page.goto('/investigations/'+iid+'/report');await page.reload();
  await expect(page.getByRole('heading',{name:'调查报告与人工审核'})).toBeVisible();
  await page.getByRole('button',{name:'查看来源 ↗',exact:true}).first().click();
  await expect(page.getByRole('dialog',{name:'实际证据来源'})).toBeVisible();await page.getByRole('button',{name:'关闭',exact:true}).click();
 }else await expect(page.getByText('PARTIALLY_VERIFIED',{exact:false}).first()).toBeVisible();
 await page.screenshot({path:process.env.NETSENTRY_E2E_OUT+'/portable.png',fullPage:true});expect(writes).toEqual([]);
});

test('API 404 stays JSON and docs/OpenAPI keep their routes',async({request})=>{
 const missing=await request.get('/api/v1/does-not-exist');expect(missing.status()).toBe(404);expect(missing.headers()['content-type']).toContain('application/json');
 expect((await request.get('/openapi.json')).status()).toBe(200);
 expect((await request.get('/docs')).status()).toBe(200);
 if(process.env.NETSENTRY_SERVING==='static'){
  expect((await request.get('/assets/missing.js')).status()).toBe(404);
  expect((await request.get('/outputs/m3/runtime/events.sqlite')).status()).toBe(404);
 }
});
