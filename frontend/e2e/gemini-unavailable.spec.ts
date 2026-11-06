import {test,expect} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
test('Gemini catalog status and unavailable mode are truthful',async({page,request})=>{
 const r=await request.get('/api/v1/console/gemini');expect(r.ok()).toBeTruthy();const status=await r.json();
 await page.goto('/alerts/d921f53d7ed74100b814e6027fe6cc1f');
 const option=page.getByRole('option',{name:'Gemini LLM Agent'});
 await expect(option).toHaveJSProperty('disabled',!status.ready);
 await expect(page.getByText(/Provider: Google Gemini/)).toContainText(status.status);
 mkdirSync(process.env.NETSENTRY_E2E_OUT!,{recursive:true});
 await page.screenshot({path:join(process.env.NETSENTRY_E2E_OUT!,'gemini-status.png'),fullPage:true});
});
