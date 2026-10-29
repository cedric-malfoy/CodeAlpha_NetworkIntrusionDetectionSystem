const {test,before,after}=require('node:test');
const assert=require('node:assert/strict');
const {spawn}=require('node:child_process');
const {createInterface}=require('node:readline');
const {once}=require('node:events');
const path=require('node:path');
const fs=require('node:fs');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'..'),artifacts=path.join(root,'artifacts');
let fixture,browser,url;
before(async()=>{
  fs.mkdirSync(artifacts,{recursive:true});
  fixture=spawn(process.env.PYTHON||path.join(root,'.venv/bin/python'),['tools/browser_fixture.py'],{cwd:root,stdio:['pipe','pipe','pipe']});fixture.stderr.resume();
  url=await new Promise((resolve,reject)=>{const lines=createInterface({input:fixture.stdout});const timeout=setTimeout(()=>reject(new Error('Fixture readiness timeout')),30000);fixture.once('error',reject);fixture.once('exit',code=>{if(!url)reject(new Error('Fixture exited '+code));});lines.once('line',line=>{clearTimeout(timeout);lines.close();resolve(JSON.parse(line).url);});});
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||(fs.existsSync('/usr/bin/chromium')?'/usr/bin/chromium':undefined),headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
});
after(async()=>{await browser?.close();if(fixture&&fixture.exitCode===null){const closed=once(fixture,'close');fixture.stdin.end();await closed;}});
async function pageFor(t,width=1440){const context=await browser.newContext({viewport:{width,height:1050}});t.after(()=>context.close());const page=await context.newPage();await page.goto(url);await page.locator('#alerts tr').first().waitFor();return page;}
test('overview renders real alerts and escaped source data without script errors',async t=>{
 const page=await pageFor(t),errors=[];page.on('pageerror',error=>errors.push(error.message));
 assert.equal(await page.title(),'Signalwatch · Custom ML IDS');
 assert.equal(await page.locator('#status').innerText(),'Replay complete');
 assert.equal(await page.evaluate(()=>window.pwned),undefined);
 assert.match(await page.locator('#alerts').innerText(),/<script>window.pwned=true<\/script>/);
 await page.getByRole('button',{name:'Inspect detection 1',exact:true}).click();await page.locator('#detail[open]').waitFor();
 await page.getByRole('button',{name:'Close detection details'}).click();assert.deepEqual(errors,[]);
});
test('severity, source, signature, and detector filters work and can be cleared',async t=>{
 const page=await pageFor(t);
 await page.getByLabel('Filter by severity').selectOption('1');await page.waitForTimeout(500);
 const values=await page.locator('#alerts .badge.high').count();assert.ok(values>0);
 await page.getByLabel('Filter by source').fill('no-such-source');await page.locator('#alerts-empty').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Clear filters',exact:true}).click();await page.locator('#alerts tr').first().waitFor();
 await page.getByLabel('Filter by detector').selectOption('Both');await page.waitForTimeout(500);assert.ok(await page.locator('#alerts tr').count()>0);
 await page.getByLabel('Filter by signature').selectOption('CUSTOM-004');await page.waitForTimeout(500);assert.match(await page.locator('#alerts').innerText(),/traversal/i);
});
test('incident and model routes expose evidence, including public false positives',async t=>{
 const page=await pageFor(t);await page.getByRole('link',{name:/Incidents/}).click();await page.locator('#view-incidents').waitFor({state:'visible'});assert.ok(await page.locator('#incidents tr').count()>0);
 await page.getByRole('link',{name:/Model card/}).click();await page.locator('#view-model').waitFor({state:'visible'});
 assert.match(await page.locator('#model-version').innerText(),/custom-rf-v1/);assert.match(await page.locator('#public-metrics').innerText(),/15\.4%/);assert.match(await page.locator('#baseline-results').innerText(),/Majority baseline/);
});
test('new incidents appear through two-second refresh without a page reload',async t=>{
 const page=await pageFor(t);fixture.stdin.write('add\n');await page.getByLabel('Filter by source').fill('192.0.2.250');await page.waitForFunction(()=>document.querySelector('#alerts').textContent.includes('192.0.2.250'),null,{timeout:6000});
});
test('keyboard access and all dashboard views fit 320, 390, 768, and 1440 pixels',async t=>{
 const page=await pageFor(t);
 for(const width of [320,390,768,1440]){await page.setViewportSize({width,height:1050});await page.goto(url);await page.locator('#alerts tr').first().waitFor();await page.keyboard.press('Tab');assert.equal(await page.evaluate(()=>document.activeElement.textContent),'Skip to content');await page.locator('h1').click();
   for(const view of ['overview','incidents','model']){await page.goto(url+'/#/'+view);await page.locator('#view-'+view).waitFor({state:'visible'});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`${view} at ${width}`);}
   await page.goto(url+'/#/overview');await page.locator('#view-overview').waitFor({state:'visible'});if(width===390||width===1440)await page.screenshot({path:path.join(artifacts,`dashboard-${width}.png`),fullPage:true});
 }
});
