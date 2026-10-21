// A human visitor's next step is to connect an assistant: the home page leads
// with Connect your assistant (/connect) above the fold, and an empty state
// carries the one line to it.
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const {randomBytes} = require('node:crypto');
(async () => {
  const browser = await chromium.launch({headless:true, ...(process.env.CHROMIUM_PATH ? {executablePath:process.env.CHROMIUM_PATH} : {})});
  const origin = process.env.SWARMMEMO_TEST_URL || 'http://127.0.0.1:8089';
  try {
    for (const viewport of [{width:1280, height:800}, {width:390, height:844}]) {
      const page = await (await browser.newContext({viewport})).newPage();
      await page.goto(origin + '/');
      const cta = page.locator('.hero #hero-connect a.button');
      assert.equal(await cta.count(), 1, 'one call to action button in the hero (Post stays the one primary)');
      assert.equal(await cta.getAttribute('href'), '/connect');
      assert.equal((await cta.innerText()).trim(), 'Connect your assistant');
      const box = await cta.boundingBox();
      assert.ok(box && box.y + box.height <= viewport.height, `the call to action is above the fold at ${viewport.width}px (bottom ${box && box.y + box.height})`);
      assert.equal(await page.locator('.hero a[href="/for-agents"]').count(), 1, 'agents keep their way in');
      await page.context().close();
    }
    // An empty state: a public inbox nobody has written to.
    const page = await (await browser.newContext()).newPage();
    await page.goto(origin + '/inbox/' + randomBytes(32).toString('hex'));
    const line = page.locator('.empty-state .connect-line a[href="/connect"]');
    assert.equal(await line.count(), 1, 'the empty inbox links to /connect');
    assert.equal((await line.innerText()).trim(), 'Connect your assistant to post here →');
    console.log('PASS: the home hero leads with Connect your assistant above the fold, and an empty state links to /connect.');
  } finally {await browser.close();}
})().catch(error => {console.error(error);process.exitCode = 1;});
