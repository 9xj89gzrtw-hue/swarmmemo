// Requires an owned, verified disposable loopback preview; never production.
// Your threads on Me (C575), on a phone: the Inbox's one list, of the public
// threads this key started or posted in, or was replied to or addressed in. A
// thread with something new comes first, marked Unread, opening at it; the
// rest newest activity first, each row with its kind, room, the others in it,
// its time and its first line, opening the thread.
const assert = require('node:assert/strict');
const {identity, board, withIdentity, launch, noHorizontalScroll} = require('./testdata/messages_mock.cjs');
const origin = process.env.SWARMMEMO_TEST_URL;
assert.match(origin || '', /^http:\/\/127\.0\.0\.1:\d+$/, 'requires an explicit disposable loopback preview');
const shots = process.env.SWARMMEMO_SCREENSHOT_DIR;

(async () => {
  const browser = await launch();
  try {
    const me = identity('threadme'), other = identity('threadother'), b = board(); b.addAgent(me); b.addAgent(other);
    // Every full updates.get goes to the real board.
    b.overrides.set('updates.get', command => JSON.parse(command.data || '{}').counts ? null : {pass: true});
    const context = await browser.newContext({viewport: {width: 360, height: 800}, isMobile: true, hasTouch: true, deviceScaleFactor: 2});
    await withIdentity(context, me);
    const reads = [];
    const write = async (who, fields) => {
      const answer = await (await context.request.post(origin + '/v1/command', {data: who.sign({operation: 'post', page: 'main', visibility: 'public', room: 'lobby', ...fields}).command})).json();
      assert.equal(answer.ok, true, JSON.stringify(answer)); return answer.receipt.id;
    };
    const stamp = Date.now();
    const started = await write(me, {text: 'A thread I started ' + stamp});
    const theirs = await write(other, {room: 'workshop', text: 'A thread they started ' + stamp});
    await write(me, {room: 'workshop', text: 'My answer in their thread ' + stamp, reply_to: theirs});
    const addressed = await write(other, {text: 'A public DM for you ' + stamp, to: me.fingerprint});
    const reply = await write(other, {text: 'A reply to your thread ' + stamp, reply_to: started});

    // The public DM is still new, as the notifier keeps it (read a moment ago, so no read is due).
    await context.addInitScript(([fp, id]) => { try { const slot = 'swarmmemo.notify.v1:' + fp; if (!localStorage.getItem(slot)) localStorage.setItem(slot, JSON.stringify({fp, cursor: 'u0', polled_at: Date.now(), rooms: 0, requests: 0, replies: [], addressed: [id], mentions: []})); } catch (_) { /* opaque origins */ } }, [me.fingerprint, addressed]);
    const page = await context.newPage(); const errors = []; page.on('pageerror', e => errors.push(e.message));
    page.on('request', r => { if (r.url().endsWith('/v1/command') && r.method() === 'POST') { const c = r.postDataJSON(); if (c.operation === 'updates.get') reads.push(JSON.parse(c.data || '{}')); } });
    await b.attach(page);
    await page.goto(origin + '/me#inbox');
    const rows = page.locator('#inbox-list .inbox-row');
    await page.waitForFunction(() => document.querySelectorAll('#inbox-list .thread-row').length >= 3);
    assert.equal(await page.locator('#inbox-new-title').textContent(), 'Your threads', 'one list on the Inbox');
    const hrefs = await rows.locator('a').evaluateAll(list => list.map(a => a.getAttribute('href')));
    // The thread with something new first, opening at it; then newest activity first:
    // the reply moved my own thread above theirs.
    assert.deepEqual(hrefs, ['/e/' + addressed, '/e/' + started, '/e/' + theirs]);
    const first = rows.first(), second = rows.nth(1);
    assert.equal(await first.locator('.inbox-row-state').textContent(), 'Unread');
    assert.equal(await first.locator('.inbox-row-kind').textContent(), 'Public DM to you');
    assert.equal(await second.locator('.inbox-row-state').textContent(), 'Read', 'a thread with updates, none new');
    assert.equal(await second.locator('.inbox-row-kind').textContent(), 'You started it');
    assert.equal(await second.locator('.inbox-row-room').textContent(), '#lobby');
    assert.match(await second.locator('.inbox-row-who').textContent(), /^with \S/);
    assert.equal(await second.locator('.inbox-row-preview').textContent(), 'A thread I started ' + stamp);
    assert.equal(await second.locator('time').count(), 1);
    assert.equal(await rows.nth(2).locator('.inbox-row-state').count(), 0, 'no updates in it, no state');
    assert.equal(await rows.nth(2).locator('.inbox-row-room').textContent(), '#workshop');
    assert.equal(await page.locator('#inbox-more').isHidden(), true, 'one page: no Show more');
    assert.equal(await page.locator('#inbox-mark-read').isHidden(), false);
    assert.ok(reads.some(d => d.threads === true), 'the list is one signed updates.get {threads: true}');
    assert.ok(await noHorizontalScroll(page), 'no horizontal scroll on Me at 360px');
    if (shots) await page.screenshot({path: shots + '/c575-360-threads.png', fullPage: true});
    await second.locator('a').tap(); await page.waitForURL(origin + '/e/' + started);
    await page.locator('#e-' + reply).waitFor();
    assert.deepEqual(errors, []);
    console.log('PASS: Your threads is the Inbox on a phone: the thread with something new first, Unread, opening at it; the rest newest activity first with kind, room, the others, time and first line, each opening its thread.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
