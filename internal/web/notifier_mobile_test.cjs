// Requires an owned, verified disposable loopback preview; never production.
// The header and the Inbox on a phone with new replies (C181, C184): one header
// row, with Me in the corner carrying a count; Me opens Me at its Inbox, where
// the thread with the new replies comes first (Unread, the others in it, its
// first line), opening at its newest new reply, where the reply is loaded
// (even past the conversation's first page and deeper than the page indents),
// centred and marked New. Once read, the count clears and the thread stays
// listed, marked Read.
const assert = require('node:assert/strict');
const {identity, board, withIdentity, launch, noHorizontalScroll} = require('./testdata/messages_mock.cjs');
const origin = process.env.SWARMMEMO_TEST_URL;
assert.match(origin || '', /^http:\/\/127\.0\.0\.1:\d+$/, 'requires an explicit disposable loopback preview');
const shots = process.env.SWARMMEMO_SCREENSHOT_DIR;

(async () => {
  const browser = await launch();
  try {
    const me = identity('pliplop'), other = identity('quill'), b = board(); b.addAgent(me); b.addAgent(other);
    // The notifier's counts read is the mock's; the Inbox's full read goes to the real board.
    b.overrides.set('updates.get', command => JSON.parse(command.data || '{}').counts ? null : {pass: true});
    const context = await browser.newContext({viewport: {width: 360, height: 800}, isMobile: true, hasTouch: true, deviceScaleFactor: 2});
    await withIdentity(context, me);
    // Real signed posts, so the board's own inbox read (updates.get) finds the replies.
    const write = async (who, text, reply_to) => {
      const answer = await (await context.request.post(origin + '/v1/command', {data: who.sign({operation: 'post', room: 'lobby', page: 'main', visibility: 'public', text, ...(reply_to ? {reply_to} : {})}).command})).json();
      assert.equal(answer.ok, true, JSON.stringify(answer)); return answer.receipt.id;
    };
    // My post, then a long conversation under it: 44 replies by another agent
    // (the last past the first page of 40), then a chain of 7 under that last one,
    // deeper than the page indents (5), alternating authors so each answers mine.
    const stamp = Date.now(), root = await write(me, 'My long conversation for the phone ' + stamp);
    let late = '';
    for (let i = 1; i <= 44; i++) late = await write(other, 'Reply ' + i + ' of a long conversation ' + stamp, root);
    let deep = late, mine = late;
    for (let d = 1; d <= 6; d++) { mine = await write(d % 2 ? other : me, 'Deep reply ' + d + ' ' + stamp, deep); deep = mine; }
    deep = await write(other, 'The deepest reply ' + stamp, deep);
    // Two new replies for this key, as the notifier keeps them (read a moment ago, so no read is due).
    await context.addInitScript(([fp, ids]) => { try { const slot = 'swarmmemo.notify.v1:' + fp; if (!localStorage.getItem(slot)) localStorage.setItem(slot, JSON.stringify({fp, cursor: 'u0', polled_at: Date.now(), rooms: 0, requests: 0, replies: ids, addressed: [], mentions: []})); } catch (_) { /* opaque origins */ } }, [me.fingerprint, [late, deep]]);
    const page = await context.newPage(); const errors = []; page.on('pageerror', e => errors.push(e.message));
    await b.attach(page);

    // One header row: the brand and Me, Me carrying the count. No second control.
    await page.goto(origin + '/?sort=new');
    const meLink = page.locator('.workspace-link'), count = page.locator('#me-count');
    await count.waitFor({state: 'visible'});
    assert.equal(await count.textContent(), '2');
    assert.equal(await count.getAttribute('aria-label'), '2 new in your inbox');
    assert.equal(await page.locator('header.topbar').getByText(/repl/i).count(), 0, 'no reply pill in the header');
    const [brand, mine2] = [await page.locator('header.topbar .brand').boundingBox(), await meLink.boundingBox()];
    assert.ok(Math.abs((brand.y + brand.height / 2) - (mine2.y + mine2.height / 2)) < 8, 'Me sits on the brand row, top right');
    assert.ok(mine2.x + mine2.width <= 360 && mine2.height >= 32, 'Me is on screen and a tap target');
    assert.ok(await noHorizontalScroll(page), 'no horizontal scroll at 360px');
    assert.equal(await meLink.getAttribute('href'), '/me#inbox-new', 'with news, Me opens Me at the Inbox');
    if (shots) await page.screenshot({path: shots + '/c184-after-360-feed.png'});

    // Me opens Me at the Inbox: its thread first, Unread, with kind, the others in it and
    // its first line, opening at the newest new reply (Your threads, C575).
    await meLink.tap(); await page.waitForURL(origin + '/me#inbox-new');
    const rows = page.locator('#inbox-list .inbox-row');
    await page.waitForFunction(() => document.querySelectorAll('#inbox-list .inbox-unread .inbox-row-who').length === 1);
    assert.equal(await page.locator('#me-tabs [aria-selected="true"]').textContent(), 'Inbox2');
    const first = rows.first();
    assert.equal(await first.locator('.inbox-row-state').textContent(), 'Unread');
    assert.equal(await first.locator('.inbox-row-kind').textContent(), 'Reply to you');
    assert.match(await first.locator('.inbox-row-who').textContent(), /^with \S/, 'the others in the thread');
    assert.match(await first.locator('.inbox-row-preview').textContent(), /^My long conversation for the phone/);
    assert.equal(await first.locator('a').getAttribute('href'), '/e/' + deep, 'the thread opens at its newest new reply');
    assert.equal(await rows.count(), 1, 'both replies are in the one thread');
    const box = await first.boundingBox();
    assert.ok(box.y >= 0 && box.y + box.height <= 800, 'the thread is on screen without scrolling');
    assert.ok(await page.locator('#me-tabs a[href="#more"]').count() === 1, 'Settings is one tap away on Me');
    assert.ok(await noHorizontalScroll(page), 'no horizontal scroll on Me at 360px');
    if (shots) await page.screenshot({path: shots + '/c184-after-360-me.png'});

    const centred = id => page.waitForFunction(id => { const r = document.getElementById('e-' + id).getBoundingClientRect(), mid = r.top + Math.min(r.height, innerHeight) / 2; return r.top >= 0 && Math.abs(mid - innerHeight / 2) < innerHeight / 4; }, id);
    const marked = async id => {
      const el = page.locator('#e-' + id);
      assert.ok(await el.evaluate(n => n.classList.contains('memo-focus') && n.classList.contains('memo-new')), 'the reply is highlighted');
      assert.equal(await el.locator('.memo-new-label').textContent(), 'New reply');
    };
    // The reply deeper than the page indents: its branch, with the way back up.
    await first.locator('a').tap(); await page.waitForURL(origin + '/e/' + deep);
    await page.locator('#e-' + deep).waitFor();
    assert.ok(await page.locator('a', {hasText: 'The whole conversation'}).count() > 0, 'a branch page links the whole conversation');
    await centred(deep); await marked(deep);
    await page.waitForFunction(() => document.getElementById('me-count').textContent === '1');

    // Back to the Inbox: the thread is still Unread, now opening at the other reply.
    await meLink.tap(); await page.waitForURL(origin + '/me#inbox-new');
    await page.waitForFunction(id => document.querySelector('#inbox-list .inbox-unread a')?.getAttribute('href') === '/e/' + id, late);
    // The reply past the first page: the conversation reads on to it.
    await page.locator('#inbox-list a[href="/e/' + late + '"]').tap(); await page.waitForURL(origin + '/e/' + late);
    await page.locator('#e-' + late).waitFor();
    assert.ok(await page.locator('#thread article.memo').count() > 40, 'the conversation is read on past its first page to the reply');
    await centred(late); await marked(late);
    if (shots) await page.screenshot({path: shots + '/c184-after-360-reply.png'});
    // Both read: the count clears, Me is plain Me, and the Inbox keeps the thread, marked Read.
    await count.waitFor({state: 'hidden'});
    assert.equal(await meLink.getAttribute('href'), '/me');
    await meLink.tap(); await page.waitForURL(origin + '/me');
    await page.waitForFunction(() => document.querySelectorAll('#inbox-list .inbox-row').length === 1);
    assert.equal(await page.locator('#inbox-list .inbox-unread').count(), 0);
    assert.equal(await page.locator('#inbox-list a[href="/e/' + root + '"] .inbox-row-state').textContent(), 'Read');
    assert.equal(await page.locator('#inbox-mark-read').isHidden(), true);
    if (shots) await page.screenshot({path: shots + '/c184-after-360-me-read.png'});

    // Desktop: the same one control; Mark all read clears it.
    const wide = await browser.newContext({viewport: {width: 1280, height: 800}}); await withIdentity(wide, me);
    await wide.addInitScript(([fp, id]) => { try { localStorage.setItem('swarmmemo.notify.v1:' + fp, JSON.stringify({fp, cursor: 'u0', polled_at: Date.now(), rooms: 1, requests: 0, replies: [id], addressed: [], mentions: []})); } catch (_) { /* opaque origins */ } }, [me.fingerprint, late]);
    const desk = await wide.newPage(); await b.attach(desk); desk.on('pageerror', e => errors.push(e.message));
    await desk.goto(origin + '/rooms');
    await desk.locator('#me-count').waitFor({state: 'visible'});
    assert.equal(await desk.locator('#me-count').textContent(), '2');
    assert.equal(await desk.locator('.workspace-link').getAttribute('href'), '/me#inbox-new');
    if (shots) await desk.locator('header.topbar').screenshot({path: shots + '/c184-after-1280-header.png'});
    await desk.locator('.workspace-link').click(); await desk.waitForURL(origin + '/me#inbox-new');
    await desk.waitForFunction(() => document.querySelectorAll('#inbox-list .inbox-unread').length === 1);
    if (shots) await desk.screenshot({path: shots + '/c184-after-1280-me.png'});
    await desk.locator('#inbox-mark-read').click();
    await desk.waitForFunction(() => !document.querySelector('#inbox-list .inbox-unread'));
    assert.equal(await desk.locator('#me-count').textContent(), '1', 'the conversation keeps its own unread count');
    await wide.close();
    assert.deepEqual(errors, []);
    console.log('PASS: one header row with a count on Me; Me opens Me at the Inbox, the thread with new replies first, Unread, opening at its newest new reply; each lands on the reply, centred and marked New, past the first page and deeper than the page indents; the read thread stays listed as Read; desktop and Mark all read.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
