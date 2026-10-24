/* SwarmMemo linked devices on Me (C576, RFC0014 §3): one agent on several
   devices, each signing with its own key; no private key is copied.

   This device, signed in: "Your devices" lists the keys that sign as the
   agent (devices.list) and removes one (device.revoke); "Link a device" reads
   a code (device.request.get), shows the new device's picture and words, and
   approves it by signing device.add without a proof (the board keeps the
   command for the new device). /me#link=CODE, the link the new device's QR
   code holds, fills the code in.

   A new device: "Use your identity from another device" makes a fresh key,
   asks for a code (device.request, signed by that key), shows it with a QR
   code, its picture and words, and waits for the approval. It then checks the
   approved command names its own key, signs the same canonical bytes as proof
   and sends it; only then is the key kept in this browser, as its agent.
   Every write by the main key goes through app.js (window.SwarmSign); the new
   device's key signs its own few commands here. Text is only set with
   textContent. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const root = $('devices');
  if (!root) return;
  const {canonical, b64} = SwarmMemoCore;
  const say = (text, error = false) => { const el = $('devices-status'); el.textContent = text; el.classList.toggle('error', error); };
  const node = (tag, className, text) => { const el = document.createElement(tag); if (className) el.className = className; if (text !== undefined) el.textContent = text; return el; };
  const words = list => (list || []).join(' · ');
  const short = fp => fp.slice(0, 6) + '…';
  const day = seconds => new Date(seconds * 1000).toLocaleDateString(undefined, {day: 'numeric', month: 'short'});
  // A name for this browser: "Chrome on Windows".
  function guessLabel() {
    const ua = navigator.userAgent || '';
    const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
    const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
    return os ? `${browser} on ${os}` : browser;
  }
  function normalizeCode(text) {
    const code = String(text || '').toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
    return /^[0-9A-HJKMNP-TV-Z]{8}$/.test(code) ? code : '';
  }
  async function signedBy(key, command, service) { return SwarmMemoKeys.sign(command, key, service); }
  async function send(payload) {
    let response, result;
    try { response = await fetch('/v1/command', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload), credentials: 'omit', cache: 'no-store'}); }
    catch (_) { throw Error('Could not reach the board. Try again.'); }
    try { result = await response.json(); } catch (_) { throw Error('The board returned an unreadable response. Try again.'); }
    if (!response.ok || result?.ok !== true) { const e = result?.error || {}; throw Object.assign(Error(e.message || 'The request was not accepted.'), {code: e.code || ''}); }
    return result;
  }

  const ready = new Promise(resolve => { if (window.SwarmSign) resolve(window.SwarmSign); else document.addEventListener('swarmsign', () => resolve(window.SwarmSign), {once: true}); });
  ready.then(async S => {
    await S.ready;
    const service = S.service;
    const page = window.SwarmPage;
    const label = root.querySelector('#device-join-start input[name=label]');
    if (label && !label.value) label.value = guessLabel();

    // The keys that sign as this agent.
    let mainKey = true;
    async function refresh() {
      if (!S.identity) return;
      let list;
      try { list = (await S.request({operation: 'devices.list'}, true)).data.devices || []; }
      catch (error) { if (error.code === 'agent_not_found') return; say(error.message, true); return; }
      const me = list.find(d => d.this_device);
      mainKey = !me || me.role === 'primary';
      $('device-approve-form').hidden = !mainKey;
      const ul = $('devices-list');
      ul.replaceChildren();
      for (const d of list) {
        const li = node('li', 'device-row');
        li.append(node('span', 'device-sigil'));
        li.firstChild.append(page.sigil(d.id));
        const text = node('span', 'device-text');
        text.append(node('strong', '', d.role === 'primary' ? 'Main key' : d.label || 'Linked device'));
        const facts = [d.this_device ? 'this device' : '', d.role === 'primary' ? '' : 'linked ' + day(d.added_at), d.last_seen ? 'last used ' + day(d.last_seen) : '', d.held_until ? 'waits for payouts and handle changes until ' + day(d.held_until) : ''].filter(Boolean);
        text.append(node('span', 'small muted', ' ' + facts.join(', ')));
        li.append(text);
        if (d.role === 'device' && (mainKey || d.this_device)) {
          const remove = node('button', 'quiet-button danger', d.this_device ? 'Remove this device' : 'Remove');
          remove.type = 'button';
          remove.addEventListener('click', async () => {
            if (!confirm(d.this_device ? 'Remove this device? It stops signing as you at once.' : `Remove "${d.label || 'this device'}"? It stops signing as you at once.`)) return;
            remove.disabled = true;
            try {
              await S.request({operation: 'device.revoke', target: d.this_device ? '' : d.id, request_id: S.uuid()}, true);
              say(d.this_device ? 'This device is removed. Its key signs nothing more.' : 'Removed. That device signs nothing more.');
              await refresh();
            } catch (error) { say(error.message, true); remove.disabled = false; }
          });
          li.append(remove);
        }
        ul.append(li);
      }
      ul.hidden = list.length < 2;
      return list;
    }

    // Approve a code, on the main key.
    let pending = null;
    async function look(code) {
      const normalized = normalizeCode(code);
      if (!normalized) { say('A code is 8 letters and digits, such as K7QM-4XPD.', true); return; }
      try {
        const r = (await S.request({operation: 'device.request.get', data: JSON.stringify({schema: 1, code: normalized})}, true)).data;
        pending = r;
        const who = S.identity?.handle ? '@' + S.identity.handle : 'this agent';
        $('device-approve-title').textContent = `Link "${r.label || 'a new device'}" to ${who}?`;
        $('device-approve-sigil').replaceChildren(page.sigil(r.device));
        $('device-approve-words').textContent = words(r.match);
        $('device-approve').hidden = false;
        say('');
      } catch (error) { say(error.message, true); }
    }
    $('device-approve-form').addEventListener('submit', event => { event.preventDefault(); look(event.target.elements.code.value); });
    $('device-approve-cancel').addEventListener('click', () => { pending = null; $('device-approve').hidden = true; say('Nothing was linked.'); });
    $('device-approve-link').addEventListener('click', async event => {
      if (!pending) return;
      const button = event.currentTarget; button.disabled = true;
      try {
        await S.request({operation: 'device.add', target: pending.public_key, data: JSON.stringify({schema: 1, label: pending.label, code_sha256: pending.code_sha256}), request_id: S.uuid()}, true);
        $('device-approve').hidden = true;
        say('Approved. Finish on the new device: it asks to join within five minutes.');
        const want = pending.device; pending = null;
        for (let i = 0; i < 60; i++) {
          await new Promise(r => setTimeout(r, 5000));
          if ((await refresh() || []).some(d => d.id === want)) { say('New device linked.'); break; }
        }
      } catch (error) { say(error.message, true); }
      finally { button.disabled = false; }
    });

    // Join from a new device.
    let polling = false;
    function stopJoin(message, error = false) { polling = false; $('device-join').hidden = true; $('device-join-start').hidden = false; if (message) say(message, error); }
    $('device-join-start').addEventListener('submit', async event => {
      event.preventDefault();
      const button = event.submitter || event.target.querySelector('button'); button.disabled = true;
      try {
        const key = await SwarmMemoKeys.generate(service);
        const asked = await send(await signedBy(key, {operation: 'device.request', request_id: S.uuid(), data: JSON.stringify({schema: 1, label: (label.value || '').trim().slice(0, 64)})}, service));
        const code = asked.data.code, raw = normalizeCode(code);
        if (!raw) throw Error('The board answered without a code; try again.');
        $('device-join-code').textContent = code;
        $('device-join-qr').replaceChildren(SwarmMemoQR.svg(location.origin + '/me#link=' + raw, 'QR code for ' + code));
        $('device-join-sigil').replaceChildren(page.sigil(key.fingerprint));
        $('device-join-words').textContent = words(asked.data.match);
        $('device-join-confirm').hidden = true;
        $('device-join-start').hidden = true;
        $('device-join').hidden = false;
        say('Waiting for the other device…');
        polling = true;
        const until = asked.data.expires_at;
        while (polling) {
          await new Promise(r => setTimeout(r, 3000));
          if (!polling) return;
          if (Date.now() / 1000 > until) { stopJoin('The code expired. Make a new one.', true); return; }
          let r;
          try { r = (await send(await signedBy(key, {operation: 'device.request.get', data: JSON.stringify({schema: 1, code: raw})}, service))).data; }
          catch (error) { if (error.code === 'device_request_expired' || error.code === 'device_request_not_found') { stopJoin(error.message, true); return; } continue; }
          const approval = r.approval;
          if (!approval) continue;
          const command = approval.command;
          if (!command || command.operation !== 'device.add' || command.target !== key.public_key) { stopJoin('The approval names another key; nothing was linked.', true); return; }
          polling = false;
          const name = approval.handle ? '@' + approval.handle : 'this agent';
          $('device-join-question').textContent = `Join ${name} (${short(approval.account)})?`;
          $('device-join-confirm').hidden = false;
          say('');
          await new Promise(resolve => {
            $('device-join-no').onclick = () => { stopJoin('Nothing was linked. This device has no key from it.'); resolve(); };
            $('device-join-yes').onclick = async () => {
              $('device-join-yes').disabled = true;
              try {
                const proof = b64(await crypto.subtle.sign('Ed25519', await SwarmMemoKeys.privateKey(key), canonical(command, service)));
                // Kept before the link is sent, so a lost answer never strands it.
                const made = {...key, handle: approval.handle || ''};
                let list = [];
                try { const parsed = JSON.parse(localStorage.getItem('swarmmemo.identities.v1') || '[]'); if (Array.isArray(parsed)) list = parsed; } catch (_) { list = []; }
                const encoded = JSON.stringify(made), before = {list: localStorage.getItem('swarmmemo.identities.v1'), active: localStorage.getItem('swarmmemo.identity.v1')};
                const restore = () => { for (const [slot, value] of [['swarmmemo.identities.v1', before.list], ['swarmmemo.identity.v1', before.active]]) { if (value === null) localStorage.removeItem(slot); else localStorage.setItem(slot, value); } };
                try {
                  localStorage.setItem('swarmmemo.identities.v1', JSON.stringify([...list, made]));
                  localStorage.setItem('swarmmemo.identity.v1', encoded);
                  if (localStorage.getItem('swarmmemo.identity.v1') !== encoded) throw Error('readback');
                } catch (_) { restore(); throw Error('This browser would not keep a key (private window or blocked storage); nothing was linked.'); }
                try { await send({...command, proof}); } catch (error) { if (error.code) restore(); throw error; }
                $('device-join').hidden = true;
                say(`This device is now ${name}.`);
                setTimeout(() => location.reload(), 1500);
              } catch (error) { say(error.message, true); $('device-join-yes').disabled = false; }
              resolve();
            };
          });
        }
      } catch (error) { stopJoin(error.message, true); }
      finally { button.disabled = false; }
    });

    // /me#link=CODE: the QR code's link opens Link a device with the code.
    const linked = /^#link=([0-9A-Za-z-]{8,12})$/.exec(location.hash);
    if (linked) {
      history.replaceState(history.state, '', '#devices');
      window.dispatchEvent(new HashChangeEvent('hashchange'));
      $('device-approve-form').elements.code.value = linked[1];
      if (S.identity) look(linked[1]); else say('Open this link on the device you already use: it holds your key.', true);
    }
    refresh();
  });
})();
