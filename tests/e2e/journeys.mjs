// Real-user journeys against a blank local privnet (run.sh <scratch> blank).
// Counts clicks / typed inputs / page loads and wall time per journey, and runs axe on each page.
import fs from 'fs';
const B = 'http://127.0.0.1:8098';
import { createRequire } from 'module';
// Dependencies are installed in the current (scratch) directory, not in the repo.
const req = createRequire(process.cwd() + '/');
const { chromium } = req('playwright');
const axeSrc = fs.readFileSync(req.resolve('axe-core/axe.min.js'), 'utf8');
const out = process.argv[2] || '.';
const results = [], axeAll = {};
const b = await chromium.launch({ channel: 'chrome' });

function journey(name, vp) {
  const j = { name, clicks: 0, inputs: 0, loads: 0, ms: 0, notes: [], ok: true };
  return j;
}
async function track(page, j) {
  page.on('load', () => j.loads++);
  page.on('pageerror', (e) => { j.ok = false; j.notes.push('JS error: ' + e.message); });
}
const click = async (p, j, sel) => { j.clicks++; await p.click(sel); };
const nav = async (p, j, sel) => { j.clicks++; await Promise.all([p.waitForLoadState('load'), p.waitForNavigation(), p.click(sel)]); };
const type = async (p, j, sel, v) => { j.inputs++; await p.fill(sel, v); };
async function axe(p, label) {
  await p.addScriptTag({ content: axeSrc });
  const r = await p.evaluate(async () => (await window.axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa', 'best-practice'] })).violations.map(v => ({ id: v.id, impact: v.impact, n: v.nodes.length, help: v.help, target: v.nodes[0]?.target?.join(' ') })));
  axeAll[label] = r;
}

// J1 first-time: home -> signup -> create network -> add device -> device page
{
  const ctx = await b.newContext({ bypassCSP: true, viewport: { width: 1280, height: 860 } });
  const p = await ctx.newPage(); const j = journey('J1 first-time: signup → network → device → guide'); await track(p, j);
  const t = Date.now();
  await p.goto(B + '/'); j.loads = 1; await axe(p, 'home');
  await nav(p, j, 'text=Create your network');
  await axe(p, 'signup');
  await type(p, j, 'input[name=email]', 'first@example.org');
  await type(p, j, 'input[name=password]', 'correct horse battery');
  await nav(p, j, 'button:has-text("Create account")');
  j.notes.push('after signup: ' + new URL(p.url()).pathname);
  await axe(p, 'networks-empty');
  await type(p, j, 'input[name=name]', 'Home');
  await nav(p, j, 'button:has-text("Create network")');
  j.notes.push('after create: ' + new URL(p.url()).pathname + ' focus=' + await p.evaluate(() => document.activeElement?.name || document.activeElement?.tagName));
  await axe(p, 'network-empty');
  await type(p, j, '#device-name', 'my laptop');
  await click(p, j, 'label.chip:has-text("macOS")');
  await nav(p, j, 'button:has-text("Add device")');
  j.notes.push('device page: ' + new URL(p.url()).pathname + ' qr=' + (await p.isVisible('img.qr')) + ' guideOpen=' + await p.$eval('#guide', d => d.open));
  await axe(p, 'device-new');
  j.ms = Date.now() - t; results.push(j);
  fs.writeFileSync(out + '/state.json', JSON.stringify(await ctx.storageState()));
  await ctx.close();
}
const authed = async (vp) => b.newContext({ bypassCSP: true, viewport: vp || { width: 1280, height: 860 }, storageState: out + '/state.json' });

// J2 add a second device from the network page (regular user)
{
  const ctx = await authed(); const p = await ctx.newPage(); const j = journey('J2 regular: add second device from network list'); await track(p, j);
  const t = Date.now();
  await p.goto(B + '/networks'); j.loads = 1;
  await axe(p, 'networks');
  await nav(p, j, '.net-card');
  await click(p, j, 'text=+ Add device');
  await type(p, j, '#device-name', 'phone');
  await click(p, j, 'label.chip:has-text("iPhone")');
  await nav(p, j, 'button:has-text("Add device")');
  j.ms = Date.now() - t; results.push(j); await ctx.close();
}
// J3 share onboarding link, open it anonymously
{
  const ctx = await authed(); const p = await ctx.newPage(); const j = journey('J3 share link → anonymous join page'); await track(p, j);
  const t = Date.now();
  await p.goto(B + '/networks/1'); j.loads = 1;
  await nav(p, j, 'a.dev-link >> nth=1');
  await nav(p, j, 'button:has-text("Create share link")');
  const link = await p.inputValue('#share-url');
  const anon = await (await b.newContext({ bypassCSP: true, viewport: { width: 390, height: 844 } })).newPage();
  await anon.goto(link); j.loads++;
  j.notes.push('join page: qr=' + (await anon.isVisible('img.qr')) + ' guideOpen=' + await anon.$eval('#guide', d => d.open) + ' title=' + await anon.title());
  await axe(anon, 'join');
  await anon.screenshot({ path: out + '/j-join.png', fullPage: true });
  j.ms = Date.now() - t; results.push(j); await ctx.close();
}
// J4 error handling on auth forms
{
  const ctx = await b.newContext({ bypassCSP: true }); const p = await ctx.newPage(); const j = journey('J4 auth errors: wrong password, short password, duplicate email'); await track(p, j);
  await p.goto(B + '/login');
  await axe(p, 'login');
  await type(p, j, 'input[name=email]', 'first@example.org'); await type(p, j, 'input[name=password]', 'wrong-password');
  await nav(p, j, 'button:has-text("Log in")');
  j.notes.push('wrong pw: "' + (await p.textContent('.alert-error')).trim() + '" email kept=' + (await p.inputValue('input[name=email]') !== ''));
  for (let i = 0; i < 25; i++) await p.request.post(B + '/login', { form: { email: 'victim@example.org', password: 'guess' + i } });
  const r = await p.request.post(B + '/login', { form: { email: 'victim@example.org', password: 'guess-final' } });
  j.notes.push('after 26 wrong attempts status=' + r.status() + ' (no lockout if 401)');
  await p.goto(B + '/signup');
  await type(p, j, 'input[name=email]', 'first@example.org'); await type(p, j, 'input[name=password]', 'short');
  await nav(p, j, 'button:has-text("Create account")').catch(() => j.notes.push('short pw blocked client-side (minlength)'));
  await p.fill('input[name=password]', 'long enough password');
  await nav(p, j, 'button:has-text("Create account")');
  j.notes.push('duplicate: "' + (await p.textContent('.alert-error')).trim() + '"');
  results.push(j); await ctx.close();
}
// J5 validation on create network / add device
{
  const ctx = await authed(); const p = await ctx.newPage(); const j = journey('J5 validation: duplicate device name, full network, network limit'); await track(p, j);
  await p.goto(B + '/networks/1');
  for (const n of ['my laptop', 'a', 'b']) {
    await p.click('text=+ Add device').catch(() => {});
    if (!(await p.isVisible('#device-name'))) { j.notes.push('form gone before adding "' + n + '" (network full)'); break; }
    await p.fill('#device-name', n); await nav(p, j, 'button:has-text("Add device")'); await p.goto(B + '/networks/1');
  }
  const names = await p.$$eval('a.dev-link', as => as.map(a => a.textContent.trim()));
  j.notes.push('devices after adding duplicate "my laptop": ' + names.join(', '));
  const add = await p.isVisible('text=+ Add device');
  j.notes.push('network full (4/4): add button visible=' + add + ', form text=' + (await p.textContent('#add')).replace(/\s+/g, ' ').slice(0, 120));
  for (const n of ['N2', 'N3', 'N4']) {
    await p.goto(B + '/networks'); await p.click('text=+ New network').catch(() => {});
    if (!(await p.isVisible('input[name=name]'))) { j.notes.push('limit reached UI before ' + n + ': ' + (await p.textContent('main')).replace(/\s+/g, ' ').slice(-140)); break; }
    await p.fill('input[name=name]', n); await nav(p, j, 'button:has-text("Create network")');
  }
  results.push(j); await ctx.close();
}
// J6 remove device and delete network
{
  const ctx = await authed(); const p = await ctx.newPage(); const j = journey('J6 destructive: remove device, delete network'); await track(p, j);
  const t = Date.now();
  await p.goto(B + '/networks/1'); j.loads = 1;
  await nav(p, j, 'a.dev-link >> nth=3');
  await click(p, j, '#danger summary');
  p.once('dialog', d => { j.notes.push('confirm dialog: ' + d.message()); d.accept(); });
  await nav(p, j, '#danger button');
  j.notes.push('flash: ' + (await p.textContent('[data-flash]').catch(() => 'none')).trim());
  results.push({ ...j, ms: Date.now() - t });
  await ctx.close();
}
// J7 DNS namespace + record (power user)
{
  const ctx = await authed(); const p = await ctx.newPage(); const j = journey('J7 DNS: create namespace, add custom name'); await track(p, j);
  const t = Date.now();
  await p.goto(B + '/networks'); j.loads = 1;
  await nav(p, j, 'nav >> text=DNS');
  await axe(p, 'dns');
  await type(p, j, 'input[name=label]', 'mylab-test');
  await nav(p, j, 'button:has-text("Create namespace")');
  await axe(p, 'dnszone');
  await type(p, j, 'input[name=name]', 'printer'); await type(p, j, 'input[name=ip]', '192.168.1.50');
  await nav(p, j, 'button:has-text("Add name")');
  j.notes.push('flash: ' + (await p.textContent('[data-flash]').catch(() => 'none')).trim());
  await type(p, j, 'input[name=name]', 'web'); await type(p, j, 'input[name=ip]', '8.8.8.8');
  await nav(p, j, 'button:has-text("Add name")');
  j.notes.push('public IP error: ' + (await p.textContent('.alert-error')).trim().slice(0, 90));
  j.ms = Date.now() - t; results.push(j); await ctx.close();
}
// J8 HTTPS name on a device
{
  const ctx = await authed(); const p = await ctx.newPage(); const j = journey('J8 HTTPS: request proxy certificate'); await track(p, j);
  const t = Date.now();
  await p.goto(B + '/networks/1'); j.loads = 1;
  await nav(p, j, 'a.dev-link >> nth=0');
  await click(p, j, '#https .accordion-inline > summary');
  await type(p, j, '#https input[name=name]', 'web'); await type(p, j, 'input[name=port]', '8080');
  await nav(p, j, 'button:has-text("Create certificate")');
  await p.waitForTimeout(1500);
  j.notes.push('status after create: ' + (await p.textContent('#https .cert .pill')).trim());
  j.ms = Date.now() - t; results.push(j); await ctx.close();
}
// J9 authorization: other user's objects
{
  const ctx = await b.newContext({ bypassCSP: true }); const p = await ctx.newPage(); const j = journey('J9 IDOR: second user opens first user\'s objects'); await track(p, j);
  await p.goto(B + '/signup'); await p.fill('input[name=email]', 'mallory@example.org'); await p.fill('input[name=password]', 'mallory password 1');
  await Promise.all([p.waitForNavigation(), p.click('button:has-text("Create account")')]);
  for (const u of ['/networks/1', '/devices/1', '/devices/1/config', '/devices/1/qr.png', '/api/networks/1/status', '/dns/1', '/devices/1/certs/1/privkey.pem']) {
    const r = await p.request.get(B + u); j.notes.push(u + ' → ' + r.status());
  }
  const r = await p.request.post(B + '/devices/1/delete', { headers: { Origin: B } }); j.notes.push('POST /devices/1/delete → ' + r.status());
  results.push(j); await ctx.close();
}
// J10 logout and session
{
  const ctx = await authed(); const p = await ctx.newPage(); const j = journey('J10 logout → protected page → login → back to page'); await track(p, j);
  await p.goto(B + '/networks/1');
  await nav(p, j, 'button:has-text("Log out")');
  await p.goto(B + '/devices/1'); j.notes.push('protected after logout → ' + new URL(p.url()).pathname + new URL(p.url()).search);
  await type(p, j, 'input[name=email]', 'first@example.org'); await type(p, j, 'input[name=password]', 'correct horse battery');
  await nav(p, j, 'button:has-text("Log in")');
  j.notes.push('after login → ' + new URL(p.url()).pathname + ' (expected /devices/1 unless locked out: ' + ((await p.textContent('.alert-error').catch(() => '')) || '').trim() + ')');
  fs.writeFileSync(out + '/state.json', JSON.stringify(await ctx.storageState()));
  results.push(j); await ctx.close();
}
// J11 mobile: full first-time device flow on a phone
{
  const ctx = await authed({ width: 390, height: 844 }); const p = await ctx.newPage(); const j = journey('J11 mobile: open device, find QR + guide'); await track(p, j);
  await p.goto(B + '/networks');
  await nav(p, j, '.net-card');
  await nav(p, j, '.row-action a >> nth=0');
  const qrTop = await p.$eval('img.qr', e => e.getBoundingClientRect().top);
  j.notes.push('QR top on phone: ' + Math.round(qrTop) + 'px (viewport 844)');
  const small = await p.$$eval('a, button, summary, input, label.chip span', els => els.filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && (r.height < 24 || r.width < 24); }).map(e => (e.textContent || e.name || e.tagName).trim().slice(0, 30)));
  j.notes.push('targets <24px: ' + small.length + ' ' + small.slice(0, 8).join(' | '));
  results.push(j); await ctx.close();
}
// J12 keyboard-only: create network, add device
{
  const ctx = await authed(); const p = await ctx.newPage(); const j = journey('J12 keyboard: tab order on network page'); await track(p, j);
  await p.goto(B + '/networks/1');
  const order = [];
  for (let i = 0; i < 14; i++) { await p.keyboard.press('Tab'); order.push(await p.evaluate(() => { const a = document.activeElement; return (a.getAttribute('aria-label') || a.textContent || a.name || a.tagName).trim().replace(/\s+/g, ' ').slice(0, 24); })); }
  j.notes.push('tab order: ' + order.join(' › '));
  results.push(j); await ctx.close();
}
// J13 404 / unknown pages, J14 performance timings
{
  const ctx = await authed(); const p = await ctx.newPage(); const j = journey('J13 errors + J14 timings'); await track(p, j);
  for (const u of ['/nope', '/networks/abc', '/devices/999']) { const r = await p.goto(B + u); j.notes.push(u + ' → ' + r.status() + ' "' + (await p.textContent('body')).trim().replace(/\s+/g,' ').slice(0,50) + '"'); }
  for (const u of ['/', '/networks', '/networks/1', '/devices/1', '/dns', '/dns/1', '/api/networks/1/status']) {
    const ts = [];
    for (let i = 0; i < 5; i++) { const t = Date.now(); const r = await p.request.get(B + u); await r.body(); ts.push(Date.now() - t); }
    ts.sort((a, c) => a - c); j.notes.push(`${u} median ${ts[2]}ms`);
  }
  await p.goto(B + '/networks/1');
  const nav2 = await p.evaluate(() => { const e = performance.getEntriesByType('navigation')[0]; const res = performance.getEntriesByType('resource'); return { dcl: Math.round(e.domContentLoadedEventEnd), load: Math.round(e.loadEventEnd), html: e.transferSize, res: res.map(r => r.name.split('/').pop().split('?')[0] + ':' + r.transferSize) }; });
  j.notes.push('network page DCL ' + nav2.dcl + 'ms load ' + nav2.load + 'ms html ' + nav2.html + 'B ' + nav2.res.join(' '));
  results.push(j); await ctx.close();
}
await b.close();
fs.writeFileSync(out + '/journeys.json', JSON.stringify({ results, axe: axeAll }, null, 2));
for (const r of results) {
  console.log(`\n## ${r.name}  ${r.ok ? '' : '[JS ERRORS]'}\n  clicks=${r.clicks} inputs=${r.inputs} loads=${r.loads}${r.ms ? ' time=' + r.ms + 'ms' : ''}`);
  r.notes.forEach(n => console.log('  - ' + n));
}
console.log('\n## axe');
for (const [k, v] of Object.entries(axeAll)) console.log(`  ${k}: ` + (v.length ? v.map(x => `${x.id}(${x.impact},${x.n})`).join(' ') : 'clean'));
