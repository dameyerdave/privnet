// Post-change journeys: new features + dark-mode axe. Run after journeys.mjs (same DB).
import fs from 'fs';
const B = 'http://127.0.0.1:8098';
const out = process.argv[2];
import { createRequire } from 'module';
// Dependencies are installed in the current (scratch) directory, not in the repo.
const req = createRequire(process.cwd() + '/');
const { chromium } = req('playwright');
const axeSrc = fs.readFileSync(req.resolve('axe-core/axe.min.js'), 'utf8');
const b = await chromium.launch({ channel: 'chrome' });
const log = (m) => console.log('  - ' + m);
async function axe(p) {
  await p.addScriptTag({ content: axeSrc });
  return p.evaluate(async () => (await window.axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa', 'best-practice'] })).violations.map(v => `${v.id}(${v.impact},${v.nodes.length}) ${v.nodes[0]?.target?.join(' ')}`));
}
const errs = [];

console.log('## J15 rename device (clicks/inputs)');
{
  const ctx = await b.newContext({ bypassCSP: true, storageState: out + '/state.json' });
  const p = await ctx.newPage(); p.on('pageerror', e => errs.push(e.message));
  await p.goto(B + '/devices/1');
  let clicks = 0;
  await p.click('details.rename summary'); clicks++;
  const focused = await p.evaluate(() => document.activeElement.name);
  await p.fill('details.rename input', 'work laptop');
  await Promise.all([p.waitForNavigation(), p.press('details.rename input', 'Enter')]);
  log(`clicks=${clicks} inputs=1 focus-in-field=${focused === 'name'} h1="${await p.textContent('h1')}" flash="${(await p.textContent('[data-flash] span')).trim()}"`);
  await p.click('details.rename summary'); await p.keyboard.press('Escape');
  log('Escape closes popover: ' + !(await p.$eval('details.rename', d => d.open)));
  await ctx.close();
}

console.log('## J16 account: change password, wrong password feedback');
{
  const ctx = await b.newContext({ bypassCSP: true, storageState: out + '/state.json' });
  const p = await ctx.newPage(); p.on('pageerror', e => errs.push(e.message));
  await p.goto(B + '/networks');
  await Promise.all([p.waitForNavigation(), p.click('a.nav-email')]);
  log('nav email → ' + new URL(p.url()).pathname + ' active=' + await p.$eval('a.nav-email', a => a.getAttribute('aria-current')));
  log('axe account: ' + JSON.stringify(await axe(p)));
  await p.fill('input[name=current]', 'nope'); await p.fill('input[name=new]', 'brand new password 1');
  await Promise.all([p.waitForNavigation(), p.click('button:has-text("Change password")')]);
  log('wrong current: ' + (await p.textContent('.alert-error')).trim());
  await p.fill('input[name=current]', 'correct horse battery'); await p.fill('input[name=new]', 'brand new password 1');
  await Promise.all([p.waitForNavigation(), p.click('button:has-text("Change password")')]);
  log('changed: ' + (await p.textContent('[data-flash] span')).trim());
  await p.click('#danger summary');
  log('delete disabled until email typed: ' + await p.$eval('#danger button', b => b.disabled));
  await p.screenshot({ path: out + '/after-account.png', fullPage: true });
  fs.writeFileSync(out + '/state.json', JSON.stringify(await ctx.storageState()));
  await ctx.close();
}

console.log('## J17 join page live status (anonymous)');
{
  const ctx = await b.newContext({ bypassCSP: true, storageState: out + '/state.json' });
  const p = await ctx.newPage();
  await p.goto(B + '/devices/1');
  await Promise.all([p.waitForNavigation(), p.click('button:has-text("share link")')]);
  const link = await p.inputValue('#share-url');
  const anon = await (await b.newContext({ bypassCSP: true })).newPage();
  let polls = 0; anon.on('request', r => { if (r.url().endsWith('/status')) polls++; });
  await anon.goto(link); await anon.waitForTimeout(4500);
  log('join page polled status ' + polls + 'x; pill: "' + (await anon.textContent('[data-device-state]')).trim() + '"');
  await ctx.close();
}

console.log('## J18 friendly 404 + back');
{
  const ctx = await b.newContext({ bypassCSP: true, storageState: out + '/state.json' });
  const p = await ctx.newPage();
  await p.goto(B + '/networks'); await p.goto(B + '/does-not-exist');
  log('h1="' + (await p.textContent('h1')).trim() + '" buttons=' + (await p.$$eval('.status-card .btn', bs => bs.filter(b => !b.hidden).map(b => b.textContent.trim()).join(', '))));
  await ctx.close();
}

console.log('## axe dark mode');
{
  const ctx = await b.newContext({ bypassCSP: true, colorScheme: 'dark', storageState: out + '/state.json' });
  const p = await ctx.newPage();
  for (const u of ['/networks', '/networks/1', '/devices/1', '/dns', '/account', '/does-not-exist']) {
    await p.goto(B + u); log(u + ': ' + JSON.stringify(await axe(p)));
  }
  const q = await (await b.newContext({ bypassCSP: true, colorScheme: 'dark' })).newPage();
  for (const u of ['/', '/login', '/signup']) { await q.goto(B + u); log(u + ': ' + JSON.stringify(await axe(q))); }
  await ctx.close();
}
console.log('JS errors: ' + (errs.length ? errs.join(' | ') : 'none'));
await b.close();
