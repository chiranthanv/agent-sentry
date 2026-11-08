// Optional browser smoke test: install Playwright and Chromium to run this script.
const {chromium} = require('playwright');
const fs = require('node:fs');
const assert = require('node:assert/strict');

(async () => {
  const token = fs.readFileSync('.state/api.token', 'utf8').trim();
  const browser = await chromium.launch({headless: true, channel: process.env.SENTRY_BROWSER_CHANNEL || undefined});
  const errors = [];
  try {
    const page = await browser.newPage({viewport: {width: 1440, height: 1200}});
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('http://127.0.0.1:8765/');
    await page.getByLabel('Local API token').fill(token);
    await page.getByRole('button', {name: 'Connect ledger'}).click();
    await page.getByRole('status').filter({hasText: 'Ledger loaded.'}).waitFor();
    assert.equal(await page.locator('#integrity').textContent(), 'VALID');
    assert.ok((await page.locator('#events tr').count()) >= 5);
    assert.ok(await page.getByRole('cell', {name: 'approval_required', exact: true}).count());
    await page.getByLabel('Local API token').fill('');
    fs.mkdirSync('docs/evidence', {recursive: true});
    await page.screenshot({path: 'docs/evidence/dashboard-desktop.png', fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await page.screenshot({path: 'docs/evidence/dashboard-mobile.png', fullPage: true});
    assert.deepEqual(errors, []);
    console.log('PASS: authenticated ledger, audit integrity, decision rows, responsive layout, no page errors');
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
