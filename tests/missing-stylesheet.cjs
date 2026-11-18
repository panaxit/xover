const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

test('a missing XML stylesheet settles without a render loop', { timeout: 60000 }, async () => {
  const code = fs.readFileSync(path.join(__dirname, '../xo.js'), 'utf8');
  const browser = await chromium.launch({ headless: true, channel: 'chrome' });
  try {
    const page = await browser.newPage();
    const requests = [];
    const errors = [];
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    await page.route('**/*', route => {
      const url = new URL(route.request().url());
      requests.push(url.pathname);
      if (url.pathname === '/alta_tags/') return route.fulfill({ contentType: 'text/html', body: '<!doctype html><html><head><link rel="xover-manifest" href="manifest.json"><script src="/xo.js"></script></head><body><section xo-store="seed" xo-source="alta_tags.xslt"></section></body></html>' });
      if (url.pathname === '/xo.js') return route.fulfill({ contentType: 'application/javascript', body: code });
      if (url.pathname === '/alta_tags/manifest.json') return route.fulfill({ json: { server: { login: null }, sources: { '^#([^_]+)_(.+?)$': '../assets/desarrollos/$1/alta_tags_$2.xml' } } });
      if (url.pathname.endsWith('/alta_tags_212.xml')) return route.fulfill({ contentType: 'text/xml', body: '<?xml-stylesheet type="text/xsl" href="alta_tags.xslt"?><AltaTags><Tags/></AltaTags>' });
      if (url.pathname === '/alta_tags/alta_tags.xslt') return route.fulfill({ contentType: 'text/xml', body: '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><p>Rendered</p></xsl:template></xsl:stylesheet>' });
      return route.fulfill({ status: 404, contentType: 'text/html', body: '<html><body><h1>HTTP Error 404.0 - Not Found</h1></body></html>' });
    });
    await page.goto('http://xover.test/alta_tags/#cantabria_212', { waitUntil: 'domcontentloaded' });
    await page.getByText('HTTP Error 404.0 - Not Found', { exact: true }).waitFor();
    assert.equal(await page.locator('dialog').count(), 1, 'the original failure remains visible');
    const errorCount = errors.length;
    await page.waitForTimeout(500);
    assert.equal(errors.length, errorCount, 'reporting the failure must settle');
    assert.ok(errors.length < 10, `one missing stylesheet generated ${errors.length} errors`);
    assert.equal(requests.filter(url => url === '/assets/desarrollos/cantabria/alta_tags.xslt').length, 1);
  } finally { await browser.close(); }
});
