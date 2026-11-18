const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync, statSync } = require('node:fs');
const { resolve, sep } = require('node:path');
const { chromium } = require('playwright');

for (const mode of ['local', 'delegated', 'http']) test(`fetch restores a saved ${mode} store after reload`, async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.XOVER_TEST_BROWSER_CHANNEL || 'chrome' });
  try {
    const page = await browser.newPage();
    const root = resolve(__dirname, '..');
    let networkRequests = 0;
    const networkQueries = [];
    await page.route('**/*', route => {
      const pathname = new URL(route.request().url()).pathname;
      if (pathname === '/test.html') return route.fulfill({ contentType: 'text/html', body: '<!doctype html><script src="/xo.js"></script><script>xover.init.dom = async function () {};</script>' });
      if (pathname === '/server/request.asp') {
        networkRequests++;
        networkQueries.push(Object.fromEntries(new URL(route.request().url()).searchParams));
        return route.fulfill({ contentType: 'application/xml', body: '<report origin="network"/>' });
      }
      const file = resolve(root, '.' + pathname);
      if (!file.startsWith(root + sep) || !existsSync(file) || !statSync(file).isFile()) return route.fulfill({ status: 404, body: '' });
      return route.fulfill({ contentType: file.endsWith('.wasm') ? 'application/wasm' : file.endsWith('.js') ? 'text/javascript' : 'application/octet-stream', body: readFileSync(file) });
    });
    await page.goto('http://xover.test/test.html');
    await page.evaluate(async () => {
      await xover.modernize();
      const xml = xover.xml.createDocument('<report origin="saved"><row id="42"/></report>');
      xover.stores['#reporte_interapas'] = xml;
      await xover.stores['#reporte_interapas'].save();
    });
    await page.reload();
    const result = await page.evaluate(async mode => {
      await xover.modernize();
      if (mode === 'delegated') {
        xover.manifest.server.request = '/server/request.asp';
        xover.manifest.sources['#reporte_interapas'] = { 'server:request': { FROM: 'reports', '@archivo': 'default' } };
      } else if (mode === 'http') {
        xover.manifest.sources['#reporte_interapas'] = '/server/request.asp';
      }
      const source = xover.sources['#reporte_interapas'].source;
      const protocol = source.url.protocol;
      await source.fetch();
      const file = await (await xover.storehouse.sources).get('#reporte_interapas');
      return { protocol, cached: !!file, origin: source.document.documentElement?.getAttribute('origin'), row: source.document.querySelector('row')?.getAttribute('id') };
    }, mode);
    assert.ok(result.cached, 'the saved record must remain in IndexedDB');
    assert.equal(result.origin, 'saved', JSON.stringify(result));
    assert.equal(result.row, '42');
    assert.equal(networkRequests, 0);
    if (mode === 'local') {
      const direct = await page.evaluate(async () => {
        const document = await new xover.Request('#reporte_interapas').fetch();
        return document.documentElement?.getAttribute('origin');
      });
      assert.equal(direct, 'saved', 'a direct request must also find the #store key');
    }
    if (mode === 'delegated') {
      for (const cache of ['reload', 'no-store', 'disabled']) {
        const origin = await page.evaluate(async cache => {
          const source = xover.sources['#reporte_interapas'].source;
          source.url.searchParams.set('@archivo', '248730');
          source.url.searchParams.set('@contratos', cache === 'disabled' ? null : cache === 'reload' ? '41468' : '41469');
          source.url.settings.cache = cache === 'disabled' ? 'default' : cache;
          xover.session.disableCache = cache === 'disabled';
          await source.fetch();
          return source.document.documentElement?.getAttribute('origin');
        }, cache);
        assert.equal(origin, 'network', `${cache} must bypass the saved store`);
      }
      assert.equal(networkRequests, 3);
      assert.deepEqual(networkQueries, [
        { FROM: 'reports', '@archivo': '248730', '@contratos': '41468' },
        { FROM: 'reports', '@archivo': '248730', '@contratos': '41469' },
        { FROM: 'reports', '@archivo': '248730' }
      ]);
    }
  } finally {
    await browser.close();
  }
});
