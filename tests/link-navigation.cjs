const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync, statSync } = require('node:fs');
const { resolve, sep } = require('node:path');
const { chromium } = require('playwright');

test('link navigation leaves resources and browser targets alone while preserving internal routing', async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.XOVER_TEST_BROWSER_CHANNEL || 'chrome' });
  try {
    const page = await browser.newPage();
    const root = resolve(__dirname, '..');
    await page.route('**/*', route => {
      const url = new URL(route.request().url());
      if (url.pathname === '/test.html') return route.fulfill({ contentType: 'text/html', body: '<!doctype html><div id="report"></div><div id="section"></div><script src="/xo.js"></script><script>xover.init.dom = async function () {};</script>' });
      const file = resolve(root, '.' + url.pathname);
      if (!file.startsWith(root + sep) || !existsSync(file) || !statSync(file).isFile()) return route.fulfill({ status: 404, body: '' });
      return route.fulfill({ contentType: file.endsWith('.js') ? 'text/javascript' : 'application/octet-stream', body: readFileSync(file) });
    });
    await page.goto('http://xover.test/test.html#report');
    const results = await page.evaluate(async () => {
      await xover.ready;
      let hashChanges = 0, prevented;
      window.addEventListener('beforeHashChange', () => hashChanges++);
      // Observe the dispatcher's decision, then suppress native navigation in the fixture.
      window.addEventListener('click', event => { prevented = event.defaultPrevented; event.preventDefault(); });
      const check = (href, attributes = {}, eventOptions = {}) => {
        const anchor = document.createElement('a');
        anchor.href = href;
        for (const [name, value] of Object.entries(attributes)) anchor.setAttribute(name, value);
        const child = anchor.appendChild(document.createElement('span'));
        document.body.append(anchor);
        const before = hashChanges;
        child.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, ...eventOptions }));
        anchor.remove();
        return { prevented, hashChanges: hashChanges - before };
      };
      return {
        pdf: check('http://files.test/invoice.pdf', { target: '_blank' }),
        pdfPage: check('http://files.test/invoice.pdf#page=2', { target: '_blank' }),
        selfPDF: check('/invoice.pdf', { target: '_self' }),
        download: check('#section', { download: '' }),
        blankSection: check('#section', { target: '_blank' }),
        modified: check('#section', {}, { ctrlKey: true }),
        internal: check('#section'),
        cancelled: check('#section', {}, { shiftKey: true })
      };
    });
    for (const name of ['pdf', 'pdfPage', 'selfPDF', 'download', 'blankSection', 'modified', 'cancelled']) {
      assert.deepEqual(results[name], { prevented: false, hashChanges: 0 }, name);
    }
    assert.deepEqual(results.internal, { prevented: true, hashChanges: 1 });
  } finally { await browser.close(); }
});

const runtime = readFileSync(resolve(__dirname, '../xo.js'));
const fixture = '<!doctype html><html><head><link rel="xover-manifest" href="/manifest.json"><script src="/xo.js"></script></head><body><a href="#first">First</a> <a href="#second">Second</a> <a href="#late">Late</a><header><div id="navigation" xo-source="active" xo-stylesheet="/nav.xslt"></div></header><main id="view"><p id="static">Persistent content</p></main><aside id="fixed" xo-source="#first" xo-stylesheet="/fixed.xslt"></aside></body></html>';
const manifest = JSON.stringify({ sources: { '#first': '/first.xml', '#second': '/second.xml', '#late': '/late.xml' } });
const xml = (name, view, busy = '') => `<?xml-stylesheet type="text/xsl" href="/${view}.xslt" target="#view"?><model name="${name}"${busy}/>`;
const xslt = body => `<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns="http://www.w3.org/1999/xhtml"><xsl:template match="/">${body}</xsl:template></xsl:stylesheet>`;
const view = xslt('<section id="page-view" class="page-view"><xsl:value-of select="model/@name"/></section>');
const files = {
    '/index.html': ['text/html', fixture],
    '/xo.js': ['text/javascript', runtime],
    '/manifest.json': ['application/json', manifest],
    '/first.xml': ['application/xml', xml('First store', 'first-view', ' busy="true"')],
    '/second.xml': ['application/xml', xml('Second store', 'second-view')],
    '/late.xml': ['application/xml', xml('Late store', 'late-view')],
    '/nav.xslt': ['application/xml', xslt('<div id="navigation"><span id="nav-label"><xsl:value-of select="model/@name"/></span><button id="query"><xsl:if test="model/@busy"><xsl:attribute name="disabled">disabled</xsl:attribute></xsl:if>Query</button></div>')],
    '/first-view.xslt': ['application/xml', view],
    '/second-view.xslt': ['application/xml', view],
    '/late-view.xslt': ['application/xml', view],
    '/fixed.xslt': ['application/xml', xslt('<aside id="fixed"><xsl:value-of select="model/@name"/></aside>')]
};

test('the active store updates the outlet and bound sections on links and history', { timeout: 25000 }, async () => {
    const browser = await chromium.launch({ headless: true, channel: process.env.XOVER_TEST_BROWSER_CHANNEL || 'chrome' });
    try {
        const page = await browser.newPage();
        page.on('pageerror', error => console.error('page:', error.message));
        page.on('console', message => { if (message.type() === 'error' || message.type() === 'warning') console.error(message.type(), message.text().slice(0, 500)); });
        const releaseLate = Promise.withResolvers();
        const startedLate = Promise.withResolvers();
        await page.route('**/*', async route => {
            const path = new URL(route.request().url()).pathname;
            if (path === '/late.xml') {
                startedLate.resolve();
                await releaseLate.promise;
            }
            const file = files[path];
            return file ? route.fulfill({ contentType: file[0], body: file[1] }) : route.fulfill({ status: 404, body: '' });
        });
        await page.goto('http://xover.test/index.html#first');
        const state = () => page.evaluate(() => ({ path: location.hash, active: xo.stores.active.tag, nav: document.querySelector('#nav-label')?.textContent, main: [...document.querySelectorAll('.page-view')].map(view => view.textContent), disabled: document.querySelector('#query')?.disabled, persistent: !!document.querySelector('#static'), fixed: document.querySelector('#fixed')?.textContent }));
        const expected = name => ({ path: `#${name.toLowerCase()}`, active: `#${name.toLowerCase()}`, nav: `${name} store`, main: [`${name} store`], disabled: name === 'First', persistent: true, fixed: 'First store' });
        await page.waitForFunction(() => document.querySelector('.page-view')?.textContent === 'First store' && document.querySelector('#nav-label')?.textContent === 'First store' && document.querySelector('#fixed')?.textContent === 'First store', undefined, { timeout: 7000 });
        assert.deepEqual(await state(), expected('First'));
        await page.getByRole('link', { name: 'Second' }).click();
        const settled = name => page.waitForFunction(label => document.querySelector('#nav-label')?.textContent === label && document.querySelector('.page-view')?.textContent === label, `${name} store`, { timeout: 4000 });
        try { await settled('Second'); } catch (error) {
            console.error(await page.evaluate(() => ({ views: document.querySelector('#view')?.outerHTML, state: history.state, parts: [...xo.site.sections].map(s => [s.id, s.localName, s.store?.tag, s.getAttribute('xo-stylesheet')]), xml: xo.stores.active.document?.serialize?.() })));
            assert.deepEqual(await state(), expected('Second'));
            throw error;
        }
        assert.deepEqual(await state(), expected('Second'));
        await page.goBack();
        await settled('First');
        assert.deepEqual(await state(), expected('First'));
        await page.goForward();
        await settled('Second');
        assert.deepEqual(await state(), expected('Second'));
        await page.evaluate(async () => {
            const store = xo.stores.active;
            store.document.documentElement.setAttribute('busy', 'true');
            await store.render();
        });
        await page.waitForFunction(() => document.querySelector('#query')?.disabled === true);
        await page.evaluate(async () => {
            const store = xo.stores.active;
            store.document.documentElement.removeAttribute('busy');
            await store.render();
        });
        await page.waitForFunction(() => document.querySelector('#query')?.disabled === false, undefined, { timeout: 4000 });
        assert.deepEqual(await state(), expected('Second'));
        await page.getByRole('link', { name: 'Late' }).click();
        await startedLate.promise;
        await page.getByRole('link', { name: 'First' }).click();
        const lateResponse = page.waitForResponse(response => response.url().endsWith('/late.xml'));
        releaseLate.resolve();
        await lateResponse;
        await page.evaluate(async () => {
            const store = xo.stores['#late'];
            await store.ready;
            await store.render.manager.get(store);
        });
        await settled('First');
        assert.deepEqual(await state(), expected('First'));
    } finally {
        await browser.close();
    }
});
