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
