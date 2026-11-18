const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync, statSync } = require('node:fs');
const { resolve, sep } = require('node:path');
const { chromium } = require('playwright');

test('refresh widget filters URL events by inherited scope and explicit seed scope', async () => {
  const widgetPath = process.env.XOVER_REFRESH_WIDGET || resolve(__dirname, '../../../widgets/refresh_button.xhtml');
  const widget = readFileSync(widgetPath, 'utf8');
  const browser = await chromium.launch({ headless: true, channel: process.env.XOVER_TEST_BROWSER_CHANNEL || 'chrome' });
  try {
    const page = await browser.newPage();
    const root = resolve(__dirname, '..');
    const requests = [];
    await page.route('**/*', route => {
      const url = new URL(route.request().url());
      if (url.pathname === '/test.html') return route.fulfill({ contentType: 'text/html', body: '<!doctype html><script src="/xo.js"></script><script>xover.init.dom = async function () {};</script>' });
      if (url.pathname === '/refresh-first.xml' || url.pathname === '/refresh-other.xml') {
        requests.push(url.pathname + url.search);
        return route.fulfill({ contentType: 'application/xml', body: '<data/>' });
      }
      const file = resolve(root, '.' + url.pathname);
      if (!file.startsWith(root + sep) || !existsSync(file) || !statSync(file).isFile()) return route.fulfill({ status: 404, body: '' });
      return route.fulfill({ contentType: file.endsWith('.wasm') ? 'application/wasm' : file.endsWith('.js') ? 'text/javascript' : 'application/octet-stream', body: readFileSync(file) });
    });
    await page.goto('http://xover.test/test.html');
    const result = await page.evaluate(async widget => {
      await xover.ready;
      const parsed = new DOMParser().parseFromString(widget, 'text/html');
      Function(parsed.querySelector('script').textContent)();
      const template = parsed.querySelector('template');
      class RefreshTest extends HTMLElement {}
      RefreshTest.extend = methods => xover.component.extend(RefreshTest.prototype, methods);
      customElements.define('arbitrary-refresh-widget', RefreshTest);
      const make = async (tag, path) => {
        const document = xover.xml.createDocument('<data/>');
        xover.stores[tag] = document;
        const store = xover.stores[tag];
        store.source.url = path;
        store.source.url.appliedHref = store.source.url.href;
        const button = new RefreshTest();
        button.attachShadow({ mode: 'open' }).append(template.content.cloneNode(true));
        await xover.component.applyScripts(button, button.shadowRoot);
        const section = window.document.createElement('section');
        section.setAttribute('xo-store', tag);
        section.append(button);
        window.document.body.append(section);
        return { button, store, source: store.source };
      };
      const first = await make('#refresh-first', '/refresh-first.xml?filter=one');
      const other = await make('#refresh-other', '/refresh-other.xml?filter=other');
      await first.store.save(); // The external refresh consumer selects the active store.
      history.replaceState({ ...history.state, active: '#refresh-first', seed: '#refresh-first' }, '', '#refresh-first');
      const refreshArguments = [];
      window.addEventListener('refresh', event => refreshArguments.push(event.detail.args.length));
      const urlReasons = [];
      window.addEventListener('urlchange', event => urlReasons.push(event.detail.reason));
      const state = button => ({
        text: button.shadowRoot.textContent.trim(),
        label: button.getAttribute('aria-label'), title: button.getAttribute('title'),
        dirty: button.hasAttribute('data-dirty'), icon: button.shadowRoot.querySelector('svg').getAttribute('class')
      });
      const initial = state(first.button);
      first.source.url.searchParams.set('filter', 'two');
      const pending = state(first.button);
      const untouched = state(other.button);
      first.source.url.searchParams.set('filter', 'one');
      const reverted = state(first.button);
      first.source.url.searchParams.set('filter', 'three');
      first.button.init();
      first.button.init(); // Recomposing must not attach duplicate click callbacks.
      first.button.click();
      await first.source.fetching;
      const applied = state(first.button);
      first.button.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', cancelable: true }));
      await first.source.fetching;
      const afterKeyboard = state(first.button);
      other.source.url.searchParams.set('filter', 'changed');
      const afterOther = state(first.button);
      const otherPending = state(other.button);
      // Explicit scope overrides the menu's inherited document and resolves seed dynamically.
      other.button.setAttribute('xo-store', 'seed');
      first.source.url.searchParams.set('filter', 'four');
      const seedPending = state(other.button);
      other.source.url.searchParams.set('filter', 'other');
      const ignoredFormerScope = state(other.button);
      first.source.url.searchParams.set('filter', 'three');
      const seedClean = state(other.button);
      // Events without an associated document cannot match a component's scope.
      window.dispatchEvent(new CustomEvent('urlchange', { detail: { dirty: false } }));
      const externalClean = state(first.button);
      window.dispatchEvent(new CustomEvent('urlchange', { detail: { dirty: true } }));
      const externalPending = state(first.button);
      return { urlReasons, initial, pending, untouched, reverted, applied, afterKeyboard, afterOther, otherPending, seedPending, ignoredFormerScope, seedClean, externalClean, externalPending, refreshArguments };
    }, widget);
    const clean = { text: '', label: 'Actualizar', title: 'Actualizar', dirty: false, icon: 'bi bi-arrow-clockwise' };
    const pending = { text: '', label: 'Continuar', title: 'Continuar', dirty: true, icon: 'bi bi-arrow-right' };
    assert.deepEqual(result.initial, clean);
    assert.deepEqual(result.pending, pending);
    assert.deepEqual(result.untouched, clean);
    assert.deepEqual(result.reverted, clean);
    assert.deepEqual(result.applied, clean);
    assert.deepEqual(result.afterKeyboard, clean);
    assert.deepEqual(result.afterOther, clean);
    assert.deepEqual(result.otherPending, pending);
    assert.deepEqual(result.seedPending, pending);
    assert.deepEqual(result.ignoredFormerScope, pending);
    assert.deepEqual(result.seedClean, clean);
    assert.deepEqual(result.externalClean, clean);
    assert.deepEqual(result.externalPending, clean);
    assert.deepEqual(result.refreshArguments, [0, 0]);
    assert.equal(result.urlReasons.includes('fetch'), false);
    assert.deepEqual(requests, ['/refresh-first.xml?filter=three', '/refresh-first.xml?filter=three']);
  } finally {
    await browser.close();
  }
});
