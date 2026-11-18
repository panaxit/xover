const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync, statSync } = require('node:fs');
const { join, resolve, sep } = require('node:path');
const { chromium } = require('playwright');

const code = readFileSync(join(__dirname, '../xo.js'), 'utf8');
const between = (start, end) => code.slice(code.indexOf(start), code.indexOf(end, code.indexOf(start)));

test('object listeners isolate dispatch and preserve patterns, native events and URL notifications', async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.XOVER_TEST_BROWSER_CHANNEL || 'chrome' });
  try {
    const page = await browser.newPage();
    await page.route('http://xover.test/**', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html>' }));
    await page.goto('http://xover.test/');
    const result = await page.evaluate(async ({ eventCode, matches, dispatcher, on, notifications, mutations, searchParams }) => {
      Array.prototype.distinct = function () { return [...new Set(this)]; };
      Array.prototype.coalesce = function () { return this.find(value => value != null && value !== false); };
      window.xover = window.xo = {
        listener: Object.assign(new Map(), { objects: new WeakMap() }), init: Object.assign(() => {}, { status: 'manifest-ready' }),
        site: { sections: [], seed: '#seed' }, stores: { seed: { document: {} } }, references: { scopeDocument() { return this.scope; } }, Store: class {}, Source: class {}, URL: class extends URL {}
      };
      window.instanceOf = function (type) { return this instanceof type; };
      window.existsFunction = () => false;
      xover.listener.debug = Object.assign(() => {}, { matches: () => false });
      xover.listener.history = { has: () => false, overflowed: () => false, set() {} };
      xover.listener.resolve = value => typeof value === 'function' ? value : undefined;
      for (const source of [eventCode, matches, dispatcher, on, notifications]) (0, eval)(source);

      const first = {}, second = {};
      const hits = [];
      xover.listener.on('ping', first, function (event) { hits.push(['first', this === first, event.detail.value]); });
      xover.listener.on('ping', second, function (event) { hits.push(['second', this === second, event.detail.value]); });
      const emit = async (name, context, detail = {}) => {
        const event = new xover.listener.Event(name, detail, context);
        window.dispatchEvent(event);
        await event.detail.returnValue;
      };
      await emit('ping', first, { value: 1 });
      await emit('ping', second, { value: 2 });
      await emit('ping', {}, { value: 3 });
      let reloadHits = 0, objectReloadHits = 0;
      const installGlobal = () => xover.listener.on('reload-check', function () { reloadHits++; });
      const installObject = () => xover.listener.on('object-reload-check', first, function () { objectReloadHits++; });
      installGlobal(); installGlobal();
      installObject(); installObject();
      await emit('reload-check', {});
      await emit('object-reload-check', first);
      const keyHits = [];
      const owners = [{ name: 'first' }, { name: 'second' }];
      for (let reload = 0; reload < 2; reload++) {
        for (const owner of owners) {
          xover.listener.on('keyed-reload-check', function () { keyHits.push(owner.name); }, { key: owner });
        }
      }
      await emit('keyed-reload-check', {});

      let patternHits = 0, objectChanges = 0, nativeHits = 0;
      xover.listener.on('ping::#sample', function () { patternHits++; });
      await emit('ping', { tag: '#sample' });
      xover.listener.on('change', first, function () { objectChanges++; });
      await emit('change', first);
      xover.listener.on('hashchange', window, function () { nativeHits++; });
      window.dispatchEvent(new HashChangeEvent('hashchange'));
      await emit('hashchange', first);

      const SearchParams = Function(searchParams + '\nreturn SearchParams;')();
      const url = new xover.URL('https://example.test/?b=1');
      url.source = { url };
      url.appliedHref = url.href;
      const originalParams = url.searchParams;
      Function('SearchParams', 'url', mutations)(SearchParams, url);
      const identityPreserved = originalParams === url.searchParams && url.searchParams instanceof SearchParams;
      const otherURL = new xover.URL('https://example.test/?b=1');
      otherURL.source = { url: otherURL };
      Function('SearchParams', 'url', mutations)(SearchParams, otherURL);
      const changes = [];
      xover.listener.on('urlchange', url, function (event) {
        changes.push({ reason: event.detail.reason, param: event.detail.param, previousValue: event.detail.previousValue, value: event.detail.value, dirty: event.detail.dirty, same: this === url });
      });
      otherURL.searchParams.set('b', '9');
      url.searchParams.set('b', '2');
      url.searchParams.set('b', '2'); // No event for an unchanged URL.
      url.searchParams.append('a', '3');
      url.searchParams.sort();
      url.searchParams.delete('a', 'wrong');
      url.searchParams.delete('a', '3');
      url.appliedHref = url.href;
      url.notifyChange({ reason: 'fetch' });

      let renders = 0, siteEvents = 0;
      xover.site.sections = [{ scope: xover.stores.seed.document, stylesheet: { selectNodes: () => ['a', 'flag', 'z'].map(name => ({ getAttribute: () => 'searchParams:' + name })) }, render() { renders++; } }];
      history.replaceState({ active: '#sample' }, '', '/?a=1#sample');
      const standalone = new SearchParams('?standalone=1');
      standalone.set('standalone', '2');
      const standaloneHasNoEffects = renders === 0 && location.search === '?a=1';
      const params = xover.site.searchParams;
      const historyLength = history.length;
      let urlWasUpdatedBeforeListener = true;
      xover.listener.on('searchParams', params, function () { siteEvents++; urlWasUpdatedBeforeListener &&= location.search === (this.toString() ? '?' + this.toString().replace(/=(&|$)/g, '$1') : ''); });
      params.set('a', '2');
      params.set('a', null);
      params.set('flag');
      const previousState = history.state.prev.searchParams;
      params.set('flag', undefined); // Unchanged query must not push history or render.
      params.set('flag', 'yes', 'replace');
      const replaceKeptLength = history.length === historyLength + 3;
      params.delete('flag');
      params.append('z', '1');
      params.append('a', '2');
      params.sort();
      const historyBeforeURLMutation = history.length;
      url.searchParams.set('nullable', 'present');
      url.searchParams.set('nullable', null);
      const removedNullValue = url.searchParams.get('nullable');
      const urlDidNotNavigate = history.length === historyBeforeURLMutation && location.search === '?a=2&z=1';
      const directUpdateLinked = (url.search = '?direct=1', url.searchParams.get('direct') === '1');
      return { reloadHits, objectReloadHits, keyHits: keyHits.sort(), hits, patternHits, objectChanges, nativeHits, changes, renders, siteEvents, entries: params.entries(), search: location.search, identityPreserved, standaloneHasNoEffects, urlWasUpdatedBeforeListener, replaceKeptLength, previousState, removedNullValue, urlDidNotNavigate, directUpdateLinked };
    }, {
      eventCode: between('xover.listener.Event = function', 'xover.listener.Event.prototype'),
      matches: between("Object.defineProperty(xover.listener, 'matches'", 'xover.listener.debugger ='),
      dispatcher: between("Object.defineProperty(xover.listener, 'dispatcher'", 'xover.listener.silenced ='),
      on: between("Object.defineProperty(xover.listener, 'on'", "xover.listener.on('hashchange'"),
      notifications: between('Object.defineProperties(xover.URL.prototype, {\n\tdirty:', "Object.defineProperty(URL.prototype, 'filename'"),
      mutations: 'new SearchParams(url.searchParams, url);',
      searchParams: between('class SearchParams extends URLSearchParams {', "Object.defineProperty(xover.site, 'state'")
    });
    assert.deepEqual(result.hits, [['first', true, 1], ['second', true, 2]]);
    assert.equal(result.reloadHits, 1);
    assert.equal(result.objectReloadHits, 1);
    assert.deepEqual(result.keyHits, ['first', 'second']);
    assert.equal(result.patternHits, 1);
    assert.equal(result.objectChanges, 1);
    assert.equal(result.nativeHits, 1);
    assert.deepEqual(result.changes.map(change => change.reason), ['searchParams', 'searchParams', 'searchParams', 'searchParams', 'fetch', 'searchParams', 'searchParams']);
    assert.deepEqual(result.changes[0], { reason: 'searchParams', param: 'b', previousValue: '1', value: '2', dirty: true, same: true });
    assert.equal(result.changes[4].dirty, false);
    assert.ok(result.changes.every(change => change.same));
    assert.equal(result.renders, 8, JSON.stringify(result));
    assert.equal(result.siteEvents, 8);
    assert.deepEqual(result.entries, [['a', '2'], ['z', '1']]);
    assert.equal(result.search, '?a=2&z=1');
    assert.ok(result.identityPreserved);
    assert.ok(result.standaloneHasNoEffects);
    assert.ok(result.urlWasUpdatedBeforeListener);
    assert.ok(result.replaceKeptLength);
    assert.deepEqual(result.previousState, {});
    assert.equal(result.removedNullValue, null);
    assert.ok(result.urlDidNotNavigate);
    assert.ok(result.directUpdateLinked);
  } finally {
    await browser.close();
  }
});

test('the complete runtime wires URL and location owners through the shared extension', async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.XOVER_TEST_BROWSER_CHANNEL || 'chrome' });
  try {
    const page = await browser.newPage();
    const root = resolve(__dirname, '..');
    await page.route('**/*', route => {
      const pathname = new URL(route.request().url()).pathname;
      if (pathname === '/runtime.html') return route.fulfill({ contentType: 'text/html', body: '<!doctype html><script src="/xo.js"></script><script>xover.init.dom = async function () {};</script>' });
      const file = resolve(root, '.' + pathname);
      if (!file.startsWith(root + sep) || !existsSync(file) || !statSync(file).isFile()) return route.fulfill({ status: 404, body: '' });
      return route.fulfill({ contentType: file.endsWith('.wasm') ? 'application/wasm' : file.endsWith('.js') ? 'text/javascript' : 'application/octet-stream', body: readFileSync(file) });
    });
    await page.goto('http://xover.test/runtime.html');
    const result = await page.evaluate(async () => {
      await xover.modernize();
      const url = xover.URL('https://example.test/?a=1');
      url.source = { url };
      const events = [];
      xover.listener.on('urlchange', url, function (event) {
        events.push({ type: event.type, value: event.detail.value, dirty: event.detail.dirty, context: this === url });
      });
      const params = url.searchParams;
      params.set('a', '2');
      params.toggle('a', '2');
      params.append('a', '3');
      const originalEvents = events.slice();
      url.parameters['@titular'] = 'someone';
      url.parameters['@titular'] = null;
      const nullAssignmentRemoved = !url.searchParams.has('@titular');
      const clone = url.clone();
      clone.searchParams.set('a', '4');
      const request = new xover.Request(clone);
      const requestEvents = [];
      xover.listener.on('urlchange', request.url, function ({ url: changedURL, param, value }) {
        requestEvents.push({ same: changedURL === request.url, param, value });
      });
      request.searchParams.set('a', '5'); // A URL without a source also emits.
      request.searchParams.set('a', '5'); // Unchanged parameters do not emit.
      request.source = url.source; // A URL need not be the source's principal URL.
      request.searchParams.delete('a');
      const initialSourceLinked = request.url.source === request.source;
      const replacementSource = { document: xover.xml.createDocument('<replacement/>'), url };
      request.source = replacementSource;
      const replacementSourceLinked = request.url.source === replacementSource;
      let eventSourceLinked = false;
      xover.listener.on('urlchange', request.url, function ({ source, url: changedURL }) {
        eventSourceLinked = source === replacementSource && changedURL.source.document === replacementSource.document;
      });
      request.url.notifyChange();
      request.source = undefined;
      const clearedSourceLinked = request.url.source === undefined;
      const ownedRequest = new xover.Request(url);
      ownedRequest.source = replacementSource;
      const preservedOwner = url.source.url === url && url.source !== replacementSource;
      const standaloneURL = xover.URL('https://example.test/?flag=one');
      let standaloneEvents = 0;
      xover.listener.on('urlchange', standaloneURL, function () { standaloneEvents++; });
      standaloneURL.searchParams.set('flag', 'two');
      const adoptedURL = new URL('https://example.test/?filter=one');
      const nativeParams = adoptedURL.searchParams;
      Object.setPrototypeOf(adoptedURL, xover.URL.prototype);
      const adoptedRequest = new xover.Request(adoptedURL);
      let adoptedEvents = 0;
      xover.listener.on('urlchange', adoptedURL, function () { adoptedEvents++; });
      const usesExtendedMethods = adoptedRequest.searchParams.set === params.set;
      adoptedRequest.searchParams.set('filter', 'two');
      adoptedRequest.searchParams.set('nullable', 'value');
      adoptedRequest.searchParams.set('nullable', null);
      const dirtyRequest = new xover.Request(xover.URL('http://xover.test/dirty.xml?filter=one'));
      dirtyRequest.source = url.source; // Its principal URL uses an unrelated endpoint.
      dirtyRequest.settings.cache = 'reload';
      dirtyRequest.settings.resumable = false;
      const dirtyStates = [dirtyRequest.url.dirty];
      dirtyRequest.searchParams.set('filter', 'two');
      dirtyStates.push(dirtyRequest.url.dirty);
      dirtyRequest.searchParams.set('filter', 'one');
      dirtyStates.push(dirtyRequest.url.dirty);
      const originalFetch = window.fetch;
      let mutateDuringFetch = false;
      window.fetch = async function (input, ...args) {
        if (!input.url?.includes('/dirty.xml')) return originalFetch.call(this, input, ...args);
        if (mutateDuringFetch) dirtyRequest.searchParams.set('filter', 'later');
        return new Response('<data/>', { headers: { 'Content-Type': 'application/xml' } });
      };
      try {
        dirtyRequest.searchParams.set('filter', 'two');
        await dirtyRequest.fetch();
        await new Promise(resolve => setTimeout(resolve, 0));
        dirtyStates.push(dirtyRequest.url.dirty);
        dirtyRequest.searchParams.set('filter', 'three');
        mutateDuringFetch = true;
        await dirtyRequest.fetch();
        dirtyStates.push(dirtyRequest.url.dirty);
        dirtyRequest.searchParams.set('filter', 'three');
        dirtyStates.push(dirtyRequest.url.dirty);
      } finally { window.fetch = originalFetch; }
      const site = xover.site.searchParams;
      site.set('flag', undefined, 'replace');
      const previousState = history.state.prev.searchParams;
      const query = location.search;
      site.delete('flag');
      return { dirtyStates, initialSourceLinked, replacementSourceLinked, eventSourceLinked, clearedSourceLinked, preservedOwner, usesExtendedMethods, adoptedEvents, adoptedLinked: adoptedRequest.searchParams === nativeParams && nativeParams.url === adoptedURL, adoptedFilter: adoptedURL.searchParams.get('filter'), adoptedNullable: adoptedURL.searchParams.has('nullable'), requestEvents, standaloneEvents, events: originalEvents, nullAssignmentRemoved, linked: params === url.searchParams, urlValue: url.searchParams.get('a'), cloneValue: clone.searchParams.get('a'), previousState, query, cleared: location.search === '', sameBase: Object.getPrototypeOf(Object.getPrototypeOf(site)) === Object.getPrototypeOf(params) };
    });
    assert.deepEqual(result.events, [
      { type: 'urlchange', value: '2', dirty: true, context: true },
      { type: 'urlchange', value: null, dirty: true, context: true },
      { type: 'urlchange', value: '3', dirty: true, context: true }
    ]);
    assert.ok(result.linked);
    assert.ok(result.nullAssignmentRemoved);
    assert.ok(result.sameBase);
    assert.deepEqual(result.requestEvents, [
      { same: true, param: 'a', value: '5' },
      { same: true, param: 'a', value: null },
      { same: true, param: undefined, value: undefined }
    ]);
    assert.ok(result.initialSourceLinked);
    assert.ok(result.replacementSourceLinked);
    assert.ok(result.eventSourceLinked);
    assert.ok(result.clearedSourceLinked);
    assert.ok(result.preservedOwner);
    assert.deepEqual(result.dirtyStates, [false, true, false, false, true, false]);
    assert.equal(result.standaloneEvents, 1);
    assert.ok(result.usesExtendedMethods);
    assert.equal(result.adoptedEvents, 3);
    assert.ok(result.adoptedLinked);
    assert.equal(result.adoptedFilter, 'two');
    assert.equal(result.adoptedNullable, false);
    assert.equal(result.urlValue, '3');
    assert.equal(result.cloneValue, null);
    assert.equal(result.query, '?flag');
    assert.deepEqual(result.previousState, {});
    assert.ok(result.cleared);
  } finally {
    await browser.close();
  }
});
