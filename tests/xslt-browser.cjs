const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '..');
let server, browser, origin;
const xsl = '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:param name="value"/><xsl:template match="/"><ok value="{$value}"><xsl:value-of select="/test"/></ok></xsl:template></xsl:stylesheet>';

before(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/test.html') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.end('<!doctype html><html><head><script src="/xo.js?test=1"></script><script>xover.init.dom = async function () {};</script></head><body></body></html>');
    }
    if (url.pathname === '/public.xml') {
      res.setHeader('Content-Type', 'application/xml');
      return res.end('<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="/public.xsl"?><test><script xmlns="http://www.w3.org/1999/xhtml" src="/polyfills/xslt.js"></script>public</test>');
    }
    if (url.pathname === '/public.xsl') {
      res.setHeader('Content-Type', 'application/xml');
      return res.end('<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:output method="html"/><xsl:template match="/"><html><body><p id="result">public works</p></body></html></xsl:template></xsl:stylesheet>');
    }
    const file = path.resolve(root, '.' + url.pathname);
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404); return res.end();
    }
    res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'application/octet-stream');
    res.end(fs.readFileSync(file));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true, channel: 'chrome', args: ['--disable-extensions'] });
});
after(async () => { await browser?.close(); await new Promise(resolve => server?.close(resolve)); });

async function pageFor(mode) {
  const page = await browser.newPage();
  if (mode) await page.addInitScript(mode => {
    if (mode === 'absent') delete window.XSLTProcessor;
    if (mode === 'throws') window.XSLTProcessor = class { constructor() { throw Error('disabled'); } };
    if (mode === 'null') window.XSLTProcessor = class { importStylesheet() {} setParameter() {} transformToDocument() { return null; } };
  }, mode);
  return page;
}

test('URL paths escape deployment prefixes without an external helper', async () => {
  const page = await pageFor();
  await page.goto(origin + '/test.html');
  const result = await page.evaluate(async () => {
    await xover.modernize();
    location.basepath = '/dev.1/';
    const matching = new URL('/dev.1/reports/file.xml', location.href).path;
    const unrelated = new URL('/devX1/reports/file.xml', location.href).path;
    location.basepath = '';
    const own = new URL('/module+v1/reports/file.xml', location.href);
    Object.defineProperty(own, 'basepath', { value: '/module+v1/' });
    return { matching, unrelated, own: own.path };
  });
  assert.deepEqual(result, { matching: 'reports', unrelated: 'devX1/reports', own: 'reports' });
  await page.close();
});

test('layered manifest source proxies preserve null overrides without recursion', async () => {
  const page = await pageFor();
  await page.goto(origin + '/test.html');
  const result = await page.evaluate(async () => {
    await xover.modernize();
    const manifest = new xover.Manifest({ sources: { '#login': null, '#shell': null } });
    xover.manifest = new xover.Manifest(manifest);
    return { login: xover.manifest.sources['#login'], shell: xover.manifest.sources['#shell'] };
  });
  assert.deepEqual(result, { login: null, shell: null });
  await page.close();
});

for (const mode of [undefined, 'absent', 'throws', 'null']) test(`full XOver transformation: ${mode || 'native'}`, async () => {
  const page = await pageFor(mode);
  const requested = [];
  page.on('request', req => requested.push(req.url()));
  await page.goto(origin + '/test.html');
  const result = await page.evaluate(async xslText => {
    const first = xover.modernize();
    const same = first === xover.modernize();
    await first;
    const parser = new DOMParser();
    const source = parser.parseFromString('<test> xml</test>', 'application/xml');
    const style = parser.parseFromString(xslText, 'application/xml');
    const processor = new XSLTProcessor();
    processor.setParameter(null, 'value', 'ready');
    processor.importStylesheet(style);
    const doc = processor.transformToDocument(source);
    const fragment = processor.transformToFragment(source, document);
    const transformed = await source.transform(style);
    const output = transformed.documentElement || transformed.querySelector('ok');
    return { same, modernized: window.modernized, doc: doc.documentElement.getAttribute('value'),
      fragment: fragment.querySelector('ok').getAttribute('value'), transformed: output.getAttribute('value'), text: output.lastChild.textContent,
      polyfill: !!processor.isPolyfill?.() };
  }, xsl);
  assert.equal(result.same, true);
  assert.equal(result.modernized, true);
  assert.equal(result.doc, 'ready');
  assert.equal(result.fragment, 'ready');
  // XOver supplies false for this unbound parameter in both implementations.
  assert.equal(result.transformed, 'false');
  assert.equal(result.text, ' xml');
  assert.equal(result.polyfill, !!mode);
  assert.equal(requested.some(url => url.includes('/polyfills/')), !!mode);
  await page.close();
});

test('download failure rejects concurrent modernization and init without success event', async () => {
  const page = await pageFor('absent');
  await page.route('**/xslt-polyfill.min.js', route => route.abort());
  await page.goto(origin + '/test.html');
  const result = await page.evaluate(async () => {
    let initialized = false, observed = false;
    window.addEventListener('xover-initialized', () => initialized = true);
    xover.dom.Observer = () => observed = true;
    const results = await Promise.allSettled([xover.modernize(), xover.modernize(), xover.init()]);
    const again = await Promise.allSettled([xover.init()]);
    return { results: results.map(r => r.status), again: again[0].status, initialized, observed, status: xover.init.status };
  });
  assert.deepEqual(result, { results: ['rejected', 'rejected', 'rejected'], again: 'rejected', initialized: false, observed: false, status: 'error' });
  await page.close();
});

test('a raw XML page boots with the browser XSLT feature disabled and no extension', async () => {
  // Removing the JS constructor alone would not disable native PI processing.
  const disabledBrowser = await chromium.launch({ headless: true, channel: 'chrome', args: ['--disable-extensions', '--disable-blink-features=XSLT'] });
  try {
    const page = await disabledBrowser.newPage();
    const requested = [];
    page.on('request', req => requested.push(req.url()));
    await page.goto(origin + '/public.xml');
    await page.waitForFunction(() => document.getElementById('result')?.textContent === 'public works');
    assert.ok(requested.some(url => url.endsWith('/xslt-polyfill.min.js')));
    assert.equal(await page.evaluate(() => new XSLTProcessor().isPolyfill()), true);
  } finally { await disabledBrowser.close(); }
});

test('init waits for the engine before observers, manifest and render', async () => {
  const page = await pageFor('absent');
  let release;
  const gate = new Promise(resolve => release = resolve);
  await page.route('**/xslt-polyfill.min.js', async route => { await gate; await route.continue(); });
  await page.goto(origin + '/test.html', { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => {
    window.steps = [];
    xover.dom.Observer = () => steps.push('observer');
    xover.manifest.init = async () => steps.push('manifest');
    xover.manifest.start = [];
    xover.dom.updateTitle = () => steps.push('title');
    window.addEventListener('xover-initialized', () => steps.push('initialized'));
    window.initializing = xover.init();
  });
  assert.deepEqual(await page.evaluate(() => steps), []);
  release();
  assert.deepEqual(await page.evaluate(async () => { await initializing; return steps; }), ['observer', 'manifest', 'title', 'initialized']);
  await page.close();
});

test('an explicit iframe window gets its own processor and extensions', async () => {
  const page = await pageFor('absent');
  await page.goto(origin + '/test.html');
  const result = await page.evaluate(async () => {
    await xover.modernize();
    const frame = document.createElement('iframe');
    document.body.appendChild(frame);
    const child = frame.contentWindow;
    delete child.XSLTProcessor;
    const first = xover.modernize(child);
    const same = first === xover.modernize.call(child);
    await first;
    return { same, modernized: child.modernized, polyfill: new child.XSLTProcessor().isPolyfill(), extended: typeof child.XSLTProcessor.prototype.asyncTransform };
  });
  assert.deepEqual(result, { same: true, modernized: true, polyfill: true, extended: 'function' });
  await page.close();
});

for (const failure of ['bootstrap', 'wasm', 'timeout', 'invalid']) test(`initialization rejects on ${failure} failure`, async () => {
  const page = await pageFor('absent');
  if (failure === 'bootstrap') await page.route('**/polyfills/xslt.js', route => route.abort());
  if (failure === 'wasm') await page.addInitScript(() => {
    WebAssembly.Module = class { constructor() { throw new Error('Wasm blocked'); } };
    WebAssembly.Instance = class { constructor() { throw new Error('Wasm blocked'); } };
    WebAssembly.instantiate = () => Promise.reject(new Error('Wasm blocked'));
    WebAssembly.instantiateStreaming = () => Promise.reject(new Error('Wasm blocked'));
  });
  if (failure === 'timeout') {
    await page.addInitScript(() => {
      const nativeTimeout = window.setTimeout;
      window.setTimeout = (fn, ms, ...args) => nativeTimeout(fn, ms >= 30000 ? 250 : ms, ...args);
    });
    await page.route('**/xslt-polyfill.min.js', route => route.fulfill({ contentType: 'text/javascript', body: 'window.xsltPolyfillReady = () => new Promise(() => {});' }));
  }
  if (failure === 'invalid') await page.route('**/xslt-polyfill.min.js', route => route.fulfill({ contentType: 'text/javascript', body: 'window.xsltPolyfillReady = () => Promise.resolve();' }));
  await page.goto(origin + '/test.html');
  const result = await page.evaluate(async () => {
    const results = await Promise.allSettled([xover.modernize(), xover.init()]);
    return results.map(r => ({ status: r.status, message: r.reason?.message }));
  });
  assert.ok(result.every(r => r.status === 'rejected' && r.message), JSON.stringify(result));
  await page.close();
});
