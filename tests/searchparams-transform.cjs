const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync, statSync } = require('node:fs');
const { resolve, sep } = require('node:path');
const { chromium } = require('playwright');

test('search parameter changes render only their document dependencies and XSLT reads that context', async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.XOVER_TEST_BROWSER_CHANNEL || 'chrome' });
  try {
    const page = await browser.newPage();
    const root = resolve(__dirname, '..');
    await page.route('**/*', route => {
      const pathname = new URL(route.request().url()).pathname;
      if (pathname === '/test.html') return route.fulfill({ contentType: 'text/html', body: '<!doctype html><script src="/xo.js"></script><script>xover.init.dom = async function () {};</script>' });
      const file = resolve(root, '.' + pathname);
      if (!file.startsWith(root + sep) || !existsSync(file) || !statSync(file).isFile()) return route.fulfill({ status: 404, body: '' });
      return route.fulfill({ contentType: file.endsWith('.wasm') ? 'application/wasm' : file.endsWith('.js') ? 'text/javascript' : 'application/octet-stream', body: readFileSync(file) });
    });
    await page.goto('http://xover.test/test.html');
    const result = await page.evaluate(async () => {
      await xover.ready;
      const first = xover.xml.createDocument('<data/>');
      const other = xover.xml.createDocument('<data/>');
      xover.stores['#params-seed'] = first;
      xover.stores['#params-other'] = other;
      first.source.url = '/seed.xml?filter=seed';
      other.source.url = '/other.xml?filter=other';
      history.replaceState({ ...history.state, seed: '#params-seed' }, '', '?filter=navigation#params-seed');
      const style = name => xover.xml.createDocument(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:searchParams="http://panax.io/site/searchParams" version="1.0"><xsl:param name="searchParams:${name}" select="'fallback'"/><xsl:template match="/"><out value="{$searchParams:${name}}"/></xsl:template></xsl:stylesheet>`);
      const filterStyle = style('filter');
      const prefixStyle = style('filterExtra');
      // Finish the documents' initial observer work before registering test sections.
      await new Promise(resolve => setTimeout(resolve, 0));
      const counts = { seed: 0, other: 0, prefix: 0 };
      const sections = [];
      const add = (label, scope, stylesheet) => {
        const section = { scope, stylesheet, contains: () => false, render() { counts[label]++; } };
        sections.push(section);
        xover.sections.add(section);
      };
      add('seed', first, filterStyle);
      add('other', other, filterStyle);
      add('prefix', first, prefixStyle);
      const value = async (document, stylesheet) => {
        const transformed = await document.transform(stylesheet);
        return (transformed.documentElement || transformed.querySelector('out')).getAttribute('value');
      };
      try {
        const params = first.source.url.searchParams;
        const owners = params.url === first.source.url && params.document === first && xover.site.searchParams.url === location;
        other.source.url.searchParams.set('filter', 'other2');
        const afterOther = { ...counts };
        const otherValue = await value(other, filterStyle);
        xover.site.searchParams.set('filter', 'navigation2', 'replace');
        const afterLocation = { ...counts };
        const navigationValue = await value(first, filterStyle);
        params.set('filter', 'seed2');
        params.set('filterExtra', 'extra');
        const afterSource = { ...counts };
        xover.site.searchParams.set('filter', null, 'replace');
        const fallbackValue = await value(first, filterStyle);
        const prefixValue = await value(first, prefixStyle);
        params.append('a', '1');
        params.sort();
        const afterSort = { ...counts };
        other.source.url.searchParams.set('filter', 'other2');
        first.source.url.clone().searchParams.set('filter', 'clone');
        const afterUnchangedAndClone = { ...counts };
        params.set('filter', null);
        const defaultValue = await value(first, filterStyle);
        return { owners, afterOther, afterLocation, afterSource, afterSort, afterUnchangedAndClone, otherValue, navigationValue, fallbackValue, prefixValue, defaultValue };
      } finally {
        sections.forEach(section => xover.sections.delete(section));
      }
    });
    assert.ok(result.owners);
    assert.deepEqual(result.afterOther, { seed: 0, other: 1, prefix: 0 });
    assert.deepEqual(result.afterLocation, { seed: 1, other: 1, prefix: 0 });
    assert.deepEqual(result.afterSource, { seed: 2, other: 1, prefix: 1 });
    assert.deepEqual(result.afterSort, { seed: 4, other: 1, prefix: 2 });
    assert.deepEqual(result.afterUnchangedAndClone, result.afterSort);
    assert.equal(result.otherValue, 'other2');
    assert.equal(result.navigationValue, 'navigation2');
    assert.equal(result.fallbackValue, 'seed2');
    assert.equal(result.prefixValue, 'extra');
    assert.equal(result.defaultValue, 'fallback');
  } finally {
    await browser.close();
  }
});
