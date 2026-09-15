const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const code = readFileSync(require('node:path').join(__dirname, '../xo.js'), 'utf8');

function harness() {
  const xover = { references: {}, xml: {}, components: {} };
  const Node = { ELEMENT_NODE: 1 };
  const HTMLTemplateElement = class HTMLTemplateElement {};
  const instanceOf = { call(value, ...constructors) { return constructors.some(constructor => value instanceof constructor); } };
  for (const [start, end] of [
    ['xover.references.scopeChanged =', 'xover.references.signature ='],
    ['xover.xml.getDifferences =', 'xover.xml.parseErrors ='],
    ['xover.xml.staticMerge =', 'xover.xml.getMetaNodes ='],
    ['xover.xml.combine =', 'xover.dom.combine =']
  ]) {
    // Load each function from the implementation without booting the application.
    const begin = code.indexOf(start);
    const finish = code.indexOf(end, begin);
    assert.ok(begin >= 0 && finish > begin);
    if (start === 'xover.references.scopeChanged =') {
      Function('xover', 'Node', 'instanceOf', 'HTMLTemplateElement', code.slice(begin, finish))(xover, Node, instanceOf, HTMLTemplateElement);
    } else {
      const declaration = code.slice(begin, code.indexOf('\n}', begin) + 2);
      Function('xover', 'Node', 'instanceOf', 'HTMLTemplateElement', declaration)(xover, Node, instanceOf, HTMLTemplateElement);
    }
  }
  xover.xml.getMetaNodes = function () { return []; };
  xover.HTMLTemplateElement = HTMLTemplateElement;
  return xover;
}

function section() {
  return {
    nodeType: 1, shadowRoot: null,
    hasAttribute: () => false,
    isEqualNode: () => true,
    querySelectorAll: () => [],
    replaceWith(node) { this.replacement = node; }
  };
}

test('refresh replaces the section even when the store and rendered markup are equal', () => {
  const xover = harness();
  const store = { documentElement: {} };
  const current = section();
  current.scope = store.documentElement;
  store.documentElement = {};
  const incoming = section();
  incoming.scope = store.documentElement;
  const differences = xover.xml.getDifferences(current, incoming);
  assert.equal(differences.length, 1);
  assert.equal(differences[0].get(current), incoming);
  // Changed input must return before planning any old descendant transplants.
  xover.xml.staticMerge(current, incoming);
  assert.equal(xover.xml.combine(current, incoming), incoming);
  assert.equal(current.replacement, incoming);
});

test('a filter refresh with the same origin signature still replaces the entire DOM node', () => {
  const xover = harness();
  const current = section();
  const incoming = section();
  current.getAttribute = incoming.getAttribute = () => 'same-source|section|report';
  current.scope = {};
  incoming.scope = {};
  assert.equal(xover.xml.combine(current, incoming), incoming);
  assert.equal(current.replacement, incoming);
});

test('a scoped template reaches template composition instead of replacing its host', () => {
  const xover = harness();
  const current = section();
  const template = new xover.HTMLTemplateElement();
  current.scope = {};
  template.scope = {};
  assert.deepEqual(xover.xml.getDifferences(current, template), []);
});

test('editing an existing data node keeps incremental rendering available', () => {
  const xover = harness();
  const input = {};
  const current = section();
  const incoming = section();
  current.scope = input;
  input.filter = 'updated';
  incoming.scope = input;
  assert.equal(xover.references.scopeChanged(current, incoming), false);
  assert.deepEqual(xover.xml.getDifferences(current, incoming), []);
});

test('parent-generated placeholders without a render input do not force child replacement', () => {
  const xover = harness();
  const current = section();
  const placeholder = section();
  current.scope = {};
  assert.equal(xover.references.scopeChanged(current, placeholder), false);
});

test('separate sections retain independent input identities', () => {
  const xover = harness();
  const current = section();
  const incoming = section();
  const unrelated = section();
  const input = {};
  current.scope = input;
  incoming.scope = input;
  unrelated.scope = {};
  assert.equal(xover.references.scopeChanged(current, incoming), false);
});

function attributeSection(attr) {
  return Object.assign(section(), {
    getAttributeNode: name => name === attr.name ? attr : null,
    hasAttribute: name => name === attr.name,
    closest(selector) { return selector.startsWith('[xo-store]') ? this : null; }
  });
}

test('source resolution honors the captured reference for active, seed and inherit', () => {
  const xover = harness();
  const begin = code.indexOf('xover.references.source =');
  const end = code.indexOf('xover.references.find =', begin);
  Function('xover', code.slice(begin, end))(xover);
  xover.references.expand = value => value;
  const oldNode = { nodeType: 9 };
  const newNode = { nodeType: 9 };
  for (const alias of ['active', 'seed', 'inherit']) {
    xover.sources = { [alias]: newNode };
    const attr = { name: 'xo-store', value: alias, source: oldNode };
    assert.equal(xover.references.source.call(attr), oldNode);
    assert.equal(xover.references.source.call({ name: 'xo-store', value: alias }), newNode);
  }
});

test('scope getter returns captured document, element or attribute without resolving aliases again', () => {
  const xover = harness();
  const begin = code.indexOf('let scope_handler = {');
  const end = code.indexOf('const legacy_source_handler =', begin);
  const scopeHandler = Function('xover', 'HTMLTableCellElement', 'Node', code.slice(begin, end) + ';return scope_handler;')(
    xover, class {}, { TEXT_NODE: 3 }
  );
  xover.references.cached = () => { throw new Error('Bound scope must not be resolved again'); };
  for (const nodeType of [9, 1, 2]) {
    const savedNode = { nodeType };
    const attr = { name: 'xo-scope', value: 'same-selector', source: { URL: 'same-url' }, scope: savedNode };
    const el = attributeSection(attr);
    Object.defineProperty(el, 'scope', { get: scopeHandler.get });
    assert.equal(scopeHandler.get.call(el), savedNode);
    attr.source = { URL: 'another-url' };
    assert.equal(scopeHandler.get.call(el), savedNode);
    const incoming = attributeSection({ ...attr, scope: { nodeType } });
    Object.defineProperty(incoming, 'scope', { get: scopeHandler.get });
    assert.equal(xover.references.scopeChanged(el, incoming), true);
  }
});

test('scope getter resolves again when fetch replaces its source document', () => {
  const xover = harness();
  const begin = code.indexOf('let scope_handler = {');
  const end = code.indexOf('const legacy_source_handler =', begin);
  const scopeHandler = Function('xover', 'HTMLTableCellElement', 'Node', code.slice(begin, end) + ';return scope_handler;')(
    xover, class {}, { TEXT_NODE: 3 }
  );
  xover.references.expand = value => value;
  xover.references.find = () => null;
  const firstDocument = { nodeType: 9 };
  const secondDocument = { nodeType: 9 };
  const source = { document: firstDocument };
  const attr = { name: 'xo-scope', value: '', source, scope: firstDocument, scopeSource: firstDocument };
  const el = attributeSection(attr);
  Object.defineProperty(el, 'scope', { get: scopeHandler.get });
  assert.equal(scopeHandler.get.call(el), firstDocument);
  source.document = secondDocument;
  assert.equal(scopeHandler.get.call(el), secondDocument);
  assert.equal(attr.scope, secondDocument);
  assert.equal(attr.scopeSource, secondDocument);
});

test('store getter uses the captured store after navigation changes each alias', () => {
  const xover = harness();
  const begin = code.indexOf('const store_handler = {');
  const end = code.indexOf("if (!Text.prototype.hasOwnProperty('store'))", begin);
  const storeHandler = Function('xover', code.slice(begin, end) + ';return store_handler;')(xover);
  for (const alias of ['active', 'seed', 'inherit']) {
    const originalStore = {};
    const nextStore = {};
    xover.stores = { [alias]: originalStore };
    const attr = { name: 'xo-store', value: alias };
    const el = attributeSection(attr);
    el.namespaceURI = 'http://www.w3.org/1999/xhtml';
    assert.equal(storeHandler.get.call(el), originalStore);
    xover.stores[alias] = nextStore;
    assert.equal(storeHandler.get.call(el), originalStore);
    const incoming = attributeSection({ name: 'xo-store', value: alias });
    incoming.namespaceURI = el.namespaceURI;
    assert.equal(storeHandler.get.call(incoming), nextStore);
  }
});

test('deep attribute copies preserve scope, source and store identity', () => {
  const xover = harness();
  class Attr {
    constructor(name) { this.name = name; }
  }
  Attr.cloneNode = function () { return new Attr(this.name); };
  const begin = code.indexOf('Attr.prototype.cloneNode = function');
  const end = code.indexOf('HTMLScriptElement.cloneNode =', begin);
  Function('Attr', code.slice(begin, end))(Attr);
  const attr = Object.assign(new Attr('xo-store'), { scope: {}, scopeSource: {}, source: {}, store: {} });
  const clone = attr.cloneNode(true);
  for (const prop of ['scope', 'scopeSource', 'source', 'store']) assert.equal(clone[prop], attr[prop]);
  assert.equal(attr.cloneNode(false).scope, undefined);
});

test('collection scopes compare member identities rather than the collection wrapper', () => {
  const xover = harness();
  const first = {}, second = {};
  assert.equal(xover.references.scopeChanged({ scope: [first, second] }, { scope: [first, second] }), false);
  assert.equal(xover.references.scopeChanged({ scope: [first, second] }, { scope: [second, first] }), true);
});
