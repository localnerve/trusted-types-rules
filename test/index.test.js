/**
 * Tests for trusted-types-rules.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractTrustedTypesSources } from '../index.js';

test('computes cspDirective from default policy name', () => {
  const report = extractTrustedTypesSources([
    "el.innerHTML = '<b>hi</b>';"
  ]);
  assert.equal(report.cspDirective, 'trusted-types default');
  assert.deepEqual(report.policyNames, ['default']);
});

test('detects innerHTML sink and required createHTML hook', () => {
  const report = extractTrustedTypesSources([
    "const x = '<i>x</i>';\n\ndocument.getElementById('a').innerHTML = x;"
  ]);
  assert.equal(report.sinks.length, 1);
  assert.equal(report.sinks[0].sink, 'innerHTML');
  assert.equal(report.sinks[0].line, 3);
  assert.equal(report.requiredHooks.createHTML, true);
});

test('detects outerHTML and insertAdjacentHTML sinks', () => {
  const report = extractTrustedTypesSources([
    "el.outerHTML = s;\n" +
    "el.insertAdjacentHTML('beforeend', s);"
  ]);
  assert.deepEqual(report.sinks.map(s => s.sink), ['outerHTML', 'insertAdjacentHTML']);
});

test('detects document.write sinks', () => {
  const report = extractTrustedTypesSources([
    "document.write(x);\n" +
    "document.writeln(y);"
  ]);
  assert.equal(report.sinks.length, 2);
  assert.ok(report.sinks.every(s => s.hook === 'createHTML'));
});

test('detects eval and new Function as createScript sinks', () => {
  const report = extractTrustedTypesSources([
    "eval(code);\n" +
    "const f = new Function('a', 'return a');"
  ]);
  assert.deepEqual(
    report.sinks.map(s => s.sink).sort(),
    ['eval', 'new Function']
  );
  assert.equal(report.requiredHooks.createScript, true);
});

test('does not match eval/innerHTML inside identifiers or properties of other objects', () => {
  // 'evaluate' and '.someInnerHTML' should not count as sinks
  const report = extractTrustedTypesSources([
    "function evaluate (x) { return x; }\n" +
    "const y = obj.someInnerHTML;\n" +
    "obj._eval(code);"
  ]);
  assert.equal(report.sinks.length, 0);
});

test('detects script element creation and Worker as URL sinks with warning', () => {
  const report = extractTrustedTypesSources([
    "const s = document.createElement('script');\n" +
    "const w = new Worker('/w.js');"
  ]);
  assert.equal(report.requiredHooks.createScriptURL, true);
  assert.ok(report.warnings.some(w => /createElement/.test(w)));
  assert.ok(report.warnings.some(w => /Worker/.test(w)));
});

test('detects web components via customElements.define', () => {
  const report = extractTrustedTypesSources([
    "customElements.define('my-widget', class extends HTMLElement {});\n" +
    "customElements.define(\"another-thing\", X);"
  ]);
  assert.deepEqual(
    report.webComponents.map(c => c.tag).sort(),
    ['another-thing', 'my-widget']
  );
});

test('detects createPolicy registration and its hooks', () => {
  const report = extractTrustedTypesSources([
    "trustedTypes.createPolicy('default', {\n" +
    "  createHTML: s => s,\n" +
    "  createScriptURL: (u, o) => u\n" +
    "});"
  ]);
  assert.deepEqual(report.policyNames, ['default']);
  assert.equal(report.policyHooks.createHTML, true);
  assert.equal(report.policyHooks.createScriptURL, true);
  assert.equal(report.policyHooks.createScript, false);
  assert.deepEqual(report.warnings, []);
});

test('createScript hook regex does not match createScriptURL', () => {
  const report = extractTrustedTypesSources([
    "trustedTypes.createPolicy('p', { createScriptURL: u => u });"
  ]);
  assert.equal(report.policyHooks.createScript, false);
  assert.equal(report.policyHooks.createScriptURL, true);
});

test('adds detected policy names to the directive allowlist (multi-name)', () => {
  const report = extractTrustedTypesSources(
    [
      { path: 'app.js', source: "trustedTypes.createPolicy('default', {});" },
      { path: 'component.js', source: "trustedTypes.createPolicy('editable-object', {});" }
    ],
    { policyNames: ['default'] }
  );
  assert.deepEqual(report.detectedPolicyNames.sort(), ['default', 'editable-object']);
  assert.equal(report.cspDirective, 'trusted-types default editable-object');
});

test('resolves identifier-form createPolicy names (minified const hoisting)', () => {
  // mirrors terser output: name hoisted into a const, passed as identifier
  const minified = 'const r="my-component";function f(e){return trustedTypes.createPolicy(e,{createHTML:t=>t})}f(r);';
  const report = extractTrustedTypesSources([minified]);
  assert.deepEqual(report.detectedPolicyNames, ['my-component']);
  assert.equal(report.cspDirective, 'trusted-types default my-component');
});

test('resolves names through nested function params without cross-scope false positives (real bundle shape)', () => {
  // mirrors the editable-object terser output: const hoisting, helper factory
  // with a Map cache, and unrelated consts sharing short identifiers
  const realShape = [
    'const t=new Map();',
    'function s(e,s={createHTML:t=>String(t),createScriptURL:t=>String(t)}){',
    'return"undefined"!=typeof window&&"trustedTypes"in window?',
    '(t.has(e)||t.set(e,trustedTypes.createPolicy(e,s)),t.get(e)):null;}',
    'function n(e,s){const r=s(e);return r?r.createHTML(s):s}',
    'const r="editable-object";',
    'let i=null;',
    'const a="disable-edit";',
    'class o{c(){i=i||n(r,i)||""}}'
  ].join('');
  const report = extractTrustedTypesSources([realShape]);
  assert.deepEqual(report.detectedPolicyNames, ['editable-object']);
  assert.equal(report.cspDirective, 'trusted-types default editable-object');
});

test('accepts a string or array policyNames and dedupes', () => {
  const single = extractTrustedTypesSources(['x'], { policyNames: 'custom' });
  assert.equal(single.cspDirective, 'trusted-types custom');

  const dupes = extractTrustedTypesSources(
    ["trustedTypes.createPolicy('a', {});"],
    { policyNames: ['a', 'b'] }
  );
  assert.equal(dupes.cspDirective, 'trusted-types a b');
});

test('warns when required hook is missing from sources', () => {
  const report = extractTrustedTypesSources([
    "el.innerHTML = x;"
  ]);
  assert.ok(report.warnings.some(w => /createHTML/.test(w)));
});

test('accepts objects with path and source, using the path in reports', () => {
  const report = extractTrustedTypesSources([
    { path: 'src/app.js', source: "el.innerHTML = x;" }
  ]);
  assert.equal(report.sinks[0].file, 'src/app.js');
});

test('throws on invalid input', () => {
  assert.throws(() => extractTrustedTypesSources('not-an-array'));
  assert.throws(() => extractTrustedTypesSources([42]));
});
