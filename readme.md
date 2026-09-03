# @localnerve/trusted-types-rules

Compute Content-Security-Policy `trusted-types` rules and audit injection sinks
from JavaScript sources, including web components.

A build-time companion to the CSP meta tag: it scans your application code (or
build output) for Trusted Types injection sinks and derives the
`trusted-types <policyName>` directive you need — so newly added web components
or `innerHTML` usage are picked up automatically on each build instead of being
missed in a hand-maintained policy.

## Why

`require-trusted-types-for 'script'` makes the browser reject plain strings at
DOM injection sinks (`innerHTML`, `document.write`, `eval`, `<script src>`, ...).
To keep your app working you must:

1. register a policy with hooks that cover every sink your code uses, and
2. allowlist that policy's name in the CSP `trusted-types` directive.

Doing this by hand drifts as the codebase grows — especially when **web
components** each register their **own** named policy. This library computes the
full multi-name allowlist from the sources themselves.

## Install

```sh
npm install @localnerve/trusted-types-rules
```

## Usage

```js
import { extractTrustedTypesSources } from '@localnerve/trusted-types-rules';

const report = extractTrustedTypesSources(
  [
    { path: 'dist/app.js', source: fs.readFileSync('dist/app.js', 'utf8') },
    { path: 'dist/sw.reg.js', source: fs.readFileSync('dist/sw.reg.js', 'utf8') }
  ],
  // optional: policy name(s) you always want in the directive. Detected
  // createPolicy() names (e.g. web component policies) are added automatically.
  { policyNames: ['default'] }
);

// report.cspDirective -> "trusted-types default editable-object"
```

Then substitute the directive into your CSP meta tag at build time:

```js
html = html.replace(/trusted-types [^;']+/g, report.cspDirective);
```

### Options

| Option | Default | Description |
| --- | --- | --- |
| `policyNames` | `['default']` | Policy name (string) or names (array of strings) to always include in the directive. Names detected from `createPolicy()` registrations are added automatically (deduplicated), so web components that register their own policies are allowlisted without being listed here. |

### Report shape

```js
{
  cspDirective: 'trusted-types default editable-object', // ready to drop into a CSP
  policyNames: ['default', 'editable-object'],           // every name in the directive
  detectedPolicyNames: ['editable-object'],              // names found via createPolicy()
  sinks: [                                               // every injection sink found
    { file: 'dist/app.js', line: 12, column: 5, sink: 'innerHTML', hook: 'createHTML' }
  ],
  webComponents: [                                       // customElements.define() tags found
    { tag: 'editable-object', file: 'dist/app.js', line: 40 }
  ],
  policyHooks: { createHTML: true, createScriptURL: true, createScript: false },
  requiredHooks: { createHTML: true, createScriptURL: true, createScript: false },
  warnings: [                            // uncovered sinks, mismatches, URL heuristics
    'Worker detected in dist/sw.reg.js: verify the policy createScriptURL hook covers these URLs.'
  ]
}
```

### What is detected

- **Markup sinks** (`createHTML`): `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `document.write`/`writeln`, `srcdoc` attribute.
- **Code execution sinks** (`createScript` or the CSP `trusted-types-eval`
  keyword): `eval()`, `new Function()`.
- **Script URL patterns** (`createScriptURL`): `createElement('script')`,
  `new Worker()` — reported as warnings because they need review.
- **Web components**: every `customElements.define('<tag>', ...)` tag, so new
  components added to the site are automatically part of the audit.
- **Existing policies**: `trustedTypes.createPolicy('name', { ... })` registrations
  and which hooks (`createHTML`, `createScriptURL`, `createScript`) they define.

### Policy name resolution (AST)

Policy names are resolved with real AST analysis ([acorn](https://github.com/acornjs/acorn)),
**not** a text regex, so they survive arbitrary minification/terser output. This
matters because terser hoists `createPolicy('my-name', ...)` into shapes like:

```js
const r = "my-name"; /* ... */ f(r); // f eventually calls trustedTypes.createPolicy
```

The resolver handles all of these, scope-aware (each identifier resolves against
the innermost binding at its own position, so minified single-letter name reuse
across scopes cannot false-match):

- string literals: `trustedTypes.createPolicy('my-name', ...)`
- hoisted string constants: `const r = "my-name"; f(r)`
- parameters passed through nested function call chains (bounded depth, cycle-safe)

Sources that fail to parse fall back to literal-name detection only.

### Limitations

- **Sink detection is a text heuristic** (regex), not AST-based. It errs toward
  reporting more than fewer — the right bias for a security audit: a false
  positive becomes a warning to review, while a false negative would be a hole.
  The patterns are written to survive terser-style minification.
- **Script URL sinks** (`createElement('script')`, `new Worker()`) are reported as
  warnings rather than hard requirements, because whether they need coverage
  depends on the URLs in play.

## License

MIT — [license.md](./license.md)
