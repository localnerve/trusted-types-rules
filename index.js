/**
 * trusted-types-rules
 * 
 * Compute Content-Security-Policy `trusted-types` rules and audit injection
 * sinks from JavaScript sources, including web components.
 * 
 * The library scans a set of JavaScript source strings (plain app code,
 * bundled output, or the dist/ of a build) for:
 *   - markup injection sinks (innerHTML, outerHTML, insertAdjacentHTML,
 *     document.write*, srcdoc) that require a `createHTML` policy hook,
 *   - direct code execution sinks (eval, new Function) that require a
 *     `createScript` hook or the trusted-types-eval CSP keyword,
 *   - script URL patterns (createElement('script'), Workers) that require a
 *     `createScriptURL` hook,
 *   - web components via customElements.define(), so newly added components
 *     are picked up automatically on each build,
 *   - existing trustedTypes.createPolicy() registrations and their hooks.
 * 
 * From the findings it derives:
 *   - the `trusted-types <policyName>` CSP directive to allowlist (suitable
 *     for replacing a placeholder in a meta tag at build time),
 *   - which policy hooks the registered policy must define,
 *   - warnings for sinks that no defined hook covers.
 *
 * Policy names are resolved with real AST analysis (acorn) so they survive
 * arbitrary minification/terser output: `trustedTypes.createPolicy('name')`,
 * hoisted string constants (`const r="name"; f(r)`), and parameters passed
 * through nested function call chains. Sink detection remains a text heuristic
 * that errs toward reporting more than fewer - the right bias for a security
 * audit.
 * 
 * Copyright (c) 2026 Alex Grant (@localnerve), LocalNerve LLC
 * Licensed under the MIT license.
 */
import { parse as acornParse } from 'acorn';

/**
 * Sink definitions: name, regex to find usage, and the policy hook that must
 * cover them when require-trusted-types-for 'script' is enforced.
 */
const SINK_DEFINITIONS = [
  {
    sink: 'innerHTML',
    hook: 'createHTML',
    re: /\b(?:inner|outer)HTML\s*=(?!=)/g
  },
  {
    sink: 'insertAdjacentHTML',
    hook: 'createHTML',
    re: /\binsertAdjacentHTML\s*\(/g
  },
  {
    sink: 'document.write',
    hook: 'createHTML',
    re: /\bdocument\.writ(?:e|eln)\s*\(/g
  },
  {
    sink: 'srcdoc',
    hook: 'createHTML',
    re: /(?:\bsrcdoc\s*=(?!=)|\bsetAttribute\(\s*['"]srcdoc['"])/g
  }
];

/** Direct code execution sinks (require createScript or trusted-types-eval). */
const SCRIPT_SINKS = [
  { sink: 'eval', re: /(?<![\w$.])eval\s*\(/g },
  { sink: 'new Function', re: /\bnew\s+Function\s*\(/g }
];

/** Script URL loading patterns (require createScriptURL). */
const SCRIPT_URL_SINKS = [
  { sink: "createElement('script')", re: /createElement\(\s*['"]script['"]\s*\)/g },
  { sink: 'Worker', re: /new\s+Worker\s*\(/g }
];

/** Web component registration. */
const COMPONENT_RE = /customElements\.define\(\s*['"`]([a-z][a-z0-9]*(?:-[a-z0-9]+)+)['"`]/g;

/** Fallback literal detection for unparseable sources. */
const POLICY_NAME_LITERAL_RE = /trustedTypes\.createPolicy\(\s*['"`]([^'"`]+)['"`]/;
const HOOK_RES = {
  createHTML: /\bcreateHTML\s*[:=]/,
  createScriptURL: /\bcreateScriptURL\s*[:=]/,
  createScript: /\bcreateScript\s*[:=]/
};

/**
 * Extract the string value of a node when it is a plain string literal or an
 * expressionless template literal.
 * 
 * @param {Object} node - AST node
 * @returns {String|null} The string value, or null.
 */
function literalString (node) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0 && node.quasis.length === 1) {
    return node.quasis[0].value.cooked;
  }
  return null;
}

/**
 * Parameter names of a function-like AST node (handles defaults and rest).
 * 
 * @param {Object} fnNode - FunctionDeclaration/FunctionExpression/ArrowFunctionExpression
 * @returns {Array<String>} The parameter names.
 */
function paramNames (fnNode) {
  return fnNode.params.map(p => {
    if (p.type === 'Identifier') return p.name;
    if (p.type === 'AssignmentPattern' && p.left?.type === 'Identifier') return p.left.name;
    if (p.type === 'RestElement' && p.argument?.type === 'Identifier') return p.argument.name;
    return null;
  }).filter(Boolean);
}

/**
 * Resolve the policy name(s) of createPolicy() calls in a source string using
 * AST analysis. Handles: literal names, identifiers bound to string constants,
 * and parameters passed through nested function call chains (minifiers hoist
 * `createPolicy('name', ...)` into `const r="name"; f(r)` shapes). Scope-aware:
 * each identifier resolves against the innermost binding that declares it at
 * its own position, so minified single-letter name reuse across scopes cannot
 * false-match. Depends only on standard AST node shapes, not on how terser
 * happens to format the output.
 * 
 * @param {String} source - JavaScript source text
 * @returns {Set<String>} The resolved policy names.
 */
function resolvePolicyNames (source) {
  const names = new Set();

  let ast;
  try {
    ast = acornParse(source, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true });
  } catch {
    // unparseable source: fall back to literal-name detection only
    const lit = source.match(POLICY_NAME_LITERAL_RE);
    if (lit) names.add(lit[1]);
    return names;
  }

  // per-identifier binding maps, keyed by the identifier node itself
  const encConst = new Map(); // Identifier node -> string constant value
  const encParamFn = new Map(); // Identifier node -> innermost fn name declaring it as param
  const callSites = new Map(); // callee name -> Array<first-arg nodes>
  const createPolicyArgs = [];

  const visit = (node, scopes) => {
    if (!node || typeof node.type !== 'string') return;

    if (node.type === 'CallExpression') {
      if (node.callee?.type === 'Identifier' && node.arguments.length) {
        if (!callSites.has(node.callee.name)) callSites.set(node.callee.name, []);
        callSites.get(node.callee.name).push(node.arguments[0]);
      }
      if (node.callee?.type === 'MemberExpression' &&
          node.callee.object?.type === 'Identifier' && node.callee.object.name === 'trustedTypes' &&
          node.callee.property?.type === 'Identifier' && node.callee.property.name === 'createPolicy') {
        createPolicyArgs.push(node.arguments[0]);
      }
    }

    if (node.type === 'Identifier') {
      // innermost binding for this identifier at this position
      for (let i = scopes.length - 1; i >= 0; i--) {
        const scope = scopes[i];
        if (scope.consts.has(node.name)) {
          encConst.set(node, scope.consts.get(node.name));
          break;
        }
        if (scope.params.includes(node.name) && scope.fnName) {
          encParamFn.set(node, scope.fnName);
          break;
        }
      }
    }

    const isFn = ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type);
    const nextScopes = isFn
      ? [...scopes, { fnName: node.id?.name ?? null, params: paramNames(node), consts: new Map() }]
      : scopes;

    if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations) {
        const lit = literalString(decl.init);
        if (lit !== null && decl.id?.type === 'Identifier') {
          // bind to the scope in effect at the declaration (const/let are not
          // hoisted, so traversal order matches runtime binding order)
          nextScopes[nextScopes.length - 1].consts.set(decl.id.name, lit);
        }
      }
    }

    for (const key of Object.keys(node)) {
      if (key === 'type') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(c => visit(c, nextScopes));
      } else if (child && typeof child.type === 'string') {
        visit(child, nextScopes);
      }
    }
  };

  // single scope entry = module/global scope for string constants
  visit(ast, [{ fnName: null, params: [], consts: new Map() }]);

  const MAX_DEPTH = 5;
  // resolve an argument node: literal > local constant > parameter (via the
  // function's call sites). A parameter binding shadows outer constants, so
  // there is no fall-through once a parameter match is found.
  const resolve = (node, depth, seen) => {
    if (!node || depth > MAX_DEPTH) return null;
    if (seen.has(node)) return null;
    seen.add(node);

    const direct = literalString(node);
    if (direct !== null) return direct;
    if (node.type !== 'Identifier') return null;

    const constant = encConst.get(node);
    if (constant !== undefined) return constant;

    const fnName = encParamFn.get(node);
    if (fnName) {
      const sites = callSites.get(fnName);
      if (sites) {
        for (const arg of sites) {
          const value = resolve(arg, depth + 1, new Set(seen));
          if (value !== null) return value;
        }
      }
    }
    return null;
  };

  for (const arg of createPolicyArgs) {
    const value = resolve(arg, 0, new Set());
    if (value !== null) names.add(value);
  }

  return names;
}

/**
 * Find all regex matches in a source string with line/column positions.
 * 
 * @param {String} source - JavaScript source text
 * @param {RegExp} re - global regex
 * @returns {Array<Object>} Matches with offset, line, column, and text.
 */
function findMatches (source, re) {
  const regex = new RegExp(re.source, re.flags); // fresh state per call
  const matches = [];
  let m;
  while ((m = regex.exec(source))) {
    const before = source.slice(0, m.index);
    matches.push({
      offset: m.index,
      line: before.split('\n').length,
      column: m.index - before.lastIndexOf('\n'),
      text: m[0]
    });
  }
  return matches;
}

/**
 * Normalize input sources to { path, source } objects.
 * 
 * @param {Array<String|Object>} sources - source strings or { path, source } objects
 * @returns {Array<Object>} Normalized source objects
 */
function normalizeSources (sources) {
  if (!Array.isArray(sources)) {
    throw new TypeError('extractTrustedTypesSources expects an array of sources.');
  }
  return sources.map((s, i) => {
    if (typeof s === 'string') {
      return { path: `source-${i}`, source: s };
    }
    if (s && typeof s.source === 'string') {
      return { path: s.path ?? `source-${i}`, source: s.source };
    }
    throw new TypeError(`sources[${i}] must be a string or an object with a source string.`);
  });
}

/**
 * Compute trusted-types CSP rules and audit injection sinks from JavaScript
 * sources.
 * 
 * @param {Array<String|Object>} sources - JavaScript source strings, or objects of the form { path, source }.
 * @param {Object} [options] - Options.
 * @param {String|Array<String>} [options.policyNames=['default']] - Requested policy name(s) to include in the `trusted-types` directive. Names detected from createPolicy() registrations are added automatically (deduplicated), so web components and app code that register their own policies are allowlisted without being listed here.
 * @returns {Object} Report object:
 *   - cspDirective: String, the `trusted-types <name...>` directive for the CSP (all requested + detected names).
 *   - policyNames: Array of String, every name in the directive.
 *   - detectedPolicyNames: Array of String, names found via createPolicy() in the sources.
 *   - sinks: Array of { file, line, column, sink, hook } markup/code/URL sink usages.
 *   - webComponents: Array of { tag, file, line }.
 *   - policyHooks: Object with booleans for createHTML, createScriptURL, createScript found in sources.
 *   - requiredHooks: Object with booleans for the hooks the sinks demand.
 *   - warnings: Array of strings describing uncovered sinks or mismatches.
 */
export function extractTrustedTypesSources (sources, options = {}) {
  const requestedNames = Array.isArray(options.policyNames) ? [...options.policyNames]
    : typeof options.policyNames === 'string' ? [options.policyNames]
      : ['default'];
  const normalized = normalizeSources(sources);

  const sinks = [];
  const webComponents = [];
  const warnings = [];
  const requiredHooks = { createHTML: false, createScriptURL: false, createScript: false };
  const policyHooks = { createHTML: false, createScriptURL: false, createScript: false };
  const detectedPolicyNames = new Set();

  for (const { path, source } of normalized) {
    // markup + code-execution sinks
    for (const def of [...SINK_DEFINITIONS, ...SCRIPT_SINKS]) {
      const isScriptSink = SCRIPT_SINKS.includes(def);
      for (const m of findMatches(source, def.re)) {
        // the inner/outer regex covers both; label by what actually matched
        const sink = def.sink === 'innerHTML' && /outer/i.test(m.text) ? 'outerHTML' : def.sink;
        sinks.push({ file: path, line: m.line, column: m.column, sink, hook: def.hook });
        requiredHooks[isScriptSink ? 'createScript' : def.hook] = true;
      }
    }
    // script URL sinks (heuristic - flag for review)
    for (const def of SCRIPT_URL_SINKS) {
      const matches = findMatches(source, def.re);
      if (matches.length) {
        requiredHooks.createScriptURL = true;
        warnings.push(`${def.sink} detected in ${path}: verify the policy createScriptURL hook covers these URLs.`);
      }
    }
    // web components (any new component added to the site is picked up here)
    for (const m of findMatches(source, COMPONENT_RE)) {
      webComponents.push({ tag: m.text.match(/['"`]([a-z][a-z0-9]*(?:-[a-z0-9]+)+)['"`]/)[1], file: path, line: m.line });
    }
    // existing policy registrations + hooks
    // (createScript's regex requires : or = directly after the name, so it
    // cannot false-match createScriptURL)
    for (const name of resolvePolicyNames(source)) {
      detectedPolicyNames.add(name);
    }
    for (const [hook, re] of Object.entries(HOOK_RES)) {
      if (re.test(source)) policyHooks[hook] = true;
    }
  }

  // directive allowlist: requested names first (stable order), then any extra
  // names detected in the sources (e.g. web component policies)
  const policyNames = [...requestedNames];
  for (const name of detectedPolicyNames) {
    if (!policyNames.includes(name)) policyNames.push(name);
  }
  for (const [hook, required] of Object.entries(requiredHooks)) {
    if (required && !policyHooks[hook]) {
      warnings.push(`Sinks require a ${hook} hook, but none was found in the sources.`);
    }
  }

  return {
    cspDirective: `trusted-types ${policyNames.join(' ')}`,
    policyNames,
    detectedPolicyNames: [...detectedPolicyNames],
    sinks,
    webComponents,
    policyHooks,
    requiredHooks,
    warnings
  };
}

export default extractTrustedTypesSources;
