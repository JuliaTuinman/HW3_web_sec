# toddlerproto2 

## The vulnerability

Same vulnerable `deepMerge` on `POST /add` as babyproto1, but with a minimal guard:
it strips `__proto__` **only at the top level** (`depth === 0`), so a nested occurrence
sails through (`app.js`):


    function deepMerge(target, source, depth) {
        if (depth === undefined) { depth = 0; }
        if (isObject(target) && isObject(source)) {
            for (let key in source){
                if(depth === 0 && key === '__proto__'){ continue; }   // only depth 0!
                if(source.hasOwnProperty(key)){ ... deepMerge(target[key], source[key], depth + 1) ... }
            }
        }
    }


A payload like `{"x":{"__proto__":{...}}}` passes `x` at depth 0, then reaches `__proto__`
at depth 1 (unchecked) and pollutes `Object.prototype`.

`GET /flag` requires two things, both per-instance randomized and leaked by `/data` (`_touch_target` is base64, `_guard` is plain):


    if (fs.existsSync(RCE_MARKER) && Object.prototype[GUARD_PROP] === true) { /* give flag */ }


So we need (a) prototype pollution to set the guard prop, and (b) code execution to
create a file named `RCE_MARKER` on the server.

The RCE comes from Squirrelly 8.0.8 (`app.set('view engine','squirrelly')`). Squirrelly sanitizes its own config: `getConfig()` deep-copies `defaultConfig`, which resets `defaultFilter` to `false`, so simply polluting `Object.prototype.defaultFilter` is wiped out before compilation. But `renderFile`
(Express's `__express`) re-merges user settings *after* `getConfig`:


    var viewOpts = data.settings['view options'];
    if (viewOpts) { copyProps(Config, viewOpts); }   // overrides the sanitized config


Express passes the app settings object as `data.settings`. It has no own `view options`
key, so `data.settings['view options']` resolves through the prototype chain. By polluting
`Object.prototype['view options']`, we control that merged object and make a malicious
`defaultFilter` survive into compilation.

At compile time, Squirrelly builds the template function as a string and emits, for the
`{{it.readme}}` interpolation:

    tR += c.l('F','<defaultFilter>')(it.readme);


`defaultFilter` is concatenated unescaped, so it is a string-injection into generated code
that runs through `new Function(...)` (for example RCE).

## How I exploited it

1. **`GET /data`**: read `_touch_target` (base64 -> `RCE_MARKER`) and
   `_guard` (`GUARD_PROP`). 
    * This also initializes `AQMAP`; the merge is a no-op until then.
2. **`POST /add`** one nested `__proto__` payload that sets both requirements at once:

        {"x":{"__proto__":{
            "view options":{
                "defaultFilter":"e');process.mainModule.require('child_process').execSync('touch <RCE_MARKER>')//",
                "autoEscape":false
            },
            "<GUARD_PROP>":true
        }}}

    - `autoEscape:false` avoids an extra `c.l('F','e')(...)` wrapper so the break-out is clean.
    - The `defaultFilter` value closes the generated `c.l('F','e'` call with `e')`, runs `execSync('touch <RCE_MARKER>')`, and comments out the tail with `//`. 
3. **`GET /`**: renders the template, executing the `touch` server-side (the HTTP response may hang/time out, but the side effect runs regardless).
4. **`GET /flag`**: `RCE_MARKER` now exists and `Object.prototype[GUARD_PROP] === true`, so the flag is returned.

(Wrote a script to accomplish this)

## The patch

The root cause is the depth-limited guard in `deepMerge`. `vuln.patch` replaces it with a
check that rejects the dangerous keys at **every** depth:

    for (let key in source){
        // Block prototype-pollution keys at EVERY depth. The original only
        // stripped __proto__ at depth 0, so nested payloads slipped through.
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') { continue; }
        if (source.hasOwnProperty(key)) { ... }
    }


- **Blocks the exploit**: neither `Object.prototype['view options']` nor `GUARD_PROP` can be set, so `defaultFilter` is never smuggled in (no RCE) and the guard condition is never met.
    * `constructor`/`prototype` are also blocked, closing the equivalent `constructor.prototype` vector.
- **Keeps benign behavior**: legitimate location updates (`{"loc9":{...}}`) still merge normally -> only the three reserved keys are skipped.
- **No new risk**: a pure deny-list guard with no added parsing, I/O, or state.
