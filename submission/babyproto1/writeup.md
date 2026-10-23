# babyproto1

## The vulnerability

`POST /add` merges the raw request body into a server object using a recursive
`deepMerge` that never excludes the special `__proto__` / `constructor` / `prototype`
keys (`app.js`):

    app.post('/add', (req, res) => { deepMerge(AQMAP, req.body); res.send('Added!') })

    function deepMerge(target, source) {
        if (isObject(target) && isObject(source)) {
            for (let key in source){
                if(source.hasOwnProperty(key)){
                    if(isObject(source[key])){ if(!target[key]){target[key]={}} deepMerge(target[key], source[key]) }
                    else { target[key] = source[key] }
                }
            }
        }
    }


`JSON.parse` makes `__proto__` a real own, enumerable key, so for a body
`{"__proto__":{"flag":"x"}}` the merge recurses into `target["__proto__"]` (which *is*
`Object.prototype`) and sets `Object.prototype.flag = "x"` globally. 

`GET /flag` gates the
flag on exactly that property:


    if (Object.prototype.flag === UNLOCK_TOKEN) { /* read ./flag */ }


`UNLOCK_TOKEN` is a per-boot random value that `GET /data` leaks to clients as
`_client_nonce`.

## How I exploited it

1. **`GET /data`**: read `_client_nonce` (the value `flag` must equal). This also
   initializes `AQMAP` -> the merge is a no-op until it exists.
2. **`POST /add`** the pollution payload:
   
        curl -s -X POST "$BASE/add" -H 'Content-Type: application/json' \
            --data '{"__proto__":{"flag":"<_client_nonce>"}}'

   This sets `Object.prototype.flag` to the token.
3. **`GET /flag`**: the check now passes and the flag is returned.

(Wrote a script to accomplish this)

## The patch

`vuln.patch` adds a key filter at the top of the merge loop so untrusted input can never
reach the prototype:


    for (let key in source){
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        if (source.hasOwnProperty(key)) { ... }
    }


- **Blocks the exploit**: both vectors (`__proto__` and `constructor`→`prototype`) are
  skipped, so `Object.prototype.flag` can't be set and `/flag` always returns `Nice Try!`.
- **Keeps benign behavior**: normal map updates (e.g. `{"loc9":{"name":"New Site","AQ":42}}`)
  still merge -> only the three reserved keys are excluded.
- **No new risk**: a pure deny-list guard with no added parsing, I/O, or state.
