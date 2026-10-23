# polluteagain 

## The vulnerability

`POST /add` merges attacker JSON into a server object via `deep_merge`, which walks keys
and, for an arbitrary object `dst`, recurses with `getattr`/`setattr` (`app.py`):

    def deep_merge(src, dst):
      BLOCKED = {'__class__', '__init__', '__bases__', '__base__', '__mro__', '__subclasses__'}
      for k, v in src.items():
          if k in BLOCKED:
              continue
          if hasattr(dst, '__getitem__'):
              if dst.get(k) and type(v) == dict: deep_merge(v, dst.get(k))
              else: dst[k] = v
          elif hasattr(dst, k) and type(v) == dict: deep_merge(v, getattr(dst, k))
          else: setattr(dst, k, v)


This is **class pollution** 

The blacklist only rejects the textbook `__class__.__init__.__globals__` chain -> but it's an *allow-by-omission* list and misses other traversal gadgets. In particular, a bound method exposes
`__globals__`, which points at the module globals. 

`AQMAP.update` is a bound method, and
neither `update` nor `__globals__` is blacklisted, so:


    dst = AQMap instance
      -> "update"      : getattr -> bound method   (not blocked)
        -> "__globals__": getattr -> module globals (not blocked!)
          -> set arbitrary module globals


`/flag` requires **three** conditions at once:

    if payload.get('isadmin') == True and str(payload.get('nonce')) == FLAG_NONCE \
      and globals().get(GATE_NAME) is True:

- `isadmin`: but the JWT is signed with `secret_key = os.urandom(32)` (unknown), so we can't forge a token. -> unless we overwrite `secret_key` with a value we choose.
- `nonce == FLAG_NONCE`: `FLAG_NONCE` is RSA-encrypted -> `/data` leaks only `(n, e, c)`.
- `GATE_NAME`: a randomly-named global that must be flipped to `True`.

Class pollution of the module globals gives us the first and third (RSA recon gives the second).

## How I exploited it

1. **Recon (`GET /data`)**: Returns `_rsa = {n, e, c}` and `_gate = GATE_NAME`. 
    * The modulus `n` is ~56-bit, so factor it (Pollard's rho locally, or factordb.com): `p, q = factor(n)`, `d = e⁻¹ mod (p-1)(q-1)`, `nonce = c^d mod n`. 
    * That integer is `FLAG_NONCE` (`/data` also loads `AQMAP.data` from `db.json`, which `/add` needs.)
2. **Class pollution (`POST /add`)**: One payload reaches the module globals via the bound-method route and sets both globals we need

        {"update": {"__globals__": {"secret_key": "pwned-key", "<GATE_NAME>": true}}}

   Now `secret_key` is a value we know and `globals()[GATE_NAME] is True`.
3. **Forge the admin JWT**, signed with the key we just planted:

          jwt.encode({"isadmin": True, "nonce": nonce, "exp": <+1h>}, "pwned-key", algorithm="HS256")

4. **Collect (`GET /flag`)** with `Cookie: auth_token=<forged token>`. All three conditions hold, so the flag is returned.

(Wrote a script to accomplish this)

## The patch

The root cause is that `deep_merge` lets attacker-named keys drive `getattr`/`setattr` into object internals, and the blacklist is incomplete. 

`vuln.patch` replaces the name-by-name blacklist with a rule that rejects **every dunder key**:

    for k, v in src.items():
        if isinstance(k, str) and k.startswith('__') and k.endswith('__'):
            continue
        ...


- **Blocks the exploit**: `__globals__` (and `__class__`, `__init__`, `__dict__`, `__builtins__`, every other `__...__` gadget) is skipped, so the merge can never traverse out of the data object into module globals or the class hierarchy
  * `secret_key` and the gate can't be polluted, so no forged token is ever accepted.
- **Keeps benign behavior**: legitimate air-quality keys (`loc5`, `name`, `AQ`, …) are never dunders, so normal `/add` updates and nested `data` merges work exactly as before.
- **No new risk**: a deny rule with no added I/O or state -> it strictly narrows what keys may be followed.
