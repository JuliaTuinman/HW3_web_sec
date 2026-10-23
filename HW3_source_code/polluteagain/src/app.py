from flask import Flask, request, jsonify, render_template, send_from_directory, make_response
import json
import os
import copy
import jwt
import datetime

app = Flask(__name__, static_folder='public', static_url_path='/static')
secret_key = os.urandom(32)

import random as _random

def _is_prime(n):
    if n < 2:
        return False
    for _p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % _p == 0:
            return n == _p
    d = n - 1; r = 0
    while d % 2 == 0:
        d //= 2; r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

def _gen_prime(bits):
    while True:
        cand = _random.getrandbits(bits) | 1 | (1 << (bits - 1))
        if _is_prime(cand):
            return cand

def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = _egcd(b, a % b)
    return (g, y, x - (a // b) * y)

# Per-instance small RSA. The nonce the forged admin token must carry is RSA-encrypted;
# /data exposes only (n, e, c). Recover it by factoring the (small) modulus n
# (e.g. on factordb.com), deriving the private key, and decrypting c.
RSA_E = 65537
while True:
    _p = _gen_prime(28); _q = _gen_prime(28)
    if _p == _q:
        continue
    _phi = (_p - 1) * (_q - 1)
    if _egcd(RSA_E, _phi)[0] == 1:
        break
RSA_N = _p * _q                                  # ~56-bit: any factorizer (factordb.com) cracks it
_d = _egcd(RSA_E, _phi)[1] % _phi
# 4-byte nonce: far too large to brute-force /flag online, still < n so RSA is well-defined.
_nonce_int = max(2, int.from_bytes(os.urandom(4), 'big'))
RSA_C = pow(_nonce_int, RSA_E, RSA_N)
FLAG_NONCE = str(_nonce_int)

# STRUCTURAL RANDOMIZATION: a randomly-NAMED module global that must ALSO be flipped to
# True (through the same class-pollution primitive) before the flag unlocks. A hard-coded
# exploit that only overwrites secret_key won't transfer between instances — the gate name
# changes every boot and is disclosed only via /data.
GATE_NAME = 'gate_' + os.urandom(3).hex()
globals()[GATE_NAME] = False

# Template context for rendering
README_TEXT = "Have you ever read about Silent Spring?"

# Global variable to store the air quality map data
class AQMap:
    def __init__(self, data=None):
        self.data = data or {}

    def update(self, new_data):
        """Update the map data using deep merge"""
        deep_merge(new_data, self)


AQMAP = AQMap()

def deep_merge(src, dst):
  # Naive "defense": refuse the textbook class-traversal keys, so the standard
  # __class__.__init__.__globals__ chain can no longer reach the module globals.
  BLOCKED = {'__class__', '__init__', '__bases__', '__base__', '__mro__', '__subclasses__'}
  for k, v in src.items():
      if k in BLOCKED:
          continue
      if hasattr(dst, '__getitem__'):
          if dst.get(k) and type(v) == dict:
              deep_merge(v, dst.get(k))
          else:
              dst[k] = v
      elif hasattr(dst, k) and type(v) == dict:
          deep_merge(v, getattr(dst, k))
      else:
          setattr(dst, k, v)

@app.route('/')
def index():
    """Render the main map page"""
    response = make_response(render_template('index.html', readme=README_TEXT))
    
    # Check if user already has a JWT cookie
    token = request.cookies.get('auth_token')
    if not token:
        # Create JWT with isadmin=false
        payload = {
            'isadmin': False,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        response.set_cookie('auth_token', token)
    
    return response

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('public', filename)

@app.route('/data')
def get_data():
    """Fetch the AQ Map data"""
    global AQMAP
    if not AQMAP.data:
        try:
            with open('db.json', 'r') as f:
                AQMAP = AQMap(json.load(f))
        except Exception as e:
            return jsonify({"error": "Error retrieving data"}), 500

    return jsonify({**AQMAP.data, '_rsa': {'n': RSA_N, 'e': RSA_E, 'c': RSA_C}, '_gate': GATE_NAME})

@app.route('/add', methods=['POST'])
def add_data():
    """Add new data points to the Map from the client side"""
    global AQMAP
    if not AQMAP.data:
        return jsonify({"error": "Data not loaded"}), 500
    
    data = request.get_json()
    AQMAP.update(data)
    return 'Added!'

@app.route('/flag', methods=['GET'])
def return_flag():
    """Decrypt the flag using the secret key and return it if isadmin=true in the jwt"""
    token = request.cookies.get('auth_token')
    
    if not token:
        return 'No authentication token found!'
    
    try:
        # Decode JWT using the secret key
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        
        # Check if isadmin is true
        if payload.get('isadmin') == True and str(payload.get('nonce')) == FLAG_NONCE and globals().get(GATE_NAME) is True:
            try:
                with open('./flag', 'r') as f:
                    flag = f.read().strip()
                return flag
            except Exception:
                return 'Did you delete the flag?'
        else:
            return 'Access denied! Admin privileges required.'
            
    except jwt.ExpiredSignatureError:
        return 'Token expired!'
    except jwt.InvalidTokenError:
        return 'Invalid token!'

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8399))
    app.run(host='0.0.0.0', port=port, debug=False)