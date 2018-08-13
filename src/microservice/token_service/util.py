import os
import stat
import math
import binascii
import hashlib
import base64
import json
from urllib.parse import quote

'''
Returns a random hex string with provided length. URL safe.
String returned contains (1/2 * length) bytes of urandom entropy.
'''
def generate_nonce(length):
    nonce = os.urandom(math.ceil(length))
    
    return binascii.b2a_hex(nonce)[:length].decode('utf-8')

'''
Returns a random base64 string with provided length. Not URL safe.
String returned contains (3/4 * length) bytes of urandom entropy.
'''
def generate_base64(length):
    nonce = os.urandom(math.ceil(int(float(length)*3/4)))
    return base64.b64encode(nonce).decode('utf-8')

def sanitize_base64(s):
    s = s.replace('+', '-')
    s = s.replace('/', '_')
    s = s.replace('=', '~')
    return s

'''
Takes two iterables, returns True if A is a subset of B
'''
def list_subset(A, B):
    if not A or not B:
        return False
    for a in A:
        if a not in B:
            return False
    return True

def sha256(s):
    if not isinstance(s, str):
        return None
    hasher = hashlib.sha256()
    hasher.update(s.encode('utf-8'))
    return hasher.hexdigest()

def is_sock(path):
    if not path or not isinstance(path, str):
        return False
    try:
        file_stat = os.stat(path)
    except FileNotFoundError as e:
        return False

    return stat.S_ISSOCK(file_stat.st_mode)

def build_redirect_url(base_url, token):
    #access_token, uid, user_name=None, first_name=None, last_name=None):
    user = token.user
    url = '{}/?access_token={}'.format(base_url, token.access_token)
    url += '&uid=' + quote(user.id)
    url += '&user_name=' + quote(user.user_name)
    url += '&name=' + quote(user.name)

    #body = {
    #        'access_token': token.access_token,
    #        'uid': user.id,
    #        'user_name': user.user_name,
    #        'name': user.name
    #}
    #body_encoded = base64.b64encode(json.dumps(body))
    #url = '{}/?context={}'.format(base_url, body_encoded)

    return url

