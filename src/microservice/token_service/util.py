import os
import stat
import math
import binascii
import hashlib

'''
    Returns a random hex string with provided length. URL safe.
'''
def generate_nonce(length):
    nonce = os.urandom(math.ceil(length))
    
    return binascii.b2a_hex(nonce)[:length].decode('utf-8')

'''
takes two iterables, returns True if A is a subset of B
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

