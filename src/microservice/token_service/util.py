import os
import math
import binascii


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
