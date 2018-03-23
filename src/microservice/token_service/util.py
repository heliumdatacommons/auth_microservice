import os
import math
import binascii


'''
    Returns a random hex string with provided length. URL safe.
'''
def generate_nonce(length):
    nonce = os.urandom(math.ceil(length))
    
    return binascii.b2a_hex(nonce)[:length].decode('utf-8')
