import math
import binascii


'''
    Returns a random hex string with provided length. URL safe.
'''
def generate_nonce(length):
    nonce = os.urandom(length)
    
    return base64.b64encode(nonce)[:length]
