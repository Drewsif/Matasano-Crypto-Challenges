#!/usr/bin/env python
from __future__ import division, absolute_import, with_statement, print_function, unicode_literals
import base64

def hex_to_base64(hex):
    if isinstance(hex, unicode):
        hex = hex.decode('hex')
    data = base64.b64encode(hex)
    return data

if __name__ == '__main__':
    test1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    result1 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    if hex_to_base64(test1) == result1:
        print('hex_to_base64 passed')
    else:
        print('hex_to_base64 failed') 