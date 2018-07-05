# !/usr/bin/env python

from pycipher import Vigenere

ciphertext=raw_input("please input the decode strings:")
key = raw_input("please input the key:")

plaintext=Vigenere(key).encipher(ciphertext)

print "the result is:"+plaintext
