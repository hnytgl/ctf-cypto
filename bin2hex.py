import binascii

__author__ = 'feifei'
# !/usr/bin/env python
# -*- coding: utf-8 -*-


base = [str(x) for x in range(10)] + [chr(x) for x in range(ord('A'), ord('A') + 6)]


# bin2dec
def bin2dec(string_num):
    return str(int(string_num, 2))


# hex2dec
def hex2dec(string_num):
    return str(int(string_num.upper(), 16))


# dec2bin
def dec2bin(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0: break
        num, rem = divmod(num, 2)
        mid.append(base[rem])

    return ''.join([str(x) for x in mid[::-1]])


# dec2hex
def dec2hex(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0:
            break
        num, rem = divmod(num, 16)
        mid.append(base[rem])

    return ''.join([str(x) for x in mid[::-1]])


# hex2tobin
def hex2bin(string_num):
    return dec2bin(hex2dec(string_num.upper()))


# bin2hex
def bin2hex(string_num):
    return dec2hex(bin2dec(string_num))


if __name__ == '__main__':
    file1 = open('question.txt')
    s = file1.read()
    hexx = bin2hex(s)
    print hexx
    file2 = open('4.txt', 'wb')
    file2.write(binascii.a2b_hex(hexx))