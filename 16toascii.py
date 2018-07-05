# -*- coding: utf-8 -*-
import binascii
import sys

try:
    if(sys.argv[1][:2]=="0x"):
        sys.argv[1]=sys.argv[1][2:]
        res = binascii.a2b_hex(sys.argv[1])  # 转换成ASCii编码的字符串
        print res
    else:
        res = binascii.a2b_hex(sys.argv[1]) #转换成ASCii编码的字符串
        print res
except Exception,e:
    print e