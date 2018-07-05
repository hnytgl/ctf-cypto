#! usr/bin/env python
# coding:utf-8
import string

upperdict = {}
lowerdict = {}
upperletters = string.ascii_uppercase
lowerletters = string.ascii_lowercase  # ：所有小写字母

dststr = []
oristr = raw_input('Enter string to rot13:')  # 版本3.0不能用raw_input
print('Your string ro en/crypt was :', oristr)

for i in range(0, len(lowerletters)):  # 把所有小写字母转为rot13
    if i < 13:
        lowerdict[lowerletters[i]] = lowerletters[i + 13]
    else:
        lowerdict[lowerletters[i]] = lowerletters[i - 13]

for i in range(0, len(upperletters)):  # 把所有大写字母转为rot13
    if i < 13:
        lowerdict[upperletters[i]] = upperletters[i + 13]
    else:
        lowerdict[upperletters[i]] = upperletters[i - 13]

for ch in oristr:
    if ch in lowerdict:
        dststr.append(lowerdict[ch])
    elif ch in upperdict:
        dststr.append(upperdict[ch])
    else:
        dststr.append(ch)
dststr = ''.join(dststr)

print('the rot13 string is:', dststr)