#!/usr/bin/env python
# -*- coding: gbk -*-
# -*- coding: utf_8 -*-

e = raw_input('please input the string you want to decode:\n')
elen = len(e)
field=[]
for i in range(2,elen):
            if(elen%i==0):
                field.append(i)
 
for f in field:
    b = elen / f
    result = {x:'' for x in range(b)}
    for i in range(elen):
        a = i % b;
        result.update({a:result[a] + e[i]})
    d = ''
    for i in range(b):
        d = d + result[i]
    print 'result '+str(f)+'\t'+'times, the result is:'+d
