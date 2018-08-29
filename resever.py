f=open('/root/16jinzhiwenjian','r')
res = f.read().split(" ")
f.close
ff=open('/root/flag','w')
ff.writelines(res[::-1])
ff.close