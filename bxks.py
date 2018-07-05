
s= raw_input("please input the string you want to decode(bianxiangkaisa):")
res=""
for i in range(-20,20,1):
	for j in range(0,len(s)):
		res+=chr(ord(s[j])+i)
		#print ord(s[j])+i,
	#print res+'\n'
	if 'flag' in res:
		print res
	res=""
	