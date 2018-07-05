def xxcode(s):
	flag = ''
	ans = ''
	consts = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
	for i in s:
		for j in range(0,len(consts)):
			if i == consts[j] :
				k = j
		#print k
		num = ''
		while(k>0):
			num += chr(k%2+ord('0'))
			k = k/2
		while(len(num)<6):
			num = num + '0'
		#print num
		num = num[::-1]
		#print num
		flag += num
	#print flag
	while(len(flag)%8!=0):
		flag += '0'
	for i in range(0,len(flag),8):
		x = 0
		for j in range(0,8):
			x *= 2
			if flag[i+j]=='1':
				x += 1
		#print x
		ans += chr(x)
	print ans
if __name__ == '__main__':
	
	s = raw_input("Please input the string you want to xxdecode:")
	#s = 'Eq3o'
	print xxcode(s)