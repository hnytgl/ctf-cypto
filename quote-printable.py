import quopri

def qoutdecode(s):
	print quopri.decodestring(s)
	
res = raw_input("please input the quoted-printable encode string:")
qoutdecode(res)