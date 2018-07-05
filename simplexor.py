# coding=utf-8

import base64

import string

import binascii



#随便从known.txt中取出一行，这里去除第一行

plain = "jYj0ApA8korwFrDKhkBsyAfcklX81hYr"

password = "IB8hBnIHFQkRBAERABwFCDsPe0AadDEZJVkIbWMyFzo="



#password.enc中的内容

encpwd = base64.b64decode("CzVrT1wCdFoUBARGMgYgN3McVkFDQzIINxUjPD8qIi0=")



dpwd = base64.b64decode(password)

#长度为32，和明文长度相同，则使用简单的异或运算

key = ""

for i in range(0,len(plain)):

	key += chr(ord(plain[i])^ ord(dpwd[i]))

	filekey = ""



for i in range(0,len(plain)):

	filekey += chr(ord(key[i])^ ord(encpwd[i]))

	#获得压缩文件的解压缩密码

print "file password : " + filekey



plain_text = ""

cipher_text = ""



#根据每一样用：分割的字符长度相同，大概看一下为基础的替换

f = open("C:\Users\hnytg\Desktop\Known_2606af6097a6154ad2fe4c67748ee089\level1\level2\known.txt","r")

data = f.readline()

#拼接明文字串以及密文字串

while(len(data) != 0):

	data = f.readline()[0:-1]

	dt = data.split(':')

	if(len(dt) == 2) :

		plain_text =  plain_text + dt[0]

		cipher_text = cipher_text + dt[1]

f.close()



#获取标准字串对应的替换字串

encode_table = '{' + string.letters + string.digits + '}'

decode_table = ""

for i in encode_table:

	decode_table += cipher_text[plain_text.find(i)]

print "default table : " + encode_table

print "challage_table : " + decode_table



#加密的flag

encrypt_flag = "uAmUXk{jW{Stp{JpMA0spF7OS0SS0aq8"

decrypt_flag =""

#利用对应关系获得原始的flag

for i in encrypt_flag:

	decrypt_flag += encode_table[decode_table.find(i)]

	print "The True flag is : " + decrypt_flag

