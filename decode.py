# -*- coding:utf-8 -*- 
import sys,os
import random
import base64
import random
'''  
# author = "QiAnXin_RedDrip"
# twitter = @RedDrip7
# create_date = "2020-12-15"
# update_date = "2020-12-16"
# Thanks QiAnXin CERT for the discovery of decodeable DGA domains
# https://mp.weixin.qq.com/s/v-ekPFtVNZG1W7vWjcuVug
'''

def Int2Hex(value,format):
	#format 可以是2/4/8
	hexStr = ""
	hexStr = hex(value)
	if(len(hexStr) != format+2):
		zero = format+2 - len(hexStr)
		for i in range(zero):
			hexStr = hexStr[:2] + '0' + hexStr[2:]
	return hexStr[2:]

def Base32Encode(tring,rt):
	text = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
	text2 = ""
	num = 0
	ib = 0;
	for i in range(len(tring)):
		iint = tring[i]
		b = "0x" + Int2Hex(ord(iint),2)
		num |= (int(b,16) << ib)
		ib+=8
		while (ib >= 5):
			text2 += text[num & 31]
			num >>= 5  #将高位的部分右移
			ib -= 5
			pass
		pass

	if (ib > 0):
		if (rt):
			pass
		text2 += text[(num & 31)]
		pass

	return text2; 

def Base32Decode(string):
	text = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
	restring = ""
	datalen = len(string) / 8 * 5
	num = 0
	ib = 0;
	if len(string) < 3:
		restring = chr(text.find(string[0]) | text.find(string[1]) << 5 & 255)
		return restring
	
	k = text.find(string[0]) | (text.find(string[1]) << 5)
	j = 10
	index = 2
	for i in range(datalen):
		restring += chr(k & 255)
		k = k >> 8
		j -= 8
		while( j < 8 and index < len(string)):
			k |= (text.find(string[index]) << j)
			index += 1
			j += 5

	return restring

'''OrionImprovementBusinessLayer.CryptoHelper.Base64Decode'''
def Encode(tring):
	text = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj"
	text2 = "0_-."
	text3 = ""
	#print random.randint()
	for i in range(len(tring)):
		ch = tring[i]
		tx_index = -1
		tx2_index = -1
		if ch in text2:
			tx2_index = text2.find(ch)
			text3 = text3 + text2[0] + text[tx2_index + (random.randint(0,8) % (len(text) / len(text2))) * len(text2)]
		else:
			tx_index = text.find(ch)
			text3 = text3+text[(tx_index + 4) % len(text)]

	return text3

'''OrionImprovementBusinessLayer.CryptoHelper.Base64Decode-decode'''
def Decode(string):
	text = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj"
	text2 = "0_-."
	retstring = ""
	flag = False
	for i in range(len(string)):
		ch = string[i]
		tx_index = -1
		tx2_index = -1
		if flag:
			t1i = text.find(ch)
			x = t1i - ((random.randint(0,8) % (len(text) / len(text2))) * len(text2))
			retstring = retstring+text2[x % len(text2)]
			flag = False
			continue
		if ch in text2:
			tx2_index = text2.find(ch)
			flag = True
			pass
		else:
			tx_index = text.find(ch)
			oindex = tx_index - 4
			retstring = retstring+text[oindex % len(text)]

		pass
	return retstring

#print Encode("qingmei-inc.com")
#print Decode("aovthro08ove0ge2h")
#print Base32Decode("9tslbqv1ftss4r01eqtobmv1")

'''
  1fik67gkncg86q6daovthro0love0oe2.appsync-api.us-west-2.avsvmcloud.com
  this.guid  --> 1fik67gkncg86q6
  单个字符：  d
  域： qingmei-inc.com   --- > aovthro0love0oe2h  但是由于取的是this.dnStrLower而不是this.dnStr，会吞掉一部分字符,所以最终"h"被吞掉了
'''

#在有域的主机中，走GetPreviousString()模式, 拼接方式： CreateSecureString(this.guid, true) + 一个字符 + this.dnStrLower + ".appsync-api.us-west-2.avsvmcloud.com"
for line in sys.stdin:
	data = line.rstrip().split(".")[0]
	if len(data) < 16:
		continue
	string = data[16:] #前十六字节： this.guid + 一个字符
	if "0" not in string:  #如果没有0，说明不是OrionImprovementBusinessLayer.CryptoHelper.Base64Encode和OrionImprovementBusinessLayer.CryptoHelper.Base64Decode，暂时解不开
		continue
	try:
		if "00" in string:
			string = string[2:]
			comp = Base32Decode(string)
		else:
			comp = Decode(string)

		print "%s,%s" % (line.rstrip(),comp)
	except:
		pass
