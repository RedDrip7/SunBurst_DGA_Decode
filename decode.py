#!/usr/env python
# -*- coding:utf-8 -*-
import sys
import random

import argparse

'''
# author = "QiAnXin_RedDrip"
# twitter = @RedDrip7
# create_date = "2020-12-15"
# update_date = "2020-12-16"
# Thanks QiAnXin CERT for the discovery of decodeable DGA domains
# https://mp.weixin.qq.com/s/v-ekPFtVNZG1W7vWjcuVug
'''


def Base32Encode(input_string, rt):
    text = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
    text2 = ""
    num = 0
    ib = 0
    for i in range(len(input_string)):
        iint = input_string[i]
        b = '0x{0:{1}X}'.format(ord(iint), 2)
        num |= (int(b, 16) << ib)
        ib += 8
        while (ib >= 5):
            text2 += text[num & 31]
            num >>= 5  # 将高位的部分右移
            ib -= 5
            pass
        pass

    if (ib > 0):
        if (rt):
            pass
        text2 += text[(num & 31)]
        pass

    return text2


def Base32Decode(b32string):
    text = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
    restring = ""
    datalen = len(b32string) // 8 * 5
    num = 0
    ib = 0
    if len(b32string) < 3:
        restring = chr(text.find(b32string[0]) | text.find(b32string[1]) << 5 & 255)
        return restring

    k = text.find(b32string[0]) | (text.find(b32string[1]) << 5)
    j = 10
    index = 2
    for i in range(datalen):
        restring += chr(k & 255)
        k = k >> 8
        j -= 8
        while (j < 8 and index < len(b32string)):
            k |= (text.find(b32string[index]) << j)
            index += 1
            j += 5

    return restring


'''OrionImprovementBusinessLayer.CryptoHelper.Base64Decode'''


def Encode(input_string):
    text = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj"
    text2 = "0_-."
    text3 = ""
    for i in range(len(input_string)):
        ch = input_string[i]
        tx_index = -1
        tx2_index = -1
        if ch in text2:
            tx2_index = text2.find(ch)
            text3 = text3 + text2[0] + text[tx2_index + (random.randint(0, 8) % (len(text) // len(text2))) * len(text2)]
        else:
            tx_index = text.find(ch)
            text3 = text3 + text[(tx_index + 4) % len(text)]

    return text3


'''OrionImprovementBusinessLayer.CryptoHelper.Base64Decode-decode'''


def Decode(input_string):
    text = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj"
    text2 = "0_-."
    retstring = ""
    flag = False
    for i in range(len(input_string)):
        ch = input_string[i]
        tx_index = -1
        tx2_index = -1
        if flag:
            t1i = text.find(ch)
            x = t1i - ((random.randint(0, 8) % (len(text) // len(text2))) * len(text2))
            retstring = retstring + text2[x % len(text2)]
            flag = False
            continue
        if ch in text2:
            tx2_index = text2.find(ch)
            flag = True
            pass
        else:
            tx_index = text.find(ch)
            oindex = tx_index - 4
            retstring = retstring + text[oindex % len(text)]

        pass
    return retstring


# print (Encode("qingmei-inc.com"))
# print (Decode("aovthro08ove0ge2h"))
# print (Base32Decode("9tslbqv1ftss4r01eqtobmv1"))

'''
  1fik67gkncg86q6daovthro0love0oe2.appsync-api.us-west-2.avsvmcloud.com
  this.guid  --> 1fik67gkncg86q6
  单个字符：  d
  域： qingmei-inc.com   --- > aovthro0love0oe2h  但是由于取的是this.dnStrLower而不是this.dnStr，会吞掉一部分字符,所以最终"h"被吞掉了
'''

# # 在有域的主机中，走GetPreviousString()模式, 拼接方式： CreateSecureString(this.guid, true) + 一个字符 + this.dnStrLower + ".appsync-api.us-west-2.avsvmcloud.com"
# for line in sys.stdin:
#     data = line.rstrip().split(".")[0]
#     if len(data) < 16:
#         continue
#     string = data[16:]  # 前十六字节： this.guid + 一个字符
#     if "0" not in string:  # 如果没有0，说明不是OrionImprovementBusinessLayer.CryptoHelper.Base64Encode和OrionImprovementBusinessLayer.CryptoHelper.Base64Decode，暂时解不开
#         continue
#     try:
#         if "00" in string:
#             string = string[2:]
#             comp = Base32Decode(string)
#         else:
#             comp = Decode(string)
#
#         print ("%s,%s" % (line.rstrip(), comp))
#     except:
#         pass
#

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', type=argparse.FileType('r'), default=sys.stdin)
    parser.add_argument('-o', '--output', type=argparse.FileType('w'), default=sys.stdout)

    args = parser.parse_args()
    in_file = args.input
    out_file = args.output
    for line in in_file:
        data = line.rstrip().split(".")[0]
        if len(data) < 16:
            continue
        in_string = data[16:]  # 前十六字节： this.guid + 一个字符
        if "0" not in in_string :  # 如果没有0，说明不是OrionImprovementBusinessLayer.CryptoHelper.Base64Encode和OrionImprovementBusinessLayer.CryptoHelper.Base64Decode，暂时解不开
            continue
        try:
            if "00" in in_string :
                in_string  = in_string [2:]
                comp = Base32Decode(in_string)
            else:
                comp = Decode(in_string)
            out_file.write('{0}, {1}\n'.format(line.rstrip(), comp))
        except:
            pass


if __name__ == '__main__':
    main()
