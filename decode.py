#!/usr/env python
# -*- coding:utf-8 -*-
import re
import sys
import random
import argparse

'''
# author = "QiAnXin_RedDrip"
# twitter = @RedDrip7
# create_date = "2020-12-15"
# Thanks QiAnXin CERT for the discovery of decodeable DGA domains
# https://mp.weixin.qq.com/s/v-ekPFtVNZG1W7vWjcuVug
# modified by @malvidin
# update_date = "2020-12-17"
'''


def make_trans(text_in, text_out):
    if isinstance(text_in, bytes):
        try:
            trans = bytes.maketrans(text_in, text_out)
        except:
            import string
            trans = string.maketrans(text_in, text_out)
    else:
        try:
            trans = str.maketrans(text_in, text_out)
        except:
            import string
            trans = string.maketrans(text_in, text_out)
    return trans


def ensure_str(input_string):
    if isinstance(input_string, str):
        return input_string
    if isinstance(input_string, bytes):
        return input_string.decode()
    if isinstance(input_string, unicode):
        return input_string.encode()
    return str(input_string)


def custom_base32encode(input_string, rt=True):
    text = 'ph2eifo3n5utg1j8d94qrvbmk0sal76c'
    ret_string= ''

    bits_on_stack = 0
    bit_stack = 0
    for ch in input_string:
        bit_stack |= ord(ch) << bits_on_stack
        bits_on_stack += 8
        while bits_on_stack >= 5:
            ret_string += text[bit_stack & 0b11111]
            bit_stack >>= 5  #将高位的部分右移
            bits_on_stack -= 5
    if bits_on_stack > 0:
        if rt:
            ret_string += text[bit_stack & 0b11111]
    return ret_string


def custom_base32decode(input_string, rt=True, bits_on_stack=0, bit_stack=0):
    text = 'ph2eifo3n5utg1j8d94qrvbmk0sal76c'
    ret_string = ''

    for ch in input_string:
        bit_stack |= text.find(ch) << bits_on_stack
        bits_on_stack += 5
        if bits_on_stack >= 8:
            ret_string += chr(bit_stack & 255)
            bit_stack >>= 8
            bits_on_stack -= 8
    if bits_on_stack > 0 and bit_stack > 0:
        if rt:
            ret_string += ' (0b{:06b}, {})'.format(bit_stack & 255, bits_on_stack)
    return ret_string


'''OrionImprovementBusinessLayer.CryptoHelper.Base64Decode'''


def encode_sub_cipher(input_string):
    text = 'rq3gsalt6u1iyfzop572d49bnx8cvmkewhj'
    text_spec = '0_-.'
    trans = make_trans(text, text[4:] + text[:4])
    trans_string = input_string.translate(trans)
    # Use # to track the special substitutions
    re_spec = '([{}])'.format(re.escape(text_spec))
    trans_string = re.sub(re_spec, r'#\1', trans_string)
    # make the substitutions based on the text replacement string
    spec_choices = {k:text[i::len(text_spec)] for i,k in enumerate(text_spec)}
    while '#' in trans_string:
        idx = trans_string.find('#')
        trans_char = trans_string[idx+1]
        trans_string = trans_string[:idx] + '{}{}'.format(text_spec[0], random.choice(spec_choices[trans_char])) + trans_string[idx+2:]

    return trans_string


'''OrionImprovementBusinessLayer.CryptoHelper.Base64Decode-decode'''


def decode_subs_cipher(input_string):
    text = 'rq3gsalt6u1iyfzop572d49bnx8cvmkewhj'
    text_spec = '0_-.'
    trans = make_trans(text[4:] + text[:4], text)

    for i, ch in enumerate(input_string):
        if ch in text_spec:
            spec_idx = text.find(input_string[i+1]) % len(text_spec)
            # Since we're walking through each character, the string length must not change
            input_string = input_string[:i] + '#' + text_spec[spec_idx] + input_string[i+2:]
    input_string = input_string.replace('#', '')
    trans_string = input_string.translate(trans)

    return trans_string


'''OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString-decode'''


def decode_guid(input_string):
    ret_string = ''
    decoded = custom_base32decode(input_string)
    xor_key = ord(decoded[0])
    encoded_guid = decoded[1:]
    for b in encoded_guid:
        ret_string += '{:02X}'.format(ord(b)^xor_key)
    return ret_string


def encode_guid(input_string, xor_key=None):
    ret_string = ''
    if xor_key is None:
        xor_key = random.randint(1,127) | 128
    ret_string += chr(xor_key)
    while len(input_string)>0:
        hx = input_string[:2]
        input_string =  input_string[2:]
        ret_string += chr(int(hx, 16) ^ xor_key)
    return custom_base32encode(ret_string)


def decode_dga(input_string, prev_strings=None):
    if prev_strings is None:
        prev_strings = []
    data = input_string.split('.', maxsplit=1)[0]
    system_guid, dn_str_lower = ('',) * 2
    if len(data) >= 16:
        try:
            system_guid = decode_guid(data[:16])
        except:
            pass
        encoded_string = data[16:]

        if '0' in data[16:]:
            try:
                dn_str_lower = None
                if encoded_string.startswith('00'):
                    # Custom Base32 Encoding
                    encoded_string = encoded_string[2:]
                    for prev_string in prev_strings:
                        dn_str_lower_test = custom_base32decode(encoded_string + prev_string)
                        if all(ord(char) < 128 for char in dn_str_lower_test):
                            dn_str_lower = dn_str_lower_test
                            break
                    if dn_str_lower is None:
                        dn_str_lower = custom_base32decode(encoded_string)
                else:
                    # Substitution Cipher
                    # This will incorrectly decode some continuation characters from base32 encoding that contain '0'
                    dn_str_lower = decode_subs_cipher(encoded_string.rstrip('0'))
            except:
                dn_str_lower = '(decode failed)'
        else:
            # These strings be from a domain that 16+ characters long, or continuation characters from base32 encoding
            dn_str_lower = decode_subs_cipher(encoded_string) + ' (no dot)'

    return system_guid, dn_str_lower

assert decode_subs_cipher('aovthro08ove0ge2h') == 'qingmei-inc.com'
assert decode_subs_cipher(encode_sub_cipher('qingmei-inc.com')) == 'qingmei-inc.com'
assert custom_base32encode('qingmei-inc.com') == '9tslbqv1ftss4r01eqtobmv1'
assert custom_base32decode('9tslbqv1ftss4r01eqtobmv1') == 'qingmei-inc.com'

# Thanks to netresec.com for the GUID values
assert decode_guid('r1qshoj05ji05ac6') == 'F9A9387F7D25284243'
assert encode_guid('F9A9387F7D25284243', xor_key=180) == 'r1qshoj05ji05ac6'


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', type=argparse.FileType('r'), default=sys.stdin)
    parser.add_argument('-o', '--output', type=argparse.FileType('w'), default=sys.stdout)

    args = parser.parse_args()
    in_file = args.input
    out_file = args.output
    summary_dict = {}
    for line in in_file:
        line = line.rstrip()
        system_guid, dn_str_lower = decode_dga(line)
        out_file.write(','.join([line, system_guid, dn_str_lower]) + '\n')
        
        if system_guid in summary_dict:
            if dn_str_lower not in summary_dict[system_guid]:
                summary_dict[system_guid]
        else:
            summary_dict[system_guid] = [dn_str_lower]
        if summary_dict:
            out_file.write('\nSummary by GUID:\n')
            for guid, dn_list in summary_dict.items():
                for li in dn_list:
                    out_file.write(','.join([guid, li]) + '\n')


if __name__ == '__main__':
    main()
