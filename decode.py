#!/usr/env python
# -*- coding:utf-8 -*-
import re
import sys
import random
import argparse
import csv
import ipaddress

from enum import Flag
from datetime import datetime, timedelta

'''
# author = "QiAnXin_RedDrip"
# twitter = @RedDrip7
# create_date = "2020-12-15"
# Thanks QiAnXin CERT for the discovery of decodeable DGA domains
# https://mp.weixin.qq.com/s/v-ekPFtVNZG1W7vWjcuVug
# modified by @malvidin
# update_date = "2020-01-10"
'''


class SecurityApps(Flag):
    WINDOWS_DEFENDER_RUNNING = 0x0001
    WINDOWS_DEFENDER_STOPPED = 0x0002
    WINDOWS_DEFENDER_ATP_RUNNING = 0x0004
    WINDOWS_DEFENDER_ATP_STOPPED = 0x0008
    MS_DEFENDER_FOR_IDENTITY_RUNNING = 0x0010
    MS_DEFENDER_FOR_IDENTITY_STOPPED = 0x0020
    CARBON_BLACK_RUNNING = 0x0040
    CARBON_BLACK_STOPPED = 0x0080
    CROWDSTRIKE_RUNNING = 0x0100
    CROWDSTRIKE_STOPPED = 0x0200
    FIREEYE_RUNNING = 0x0400
    FIREEYE_STOPPED = 0x0800
    ESET_RUNNING = 0x1000
    ESET_STOPPED = 0x2000
    FSECURE_RUNNING = 0x4000
    FSECURE_STOPPED = 0x8000


def make_trans(text_in, text_out):
    if isinstance(text_in, bytes):
        trans = bytes.maketrans(text_in, text_out)
    else:
        trans = str.maketrans(text_in, text_out)
    return trans


def custom_base32encode(input_bytes, rt=True):
    text = 'ph2eifo3n5utg1j8d94qrvbmk0sal76c'
    ret_string = ''

    bits_on_stack = 0
    bit_stack = 0
    for ch in input_bytes:
        bit_stack |= ord(ch) << bits_on_stack
        bits_on_stack += 8
        while bits_on_stack >= 5:
            ret_string += text[bit_stack & 0b11111]
            bit_stack >>= 5  # 将高位的部分右移
            bits_on_stack -= 5
    if bits_on_stack > 0:
        if rt:
            ret_string += text[bit_stack & 0b11111]
    return ret_string


def custom_base32decode(input_string, rt=True, bits_on_stack=0, bit_stack=0):
    text = 'ph2eifo3n5utg1j8d94qrvbmk0sal76c'
    ret_bytes = b''

    for ch in input_string:
        bit_stack |= text.find(ch) << bits_on_stack
        bits_on_stack += 5
        if bits_on_stack >= 8:
            ret_bytes += bytes([bit_stack & 255])
            bit_stack >>= 8
            bits_on_stack -= 8
    if bits_on_stack > 0 and bit_stack > 0:
        if rt:
            ret_bytes += ' (0b{:06b}, {})'.format(bit_stack & 255, bits_on_stack).encode()
    return ret_bytes


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
    spec_choices = {k: text[i::len(text_spec)] for i, k in enumerate(text_spec)}
    while '#' in trans_string:
        idx = trans_string.find('#')
        trans_char = trans_string[idx + 1]
        trans_string = trans_string[:idx] + \
                       '{}{}'.format(text_spec[0], random.choice(spec_choices[trans_char])) + \
                       trans_string[idx + 2:]
    return trans_string


'''OrionImprovementBusinessLayer.CryptoHelper.Base64Decode-decode'''


def decode_subs_cipher(input_string):
    text = 'rq3gsalt6u1iyfzop572d49bnx8cvmkewhj'
    text_spec = '0_-.'
    trans = make_trans(text[4:] + text[:4], text)
    input_string = input_string.rstrip('0')

    for i, ch in enumerate(input_string):
        if ch in text_spec:
            spec_idx = text.find(input_string[i + 1]) % len(text_spec)
            # Since we're walking through each character, the string length must not change
            input_string = input_string[:i] + '#' + text_spec[spec_idx] + input_string[i + 2:]
    input_string = input_string.replace('#', '')
    trans_string = input_string.translate(trans)

    return trans_string


'''OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString-decode'''


def decode_guid(input_string):
    ret_string = ''
    decoded = custom_base32decode(input_string)
    xor_key = decoded[0]
    encoded_guid = decoded[1:]
    for b in encoded_guid:
        ret_string += '{:02X}'.format(b ^ xor_key)
    return ret_string


def encode_guid(input_string, xor_key=None):
    ret_string = ''
    if xor_key is None:
        xor_key = random.randint(1, 127) | 128
    ret_string += chr(xor_key)
    while len(input_string) > 0:
        hx = input_string[:2]
        input_string = input_string[2:]
        ret_string += chr(int(hx, 16) ^ xor_key)
    return custom_base32encode(ret_string)


def get_domain_order(first_char, input_char):
    text = '0123456789abcdefghijklmnopqrstuvwxyz'
    return (text.find(input_char) - ord(first_char)) % 36


def decode_dga(input_string):
    data = input_string.split('.', maxsplit=1)[0]
    system_guid, dn_str_lower, decode_info, encoded_string = ('',) * 4
    if len(data) >= 16:
        try:
            system_guid = decode_guid(data[:15])[:16]
        except:
            pass
        encoded_string = data[16:]

        if '0' in data[16:]:
            try:
                if encoded_string.startswith('00'):
                    # Custom Base32 Encoding
                    dn_str_lower = custom_base32decode(encoded_string[2:].replace('00', '0')).decode()
                    decode_info = 'custom_base32'
                else:
                    # Substitution Cipher
                    # This will incorrectly decode some continuation characters from base32 encoding that contain '0'
                    dn_str_lower = decode_subs_cipher(encoded_string)
                    decode_info = 'subs_cipher'
            except:
                decode_info = 'decode failed'
        else:
            # These strings be from a domain that 16+ characters long, or continuation characters from base32 encoding
            dn_str_lower = decode_subs_cipher(encoded_string)
            decode_info = 'subs_cipher (no dot)'
    return system_guid, encoded_string, dn_str_lower, decode_info


def lookup_address_family(ip_address):
    # Needs additional AddressFamilyEx context and IP mapping
    ipv4nets = {
        'Atm (prevent execution)': [
            ipaddress.IPv4Network('127.0.0.0/8'),
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('224.0.0.0/4'),
        ],
        'ImpLink': [
            ipaddress.IPv4Network('20.140.0.0/15'),
            ipaddress.IPv4Network('96.31.172.0/24'),
            ipaddress.IPv4Network('131.228.12.0/22'),
            ipaddress.IPv4Network('144.86.226.0/24'),
        ],
        'Ipx (update Status)': [
            ipaddress.IPv4Network('41.84.159.0/24'),
            ipaddress.IPv4Network('74.114.24.0/21'),
            ipaddress.IPv4Network('154.118.140.0/24'),
            ipaddress.IPv4Network('217.163.7.0/24'),
        ],
        'NetBios (intialize HTTP channel)': [
            ipaddress.IPv4Network('8.18.144.0/23'),
            ipaddress.IPv4Network('18.130.0.0/16'),  # ext = true
            ipaddress.IPv4Network('71.152.53.0/24'),
            ipaddress.IPv4Network('99.79.0.0/16'),  # ext = true
            ipaddress.IPv4Network('87.238.80.0/21'),
            ipaddress.IPv4Network('199.201.117.0/24'),
            ipaddress.IPv4Network('184.72.0.0/15'),  # ext = true
        ],
    }
    ipv6nets = {
        'Atm (enum processes and services)': [
            ipaddress.IPv6Network('fc00::/15'),
            ipaddress.IPv6Network('fe00::/16'),
            ipaddress.IPv6Network('ff00::/16'),
        ],
    }

    try:
        ip = ipaddress.IPv4Address(ip_address)
        for address_family, net_list in ipv4nets.items():
            for net in net_list:
                if ip in net:
                    return address_family
    except:
        pass
    try:
        ip = ipaddress.IPv6Address(ip_address)
        for address_family, net_list in ipv6nets.items():
            for net in net_list:
                if ip in net:
                    return address_family
    except:
        pass
    return ''


def store_command_summary(line, summary_dict):
    decoded_data = custom_base32decode(line.split('.')[0], rt=False)
    xor_key = decoded_data[0]
    data_xor_byte = b''
    for ch in decoded_data:
        data_xor_byte += bytes([ch ^ xor_key])

    # using little endian instead of XOR'ing the first byte and ignoring it later
    key_xor_word = int.from_bytes(data_xor_byte[10:12], 'little')
    data_xor_words = 0
    for i in range(1, 9, 2):
        data_xor_words <<= 16
        d = int.from_bytes(data_xor_byte[i:i + 2], 'big')
        data_xor_words += (d ^ key_xor_word)

    system_guid = '{:016X}'.format(data_xor_words)
    data_info = int.from_bytes(data_xor_byte[9:12], 'big')
    activity_date = datetime(2010, 1, 1) + timedelta(
        minutes=15 * (data_info & 0x0FFFFE))  # quarter hour per tick, not 4 seconds
    dnssec = True if data_info & 0x1 else False
    data_len = data_info >> 20

    # Get svcList
    if 1 <= data_len <= 2:
        str_flags = 'ping'
        data_payload = int.from_bytes(data_xor_byte[12:12 + data_len], 'big')
        app_flags = SecurityApps(data_payload)
        if app_flags:
            str_flags = str(SecurityApps(data_payload)).split('.', maxsplit=1)[-1]
    else:
        return None, None, None

    # Limit dates to known timeframes
    if datetime(2020, 1, 1) > activity_date or activity_date > datetime.now() + timedelta(days=15):
        return None, None, None

    if system_guid in summary_dict:
        if 'activity' in summary_dict[system_guid]:
            if activity_date in summary_dict[system_guid]['activity']:
                summary_dict[system_guid]['activity'][activity_date] += '|{}'.format(str_flags)
            else:
                summary_dict[system_guid]['activity'][activity_date] = str_flags
        else:
            summary_dict[system_guid]['activity'] = {activity_date: str_flags}
    else:
        summary_dict[system_guid] = {'activity': {activity_date: str_flags}}

    return activity_date, str_flags, system_guid


def store_domain_summary(domain_order, line, summary_dict):
    system_guid, encoded_string, dn_str_lower, decode_info = decode_dga(line)
    if system_guid not in summary_dict:
        summary_dict[system_guid] = {'encoded_strings': {}}
    elif 'encoded_strings' not in summary_dict[system_guid]:
        summary_dict[system_guid]['encoded_strings'] = {}
    summary_dict[system_guid]['encoded_strings'][domain_order] = encoded_string

    return decode_info, dn_str_lower, system_guid


assert decode_subs_cipher('aovthro08ove0ge2h') == 'qingmei-inc.com'
assert decode_subs_cipher(encode_sub_cipher('qingmei-inc.com')) == 'qingmei-inc.com'
assert custom_base32encode('qingmei-inc.com') == '9tslbqv1ftss4r01eqtobmv1'
assert custom_base32decode('9tslbqv1ftss4r01eqtobmv1').decode() == 'qingmei-inc.com'

# Thanks to netresec.com for the GUID values
assert decode_guid('r1qshoj05ji05ac6') == 'F9A9387F7D25284243'
assert encode_guid('F9A9387F7D25284243', xor_key=180) == 'r1qshoj05ji05ac6'


def join_dn_str_dict(input_dict):
    # From a dict that contains the index of each encoded string, like {0:'01234567890abcdef', 35: '0123456'}
    # attempts to decode, even if data is missing. If the there is data missing in indexes 1+, it may not be
    # recoverable

    str_list = []
    multi_str = False
    complete_str = True
    prev_num = None

    for i, val in sorted(input_dict.items()):
        if i not in range(0, 36):
            continue
        if multi_str:
            if not prev_num == i - 1:
                complete_str = False
        str_list.append(val)
        prev_num = i

    if str_list[0].startswith('00'):
        decode_type = 'custom_base32'
        if str_list:
            joined_string = str_list[0][2:].rstrip('0')
            if len(str_list) > 1:
                joined_string += ''.join([x.rstrip('0') for x in str_list[1:]])
        else:
            joined_string = str_list.pop(35)[2:].rstrip('0')
        dn_str = custom_base32decode(joined_string).decode('utf8', errors='backslashreplace')
    else:
        decode_type = 'subs_cipher'
        dn_str = decode_subs_cipher(''.join(str_list))

    if 35 in input_dict and 0 not in input_dict:
        # Try base32 decoding
        joined_string = ''.join([x.rstrip('0') for x in str_list])
        if re.match(r'^[-a-z0-9.]*[.][-a-z0-9]{2,10}$', dn_str) or len(joined_string) <= 5:
            # Can't brute force short strings that might be base32 encoded
            pass
        else:
            for i in range(8):
                test_dn_bytes = custom_base32decode(joined_string, rt=False, bits_on_stack=i)
                if test_dn_bytes:
                    test_dn_bytes = test_dn_bytes[1:]
                try:
                    test_dn_str = test_dn_bytes.decode('utf8', errors='strict')
                    if re.match(r'^[-A-Za-z0-9.]{2,64}$', test_dn_str):
                        decode_type = 'custom_base32'
                        dn_str = '{}'.format(test_dn_str)
                except:
                    pass
    if 35 not in input_dict and 0 in input_dict:
        decode_type = 'partial_{}'.format(decode_type)
    return dn_str, complete_str, decode_type


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', type=argparse.FileType('r'), default=sys.stdin,
                        help='Input File, defaults to stdin')
    parser.add_argument('-o', '--output', type=argparse.FileType('w'), default=sys.stdout,
                        help='Output File, defaults to stdin')

    parser.add_argument('-c', '--csv', type=argparse.FileType('r'),
                        help='Input CSV')

    args = parser.parse_args()
    use_csv = False
    if args.csv:
        use_csv = True
        in_file = args.csv
    else:
        in_file = args.input

    out_file = args.output
    out_file.reconfigure(newline='')

    summary_dict = {}
    csv_out = None

    if not use_csv:
        for line in in_file:
            line = line.rstrip()
            dga_data = line.split('.')[0]
            if len(dga_data) < 16:
                out_file.write('{},too short\n'.format(line))
                continue

            domain_order = get_domain_order(dga_data[0], dga_data[15])

            # If the domain_order is 35, it is the farthest right portion of the encoded domain
            # otherwise, the length should be 32, with a value that indicates the index
            if domain_order == 35 or len(dga_data) >= 30:
                # Decode domain information
                decode_info, dn_str_lower, system_guid = store_domain_summary(domain_order, dga_data, summary_dict)
                if decode_info:
                    out_file.write(','.join([line, system_guid, dn_str_lower, decode_info, str(domain_order)]) + '\n')
                    continue
            else:
                # Attempt to decode AV info
                activity_date, str_flags, system_guid = store_command_summary(dga_data, summary_dict)
                if activity_date:
                    out_file.write(','.join([line, system_guid, str(activity_date), str_flags]) + '\n')
                    continue

            out_file.write('{},decode_failed\n'.format(line))

        if summary_dict:
            out_file.write('\n')
            out_file.write('Summary by GUID:\n')
            for guid, summ_info in summary_dict.items():
                out_file.write(guid + '\n')
                if 'encoded_strings' in summ_info:
                    dn_str, complete_str, decode_type = join_dn_str_dict(summ_info['encoded_strings'])
                    if dn_str:
                        out_file.write('    {}\n'.format(dn_str))
                    elif not complete_str:
                        out_file.write('    missing dn_str values for GUID\n')
                if 'activity' in summ_info:
                    sorted_activity = sorted(summ_info['activity'].items())
                    for d, s in sorted_activity:
                        out_file.write('    {!s},{}\n'.format(d, s))
                out_file.write('\n')

    else:
        dialect = csv.Sniffer().sniff(in_file.read(1024))
        in_file.seek(0)
        reader = csv.DictReader(in_file, dialect=dialect)
        header = reader.fieldnames
        query_field = header[0]
        query_type = None
        ip_field = None
        for field in header:
            if query_field is None and field.lower() in ('query', 'domain', 'name'):
                query_field = field
            elif query_type is None and 'type' in field.lower():
                query_type = field
            elif ip_field is None and 'ip' in field.lower() or 'response' in field.lower() or 'rdata' in field.lower():
                ip_field = field

        csv_out = []
        for line in reader:
            dga_data = line[query_field].split('.')[0]

            if len(dga_data) < 16:
                csv_out.append(line)
                continue

            domain_order = get_domain_order(dga_data[0], dga_data[15])

            if domain_order == 35 or len(dga_data) >= 30:
                # Decode domain information
                _, _, system_guid = store_domain_summary(domain_order, dga_data, summary_dict)
            else:
                activity_date, str_flags, system_guid = store_command_summary(dga_data, summary_dict)
                if activity_date:
                    line['activity_date'] = str(activity_date)
                    line['flags'] = str_flags
            if system_guid:
                line['system_guid'] = system_guid

            if ip_field:
                line['address_family'] = lookup_address_family(line[ip_field])
                if query_type and line[query_type].lower() == 'cname':
                    line['address_family'] = 'C2 Domain - {}'.format(line[ip_field])
            csv_out.append(line)

        if summary_dict:
            for guid, summ_info in summary_dict.items():
                dn_str = None
                if 'encoded_strings' in summ_info:
                    dn_str, complete_str, decode_type = join_dn_str_dict(summ_info['encoded_strings'])
                    if dn_str:
                        summary_dict[guid]['dn_str_lower'] = dn_str
                        summary_dict[guid]['decode_info'] = decode_type

        for line in csv_out:
            if 'system_guid' not in line:
                continue
            guid = line['system_guid']
            if line['system_guid'] in summary_dict:
                if 'dn_str_lower' in summary_dict[guid]:
                    line['dn_str_lower'] = summary_dict[guid]['dn_str_lower']
                if 'decode_info' in summary_dict[guid]:
                    line['decode_info'] = summary_dict[guid]['decode_info']

        for decode_header in ('system_guid', 'dn_str_lower', 'decode_info', 'activity_date', 'flags', 'address_family',):
            if decode_header not in header:
                header.append(decode_header)
        writer = csv.DictWriter(out_file, header, dialect=dialect)
        writer.writeheader()
        for row in csv_out:
            writer.writerow(row)


if __name__ == '__main__':
    main()
