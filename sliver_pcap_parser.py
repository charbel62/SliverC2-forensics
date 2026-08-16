import argparse
from binascii import unhexlify
import os
import re
import gzip
import json

import pyshark


encoders = {
    
    13: "b64",
    31: "words",
    22: "png",
    43: "b58",
    45: "gzip-words",
    49: "gzip",
    64: "gzip-b64",
    65: "b32",
    92: "hex"

}

ENCODER_MODULI = (101, 65537)

base32_modified = 'ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz'


def decode_nonce(nonce_value):
    digits = re.sub('[^0-9]', '', nonce_value)
    if not digits:
        return None
    nonce = int(digits)
    for modulus in ENCODER_MODULI:
        enc = encoders.get(nonce % modulus)
        if enc:
            return enc
    return None


def detect_encoder(raw):
    if not raw:
        return None
    if raw[:2] == b'\x1f\x8b':
        return 'gzip'
    if raw[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError:
        return None
    stripped = text.replace(' ', '')
    if not stripped:
        return None
    if ' ' in text.strip() and all(c.isalpha() for c in stripped):
        return 'words'
    if all(c in '0123456789abcdefABCDEF' for c in stripped):
        return 'hex'
    if all(c in base32_modified for c in stripped):
        return 'b32'
    return 'b64'


def extract_http(packets, domain_name):
    print(f'[+] Filtering for HTTP traffic')
    payload_counter = 0

    if not os.path.exists('captures'):
        os.mkdir('captures')

    sessions = []
    seen = set()
    print('[+] Collecting Sessions')
    for packet in packets:
        packet_data = {
            'request_uri': ''
        }

        if hasattr(packet.http, 'request_method'):
            packet_data['request_method'] = packet.http.request_method
        if hasattr(packet.http, 'request_full_uri'):
            packet_data['request_uri'] = packet.http.request_full_uri
        if hasattr(packet.http, 'file_data'):
            packet_data['body'] = packet.http.file_data

        # Extract the HTTP response data. On a response the associated request
        # URI (which carries the nonce) is exposed as response_for_uri.
        if hasattr(packet.http, 'response_for_uri'):
            packet_data['request_uri'] = packet.http.response_for_uri
        if hasattr(packet.http, 'response_code'):
            packet_data['response_code'] = packet.http.response_code
        if hasattr(packet.http, 'file_data'):
            packet_data['body'] = packet.http.file_data

        # Filter against our domain
        if domain_name not in packet_data['request_uri']:
            continue

        body = packet_data.get('body')
        if not body:
            continue

        # Turn the colon separated hex tshark gives us into raw bytes so we can
        # look at what the encoder actually produced.
        try:
            raw = bytes.fromhex(body.replace(':', ''))
        except ValueError:
            continue

        # Identify the encoder from the body itself (version independent), and
        # fall back to the URL nonce only as a hint. We deliberately do NOT
        # drop a payload just because the nonce id is unknown - the decryptor
        # brute forces the encoder with the ChaCha auth tag anyway.
        encoder = detect_encoder(raw)
        if not encoder and '?' in packet_data['request_uri']:
            query = packet_data['request_uri'].split('?', 1)[1]
            for possible in query.split('='):
                hint = decode_nonce(possible)
                if hint:
                    encoder = hint
                    break
        packet_data['encoder'] = encoder

        # Deduplicate - captures are full of retransmissions and re-polls.
        dedup_key = (packet_data['request_uri'], body)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        sessions.append(packet_data)


    print(f'  [-] Found {len(sessions)} probable Sliver Payloads')

    with open('http-sessions.json', 'w') as json_file:
        json.dump(sessions, json_file)

    print('[!] Extraction Complete, if you have a key or process dump use the sliver-decrypy.py script')


def extract_dns(packets, domain_name):
    print(f'[+] Filtering for DNS traffic')
    encoded_payloads = []
    payload_counter = 0
    for p in packets:
        if hasattr(p.dns, 'resp_name'):
            # responses also include the request data so ignore
            continue

        if domain_name in p.dns.qry_name:
            payload_counter += 1
            
            encoded_value = p.dns.qry_name.split(domain_name)[0]
            encoded_payloads.append(encoded_value)
    
    print(f"  [-] Found {payload_counter} Possible encoded values")
    # DNS Needs recombining before we can decrypt the values correctly 
    # So we put them all in to a single file
    print(f"  [-] Writing encoded payloads to dns-{domain_name}.txt")
    with open(f'dns-{domain_name}.txt', 'w') as output_file:
        for payload in encoded_payloads:
            output_file.write(f'{payload}\n')
    print('[!] Extraction Complete, if you have a key or process dump use the sliver-decrypy.py script')



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Extract Sliver C2 from a PCAP file')

    parser.add_argument(
        '--pcap',
        help='Path to pcap file',
        required=True)

    parser.add_argument(
        '--filter',
        help='Filter for HTTP, or DNS',
        choices=['http', 'dns'],
        dest='packet_filter',
        required=True)

    parser.add_argument(
        '--domain_name',
        help='Filter traffic to a specific DNS or IP address',
        default=None,
        required=True)

    args = parser.parse_args()


    #if args.packet_filter == 'dns' and not args.domain_name:
    #    print('[!] You must provice the domain name for DNS extraction')
    #    exit()

    packets = pyshark.FileCapture(args.pcap, display_filter=args.packet_filter)

    if args.packet_filter == 'http':
        extract_http(packets, args.domain_name)
    elif args.packet_filter == 'dns':
        extract_dns(packets, args.domain_name)
