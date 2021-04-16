#!/usr/bin/env python3 

import sys
import codecs

import colorama
from colorama import Fore

colorama.init(autoreset=True)

APPKEY = "3216d1509884b533248541792b877f98"
NETKEY = "f7a2a44f8e8a8029064f173ddc1e2b00"
DEVKEY = "37c612c4a2d337cb7b98355531b3617f"

import meshsec as ms

"""
NOTE:
Network Nonce Structure:
Nonce   = 0x00      (1 byte)
CTL/TTL = 0x        (1 byte)
SEQ     =           (3 bytes)
SRC     =           (2 bytes)
Pad     = 0x0000    (2 bytes)
IVIndex =           (4 bytes)

NetMIC  = 4 (if CTL = 0)       -> Access Message
       or 8 bytes (if CTL = 1) -> Control Message
"""

if __name__ == "__main__":
    n = b"" 
    enc = b""
    nonce = b""
    netMIC = b"" # usually its Access message, so lenght is 4 (and CTL = 0)
    if len(sys.argv) > 3:
        n = sys.argv[1]
        # c6ebdc7d08351c2f8d3b848db0 9bba032615d4
        enc = sys.argv[2]
        nonce = sys.argv[3]
        if len(sys.argv) > 4: 
            netMIC = sys.argv[4]
    else:
        print("Usage:")
        print("<NetKey> <EncDST || EncTransportPDU> <NetworkNonce>")
        print("<NetKey> <EncDST || EncTransportPDU> <NetworkNonce> <NetMIC>")
        sys.exit()
    a = ms.gen_k2(n)
    if (a):
        print(Fore.GREEN + f"EncyptionKey: {codecs.encode(a[0], 'hex')}")
        print(Fore.GREEN + f"PrivacyKey: {codecs.encode(a[1], 'hex')}")
        print(Fore.GREEN + f"NID: {a[2]}")
        b = ms.gen_k3(n)
        encTest = b"\xb5\xe5\xbf\xda\xcb\xaf\x6c\xb7\xfb\x6b\xff\x87\x1f"
        networkNonce = b'\x00\x80\x00\x00\x01\x12\x01\x00\x00\x12\x34\x56\x78'
        dc = ms.aes_ccm_decrypt(a[0], codecs.decode(nonce, 'hex'), codecs.decode(enc, 'hex'), 0)
        print(codecs.encode(dc[0], 'hex'), codecs.encode(dc[1], 'hex'))
        if (len(netMIC) > 2):
            ms.defuscate(dc[0], dc[1], codecs.decode(netMIC, 'hex'), b"\x00\x00\x00\x00", a[1])
