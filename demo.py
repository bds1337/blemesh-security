#!/usr/bin/env python3 

import sys
import codecs

APPKEY = "3216d1509884b533248541792b877f98"
NETKEY = "f7a2a44f8e8a8029064f173ddc1e2b00"
DEVKEY = "37c612c4a2d337cb7b98355531b3617f"

import meshsec as ms

"""
NOTE:
Network Nonce Structure:
Nonce   = 0x00      (1 byte)  (0x01 for App, 0x02 for Device, 0x03 for Proxy)
CTL/TTL = 0x        (1 byte)
SEQ     =           (3 bytes)
SRC     =           (2 bytes)
Pad     = 0x0000    (2 bytes)
IVIndex =           (4 bytes)

NetMIC  = 4 (if CTL = 0)       -> Access Message
       or 8 bytes (if CTL = 1) -> Control Message
"""


def net_decrypt(encryptionKey, networkNonce, DST, transportPDU):
    """! 
    """



if __name__ == "__main__":
    n = b"" 
    enc = b""
    nonce = b""
    netMIC = b"" # usually its Access message, so lenght is 4 (and CTL = 0)
    ivindex = b""
    if len(sys.argv) > 3:
        n = sys.argv[1]
        nonce = sys.argv[2]
        # NOTE: wireshark output (netMIC should be 4 or 8 bytes)
        # c6ebdc7d08351c2f8d3b84     8db09bba032615d4
        # 5397ffbfaaf8969e1deb46     9b81ea9c399cc976
        # d91d56eb05                 e5f64efa4aa59865 
        # mesh doc: message 1 sample data
        # b5e5bfdacbaf6cb7fb6bff871f 035444ce83a670df
        enc = sys.argv[3]
        obfuscated = sys.argv[4]
    else:
        print("Usage:")
        print("<NetKey> <NetworkNonce> <Encrypted data and NetMIC> <obfuscatedData>")
        sys.exit()
    netMIC = enc[-16:]
    enc = enc[:-16]
    ivindex = nonce[-8:]
    print("netMIC " + netMIC)
    print("enc " + enc)
    print("ivindex " + ivindex)
    a = ms.gen_k2(n)
    if not a:
        sys.exit()
    enc_key = a[0]
    priv_key = a[1]
    nid = a[2]
    print(f"EncyptionKey: {codecs.encode(enc_key, 'hex')}")
    print(f"PrivacyKey: {codecs.encode(priv_key, 'hex')}")
    print(f"NID: {nid}")
    netid = ms.gen_k3(n)
    print(f"NetworkID: {netid}")
    if len(netMIC) < 2:
        sys.exit()
    b = ms.defuscate(codecs.decode(enc, 'hex'), codecs.decode(netMIC, 'hex'), codecs.decode(ivindex, 'hex'), priv_key, codecs.decode(obfuscated, "hex"))
    print(f"CTL+TTL: {codecs.encode(b[0], 'hex')}")
    print(f"SEQ: {codecs.encode(b[1], 'hex')}")
    print(f"SRC: {codecs.encode(b[2], 'hex')}")

    dc = ms.aes_ccm_decrypt(enc_key, codecs.decode(nonce, 'hex'), codecs.decode(enc, 'hex'), 0)
    print(f"DST: {codecs.encode(dc[0], 'hex')}")
    print(f"TransportPDU: {codecs.encode(dc[1], 'hex')}")
