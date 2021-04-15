#!/usr/bin/env python3 

import sys
import codecs
from CryptoPlus.Cipher import python_AES

import colorama
from colorama import Fore

colorama.init(autoreset=True)

APPKEY = "3216d1509884b533248541792b877f98"
NETKEY = "f7a2a44f8e8a8029064f173ddc1e2b00"
DEVKEY = "37c612c4a2d337cb7b98355531b3617f"

# NetKey 14BAA72000D72457D562BB314758E747

def aes_cmac(k, m):
    print(f"CMAC \nk: {k}\nm: {m}")
    c = python_AES.new(k,python_AES.MODE_CMAC)
    return c.encrypt(m)

def gen_k2(N):
    """! The k2 function (master) 
    
    Used to convert the master security credentials 
    NetKey as N and generate the master security material
    NID, EncryptionKey and PrivacyKey

    @param N    NetKey

    @return List of EncryptionKey, PrivacyKey and NID
    """
    P = b"\x00"
    salt = gen_salt("smk2")
    T = aes_cmac(salt, codecs.decode(N, 'hex'))
    print(Fore.MAGENTA + f"T: {codecs.encode(T, 'hex')}")
    T0 = b""
    T1 = aes_cmac(T, T0 + P + b"\x01")
    print(Fore.MAGENTA + f"T1: {codecs.encode(T1, 'hex')}")
    T2 = aes_cmac(T, T1 + P + b"\x02")
    print(Fore.MAGENTA + f"T2: {codecs.encode(T2, 'hex')}")
    T3 = aes_cmac(T, T2 + P + b"\x03")
    print(Fore.MAGENTA + f"T3: {codecs.encode(T3, 'hex')}")
    nid = hex((int(codecs.encode(T1 + T2 + T3, 'hex'), 16))%2**263)
    return [T2, T3, nid]

def gen_salt(msg):
    """! s1 SALT generation function 
    
    @param msg   string 

    @return output of the salt generation 
    """
    key = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ret = aes_cmac(key, msg.encode())
    print(Fore.CYAN + f"SALT: {codecs.encode(ret, 'hex')}")
    return ret

if __name__ == "__main__":
    n = NETKEY
    #n = b'14BAA72000D72457D562BB314758E747'
    #n = b"7dd7364cd842ad18c17c2b820c84c3d6" 
    #n = b"14BAA72000D72457D562BB314758E747"
    if len(sys.argv) > 1:
        n = sys.argv[1]
    a = gen_k2(n)
    if (a):
        print(Fore.GREEN + f"EncyptionKey: {codecs.encode(a[0], 'hex')}")
        print(Fore.GREEN + f"PrivacyKey: {codecs.encode(a[1], 'hex')}")
        print(Fore.GREEN + f"NID: {a[2]}")

