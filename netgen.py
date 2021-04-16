#!/usr/bin/env python3 

import sys
import codecs
from CryptoPlus.Cipher import python_AES
from Crypto.Cipher import AES

import colorama
from colorama import Fore

colorama.init(autoreset=True)

APPKEY = "3216d1509884b533248541792b877f98"
NETKEY = "f7a2a44f8e8a8029064f173ddc1e2b00"
DEVKEY = "37c612c4a2d337cb7b98355531b3617f"

# NetKey 14BAA72000D72457D562BB314758E747

def aes_cmac(k, m):
    """
    @return MAC
    """
    print(f"CMAC \nk: {k}\nm: {m}")
    c = python_AES.new(k, python_AES.MODE_CMAC)
    return c.encrypt(m)

def aes_ccm(k, n, m, a):
    """ 
    @param k is 128-bit key 
    @param n is 104-bit nonce 
    @param m is the variable lenght data to be encrypted
             and authenticated (plaintext) 
    @param a is the variable lenght data to be authenticated (additional data) 

    @return list of ciphertext is the variable length data after it has been encrypted
            and mic (Message Authenctication Code) is the message integrity check value of m and a. 
    """
    nonce = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    #nonce = b"\x00\x00\x00\x00\x00\x00\x00"
    c = AES.new(k, AES.MODE_CCM, nonce=nonce, assoc_len=a)
    ret = c.encrypt(n)
    print(Fore.GREEN + f"test: {codecs.encode(ret, 'hex')}")
    return []



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


def gen_k3(N):
    """! The k3 function 
    
    Used to generate a public value of 64 bits derived from private key

    @param N    NetKey

    @return NetworkID
    """
    salt = gen_salt("smk3")
    T = aes_cmac(salt, codecs.decode(N, 'hex'))
    print(Fore.MAGENTA + f"T: {codecs.encode(T, 'hex')}")
    k3 = aes_cmac(T, "id64".encode() + b"\x01")
    print(Fore.MAGENTA + f"k3: {codecs.encode(k3, 'hex')}")
    #print(int.from_bytes(k3, byteorder='big'))
    #NetworkID = hex((int(codecs.encode(k3, 'hex'), 16))%2**263)
    NetworkID = hex((int.from_bytes(k3,  byteorder="big"))%2**64)
    print(Fore.MAGENTA + f"NetworkID: {NetworkID}")
    #print(Fore.MAGENTA + f"NetworkID: {codecs.encode(NetworkID, 'hex')}")
    return NetworkID

"""! Notes:
    Network Nonce: 0x00 for Network layer, 0x01 for App layer
    DST: (16 bits) Destination address 
    TransportPDU: (8-128 bits) Transport Protocol Data Unit 
"""

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
        b = gen_k3(n)
        # test = DST + TransportPDU
        #test = b"1952b25bf885edae4dc4359715a395689eb151"
        test = b"fffd034b50057e400000010000"
        aes_ccm(b'0953fa93e7caac9638f58820220a398e',test, b'\x00',0)
        #test = codecs.decode(test, 'hex')
        #test2 = aes_cmac_decrypt(a[0], test)
        #print(Fore.GREEN + f"PrivacyKey: {codecs.encode(test2, 'hex')}")

