#!/usr/bin/env python3 

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


"""! Notes:
    Network Nonce: 0x00 for Network layer, 0x01 for App layer
    example b"00800000011201000012345678"
    DST: (16 bits) Destination address 
    TransportPDU: (8-128 bits) Transport Protocol Data Unit 
"""
def aes_ccm_encypt(k, n, m, a):
    """ 
    @param k is 128-bit key 
    @param n is 104-bit nonce 
    @param m is the variable lenght data to be encrypted
             and authenticated (plaintext) 
    @param a is the variable lenght data to be authenticated (additional data) 

    @return EncDST + EncTransportPDU
    """
    c = AES.new(k, AES.MODE_CCM, nonce=n)
    ret = c.encrypt(m)
    print(Fore.GREEN + f"EncDST + EncTransportPDU: {codecs.encode(ret, 'hex')}")
    return ret


def aes_ccm_decrypt(k, n, m, a):
    """ 
    @param k is 128-bit key 
    @param n is 104-bit nonce 
    @param m is the variable lenght data to be encrypted
             and authenticated (plaintext) 
    @param a is the variable lenght data to be authenticated (additional data) 
    """
    c = AES.new(k, AES.MODE_CCM, nonce=n)
    ret = c.decrypt(m)
    print(Fore.GREEN + f"DST + TransportPDU: {codecs.encode(ret, 'hex')}")
    return [ret[:2], ret[2:]]


def e_decrypt(key, plaintext):
    """! Security function e 

    Security function e generates 128-bit encryptedData from 
    a 128-bit key and 128-bit plaintextData using the 
    AES-128-bit block cypher

    """
    c = AES.new(key, AES.MODE_ECB)
    ret = c.decrypt(plaintext)
    return ret


def defuscate(encDST, encTransPDU, netMIC, ivindex, priv_key):
    """(CTL, TTL, SEQ, SRC)
    """
    priv_random = (encDST + encTransPDU + netMIC)[0:6]
    priv_plaintext = b"\x00\x00\x00\x00\x00" + ivindex + priv_random
    print(priv_plaintext)
    print(codecs.encode(priv_plaintext, 'hex'))
    print(f"key: {codecs.encode(priv_key, 'hex')}")
    ret = e_decrypt(priv_key, priv_plaintext)
    print(ret)
    print(codecs.encode(ret, 'hex'))


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
    NetworkID = hex((int.from_bytes(k3,  byteorder="big"))%2**64)
    print(Fore.MAGENTA + f"NetworkID: {NetworkID}")
    return NetworkID


def gen_salt(msg):
    """! s1 SALT generation function 
    
    @param msg   string 

    @return output of the salt generation 
    """
    key = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ret = aes_cmac(key, msg.encode())
    print(ret)
    print(Fore.CYAN + f"SALT: {codecs.encode(ret, 'hex')}")
    return ret
