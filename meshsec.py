#!/usr/bin/env python3 

import codecs
from CryptoPlus.Cipher import python_AES
from Crypto.Cipher import AES

import byteutils
from logger import blog

def aes_cmac(k, m):
    """
    @return MAC
    """
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
    blog(f"EncDST + EncTransportPDU: {codecs.encode(ret, 'hex')}", "SUCC")
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
    return [ret[:2], ret[2:]]


def e(key, plaintext):
    """! Security function e 

    Security function e generates 128-bit encryptedData from 
    a 128-bit key and 128-bit plaintextData using the 
    AES-128-bit block cypher

    """
    c = python_AES.new(key)
    ret = c.encrypt(plaintext)
    return ret


def defuscate(encDSTPDU, netMIC, ivindex, privacyKey, obfuscatedData):
    """
    @param encDSTPDU    EncDST + EncTransportPDU
    
    @return List of CTL+TTL, SEQ, SRC
    """
    privacyRandom = (encDSTPDU + netMIC)[:7]
    blog(f"privacyRandom: {codecs.encode(privacyRandom, 'hex')}", "PROC")
    privacyPlaintext = b"\x00\x00\x00\x00\x00" + ivindex + privacyRandom
    blog(f"privacyPlaintext: {codecs.encode(privacyPlaintext, 'hex')}", "PROC")
    pecb = e(privacyKey, privacyPlaintext)[:6]
    blog(f"PECB: {codecs.encode(pecb, 'hex')}", "PROC")
    ret = byteutils.bxor(obfuscatedData, pecb)
    blog(f"(CTL || TTL || SEQ || SRC): {codecs.encode(ret, 'hex')}", 'SUCC')
    return [ret[0:1], ret[1:4], ret[4:]]


def gen_salt(msg):
    """! s1 SALT generation function 
    
    @param msg   string 

    @return output of the salt generation 
    """
    key = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ret = aes_cmac(key, msg.encode())
    blog(f"SALT: {codecs.encode(ret, 'hex')}", "SALT")
    return ret


def gen_k1(N, salt, P):
    """! The k1 function 
    
    The k1 function is used to convert some input key material into some
    output key material that uses two inputs, known as salt and info

    @param N    NetKey
    @param SALT 
    @param P    0 or more bytes

    @return  
    """
    T = aes_cmac(salt, N)
    ret = aes_cmac(T, P)
    return ret


def gen_k2(N, P=b'\x00'):
    """! The k2 function (master) 
    
    Used to convert the master security credentials 
    NetKey as N and generate the master security material
    NID, EncryptionKey and PrivacyKey

    @param N    NetKey
    @param P    0 or more bytes

    @return List of EncryptionKey, PrivacyKey and NID
    """
    salt = gen_salt("smk2")
    T = aes_cmac(salt, codecs.decode(N, 'hex'))
    T0 = b""
    T1 = aes_cmac(T, T0 + P + b"\x01")
    blog(f"T1: {codecs.encode(T1, 'hex')}", "PROC")
    T2 = aes_cmac(T, T1 + P + b"\x02")
    blog(f"T2: {codecs.encode(T2, 'hex')}", "PROC")
    T3 = aes_cmac(T, T2 + P + b"\x03")
    blog(f"T3: {codecs.encode(T3, 'hex')}", "PROC")
    # 0x680953fa93e7caac9638f58820220a398e8b84eedec100067d670971dd2aa700cf
    #nid = (hex(((int(codecs.encode(T1 + T2 + T3, 'hex'), 16))%2**263))).encode()
    nid = (hex(((int(codecs.encode(T1 + T2 + T3, 'hex'), 16))%2**263))[2:4]).encode()
    return [T2, T3, nid]


def gen_k3(N):
    """! The k3 function 
    
    Used to generate a public value of 64 bits derived from private key

    @param N    NetKey

    @return NetworkID
    """
    salt = gen_salt("smk3")
    T = aes_cmac(salt, codecs.decode(N, 'hex'))
    k3 = aes_cmac(T, "id64".encode() + b"\x01")
    NetworkID = hex((int.from_bytes(k3, byteorder="big")%2**64))[2:].encode()
    blog(f"NetworkID: {NetworkID}", "SUCC")
    return NetworkID


def gen_k4(N):
    """! The k4 function 
    
    Used to generate an AID from an application key 

    @param N    Appkey 

    @return Application keys AID 
    """
    salt = gen_salt("smk4")
    T = aes_cmac(salt, N)
    k4 = aes_cmac(T, "id6".encode() + b"\x01")
    k4 = hex(((int.from_bytes(k4, byteorder="big")%2**6)))[2:].encode()
    blog(f"k4: {k4}", "SUCC")
    return k4 

