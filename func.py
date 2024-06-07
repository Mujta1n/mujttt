import zlib
import base64
import json
import hashlib
from pathlib import Path
from urllib.parse import parse_qsl, quote_plus, unquote_plus
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Cipher import Blowfish
import subprocess
import os
import re
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode

class AESCrypt:
    AES_MODE = AES.MODE_CBC
    AES_BLOCK_SIZE = 16
    HASH_ALGORITHM = 'SHA-256'
    IV = b'\x00' * AES_BLOCK_SIZE

    @staticmethod
    def generate_key(password):
        hashed_key = hashlib.sha256(password.encode()).digest()
        return hashed_key

    @staticmethod
    def pad_message(message):
        padding_length = AESCrypt.AES_BLOCK_SIZE - (len(message) % AESCrypt.AES_BLOCK_SIZE)
        padded_message = message + bytes([padding_length] * padding_length)
        return padded_message

    @staticmethod
    def unpad_message(padded_message):
        padding_length = padded_message[-1]
        return padded_message[:-padding_length]

    @staticmethod
    def decrypt(password, encoded_ciphertext):
        key = AESCrypt.generate_key(password)
        cipher = AES.new(key, AES.MODE_CBC, AESCrypt.IV)
        ciphertext = base64.b64decode(encoded_ciphertext)
        decrypted_message = cipher.decrypt(ciphertext)
        unpadded_message = AESCrypt.unpad_message(decrypted_message)
        return unpadded_message.decode()

def decrypt(ciphertext, password):
    if len(ciphertext) == 0:
        return ""
    v = str_to_longs(base64.b64decode(ciphertext))
    k = str_to_longs(password[:16].encode('utf-8'))
    n = len(v)
    z = v[n - 1]
    y = v[0]
    delta = -0x658C6C4C
    mx = 0
    q = 6 + 52 // n
    sum = q * delta

    while sum != 0:
        e = (sum >> 2) & 3
        for p in range(n - 1, -1, -1):
            z = v[p - 1] if p > 0 else v[n - 1]
            mx = (z >> 5 ^ (y << 2)) + (y >> 3 ^ (z << 4)) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z)
            y = (v[p] - mx) & 0xffffffff
            v[p] = y
        sum -= delta

    plaintext = longs_to_str(v)
    plaintext = plaintext.rstrip('\x00')

    return plaintext

def str_to_longs(data):
    l = []
    for i in range(0, len(data), 4):
        a = data[i] if i < len(data) else 0
        b = (data[i + 1] << 8) if i + 1 < len(data) else 0
        c = (data[i + 2] << 16) if i + 2 < len(data) else 0
        d = (data[i + 3] << 24) if i + 3 < len(data) else 0
        l.append(a + b + c + d)
    return l

def longs_to_str(l):
    s = ''
    for num in l:
        s += chr(num & 0xFF)
        s += chr((num >> 8) & 0xFF)
        s += chr((num >> 16) & 0xFF)
        s += chr((num >> 24) & 0xFF)
    return s
            