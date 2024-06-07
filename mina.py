#Mr CODING  ZXX 321
#INDONESIA SNIFFER 🇮🇩
#================
import os
import sys
import base64
import hashlib
from Crypto.Cipher import AES
import json

def decode_enzo_101(enzo_101):
    key_bytes = bytes(int(octal_byte, 8) for octal_byte in enzo_101.split())
    return key_bytes

    
class AESCrypt:
    AES_MODE = AES.MODE_CBC
    AES_BLOCK_SIZE = 16
    HASH_ALGORITHM = 'SHA-256'
    IV = b'\x00' * AES_BLOCK_SIZE

    @staticmethod
    def generate_key(password):
        hashed_key = hashlib.sha256(password).digest()
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



enzo_101 = "101 156 144 162 157 151 144 126"
password = decode_enzo_101(enzo_101)


if len(sys.argv) != 2:
    sys.exit(1)

file_path = sys.argv[1]


try:
    with open(file_path, 'r') as file:
        encrypted_data = file.read()

    decrypted_text = AESCrypt.decrypt(password, encrypted_data)
    cleaned_data = decrypted_text.replace('\n', '').replace('\r', '').replace('\t', '')
    # Load JSON data
    json_data = json.loads(cleaned_data)

    # Extract keys and values
    filtered_data = {f"├ • 🔵 {key}": f" : {value}" for key, value in json_data.items()}

    # Format and print the result
    formatted_result = "\n".join([f"{key.strip(',')}{value}" for key, value in filtered_data.items()])
    formatted_result = "╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓{mina} \n├◉────────────────◉\n│◉ ‌𝐁𝐎𝐓: @mujta1nsshbot\n╰◉────────────────◉\n" + formatted_result + "\n╭◉────────────────◉\n│◉ ‌𝐂𝐇𝐀𝐍𝐍𝐄𝐋: https://t.me/mkldec1\n╰◉────────────────◉"

    print(formatted_result)
except Exception as e:
    print("Error:", e)