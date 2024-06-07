#!/usr/bin/python3
import base64
import json 
import os 
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from argparse import ArgumentParser
from pathlib import Path
        
# Function to decrypt data using AES ECB mode
def aes_ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    return unpad(decrypted, AES.block_size)
    
''' This is the xor function, it for decrypt data 
 custom_payload
 custom_payload
 custom_sni
 custom_host 
 custom_host  
'''
def xor(plaintext):
    key = "**rVg7EkL~c2`D[aNn"
    keyLength = len(key)
    cipherAscii = ""
    for i in range(0, len(plaintext)):
        j = i % keyLength
        xor_value = ord(plaintext[i]) ^ ord(key[j])
        cipherAscii += chr(xor_value)
    return cipherAscii

def ordenar_claves(diccionario):
    etiquetas = {
        'connection_mode': 'Connection Mode',
        'server_port': 'Server Port',
        'custom_payload': 'Custom Payload',
        'custom_host': 'Custom Host',
        'custom_sni': 'Custom SNI',
        'custom_resolver': 'Custom Resolver',
        'use_realm_host': 'Use Realm Host',
        'preserve_sni': 'Preserve SNI',
        'use_tcp_payload': 'Use TCP Payload',
        'realm_host': 'Realm Host',
        'override_primary_host': 'Override Primary Host',
        'primary_host': 'Primary Host',
        'dns_primary_host': 'DNS Primary Host',
        'aotNode':'Server Node Country',
        'primary_node':' Primary Node',
        'base_tunnel': 'Base Tunnel',
        'isv5': 'Is V5',
        'descriptionv5': 'Note', 
        'password_value': 'Password Value', 
        'id_lock_value': 'ID lock value' 
        #'hwid_enabled': 'Hwid Enabled', 
        #'expire_date': 'Expire Date'
    }
    return {etiquetas.get(key, key): value for key, value in diccionario.items()}

def adding_filter(text):
    text = text.replace(',', '\n')
    return text 

try:
    print("┌───────────────\n├ ‌ha Tunnel (hat)\n├ ‌𝐆𝐑𝐎𝐔𝐏: https://t.me/mkldec\n├───────────────")
    
    parser = ArgumentParser()
    parser.add_argument('file', help='file to decrypt')
    args = parser.parse_args()

    # Read and decode the file
    file_content = Path(args.file).read_bytes()
    decoded_content = base64.b64decode(file_content)

    # Decrypt the content
    key = base64.b64decode('zbNkuNCGSLivpEuep3BcNA==')
    decrypted_text = aes_ecb_decrypt(decoded_content, key)

    # Decode the decrypted text with 'utf-8' 
    final_text = decrypted_text.decode('utf-8')
 
    # Extract specific part from the decoded text
    profile_info = final_text.split("\"profilev5\"")[1].split("\"descriptionv5\"")[0]
    profile_info = profile_info.replace(":{","{").replace("},","}").replace("\\n","")
  
    encoding = 'utf-8' # Define encoding 
  
    # Here is where the fun 😂 start with encrypt data 
    u = json.loads(profile_info)
    u['connection_mode'] = xor(str(base64.b64decode(u.get("connection_mode")), encoding))
    u['custom_payload'] = xor(str(base64.b64decode(u.get("custom_payload")), encoding))
    u['custom_sni'] = xor(str(base64.b64decode(u.get("custom_sni")), encoding))
    u['custom_host'] = xor(str(base64.b64decode(u.get("custom_host")), encoding))

    # Order the dictionary keys
    u = ordenar_claves(u)
    
    # Apply filter
    for key, value in u.items():
        if isinstance(value, str):
            u[key] = adding_filter(value)

    # Print the result as a list
    for key, value in u.items():
        print(f"│[☬] {key}: {value}") 

    print("├───────────────\n│:‌𝐊𝟏\n├ ‌𝐁𝐎𝐓: @mujta1nsshbot\n├ ‌𝐆𝐑𝐎𝐔𝐏: https://t.me/mkldec\n└───────────────")
    
except Exception as e:
    print("Error:", e)