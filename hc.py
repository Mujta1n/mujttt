from argparse import ArgumentParser
from pathlib import Path
import base64 
from base64 import b64decode
from Crypto.Hash import SHA1
from Crypto.Cipher import AES

xorList = ['。', '〃', '〄', '々', '〆', '〇', '〈', '〉', '《', '》', '「', '」', '『', '』', '【', '】', '〒', '〓', '〔', '〕']

def decrypt(contents, key):
    decryption_key = SHA1.new(data=bytes(key, 'utf-8')).digest()[:16]
    return AES.new(decryption_key, AES.MODE_ECB).decrypt(contents)

def deobfuscate(contents):
    encrypted_string = contents.decode('utf-8')
    deobfuscated_contents = b''
    
    for index in range(len(encrypted_string)):
        deobfuscated_contents += bytes([ord(encrypted_string[index]) ^ ord(xorList[index % len(xorList)])])
    
    return b64decode(deobfuscated_contents)

parser = ArgumentParser()
parser.add_argument('file', help='file to decrypt')
args = parser.parse_args()
encoded_text = Path(args.file).read_text()
content = base64.b64decode(encoded_text.encode('utf-8'))
print(content) 

# Assuming 'decryption_key' needs to be obtained from user input
decryption_keys = ['ApkCusT0m_K3y','d3V-3Pr0-T34M','d3V-3Pr0-T3@M','d3V:3Pr0@T3@M','d3V:3Pr0:T3@M','d3V:3Pr0-T3@M','d3V^3Pr0-T3@M','d3V(3Pr0-T3@M','d3V(3Pr0)T3@M','d3V-3Pr0_T3@M','d3V-ePr0_T3@M','d3V-ePr0_t3@M','d3v-ePr0_t3@M','d3v-ePr0-t34M','d3v_ePr0_t34M','d3v_ePr0_t3aM','d3v_ePr0_t3am','d3v_ePr0_bl4th','no1_ePr0_bl4th','keY_secReaT_hc_reborn','keY_secReaT_hc_reborn1','keY_secReaT_hc_reborn2','keY_secReaT_hc_reborn3','keY_secReaT_hc_reborn4','keY_secReaT_hc_reborn5','keY_secReaT_hc_reborn6','keY_secReaT_hc','keY_secReaT_hc1','keY_secReaT_hc2','keY_secReaT_hc_2','hc_reborn7','hc_reborn8','hc_reborn9','hc_reborn10','keY_secReaT_te4','keY_secReaT_te4Z','keY_secReaT_te4Z9','keY_secReaT_te4Z10','keY_secReaT_te4Z11','keY_secReaT_te54','s3cr3T_k3Y_ePro','s3cr3T_k3Y_ePr0_3NcRypT','s3cr3T_k3y_ePr0_3NcRypT','keY_secReaT_e','keY_secReaT_ePr0','keY_secReaT_ePr1','keY_secReaT_ePr2','keY_secReaT_ePr3','keY_secReaT_ePr4','hc_reborn_1','hc_reborn_2','hc_reborn_3','hc_reborn_4','hc_reborn_5','hc_reborn_6','hc_reborn_7','hc_reborn_8','hc_reborn_9','hc_reborn_10','hc_reborn___7','hc_reborn_tester','hc_reborn_tester_1','hc_reborn_tester_2','hc_reborn_tester_3','hc_reborn_tester_4','hc_reborn_tester_5','hc_reborn_tester_6','hc_reborn_tester_7','hc_reborn_tester_8','hc_reborn_tester_9','hc_reborn_for_you','hc_easypro_7','hc35_easypro_8','hc37_easypro@2020','hc38_345yPr0@2020','HTTP_Custom_v233_hc_easypro_7','HTTP_Custom_v233_hc35_easypro_8']  # Add your keys here

for key in decryption_keys:
    try:
        decoded_text = deobfuscate(content)
        decoded_text = decrypt(decoded_text, key)
        print(decoded_text.decode('utf-8'))
    except Exception as e:
        print(f"Decryption with key '{key}' failed. Error: {e}")
