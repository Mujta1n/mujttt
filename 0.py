import telebot
import sys,os
import base64
import json
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
import requests
import pathlib

Token = '6809426604:AAHBrJisyxhiR1S9C_AftNxf9WMCfMvzIdA'
bot = telebot.TeleBot(Token)
@bot.message_handler(commands=['start', 'help'])
def handle_start_help(message):
    user=message.from_user.username
    if user:
        bot.reply_to(message, '')

    else:
        bot.reply_to(message, '. '+str(message.from_user.first_name)+' '+ str(message.from_user.last_name))
@bot.message_handler(content_types=['document'])
def handle_docs_audio(message):

   # bot.reply_to(message, 'be patient till decryption complete ')
    file_info = bot.get_file(message.document.file_id)
    file_ext = pathlib.Path(file_info.file_path).suffix

    file = requests.get('https://api.telegram.org/file/bot{0}/{1}'.format(Token, file_info.file_path))
    downloaded_file = bot.download_file(file_info.file_path)
    with open('new_file'+file_ext, 'wb') as new_file:
        new_file.write(downloaded_file)

    keys = {
    ".nm":"X25ldHN5bmFfbmV0bW9kXw==",
    ".hat": "zbNkuNCGSLivpEuep3BcNA==",
    '.tut': b'fubvx788b46v',
    '.tmt': b'$$$@mfube11!!_$$))012b4u',   #✓
    '.temt': b'fubvx788B4mev',
    '.tsn': b'thirdy1996624',   #✓
    '.etun': b'dyv35224nossas!!',
    '.pxp': b'bKps&92&',
    '.ace': b'Ed',   #✓
    '.tsd': b'waiting',
    '.ost': b'gggggg',
    '.wt': b'fuMnrztkzbQ',   #✓
    '.tnl': b'A^ST^f6ASG6AS5asd',   #✓
    '.fks': b'fubvx788b46v',
    '.gv': b'Ed',
    '.act': b'fubvx788b46v',   #✓
    '.cnet': b'cnt',   #✓
    '.gibs': b'Ed',   #✓
    '.dvd': b'dyv35224nossas!!',   #✓
    '.ftp': b'Version6',   #✓ #old
    '.fthp': b'furious0982',   #✓ #new
    '.jph': b'fubvx788b46v',   #✓
    '.xsks': b'c7-YOcjyk1k',
    '.ht': b'error',
    '.ssi': b'Jicv',
    '.kt': b'kt',
    '.dvs': b'mtscrypt',
    '.fnet': b'62756C6F6B',   #✓
    '.mc': b'fubvx788b46v',   #✓
    '.hub': b'trfre699g79r',   #✓
    '.grd': b'fubvx788b46v',
    '.hta': b'Ed',   #✓
    '.eug': b'fubvx788b46v',   #✓
    '.sds': b'rdovx202b46v',
    '.htp': b'chanika acid, gimsara htpcag!!',
    '.bbb': b'xcode788b46z',
    '.ccc': b'fubgf777gf6',
    '.ddd': b'fubvx788b46vcatsn',
    '.eee': b'dyv35182!',
    '.cln': b'fubvx788b46v',   #✓
    '.cyh': b'dyv35182!',   #✓
    '.agn': b'cigfhfghdf665557',
    '.Tcv2': b'fubvx788b46v',
    '.NT': b'0x0',
    '.ai': b'Ed',
    'cks': b'2$dOxdIb6hUpzb*Y@B0Nj!T!E2A6DOLlwQQhs4RO6QpuZVfjGx',
    '.sksrv': b'y$I@no5#lKuR7ZH#eAgORu6QnAF*vP0^JOTyB1ZQ&*w^RqpGkY',
    '.garuda': b'fubvx788b46v',
    '.tpp': b'Ed',
    '.sky': b'fubux788b46v',
    '.skyp': b'\u02bb\u02bd\u1d35\u02c6\u02c8\u02c6\u2071\u02cb.milQP\u05d9\u02d1\ufe73\u2071\uff9e\u02c6\u1d4e\u02bd\u02bc\u02bc\u02c8\u05d9\ufe76\uff9e\u05d9\u1d54\uff9e\u02ceswtIX',
    '.max': b'Ed',
    '.pb': b'Cw1G6s0K8fJVKZmhSLZLw3L1R3ncNJ2e',
    '.hqp': b'Ed',
    '.hq': b'Ed',
    '.ziv': b'fubvx788b46v',
    '.tnl': b'B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg',
    '.bdi': b'@technore 2022',
    '.NT': b'0x0',
    '.pcx': b'cinbdf665$4',
    'phc': b'667562767837383862343676', 
    }

    def remove_shits(shits):
        clean_text ="".join(chr(ord(i)) for i in shits if (ord(i)<=125 and ord(i) >=32 ))
        return clean_text

    def aes_gcm_decrypt(file_path,key):
        try:
            file_contents = open(file_path, 'rb').read()
            split_base64_contents = file_contents.split(b'.')
            split_contents = list(map(base64.b64decode, split_base64_contents))
            #file_ext = Path(file_path.name).suffix

            decryption_key = PBKDF2(key, split_contents[0], hmac_hash_module=SHA256)

            cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
            decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])

            return decrypted_contents
        except Exception as e:
            #print(str(e))
            error = f"decryption failed due to :{str(e)}"
            return error.encode()

    def aes_ecb_decrypt(ciphertext, key):
        key = base64.b64decode(key)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = cipher.decrypt(ciphertext)

        return decrypted_data
    def do_nothing():
        return

    def xor(data):

        key = '**rVg7EkL~c2`D[aNn'
        keyLength = len(key)
        cipherAscii = ''

        for i in range(len(data)):
            j = i % keyLength
            xor_value = ord(data[i]) ^ ord(key[j])
            cipherAscii += chr(xor_value)

        return cipherAscii


    def output(content):
        final_result = open('decryptedtext.txt','w')
        teaser = "╭◉────────────────◉\n├ ‌𝐆𝐑𝐎𝐔𝐏: https://t.me/mkldec\n◉ ‌𝐂𝐇𝐀𝐍𝐍𝐄𝐋: https://t.me/mkldec1\n│◉ ‌𝐁𝐎𝐓 : @mujta1nsshbot\n├───────────────"
        final_result.write(teaser +"\n")
        if file_ext == '.hat':
            content = content["profilev5"]
        if type(content) == dict:

            for key,value in content.items():


                final_result.write(f'│[☬]{key} : {value}\n')
        else:
            content = content.replace("<entry key=","[").replace("</entry>","").replace("/>","] : ") .replace(">","] : ")

            final_result.write(content)
        #final_result.write(teaser +"\n")
        return final_result.close()

    if file_ext in ( '.ssh','.tmt', '.temt', '.tsn', '.etun', '.pxp',
    '.ace', '.tsd', '.ost', '.wt', '.tnl', '.fks', '.gv', '.act', '.cnet', '.gibs', '.dvd', '.ftp',
    '.fthp', '.jph', '.xsks', '.ht', '.ssi', '.kt', '.dvs', '.fnet', '.mc', '.hub', '.grd', '.hta',
    '.eug', '.sds', '.htp', '.bbb', '.ccc', '.ddd', '.eee', '.cln', '.cyh', '.agn', '.Tcv2', '.NT',
    '.ai', '.cks', '.sksrv', '.garuda', '.tpp', '.sky', '.skyp', '.max', '.ziv', '.tnl', '.pb', '.hqp',
    '.hq', '.bdi', '.NT','.nm','.pcx','.ssh','.hat'):
        file = 'new_file'+file_ext
        encrypted_file = open(file, mode='rb')

        encrypted_contents = base64.b64decode(encrypted_file.read()  )
        if file_ext == '.tnl' or file_ext == ".ziv":
                key = keys[file_ext]
                output(aes_gcm_decrypt(file,key).decode())


        if file_ext == '.hat':
            key = keys[file_ext]

            decrypted_text = aes_ecb_decrypt(encrypted_contents, key)
            #print(decrypted_text)
            data_to_json = json.loads(remove_shits(decrypted_text.decode('utf-8')))#.split("}}")[0]+"}}")
            for key, value in data_to_json.items():
                if type(value)== dict:
                   for k,v in value.items():
                        try :
                            data_to_xor = base64.b64decode(v).decode()
                            xored_data = xor(data_to_xor)
                            data_to_json[key][k] = xored_data
                        except:
                            data_to_json[key][k] = v
                else:
                    try:
                        data_to_xor = base64.b64decode(value).decode()
                        xored_data = xor(data_to_xor)

                        data_to_json[key] = xored_data

                    except:
                        data_to_json[key] = value

            output(data_to_json)
        if file_ext == '.nm':
            key = keys[file_ext]
            decrypted_text =json.loads(remove_shits(aes_ecb_decrypt(encrypted_contents,key).decode()))
            output(decrypted_text)
        else:
            do_nothing()
        try:
           decryptedfile = open('decryptedtext.txt','r')
           data = decryptedfile.read()
           bot.reply_to(message,data)
        #decryptedfile.close()
           bot.forward_message(-1001685717676, message.chat.id, message.message_id)
       
           bot.send_message(-1001685717676,data)
           
        except Exception as e:
                decryptedfile = open('decryptedtext.txt','r')
                bot.send_document(message.chat.id,decryptedfile)
                print(e)
    #else:
        #bot.send_message(message.chat.id,f"{file_ext} extension not supported yet")

bot.infinity_polling()