#pylint:disable=E0602
import telebot
from argparse import ArgumentParser
import os
import base64
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import unpad
from base64 import b64decode
import re
from Crypto.Cipher import AES
import json

tok="6809426604:AAHBrJisyxhiR1S9C_AftNxf9WMCfMvzIdA"
bot = telebot.TeleBot(tok)

FILES_DIR = "received_files"
RESULTS_DIR = "results"

if not os.path.exists(FILES_DIR):
    os.makedirs(FILES_DIR)
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)
 
@bot.message_handler(commands=['start']) 
def welcome(message) :
    bot.send_message(message.chat.id, " Telegram: https://t.me/mkldec\n ======================\nSend config to decrypt\n\n\n🔻.tnl - OpenTunnel - ✅\n🔻.nm - > NetMod Syna - ✅\n🔻.ssh - > SSH injector - ✅\n🔻.sks - > SocksHttp - ✅\n🔻.rez - > Rez Tunnel - ✅\n🔻.pcx - > Binke Tunnel ✅\n🔻.stk - > STARK VPN - ✅\n🔻.pb - > PB injector - ✅\n🔻.ziv - > Ziv vpn - ✅\n🔻.tmt - > TunnelMate - ✅\n🔻.vhd - > V2ray Hybrid - ✅\n🔻.fnet - > - ✅\n🔻.nt - > - ✅\n🔻.sds - > - ✅\n🔻.gibs - > - ✅\n🔻.hqp - > - ✅\n🔻.hq - > - ✅\n🔻.nti - > - ✅\n🔻.hta - > - ✅\n🔻.poiman - > - ✅\n🔻.ehil- http Injector  liet - > - ✅\n🔻.AIO TUNNEL [.XSCKS] - > - ✅\n\n🔺howdy, -> Howdy VPN\n\n🔺nm-vmess,ssh,... - > Net-Mod v1.12.1\n\n🔺ar-vmess,ssh,... AR-Mod v1.12.0\n§─────────────────◉\n\n│[☬]  Group:https://t.me/mkldec\n\n │[☬] Channel : @mkldec1")

@bot.message_handler(content_types=['document']) 
def post(message):
    name = message.document.file_name 
    id = message.document.file_id
    file_info = bot.get_file(id)
    downloaded_file = bot.download_file(file_info.file_path)
    
    with open(name, "wb") as file:
        file.write(downloaded_file)
    
    if name.endswith(".ssh"):
        result = sshinjector(name)
        save_and_send_result(name, result, message)
    elif name.endswith(".nm"):
        with open(name, 'rb') as file:
            encrypted_text = file.read()
        result_message = process_nm_content(encrypted_text, name)
        save_and_send_result(name, result_message, message)
    else:
        os.system('python BOOS1.py "' + name + '" > test.txt') 
        with open("test.txt", "r") as f:
            jh = f.read()
        os.system('node hat.js "' + name + '" > test.txt') 
        with open("test.txt", "r") as f:
            jm = f.read()
        os.system('node stk.js "' + name + '" > test.txt') 
        with open("test.txt", "r") as f:
            mm = f.read()
        os.system('python phc.py "' + name + '" > test.txt') 
        with open("test.txt", "r") as f:
            vv = f.read()
        os.system('python xscks.py "' + name + '" > test.txt') 
        with open("test.txt", "r") as f:
            gg = f.read()
        os.system('python mina.py "' + name + '" > test.txt') 
        with open("test.txt", "r") as f:
            ss = f.read()
        os.system('python hat.py "' + name + '" > test.txt') 
        with open("test.txt", "r") as f:
            zz = f.read()    
        result = jh + "\n" + jm + "\n" + mm + "\n" + vv + "\n" + gg + "\n" + ss + "\n" + zz
        save_and_send_result(name, result, message)

def save_and_send_result(name, result, message):
    with open(os.path.join(RESULTS_DIR, name.split('.')[0] + ".txt"), "w") as result_file:
        result_file.write(result)
        
    if name.endswith((".ssh", ".nm",  ".stk", ".tnl", ".ehil", ".sks", ".ziv", ".pb", ".pcx", ".rez", ".npv2", ".phc", ".py", ".tmt", ".xscks,", ".hat", ".mina", ".hc")):

       bot.send_document(message.chat.id, open(os.path.join(RESULTS_DIR, name.split('.')[0] + ".txt"), "rb"), 
                      caption= (f"• ┅┅━━ 𖣫 ━━┅┅ •\n├ • @{message.from_user.username}\n├ • ID: {message.from_user.id}\n• ┅┅━━ 𖣫 ━━┅┅ •")) 

    bot.reply_to(message, result)

def sshinjector(file, key=b'263386285977449155626236830061505221752'):
    try:
        text = b64decode(open(file, 'rb').read())
        iv = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        plaintext = cipher.decrypt(text)
        decrypt_text = unpad(plaintext, Blowfish.block_size).decode()

        pattern = r'<entry key="(.*)">(.*)</entry>'
        match = re.findall(pattern, decrypt_text)
        
        decrypted_message ='Telegram: https://t.me/mkldec\n=====================================\n'
        for i in match:
            key, value = i
            decrypted_message += f"├ • 💠  {key}: {value}\n"
        
        return decrypted_message
    except Exception as e:
        return f"Error: {str(e)}"
    
def remove_random_characters(text):
    replacements = {
        ',': '\n',
        '"': '',
        '{': '',
        '}': '',
        'ps:': 'ProfileName: ',
        '\\': '', 
        ':': ' : '
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text

def add_marker_to_lines(text, marker="\n│[☬] "):
    lines = text.split('\n')
    marked_lines = [f'{marker} {line}' for line in lines]
    marked_text = '\n'.join(marked_lines)
    return marked_text

# Función para manejar mensajes que contienen configuraciones cifradas
@bot.message_handler(func=lambda message: 'nm-vmess://' in message.text or 'nm-dns://' in message.text or 'nm-vless://' in message.text or 'nm-trojan://' in message.text or 'nm-ssr://' in message.text)
def decrypted_config(message):
    # Verificar si el mensaje proviene de un chat privado
    if message.chat.type == 'private':
        bot.reply_to(message, "\n╭◉────────────────◉\n│Lo siento, solo puedes utilizarme\n│en estos grupos:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉\n\n╭◉────────────────◉\n│I'm sorry, you can only use me\n│in these groups:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉")
        return

    # Si no es un chat privado, continuar con el procesamiento de la configuración cifrada
    encrypted_text_base64 = message.text.strip()
    cle = 'X25ldHN5bmFfbmV0bW9kXw==' 
    pattern = r'^nm-(dns|vless|vmess|trojan|ssr)://'
    cfg_type = re.match(pattern, encrypted_text_base64)
    try:
        if cfg_type is not None:
            encryption_key = base64.b64decode(cle)

            config_encrypt = encrypted_text_base64[len(cfg_type[0]):]
            encrypted_text = base64.b64decode(config_encrypt)

            cipher = AES.new(encryption_key, AES.MODE_ECB)

            decrypt_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)

            decrypt_text = decrypt_text.decode('utf-8')
            cd = '\n╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n├◉────────────────◉\n│◉ 𝘿𝙚𝙫𝙚𝙡𝙤𝙥𝙚𝙧 : @mujta1n\n╰◉────────────────◉' + \
                 add_marker_to_lines(decrypt_text) + '\n╭◉────────────────◉\n│◉ 𝘾𝙝𝙖𝙣𝙣𝙚𝙡 : https://t.me/mkldec1\n│◉ 𝘽𝙤𝙩 : @mujta1nsshbot\n╰◉────────────────◉'
            bot.reply_to(message, cd) 
    except Exception as e:
        bot.reply_to(message, f"‼️Oops! An error occurred:\n{e}‼️")
    
    #FUNTION NM
def decrypt_aes_ecb_128(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip()

def convert_value(value):
    if isinstance(value, str):
        return value.replace("\r\n", "\\r\\n").replace("\n", "\\n")
    else:
        return value

def flatten_dict(dictionary, parent_key='', separator=': '):
    items = []
    for key, value in dictionary.items():
        new_key = f"{parent_key} {key}".strip()
        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, separator=separator).items())
        else:
            items.append((new_key, convert_value(value)))
    return dict(items)

def format_nested_keys(data, indent=0):
    formatted_text = ""
    for key, value in data.items():
        if isinstance(value, dict):
            formatted_text += "" * indent + f"│[☬] {key} Values\n"
            formatted_text += format_nested_keys(value, indent + 1)
        elif isinstance(value, list):
            formatted_text += "" * indent + f"│[☬] {key} Values\n"
            for item in value:
                if isinstance(item, dict):
                    formatted_text += format_nested_keys(item, indent + 1)
                elif item != 0 and item != "" and item not in [True, False]:
                    formatted_text += "" * (indent + 1) + f"{convert_value(item)}\n"
        elif value != 0 and value != "" and value not in [True, False]:
            formatted_text += "" * indent + f"│[☬] {key}: {convert_value(value)}\n"
    return formatted_text

def process_nm_extension(file_path, file_extension, file_name):
    
    try:
        with open(file_path, 'rb') as file:
            encrypted_text = file.read()
            result_message = process_nm_content(encrypted_text, file_name)
        return result_message
    except Exception as e:
        print(f"Error al procesar archivo .nm: {str(e)}")
        return "Error al procesar archivo .nm."

def process_nm_content(encrypted_content, filename, print_messages=True):
    result = ""

    result += "┌───────────────\n│𝗞𝟭 𝗕𝗢𝗧 (.nm)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://t.me/mujta1n\n├───────────────\n"

    base64_key = "X25ldHN5bmFfbmV0bW9kXw=="
    key = base64.b64decode(base64_key)

    ciphertext = base64.b64decode(encrypted_content)

    decrypted_text = decrypt_aes_ecb_128(ciphertext, key)

    formatted_text = decrypted_text.decode('utf-8')
    start_index = formatted_text.find("{")
    end_index = formatted_text.rfind("}")

    if start_index == -1 or end_index == -1 or end_index < start_index:
        if print_messages:
            result += "Error: Could not find a valid JSON format."
        return result

    json_text = formatted_text[start_index:end_index + 1]

    try:
        data = json.loads(json_text)
        flattened_dict = flatten_dict(data)
        formatted_text = format_nested_keys(flattened_dict)
    except json.JSONDecodeError as e:
        if print_messages:
            result += f"Error loading JSON: {e}"
        return result

    result += formatted_text
    result += "├───────────────\n│[☬] 𝗚𝗥𝗢𝗨𝗣 : @mkldec \n│[☬] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : https://t.me/mkldec1\n└───────────────\n"

    return result
    
Px_inicio = "┌───────────────\n│ 𝗞𝟭 𝗕𝗢𝗧 (.hat)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : Telegram: https://t.me/muja1n\n├───────────────\n"
Px_fin = "\n├───────────────\n│[☬] 𝗚𝗥𝗢𝗨𝗣 : @mkldec \n│[☬] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : https://t.me/mkldec1\n└───────────────\n"

#Función hat túnel 

def adding_filter(text):
    text = text.replace('{', '').replace('}', '').replace('[', '').replace(']', '').replace('(', '').replace(')', '').replace('"', '').replace('_', ' ').replace(',', '\n')
    filtered_lines = [line for line in text.splitlines() if 'description:' not in line.lower() and 'profile:' not in line.lower()]
    return '\n'.join(filtered_lines)

def process_hat_extension(file_path):
    hat = base64.b64decode(open(file_path, 'rb').read())
    cle = base64.b64decode('zbNkuNCGSLivpEuep3BcNA==')
    cipher = AES.new(cle, AES.MODE_ECB)

    decrypted_text = unpad(cipher.decrypt(hat), AES.block_size)
    final_text = decrypted_text.decode('utf-8')
    final_text = adding_filter(final_text)

    full_message = Px_inicio
    decoded_lines = [f'\n[☬] {line} ' for line in final_text.splitlines()]
    full_message += '' + '\n'.join(decoded_lines)
    full_message += Px_fin

    return full_message

      
def cbc_iv(data):
    data = data.replace("\n", "")
    cipher = AES.new(b'poiuytrewqas+=~|', AES.MODE_CBC, b'r4tgv3b2zcmdW6ZZ')
    decrypted_data = cipher.decrypt(base64.b64decode(data))
    return decrypted_data.decode()

# Función para manejar mensajes que contienen configuraciones cifradas
@bot.message_handler(func=lambda message: 'howdy://' in message.text)
def handle_message(message):
    # Verificar si el mensaje proviene de un chat privado
    if message.chat.type == 'private':
        bot.reply_to(message, "╭◉────────────────◉\n│Lo siento, solo puedes utilizarme\n│en estos grupos:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉\n\n╭◉────────────────◉\n│I'm sorry, you can only use me\n│in these groups:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉")
        return

    # Si no es un chat privado, continuar con el procesamiento del mensaje
    chat_id = message.chat.id
    text = message.text
    message_id = message.message_id

    print(f"Received message: {text} from chat_id: {chat_id}")

    try:
        decode = text.split('://')[1]
        data = base64.b64decode(decode)
        json_data = json.loads(data)
        username = json_data['username']
        password = json_data['password']
        port = json_data['port']
        server = json_data['server']
        dataa = cbc_iv(server)
        sni = json_data['sni']
        sni2 = cbc_iv(sni)
        type = json_data['type']
        linkserver = f"\n[☬] Username: {username}\n◉─────────────────◉\n[☬] Password: {password}\n◉─────────────────◉\n[☬] Server: {dataa}\n◉─────────────────◉\n[☬] Port: {port}\n◉─────────────────◉\n[☬] Type: {type}"
        bot.send_message(chat_id, f"<strong>\n╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n├◉────────────────◉\n│◉ 𝘿𝙚𝙫𝙚𝙡𝙤𝙥𝙚𝙧 : @mujta1nsshbot\n│◉ 𝘾𝙝𝙖𝙣𝙣𝙚𝙡 : https://t.me/mkldec1\n│◉ 𝘽𝙤𝙩 : @mujta1nsshbot\n╰◉────────────────◉\n </strong>", parse_mode="html", reply_to_message_id=message_id)
        print(f"Sent decrypted message to chat_id: {chat_id}")
    except Exception as e:
        bot.send_message(chat_id, f"Sorry, if there was an error decoding, could I send it again?\n\nLo siento, hubo un error al decodificar,¿ podría enviarlo otra vez? ", reply_to_message_id=message_id)
        print(f"Error occurred: {str(e)}")
          
@bot.message_handler(func=lambda message: True) 
def wel(message) :
   if message.forward_from == None :
      if message.reply_to_message == None:
         bot.forward_message("", message.chat.id,message.id)
      else :
         id = message.json["from"]["id"]
         
         bot.send_message(id,message.text)
         
         
   else :
       pass
   
   
   
  
bot.infinity_polling() 

 