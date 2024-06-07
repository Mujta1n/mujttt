#!/usr/bin/env python3
import random
import telebot
from telebot import types
from io import BytesIO
from sys import stdin, stdout, stderr
from argparse import ArgumentParser
from pathlib import Path
from base64 import b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad 
from telebot.types import Message
from telebot.types import CallbackQuery
from datetime import datetime
from Crypto.Cipher import AES
from pathlib import Path
import base64
import time
from threading import Timer
from time import sleep 
from datetime import timedelta
from datetime import datetime, timedelta
from typing import Optional
import os
import time
import zlib
import base64
import subprocess
import json
import requests
import csv 
import tempfile
import threading
import sys
import re
from Crypto.Cipher import Blowfish
import html
import traceback
from telebot import TeleBot, types
from telebot.types import CallbackQuery, Message
from telegram.ext import CallbackQueryHandler
from telegram import CallbackQuery, Update
from func import *

ALLOWED_EXTENSIONS = [
    '.howdy', '.tut','.ssh','.tmt', '.sks', '.temt', '.tsn', '.etun', '.pxp',
    '.ace', '.tsd', '.ost', '.wt', '.tnl', '.fks', '.gv', '.act', '.cnet', '.gibs', '.dvd', '.ftp',
    '.fthp', '.jph', '.xsks', '.ht', '.ssi', '.kt', '.dvs', '.fnet', '.mc', '.hub', '.grd', '.hta',
    '.eug', '.sds', '.htp', '.bbb', '.ccc', '.ddd', '.eee', '.cln', '.cyh', '.Tcv2', '.NT',
    '.ai', '.cks', '.sksrv', '.garuda', '.tpp', '.sky', '.skyp', '.max', '.ziv', '.tnl', '.pb', '.hqp',
    '.hq', '.bdi', '.NT','.nm','.rez','sks','.pcx','.ssh','.vmess','.phc','.ePro','.vpnlite','.hat','.cly',
    '.agn','.xtp','.mina','.xscks','.ost','.vpc','.Fn','.jvi','.jvc','.aro','.mij', '.sut',
] # Agrega las extensiones permitidas aquí

# Diccionario para mapear extensiones a scripts
extension_to_script = {
    "hat": "hat.js",
    "ziv": "ziv.py",
    "pb": "pb.py",
    "pcx": "pcx.py", 
    "ipt": "ipt.py", 
    "mij": "mij.py", 
    "ost": "ost.py",
    "sut": "sut.py", 
    "aro": "aro.py",
    "func": "func.py", 
    "cloudy": "cloudy.py",
    "fnnetwork": "fnnetwork.py", 
    "maya": "maya.py",
    "sksrv": "sksrv.py", 
    "xtproy": "xtproy.py", 
    "mtl": "mtl.py", 
    "mrc": "mrc.py", 
    "xscks": "xscks.py", 
    "phc": "phc.py", 
    "agn": "agn.py",
    "mina": "mina.py",
    "vpc": "vpc.py",
    "fn": "fn.py", 
    "clay": "clay.py",
    "tnl": "tnl.js",
    "vpnlite": "vpnlite.py", 
    "jvi": "jvi.py", 
    "jvc": "jvc.py", 
    "tnl": "tnl.py", 
    "sks": "sks.js",
    "v2i": "v2i.py", 
    "rez": "rez.js",
    "stk": "stk.js"
}
mij_password = "Ed"
extension_python = ['mina', 'xscks', 'vpnlite', 'phc', 'maya', 'sksrv', 'xtproy', 'ost', 'mtl', 'mrc', 'mij', 'ipt', 'aro', 'sut', 'fnnetwork', 'cloudy', 'func', 'agn', 'vpc', 'fn', 'clay', 'jvi', 'jvc', 'v2i', 'tnl', 'pcx', 'ziv', 'pb']

DEFAULT_FILE_EXTENSION = '.tmt'

# passwords to derive the key from
PASSWORDS = {
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
    #'.ziv': b'fubvx788b46v',
    #'.tnl': b'B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg',
    #'.pb': b'Cw1G6s0K8fJVKZmhSLZLw3L1R3ncNJ2e',
    '.hqp': b'Ed',
    '.hq': b'Ed',
    '.bdi': b'@technore 2022',
    '.NT': b'0x0',
    #'.pcx': b'cinbdf665$4',
}

TOKEN = '6773121743:AAGlPnaivdYdpXF6HN4NpnTojHqUhcjWNTM'
bot = telebot.TeleBot(TOKEN)
FILES_DIR = 'files'
activity_log = {}
headerss = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'ar,en-US;q=0.9,en;q=0.8',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'DNT': '1',
    'Host': 'api.telegram.org',
    'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36'
}

dectext = "Decrypting the file... ⚙️"

accde = "•‼️Access Denied‼️•\n==============================\n 🔌 Only work in the following Group ✓\n\n • @mkldec | • Channel : @mkldec1\n\n⫹⫺ 2024 𝖠𝗅𝗅 𝗋𝗂𝗀𝗁𝗍 𝗋𝖾𝗌𝖾𝗋𝗏𝖾𝖽 | @mujta1nsshbot, mujta1n ®\n============================== "
    
@bot.message_handler(commands=['limpiar'])    
def limpiar_carpeta(message):
    try:
        for archivo in os.listdir(FILES_DIR):
            ruta_archivo = os.path.join(FILES_DIR, archivo)
            if os.path.isfile(ruta_archivo):
                os.remove(ruta_archivo)
        bot.send_message(message.chat.id, "Archivos eliminados correctamente.")
    except Exception as e:
        bot.send_message(message.chat.id, f"Error al limpiar la carpeta: {e}")
        
# FUNCIONES ÚTILES
# ----------------------------------------------------------------------------------------------------------------------------------

# Función para decodificar la parte Base64 de un mensaje que contiene "vmess://"
@bot.message_handler(func=lambda message: 'vmess://' in message.text)
def decodificar_base64(message):
    # Obtener la parte de la cadena después de 'vmess://'
    cadena_a_decodificar = message.text.split('vmess://', 1)[1]

    try:
        # Decodificar la parte relevante en Base64
        cadena_decodificada = base64.b64decode(cadena_a_decodificar).decode('utf-8')

        # Enviar el mensaje decodificado
        
        bot.reply_to(message, f'┌───────────────\n│[☬] open vpn (vmess://)\n│[☬] bot: @mujta1nsshbot\n├───────────────\n' + \
                 cadena_decodificada + '\n│[☬] bot: @mujta1nsshbot \n│[☬] Channel : https://t.me/mkldec1\n└───────────────\n')

    except Exception as e:
        bot.reply_to(message, f'Error al decodificar la cadena: {e}')

# Función para decodificar la parte Base64 de un mensaje que contiene "ar-ssh://"
@bot.message_handler(func=lambda message: 'ar-ssh://' in message.text)
def decodificar_base64(message):
    # Obtener la parte de la cadena después de 'vmess://'
    cadena_a_decodificar = message.text.split('ar-', 1)[1]

    try:

        # Enviar el mensaje decodificado
        bot.reply_to(message, f'Copy Text For Artunnel: \n\n`{cadena_a_decodificar}`', parse_mode="MarkDown")
                 
    except Exception as e:
        bot.reply_to(message, f'Error al decodificar la cadena: {e}')
                
                
def cbc_iv(data):
    data = data.replace("\n", "")
    cipher = AES.new(b'poiuytrewqas+=~|', AES.MODE_CBC, b'r4tgv3b2zcmdW6ZZ')
    decrypted_data = cipher.decrypt(base64.b64decode(data))
    return decrypted_data.decode()

@bot.message_handler(func=lambda message: 'howdy://' in message.text)
def handle_message(message):
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
        linkserver = f"├ • 🔥  Username: {username}\n├ • 🔥  Password: {password}\n├ • 🔥  Server: {dataa}\n├ • 🔥  Port: {port}\n├ • 🔥  Type: {type}"
        bot.send_message(chat_id, f"<strong>\n‌‌𝐆𝐑𝐎𝐔𝐏: https://t.me/mkldec\n======================\n{linkserver}\n======================\n ‌𝐁𝐎𝐓 : @mujta1nsshbot </strong>", parse_mode="html", reply_to_message_id=message_id)
        print(f"Sent decrypted message to chat_id: {chat_id}")
    except Exception as e:
        bot.send_message(chat_id, f"Oops, there was an error, bro: {str(e)}", reply_to_message_id=message_id)
        print(f"Error occurred: {str(e)}")

    
# Obtener usuarios premium desde el archivo premium.txt
def get_premium_users():
    with open("premium.txt", "r") as file:
        premium_users = file.read().splitlines()
    return premium_users
    
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

def add_marker_to_lines(text, marker="\n│[☬]"):
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
            cd = '\n╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓(nm vmess) \n├◉────────────────◉\n│◉ ‌bot: @mujta1nsshbot\n╰◉────────────────◉' + \
                 add_marker_to_lines(decrypt_text) + '\n╭◉────────────────◉\n│◉ ‌: Channel : https://t.me/mkldec1\n│◉ bot:@mujta1nsshbot \n╰◉────────────────◉'
            bot.reply_to(message, cd) 
    except Exception as e:
        bot.reply_to(message, f"‼️Oops! An error occurred:\n{e}‼️")
        
# Función para manejar mensajes que contienen configuraciones cifradas
@bot.message_handler(func=lambda message: 'zivpn://' in message.text)
def decrypted_config(message):
    # Función para manejar mensajes en grupos privados
    user_ids = str(message.from_user.id)
    group_id = str(message.chat.id)  # ID del grupo
    if user_ids not in get_premium_users() and group_id not in get_premium_users():
        bot.reply_to(message, accde)
        return
    try:
        encoded_ciphertext = message.text.replace('zivpn://', '')
        ziv_password = "dTlxdXdscWs4ODFkaTFneGpuMWF1YnkzZmFmdm9tOXQ="
        password = base64.b64decode(ziv_password).decode('utf-8')
    # Assuming AES decryption here, replace with your decryption logic
        decrypted_text = AESCrypt.decrypt(password, encoded_ciphertext)
        #decrypted_text = decrypted_text.decode('utf-8')
        cd = f'┌───────────────\n├◉ vmess (zivpn://)\n├◉ Channel : https://t.me/mkldec1 \n├───────────────\n' + \
                 add_marker_to_lines(decrypted_text) + '\n├◉ 𝗗𝗲𝗰𝗿𝘆𝗽𝘁𝗲𝗱𝗕𝘆: @mujta1nsshbot \n├◉ 𝗚𝗥𝗢𝗨𝗣 : @mkldec \n└───────────────\n '
        bot.reply_to(message, cd) 
    except Exception as e:
        bot.reply_to(message, f"‼️Oops! An error occurred:\n{e}‼️")
KEY_LABELS = {
    "sshServer": "SSH Server",
    "sshPort": "SSH Port",
    "sshUser": "SSH User",
    "sshPass": "SSH Password",
    "sshPortLocal": "Local Port",
    "proxyPayload": "Proxy Payload",
    "sslHost": "SSL Host",
    "proxyRemotePort": "Remote Proxy",
    "proxyRemote": "Remote Proxy Port",
    "proxyuser": "Proxy User",
    "proxypass": "Proxy Password",
    "sslProtocol": "SSL Protocol",
    "sniHost": "SNI Host",
    "cUUID": "UUID",
    "dnspu": "PublicKey",
    "dnsnameserver": "DNS Name Server",
    "proxy.payload": "proxy.payload",
    #ziv
    "sshAllinOne": "SSH Field",
    "nameServer": "NameServer",
    "publickey": "PublicKey",
    "udpserver": "UDP Server",
    "dnsResolver": "Primary DNS",
    "udpResolver": "UDPGW",
    #pcx
    "udpauth": "udpauth",
    "up_mbps": "Upload Mbps",
    "down_mbps": "Download Mbps",
    "udpwindow": "QUIC Windows",
    "udpauth": "Authentication",
    "udpobfs": "Obfuscate",
    "sshPortaLocal": "Local Port",
    #Otros
    "v2rayprotocol": "v2rayprotocol",
    "file.appVersionCode": "file.appVersionCode",
    "injectionmode": "injectionmode",
    "udpForward": "udpForward",
    "v2raytlsinsecure": "v2raytlsinsecure",
    "wakelock": "wakelock",
    "speeddown": "speeddown",
    "blockroot": "blockroot",
    "file.protect": "file.protect",
    "speedup": "speedup",
    "tunnelType": "tunnelType",
    "appVersion": "appVersion",
    "ConfigValidityDate": "ConfigValidityDate",
    "isHTTPDirect": "isHTTPDirect",
    "isPayloadAfterTLS": "isPayloadAfterTLS",
}

# Función para verificar si el usuario está en el archivo premium.txt
def check_premium(user_id):
    with open('premium.txt', 'r') as file:
        premium_users = file.readlines()
        premium_users = [user.strip() for user in premium_users]
        if str(user_id) in premium_users:
            return "PREMIUM"
        else:
            return "FREE"
            
@bot.message_handler(commands=['files'])
def get(message: telebot.types.Message):
    bot.send_message(message.chat.id, f"Please Send File To Decrypt 🧑🏻‍💻\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n{ALLOWED_EXTENSIONS}\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    
@bot.message_handler(commands=['start'])
def welcome(message):
    # Obtener el nombre del usuario
    first_name = message.from_user.first_name
    # Generar URL para el perfil del usuario
    profile_url = f"https://t.me/{message.from_user.username}"
    welcome_text = f"""Welcome <a href='{profile_url}'>{first_name}</a>! ♻️\n- Your ID: <code>{message.from_user.id}</code>"""
    markup = telebot.types.InlineKeyboardMarkup()
    # Botones en línea
    markup.row(
        telebot.types.InlineKeyboardButton(text="My Account", callback_data="PERFIL"),
    )
    markup.row(
        telebot.types.InlineKeyboardButton(text="Channel", url="https://t.me/mkldec1"),
        telebot.types.InlineKeyboardButton(text="Group", url="https://t.me/mkldec")
    )
    markup.row(
        telebot.types.InlineKeyboardButton(text="Owner", url="https://t.me/BOOSTOOLS")
    )
    bot.send_message(message.chat.id, welcome_text, reply_markup=markup, reply_to_message_id=message.message_id, parse_mode='HTML')

@bot.callback_query_handler(func=lambda call: call.data == 'PERFIL')
def perfil_callback(call):
    # Obtén la información del usuario
    user_id = call.from_user.id
    Rank = check_premium(user_id)
    username = call.from_user.username
    language_code = call.from_user.language_code
    first_name = call.from_user.first_name
    
    # Crea el mensaje de perfil con la información obtenida
    perfil_message = f"""
    🜲 𝗔𝗥𝗘𝗔 𝗗𝗘𝗟 𝗣𝗘𝗥𝗙𝗜𝗟 
━ • ━━━━━━━━━━━━ • ━
➜ 𝗨𝗦𝗨𝗔𝗥𝗜𝗢 @{username}
➜ 𝗜𝗗: <code>{user_id}</code>
➜ 𝗥𝗔𝗡𝗚𝗢: {Rank}
━ • ━━━━━━━━━━━━ • ━"""
    
    try:
        # Edita el mensaje original con la nueva información de perfil y la foto de perfil
        bot.edit_message_caption(chat_id=call.message.chat.id, message_id=call.message.message_id, caption=perfil_message, parse_mode='html')
        
    except telebot.apihelper.ApiTelegramException as e:
        # Maneja el error si el mensaje no existe o no se puede editar
        print(f"No se pudo editar el mensaje: {e}")
 
            
# Función para manejar mensajes entrantes
@bot.message_handler(commands=['id'])
def get_admin_id(message):
    chat_id = message.chat.id
    bot.reply_to(message, f"ID : {chat_id}")
    
# Función para autorizar el ID
def autorizar_id(id):
    with open('premium.txt', 'r') as file:
        existing_ids = file.read().splitlines()
        if str(id) in existing_ids:
            return False
        else:
            with open('premium.txt', 'a') as file:
                file.write(str(id) + '\n')
            return True

# Manejar el comando /autorize
@bot.message_handler(commands=['autorize'])
def autorize_command(message):
    if message.from_user.id == 1030659113:
        if len(message.text.split()) == 2:
            auchat = message.text.split()[1]
            id_to_authorize = message.text.split()[1]
            bot.send_message(auchat, "ID AUTORIZADO YA PUEDE USAR EL BOT")
            if autorizar_id(id_to_authorize):
                bot.reply_to(message, "ID autorizado con éxito.")
            else:
                bot.reply_to(message, "Este ID ya está autorizado.")
        else:
            bot.reply_to(message, "El comando debe ser en el formato /autorize ID.")
    else:
        bot.reply_to(message, "Este comando solo puede ser ejecutado por el Dueño.")

# Función para eliminar el ID
def autorizar_del(id):
    with open('premium.txt', 'r') as file:
        existing_ids = file.read().splitlines()
        if str(id) in existing_ids:
            existing_ids.remove(str(id))  # Eliminar el ID si ya existe
            with open('premium.txt', 'w') as file:
                for line in existing_ids:
                    file.write(line + '\n')
            return False
        else:
            return True

# Manejar el comando "/delchat"
@bot.message_handler(commands=['delchat'])
def handle_delete_id(message):
    chat_id = message.chat.id
    user_id = message.from_user.id
    command_args = message.text.split()
    if len(command_args) == 2:
        id_to_delete = command_args[1]
        if not autorizar_del(id_to_delete):
            bot.send_message(chat_id, "ID ha sido eliminado correctamente.")
        else:
            bot.send_message(chat_id, "ID no está en la lista.")
    else:
        bot.send_message(chat_id, "Por favor, proporcione un ID válido después de /delchat.")

# Función para procesar un archivo recibido
def process_received_file(message, name, extension):
    script_name = extension_to_script.get(extension)
    if script_name is None:
        return
    user_ids = str(message.from_user.id)
    group_id = str(message.chat.id)  # ID del grupo
    if user_ids not in get_premium_users() and group_id not in get_premium_users():
        bot.reply_to(message, accde)
        return
        
    chat_id = message.chat.id
    file_info = bot.get_file(message.document.file_id)
    downloaded_file = bot.download_file(file_info.file_path)

    received_file_path = os.path.join(FILES_DIR, name)

    with open(received_file_path, "wb") as received_file:
        received_file.write(downloaded_file)

    if script_name:
        if extension in extension_python:  # Ejecutar códigos Python
            python_command = f'python3 {script_name} "{received_file_path}"'
            result = subprocess.run(python_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:  # Para otras extensiones, ejecuta los scripts con Node.js
            js_command = f'node {script_name} "{received_file_path}"'
            result = subprocess.run(js_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        activity_log.setdefault(message.chat.id, []).append({
            "user": message.from_user.username,
            "file_name": name,
            "result_stdout": result.stdout,
            "result_stderr": result.stderr
        })

        response_message = None

        if result.stdout.strip():
            message_limit = 4096
            message_parts = [result.stdout[i:i+message_limit] for i in range(0, len(result.stdout), message_limit)]
            for part in message_parts:
                # Enviar mensajes tanto en grupos como en el chat del bot, respondiendo al mensaje original
                bot.send_message(message.chat.id, part, reply_to_message_id=message.message_id)
        else:
            response_message = "An error occurred while processing the file."

        # Enviar mensaje de respuesta en caso de error
        if response_message:
            bot.send_message(message.chat.id, response_message, reply_to_message_id=message.message_id)           

#─────────────── FILE .SSH ───────────────   

Px_inicio = "\n┌───────────────\n│[☬] open vpn (.ssh)\n│[☬] bot: @mujta1nsshbot\n├───────────────"
Px_fin = "\n│[☬] Channel : https://t.me/mkldec1 \n└───────────────"


def aes_ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(data)
        return unpad(decrypted, AES.block_size)
    except ValueError:
        return b"Incorrect padding"

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
    decoded_lines = [f'│[☬] {line} ' for line in final_text.splitlines()]
    full_message += '' + '\n'.join(decoded_lines)
    full_message += Px_fin

    return full_message

                
#─────────────── FILE .SSH ───────────────          
def ssh_injector(file, file_extension):
    key = b'263386285977449155626236830061505221752'
    text = b64decode(open(file, 'rb').read())
    iv = b'\x00\x01\x02\x03\x04\x05\x06\x07'
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = cipher.decrypt(text)
    decrypt_text = unpad(plaintext, Blowfish.block_size).decode()  # remove pkcs#7

    result_message = ''

    for i in re.findall(r'<entry key="(.*)">(.*)</entry>', decrypt_text):
        key, value = i
        result_message += f"\n│[☬] {key} : {value}\n├───────────────"

    principio_result_str = f"┌───────────────\n│[☬] open vpn (.ssh)\n│[☬] bot: @mujta1nsshbot\n├───────────────"
    final_result_str = "\n│[☬] Channel : https://t.me/mkldec1 \n└───────────────"

    # Texto final después de los datos obtenidos
    result_str = principio_result_str + result_message + final_result_str

    return result_str

#─────────────── FILE VARIABLES ───────────────       

def decrypt_document(file_path, file_extension, file_name):
    encrypted_contents = open(file_path, 'r').read()
    file_ext = Path(file_path).suffix
    
    if file_ext not in PASSWORDS:
        print(f'Unknown file extension, defaulting to {DEFAULT_FILE_EXTENSION}')
        file_ext = DEFAULT_FILE_EXTENSION
    
    split_base64_contents = encrypted_contents.split('.')
    split_contents = list(map(b64decode, split_base64_contents))
   
    decryption_key = PBKDF2(PASSWORDS[file_ext], split_contents[0], hmac_hash_module=SHA256)
    
    cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
    decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])
    
    try:
        return decrypted_contents.decode('utf-8')
    except UnicodeDecodeError:
        return decrypted_contents.decode('latin-1')

def print_result(config, file_extension, file_name):
    result_str = f"┌───────────────\n│[☬] open vpn ({file_extension})\n│[☬] bot: @mujta1nsshbot\n├───────────────"

    configdict = {}
    for line in config.split('\n'):
        if line.startswith('<entry'):
            line = line.replace('<entry key="', '')
            line = line.replace('</entry', '')
            line = line.split('">')
            if len(line) > 1:
                key = line[0]
                value = line[1].strip(">")
                configdict[key] = value
            else:
                key = line[0].strip('"/>')
                value = None
                configdict[key] = value

    for key, value in configdict.items():
        if value and value != "0" and value != "*******":
            result_str += f"\n│[☬] {key} : {value}\n├───────────────"

    result_str += "\n│[☬] bot: @mujta1nsshbot \n│[☬] Channel : https://t.me/mkldec1\n└───────────────\n "

    return result_str

                          
#─────────────── FILE .nm ───────────────       
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
    # Lógica específica para archivos con extensión .nm
    try:
        with open(file_path, 'rb') as file:
            encrypted_text = file.read()
            result_message = process_nm_content(encrypted_text, file_name)
        return result_message
    except Exception as e:
        print(f"Error al procesar archivo .nm: {str(e)}")
        return "Error al procesar archivo .nm."

def decrypt_mij_file(file_path, password):
    try:
        # Memastikan bahwa input adalah objek byte
        with open(file_path, 'rb') as file:
            encrypted_mij = file.read()

        # Memisahkan konten terenkripsi menjadi bagian-bagian yang sesuai
        split_base64_contents = encrypted_mij.split(b'.')
        split_contents = list(map(base64.b64decode, split_base64_contents))
        
        # Membangun kunci dekripsi menggunakan PBKDF2
        decryption_key = PBKDF2(password.encode('utf-8'), split_contents[0], hmac_hash_module=SHA256)
        
        # Membuat objek cipher AES dengan mode GCM dan nonce yang sesuai
        cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
        
        # Melakukan dekripsi dan verifikasi
        decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])

        # Mengembalikan hasil dekripsi dalam format teks UTF-8
        return decrypted_contents.decode('utf-8', 'ignore')
    except ValueError as e:
        print("Error decrypting file:", str(e))
        return None
    except Exception as e:
        print("Unexpected error:", str(e))
        return None

def filter_mij_content(config, file_extension):
    result_str = f"┌───────────────\n│[☬] open vpn ({file_extension})\n│[☬] bot: @mujta1nsshbot\n├───────────────"

    configdict = {}
    for line in config.split('\n'):
        if line.startswith('<entry'):
            line = line.replace('<entry key="', '')
            line = line.replace('</entry', '')
            line = line.split('">')
            if len(line) > 1:
                key = line[0]
                value = line[1].strip(">")
                configdict[key] = value
            else:
                key = line[0].strip('"/>')
                value = None
                configdict[key] = value

    for key, value in configdict.items():
        if value and value != "0" and value != "*******":
            result_str += f"\n│[☬] {key} : {value}\n├───────────────"

    result_str += "\n│[☬] bot: @mujta1nsshbot \n│[☬] Channel : https://t.me/mkldec1\n└───────────────\n "

    return result_str
        
def process_nm_content(encrypted_content, filename, print_messages=True):
    result = ""

    result += "┌───────────────\n│[☬] open vpn (.nm)\n│[☬] bot: @mujta1nsshbot\n├───────────────\n"

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
    result += "├───────────────\n│[☬] Channel : https://t.me/mkldec1 \n └───────────────\n"

    return result
    
# Handler para documentos recibidos
@bot.message_handler(content_types=['document'])
def post(message):
    # Función para manejar mensajes entrantes con archivos
    chat_id = message.chat.id
    user_id = message.from_user.id
    username = message.from_user.username

# Función para manejar mensajes en grupos privados
    user_ids = str(message.from_user.id)
    group_id = str(message.chat.id)  # ID del grupo
    if user_ids not in get_premium_users() and group_id not in get_premium_users():
        bot.reply_to(message, accde)
        return


    # Obtener nombre y extensión del documento
    name = message.document.file_name
    extension = name.split('.')[-1]

    # Procesar el documento
    threading.Thread(target=process_received_file, args=(message, name, extension)).start()

    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        file_path = os.path.join(FILES_DIR, f"{message.document.file_name}")
        with open(file_path, 'wb') as new_file:
            new_file.write(downloaded_file)

        file_extension = Path(file_path).suffix  # Asegúrate de definir file_extension aquí
        #time.sleep(60)
        if file_extension in ALLOWED_EXTENSIONS:
            bot.reply_to(message, dectext)
            if file_extension == '.nm':
                result_message = process_nm_extension(file_path, file_extension, message.document.file_name)
            elif file_extension == '.ssh':
                result_message = ssh_injector(file_path, file_extension)  # Pasa file_extension como parámetro
            elif file_extension == '.mij':
                decrypted_content = decrypt_mij_file(file_path, mij_password)
                result_message = print_result(decrypted_content, file_extension, message.document.file_name)
            else:
                decrypted_content = decrypt_document(file_path, file_extension, message.document.file_name)
                result_message = print_result(decrypted_content, file_extension, message.document.file_name)

            # Envía el mensaje de resultado en el mismo chat donde se recibió el documento
            send_long_message(chat_id, result_message, reply_to_message_id=message.message_id)

    except Exception as e:
        print(f"Error al procesar el documento: {str(e)}")

# Función para enviar un mensaje largo dividido en partes si es necesario
def send_long_message(chat_id, message, reply_to_message_id=None):
    if len(message) <= 4096:
        bot.send_message(chat_id, message, reply_to_message_id=reply_to_message_id)
    else:
        parts = [message[i:i + 4096] for i in range(0, len(message), 4096)]
        for part in parts:
            bot.send_message(chat_id, part, reply_to_message_id=reply_to_message_id)
        
# Ejecutar el bot en segundo plano
if __name__ == '__main__':
    try:
        while True:
            print("Bot activo")
            bot.polling(none_stop=True)

    except Exception as e:
        print(f"Error: {e}")