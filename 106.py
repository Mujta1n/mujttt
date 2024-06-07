#!/usr/bin/env python3
import telebot
from telebot import types
from io import BytesIO
from argparse import ArgumentParser
from pathlib import Path
from base64 import b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES, Blowfish
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
from telebot.types import Message, CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup
from datetime import datetime, timedelta
from typing import Optional
import os
import time
import zlib
import subprocess
import json
import requests
import csv
import tempfile
import threading
import sys
import re
import asyncio
import logging
import base64 
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
from Crypto.Util.Padding import unpad
from pathlib import Path
import base64
import time
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
import asyncio
from datetime import datetime
import time
from datetime import timedelta
from datetime import datetime, timedelta
from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

TOKEN = '6809426604:AAHBrJisyxhiR1S9C_AftNxf9WMCfMvzIdA'
bot = telebot.TeleBot(TOKEN)

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

RESULTS_DIR = 'results'
FILES_DIR = 'files'
USERS_INFO_FILE = 'users_info.json'
# ID del administrador autorizado
AUTHORIZED_USER_ID = 1030659113 
AUTHORIZED_USER_ALIAS = 'τ н є ℓ σ я ɒ'
grupo_autorizado = '1685717676'
ch = '1685717676' # Reemplaza con el ID de tu canal
own = '1194429691'  
added_by_dict = {}
# Variable para rastrear el límite de archivos
file_count = {}
lista_administradores = [1030659113]
# Lista de IDs de administradores
admins = []
activity_log = {}
# Variable para controlar la ejecución del bot
ID_GRUPO_PERMITIDO = -1685717676 

ALLOWED_EXTENSIONS = [
    '.howdy', '.tut','.ssh','.tmt', '.temt', '.tsn', '.etun', '.pxp',
    '.ace', '.tsd', '.ost', '.wt', '.tnl', '.fks', '.gv', '.act', '.cnet', '.gibs', '.dvd', '.ftp',
    '.fthp', '.jph', '.xsks', '.ht', '.ssi', '.kt', '.dvs', '.fnet', '.mc', '.hub', '.grd', '.hta',
    '.eug', '.sds', '.htp', '.bbb', '.ccc', '.ddd', '.eee', '.cln', '.cyh', '.agn', '.Tcv2', '.NT',
    '.ai', '.cks', '.sksrv', '.garuda', '.tpp', '.sky', '.skyp', '.max', '.ziv', '.tnl', '.pb', '.hqp',
    '.hq', '.bdi', '.NT','.nm','.hat','.rez','.pcx','.ssh','.phc','.xscks'
] # Agrega las extensiones permitidas aquí

# Función para crear directorios si no existen
def create_directories():
    for directory in [RESULTS_DIR, FILES_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)

# Diccionario para mapear extensiones a scripts
extension_to_script = {
    "rez": "rez.js",
    "stk": "stk.js",
    #"nodehat": "nodehat.json", 
    "phc": "phc.py",
    
    "xscks": "xscks.py",
    "hat": "hat.js",
    "mina": "mina.py",
    "ehil": "ehil.js",
    "vpnlite": "vpnlite.py", 
    "sks": "sks.js"
}

def search_users(id):
    lines = open('users.txt', 'r').read().splitlines()
    return any(id in line for line in lines)

def search_admins(id):
    lines = open('admin.txt', 'r').read().splitlines()
    return any(id in line for line in lines)

def search_blocked(id):
    lines = open('block.txt', 'r').read().splitlines()
    return any(id in line for line in lines)

def save_user(id, username):
    with open('log.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([id, username])
        
def load_user_info():
    try:
        with open(USERS_INFO_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_user_info(user_id, alias):
    user_info = load_user_info()
    user_info[user_id] = {'alias': alias}
    
    with open(USERS_INFO_FILE, 'w') as file:
        json.dump(user_info, file)

def cargar_lista_administradores():
    try:
        with open('administradores.json', 'r') as file:
            data = file.read()
            if data:
                lista_administradores.extend(json.loads(data))
    except (FileNotFoundError, json.JSONDecodeError):
        # Si el archivo no existe o no puede ser decodificado como JSON, no se cargan administradores
        pass

def guardar_lista_administradores():
    with open('administradores.json', 'w') as file:
        json.dump(lista_administradores, file)

# Cargar la lista de administradores al inicio
cargar_lista_administradores()
        
# Función para obtener la lista de grupos actuales del bot
def get_current_groups():
    filename = 'group_aliases.json'
    
    if not os.path.exists(filename):
        # Si el archivo no existe, crea uno vacío
        with open(filename, 'w') as json_file:
            json.dump([], json_file)
    
    try:
        # Intenta cargar los datos desde el archivo JSON
        with open(filename, 'r') as json_file:
            return json.load(json_file)
    except json.JSONDecodeError:
        # Si ocurre un error de decodificación JSON, elimina el archivo y crea uno nuevo
        os.remove(filename)
        with open(filename, 'w') as json_file:
            json.dump([], json_file)
        # Retorna una lista vacía
        return []

# Función para almacenar los alias de los grupos
def store_group_aliases():
    filename = 'group_aliases.json'

    # Obtén la lista actualizada de grupos después de salir
    updated_group_ids = get_current_groups()

    # Verifica si el archivo JSON ya existe
    if os.path.exists(filename):
        # Si existe, carga los datos existentes
        with open(filename, 'r') as json_file:
            existing_aliases = json.load(json_file)
        
        # Agrega los nuevos IDs a los datos existentes
        existing_aliases.extend(updated_group_ids)
    else:
        # Si no existe, crea un nuevo archivo con los IDs proporcionados
        existing_aliases = updated_group_ids

    # Guarda los IDs actualizados en el archivo JSON
    with open(filename, 'w') as json_file:
        json.dump(existing_aliases, json_file)

# Ejemplo de uso:
store_group_aliases()

Px_inicio = "\n╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n├◉────────────────◉\n│◉ ‌‌𝐆𝐫𝐨𝐮𝐩: https://t.me/mkldec\n╰◉────────────────◉"
Px_fin = "\n╭◉────────────────◉\n│◉ 𝘾𝙝𝙖𝙣𝙣l: https://t.me/mkldec1\n│◉ ‌𝐆𝐫𝐨𝐮𝐩: https://t.me/mkldec\n╰◉────────────────◉"
    
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
    '.ziv': b'fubvx788b46v',
    # '.ziv': b'fubvx788b46v',
    '.tnl': b'B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg',
    '.pb': b'Cw1G6s0K8fJVKZmhSLZLw3L1R3ncNJ2e',
    '.hqp': b'Ed',
    '.hq': b'Ed',
    '.bdi': b'@technore 2022',
    '.NT': b'0x0',
    '.pcx': b'cinbdf665$4',
    'phc': b'667562767837383862343676',
     '.artunl': b'artunnel57221021', 
}

def handle_send_message_error(error, message):
    print(f"Error al enviar el mensaje: {error}")
    # Aquí puedes agregar código para manejar el error, como enviar un mensaje de error al usuario o registrar el error en un archivo de registro.

@bot.message_handler(commands=['start'])
def welcome(message: telebot.types.Message):
    try:
        if message.chat.type == 'private' or message.chat.type in ['group', 'supergroup']:
            handle_start(message)
    except Exception as e:
        handle_send_message_error(e, message)

def handle_start(message):
    try:
        ch = '1685717676'  # Reemplaza 'tu_canal' con el ID de tu canal
        user_id = str(message.from_user.id)

        # Verificar si el usuario está bloqueado
        if search_blocked(user_id):
            bot.send_message(message.chat.id, text='''
- Bienvenido Pro ⚜️
- Has sido bloqueado  ⛔️
-  Contacta a @decrypt_filebot para desbloquear
            ''')
            return

        # Verificar la membresía del usuario en el canal
        req = requests.get(
            f'https://api.telegram.org/bot{TOKEN}/getChatMember?chat_id={ch}&user_id={user_id}', headers=headerss).json()

        status_key = 'result' if 'result' in req else 'error'
        stt = req.get(status_key, {}).get('status') if status_key == 'result' else None

        # Si el usuario no está en el canal, enviar mensaje de bienvenida
        if stt == 'left' and message.chat.type in ['group', 'supergroup']:
            bot.send_message(message.chat.id, text='''
- Nuevo usuario, bienvenido Pro ⚜️

- Debes unirte a nuestro canal primero para usar el bot

- Únete ahora ♡ {ch} ♡
            ''')
        else:
            # Obtener información del usuario
            first = message.from_user.first_name
            user = message.from_user.username

            # Mensaje de bienvenida normal
            bot.send_photo(message.chat.id,
                           "https://t.me/mkl_ove/3700",
                           f"""
╭◉────────────────◉
│        𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓
├◉────────────────◉
│Discover the fascinating world
│of decryption with our
│specialized bot:
├◉────────────────◉
│🔐bot for decoding files.🔐
├◉────────────────◉
│◉ ‌𝐁𝐎𝐓: @mujta1nsshbot
│◉ ‌𝐂𝐇𝐀𝐍𝐍𝐄𝐋: https://t.me/mkldec1
│◉ ‌𝐆𝐑𝐎𝐔𝐏 :https://t.me/mkldec
│◉ Assistant Developer : 𝐊𝟏
├◉────────────────◉
│◉Use /help to learn more
│about using the Bot.
│◉Use /files to find out the
│file format of the bot decryptor
│◉Use /decssh to decrypt ssh
╰◉────────────────◉
            """)
    except Exception as e:
        handle_send_message_error(e, message)
       
# Comando de ayuda
@bot.message_handler(commands=['help'])
def send_help(message):
    try:
        bot.send_message(message.chat.id, "𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n╭◉────────────────◉\n│Hello! I'm a bot for decoding files.\n│To use my services, simply submit\n│a file and I will provide you with\n│relevant information. You can\n│use the /files command to see the\n│extensions that the bot supports. 🤖\n╰◉────────────────◉\n\n╭◉────────────────◉\n│to decrypt ssh use the command\n│/decssh example:\n╰◉────────────────◉\n/decssh K1.com:80@-1903334718.14.-1985794238.17.-1743538508.13.1858394836.23.-475139141.25.1907334462.12:-1903334718.14.-1985794238.17.-1743538508.13.1858394836.23.-475139141.25.1907334462.12")
    except telebot.apihelper.ApiTelegramException as e:
        if e.error_code == 400 and "message to reply not found" in e.description:
            # Si el mensaje al que estamos tratando de responder no se encuentra, envía un nuevo mensaje
            bot.send_message(message.chat.id, "𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n╭◉────────────────◉\n│Hello! I'm a bot for decoding files.\n│To use my services, simply submit\n│a file and I will provide you with\n│relevant information. You can\n│use the /files command to see the\n│extensions that the bot supports. 🤖\n╰◉────────────────◉\n\n╭◉────────────────◉\n│to decrypt ssh use the command\n│/decssh example:\n╰◉────────────────◉\n/decssh K1.com:80@-1903334718.14.-1985794238.17.-1743538508.13.1858394836.23.-475139141.25.1907334462.12:-1903334718.14.-1985794238.17.-1743538508.13.1858394836.23.-475139141.25.1907334462.12")
        else:
            # Si ocurre algún otro error, imprímelo en la consola
            print(f"Error al enviar el mensaje de ayuda: {e}")

@bot.message_handler(commands=['files'])
def get(message: telebot.types.Message):
    bot.send_message(message.chat.id, "╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n├◉────────────────◉\n│◉ ‌𝐁𝐎𝐓: @mujta1nsshbot\n│◉ ‌𝐂𝐇𝐀𝐍𝐍𝐄𝐋: https://t.me/mkldec1\n│◉ ‌𝐁𝐎𝐓 : @mujta1nsshbot\n├◉────────────────◉\n│🔐Send File To Decrypt 🔐\n╰◉────────────────◉\n╭◉────────────────◉\n│.tmt .sks .ace .tnl .gv .act .gibs\n│.fnet .mc .sds .NT .sksrv .ziv\n│.tnl .pb .NT .nm .hat .pcx\n│.stk .rez  .xscks .mina .phc\n│.ssh\n╰◉────────────────◉")

# Método para enviar un mensaje en el grupo
@bot.message_handler(func=lambda message: message.text.startswith('/send'))
def send_message_to_group_command(message: Message):
    chat_id = message.chat.id
    reply_to_message = message.reply_to_message

    # Verificar si se está respondiendo a un mensaje
    if reply_to_message:
        # Eliminar el comando del mensaje original
        command_length = len('/send')
        original_text = message.text
        message_text = original_text[command_length:].strip()

        # Enviar el mensaje al usuario al que se respondió en el mismo grupo
        try:
            bot.send_message(reply_to_message.chat.id, message_text, reply_to_message.message_id)
            bot.delete_message(chat_id, message.message_id)
        except Exception as e:
            print(f"Error al enviar mensaje: {e}")
    else:
        # Eliminar el comando del mensaje original
        command_length = len('/send')
        original_text = message.text
        message_text = original_text[command_length:].strip()

        # Enviar el mensaje en el grupo o supergrupo sin avisar
        try:
            bot.send_message(chat_id, message_text)
            bot.delete_message(chat_id, message.message_id)
        except Exception as e:
            print(f"Error al enviar mensaje en el grupo: {e}")      
        
# Comando /developer para obtener información del dueño del bot
@bot.message_handler(commands=['developer'])
def developer_info(message):
    user_name = message.from_user.first_name
    bot_name = bot.get_me().first_name
    authorized_user_alias = "@decrypt_filebot"

    response_message = (
        f'Hello {user_name}! 👋\n'
        f'I\'m {bot_name}, a bot created by {authorized_user_alias} I\'m here to assist you with anything you need.\n\n'
        f'For more information about, please contact {authorized_user_alias}\n'
        f'Thanks for using the bot! 🤖'
    )

    # Enviar el mensaje al usuario
    bot.send_message(message.chat.id, response_message)         

def dec_ssh(ld):
    userlv = [i for i in ld.split('.')][::2]
    userld = [i for i in ld.split('.')][1::2]
    newld = ""
    for x in range(len(userld)):
        v = int(userlv[x]) - len(userlv)
        w = int(userld[x]) - len(userlv)
        m = int(v // (2**w)) % 256
        newld += chr(m)
    return newld


@bot.message_handler(commands=['decssh'])
def dec_ssh_command(message):
    
    encoded_data = message.text.replace("/decssh", "").strip()

    if '@' in encoded_data and ':' in encoded_data.split('@')[1]:
    
        user = dec_ssh(encoded_data.split('@')[1].split(':')[0])
        passw = dec_ssh(encoded_data.split('@')[1].split(':')[1])

        bot.reply_to(message, f'╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n├◉────────────────◉\n│‌𝐁𝐎𝐓: @mujta1nsshbot\n│‌𝐂𝐇𝐀𝐍𝐍𝐄𝐋: https://t.me/mkldec1\n│‌‌𝐆𝐑𝐎𝐔𝐏 : https://t.me/mkldec\n╰◉────────────────◉\nData encode:\n{encoded_data}\n╭◉────────────────◉\n│SSH: {encoded_data.split("@")[0]}\n│User: {user}\n│Password: {passw}\n├◉────────────────◉\n│{encoded_data.split("@")[0]}@{user}:{passw}\n╰◉────────────────◉\n')
    else:
        bot.reply_to(message, 'Data not detected in the command. Please provide valid data to decode.')

# Función para obtener el nombre del usuario
def get_user_name(user):
    if user.first_name:
        name = user.first_name
        if user.last_name:
            name += ' ' + user.last_name
    elif user.username:
        name = user.username
    else:
        name = "Usuario sin nombre"
    return name

# Manejar evento de nuevos miembros en el grupo
@bot.message_handler(func=lambda message: message.new_chat_members is not None)
def welcome_message(message):
    for new_member in message.new_chat_members:
        send_welcome_message(message, new_member)

# Función para enviar un mensaje de bienvenida detallado con una imagen
def send_welcome_message(message, new_member):
    # Obtener información del nuevo miembro
    user_id = new_member.id
    username = new_member.username
    join_date = datetime.utcfromtimestamp(new_member.join_date).strftime('%Y-%m-%d %H:%M:%S')
    account_created_date = datetime.utcfromtimestamp(new_member.created_at).strftime('%Y-%m-%d %H:%M:%S')

    # Obtener el nombre del nuevo miembro
    name = get_user_name(new_member)

    # Construir el mensaje de bienvenida detallado
    welcome_text = (
        "━━━━━━━━━━━━━━━━━━━━\n"
        "      𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓 \n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"- Name: {name}\n"
        f"- Username: @{username}\n"
        f"- ID: {user_id}\n"
        f"- Join Date: {join_date}\n"
        f"- Account Created Date: {account_created_date}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓 https://t.me/mkldec\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "📜 Group Rules:\n\n"
        "⚠️Solo se permite el inglés⚠️\n\n"
        "× No multiple accounts allowed.\n\n"
        "× Do not delete the config after decryption otherwise you'll be muted.\n\n"
        "× Do not forward configs from other channels or send with channel links.. download the config then send it here.\n\n"
        "× Only English Language is Allowed .\n\n"
        "× Don't send the same file multiple times.\n\n"
        "× Any spam links or insults will get you banned immediately.\n\n"
        "𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
    )

    # Ruta de la imagen de bienvenida
    image_path = '/results/welcome.png'

    # Enviar el mensaje de bienvenida con la imagen
    with open(image_path, 'rb') as photo:
        bot.send_photo(message.chat.id, photo, caption=welcome_text)
       
      
     
# Método para verificar si un usuario es administrador
def es_admin(user_id):
    return user_id in admins 

# Manejador de comando '/admin'
@bot.message_handler(commands=['admin'])
def handle_admin(message):
    user_id = message.from_user.id
    print("ID del usuario que envió el comando:", user_id)  # Agregar esta línea para imprimir el ID del usuario
    chat_id = message.chat.id

    # Verificar si el usuario es un administrador
    if es_admin(user_id):
        control_buttons = [
            InlineKeyboardButton('Send Message 👥', callback_data="msg"),
            InlineKeyboardButton('Set New Admin 👨‍💻', callback_data="new_admin"),
            InlineKeyboardButton('Mute User 🔇', callback_data="mute"),
            InlineKeyboardButton('Unmute User 🔊', callback_data="unmute"),
            InlineKeyboardButton('Kick User 👢', callback_data="kick"),
            InlineKeyboardButton('Members Count 🤖', callback_data="count")
        ]

        control_markup = InlineKeyboardMarkup().add(*control_buttons)

        control_message = '''- Welcome To Control Panel 🧑‍🔧
- Here You Can Control The Bot 🤖
- Please Select An Option To Start 💫'''

        bot.send_message(chat_id, control_message, reply_markup=control_markup)
    else:
        response_text = "No tienes los permisos para acceder al panel de control."
        bot.send_message(chat_id, response_text)

# Método para agregar un nuevo administrador
def agregar_nuevo_admin(message, text, alias=None):
    user_id = message.from_user.id
    chat_id = message.chat.id
    new_admin_info = text

    # Si se proporciona un alias, usarlo en lugar del nombre o ID
    if alias:
        new_admin_info = alias

    # Extraer el ID o el alias del nuevo administrador
    try:
        new_admin_id = int(new_admin_info)
    except ValueError:
        # Si no se proporciona un ID válido, intentar buscar por alias
        new_admin_id = None

    if new_admin_id is None:
        # Intentar encontrar el ID del nuevo administrador por su alias
        try:
            new_admin = bot.get_chat_member(chat_id, new_admin_info).user
            new_admin_id = new_admin.id
        except Exception as e:
            bot.send_message(chat_id, f"No se pudo encontrar al usuario con el alias '{new_admin_info}'. Inténtalo de nuevo.")
            return

    # Verificar si el nuevo administrador ya está en la lista
    if new_admin_id in admins:
        bot.send_message(chat_id, "El usuario ya es un administrador.")
    else:
        # Agregar el nuevo administrador a la lista y otorgar permisos
        admins.append(new_admin_id)
        bot.promote_chat_member(chat_id=chat_id, user_id=new_admin_id, can_change_info=True, can_delete_messages=True)
        
        # Mensaje de confirmación con el alias personalizado si se proporciona
        if alias:
            bot.send_message(chat_id, f"¡Nuevo administrador '{alias}' (ID: {new_admin_id}) configurado!")
        else:
            bot.send_message(chat_id, f"¡Nuevo administrador (ID: {new_admin_id}) configurado!")

# Manejador para las opciones del panel de control
@bot.callback_query_handler(func=lambda call: call.data in ['msg', 'new_admin', 'mute', 'unmute', 'kick', 'count'])
def handle_control_options(callback_query):
    chat_id = callback_query.message.chat.id
    option = callback_query.data

    if option == 'msg':
        bot.send_message(chat_id, "Por favor, ingresa el mensaje a enviar:")
        bot.register_next_step_handler(callback_query.message, lambda message: send_message_to_group(callback_query, message.text))
    
    elif option == 'new_admin':
        bot.send_message(chat_id, "Por favor, menciona o escribe el ID o el alias del nuevo administrador:")
        bot.register_next_step_handler(callback_query.message, lambda message: ask_for_admin_alias(callback_query, message.text))
    
    elif option == 'mute':
        bot.send_message(chat_id, "Por favor, menciona al usuario que quieres silenciar:")
        bot.register_next_step_handler(callback_query.message, lambda message: silenciar_usuario(callback_query, message.text))
    
    elif option == 'unmute':
        bot.send_message(chat_id, "Por favor, menciona al usuario que quieres desilenciar:")
        bot.register_next_step_handler(callback_query.message, lambda message: quitar_silencio_usuario(callback_query, message.text))
    
    elif option == 'kick':
        bot.send_message(chat_id, "Por favor, menciona al usuario que quieres expulsar:")
        bot.register_next_step_handler(callback_query.message, lambda message: expulsar_usuario(callback_query, message.text))
    
    elif option == 'count':
        count_members(callback_query)

# Método para pedir el alias del nuevo administrador (opcional)
def ask_for_admin_alias(callback_query, message_text):
    chat_id = callback_query.message.chat.id
    bot.send_message(chat_id, "Por favor, ingresa el nombre o alias deseado para el nuevo administrador (opcional):")
    bot.register_next_step_handler(callback_query.message, lambda message: agregar_nuevo_admin(callback_query, message_text, message.text))

# Método para contar miembros del grupo
def count_members(callback_query):
    chat_id = callback_query.message.chat.id
    member_count = bot.get_chat_members_count(chat_id)
    bot.send_message(chat_id, f"El número de miembros en este grupo es: {member_count}")

# Método para expulsar a un usuario del grupo
def expulsar_usuario(callback_query, user_info):
    chat_id = callback_query.message.chat.id
    user_id = extract_user_id(user_info)

    if user_id is None:
        bot.send_message(chat_id, "No se pudo encontrar al usuario. Inténtalo de nuevo.")
        return

    try:
        bot.kick_chat_member(chat_id, user_id)
        bot.send_message(chat_id, f"El usuario {user_id} ha sido expulsado del grupo.")
    except Exception as e:
        bot.send_message(chat_id, f"No se pudo expulsar al usuario {user_id}. Error: {e}")

# Método para quitar el silencio a un usuario en el grupo
def quitar_silencio_usuario(callback_query, user_info):
    chat_id = callback_query.message.chat.id
    user_id = extract_user_id(user_info)

    if user_id is None:
        bot.send_message(chat_id, "No se pudo encontrar al usuario. Inténtalo de nuevo.")
        return

    try:
        bot.restrict_chat_member(chat_id, user_id, can_send_messages=True)
        bot.send_message(chat_id, f"El usuario {user_id} ya puede enviar mensajes en el grupo.")
    except Exception as e:
        bot.send_message(chat_id, f"No se pudo quitar el silencio al usuario {user_id}. Error: {e}")

# Método para silenciar a un usuario en el grupo
def silenciar_usuario(callback_query, user_info):
    chat_id = callback_query.message.chat.id
    user_id = extract_user_id(user_info)

    if user_id is None:
        bot.send_message(chat_id, "No se pudo encontrar al usuario. Inténtalo de nuevo.")
        return

    try:
        bot.restrict_chat_member(chat_id, user_id, can_send_messages=False)
        bot.send_message(chat_id, f"El usuario {user_id} ha sido silenciado en el grupo.")
    except Exception as e:
        bot.send_message(chat_id, f"No se pudo silenciar al usuario {user_id}. Error: {e}")

# Método para enviar un mensaje en el grupo
def send_message_to_group(callback_query, message_text):
    chat_id = callback_query.message.chat.id

    try:
        bot.send_message(chat_id, message_text)
    except Exception as e:
        bot.send_message(chat_id, f"No se pudo enviar el mensaje en el grupo. Error: {e}")     
                                        
#Función Net Mod Syna (.nm)    
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
            formatted_text += "" * indent + f"\n│[☬]{key} Values"
            formatted_text += format_nested_keys(value, indent + 1)
        elif isinstance(value, list):
            formatted_text += "" * indent + f"\n│[☬]{key} Values"
            for item in value:
                if isinstance(item, dict):
                    formatted_text += format_nested_keys(item, indent + 1)
                elif item != 0 and item != "" and item not in [True, False]:
                    formatted_text += "" * (indent + 1) + f"{convert_value(item)}"
        elif value != 0 and value != "" and value not in [True, False]:
            formatted_text += "" * indent + f"\n│[☬]{key}: {convert_value(value)}"
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

def process_nm_content(encrypted_content, filename, print_messages=True):
    result = ""

    result += "\n╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n├◉────────────────◉\n│◉ ‌𝐁𝐎𝐓: @mujta1nsshbot\n╰◉────────────────◉"

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
    result += "\n╭◉────────────────◉\n│◉ ‌𝐂𝐇𝐀𝐍𝐍𝐄𝐋: https://t.me/mkldec1\n│◉ ‌𝐁𝐎𝐓 : @mujta1nsshbot\n╰◉────────────────◉"

    return result
    
#Función hat túnel 

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
    decoded_lines = [f'\n│[☬]{line} ' for line in final_text.splitlines()]
    full_message += '' + '\n'.join(decoded_lines)
    full_message += Px_fin

    return full_message
    
 # Definir tu ID de chat
tu_id = 1685717676

# Comando para expulsar al bot de un grupo
@bot.message_handler(commands=['salir'])
def salir(message):
    if message.chat.type == 'private' and message.chat.id == tu_id:
        try:
            group_alias = message.text.split(' ', 1)[1]
            bot.leave_chat(group_alias)
            bot.send_message(tu_id, f"El bot ha salido exitosamente del grupo {group_alias}.")
        except Exception as e:
            bot.send_message(tu_id, f"Se produjo un error al intentar salir del grupo: {e}")
    else:
        bot.reply_to(message, "Este comando solo puede ser usado por mi desarrollador.")

# Función para manejar el registro de comandos
def log_comando(message):
    # Lógica para registrar el comando
    pass
    
# Manejador de comando '/groupid'
@bot.message_handler(commands=['ID'])
def get_group_id(message):
    chat_id = message.chat.id
    bot.send_message(chat_id, f"El ID de este grupo es: {chat_id}")
   

# Archivo para almacenar información del usuario
USER_FILE = "users.json"

# Función para cargar datos de usuario desde el archivo
def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r') as file:
            return json.load(file)
    return {}

# Función para guardar datos de usuario en el archivo
def save_users(users):
    with open(USER_FILE, 'w') as file:
        json.dump(users, file)

# Función para procesar un archivo recibido
def process_received_file(message, name, extension):
    script_name = extension_to_script.get(extension)
    if script_name is None:
        return

    # Obtener el chat_id del mensaje
    chat_id = message.chat.id

    file_info = bot.get_file(message.document.file_id)
    downloaded_file = bot.download_file(file_info.file_path)

    received_file_path = os.path.join(FILES_DIR, name)

    with open(received_file_path, "wb") as received_file:
        received_file.write(downloaded_file)

    if script_name:
        try:
            python_command = f'python {script_name} "{received_file_path}"'
            result = subprocess.run(python_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            activity_log.setdefault(message.chat.id, []).append({
                "user": message.from_user.username,
                "file_name": name,
                "result_stdout": result.stdout,
                "result_stderr": result.stderr
            })

            if result.stdout.strip():
                message_limit = 4096
                message_parts = [result.stdout[i:i + message_limit] for i in range(0, len(result.stdout), message_limit)]
                for part in message_parts:
                    bot.send_message(chat_id, part, reply_to_message_id=message.message_id)
            else:
                bot.send_message(chat_id, "An error occurred while processing the file.", reply_to_message_id=message.message_id)
        except Exception as e:
            bot.send_message(chat_id, f"An error occurred while processing the file: {str(e)}", reply_to_message_id=message.message_id)
    else:  # Para otras extensiones, ejecuta los scripts con Node.js
        js_command = f'node {script_name} "{received_file_path}"'
        try:
            result = subprocess.run(js_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            activity_log.setdefault(message.chat.id, []).append({
                "user": message.from_user.username,
                "file_name": name,
                "result_stdout": result.stdout,
                "result_stderr": result.stderr
            })

            if result.stdout.strip():
                message_limit = 4096
                message_parts = [result.stdout[i:i + message_limit] for i in range(0, len(result.stdout), message_limit)]
                for part in message_parts:
                    bot.send_message(chat_id, part, reply_to_message_id=message.message_id)
            else:
                bot.send_message(chat_id, "An error occurred while processing the file.", reply_to_message_id=message.message_id)
        except Exception as e:
            bot.send_message(chat_id, f"An error occurred while processing the file: {str(e)}", reply_to_message_id=message.message_id)
       
# Handler para documentos recibidos
@bot.message_handler(content_types=['document'])
def post(message):
    # Verificar si el mensaje proviene de un chat privado
    if message.chat.type == 'private':
        bot.reply_to(message, "\n╭◉────────────────◉\n│Lo siento, solo puedes utilizarme\n│en estos grupos:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉\n\n╭◉────────────────◉\n│I'm sorry, you can only use me\n│in these groups:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉")
        return

    # Si no es un chat privado, continuar con el procesamiento del documento
    if message.from_user is None:
        print("Error: El mensaje no tiene un usuario asociado.")
        return

    user_id = message.from_user.id
    chat_id = message.chat.id

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

        if file_extension in ALLOWED_EXTENSIONS:
            if file_extension == '.nm':
                result_message = process_nm_extension(file_path, file_extension, message.document.file_name)
            #elif file_extension == '.hat':
                #result_message = process_hat_extension(file_path)
            elif file_extension == '.ssh':
                result_message = ssh_injector(file_path, file_extension)  # Pasa file_extension como parámetro
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
        result_message += f"\n├ • 🔥{key} : {value}"

    principio_result_str = f"\n╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n├◉────────────────◉\n│◉ ‌𝐁𝐎𝐓: @mujta1nsshbot\n╰◉────────────────◉"
    final_result_str = "\n╭◉────────────────◉\n│◉ ‌𝐂𝐇𝐀𝐍𝐍𝐄𝐋: https://t.me/mkldec1\n│◉ ‌𝐁𝐎𝐓 : @mujta1nsshbot\n╰◉────────────────◉"

    # Texto final después de los datos obtenidos
    result_str = principio_result_str + result_message + final_result_str

    return result_str

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
    
    return decrypted_contents.decode('utf-8', 'ignore')

def print_result(config, file_extension, file_name):
    result_str = f"\n╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n├◉────────────────◉\n│◉ ‌𝐁𝐎𝐓: @mujta1nsshbot\n╰◉────────────────◉"

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
                value = " ***"
                configdict[key] = value

    for key, value in configdict.items():
        result_str += f"\n├ • 🔥{key}: {value}"

    result_str += "\n╭◉────────────────◉\n│◉ ‌𝐂𝐇𝐀𝐍𝐍𝐄𝐋: https://t.me/mkldec1\n│◉ ‌𝐁𝐎𝐓 : @mujta1nsshbot\n╰◉────────────────◉"

    return result_str 
    
def add_marker_to_lines(text):
    return text

def add_second_marker_to_lines(text, protocol):
    return text

def decode_message(encrypted_text_base64):
    cle = 'YXJ0dW5uZWw3ODc5Nzg5eA=='
    pattern = r'^ar-(dns|vless|vmess|trojan|ssr|socks|trojan-go|ssh)://'
    cfg_type = re.match(pattern, encrypted_text_base64)
    
    if cfg_type is not None:
        encryption_key = base64.b64decode(cle)

        config_encrypt = encrypted_text_base64[len(cfg_type[0]):]
        encrypted_text = base64.b64decode(config_encrypt)

        cipher = AES.new(encryption_key, AES.MODE_ECB)
        decrypt_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)
        decrypt_text = decrypt_text.decode('utf-8')
        
        try:
            json_data = json.loads(decrypt_text)
            formatted_text = "\n".join([f"│[☬] {k}: {v}" for k, v in json_data.items()])
            final_text = ("\n┌───────────────\n│𝗞𝟭 - 𝗗𝗘𝗖𝗢𝗗𝗘 (ar-??)\n│GROUP:https://t.me/mkldec\n├───────────────\n"
                              f"{formatted_text}\n"
                              "├───────────────\n│[☬] 𝗚𝗥𝗢𝗨𝗣 : https://t.me/mkldec \n│[☬] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : https://t.me/mkldec1\n└───────────────\n")
        except json.JSONDecodeError:
            final_text = ("\n┌───────────────\n│𝗞𝟭 - 𝗗𝗘𝗖𝗢𝗗𝗘 (ar-??)\n│GROUP:/mkldec\n├───────────────\n"
                              f"{decrypt_text}\n"
                              "├───────────────\n│[☬] 𝗚𝗥𝗢𝗨𝗣 : @mkldec \n│[☬] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : https://t.me/mkldec1\n└───────────────\n")
        
        return final_text

def decode_ar_message(update, context):
    encrypted_text_base64 = update.message.text
    try:
        final_text = decode_message(encrypted_text_base64)
        update.message.reply_text(final_text, parse_mode='HTML')
    except Exception as e:
        update.message.reply_text(f"Error decoding message: {str(e)}")
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
            cd = '\n╭◉────────────────◉\n│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓\n├◉────────────────◉\n│◉ ‌𝐁𝐎𝐓: @mujta1nsshbot\n╰◉────────────────◉' + \
                 add_marker_to_lines(decrypt_text) + '\n╭◉────────────────◉\n│◉ ‌𝐂𝐇𝐀𝐍𝐍𝐄𝐋: https://t.me/mkldec1\n│◉ ‌𝐁𝐎𝐓 : 𝐁𝐎𝐓\n╰◉────────────────◉'
            bot.reply_to(message, cd) 
    except Exception as e:
        bot.reply_to(message, f"‼️Oops! An error occurred:\n{e}‼️")
                          
# Función para enviar mensaje de bienvenida personalizado
def send_welcome_message(chat_id, name, username, user_id):
    welcome_message = """

╭◉────────────────◉
│     𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓
├◉────────────────◉
│ Name: {name}
│ Username: @{username}
│ ID: {user_id}
├◉────────────────◉
│ 𝘿𝙚𝙫𝙚𝙡𝙤𝙥𝙚𝙧 : @mujta1n
│ 𝘾𝙝𝙖𝙣𝙣𝙚𝙡 :@mkldec1
│ group : @mkldec
├◉────────────────◉
│𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐎𝐑 𝐁𝐎𝐓
├◉/start command to use the bot
╰◉────────────────◉
""".format(name=name, username=username, user_id=user_id)

    bot.send_message(chat_id, welcome_message)

# Manejar la entrada de nuevos miembros al grupo
@bot.message_handler(content_types=['new_chat_members'])
def welcome_new_members(message):
    for member in message.new_chat_members:
        send_welcome_message(message.chat.id, member.first_name, member.username, member.id)


@bot.message_handler(func=lambda message: message.new_chat_members and bot.get_me() in message.new_chat_members)
def added_by_others(message):
    chat_id = message.chat.id
    group_title = message.chat.title
    added_by = message.from_user.username
    bot.send_message(chat_id, f"¡Hola! He sido añadido al grupo {group_title} por @{added_by}.")


# Lista de ID de grupos permitidos
allowed_group_ids = [-1001685717676,-1001820297754,-1002068726651,-1002088487438,-1001928633066,-1006493733338]

@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    group_id = message.chat.id
    if group_id not in allowed_group_ids:
        message_text = "╭◉────────────────◉\n│Lo siento, solo puedes utilizarme\n│en estos grupos:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉\n\n╭◉────────────────◉\n│I'm sorry, you can only use me\n│in these groups:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉"
        enviar_mensaje(group_id, message_text)
        bot.leave_chat(group_id)
            
def manejar_excepcion_envio_mensaje(e):
    if e.error_code == 403:
        print("El bot fue bloqueado por el usuario.")
        # Aquí puedes realizar alguna acción, como enviar un mensaje al administrador
    else:
        # Manejar otros errores de manera apropiada
        print("Error al enviar el mensaje:", e)

def enviar_mensaje(chat_id, mensaje):
    try:
        bot.send_message(chat_id, mensaje)
    except ApiTelegramException as e:
        manejar_excepcion_envio_mensaje(e)                  
bot.infinity_polling()