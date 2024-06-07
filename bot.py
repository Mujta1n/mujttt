import telebot
import os
import subprocess
import threading
import json

# Bot token
TOKEN = "6809426604:AAHBrJisyxhiR1S9C_AftNxf9WMCfMvzIdA"  # Reemplaza con tu token
bot = telebot.TeleBot(TOKEN)

# Directorio para guardar resultados únicos por usuario
RESULTS_DIR = "results"
FILES_DIR = "files"

for directory in [RESULTS_DIR, FILES_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Diccionario para mapear extensiones a scripts
extension_to_script = {
    "tnl": "tnl.py",
    "rez": "rez.js",
    "stk": "stk.js",
    "sks": "sks.js",
    "phc": "phc.py",
    "xscks": "xscks.py",
    "mina": "mina.py",
    "hat": "hat.py",
}

# Lista de extensiones permitidas
allowed_extensions = ["tnl", "agn", "ziv", "pb", "phc", "xscks", "mina", "hat", "sks", "rez", "stk"]

# Registro de actividad
activity_log = {}

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

# Función para enviar un archivo descifrado como respuesta al archivo original
def send_decrypted_file_reply(chat_id, file_path, user_info, original_message_id):
    with open(file_path, "rb") as f:
        bot.send_document(chat_id, f, caption=f"{user_info}", reply_to_message_id=original_message_id)

# Función para procesar un archivo recibido
def process_received_file(message, name, extension):
    if extension not in allowed_extensions:
        # Solo enviar mensaje si el mensaje proviene del chat del bot
        if message.chat.type == "private":
            bot.reply_to(message, "File extension not allowed.")
        return

    script_name = extension_to_script.get(extension)
    if script_name is None:
        return

    file_info = bot.get_file(message.document.file_id)
    downloaded_file = bot.download_file(file_info.file_path)

    received_file_path = os.path.join(FILES_DIR, name)

    with open(received_file_path, "wb") as received_file:
        received_file.write(downloaded_file)

    if script_name:
        if extension in ["sks", "rez", "stk"]:
            js_command = f'node {script_name} "{received_file_path}"'
            result = subprocess.run(js_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            python_command = f'python {script_name} "{received_file_path}"'
            result = subprocess.run(python_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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

# Handler para el comando '/start'
@bot.message_handler(commands=['start'])
def welcome(message):
    user_info = f"@{message.from_user.username}" if message.from_user.username else f"ID: {message.from_user.id}"
    chat_id = message.chat.id

    # Verifica si el mensaje proviene de un chat individual y no de un grupo
    if message.chat.type == "private":
        users = load_users()
        if chat_id not in users:
            bot.send_message(message.chat.id, f"Hello {user_info} Welcome\nSend files with the following extensions\n\n.🔻.hat - > ha Tunnel - ✅\n .🔻.tnl - OpenTunnel - ✅\n .🔻.ziv - > Ziv vpn - ✅\n .🔻.pb - > PB injector - ✅\n .🔻.pcx - > Binke Tunnel ✅\n .🔻.ssh - > SSH injector - ✅\n .🔻.xscks - > AIO TUNNEL - ✅\n .🔻.mina - MINA PRO  - ✅\n . 🔻.phc - > PHC TUNNEL - ✅\n .🔻.sks - > SocksHttp - ✅\n .🔻.stk - > STARK VPN - ✅\n .🔻.rez - > Rez Tunnel - ✅\n .🔻.vhd - > V2ray Hybrid - ✅\n .🔻.tmt - > TunnelMate - ✅\n . 🔻.nm - > NetMod Syna - ✅\n\n│[☬] only work in the following group\n\n│[☬] https://t.me/mkldec\n\n│[☬] Bot: @mujta1nsshbot")
            users[chat_id] = True
            save_users(users)

# Handler para documentos recibidos
@bot.message_handler(content_types=['document'])
def post(message):
    name = message.document.file_name
    extension = name.split('.')[-1]
    threading.Thread(target=process_received_file, args=(message, name, extension)).start()

# Inicia el bot
if __name__ == "__main__":
    bot.infinity_polling() 