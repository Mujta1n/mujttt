import os
import subprocess
import logging
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
import re
import random
from base64 import b64decode
from Crypto.Cipher import AES
import json
import base64

extension_to_script = {
    "ehil": "ehil.js",
    "hat": "hat.js", 
    "mij": "mij.py", 
    "mina": "mina.py", 
    "mrc": "mrc.py", 
    "xscks": "xscks.py", 
    "phc": "phc.py", 
    "nm": "nm.py",
    "mina": "mina.py",
    "tnl": "tnl.py",
    "tmt": "tmt.py", 
    "pcx": "pcx.py",
    #"hat1": "hat1.js",
    "vpnlite": "vpnlite.py", 
    "ziv": "ziv.py", 
    "pb": "pb.py", 
    "ssh": "ssh.py", 
    "sks": "sks.js",
    "arssh": "arssh.py", 
    "rez": "rez.js",
    "stk": "stk.js"
}

FILES_DIR = "Downloads"

grupos_permitidos_ids = [-1001685717676,-1001820297754,-1002068726651,-1002088487438,-1001928633066,-1006493733338,-1002034580355,-1001699288159]

def process_received_file(update, context):
    grupo_id = update.message.chat_id
    if is_group_allowed(grupo_id):
        file_info = context.bot.get_file(update.message.document.file_id)
        file_extension = file_info.file_path.split(".")[-1]
        file_name = update.message.document.file_name        
        if file_extension in extension_to_script:
            downloaded_file = file_info.download_as_bytearray()
            received_file_path = os.path.join(FILES_DIR, file_name)
            with open(received_file_path, "wb") as received_file:
                received_file.write(downloaded_file)
                                           
            script_name = extension_to_script[file_extension]
            script_path = os.path.join(os.path.dirname(__file__), script_name)
            if file_extension in ["rez", "sks", "stk", "hat"]:
                script_command = f'node "{script_path}" "{received_file_path}"'
            else:
                script_command = f'python "{script_path}" "{received_file_path}"'
            
            result = subprocess.run(script_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result.stdout.strip():
                message_limit = 4096
                message_parts = [result.stdout[i:i+message_limit] for i in range(0, len(result.stdout), message_limit)]
                for part in message_parts:
                    update.message.reply_text(part, reply_to_message_id=update.message.message_id)
            elif result.stderr.strip():
                update.message.reply_text(f"Error: {result.stderr}", reply_to_message_id=update.message.message_id)
        else:
            pass
    else:
        if update.message.chat.type == "private":
            context.bot.send_message(chat_id=grupo_id, text="•‼️Access Denied‼️•\n==============================\n 🔌 Only work in the following Group ✓\n\n • @mkldec | • Channel : @mkldec1\n\n⫹⫺ 2024 𝖠𝗅𝗅 𝗋𝗂𝗀𝗁𝗍 𝗋𝖾𝗌𝖾𝗋𝗏𝖾𝖽 | @mujta1nsshbot, 𝐊𝟏 ®\n==============================")
        else:
            context.bot.send_message(chat_id=grupo_id, text="•‼️Access Denied‼️•\n==============================\n 🔌 Only work in the following Group ✓\n\n • @mkldec | • Channel : @mkldec1\n\n⫹⫺ 2024 𝖠𝗅𝗅 𝗋𝗂𝗀𝗁𝗍 𝗋𝖾𝗌𝖾𝗋𝗏𝖾𝖽 | @mujta1nsshbot, mujta1n ®\n==============================")
            context.bot.leave_chat(chat_id=grupo_id)

def is_group_allowed(grupo_id):
    if grupo_id in grupos_permitidos_ids:
        return True
    else:
        return False

def is_user_in_channel(bot, user_id, channel_id):
    try:
        member = bot.get_chat_member(channel_id, user_id)
        return True if member.status != "left" else False
    except Exception as e:
        print(f"Error checking user membership: {e}")
        return False     
def is_user_subscribed_to_both_channels(bot, user_id, channels):
    try:
        for channel_id in channels:
            member = bot.get_chat_member(channel_id, user_id)
            if member.status == "left":
                return False
        return True
    except Exception as e:
        print(f"Error checking user subscription: {e}")
        return False                          
def start(update, context):
    user_id = update.message.from_user.id
    chat_type = update.message.chat.type
    
    channels = [-1001194429691]  # Lista de canales requeridos
    
    if chat_type == 'private' or chat_type in ['group', 'supergroup']:
        # Comprobar si el usuario está en los canales requeridos
        for channel_id in channels:
            if not is_user_in_channel(context.bot, user_id, channel_id):
                context.bot.send_message(update.message.chat_id, f"Please join our channel: https://t.me/mkldec1")
                join_channel(context.bot, user_id, channel_id)
                return
        
        # Enviar mensaje de bienvenida
        send_welcome_message(update.message)

def send_welcome_message(message):
    user = message.from_user
    last_name = message.from_user.full_name
    username = user.username
    user_id = message.chat_id
    group_link = f"https://t.me/{message.chat.username}"
    
    photos = message.bot.get_user_profile_photos(user_id).photos
    photo_file_id = None
    
    try:
        if photos:
            photo_file_id = photos[0][-1].file_id
            
            message.bot.send_photo(
                message.chat_id,
                photo=photo_file_id,
                caption=f"""⚕ 𓆰 Welcome {last_name}
-  -  -  ‌-  -  -  ‌-  -  -  ‌
• 🤍 | User: @{username}
• 🍷 | Link: https://t.me/{username}
• 🐊 | ID: {user_id}
• 🦇 | Name: {last_name} 
• 🌐 | Group Link: {group_link}
-  -  -  ‌-  -  -  ‌-  -  -  ‌
🍷Developer: - @mujta1n
👑 ‌bot: - @mujta1nsshbot"""
            )
        else:
            message.bot.send_message(
                message.chat_id,
                text=f"""⚕ 𓆰 Welcome {last_name}
-  -  -  ‌-  -  -  ‌-  -  -  ‌
• 🤍 | User: @{username}
• 🍷 | Link: https://t.me/{username}
• 🐊 | ID: {user_id}
• 🦇 | Name: {last_name} 
• 🌐 | Group Link: {group_link}
-  -  -  ‌-  -  -  ‌-  -  -  ‌
🍷Developer: - @mujta1n
👑 Owner: - @mujta1nsshbot"""
            )
    except AttributeError:
        message.bot.send_message(
            message.chat_id,
            text=f"""⚕ 𓆰 Welcome {last_name}
-  -  -  ‌-  -  -  ‌-  -  -  ‌
• 🤍 | User: @{username}
• 🍷 | Link: https://t.me/{username}
• 🐊 | ID: {user_id}
• 🦇 | Name: {last_name} 
• 🌐 | Group Link: {group_link}
-  -  -  ‌-  -  -  ‌-  -  -  ‌
🍷Developer: - @mujta1n
👑 Owner: - @mujta1nsshbot"""
        )

def send_welcome_message_group(bot, message):
    bot.reply_text(
        message.chat_id,
        f"""⚕ 𓆰 Welcome to our group! Feel free to explore and engage with other members. If you have any questions, don't hesitate to ask."""
    )
        
        
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
        

def decode_ar():
    # Limpiar la terminal
    os.system("clear")

    encrypted_text_base64 = input("Enter your text ar-??: ")
    try:
        final_text = decode_message(encrypted_text_base64)
        print(final_text)
        input("Press Enter to continue...")
        os.system("clear")
    except Exception as e:
        print("Error:", e)        

def cbc_iv(data):
    data = data.replace("\n", "")
    cipher = AES.new(b'poiuytrewqas+=~|', AES.MODE_CBC, b'r4tgv3b2zcmdW6ZZ')
    decrypted_data = cipher.decrypt(base64.b64decode(data))
    return decrypted_data.decode()

def handle_message(update, context):
    message = update.message
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
        context.bot.send_message(chat_id, f"<strong>\n‌‌𝐆𝐑𝐎𝐔𝐏: https://t.me/mkldec\n======================\n{linkserver}\n======================\n ‌𝐁𝐎𝐓 : @mujta1nsshbot </strong>", parse_mode="html", reply_to_message_id=message_id)
        print(f"Sent decrypted message to chat_id: {chat_id}")
    except Exception as e:
        context.bot.send_message(chat_id, f"Oops, there was an error, bro: {str(e)}", reply_to_message_id=message_id)
        print(f"Error occurred: {str(e)}")

def decrypted_config(message):
    if message.chat.type == 'private':
        bot.reply_to(message, "\n╭◉────────────────◉\n│Lo siento, solo puedes utilizarme\n│en estos grupos:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉\n\n╭◉────────────────◉\n│I'm sorry, you can only use me\n│in these groups:\n│𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐅𝐢𝐥𝐞𝐬 📂 🔓\n│https://t.me/mkldec\n╰◉────────────────◉")
    else:
        bot.send_message(chat_id=message.chat.id, text="This feature is only available in private chats.")

def main():
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.ERROR)
    try:
        os.makedirs(FILES_DIR, exist_ok=True)
        updater = Updater("6773121743:AAGlPnaivdYdpXF6HN4NpnTojHqUhcjWNTM", use_context=True)
        start_handler = CommandHandler('start', start)
        updater.dispatcher.add_handler(start_handler)
        
        file_handler = MessageHandler(Filters.document, process_received_file)
        updater.dispatcher.add_handler(file_handler) 
        
        updater.dispatcher.add_handler(MessageHandler(Filters.text & Filters.regex(r'howdy://'), handle_message))
        updater.dispatcher.add_handler(MessageHandler(Filters.text & (Filters.regex(r'nm-vmess://') | Filters.regex(r'nm-dns://') | Filters.regex(r'nm-vless://') | Filters.regex(r'nm-trojan://') | Filters.regex(r'nm-ssr://')), decrypted_config))
        
        updater.dispatcher.add_handler(MessageHandler(Filters.text & Filters.regex(r'ar-ssh://'), handle_message))
        
        updater.start_polling()
        updater.idle()
    except Exception as e:
        logging.error(f"An exception occurred: {str(e)}")

if __name__ == '__main__':
    main()