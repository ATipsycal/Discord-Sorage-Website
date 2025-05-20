from flask import Flask, request, session, jsonify, render_template, redirect, url_for, send_file, after_this_request
from flask_session import Session
from cryptography.fernet import Fernet
from werkzeug.datastructures import FileStorage
import discord
import os
import aiohttp
import asyncio
import threading
import time
from datetime import timedelta
import logging
from datetime import datetime
from concurrent.futures import CancelledError
import glob
import argparse
import hashlib
import csv
import io



if not os.path.isfile("encryptionkey.key"):

    key = Fernet.generate_key()
 
    # Write key in a file - !!! DON'T LOSE THE KEY OR THE FILES CAN'T BE DECRYPTED !!!
    with open('encryptionkey.key', 'wb') as filekey:
        filekey.write(key)



app = Flask(__name__)
app.config["SECRET_KEY"] = ""


BOT_TOKEN = '' #Replace with your bot token
WEBPAGE_IP = '127.0.0.1'
PORT = '5000'
USER_CSV_FILE_PATH = 'users.csv'
NEW_MESSAGE_FETCH_WAIT_TIME = 10
guild_id =  #replace with discord server id
# Initialize Discord client
intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
client = discord.Client(intents=intents)
uploads = {}

@app.route('/user_on_page', methods=['POST'])
def user_on_page():
    print(f"user {session["users"]["hashed_name"]} still on page")
    if uploads[session["users"]["hashed_name"]]["dont_use_cache_save_unless_user_on_page"] == False :
        uploads[session["users"]["hashed_name"]]["dont_use_cache_save_unless_user_on_page"] = True
        client.loop.create_task(periodic_message_fetch(uploads[session["users"]["hashed_name"]]["dont_use_cache_save_unless_user_on_page"], session["users"].get("CHANNEL_ID"), session["users"].get("csv_file_path")))
    return jsonify({'onpage'}), 204

@app.route('/user_left', methods=['POST'])
def user_left():
    global uploads
    uploads[session["users"]["hashed_name"]]["dont_use_cache_save_unless_user_on_page"]= False
    print(f"user {session["users"]["hashed_name"]} left")
    return '', 204

def encryptfile(path : str):
    with open('encryptionkey.key', 'rb') as filekey:
        key = filekey.read()

    fernet = Fernet(key)

    with open(path, 'rb') as file:
        original = file.read()

    encrypted = fernet.encrypt(original)

    with open(path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def decryptfiles(filen):
    with open('encryptionkey.key', 'rb') as filekey:
        key = filekey.read()

    fernet = Fernet(key)
    files_to_decrypt = glob.glob(os.path.join(download_folder, '*.part*'))
    for file_path in files_to_decrypt:
        try:
            with open(file_path, 'rb') as enc_file:
                encrypted = enc_file.read()
            decrypted = fernet.decrypt(encrypted)
            with open(file_path, 'wb') as dec_file:
                dec_file.write(decrypted)
            print("Decryption successful!")
        except Exception as e:
            print(f"Error during decryption: {e}")

def search_csv_file(search_text, exclude_keywords):
    input_file = session["users"].get("csv_file_path")
    matching_message_and_user_ids = []

    with open(input_file, mode='r', encoding='utf-8') as infile:
        reader = csv.reader(infile)
        for row in reader:
            message_id, timestamp, user_id, content = row[0], datetime.fromisoformat(row[1]), row[2], row[3] if len(row) > 3 else ""
            if search_text in content and not any(keyword in content for keyword in exclude_keywords):
                matching_message_and_user_ids.append((message_id, timestamp, user_id, content))
                break
    return matching_message_and_user_ids

def search_csv_for_message(query):
    results = []
    with open(session["users"].get("csv_file_path"), mode='r', newline='', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            content = row[3]
            if query.lower() in content.lower() and "attachment" not in content.lower() and "all files have been uploaded successfully!" not in content.lower():
                results.append(content)
    return results

def get_last_timestamp_from_csv(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            last_row = None
            for last_row in csv_reader:
                pass
            if last_row:
                return datetime.fromisoformat(last_row[1])
    except FileNotFoundError:
        return None

async def createchannel(hashed_name):
    guild = discord.utils.get(client.guilds, id=guild_id)
    if guild:
        existing_channel = discord.utils.get(guild.channels, name=hashed_name)
        if not existing_channel:
            await guild.create_text_channel(name=hashed_name)
            print(f'Channel "{hashed_name}" has been created.')

async def periodic_message_fetch(dont_duplicate_message_fetch, CHANNEL_ID, csv_file_path):
    while uploads[session["users"]["hashed_name"]]["dont_use_cache_save_unless_user_on_page"]:
        try:
            channel = client.get_channel(CHANNEL_ID)
            if not channel:
                print(f"Could not access the channel with ID {CHANNEL_ID}")
                await asyncio.sleep(5)
                continue
            last_timestamp = get_last_timestamp_from_csv(csv_file_path)
            messages = []
            if last_timestamp is None:
                print("No previous messages found in CSV. Fetching all messages.")
                async for message in channel.history(limit=1, oldest_first=True):
                    messages.append([message.id, message.created_at, message.author.id, message.content.replace('\n', ' ') if message.content else 'Attachment'])
                with open(csv_file_path, 'a', encoding='utf-8', newline='') as file:
                    csv_writer = csv.writer(file)
                    csv_writer.writerows(messages)
            last_timestamp = get_last_timestamp_from_csv(csv_file_path)
            print(f"Last timestamp from CSV: {last_timestamp}")

            messages = []
            if last_timestamp:
                async for message in channel.history(limit=None, after=last_timestamp):
                    messages.append([message.id, message.created_at, message.author.id, message.content.replace('\n', ' ') if message.content else 'Attachment'])

            with open(csv_file_path, 'a', encoding='utf-8', newline='') as file:
                csv_writer = csv.writer(file)
                csv_writer.writerows(messages)

            print(f"New messages after {last_timestamp} have been saved to {csv_file_path}")
        except Exception as e:
            print(f"Error in periodic fetch: {e}")
        await asyncio.sleep(NEW_MESSAGE_FETCH_WAIT_TIME)

@app.route('/download')
def download():
    path = str(uploads[session["users"]["hashed_name"]]["download_file_path"])
    filename = os.path.basename(path).replace(f"{str(session['users']['hashed_name'])}_", "")
    print(path)
    print(os.path.getsize(path) / 1000000)

    @after_this_request
    def remove_file(response):
        def delayed_delete(file_path):
            try:
                time.sleep(os.path.getsize(path) / 1000000)
                os.remove(file_path)
            except Exception as error:
                print(f"Error deleting file: {error}")

        threading.Thread(target=delayed_delete, args=(path,)).start()
        return response

    return send_file(path, download_name=filename, as_attachment=True)

def stitch_files(directory, *, output_file: str, base_filename: str):
    hashed_name = str(session['users']['hashed_name'])
    if not directory.endswith(os.path.sep):
        directory += os.path.sep

    parts = [filename for filename in os.listdir(directory) if filename.startswith(base_filename) and filename != output_file]
    parts.sort(key=lambda x: int(x.split('part')[-1]))

    with open(directory + output_file, 'wb') as output:
        for part in parts:
            with open(directory + part, 'rb') as f:
                output.write(f.read())

    files_to_delete = glob.glob(os.path.join(directory, f"{hashed_name}*.part*"))
    encrypted_files = glob.glob(os.path.join(download_folder, f"{hashed_name}*.encrypted"))

    for file in encrypted_files:
        os.rename(file, file.replace(".encrypted", ""))

    for file_path in files_to_delete:
        try:
            os.remove(file_path)
            print(f"Deleted: {file_path}")
        except Exception as e:
            print(f"Error deleting {file_path}: {e}")

    files_to_delete = glob.glob(os.path.join(directory, f"{hashed_name}*.encrypted*"))
    for file_path in files_to_delete:
        try:
            os.remove(file_path)
            print(f"Deleted: {file_path}")
        except Exception as e:
            print(f"Error deleting {file_path}: {e}")

    filepath = directory + output_file
    print(f"Stitched {len(parts)} parts into {output_file}")
    if os.path.exists(filepath):
        uploads[session["users"]["hashed_name"]]["download_file_path"] = filepath
    else:
        print("File not found")
        return "File not found", 404

# Create the "downloaded" folder if it doesn't exist
download_folder = os.path.join(os.getcwd(), "downloaded")
if not os.path.exists(download_folder):
    os.makedirs(download_folder)

# Create the "uploaded" folder if it doesn't exist    
upload_folder = os.path.join(os.getcwd(), "uploaded")
if not os.path.exists(upload_folder):
    os.makedirs(upload_folder)

async def search_message(*, query: str):
    exclude_keywords = []
    matching_message = search_csv_file(query, exclude_keywords)
    channel = client.get_channel(session["users"].get("CHANNEL_ID"))
    if matching_message:
        found_message_id = matching_message[0][0]
        if found_message_id:
            print(f"Message found: {matching_message[0][3]} (Sent by: {matching_message[0][2]})")
            timestamp = matching_message[0][1]
            await download_files_from(channel, timestamp, query=query)
        else:
            print(f"No messages found with query: '{query}'")

async def download_files_from(channel, starting_message, *, query: str):
    async for message in channel.history(limit=None, after=starting_message):
        if message.attachments:
            for attachment in message.attachments:
                file_url = attachment.url
                file_name = attachment.filename
                async with aiohttp.ClientSession() as session:
                    async with session.get(file_url) as resp:
                        if resp.status == 200:
                            file_path = os.path.join(download_folder, file_name)
                            with open(file_path, "wb") as f:
                                f.write(await resp.read())
        else:
            tempFileName = file_name.split(".part")
            file_name = tempFileName[0]
            if ".encrypted" in file_path:
                decryptfiles(file_name)
                tempFileName = file_name.split(".encrypted")
                file_name = tempFileName[0]
            stitch_files(download_folder, output_file=query, base_filename=file_name)
            print("No more files found. Stopping the download process.")
            break

@app.route('/upload_parts', methods=['POST'])
def upload_parts():
    data = request.get_json()
    session["users"]["upload_queue"] = int(data.get('total_parts'))
    print(f'Total Parts Received: {session["users"]["upload_queue"]}')
    session.modified = True

@app.route('/search', methods=['POST'])
def search():
    query = request.form.get('query')
    if query:
        results = search_csv_for_message(query)
        return render_template('index.html', results=results, query=query)
    return render_template('index.html', results=[], query='')

@app.route('/store_click', methods=['POST'])
def store_click():
    session["users"]["clicked_message"] = request.json.get('clicked_message')
    print(f"Clicked message stored: {session["users"].get("clicked_message")}")
    if session["users"].get("clicked_message"):
        asyncio.run_coroutine_threadsafe(search_message(query=session["users"].get("clicked_message")), client.loop)
    return jsonify({'status': 'success', 'message': 'Message stored successfully'})

@app.route('/submit_checkbox', methods=['POST'])
def submit_checkbox():
    session["users"]["checkbox_state"] = int(request.form.get('checkbox1'))
    session.modified = True
    
    #Checkbox state
    if session["users"].get("checkbox_state") == 1 :
        print("Encryption is enabled")
    else:
        print("Encryption is disabled")

lock = asyncio.Lock()

logging.basicConfig(filename='file_upload_failures.log', 
                    level=logging.ERROR,
                    format='%(asctime)s %(message)s')

@app.route('/')
def hello_world():
    return render_template("login.html")


def load_users_from_csv(filepath):
    users_file = {}
    if os.path.exists(filepath):
        with open(filepath, mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) >= 2:
                    username, password, channel_id = row[0], row[1], row[2]
                    users_file[username] = {
                        "password": password,
                        "login_channel_id": channel_id  # Store channel_id under each username
                    }
    return users_file

@app.route('/form_login', methods=['POST'])
def login():
    database = load_users_from_csv(USER_CSV_FILE_PATH)
    username = request.form['username']
    password = request.form['password']
    hashed_username = hashlib.sha256(username.encode()).hexdigest()
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
    clicked_message = 'A'
    dont_duplicate_message_fetch = False
    upload_queue = 0
    CHANNEL_ID = 0
    csv_file_path = "A"
    checkbox_state = 0
    global uploads
    download_file_path = ""

    # Check if a dictionary of users exists in the session, create one if not
    if "users" not in session:
        session["users"] = {}

    # Store or update the user's information in the session
    session["users"] = {
        "hashed_name": hashed_username,
        "hashed_pwd" : hashed_pwd,
        "clicked_message" : clicked_message,
        "dont_duplicate_message_fetch" : dont_duplicate_message_fetch,
        "upload_queue" : int(upload_queue),
        "csv_file_path" : csv_file_path,
        "CHANNEL_ID" : CHANNEL_ID,
        "checkbox_state" : int(checkbox_state)
    }
    if session["users"].get("hashed_name") not in database:
        return render_template('login.html', info='Invalid User')
    elif database[session["users"].get("hashed_name")].get("password") != session["users"].get("hashed_pwd"):
        return render_template('login.html', info='Invalid Password')
    else:
        uploads[session["users"]["hashed_name"]] = {
            "hashed_name": hashed_username,
            "upload_queue": 0,
            "cleaned_filename_copy" : "sagsagfsdghfsfdsfsdfbgfruihhoibrojivefojbjcdbjscjbikorioighobvjefvbjk",
            "dont_use_cache_save_unless_user_on_page" : True,
            "download_file_path" : download_file_path
        }
        session["users"]["csv_file_path"] = f"userCache/{session["users"].get("hashed_name")}_message_cache.csv" 
        session["users"]["CHANNEL_ID"] = int(database[session["users"].get("hashed_name")]["login_channel_id"])
        session["users"]["dont_duplicate_message_fetch"] = True
        client.loop.create_task(periodic_message_fetch(uploads[session["users"]["hashed_name"]]["dont_use_cache_save_unless_user_on_page"], session["users"].get("CHANNEL_ID"), session["users"].get("csv_file_path")))
        return render_template('index.html', name=session["users"].get(hashed_username))

@app.route('/register')
def register():
    return render_template("register.html")

@app.route('/form_register', methods=['POST'])
def form_register():
    database = load_users_from_csv(USER_CSV_FILE_PATH)
    username = request.form['username']
    password = request.form['password']
    hashed_username = hashlib.sha256(username.encode()).hexdigest()
    hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
    clicked_message = 'A'
    dont_duplicate_message_fetch = False
    upload_queue = 0
    CHANNEL_ID = 0
    csv_file_path = "A"
    checkbox_state = 0

    # Check if a dictionary of users exists in the session, create one if not
    if "users" not in session:
        session["users"] = {}

    # Store or update the user's information in the session
    session["users"] = {
        "hashed_name": hashed_username,
        "hashed_pwd" : hashed_pwd,
        "clicked_message" : clicked_message,
        "dont_duplicate_message_fetch" : dont_duplicate_message_fetch,
        "upload_queue" : int(upload_queue),
        "csv_file_path" : csv_file_path,
        "CHANNEL_ID" : CHANNEL_ID,
        "checkbox_state" : int(checkbox_state)
    }

    if session["users"].get("hashed_name") in database:
        return render_template('register.html', info='User already exists')

    # Write the new user to the CSV file
    with open(USER_CSV_FILE_PATH, mode='a', newline='') as file:
        future = asyncio.run_coroutine_threadsafe(createchannel(session["users"].get("hashed_name")), client.loop)
        try:
            future.result()  # Wait for the coroutine to finish and return its result
        except Exception as e:
            print(f"Error creating channel: {e}")
        writer = csv.writer(file)
        guild = discord.utils.get(client.guilds, id=guild_id)
        channel = discord.utils.get(guild.channels, name = session["users"].get("hashed_name"))
        writer.writerow([session["users"].get("hashed_name"), session["users"].get("hashed_pwd"),channel.id])

    # Create a new CSV file for the user
    user_file_path = f"userCache/{session["users"].get("hashed_name")}_message_cache.csv"
    if not os.path.exists(user_file_path):
        with open(user_file_path, mode='w', newline='') as user_file:
            writer = csv.writer(user_file)
    return redirect(url_for('hello_world'))

def start_discord_bot():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    @client.event
    async def on_ready():
        print(f'Logged in as {client.user}')

    loop.run_until_complete(client.start(BOT_TOKEN))

async def compare_and_update(file):
    async with lock:
        hashed_name = str(session['users']['hashed_name'])
        channel = client.get_channel(session["users"].get("CHANNEL_ID"))
        cleaned_filename = '.'.join(file.filename.split('.')[:-1]).replace(f"{hashed_name}_", "")
        print(cleaned_filename)
        if cleaned_filename != uploads[session["users"]["hashed_name"]]["cleaned_filename_copy"]:
            await channel.send(cleaned_filename)
        uploads[session["users"]["hashed_name"]]["cleaned_filename_copy"] = cleaned_filename

# Run Discord client in a background thread
threading.Thread(target=start_discord_bot, daemon=True).start()


@app.route('/upload', methods=['POST'])
def upload_file(): 
    hashed_name = str(session['users']['hashed_name'])
    # Access the uploaded file
    file = request.files['file']
    file.filename = f"{hashed_name}_" + file.filename
    global uploads
    uploads[session["users"].get("hashed_name")]["upload_queue"] += 1

    # If the checkbox is checked, encrypt the file
    if int(session["users"].get("checkbox_state")) == 1:
        filepath = os.path.join(upload_folder, file.filename)
    # Save the file to the file system
        file.save(filepath)
        file.seek(0)
        print("Encrypting the file...")
        encryptfile(filepath)

        # Read the encrypted file into memory
        with open(filepath, 'rb') as file_stream:
            file_data = file_stream.read()

        # Use io.BytesIO to keep the encrypted file in memory
        memory_file = io.BytesIO(file_data)

        # Create a new FileStorage object from the in-memory encrypted file
        file = FileStorage(
            stream=memory_file,
            filename=file.filename
        )
        file.seek(0)
    # Ensure the Discord client is ready before attempting to send
    if not client.is_closed():
        try:
            future = asyncio.run_coroutine_threadsafe(send_file_to_discord(file), client.loop)
            result = future.result()  # Wait for the coroutine to finish and return its result
            return jsonify({'message': 'File uploaded successfully!'})
        except CancelledError:
            return jsonify({'error': 'Task was cancelled due to an error.'}), 500
        except Exception as e:
            print(f"Error during upload: {e}")
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Discord client is closed.'}), 500

async def send_file_to_discord(file):
    channel = client.get_channel(session["users"].get("CHANNEL_ID"))
    retries = 5
    wait_time = 5
    file.filename = file.filename
    await compare_and_update(file)
    # Add initial delay before first upload attempt
    await asyncio.sleep(1)
    
    # Store the original file data
    file_data = file.read()
    
    for attempt in range(retries):
        try:
            # Create a new BytesIO object with the file data for each attempt
            file_stream = io.BytesIO(file_data)
            message = await channel.send(file=discord.File(file_stream, filename=file.filename))
            print(f"File {file.filename} uploaded successfully on attempt {attempt + 1}")
            # Add delay after successful upload
            await asyncio.sleep(1)
            break
        except discord.errors.HTTPException as e:
            print(f"Error uploading file: {e}. Attempt {attempt + 1}/{retries}")
            logging.error(f"Failed to upload file: {file.filename}, Error: {e}, Attempt: {attempt + 1}/{retries}")
            if attempt < retries - 1:
                await asyncio.sleep(wait_time)
            else:
                raise
        except Exception as e:
            print(f"Unexpected error: {e}. Attempt {attempt + 1}/{retries}")
            logging.error(f"Unexpected failure for file: {file.filename}, Error: {e}, Attempt: {attempt + 1}/{retries}")
            if attempt < retries - 1:
                await asyncio.sleep(wait_time)
            else:
                raise
    uploads[session["users"].get("hashed_name")]["upload_queue"] -= 1
    if uploads[session["users"].get("hashed_name")]["upload_queue"] == 0:
        hashed_name = str(session['users']['hashed_name'])
        files_to_delete = glob.glob(os.path.join(upload_folder, f"{hashed_name}_*part*"))
        for file_path in files_to_delete:
            try:
                os.remove(file_path)
                print(f"Deleted: {file_path}")
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")
        await channel.send("All files have been uploaded successfully!")

@app.route('/download_selected_files', methods=['POST'])
def download_selected_files():
    data = request.get_json()
    selected_files = data.get('files', [])
    print("Selected files:", selected_files)  # Debugging line
    if not selected_files:
        return jsonify({'success': False, 'error': 'No files selected'}), 400

    download_urls = []
    for file in selected_files:
        matching_message = search_csv_file(file, [])
        if matching_message:
            found_message_id = matching_message[0][0]
            timestamp = matching_message[0][1]
            asyncio.run_coroutine_threadsafe(download_files_from(client.get_channel(session["users"].get("CHANNEL_ID")), timestamp, query=file), client.loop).result()
            stitched_file_path = os.path.join(download_folder, file)
            if os.path.exists(stitched_file_path):
                if stitched_file_path.endswith(".encrypted"):
                    new_stitched_file_path = stitched_file_path.replace(".encrypted", "")
                    os.rename(stitched_file_path, new_stitched_file_path)
                    stitched_file_path = new_stitched_file_path
                download_url = url_for('download_file', filename=os.path.basename(stitched_file_path))
                download_urls.append({'name': os.path.basename(stitched_file_path), 'url': download_url})
            else:
                return jsonify({'success': False, 'error': f'File not found: {file}'}), 404
        else:
            return jsonify({'success': False, 'error': f'File not found: {file}'}), 404

    return jsonify({'success': True, 'files': download_urls})

@app.route('/download_file/<filename>')
def download_file(filename):
    file_path = os.path.join(download_folder, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return 'File not found', 404

@app.route('/show_all_files')
def show_all_files():
    results = search_csv_for_message('')
    return render_template('index.html', results=results, query='')

if __name__ == '__main__':
    app.run(port = PORT, host = WEBPAGE_IP)