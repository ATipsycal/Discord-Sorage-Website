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
app.config["SECRET_KEY"] = "" #Replace with your secret key


BOT_TOKEN = '' #Replace with your bot token
WEBPAGE_IP = '127.0.0.1'
PORT = '5000'
USER_CSV_FILE_PATH = 'users.csv'
NEW_MESSAGE_FETCH_WAIT_TIME = 10
guild_id = 0 #Replace with your guild id
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
        uploads[session["users"]["hashed_name"]]["dont_use_cache_save_unless_user_on_page"]= True
        client.loop.create_task(periodic_message_fetch(uploads[session["users"]["hashed_name"]]["dont_use_cache_save_unless_user_on_page"], session["users"].get("CHANNEL_ID"), session["users"].get("csv_file_path")))
    return jsonify({'onpage'})

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
    # Read the encryption key from the file
    with open('encryptionkey.key', 'rb') as filekey:
        key = filekey.read()

    fernet = Fernet(key)
    files_to_decrypt = glob.glob(os.path.join(download_folder, '*.part*'))
    for file_path in files_to_decrypt:
        try:
            with open(file_path, 'rb') as enc_file:
                encrypted = enc_file.read()

        # Decrypt the file content
            decrypted = fernet.decrypt(encrypted)

        # Write the decrypted content back to the file
            with open(file_path, 'wb') as dec_file:
                dec_file.write(decrypted)
            print("Decryption successful!")
        except:
            print("Error during decryption!")

def search_csv_file(search_text, exclude_keywords):
    input_file=session["users"].get("csv_file_path")
    matching_message_and_user_ids = []  # List to store matching message IDs and line numbers

    with open(input_file, mode='r', encoding='utf-8') as infile:
        reader = csv.reader(infile)
        found = False
        # Iterate through each row in the CSV file
        for line_number, row in enumerate(reader, start=1): 
            # Extract the first 3 columns: message_id, timestamp, user id, content
            message_id = row[0]
            timestamp = datetime.fromisoformat(row[1])
            user_id = row[2]
            content = row[3] if len(row) > 3 else ""  # Avoid errors if content is missing

            # Check if the message contains the search text and doesn't contain any exclude keywords
            if search_text in content and not any(keyword in content for keyword in exclude_keywords):        
                # Add the matching message ID and line number to the list
                if not found:
                    matching_message_and_user_ids.append((message_id, timestamp, user_id, content, line_number))
                    found = True
    return matching_message_and_user_ids

def search_csv_for_message(query):
    results = []
    # Open the CSV file and search for the query in the last column
    with open(session["users"].get("csv_file_path"), mode='r', newline='', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile)
        attachment = "Attachment"
        allfiles = "All files have been uploaded successfully!"
        for row in csvreader:
            # Assuming the content is in the last column of each row
            content = row[3]
            if (query.lower() in content.lower()) and (attachment.lower() not in content.lower()) and (allfiles.lower() not in content.lower()):
                results.append(content)
    return results

def get_last_timestamp_from_csv(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            # Get the last row in the CSV
            last_row = None
            for last_row in csv_reader:
                pass

            if last_row:
                # Extract timestamp and convert to datetime object
                last_timestamp_str = last_row[1]
                return datetime.fromisoformat(last_timestamp_str)
            else:
                # No previous entries, return None
                return None
    except FileNotFoundError:
        # If the file doesn't exist, assume it's the first run
        return None

async def createchannel(hashed_name):
        guild = discord.utils.get(client.guilds, id=guild_id)
        if guild:
            existing_channel = discord.utils.get(guild.channels, name=hashed_name)
            if not existing_channel:
                await guild.create_text_channel(name=hashed_name)
                print(f'Channel "{hashed_name}" has been created.')
            else:
               print(f'A channel with the name "{hashed_name}" already exists.')

async def periodic_message_fetch(dont_duplicate_message_fetch, CHANNEL_ID, csv_file_path ):
    while uploads[session["users"]["hashed_name"]]["dont_use_cache_save_unless_user_on_page"] == True:
        try:
            channel = client.get_channel(CHANNEL_ID)
            if channel is None:
                print(f"Could not access the channel with ID {CHANNEL_ID}")
                await asyncio.sleep(5)
                continue
            last_timestamp = get_last_timestamp_from_csv(csv_file_path)
            messages = []
            if last_timestamp is None:
                print("No previous messages found in CSV. Fetching all messages.")
                async for message in channel.history(limit=1, oldest_first=True):
                    msg_id = message.id
                    timestamp = message.created_at
                    user_id = message.author.id
                    content = message.content.replace('\n', ' ') if message.content else 'Attachment'
                    messages.append(f'{msg_id},{timestamp},{user_id},{content}')
                with open(csv_file_path, 'a', encoding='utf-8', newline='') as file:
                    csv_writer = csv.writer(file)
                    for msg in messages:
                        csv_writer.writerow(msg.split(','))
            last_timestamp = get_last_timestamp_from_csv(csv_file_path)
            print(f"Last timestamp from CSV: {last_timestamp}")

            messages = []
            if last_timestamp:
                async for message in channel.history(limit=None, after=last_timestamp):
                    msg_id = message.id
                    timestamp = message.created_at
                    user_id = message.author.id
                    content = message.content.replace('\n', ' ') if message.content else 'Attachment'
                    messages.append(f'{msg_id},{timestamp},{user_id},{content}')

            with open(csv_file_path, 'a', encoding='utf-8', newline='') as file:
                csv_writer = csv.writer(file)
                for msg in messages:
                    csv_writer.writerow(msg.split(','))

            print(f"New messages after {last_timestamp} have been saved to {csv_file_path}")
        except Exception as e:
            print(f"Error in periodic fetch: {e}")
        await asyncio.sleep(NEW_MESSAGE_FETCH_WAIT_TIME)  # Wait for NEW_MESSAGE_FETCH_WAIT_TIME seconds before fetching again


@app.route('/download')
def download():
    path = str(uploads[session["users"]["hashed_name"]]["download_file_path"])
    filename = path.replace(f"{str(session['users']['hashed_name'])}_", "")
    filename = os.path.basename(filename)
    print (path)
    print(os.path.getsize(path)/1000000)
    @after_this_request
    def remove_file(response):
        def delayed_delete(file_path):
            try:
                # Delay the deletion slightly to allow file handling to complete
                import time
                time.sleep(os.path.getsize(path)/1000000)
                os.remove(file_path)
            except Exception as error:
                print(f"Error deleting file: {error}")

        # Start a new thread to delete the file after a slight delay
        thread = threading.Thread(target=delayed_delete, args=(path,))
        thread.start()

        return response

    return send_file(path, download_name=filename, as_attachment=True)

def stitch_files(directory, *,output_file : str, base_filename : str):
    hashed_name = str(session['users']['hashed_name'])
    
    # Ensure the directory ends with a slash
    if not directory.endswith(os.path.sep):
        directory += os.path.sep

    parts = []

    # List all files in the directory and filter out the parts
    for filename in os.listdir(directory):
        if filename.startswith(base_filename) and filename != output_file:
            parts.append(filename)

    # Sort the parts by their part number
    parts.sort(key=lambda x: int(x.split('part')[-1]))

    with open(directory + output_file, 'wb') as output:
        # Iterate over each part and append contents to output file
        for part in parts:
            with open(directory + part, 'rb') as f:
                output.write(f.read())
    files_to_delete = glob.glob(os.path.join(directory, f"{hashed_name}*.part*"))

    encrypted_files = glob.glob(os.path.join(download_folder, f"{hashed_name}*.encrypted"))

    for file in encrypted_files:
        new_name = file.replace(".encrypted", "")
        os.rename(file, new_name)

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
        global uploads
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
        timestamp= matching_message[0][1]
        await download_files_from(channel, timestamp, query=query)
    else:
       print(f"No messages found with query: '{query}'")

async def download_files_from(channel, starting_message, *, query : str):
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
            stitch_files(download_folder, output_file = query, base_filename = file_name)
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
    
    # Log or process the checkbox state
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
            global uploads
            hashed_name = str(session['users']['hashed_name'])
            channel = client.get_channel(session["users"].get("CHANNEL_ID"))
            cleaned_filename = '.'.join(file.filename.split('.')[:-1])
            cleaned_filename = cleaned_filename.replace(f"{hashed_name}_", "")
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

    # If the checkbox is checked (1), encrypt the file
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
    retries = 5  # Set retry attempts
    wait_time = 5  # Wait time between retries in seconds
    global uploads
    file.filename = file.filename
    await compare_and_update(file)
    for attempt in range(retries):
        try:
            # Send the file to Discord
            message = await channel.send(file=discord.File(file.stream, filename= f"{file.filename}" ))
            print(f"File {file.filename} uploaded successfully on attempt {attempt + 1}")
            break
        except discord.errors.HTTPException as e:
            # Handle Discord API errors
            error_message = f"Error uploading file: {e}. Attempt {attempt + 1}/{retries}"
            print(error_message)
            logging.error(f"Failed to upload file: {file.filename}, Error: {e}, Attempt: {attempt + 1}/{retries}")
            if attempt < retries - 1:
                await asyncio.sleep(wait_time)
            else:
                raise
        except Exception as e:
            error_message = f"Unexpected error: {e}. Attempt {attempt + 1}/{retries}"
            print(error_message)
            logging.error(f"Unexpected failure for file: {file.filename}, Error: {e}, Attempt: {attempt + 1}/{retries}")
            if attempt < retries - 1:
                await asyncio.sleep(wait_time)
            else:
                raise
    uploads[session["users"].get("hashed_name")]["upload_queue"] -= 1
    # Once all files are uploaded, send a final message
    #if session["users"]["upload_queue"] == 0:
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

if __name__ == '__main__':
    app.run(port = PORT, host = WEBPAGE_IP)
