import socket
import ssl
import threading
import json
import uuid
import datetime
from flask import Flask, request, jsonify
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 
del warnings

from cryptography.fernet import Fernet
import mysql.connector
import hashlib
import base64
import os

# users = {}       
tokens = {}      #(username, expiry datetime) #TODO: encrypt (mostly done?)
chatrooms = {}
chatrooms_lock = threading.Lock()

# SET UP MYSQL/MARIADB CONNECTION
db = mysql.connector.connect(
    host="localhost",
    user="root",         # i hope you know what you're doing
    password="some",     
    database="omdoh_rew"  
)
cursor = db.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255))")
db.commit()
try:
    cursor.execute("ALTER TABLE users ADD COLUMN avatar VARCHAR(255)")
    db.commit()
except mysql.connector.Error:
    # if exist then eh we do not care
    pass

# SET UP TOKEN ENCRYPTION
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

# ssl
dossl=False # if you setup a self-signed certificate, set it to False, because yeah self-explanatory (only for Flask tho)
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.pem")

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user by posting application/json:
    { "username": "user", "password": "pass" }
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        return jsonify({"error": "User already exists"}), 400
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
    db.commit()
    return jsonify({"status": "Registered successfully"})

@app.route('/login', methods=['POST'])
def login():
    """
    Log in using:
    { "username": "user", "password": "pass" }
    Returns an access token (and expiry) valid for 24 hours.
    Also returns the avatar filename (hash+extension) if set.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if not user or user[1] != hashed_password:
        return jsonify({"error": "Invalid credentials"}), 401
    raw_token = uuid.uuid4().hex
    token = cipher.encrypt(raw_token.encode()).decode()  # token encrypted and Base64'ed by Fernet
    expires = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    tokens[token] = (username, expires)
    # filename return.
    cursor.execute("SELECT avatar FROM users WHERE username = %s", (username,))
    r = cursor.fetchone()
    avatar_filename = r[0] if r and r[0] is not None else ""
    return jsonify({"access_token": token, "expires": expires.isoformat(), "avatar": avatar_filename})

@app.route('/status', methods=['GET'])
def status():
    # GET STATUS: registered users and connected clients
    cursor.execute("SELECT COUNT(*) FROM users")
    registered = cursor.fetchone()[0]
    
    with chatrooms_lock:
        unique_connections = set()
        for room, conns in chatrooms.items():
            unique_connections.update(conns)
        connected = len(unique_connections)
    
    return jsonify({"registered": registered, "connected": connected})

@app.route('/send_contact_request', methods=['POST'])
def send_contact_request():
    """
    Send a contact request.
    Expects application/json:
    { "token": "some-token", "contact": "target_username" }
    If a reciprocal request exists, both requests are replaced by a confirmed contact.
    """
    data = request.get_json()
    token = data.get("token")
    contact = data.get("contact")
    if not token or not contact:
        return jsonify({"error": "Missing token or contact username"}), 400
    if token not in tokens:
        return jsonify({"error": "Invalid token"}), 401
    sender, _ = tokens[token]
    cursor.execute("SELECT * FROM users WHERE username = %s", (contact,))
    if not cursor.fetchone():
        return jsonify({"error": "Contact not found"}), 404
    try:
        cursor.execute("CREATE TABLE IF NOT EXISTS contact_requests (sender VARCHAR(255), receiver VARCHAR(255), PRIMARY KEY (sender, receiver))")
        db.commit()
    except mysql.connector.Error as e:
        return jsonify({"error": "DB error: " + str(e)}), 500
    cursor.execute("SELECT * FROM contact_requests WHERE sender = %s AND receiver = %s", (contact, sender))
    reciprocal = cursor.fetchone()
    if reciprocal:
        cursor.execute("DELETE FROM contact_requests WHERE sender = %s AND receiver = %s", (contact, sender))
        try:
            cursor.execute("CREATE TABLE IF NOT EXISTS contacts (user1 VARCHAR(255), user2 VARCHAR(255), PRIMARY KEY (user1, user2))")
            db.commit()
        except mysql.connector.Error as e:
            return jsonify({"error": "DB error while creating contacts: " + str(e)}), 500
        user1, user2 = sorted([sender, contact])
        cursor.execute("INSERT IGNORE INTO contacts (user1, user2) VALUES (%s, %s)", (user1, user2))
        db.commit()
        return jsonify({"status": "Contact added"}), 200
    else:
        cursor.execute("INSERT IGNORE INTO contact_requests (sender, receiver) VALUES (%s, %s)", (sender, contact))
        db.commit()
        return jsonify({"status": "Contact request sent"}), 200

@app.route('/get_contacts', methods=['POST'])
def get_contacts():
    """
    Get the contacts list for the authenticated user.
    Expects application/json: { "token": "some-token" }
    Returns list of contacts.
    """
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"error": "Missing token"}), 400
    if token not in tokens:
        return jsonify({"error": "Invalid token"}), 401
    username, _ = tokens[token]
    cursor.execute("CREATE TABLE IF NOT EXISTS contacts (user1 VARCHAR(255), user2 VARCHAR(255), PRIMARY KEY (user1, user2))")
    db.commit()
    cursor.execute("SELECT user1, user2 FROM contacts WHERE user1 = %s OR user2 = %s", (username, username))
    rows = cursor.fetchall()
    contacts = []
    for user1, user2 in rows:
        if user1 == username:
            contacts.append(user2)
        else:
            contacts.append(user1)
    return jsonify({"contacts": contacts}), 200

@app.route('/update_status', methods=['POST'])
def update_status():
    """
    Update user's status message.
    Expects application/json: { "token": "some-token", "status": "I am busy" }
    """
    data = request.get_json()
    token = data.get("token")
    status_msg = data.get("status")
    if not token or status_msg is None:
        return jsonify({"error": "Missing token or status"}), 400
    if token not in tokens:
        return jsonify({"error": "Invalid token"}), 401
    username, _ = tokens[token]
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN status VARCHAR(255)")
        db.commit()
    except mysql.connector.Error:
        pass
    cursor.execute("UPDATE users SET status = %s WHERE username = %s", (status_msg, username))
    db.commit()
    return jsonify({"status": "Status updated"}), 200

@app.route('/get_status', methods=['POST'])
def get_status():
    """
    Get status of a given user.
    Expects application/json: { "username": "some-user" }
    """
    data = request.get_json()
    user = data.get("username")
    if not user:
        return jsonify({"error": "Missing username"}), 400
    cursor.execute("SELECT status FROM users WHERE username = %s", (user,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"username": user, "status": row[0] if row[0] else ""}), 200

@app.route('/contacts_status', methods=['POST'])
def contacts_status():
    """
    Get statuses and avatars of all contacts for the authenticated user.
    Expects application/json: { "token": "some-token" }
    """
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"error": "Missing token"}), 400
    if token not in tokens:
        return jsonify({"error": "Invalid token"}), 401
    username, _ = tokens[token]
    cursor.execute("CREATE TABLE IF NOT EXISTS contacts (user1 VARCHAR(255), user2 VARCHAR(255), PRIMARY KEY (user1, user2))")
    db.commit()
    cursor.execute("SELECT user1, user2 FROM contacts WHERE user1 = %s OR user2 = %s", (username, username))
    rows = cursor.fetchall()
    contacts = []
    for user1, user2 in rows:
        contact = user2 if user1 == username else user1
        # status and avatar
        cursor.execute("SELECT status, avatar FROM users WHERE username = %s", (contact,))
        r = cursor.fetchone()
        if r:
            status = r[0] if r[0] is not None else ""
            avatar = r[1] if r[1] is not None else ""
        else:
            status, avatar = "", ""
        contacts.append({"username": contact, "status": status, "avatar": avatar})
    return jsonify({"contacts": contacts}), 200


@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    """
    Upload avatar image. Expects multipart form-data with fields:
      - token: the user's access token
      - avatar: the image file (gif functionality supported)
    Saves file to permanent storage in the "avatars" folder and updates the user's avatar info in the database (hash+extension).
    """
    if 'avatar' not in request.files:
        return jsonify({"error": "No avatar file provided"}), 400
    token = request.form.get("token")
    if not token:
        return jsonify({"error": "Token required"}), 400
    if token not in tokens:
        return jsonify({"error": "Invalid token"}), 401
    username, _ = tokens[token]
    
    file = request.files['avatar']
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    file_bytes = file.read()
    if not file_bytes:
        return jsonify({"error": "Empty file"}), 400
        
    # compute file hash to use as avatar filename
    avatar_hash = hashlib.sha256(file_bytes).hexdigest()
    original_filename = file.filename
    ext = ''
    if '.' in original_filename:
        ext = '.' + original_filename.rsplit('.', 1)[1].lower()
    allowed_ext = ['.png', '.jpg', '.jpeg', '.gif']
    if ext not in allowed_ext:
        return jsonify({"error": "Unsupported file type"}), 400
        
    avatars_folder = os.path.join(os.getcwd(), "avatars")
    if not os.path.exists(avatars_folder):
        os.makedirs(avatars_folder)
        
    avatar_filename = avatar_hash + ext
    filepath = os.path.join(avatars_folder, avatar_filename)
    with open(filepath, 'wb') as f:
        f.write(file_bytes)
        
    # update user record with avatar filename, add avatar column if needed
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN avatar VARCHAR(255)")
        db.commit()
    except mysql.connector.Error:
        pass
    cursor.execute("UPDATE users SET avatar = %s WHERE username = %s", (avatar_filename, username))
    db.commit()
    return jsonify({"status": "Avatar uploaded", "avatar": avatar_filename})

@app.route('/avatars/<avatar_filename>', methods=['GET'])
def get_avatar(avatar_filename):
    """
    Retrieve avatar image by filename.
    """
    from flask import send_from_directory
    avatars_folder = os.path.join(os.getcwd(), "avatars")
    return send_from_directory(avatars_folder, avatar_filename)


def handle_client(connection):
    """
    Handles each secure TCP client.
    
    Client workflow:
      - Sends an initial JSON with the access token: { "token": "..." }
      - Receives confirmation and then sends commands:
          • Join room: { "command": "join", "room": "room_name" }
          • Send message: { "command": "message", "room": "room_name", "message": "text" }
    """
    try:
        file = connection.makefile('r')
        # read the first line and authenticate using the access token.
        auth_line = file.readline()
        if not auth_line:
            connection.close()
            return
        try:
            auth_msg = json.loads(auth_line)
        except json.JSONDecodeError:
            connection.sendall(json.dumps({"error": "Invalid JSON format"}).encode() + b"\n")
            connection.close()
            return

        token = auth_msg.get("token")
        if token not in tokens:
            connection.sendall(json.dumps({"error": "Invalid token"}).encode() + b"\n")
            connection.close()
            return
        username, expires = tokens[token]
        if datetime.datetime.utcnow() > expires:
            connection.sendall(json.dumps({"error": "Expired token"}).encode() + b"\n")
            connection.close()
            return

        connection.sendall(json.dumps({"status": "Authenticated", "username": username}).encode() + b"\n")
        current_rooms = set()

        # process client commands.
        while True:
            line = file.readline()
            if not line:
                break  # disconnected
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                connection.sendall(json.dumps({"error": "Invalid JSON format"}).encode() + b"\n")
                continue

            command = msg.get("command")
            print(line)
            if command == "join":
                room = msg.get("room")
                if room:
                    # no stalking!!!
                    if room.startswith("private:"):
                        allowed_users = room[len("private:"):].split("_")
                        if username not in allowed_users:
                            connection.sendall(json.dumps({"error": "Unauthorized to join this private chat"}).encode() + b"\n")
                            continue
                    with chatrooms_lock:
                        if room not in chatrooms:
                            chatrooms[room] = []
                        chatrooms[room].append(connection)
                    current_rooms.add(room)
                    connection.sendall(json.dumps({"status": f"Joined room {room}"}).encode() + b"\n")
                else:
                    connection.sendall(json.dumps({"error": "No room specified"}).encode() + b"\n")
            elif command == "message":
                room = msg.get("room")
                message_text = msg.get("message")
                if room and message_text:
                    broadcast = json.dumps({
                        "room": room,
                        "username": username,
                        "message": message_text,
                        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
                    })
                    with chatrooms_lock:
                        recipients = chatrooms.get(room, [])
                        for sock in recipients:
                            try:
                                sock.sendall(broadcast.encode() + b"\n")
                            except Exception as e:
                                print("Error broadcasting to a client:", e)
                else:
                    connection.sendall(json.dumps({"error": "Missing room or message"}).encode() + b"\n")
            else:
                connection.sendall(json.dumps({"error": "Unknown command"}).encode() + b"\n")
    except Exception as e:
        print("Error in client handler:", e)
    finally:
        # clean chatroom connection
        with chatrooms_lock:
            for room in current_rooms:
                if room in chatrooms and connection in chatrooms[room]:
                    chatrooms[room].remove(connection)
        connection.close()

def start_tcp_server():
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.bind(("0.0.0.0", 6000))
    tcp_server.listen(5)
    print("omdoh TCP server listening on port 6000...")

    while True:
        client_sock, addr = tcp_server.accept()
        try:
            secure_conn = context.wrap_socket(client_sock, server_side=True)
            print("Accepted secure connection from", addr)
            threading.Thread(target=handle_client, args=(secure_conn,), daemon=True).start()
        except Exception as e:
            print("Failed to establish secure connection:", e)
            client_sock.close()

if __name__ == "__main__":
    # Start the omdoh TCP server
    tcp_thread = threading.Thread(target=start_tcp_server, daemon=True)
    tcp_thread.start()
    # make general chatroom:
    chatrooms["General"]=[] # please worky :)

    # omdoh http (for login, register)
    print("HTTP server listening on port 5000...")
    if dossl==True: 
        app.run(host="0.0.0.0", port=5000, ssl_context=context)
    else: 
        app.run(host="0.0.0.0", port=5000)
