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

# temporary storage
# TODO: use mysql/mariadb
users = {}       
tokens = {}      #(username, expiry datetime) #TODO: encrypt
chatrooms = {}
chatrooms_lock = threading.Lock()

# ssl
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
    if username in users:
        return jsonify({"error": "User already exists"}), 400
    users[username] = password
    return jsonify({"status": "Registered successfully"})

@app.route('/login', methods=['POST'])
def login():
    """
    Log in using:
    { "username": "user", "password": "pass" }
    Returns an access token (and expiry) valid for 24 hours.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if username not in users or users[username] != password:
        return jsonify({"error": "Invalid credentials"}), 401
    token = uuid.uuid4().hex
    expires = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    tokens[token] = (username, expires)
    return jsonify({"access_token": token, "expires": expires.isoformat()})

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
    app.run(host="0.0.0.0", port=5000)
