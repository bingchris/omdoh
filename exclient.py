import tkinter as tk
from tkinter import messagebox, ttk
import requests
import socket
import ssl
import json
import threading

# config
HTTP_LOGIN_URL = "http://127.0.0.1:5000/login" # replace with a real URL if in production
TCP_HOST = "127.0.0.1"
TCP_PORT = 6000

class LoginWindow:
    def __init__(self, master):
        self.master = master
        master.title("omdoh login")
        master.geometry("300x150")

        tk.Label(master, text="Username:").pack(pady=(10, 0))
        self.username_entry = tk.Entry(master)
        self.username_entry.pack()

        tk.Label(master, text="Password:").pack(pady=(10, 0))
        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.pack()

        tk.Button(master, text="Login", command=self.login).pack(pady=10)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return

        try:
            response = requests.post(HTTP_LOGIN_URL, json={
                "username": username,
                "password": password
            })
        except Exception as e:
            messagebox.showerror("HTTP Error", f"Failed to contact server: {e}")
            return

        if response.status_code != 200:
            messagebox.showerror("Login Failed", f"{response.json().get('error', 'Unknown error')}")
            return

        token = response.json().get("access_token")
        if not token:
            messagebox.showerror("Login Failed", "No token received.")
            return

        try:
            # connect securelely :+1:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            self.ssl_sock = ssl_context.wrap_socket(sock, server_hostname=TCP_HOST)
            self.ssl_sock.connect((TCP_HOST, TCP_PORT))
        except Exception as e:
            messagebox.showerror("TCP Error", f"Could not connect to TCP server: {e}")
            return

        try:
            # auth token
            auth_msg = json.dumps({"token": token}) + "\n"
            self.ssl_sock.sendall(auth_msg.encode())
            self.sock_file = self.ssl_sock.makefile("r")
            auth_reply = self.sock_file.readline()
            if not auth_reply:
                raise Exception("No response from server.")
            reply = json.loads(auth_reply)
            if "error" in reply:
                messagebox.showerror("Authentication Failed", reply["error"])
                self.ssl_sock.close()
                return
        except Exception as e:
            messagebox.showerror("Authentication Error", str(e))
            self.ssl_sock.close()
            return

        # the device connectede successfully.
        self.master.destroy()
        ChatWindow(username, self.ssl_sock, self.sock_file)

class ChatWindow:
    def __init__(self, username, ssl_sock, sock_file):
        self.username = username
        self.ssl_sock = ssl_sock
        self.sock_file = sock_file
        self.room_tabs = {}

        self.root = tk.Tk()
        self.root.title(f"IM Client - {username}")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.build_gui()

        # get message
        self.receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receiver_thread.start()

        self.root.mainloop()

    def build_gui(self):
        # join room
        top_frame = tk.Frame(self.root)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        tk.Label(top_frame, text="Room:").pack(side=tk.LEFT)
        self.room_entry = tk.Entry(top_frame)
        self.room_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Join", command=self.join_room).pack(side=tk.LEFT)

        # tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)
        self.current_room = None  

        
        bottom_frame = tk.Frame(self.root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        self.message_entry = tk.Entry(bottom_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        tk.Button(bottom_frame, text="Send", command=self.send_message).pack(side=tk.LEFT)

    def join_room(self):
        room = self.room_entry.get().strip()
        if not room:
            messagebox.showerror("Join Error", "Enter a room name to join.")
            return

        join_msg = json.dumps({"command": "join", "room": room}) + "\n"
        try:
            self.ssl_sock.sendall(join_msg.encode())
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send join request: {e}")
            return

        # self explained
        if room not in self.room_tabs:
            tab_frame = tk.Frame(self.notebook)
            text_widget = tk.Text(tab_frame, state=tk.DISABLED, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True)
            self.notebook.add(tab_frame, text=room)
            self.room_tabs[room] = text_widget

        self.room_entry.delete(0, tk.END)
        # tab switch
        for idx in range(self.notebook.index("end")):
            if self.notebook.tab(idx, "text") == room:
                self.notebook.select(idx)
                self.current_room = room
                break

    def send_message(self):
        if self.current_room is None:
            messagebox.showerror("Send Error", "No active chatroom. Join a room first.")
            return
        message_text = self.message_entry.get().strip()
        if not message_text:
            return
        msg = {"command": "message", "room": self.current_room, "message": message_text}
        try:
            self.ssl_sock.sendall((json.dumps(msg) + "\n").encode())
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", f"Could not send message: {e}")

    def receive_messages(self):
        while True:
            line = self.sock_file.readline()
            if not line:
                self.show_tab_message("General", "Disconnected from server.\n")
                break
            try:
                data = json.loads(line)
                room = data.get("room", "General")
                username = data.get("username", "Unknown")
                message_text = data.get("message", "")
                timestamp = data.get("timestamp", "")
                
                # format
                formatted = f"[{timestamp}] {username}: {message_text}\n"
                self.update_room_tab(room, formatted)
            except json.JSONDecodeError:
                self.show_tab_message("General", f"Invalid message received: {line}\n")

    def update_room_tab(self, room, message):
        # make room tab if not exist
        if room not in self.room_tabs:
            self.root.after(0, self.create_room_tab, room)

        self.root.after(0, self.append_message, room, message)

    def create_room_tab(self, room):
        tab_frame = tk.Frame(self.notebook)
        text_widget = tk.Text(tab_frame, state=tk.DISABLED, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True)
        self.notebook.add(tab_frame, text=room)
        self.room_tabs[room] = text_widget

    def append_message(self, room, message):
        text_widget = self.room_tabs.get(room)
        if text_widget:
            text_widget.config(state=tk.NORMAL)
            text_widget.insert(tk.END, message)
            text_widget.see(tk.END)
            text_widget.config(state=tk.DISABLED)

    def show_tab_message(self, room, message):
        msg_room = room if room in self.room_tabs else "General"
        self.append_message(msg_room, message)

    def on_tab_change(self, event):
        selected_tab = self.notebook.select()
        if selected_tab:
            room = self.notebook.tab(selected_tab, "text")
            self.current_room = room

    def on_close(self):
        try:
            self.ssl_sock.close()
        except Exception:
            pass
        self.root.destroy()

def main():
    root = tk.Tk()
    LoginWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
