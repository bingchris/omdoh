import tkinter as tk
from tkinter import messagebox, ttk
import requests
import socket
import ssl
import json
import threading
from PIL import Image, ImageTk
from io import BytesIO

# config
HTTP_LOGIN_URL = "http://127.0.0.1:5000/login"  # replace with your URL if in production
HTTP_STATUS_URL = "http://127.0.0.1:5000/update_status"
HTTP_CONTACTS_URL = "http://127.0.0.1:5000/contacts_status"
HTTP_AVATAR_BASE = "http://127.0.0.1:5000/avatars/"
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
        avatar_filename = response.json().get("avatar", "")
        if not token:
            messagebox.showerror("Login Failed", "No token received.")
            return

        try:
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

        self.master.destroy()
        MainWindow(username, token, avatar_filename, self.ssl_sock, self.sock_file)

class MainWindow:
    def __init__(self, username, token, avatar_filename, ssl_sock, sock_file):
        self.username = username
        self.token = token
        self.ssl_sock = ssl_sock
        self.sock_file = sock_file
        self.chatrooms = {}   # key: room name, value: ChatRoomWindow instance
        self.contact_images = {}  # dictionary to store contact PhotoImages (to avoid GC)

        # load avatar
        self.pfp_photo = None
        if avatar_filename:
            try:
                r = requests.get(HTTP_AVATAR_BASE + avatar_filename)
                if r.status_code == 200:
                    print(f"Loaded profile avatar from {HTTP_AVATAR_BASE + avatar_filename}")
                    image_data = BytesIO(r.content)
                    self.pfp_image = Image.open(image_data)
                    self.pfp_image = self.pfp_image.resize((50,50), Image.Resampling.LANCZOS)
                    self.pfp_photo = ImageTk.PhotoImage(self.pfp_image)
            except Exception as e:
                print("Error loading profile avatar from server:", e)
        if not self.pfp_photo:
            try:
                self.pfp_image = Image.open("default_avatar.png")
                self.pfp_image = self.pfp_image.resize((50,50), Image.Resampling.LANCZOS)
                self.pfp_photo = ImageTk.PhotoImage(self.pfp_image)
            except Exception as e:
                self.pfp_photo = None

        # h
        self.root = tk.Tk()
        self.root.title(f"omdoh - Logged in as {username}")
        self.root.geometry("800x600")
        self.paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True)

        # left
        self.left_frame = tk.Frame(self.paned, width=250, bg="#F0F0F0")
        self.paned.add(self.left_frame)
        profile_frame = tk.Frame(self.left_frame, bg="#F0F0F0")
        profile_frame.pack(pady=10)
        if self.pfp_photo:
            tk.Label(profile_frame, image=self.pfp_photo, bg="#F0F0F0").pack()
        tk.Label(profile_frame, text=username, bg="#F0F0F0", font=("Segoe UI", 12, "bold")).pack()

        status_frame = tk.Frame(self.left_frame, bg="#F0F0F0")
        status_frame.pack(pady=5)
        tk.Label(status_frame, text="Status:", bg="#F0F0F0").pack(side=tk.LEFT)
        self.status_entry = tk.Entry(status_frame)
        self.status_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(status_frame, text="Update", command=self.update_status).pack(side=tk.LEFT)

        # vtgbyhjk,v 
        style = ttk.Style(self.left_frame)
        style.configure("Treeview", rowheight=30)
        tk.Label(self.left_frame, text="Contacts", bg="#F0F0F0", font=("Segoe UI", 10, "bold")).pack(pady=(10,0))
        self.contacts_tree = ttk.Treeview(self.left_frame, show="tree")
        self.contacts_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.contacts_tree.bind("<Double-1>", self.on_contact_double_click)
        tk.Button(self.left_frame, text="Refresh Contacts", command=self.refresh_contacts).pack(pady=5)

        # right
        self.right_frame = tk.Frame(self.paned, bg="#FFFFFF")
        self.paned.add(self.right_frame)
        tk.Label(self.right_frame, text="Join a Public Chatroom", bg="#FFFFFF", font=("Segoe UI", 10, "bold")).pack(pady=10)
        join_frame = tk.Frame(self.right_frame, bg="#FFFFFF")
        join_frame.pack(pady=5)
        tk.Label(join_frame, text="Room:", bg="#FFFFFF").pack(side=tk.LEFT)
        self.room_entry = tk.Entry(join_frame)
        self.room_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(join_frame, text="Join", command=self.join_public_room).pack(side=tk.LEFT)

        # get
        self.receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receiver_thread.start()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.refresh_contacts()
        self.root.mainloop()

    def update_status(self):
        new_status = self.status_entry.get().strip()
        if not new_status:
            messagebox.showerror("Status Error", "Status cannot be empty.")
            return
        try:
            resp = requests.post(HTTP_STATUS_URL, json={"token": self.token, "status": new_status})
            if resp.status_code != 200:
                messagebox.showerror("Status Error", resp.json().get("error", "Unknown error."))
            else:
                messagebox.showinfo("Status", "Status updated successfully.")
                self.refresh_contacts()
        except Exception as e:
            messagebox.showerror("HTTP Error", str(e))

    def refresh_contacts(self):
        try:
            resp = requests.post(HTTP_CONTACTS_URL, json={"token": self.token})
            if resp.status_code == 200:
                contacts = resp.json().get("contacts", [])
                print("Contacts received:", contacts)
                for item in self.contacts_tree.get_children():
                    self.contacts_tree.delete(item)
                for contact in contacts:
                    username = contact.get("username", "")
                    status = contact.get("status", "")
                    display_text = f"{username} - {status}"
                    avatar_filename = contact.get("avatar", "")
                    avatar_photo = None
                    if avatar_filename:
                        try:
                            url = HTTP_AVATAR_BASE + avatar_filename
                            print(f"Fetching avatar for {username} from: {url}")
                            r = requests.get(url)
                            if r.status_code == 200:
                                image_data = BytesIO(r.content)
                                img = Image.open(image_data)
                                img = img.resize((20,20), Image.Resampling.LANCZOS)
                                avatar_photo = ImageTk.PhotoImage(img)
                                self.contact_images[username] = avatar_photo
                            else:
                                print(f"Failed to fetch avatar for {username}; status code: {r.status_code}")
                        except Exception as e:
                            print("Error loading contact avatar for", username, ":", e)
                    if avatar_photo is not None:
                        self.contacts_tree.insert("", "end", text=display_text, image=avatar_photo, values=(username,))
                    else:
                        self.contacts_tree.insert("", "end", text=display_text, values=(username,))
            else:
                messagebox.showerror("Contacts Error", resp.json().get("error", "Unknown error"))
        except Exception as e:
            messagebox.showerror("HTTP Error", str(e))

    def join_public_room(self):
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
        if room not in self.chatrooms:
            self.chatrooms[room] = ChatRoomWindow(room, self.username, self.ssl_sock)
        self.room_entry.delete(0, tk.END)

    def on_contact_double_click(self, event):
        item_id = self.contacts_tree.focus()
        if not item_id:
            return
        item = self.contacts_tree.item(item_id)
        contact_username = item.get("values", [""])[0]
        if not contact_username:
            return
        room = "private:" + "_".join(sorted([self.username, contact_username]))
        join_msg = json.dumps({"command": "join", "room": room}) + "\n"
        try:
            self.ssl_sock.sendall(join_msg.encode())
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send join request: {e}")
            return
        if room not in self.chatrooms:
            self.chatrooms[room] = ChatRoomWindow(room, self.username, self.ssl_sock)
        else:
            self.chatrooms[room].win.lift()

    def receive_messages(self):
        while True:
            line = self.sock_file.readline()
            if not line:
                for r, chat in self.chatrooms.items():
                    chat.append_message("System", "Disconnected from server.\n")
                break
            try:
                data = json.loads(line)
                local_room = data.get("room")
                if local_room is None:
                    local_room = "General"
                sender = data.get("username", "Unknown")
                message_text = data.get("message", "")
                timestamp = data.get("timestamp", "")
                formatted = f"[{timestamp}] {sender}: {message_text}\n"
                if local_room not in self.chatrooms:
                    self.chatrooms[local_room] = ChatRoomWindow(local_room, self.username, self.ssl_sock)
                self.chatrooms[local_room].append_message(sender, formatted)
            except Exception as e:
                print("Error processing message:", e)

    def on_close(self):
        try:
            self.ssl_sock.close()
        except Exception:
            pass
        self.root.destroy()

class ChatRoomWindow:
    def __init__(self, room, username, ssl_sock):
        self.room = room
        self.username = username
        self.ssl_sock = ssl_sock
        self.win = tk.Toplevel()
        self.win.title(f"Chat - {room}")
        self.win.geometry("500x400")
        self.text_display = tk.Text(self.win, state=tk.DISABLED, wrap=tk.WORD)
        self.text_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        bottom_frame = tk.Frame(self.win)
        bottom_frame.pack(fill=tk.X, padx=5, pady=5)
        self.message_entry = tk.Entry(bottom_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        tk.Button(bottom_frame, text="Send", command=self.send_message).pack(side=tk.LEFT)
        self.win.protocol("WM_DELETE_WINDOW", self.on_close)

    def send_message(self):
        message_text = self.message_entry.get().strip()
        if not message_text:
            return
        msg = {"command": "message", "room": self.room, "message": message_text}
        try:
            self.ssl_sock.sendall((json.dumps(msg) + "\n").encode())
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", f"Could not send message: {e}")

    def append_message(self, sender, message):
        self.text_display.config(state=tk.NORMAL)
        self.text_display.insert(tk.END, message)
        self.text_display.see(tk.END)
        self.text_display.config(state=tk.DISABLED)

    def on_close(self):
        self.win.destroy()

def main():
    root = tk.Tk()
    LoginWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
