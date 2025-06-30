import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import socket
import threading
import base64
import hashlib
import io
from PIL import Image, ImageTk

# Constants from the C# application
DEFAULT_SERVER_PORT = 3708
IMAGE_PREFIX = "IMAGE_DATA:"
FILE_PREFIX = "FILE_DATA:"
MAX_IMAGE_MESSAGE_LENGTH = 750 * 1024
MAX_FILE_MESSAGE_LENGTH = 2000 * 1024


class XZChatClient:
    """A Python implementation of the XZChat client using Tkinter."""

    def __init__(self, root):
        self.root = root
        self.root.title("XZChat (Python)")
        self.root.geometry("600x500")
        self.root.minsize(500, 400)

        self.client_socket = None
        self.username = "Anonymous"
        self.is_connected = False
        self.receive_thread = None
        # Keep a reference to PhotoImage objects to prevent garbage collection
        self.image_references = [] 

        self._setup_ui()
        self.update_ui_state()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _setup_ui(self):
        """Initializes and places all the GUI components."""
        
        # --- Top Connection Frame ---
        top_frame = ttk.Frame(self.root, padding="6 6 6 12")
        top_frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(top_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.ip_entry = ttk.Entry(top_frame)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        self.ip_entry.insert(0, "127.0.0.1")

        ttk.Label(top_frame, text="Username:").grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.username_entry = ttk.Entry(top_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=2, sticky=tk.EW)
        self.username_entry.insert(0, "Anonymous")

        self.connect_button = ttk.Button(top_frame, text="Connect", command=self.toggle_connection)
        self.connect_button.grid(row=0, column=2, rowspan=2, padx=5, pady=2, sticky="NS")
        
        top_frame.columnconfigure(1, weight=1)

        # --- Chat Window ---
        self.chat_window = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state=tk.DISABLED)
        self.chat_window.pack(padx=10, pady=5, expand=True, fill=tk.BOTH)

        # --- Bottom Message Frame ---
        bottom_frame = ttk.Frame(self.root, padding="6 6 6 6")
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.chat_box = ttk.Entry(bottom_frame)
        self.chat_box.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        self.chat_box.bind("<Return>", self.send_message)

        self.send_image_button = ttk.Button(bottom_frame, text="Send Image", command=self.select_image_to_send)
        self.send_image_button.pack(side=tk.RIGHT, padx=(0, 5))

        self.send_file_button = ttk.Button(bottom_frame, text="Send File", command=self.select_file_to_send)
        self.send_file_button.pack(side=tk.RIGHT, padx=(0, 5))

        self.send_button = ttk.Button(bottom_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

    def calculate_sha256_hash(self, data: str) -> str:
        """Calculates the SHA256 hash of a string."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def update_ui_state(self, is_connecting=False):
        """Enables or disables UI elements based on connection status."""
        is_connected = self.is_connected
        
        self.ip_entry.config(state=tk.DISABLED if is_connected or is_connecting else tk.NORMAL)
        self.username_entry.config(state=tk.DISABLED if is_connected or is_connecting else tk.NORMAL)

        self.chat_box.config(state=tk.NORMAL if is_connected else tk.DISABLED)
        self.send_button.config(state=tk.NORMAL if is_connected else tk.DISABLED)
        self.send_image_button.config(state=tk.NORMAL if is_connected else tk.DISABLED)
        self.send_file_button.config(state=tk.NORMAL if is_connected else tk.DISABLED)
        
        if is_connecting:
            self.connect_button.config(text="Connecting...", state=tk.DISABLED)
        elif is_connected:
            self.connect_button.config(text="Disconnect", state=tk.NORMAL)
        else:
            self.connect_button.config(text="Connect", state=tk.NORMAL)

    def append_message(self, text: str, sender: str = None):
        """Appends a text message to the chat window in a thread-safe way."""
        if self.root.winfo_exists():
            self.chat_window.config(state=tk.NORMAL)
            if sender:
                self.chat_window.insert(tk.END, f"{sender}: {text}\n")
            else:
                 self.chat_window.insert(tk.END, f"{text}\n")
            self.chat_window.config(state=tk.DISABLED)
            self.chat_window.yview(tk.END)

    def append_image(self, image: Image.Image, sender: str):
        """Appends an image to the chat window in a thread-safe way."""
        if not self.root.winfo_exists():
            return

        max_width = self.chat_window.winfo_width() - 25
        if image.width > max_width:
            scale = max_width / image.width
            new_height = int(image.height * scale)
            image = image.resize((max_width, new_height), Image.Resampling.LANCZOS)
        
        tk_image = ImageTk.PhotoImage(image)
        self.image_references.append(tk_image)  # Keep a reference!

        self.chat_window.config(state=tk.NORMAL)
        self.chat_window.insert(tk.END, f"{sender} sent an image:\n")
        self.chat_window.image_create(tk.END, image=tk_image)
        self.chat_window.insert(tk.END, "\n\n") # Add spacing
        self.chat_window.config(state=tk.DISABLED)
        self.chat_window.yview(tk.END)

    def toggle_connection(self):
        """Handles the connect/disconnect button clicks."""
        if self.is_connected:
            self.disconnect()
        else:
            self.connect_to_server()

    def connect_to_server(self):
        """Validates input and starts the connection thread."""
        ip_address = self.ip_entry.get().strip()
        self.username = self.username_entry.get().strip() or "Anonymous"
        
        try:
            socket.inet_aton(ip_address) # Validate IP
        except socket.error:
            messagebox.showerror("Invalid IP", "Please enter a valid IP address.")
            return

        self.update_ui_state(is_connecting=True)
        self.append_message(f"Attempting to connect to {ip_address}:{DEFAULT_SERVER_PORT}...")
        
        # Run connection in a separate thread to not freeze the GUI
        connect_thread = threading.Thread(target=self._connection_worker, args=(ip_address, self.username), daemon=True)
        connect_thread.start()

    def _connection_worker(self, ip, user):
        """The actual connection logic running in a background thread."""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, DEFAULT_SERVER_PORT))
            self.is_connected = True
            
            # Send nickname to server
            nick_command = f"/nick {user}"
            nick_hash = self.calculate_sha256_hash(nick_command)
            self.client_socket.sendall(f"{nick_command}|{nick_hash}\n".encode('utf-8'))

            self.root.after(0, lambda: self.append_message("Connected to server!"))
            self.root.after(0, lambda: self.root.config(title=f"XZChat - Logged in as {user}"))
            
            # Start listening for messages
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()

        except Exception as e:
            self.root.after(0, lambda: self.append_message(f"Connection Error: {e}"))
            self.disconnect() # Cleanup
        finally:
            self.root.after(0, self.update_ui_state)

    def receive_messages(self):
        """Listens for incoming data from the server."""
        buffer = ""
        while self.is_connected:
            try:
                data = self.client_socket.recv(8192)
                if not data:
                    self.root.after(0, lambda: self.append_message("Server has closed the connection."))
                    break
                
                buffer += data.decode('utf-8')
                while '\n' in buffer:
                    message, buffer = buffer.split('\n', 1)
                    self.root.after(0, self.process_received_message, message.strip())

            except (ConnectionResetError, BrokenPipeError, OSError):
                self.root.after(0, lambda: self.append_message("Disconnected from server."))
                break
            except Exception as e:
                if self.is_connected: # Don't show error if we intentionally disconnected
                    self.root.after(0, lambda: self.append_message(f"Receive Error: {e}"))
                break
        self.disconnect()

    def process_received_message(self, data: str):
        """Processes a single, complete message from the server."""
        try:
            if data.startswith(IMAGE_PREFIX):
                # Format: IMAGE_DATA:base64_image|hash
                img_data_with_hash = data[len(IMAGE_PREFIX):]
                base64_img, received_hash = img_data_with_hash.rsplit('|', 1)
                
                if self.calculate_sha256_hash(base64_img) == received_hash:
                    img_bytes = base64.b64decode(base64_img)
                    image = Image.open(io.BytesIO(img_bytes))
                    self.append_image(image, "Remote User")
                else:
                    self.append_message("[CORRUPTED IMAGE RECEIVED]")

            elif data.startswith(FILE_PREFIX):
                # Format: FILE_DATA:username|filename|base64_file|hash
                file_data_with_hash = data[len(FILE_PREFIX):]
                parts = file_data_with_hash.split('|', 3)
                if len(parts) == 4:
                    sender, filename, base64_file, received_hash = parts
                    if self.calculate_sha256_hash(base64_file) == received_hash:
                        self.handle_incoming_file(sender, filename, base64_file)
                    else:
                        self.append_message(f"[CORRUPTED FILE RECEIVED from {sender}]")
            else:
                # Format: message|hash
                message_part, hash_part = data.rsplit('|', 1)
                if self.calculate_sha256_hash(message_part) == hash_part:
                    self.append_message(message_part)
                else:
                    self.append_message(f"[CORRUPTED] {message_part}")
        except Exception as e:
            self.append_message(f"[RAW/ERROR] {data} ({e})")

    def handle_incoming_file(self, sender, filename, base64_file):
        """Prompts the user to save an incoming file."""
        if messagebox.askyesno("Incoming File", f"{sender} sent a file: {filename}.\nDo you want to save it?"):
            save_path = filedialog.asksaveasfilename(initialfile=filename, title=f"Save file from {sender}")
            if save_path:
                try:
                    file_bytes = base64.b64decode(base64_file)
                    with open(save_path, 'wb') as f:
                        f.write(file_bytes)
                    self.append_message(f"File from {sender} saved to: {os.path.basename(save_path)}")
                except Exception as e:
                    messagebox.showerror("Save Error", f"Failed to save file: {e}")
                    self.append_message(f"[Error saving file: {e}]")
        else:
            self.append_message(f"Declined file from {sender}: {filename}.")
            
    def send_message(self, event=None):
        """Sends a text message to the server."""
        message = self.chat_box.get().strip()
        if not message or not self.is_connected:
            return
        
        try:
            hash_val = self.calculate_sha256_hash(message)
            message_with_hash = f"{message}|{hash_val}\n"
            self.client_socket.sendall(message_with_hash.encode('utf-8'))
            self.append_message(message, "You")
            self.chat_box.delete(0, tk.END)
        except Exception as e:
            self.append_message(f"Send Error: {e}")
            self.disconnect()

    def select_image_to_send(self):
        """Opens a file dialog to select an image."""
        filepath = filedialog.askopenfilename(
            title="Select an Image to Send",
            filetypes=[("Image Files", "*.jpg *.jpeg *.png *.gif *.bmp"), ("All Files", "*.*")]
        )
        if filepath:
            threading.Thread(target=self._file_sender_worker, args=(filepath, True), daemon=True).start()

    def select_file_to_send(self):
        """Opens a file dialog to select any file."""
        filepath = filedialog.askopenfilename(title="Select File to Send")
        if filepath:
            threading.Thread(target=self._file_sender_worker, args=(filepath, False), daemon=True).start()

    def _file_sender_worker(self, filepath: str, is_image: bool):
        """Reads, encodes, and sends a file in a background thread."""
        try:
            with open(filepath, 'rb') as f:
                file_bytes = f.read()

            base64_content = base64.b64encode(file_bytes).decode('utf-8')
            content_hash = self.calculate_sha256_hash(base64_content)
            filename = os.path.basename(filepath)

            if is_image:
                message = f"{IMAGE_PREFIX}{base64_content}|{content_hash}\n"
                if len(message) > MAX_IMAGE_MESSAGE_LENGTH:
                    self.root.after(0, lambda: messagebox.showwarning("Image Too Large", "The selected image is too large to send."))
                    return
                # Display image locally
                image = Image.open(filepath)
                self.root.after(0, self.append_image, image, "You")
            else:
                message = f"{FILE_PREFIX}{self.username}|{filename}|{base64_content}|{content_hash}\n"
                if len(message) > MAX_FILE_MESSAGE_LENGTH:
                    self.root.after(0, lambda: messagebox.showwarning("File Too Large", "The selected file is too large to send."))
                    return
                self.root.after(0, self.append_message, f"You sent file: {filename}")

            self.client_socket.sendall(message.encode('utf-8'))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Send Error", f"Failed to send file: {e}"))

    def disconnect(self):
        """Closes the connection and resets the UI."""
        if self.is_connected:
            self.is_connected = False
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            
            if self.root.winfo_exists():
                self.root.after(0, self.update_ui_state)
                self.root.after(0, lambda: self.root.config(title=f"XZChat (Python)"))

    def on_closing(self):
        """Handles the window close event."""
        self.disconnect()
        self.root.destroy()


if __name__ == "__main__":
    import os
    main_root = tk.Tk()
    app = XZChatClient(main_root)
    main_root.mainloop()