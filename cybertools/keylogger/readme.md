# Secure Cross-Platform Encrypted Keylogger with GUI

This Python keylogger program records keystrokes globally across Windows, macOS, and Linux platforms. It encrypts the recorded keystrokes using a dynamically set password and stores them securely in a local file. The keylogger cannot be stopped or closed unless the password is provided, ensuring secure access control. The user can also view decrypted logs only after entering the correct password.

---

## Features

- **Cross-platform support:** Works on Windows, macOS (requires Accessibility/Input Monitoring permissions), and Linux.
- **Encrypted logging:** Keystrokes are encrypted line-by-line using symmetric encryption (Fernet) with a password-derived key.
- **Password-protected:** 
  - User sets the password on startup.
  - Password is required to stop the keylogger.
  - Password is required to decrypt and view the logs.
- **Persistent logs:** Encrypts and saves keystrokes to a local log file (`keylog_encrypted.log`).
- **Graphical User Interface (GUI):** Built with `tkinter` for user-friendly interaction.
- **Prevents accidental closing:** Window cannot be closed unless the keylogger is stopped via password authentication.
- **Uses `pynput` for global keystroke capture:** Cross-platform key event listener.

---

## Requirements

- Python 3.x
- Python packages:
  - [`pynput`](https://pypi.org/project/pynput/) — for cross-platform keyboard event listening
  - [`cryptography`](https://pypi.org/project/cryptography/) — for encryption and decryption

Install dependencies via pip:

pip install pynput cryptography
text

---

## Setup & Usage

1. **Download or clone** the repository containing the `secure_keylogger.py` script.

2. **Run the script:**

python secure_keylogger.py
text

3. **Set your encryption password** when prompted. This password will be required to stop logging and decrypt logs later.

4. The keylogger window will appear, indicating the keylogger is running.

5. Use the GUI buttons to:

   - **View Logs:** Enter your password to decrypt and display recorded keystrokes.
   - **Stop Keylogger:** Enter your password to stop logging keystrokes and enable safe program exit.

6. **To exit the program:** Stop the keylogger using the password, then close the window.

---

## Important Notes

- **Permissions:**
  - On **macOS**, you must grant Accessibility and Input Monitoring permissions to your terminal or Python executable to allow global keystroke capture.
  - On **Linux**, the script may require root/administrative privileges.
  - On **Windows**, running the script as Administrator is recommended for proper key capture.

- **Ethical and legal use only:**  
  This software should only be used on machines you own or have explicit permission to monitor. Unauthorized keylogging is illegal and unethical.

- **Performance considerations:**  
  This script logs every keystroke globally, which could impact system resources or privacy if misused.

- **Log file:**  
  The encrypted log file is saved as `keylog_encrypted.log` in the same directory as the script.

---

## Customization

- The encrypted log file location can be changed by modifying `self.log_file_path` in the script.
- For advanced features like multi-user support, remote logging, or timestamping keys, further development is needed.

---

## License & Disclaimer

This software is provided "as-is" without warranty. Use at your own risk.

---

## Support

If you have questions, want assistance customizing the code, or need help extending features, please feel free to ask.

---

**Enjoy secure and controlled keylogging!**