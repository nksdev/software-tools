# Brute-Force ZIP and RAR Password Cracker

This Python script attempts to brute-force crack the password of a password-protected ZIP or RAR archive file by trying **all possible combinations of characters** starting from length 1 and increasing indefinitely until the correct password is found.

---

## Features

- Supports both ZIP and RAR password-protected archive files.
- Starts brute forcing from length 1 and **runs indefinitely** until the correct password is found or the script is manually stopped.
- Uses a customizable character set (`a-z` and `0-9` by default) to generate password guesses on the fly without storing all combinations.
- Uses Python’s built-in `zipfile` module for ZIP files.
- Uses the third-party `rarfile` module for RAR files.
- Automatically detects the archive type based on file extension.
- Simple user input for file path.

---

## Requirements

- Python 3.x
- For ZIP files: no additional libraries required.
- For RAR files:
  - `rarfile` Python module (`pip install rarfile`)
  - `unrar` or `unar` command-line tool installed on your machine (required by `rarfile`)

---

## Usage

1. Clone or download this repository.
2. Open a terminal or command prompt.
3. Run the script:

python bruteforce.py
text

4. When prompted, enter the full path to your ZIP or RAR archive file you want to crack.

5. The script will start trying passwords from length 1 upwards indefinitely until it finds the correct password or you stop it (e.g., Ctrl+C).

---

## Customization

- The character set used for password guessing is defined in the script as:

charset = string.ascii_lowercase + string.digits
text

- You can customize it to include uppercase letters or symbols as needed:

charset = string.ascii_letters + string.digits + string.punctuation
text

---

## Important Notes

- **Use this script responsibly.** Only perform brute-force attacks on archives you own or have explicit permission to test. Unauthorized cracking is illegal.
- Brute forcing is time-consuming and computationally expensive, especially for longer passwords and larger character sets.
- This script is a simple demonstration and can be improved (e.g., multi-threading, dictionary attacks, optimized guesses) for practical use.

---

## License

This script is provided "as-is" without warranty. Use at your own risk.

---

If you want help with customization or support for other archive types, feel free to ask!