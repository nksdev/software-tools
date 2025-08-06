import os
import itertools
import string
import zipfile

try:
    import rarfile
except ImportError:
    rarfile = None
    print("rarfile module not installed. RAR files cannot be processed.")

def brute_force_zip(zip_filepath, charset):
    with zipfile.ZipFile(zip_filepath) as zf:
        length = 1
        while True:
            print(f"Trying ZIP passwords with length {length}...")
            for guess_tuple in itertools.product(charset, repeat=length):
                guess = ''.join(guess_tuple)
                try:
                    zf.extractall(pwd=guess.encode('utf-8'))
                    print(f"ZIP Password found: {guess}")
                    return True
                except:
                    continue
            length += 1
    return False

def brute_force_rar(rar_filepath, charset):
    if rarfile is None:
        print("rarfile module is required for RAR files; skipping RAR brute force.")
        return False

    rf = rarfile.RarFile(rar_filepath)
    length = 1
    while True:
        print(f"Trying RAR passwords with length {length}...")
        for guess_tuple in itertools.product(charset, repeat=length):
            guess = ''.join(guess_tuple)
            try:
                rf.extractall(pwd=guess)
                print(f"RAR Password found: {guess}")
                return True
            except:
                continue
        length += 1
    return False

def main():
    file_path = input("Enter the path of your ZIP or RAR file: ").strip()

    if not os.path.exists(file_path):
        print("File does not exist.")
        return

    charset = string.ascii_lowercase + string.digits  # Customize charset here

    if file_path.lower().endswith('.zip'):
        print("Detected ZIP file.")
        brute_force_zip(file_path, charset)
    elif file_path.lower().endswith('.rar'):
        print("Detected RAR file.")
        brute_force_rar(file_path, charset)
    else:
        print("Unsupported file type. Please provide a ZIP or RAR file.")

if __name__ == "__main__":
    main()
