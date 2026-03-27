from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import unpad
import sys

def oracle(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext)
    try:
        unpad(decrypted_text, DES.block_size)
        return True
    except ValueError:
        return False
    
def main():
    if len(sys.argv) != 3:
        sys.exit()
    ciphertext = bytes.fromhex(sys.argv[1])
    iv = bytes.fromhex(sys.argv[2])
    # read the key from key.txt
    with open("key.txt", "rb") as f:
        key = f.read().strip()
        if len(key) != DES.key_size:
            sys.exit()
    if oracle(ciphertext, key, iv):
        print(1)
    else:
        print(0)
        
if __name__ == "__main__":
    main()