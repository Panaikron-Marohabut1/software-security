import os

from Crypto.Cipher import AES

from solution_skeleton import encrypt_gcm


key = bytes.fromhex(os.environ["ENC_KEY_HEX"])
message = b"secret message"
nonce, ciphertext, tag = encrypt_gcm(message, key)

decryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = decryptor.decrypt_and_verify(ciphertext, tag)
print("decrypted:", plaintext.decode())

tampered = bytearray(ciphertext)
tampered[0] ^= 1

try:
    decryptor = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decryptor.decrypt_and_verify(bytes(tampered), tag)
    print("tampered: accepted")
except ValueError:
    print("tampered: rejected - authentication tag check failed")
