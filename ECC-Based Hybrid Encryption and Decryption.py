#!/usr/bin/env python
# coding: utf-8

# # ECC-Based Hybrid Encryption / Decryption

# # 1. ECC + AES-GCM hybrid encryption/decryption

# In[1]:



from tinyec import registry
from Cryptodome.Cipher import AES
import hashlib, secrets, binascii

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)
#The ciphertext is obtained by the symmetric AES-GCM encryption
#nonce (random AES initialization vector) and authTag 
#(the MAC code of the encrypted text, obtained by the GCM block mode)


def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')


def encrypt_ECC(msg, pubKey):
    AlicePrivKey = secrets.randbelow(curve.field.n)
# sharedECCKey is a point
    sharedECCKey = AlicePrivKey * pubKey
# convert 256 bits secretKey for AES scheme
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    
# a randomly generated ephemeral public key ciphertextPubKey, 
#which will be encapsulated in the encrypted message and will be
#used to recover the AES symmetric key during the decryption 
    AlicePubKey = AlicePrivKey * curve.g
    return (ciphertext, nonce, authTag, AlicePubKey)


def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, AlicePubKey) = encryptedMsg
    sharedECCKey = privKey * AlicePubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    print(len(secretKey))
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


msg = b'I really want a border collie'
print("original msg:", msg)
print("\n")
BobPrivKey = secrets.randbelow(curve.field.n)
BobPubKey = BobPrivKey * curve.g

encryptedMsg = encrypt_ECC(msg, BobPubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'AlicePubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}
print("encrypted msg:", encryptedMsgObj)

print("\n")
decryptedMsg = decrypt_ECC(encryptedMsg, BobPrivKey)
print("decrypted msg:", decryptedMsg)


# # 2. ECC + AES-CTR hybrid encryption/decryption

# In[2]:


import pyaes, binascii, os, secrets

def encrypt_AES_CTR(msg,key,iv):
# Encrypt the plaintext with the given key:
#   ciphertext = AES-256-CTR-Encrypt(plaintext, key, iv)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    ciphertext = aes.encrypt(msg)
    return ciphertext

def decrypt_AES_CTR(ciphertext,key,iv):
# Decrypt the ciphertext with the given key:
#   plaintext = AES-256-CTR-Decrypt(ciphertext, key, iv)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    decrypted = aes.decrypt(ciphertext)
    return  decrypted

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def encrypt_ECC(msg, pubKey):
    AlicePrivKey = secrets.randbelow(curve.field.n)
# sharedECCKey is a point
    sharedECCKey = AlicePrivKey * pubKey
# convert 256 bits secretKey for AES scheme
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    print('AES encryption key:', binascii.hexlify(secretKey))
    iv = secrets.randbits(256)
    ciphertext = encrypt_AES_CTR(msg,secretKey,iv)
# a randomly generated ephemeral public key ciphertextPubKey, 
#which will be encapsulated in the encrypted message and will be
#used to recover the AES symmetric key during the decryption 
    AlicePubKey = AlicePrivKey * curve.g
    return (ciphertext, AlicePubKey,iv)


def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext,AlicePubKey,iv) = encryptedMsg
    sharedECCKey = privKey * AlicePubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    decrypted = decrypt_AES_CTR(ciphertext,secretKey,iv)
    return decrypted


msg = b'I really want a border collie'
print("original msg:", msg)
print("\n")
BobPrivKey = secrets.randbelow(curve.field.n)
BobPubKey = BobPrivKey * curve.g

encryptedMsg = encrypt_ECC(msg, BobPubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'AlicePubKey': hex(encryptedMsg[1].x) + hex(encryptedMsg[1].y % 2)[2:],
    'iv': encryptedMsg[2]
}

print("encrypted msg:", encryptedMsgObj)

print("\n")
decryptedMsg = decrypt_ECC(encryptedMsg, BobPrivKey)
print("decrypted msg:", decryptedMsg)  


# # 3. ECC + Chacha20 hybrid encryption/decryption

# In[3]:


import pyaes, binascii, os, secrets
from chacha20poly1305 import ChaCha20Poly1305

def encrypt_ChaCha20(msg,key,nonce):
    cip = ChaCha20Poly1305(key)
    ciphertext = cip.encrypt(nonce, msg)
    return ciphertext

def decrypt_ChaCha20(key,ciphertext,nonce):
    cip = ChaCha20Poly1305(key)
    decrypted = cip.decrypt(nonce, ciphertext)
    return  decrypted

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def encrypt_ECC(msg, pubKey):
    AlicePrivKey = secrets.randbelow(curve.field.n)
# sharedECCKey is a point
    sharedECCKey = AlicePrivKey * pubKey
# convert 256 bits secretKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    print('secret key:', binascii.hexlify(secretKey))
    nonce = os.urandom(12)
    ciphertext = encrypt_ChaCha20(msg,secretKey,nonce)
    AlicePubKey = AlicePrivKey * curve.g
    return (ciphertext, AlicePubKey,nonce)


def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext,AlicePubKey,nonce) = encryptedMsg
    sharedECCKey = privKey * AlicePubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    decrypted = decrypt_ChaCha20(secretKey,ciphertext,nonce)
    return decrypted


msg = b'I really want a border collie'
print("original msg:", msg)
print("\n")
BobPrivKey = secrets.randbelow(curve.field.n)
BobPubKey = BobPrivKey * curve.g

encryptedMsg = encrypt_ECC(msg, BobPubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'AlicePubKey': hex(encryptedMsg[1].x) + hex(encryptedMsg[1].y % 2)[2:],
    'nonce': encryptedMsg[2]
}

print("encrypted msg:", encryptedMsgObj)

print("\n")
decryptedMsg = decrypt_ECC(encryptedMsg, BobPrivKey)
print("decrypted msg:", decryptedMsg)  

