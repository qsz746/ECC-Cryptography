#!/usr/bin/env python
# coding: utf-8

# # ECDSA Digital signature

# In[1]:


import pycoin
from pycoin.ecdsa import secp256k1
from pycoin.ecdsa import Generator
import hashlib, secrets


def sha3_256Hash(msg):
    hashBytes = hashlib.sha3_256(msg.encode("utf8")).digest()
    return int.from_bytes(hashBytes, byteorder="big")

def signECDSAsecp256k1(msg, privKey):
    msgHash = sha3_256Hash(msg)    
# ECDSA verify signature (using the curve secp256k1 + SHA3-256)
#ECDSA signature {r, s}
    signature = secp256k1.secp256k1_generator.sign(BobPrivKey, msgHash)
    return signature

def verifyECDSAsecp256k1(msg, signature, pubKey):
    msgHash = sha3_256Hash(msg)
    valid = secp256k1.secp256k1_generator.verify(pubKey,msgHash,signature)
    return valid
   


# In[2]:


# ECDSA sign message (using the curve secp256k1 + SHA3-256)
msg = "Message for ECDSA signing"


#Bob generates a private key
BobPrivKey = secrets.randbelow(secp256k1.secp256k1_generator.order())
signature = signECDSAsecp256k1(msg, BobPrivKey)
print("Message:", msg)
print("Private key:", hex(BobPrivKey))
print("Signature: r=" + hex(signature[0]) + ", s=" + hex(signature[1]))
print("\n")


BobPubKey = secp256k1.secp256k1_generator.Point(secp256k1._Gx,secp256k1._Gy)*BobPrivKey


valid = verifyECDSAsecp256k1(msg, signature, BobPubKey)
print("\nMessage:", msg)
print("Public key: (" + hex(BobPubKey[0]) + ", " + hex(BobPubKey[1]) + ")")
print("Signature valid?", valid)
print("\n")


# ECDSA verify tampered signature (using the curve secp256k1 + SHA3-256)
msg = "Tampered message"
valid = verifyECDSAsecp256k1(msg, signature, BobPubKey)
print("\nMessage:", msg)
print("Signature (tampered msg) valid?", valid)


# In[3]:


def recoverPubKeyFromSignature(msg, signature):
    
    msgHash = sha3_256Hash(msg)

    recoveredPubKeys = secp256k1.secp256k1_generator.possible_public_pairs_for_signature(BobPrivKey, signature)
    return recoveredPubKeys

msg = "571k Cryptography"
recoveredPubKeys = recoverPubKeyFromSignature(msg, signature)
print("\nMessage:", msg)
print("\n")
print("Signature: r=" + hex(signature[0]) + ", s=" + hex(signature[1]))
print("\n")
for pk in recoveredPubKeys:
    print("Recovered public key from signature: (" +
          hex(pk[0]) + ", " + hex(pk[1]) + ")")

