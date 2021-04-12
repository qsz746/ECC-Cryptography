#!/usr/bin/env python
# coding: utf-8

# # ECDH Key Exchange
# 

# In[1]:


from tinyec import registry
import secrets

def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

curve = registry.get_curve('brainpoolP256r1')

# Alice generates a random secret key
AlicePrivKey = secrets.randbelow(curve.field.n)
# Alice gets her pub key 
AlicePubKey = AlicePrivKey * curve.g
print("Alice public key:", compress(AlicePubKey))

# Bob generates a random secret key
BobPrivKey = secrets.randbelow(curve.field.n)
# Bob gets his pub key, which is a point
BobPubKey = BobPrivKey * curve.g
print("Bob public key:", compress(BobPubKey))
print("\n")


AliceSharedKey = AlicePrivKey * BobPubKey
print("Alice shared key:", compress(AliceSharedKey))
print("\n")

BobSharedKey = BobPrivKey * AlicePubKey
print("Bob shared key:", compress(BobSharedKey))

print("\n")
print("Equal shared keys:", AliceSharedKey == BobSharedKey)

