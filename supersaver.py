import shutil
import tempfile
import sys
import unittest
import os
import json

from StringIO import StringIO
from electrum.storage import WalletStorage, FINAL_SEED_VERSION
from electrum.keystore import *
from electrum.bitcoin import *

wallet_path = raw_input("electrum wallet.dat location: [default: /home/anonymous/.electrum/wallets/wallet_multisig")
password = raw_input("wallet passphrase (required for decryption):")

watchfor = []
while True:
    xpassword = raw_input("Enter (yet another) address or public key for which you want to recover the private key for. Leave empty to continue:")
    if xpassword != "":
        watchfor.append(xpassword)
    else:
        break

def pseudoload(dictx):
    k=None
    t="unknown"
    if "mpk" in dictx:
        t="old"
    elif "keypairs" in dictx:
        t="imported"
    elif "xprv" in dictx:
        t="bip32"

    if t == 'old':
        k = Old_KeyStore(dictx)
    elif t == 'imported':
        k = Imported_KeyStore(dictx)
    elif t == 'bip32':
        k = BIP32_KeyStore(dictx)
        return k
  

if wallet_path=="":
    wallet_path="/home/anonymous/.electrum/wallets/wallet_multisig"
storage = WalletStorage(wallet_path)
if storage.is_encrypted():
    print "[!] decrypting wallet"
    storage.decrypt(password)
xx = storage.data
cnt=1
recovered_keys = []
keystores = []
print "[!] trying to recover private keys. this may take enough time for you to grab a coffee"

while True:

    if "x"+str(cnt)+"/" in storage.data:
        xi = storage.data["x"+str(cnt) + "/"]
        did = pseudoload(xi)
        for x in range(25):
            print "[!] (keystore " + str(cnt) + ") - trying key derivation",(x+1),"of 50"
            dx = did.get_private_key([0, x], password)
            raw = DecodeBase58Check(dx)
            pubkey = public_key_from_private_key(dx)
            add = address_from_private_key(dx)
            if pubkey in watchfor or add in watchfor:
                print "\npublic key:\t",pubkey,"\nb58 address:\t",add,"\nprivate key:\t",dx,"\n\n"
        for x in range(25):
            print "[!] (keystore " + str(cnt) + ") - trying key derivation",(x+1+25),"of 50"
            dx = did.get_private_key([1, x], password)
            raw = DecodeBase58Check(dx)
            pubkey = public_key_from_private_key(dx)
            add = address_from_private_key(dx)
            if pubkey in watchfor or add in watchfor:
                print "\npublic key:\t",pubkey,"\nb58 address:\t",add,"\nprivate key:\t",dx,"\n\n"

        #print xi
        cnt=cnt+1
    else:
        break
privkeys = []
for x in keystores:
    print x.keypairs
