#!/usr/bin/env python3
# ~ export NIXPKGS_ALLOW_INSECURE=1; nix-shell -p python313Packages.bip-utils
import sys
import time
import base64
import hashlib
import json
import requests
import time
from bip_utils import (
    Bip39SeedGenerator,
    Bip39MnemonicValidator,
    Bip32Slip10Secp256k1,
)
from secp256k1 import PrivateKey

def load_input():
    valid = None
    if len(sys.argv) < 2:
        sys.exit("Usage: script.py <mnemonic | json-file>")

    arg = sys.argv[1]

    if arg.endswith(".json"):
        with open(arg) as f:
            data = json.load(f)
        mnemonic = data.get("mnemonic")
        comp_pubkey = data.get("publicKey")
        if not mnemonic:
            sys.exit("JSON missing 'mnemonic'")

        account_priv, account_pub = peach_get_accountkeys_from_mnemonic(mnemonic)
        valid = (account_pub == comp_pubkey)

        return account_priv, account_pub, valid

    if arg == "bacon":
        arg = "bacon " * 24
    mnemonic = arg.strip()
       
    account_priv, account_pub = peach_get_accountkeys_from_mnemonic(mnemonic)
    return account_priv, account_pub, True

def validate_mnemonic(mnemonic):
    words = mnemonic.split()
    if len(words) in (12, 15, 18, 21, 24):
        Bip39MnemonicValidator(mnemonic).Validate()
    else:
        sys.exit(f"Invalid mnemonic length: {len(words)}")

def btc_rootkey_from_mnemonic(mnemonic):
    seed = Bip39SeedGenerator(mnemonic).Generate()
    rootkey = Bip32Slip10Secp256k1.FromSeed(seed)
    return rootkey

def btc_keyset_from_rootkey(derivation_path, rootkey):
    account_key = rootkey.DerivePath(derivation_path)
    account_priv = account_key.PrivateKey().Raw().ToHex()
    account_pub  = account_key.PublicKey().RawCompressed().ToHex()
    return account_priv, account_pub

def peach_get_accountkeys_from_rootkey(bip32_wallet):
    account_priv, account_pub = btc_keyset_from_rootkey("m/48'/0'/0'/0'", bip32_wallet)
    return account_priv, account_pub

def peach_get_accountkeys_from_mnemonic(mnemonic):
    bip32_wallet = btc_rootkey_from_mnemonic(mnemonic)
    account_priv, account_pub = peach_get_accountkeys_from_rootkey(bip32_wallet)
    return account_priv, account_pub

def peach_signing_key(priv_hex):
    signing_key = PrivateKey(bytes.fromhex(priv_hex), raw=True)
    return signing_key

def peach_sign_message(msg, priv_hex):
    msg_bytes = msg.encode()
    msg_hash = hashlib.sha256(msg.encode()).digest()
    signing_key = peach_signing_key(priv_hex)
    sig_bytes = signing_key.ecdsa_sign_recoverable(msg_hash, raw=True)
    sig_64 = signing_key.ecdsa_recoverable_serialize(sig_bytes)
    sig_hex = sig_64[0].hex()
    return sig_hex

def peach_get_authtoken(account_pub, msg, sig_hex):
    payload_str = json.dumps({
            "publicKey": account_pub,
            "message": msg,
            "signature": sig_hex
        }, separators=(',', ':'))
    return payload_str

def main():
    try_auth = False
    account_priv, account_pub, valid = load_input()
    if valid != True:
        sys.exit(f"Invalid argument.")

    # there may be a time difference, didnt neet yet
    diff_ms = 0
    # ~ resp = requests.get("https://api.peachbitcoin.com/v1/system/status")
    # ~ resp.raise_for_status()
    # ~ data = resp.json()

    # ~ server_ts = int(data["serverTime"])  # serverTime is in milliseconds
    # ~ local_ts = int(time.time() * 1000)   # local time in milliseconds

    # ~ diff_ms = local_ts - server_ts

    # ~ print(f"Server time (ms): {server_ts}")
    # ~ print(f"Local  time (ms): {local_ts}")
    # ~ print(f"Difference  (ms): {diff_ms} ({diff_ms/1000:.3f} s)")

    ts_ms = int(time.time() * 1000) - diff_ms
    msg = f"Peach Registration {ts_ms}"
    sig_hex = peach_sign_message(msg, account_priv)
    payload_str = peach_get_authtoken(account_pub, msg, sig_hex)

    print("Derived private key: ", account_priv)
    print("Derived compressed pubkey:", account_pub)
    print("Hex signature:", sig_hex)
    print("Payload JSON:", payload_str)

    if try_auth == True:
        resp = requests.post("https://api.peachbitcoin.com/v1/user/auth/", headers={ "Content-Type": "application/json" }, data=payload_str)

        print("Response:", resp.status_code)
        print(resp.text)


if __name__ == "__main__":
    main()
    sys.exit(0)
