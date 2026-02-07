#!/usr/bin/env python3
# ~ export NIXPKGS_ALLOW_INSECURE=1; nix-shell -p python313Packages.bip-utils
import time
import base64
import hashlib
import json
import requests
import time
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from secp256k1 import PrivateKey

mnemonic = "bacon " * 24 # or your custom mnemonic seedphrase
mnemonic = mnemonic.strip()
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

# Derive m/48'/0'/0'/0'
node = bip32_ctx.DerivePath("m/48'/0'/0'/0'")
priv = node.PrivateKey().Raw().ToHex()
pub  = node.PublicKey().RawCompressed().ToHex()

print("Derived private key: ", priv)
print("Derived compressed pubkey:", pub)

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

priv_bytes = bytes.fromhex(priv)

sk = PrivateKey(priv_bytes, raw=True)
msg_hash = hashlib.sha256(msg.encode()).digest()

priv_bytes = bytes.fromhex(priv)
sk = PrivateKey(priv_bytes, raw=True)

sig_bytes = sk.ecdsa_sign(msg_hash, raw=True)
sig_hex = sk.ecdsa_serialize(sig_bytes).hex()
print("Hex signature:", sig_hex)

payload = {
    "publicKey": pub,
    "message": msg,
    "signature": sig_hex
}
payload_str = json.dumps(payload, separators=(',', ':'))
print("Payload JSON:", payload_str)

headers = {
    "Content-Type": "application/json"
}

resp = requests.post("https://api.peachbitcoin.com/v1/user/auth/", headers=headers, data=payload_str)

print("Response:", resp.status_code)
print(resp.text)
