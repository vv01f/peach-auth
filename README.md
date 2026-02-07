This is WIP for authentication on [Peach API](https://docs.peachbitcoin.com/)

* [x] mnemonic obtained from [decrypted file backup](https://github.com/vv01f/decrypt-peach-file-backup)
* [x] `shell.nix` for dependencies, apply with command `nix-shell`
* [x] quite some POSIX shell in `test-mnemonic.sh` with still some Python3 dependencies and the likes of `jq` to validate the steps
  + [x] `get_jq_from_json`
  + [x] `btc_seed_from_mnemonic`
  + [x] `btc_master_key_from_seed`
  + [x] derivation for path m/48'/0'/0'/0' step by step
  + [x] hex encoded compressed pubkey
  + [x] matching peachId from file backup
* [x] some Python3 in `test-mnemonic.py`
  + [x] derivation for path m/48'/0'/0'/0' thanks to `bip_utils` lib
  + [x] athentication message according to API docs
  + [x] signature like seen on [peach app](https://github.com/Peach2Peach/peach-app/blob/1627b1e705a204ce34a999530a4d9f643cc51c11/src/utils/peachAPI/websocket/createWebsocket.ts#L95)
  + [ ] validating signature

## test data

* for bacon*24 mnemonic
* seed `241e86356db60a686bb8c30b1054eac70701493b6702ed5f4a0e54cd3d13f0ccfd6d8b37506dc5c65af5575e720196d6d81aca24f0f083a5c65597541ada0e32`
* compressed pubKey `02b13b525b03d047270ba52f1f8d42f5c48d600506c716af16c8c1cfbb1887cbcc`

## how to run

### auth 
using the mnemonic in the script currently, example for bacon*24:

`./test-mnemonic.py`

resulting in
```
Derived private key:  9a4ab251744f63c60b43f78def56c903d78373761da9051d96efa9be32ab1fe2
Derived compressed pubkey: 02b13b525b03d047270ba52f1f8d42f5c48d600506c716af16c8c1cfbb1887cbcc
Hex signature: 30440220155e129f496ad8f4033c71505b7a7eb6c0881bc2c47159dd36cec418bde6e79f022079964d4d799db4a468830f469e305099cc328beb5f92228205d8f56d5a4b3a7c
Payload JSON: {"publicKey":"02b13b525b03d047270ba52f1f8d42f5c48d600506c716af16c8c1cfbb1887cbcc","message":"Peach Registration 1770467250408","signature":"30440220155e129f496ad8f4033c71505b7a7eb6c0881bc2c47159dd36cec418bde6e79f022079964d4d799db4a468830f469e305099cc328beb5f92228205d8f56d5a4b3a7c"}
Response: 400
{"error":"INVALID_SIGNATURE"}
```

### run to get bacon results
that is for validation of derivation code up to the pubkey, concluding that the privkey can be assumed correct 

```
nix-shell
./test-mnemonic.sh bacon
```

rsulting in
```
=== Step 1: Generate seed from mnemonic ===
Seed: 241e86356db60a686bb8c30b1054eac70701493b6702ed5f4a0e54cd3d13f0ccfd6d8b37506dc5c65af5575e720196d6d81aca24f0f083a5c65597541ada0e32

=== Step 2: Generate master key ===
Master Private Key (hex): e0bc36503f44566523a42a50d8b444d41ead33323bbae4e75b28a3fd93c53226
Master Chain Code   (hex): b6cd622d747e013fb6bb4ff4109f6f3fae3f13f657d73eb74bb72a83137e92fb

=== Step 3: Derive path m/48'/0'/0'/0' step by step ===
Deriving index 48 hardened...
Intermediate priv: a40f05acf6ba1f39e69ce68301676523203211bc6faef4083fda9ed2a379bfed
Intermediate chain: 4df9b1fde599b541a5a0d36b6cc092c70afd9681cda7d9af3ad59fed6f38061a
Deriving index 0 hardened...
Intermediate priv: 6de62ca8cbd9ab4f6baf522ae155e086c258cf96fe38d7ea144165f8fbf8f2e7
Intermediate chain: 95a53f13576a6512dab37c10b3e0f8dd95ad3570bc0c0b9732268402602d5ef3
Deriving index 0 hardened...
Intermediate priv: 214696b390acb7a1533e02aa143175527635e4a231ea4b6e8a5abf236b1290e2
Intermediate chain: 502212efa1445b4e31c27769594eef394abd489eb5d07f32c884d245f9d03f45
Deriving index 0 hardened...
Intermediate priv: 9a4ab251744f63c60b43f78def56c903d78373761da9051d96efa9be32ab1fe2
Intermediate chain: bae0a91e7837b0e82f4793b079f1fb0c7da4e24200fb594b5497b27020f84751
Final private key saved to privkey.hex

=== Step 4: Compute compressed public key ===
Compressed pubkey: 02b13b525b03d047270ba52f1f8d42f5c48d600506c716af16c8c1cfbb1887cbcc
passes match with expected pubkey
```

### run to get custom results
assuming `../decrypted-peach-account.json` is a valid decryted backup file, the mnemonic and pubkey will be read from it.

```
nix-shell
./test-mnemonic.sh ../decrypted-peach-account.json
```
