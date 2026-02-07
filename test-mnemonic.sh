#!/usr/bin/env sh
set -euo pipefail

# nix-shell -p "python3.withPackages(ps: [ps.secp256k1 ps.coincurve])" python3Packages.bech32 jq curl

get_jq_from_json() {
	jq=${1:-}
	[ -z $jq ] && { printf "Error: query for jq missing\n"; return 1; }
	fn=${2:-}
	[ -z $fn ] && { printf "Error: filename missing\n"; return 2; }
	
	jq -r "${jq}"  "$fn"
}

btc_master_key_from_seed() {
    seed_file=${1:-seed.hex}
    verbose=${2:-quiet}
    nofiles=${3:-nofiles}

    # read seed
    if [ -f "$seed_file" ]; then
		seed_hex=$(cat "$seed_file")
	else
		seed_hex="$seed_file"
	fi

    # convert hex to binary for OpenSSL
    seed_bin=$(printf '%s' "$seed_hex" | xxd -r -p)

    # HMAC-SHA512 with key "Bitcoin seed"
    hmac_hex=$(printf '%s' "$seed_bin" |
        openssl dgst -sha512 -mac HMAC -macopt key:"Bitcoin seed" |
        awk '{print $2}')

    # split into master private key and chain code
    master_priv=${hmac_hex:0:64}   # first 32 bytes
    master_chain=${hmac_hex:64:64} # last 32 bytes
	
	if [ ! "$verbose" = "quiet" ]; then
		printf "Master Private Key (hex): %s\n" "$master_priv"
		printf "Master Chain Code   (hex): %s\n" "$master_chain"
	fi
	if [ ! "$nofiles" = "nofiles" ]; then
		printf "%s\n" "$master_priv" > "master_priv.hex"
		printf "%s\n" "$master_chain" > "master_chain.hex"
	else
		printf "%s\n%s\n" "$master_priv" "$master_chain"
	fi
}

# --- BIP32 hardened derivation ---
btc_ckd_priv_hardened() {
    parent_priv=${1:-}
    parent_chain=${2:-}
    index=${3:-}

    i=$(($index + 0x80000000))

    # HMAC-SHA512 via OpenSSL in hex, safe for POSIX shell
    # Concatenate 00 + parent_priv + index (all in hex)
    data_hex="00${parent_priv}$(printf '%08x' "$i")"

    I_HEX=$(printf '%s' "$data_hex" | xxd -r -p \
        | openssl dgst -sha512 -mac HMAC -macopt hexkey:"$parent_chain" -hex \
        | cut -d' ' -f2)

    IL=${I_HEX%????????????????????????????????????????????????????????????????}   # first 64 chars
    IR=${I_HEX#????????????????????????????????????????????????????????????????}   # last 64 chars

    # Child private key via Python
    n=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    child_priv=$(python3 - <<EOF
IL = int("$IL",16)
kpar = int("$parent_priv",16)
n = int("$n",16)
child = (IL + kpar) % n
print(f"{child:064x}")
EOF
)

    printf '%s %s\n' "$child_priv" "$IR"
}

# btc_priv_to_pub
btc_priv_to_pub() {
	priv=${1-}
	[ -z $priv ] && { printf "argument missing: private key\n" >&2; return 1; }
    pub=$(python3 - <<EOF
import binascii, secp256k1
priv = binascii.unhexlify("$priv")
sk = secp256k1.PrivateKey(priv, raw=True)
pub = sk.pubkey.serialize(compressed=True)
print(pub.hex())
EOF
)
	# Compressed pubkey: 
    printf "%s\n" "$pub"
}

# --- Derive path m/48'/0'/0'/0' ---
btc_derive_path_4800() {
    master_priv=$1
    master_chain=$2
    out_file=${3:-privkey.hex}

    priv="$master_priv"
    chain="$master_chain"
    path_indices=(48 0 0 0)

    printf "%s\n" "Deriving path m/48'/0'/0'/0'..."
    for idx in "${path_indices[@]}"; do
        read priv chain <<< $(btc_ckd_priv_hardened "$priv" "$chain" "$idx")
        printf "%s\n%s\n%s\n" "Index $idx hardened:" "  priv:  $priv" "  chain: $chain"
    done

    # Save final private key
    printf '%s\n' "$priv" > "$out_file"
    echo "Final private key saved to $out_file"

	# Compressed pubkey: 
    printf "%s\n" $(btc_priv_to_pub "$priv")
}

hmac_sha512() {
    key_hex=$1
    data_hex=$2

    printf '%s' "$data_hex" |
        xxd -r -p |
        openssl dgst -sha512 -mac HMAC -macopt hexkey:"$key_hex" |
        awk '{print $2}'
}

btc_seed_from_mnemonic() {
    mnemonic=$1
    passphrase=${2:-}
    out_file=${3:-seed.hex}

    # Validate word count
    words=$(printf '%s\n' "$mnemonic" | wc -w | tr -d ' ')
    case "$words" in
        12|15|18|21|24) ;;
        *)
            echo "Error: mnemonic must be BIP 39 words" >&2
            return 1
            ;;
    esac

    salt="mnemonic${passphrase}"

    seed_hex=$(
        openssl kdf \
            -out /dev/stdout \
            -binary \
            -keylen 64 \
            -kdfopt digest:SHA512 \
            -kdfopt iter:2048 \
            -kdfopt pass:"$mnemonic" \
            -kdfopt salt:"$salt" \
            PBKDF2 |
        xxd -p -c 64
    ) || return 1

    # save and print
    if [ ! "$out_file" = "none" ]; then
		printf '%s\n' "$seed_hex" > "$out_file"
    fi
    #~ printf '%s\n' "$mnemonic" > "mnemonic.text"
    printf '%s\n' "$seed_hex"
}

# echo "Native SegWit address: "$(btc_pub_to_segwit "$pub" mainnet)
btc_pub_to_segwit() {
    pub_hex=$1   # compressed public key in hex
    network=${2:-mainnet}  # "mainnet" or "testnet"

    # choose Bech32 prefix
    if [ "$network" = "testnet" ]; then
        hrp="tb"
    else
        hrp="bc"
    fi

    # Python helper for HASH160 + Bech32 (BIP-173)
    addr=$(python3 - <<EOF
import binascii, hashlib
import bech32

pub = binascii.unhexlify("$pub_hex")

# HASH160: RIPEMD160(SHA256(pubkey))
h = hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()

# encode as native SegWit Bech32 (version 0)
print(bech32.encode("$hrp", 0, h))
EOF
)

    echo "$addr"
}

die() {
    printf "%s\n" "$*" >&2

    if (return 0 2>/dev/null); then
        return 1
    else
        exit 1
    fi
}

# stop if sourced
(return 0 2>/dev/null) && return 0
# otherwise run as script

comp_pubkey="02b13b525b03d047270ba52f1f8d42f5c48d600506c716af16c8c1cfbb1887cbcc" # for fallback bacon*24
mnemonic="bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon"
passphrase="" # for custom salt added to seed
arg1="${1-}"         # pass your 24-word mnemonic as first argument
if [ -z "$arg1" ]; then
	die "missing arguments: mnemonic or decrypted json backup file"
elif [ -f "$arg1" ]; then
	fn="$arg1"
	mnemonic=$(get_jq_from_json '.mnemonic' "$fn")
	comp_pubkey=$(get_jq_from_json '.publicKey' "$fn")
fi

printf "\n%s\n" "=== Step 1: Generate seed from mnemonic ==="
seed=$(btc_seed_from_mnemonic "$mnemonic" "$passphrase" "none")
echo "Seed: $seed"

printf "\n%s\n" "=== Step 2: Generate master key ==="
master=$(btc_master_key_from_seed "$seed")
printf "Master Private Key (hex): %s\nMaster Chain Code   (hex): %s\n" $(printf "%s" "$master")
master_priv=$(printf "$master" | head -n 1 | tr -d '[:space:]')
master_chain=$(printf "$master" | head -n 2 | tail -n 1 | tr -d '[:space:]')

printf "\n%s\n" "=== Step 3: Derive path m/48'/0'/0'/0' step by step ==="
#~ btc_derive_path_4800 master_priv master_chain [out_file]
priv="$master_priv"
chain="$master_chain"
path_indices="48 0 0 0"

for idx in $path_indices; do
    echo "Deriving index $idx hardened..."
    # POSIX-safe: use set -- to split output into positional parameters
    set -- $(btc_ckd_priv_hardened "$priv" "$chain" "$idx")
    priv=$1
    chain=$2
    echo "Intermediate priv: $priv"
    echo "Intermediate chain: $chain"
done

out_priv="privkey.hex"
echo "Final private key saved to $out_priv"
printf '%s\n' "$priv" > "$out_priv"

printf "\n%s\n" "=== Step 4: Compute compressed public key ==="
pub=$(btc_priv_to_pub "$priv")
printf "Compressed pubkey: %s\n" "$pub"
if [ "$pub" = "$comp_pubkey" ] ; then
	printf "%s\n" "passes match with expected pubkey"
else
	printf "%s\n" "failed match with expected pubkey"
fi
