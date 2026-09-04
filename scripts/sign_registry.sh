#!/bin/sh
# Signs registry.json with the Ed25519 private key passed as an argument.
# Produces registry.json.sig (signature) and registry.json.sha256 (checksum).
# Portable: does not depend on xxd or sha256sum.
set -e
KEY="$1"
if [ -z "$KEY" ]; then
  echo "usage: sign_registry.sh <cle_privee.pem>" >&2
  exit 1
fi

# Encodes the binary input as lowercase hexadecimal, with no spaces or newline.
hexenc() {
  if command -v xxd >/dev/null 2>&1; then
    xxd -p | tr -d '\n'
  elif command -v od >/dev/null 2>&1; then
    od -An -v -tx1 | tr -d ' \n'
  else
    hexdump -ve '/1 "%02x"'
  fi
}

PUB=$(openssl pkey -in "$KEY" -pubout -outform DER | tail -c 32 | hexenc)
SIG=$(openssl pkeyutl -sign -rawin -inkey "$KEY" -in registry.json | hexenc)
SUM=$(openssl dgst -sha256 registry.json | awk '{print $NF}')
printf '{\n  "format": "nmm-registry-signature",\n  "version": 1,\n  "algorithm": "ed25519",\n  "file": "registry.json",\n  "sha256": "%s",\n  "signatures": [\n    { "public_key": "%s", "signature": "%s" }\n  ]\n}\n' "$SUM" "$PUB" "$SIG" > registry.json.sig
printf '%s  registry.json\n' "$SUM" > registry.json.sha256
echo "signe : registry.json.sig et registry.json.sha256 ecrits."
