#!/usr/bin/env bash
set -euo pipefail
mkdir -p keys
openssl genpkey -algorithm ED25519 -out keys/m2m-client-private.pem
openssl pkey -in keys/m2m-client-private.pem -pubout -out keys/m2m-client-public.pem
chmod 600 keys/m2m-client-private.pem
echo 'M2M client key generated; keep the private key with the client only.'
