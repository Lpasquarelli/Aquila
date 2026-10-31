#!/usr/bin/env bash
set -euo pipefail
mkdir -p keys
openssl genpkey -algorithm ED25519 -out keys/dev-private.pem
openssl pkey -in keys/dev-private.pem -pubout -out keys/dev-public.pem
chmod 600 keys/dev-private.pem
echo 'Development key generated; never use it in production.'
