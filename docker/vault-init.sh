#!/bin/sh
set -e   # fail loudly on any real error

export VAULT_ADDR="http://vault:8200"
export VAULT_TOKEN="dev-root-token"

# Wait until Vault is reachable and unsealed (dev mode starts unsealed, but the
# container may not be ready the instant the healthcheck flips - small retry loop).
echo "Waiting for Vault to be reachable..."
until vault status >/dev/null 2>&1; do
  sleep 1
done
echo "Vault is reachable."

# Enable transit only if not already enabled (check-before-act, idempotent).
if vault secrets list -format=json | grep -q '"transit/"'; then
  echo "transit engine already enabled, skipping."
else
  echo "Enabling transit engine..."
  vault secrets enable transit
fi

# Create the gateway-jwt key only if it doesn't already exist.
if vault list transit/keys 2>/dev/null | grep -q '^gateway-jwt$'; then
  echo "gateway-jwt key already exists, skipping."
else
  echo "Creating gateway-jwt (ed25519) key..."
  vault write -f transit/keys/gateway-jwt type=ed25519
fi

# Create the totp-encryption key only if it doesn't already exist.
if vault list transit/keys 2>/dev/null | grep -q '^totp-encryption$'; then
  echo "totp-encryption key already exists, skipping."
else
  echo "Creating totp-encryption (aes256-gcm96) key..."
  vault write -f transit/keys/totp-encryption type=aes256-gcm96
fi

echo "Vault provisioning complete."
