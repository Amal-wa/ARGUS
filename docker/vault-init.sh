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

# --- mTLS Gateway<->OPA: PKI secrets engine ---
# Issues the CA + the two leaf certs (OPA server, Gateway client) for the
# mTLS pair discussed/agreed before implementing this. No rotation job:
# Vault runs in dev mode (in-memory storage), so the CA and every cert here
# are regenerated from scratch on every `docker compose up` anyway -- a
# rotation mechanism would have nothing to rotate against within one stack's
# lifetime. Leaf TTL is 2160h (90 days), matching that same reasoning: long
# enough to outlive any single stack run, short enough to read as a real
# policy rather than "forever".
#
# CA_TTL is deliberately LONGER than PKI_TTL, not equal to it: a leaf issued
# a few seconds after the CA (root generation and leaf issuance are two
# separate `vault write` calls, seconds apart) would otherwise have a
# notAfter a few seconds past the CA's own notAfter -- Vault refuses that
# ("cannot satisfy request... beyond the expiration of the CA certificate"),
# caught live on the first run of this script. The CA needs headroom over
# every leaf it will ever sign, not the same TTL as them.
CERTS_DIR=/certs
CA_TTL=4320h
PKI_TTL=2160h

# Extracts a single string field from a `vault write -format=json` response
# file, without jq (not present in this minimal image, and adding it via apk
# would need network egress on every provisioning run -- unnecessary for a
# one-shot, jq-free-solvable extraction). Vault's JSON here is one field per
# line with escaped \n sequences inside PEM string values; sed pulls the raw
# (still-escaped) value out, and `printf '%b'` un-escapes it back into real
# newlines.
json_field() {
  # $1 = json file, $2 = field name
  sed -n "s/^[[:space:]]*\"$2\": \"\(.*\)\",\{0,1\}\$/\1/p" "$1"
}

if vault secrets list -format=json | grep -q '"pki/"'; then
  echo "pki engine already enabled, skipping."
else
  echo "Enabling pki engine..."
  vault secrets enable pki
  vault secrets tune -max-lease-ttl="$CA_TTL" pki
fi

if [ -f "$CERTS_DIR/ca.pem" ]; then
  echo "Internal CA already issued, skipping root generation."
else
  echo "Generating internal root CA..."
  vault write -field=certificate pki/root/generate/internal \
    common_name="ZT-project internal CA" \
    ttl="$CA_TTL" > "$CERTS_DIR/ca.pem"
fi

# Two roles, not one shared role: a server cert (OPA) and a client cert
# (Gateway) have different X.509 extended key usages -- reusing one role for
# both would be technically wrong, not just untidy.
if vault read pki/roles/opa-server >/dev/null 2>&1; then
  echo "opa-server PKI role already exists, skipping."
else
  echo "Creating opa-server PKI role..."
  vault write pki/roles/opa-server \
    allowed_domains="opa" \
    allow_bare_domains=true \
    server_flag=true \
    client_flag=false \
    key_usage="DigitalSignature,KeyEncipherment" \
    ext_key_usage="ServerAuth" \
    max_ttl="$PKI_TTL"
fi

if vault read pki/roles/gateway-client >/dev/null 2>&1; then
  echo "gateway-client PKI role already exists, skipping."
else
  echo "Creating gateway-client PKI role..."
  vault write pki/roles/gateway-client \
    allowed_domains="api-gateway" \
    allow_bare_domains=true \
    server_flag=false \
    client_flag=true \
    key_usage="DigitalSignature,KeyEncipherment" \
    ext_key_usage="ClientAuth" \
    max_ttl="$PKI_TTL"
fi

if [ -f "$CERTS_DIR/opa-server.pem" ]; then
  echo "opa-server certificate already issued, skipping."
else
  echo "Issuing opa-server certificate..."
  vault write -format=json pki/issue/opa-server common_name="opa" ttl="$PKI_TTL" > /tmp/opa-issue.json
  printf '%b\n' "$(json_field /tmp/opa-issue.json certificate)" > "$CERTS_DIR/opa-server.pem"
  printf '%b\n' "$(json_field /tmp/opa-issue.json private_key)" > "$CERTS_DIR/opa-server-key.pem"
  rm -f /tmp/opa-issue.json
  chmod 644 "$CERTS_DIR/opa-server.pem"
  # 644, not 600: this file is written as root (this container) but read by
  # the opa container, which runs as uid 1000 (verified via `docker inspect
  # openpolicyagent/opa:1.18.1 --format '{{.Config.User}}'`), not root -- a
  # 600 file was unreadable to it (caught live: "permission denied" on
  # opa-server-key.pem). The real access boundary for this key is the Docker
  # volume mount (only opa/api-gateway/vault-init have it at all), not Unix
  # file permissions across containers with different, fixed UIDs.
  chmod 644 "$CERTS_DIR/opa-server-key.pem"
fi

if [ -f "$CERTS_DIR/gateway-client.pem" ]; then
  echo "gateway-client certificate already issued, skipping."
else
  echo "Issuing gateway-client certificate..."
  vault write -format=json pki/issue/gateway-client common_name="api-gateway" ttl="$PKI_TTL" > /tmp/gateway-issue.json
  printf '%b\n' "$(json_field /tmp/gateway-issue.json certificate)" > "$CERTS_DIR/gateway-client.pem"
  printf '%b\n' "$(json_field /tmp/gateway-issue.json private_key)" > "$CERTS_DIR/gateway-client-key.pem"
  rm -f /tmp/gateway-issue.json
  chmod 644 "$CERTS_DIR/gateway-client.pem"
  chmod 644 "$CERTS_DIR/gateway-client-key.pem"  # same reasoning as opa-server-key.pem above
fi

echo "Vault provisioning complete."
