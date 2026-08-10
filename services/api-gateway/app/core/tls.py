from __future__ import annotations

import ssl


def build_gateway_client_ssl_context(*, client_cert_path: str, client_key_path: str, ca_cert_path: str) -> ssl.SSLContext:
    # The Gateway's own mTLS client identity, shared across every outbound
    # internal service it authenticates to (OPA, Isolation Forest) -- one
    # certificate, one CA verification, since it's the same Gateway process
    # proving the same identity to different peers signed by the same
    # internal root (see docker/vault-init.sh). Originally OPA-specific
    # (mTLS Gateway<->OPA); generalized when the identical pattern was
    # extended to Gateway<->Isolation Forest after a live audit proved that
    # leg had zero TLS/auth at all -- see SECURITY.md.
    #
    # load_cert_chain/load_verify_locations raise (FileNotFoundError/
    # ssl.SSLError) if a path is missing or invalid -- deliberately no
    # pre-check here, so a misconfigured deployment fails loudly at startup
    # instead of falling back to an unauthenticated connection.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=ca_cert_path)
    context.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
    return context
