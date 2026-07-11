package authz.mfa

# OPA never verifies the TOTP code itself — that's a cryptographic operation
# owned by the Gateway. This module only checks whether the Gateway has
# already confirmed a successful step-up verification.
mfa_verified if {
    input.mfa.verified == true
}