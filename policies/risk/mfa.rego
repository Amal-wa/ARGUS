# METADATA
# description: mfa input shape is checked against policies/schemas/input.json via `opa check --schema`.
# schemas:
#   - input: schema["input"]
package authz.mfa

import data.authz.adaptive_access

# OPA never verifies the TOTP code itself — that's a cryptographic operation
# owned by the Gateway. This module only checks whether the Gateway has
# already confirmed a successful step-up verification.
#
# The Gateway deliberately sends two RAW, mechanical pieces of evidence
# instead of one pre-combined boolean -- see CLAUDE.md's "sensitive-action
# step-up gate" section for the finding this closes: a single TOTP used to
# unlock a 5-minute blank check for every subsequent sensitive action, not
# just the one that was actually challenged.
#
# ticket_verified: a single-use ticket scoped to exactly the (user, jti,
# route pattern, action) that was challenged. Always sufficient on its own,
# for any request, sensitive or not -- it IS proof that this specific
# action was just re-verified.
mfa_verified if {
	input.mfa.ticket_verified == true
}

# grace_verified: the broader ambient grace window (still ~5 minutes,
# scoped to user+session since the Gateway fix, but NOT to a specific
# resource/action). Sufficient for ordinary step-ups (score-driven,
# high_distinct_ips) where re-demanding a TOTP on every single request
# within the window would be pure friction with no security benefit. NOT
# sufficient on its own for a sensitive_action -- those must always show a
# ticket for THIS action, no matter how recently any other TOTP was solved.
mfa_verified if {
	input.mfa.grace_verified == true
	not adaptive_access.sensitive_action
}
