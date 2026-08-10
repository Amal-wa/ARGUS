# METADATA
# description: risk_ctx input shape is checked against policies/schemas/input.json via `opa check --schema`.
# schemas:
#   - input: schema["input"]
package authz.adaptive_access

# Bootstrap: no ML model trained yet, Gateway sends risk_ctx.score = null explicitly.
# Only this exact documented shape counts as bootstrap — a missing risk_ctx entirely
# is a contract violation and must NOT be treated as bootstrap (see note below).
bootstrap_mode if {
	input.risk_ctx.score == null
}

# Independent of the ML risk score -- a live replay of the traffic-generator's
# scenario C (session hijack: same user, brand-new IP, otherwise ordinary
# request pattern) showed this single feature is far too diluted among the
# other 15 dimensions to move the score anywhere near the threshold (0/100
# requests crossed it in that replay, despite the feature itself correctly
# jumping from 1 to 2). Checked against every real sample gathered so far
# (ml_training_samples, 2026-07): every single row with feature_vector[13] >= 2
# came from that one attack replay -- zero from any other real traffic in the
# dataset. That makes this a much cleaner standalone signal than routing it
# through the (diluted) score, at least on the evidence collected so far.
# Deliberately takes precedence over risk_decision == "allow" below (see the
# "not high_distinct_ips" guards there) rather than merely adding to the score,
# since the whole point is to not depend on the score's dilution of it.
high_distinct_ips if {
	is_number(input.feature_vector[13])
	input.feature_vector[13] >= 2
}

risk_decision := "allow" if {
	bootstrap_mode
	not high_distinct_ips
	not sensitive_action
	not monitoring_audit_access
}

# is_number alone (used below) blocks type confusion (a string/boolean/object
# where a number is expected) but NOT a numerically well-typed value outside
# the plausible [0, 1] probability domain -- is_number(57.0) is true. Proven
# live: an impersonating/malfunctioning Isolation Forest instance returning
# risk_score: 57.0 was accepted by is_number's old guard alone, propagated
# into opa_decision_log, and crashed that table's CHECK (risk_score BETWEEN 0
# AND 1) constraint with an uncaught exception -- 500'ing every authenticated
# request in the system on account of a single malformed upstream value, not
# just a wrong decision for the one request that carried it. The Gateway now
# also validates this itself (core/isolation_forest_client.py, fails closed
# with ScoringUnavailableError -> 503 before OPA is ever called), but this
# guard is deliberate defense in depth: OPA's own contract must not silently
# trust a well-typed-but-implausible number either, independent of whether
# the Gateway's own check is ever bypassed, removed, or the endpoint is ever
# called by something other than this Gateway. See SECURITY.md.
is_valid_probability(x) if {
	is_number(x)
	x >= 0
	x <= 1
}

# The threshold is data-derived (the active model's p98, injected by the Gateway from
# Redis' model:active_threshold), never hardcoded here -- see CLAUDE.md. The Gateway
# always substitutes its own fallback threshold before OPA sees the input whenever a
# score is present, so `threshold == null` alongside a non-null score should never
# happen in practice. The `is_valid_probability` guards below are defense in depth for
# that desync (and for any other malformed value -- a string, boolean, object, or an
# out-of-range number, not just null), and they subsume a plain `!= null` check since
# is_valid_probability(null) is also false.
#
# They are NOT just belt-and-braces: Rego's `<`/`>=` are defined over a *total order
# across all JSON types* (null < false < true < numbers < strings < arrays < objects),
# not just numbers -- comparing mismatched types does not error or go undefined, it
# silently returns a real boolean. E.g. `5 < {"a": 1}` is `true` (any number sorts
# below any object), and `5 >= "x"` is `false` (any number sorts below any string).
# So if `threshold` were ever an object (or `score` were ever a string) due to a bug
# upstream, the old code (`threshold != null` only) would have evaluated the raw `<`/
# `>=` comparison anyway and produced a *deterministic, wrong* allow/step_up decision
# from type-ordering trivia -- a silent fail-open, not a crash and not undefined. The
# `is_valid_probability` guards make both branches actually undefined for non-numeric
# AND out-of-range operands, which is what falls through to decision.rego's fail-closed
# default (deny) instead -- the Gateway-side warning log (for the null-threshold desync
# case) or the input schema (see policies/schemas/input.json) is what surfaces the
# underlying problem.
risk_decision := "allow" if {
	not bootstrap_mode
	is_valid_probability(input.risk_ctx.score)
	is_valid_probability(input.risk_ctx.threshold)
	input.risk_ctx.score < input.risk_ctx.threshold
	not high_distinct_ips
	not sensitive_action
	not monitoring_audit_access
}

risk_decision := "step_up" if {
	not bootstrap_mode
	is_valid_probability(input.risk_ctx.score)
	is_valid_probability(input.risk_ctx.threshold)
	input.risk_ctx.score >= input.risk_ctx.threshold
}

# Same value ("step_up") as the score-driven rule above whenever both happen to
# fire -- Rego only conflicts on DIFFERENT values for the same complete rule,
# so this is safe to define unconditionally rather than folded into every
# branch above.
risk_decision := "step_up" if {
	high_distinct_ips
}

# Independent of the ML risk score, AND independent of bootstrap_mode -- some
# actions are high-impact enough (irreversible deletion; provisioning or
# re-privileging an account) that a step-up must be required no matter what
# the score says, or whether a score exists at all. Without this, the actual
# attack surface of the adaptive-MFA model is: a password-only compromise has
# full access to anything the score doesn't flag, for the whole access-token
# lifetime -- including deleting data or creating a new admin account, as
# long as the attacker's request pattern stays under the calibrated
# threshold. This closes that specific gap without abandoning the adaptive
# model for everything else (see CLAUDE.md/SECURITY.md for the full
# rationale). Same "independent gate" mechanism as high_distinct_ips above,
# not a new architecture.
#
# Deliberately NOT guarded by `not bootstrap_mode`: today, before any model is
# ever trained, bootstrap_mode allows literally everything with zero step-up
# -- this rule closes that window too, from day one of a fresh deployment,
# not just once a model is active.
sensitive_action if {
	input.resource.action == "delete"
}

# /users specifically (not documents/orders) for create/update: this is the
# account-provisioning and role/privilege surface -- rbac.rego already treats
# /users as admin-only for every action, so this rule's real-world effect is
# to also require a fresh step-up from an already-admin session before it can
# create or re-privilege an account, not just before it can read one.
sensitive_action if {
	startswith(input.resource.route, "/users")
	input.resource.action in {"create", "update"}
}

# Same value ("step_up") as the score-driven and high_distinct_ips rules
# above whenever more than one happens to fire -- Rego only conflicts on
# DIFFERENT values for the same complete rule, so this is safe to define
# unconditionally rather than folded into every branch above.
risk_decision := "step_up" if {
	sensitive_action
}

# Independent of the ML score, and NOT guarded by `not bootstrap_mode` --
# unlike sensitive_action's case (a transient pre-training state),
# bootstrap_mode is structurally ALWAYS true for /monitoring/* routes (see
# AuthorizationService._is_monitoring_route: scoring is unconditionally
# skipped there), so such a guard would never fire at all, not just rarely.
#
# Scoped to /monitoring/audit specifically, not all of /monitoring/* -- see
# SECURITY.md. The rest of /monitoring (stats/alerts/risk-timeline/
# system-status/decisions) is polled continuously (5-30s) by the live
# dashboard view and carries far less reconnaissance value (aggregate
# counts, health); /monitoring/audit is the detailed, exportable (CSV, up
# to 5000 rows) decision/event audit trail -- fetched only on demand, the
# single highest reconnaissance-value read in this system, and the only
# monitoring endpoint capable of bulk exfiltration.
monitoring_audit_access if {
	input.resource.route == "/monitoring/audit"
}

# Same value ("step_up") as the other independent-gate rules above whenever
# more than one happens to fire -- Rego only conflicts on DIFFERENT values
# for the same complete rule, safe to define unconditionally.
risk_decision := "step_up" if {
	monitoring_audit_access
}
