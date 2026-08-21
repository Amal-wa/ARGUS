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

# Independent of the ML score, and NOT guarded by `not bootstrap_mode` -- same
# "independent gate" mechanism as high_distinct_ips/sensitive_action/
# monitoring_audit_access below. bootstrap_mode alone (score == null) cannot
# tell "no model has ever been trained" (a genuinely permissive state, day one
# of a fresh deployment) apart from "a model WAS promoted to production and
# risk_ctx.score is null now anyway" (model:active_version lost -- failed
# promotion, Redis key loss, incident). The Gateway tells these apart via
# model:ever_active (a one-way flag set once by scripts/promote_model.py,
# never cleared -- see AuthorizationService.authorize) and reports it as
# risk_ctx.model_ever_active. Strict `== true`, not a truthy check: a
# stringly-typed "true" must not satisfy this, same discipline as
# mfa.rego's ticket_verified/grace_verified checks.
model_unavailable if {
	input.risk_ctx.score == null
	input.risk_ctx.model_ever_active == true
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

# Phase 1 of a graduated response to resource enumeration (step_up only --
# deny is a later phase, not implemented here). Same "independent gate,
# bypasses the score" mechanism as high_distinct_ips above, on
# feature_vector[7] (distinct raw resources, 5 min window) instead of [13].
# Threshold 15 is a live-verified margin, not the attack floor itself: this
# session's own real data (ml_training_samples, 2026-08) shows real normal
# traffic tops out at 11 (excluding known test/attack accounts), while the
# reader8@zt.local scenario-A enumeration burst starts at 31 -- 15 sits
# comfortably above the observed normal ceiling and well below where actual
# attack traffic begins, without being pinned to the attack's own floor.
HIGH_DISTINCT_RESOURCES_THRESHOLD := 15

high_distinct_resources if {
	is_number(input.feature_vector[7])
	input.feature_vector[7] >= HIGH_DISTINCT_RESOURCES_THRESHOLD
}

# Phase 2: volume high enough AND paced mechanically enough that this is no
# longer "atypical but maybe legitimate" (phase 1's territory) -- it's refused
# outright, even though RBAC and MFA would otherwise allow it. Two independent
# gates, both required:
#   - Volume: 26, not a new number -- reused from behavioral-detector's own
#     empirically-calibrated resource_access threshold (the most active real
#     legitimate account observed, editor5@zt.local, tops out at 25) rather
#     than inventing a second, uncoordinated volume threshold for the same
#     underlying signal.
#   - Cadence: 0 < interval <= 5s. The lower bound excludes feature_vector[8]'s
#     documented sentinel (0.0, "fewer than 2 timestamps in the window yet" --
#     see FeatureVectorService._interval_stats) -- without it, the first 1-2
#     requests of every legitimate window would satisfy interval<=5 by
#     accident, not because they're fast. Live-verified this session: 178/178
#     of reader8@zt.local's real scenario-A samples (resource_access > 30) sit
#     between 0 and 1s (mean 0.82s, max 0.87s) -- never exactly 0, since a
#     resource count that high is structurally impossible on a window with
#     fewer than 2 recorded requests. 5s leaves comfortable margin above that
#     measured attack pace while still requiring genuinely mechanical timing.
HIGH_DISTINCT_RESOURCES_CRITICAL_VOLUME := 26

HIGH_DISTINCT_RESOURCES_CRITICAL_INTERVAL_SECONDS := 5

high_distinct_resources_critical if {
	is_number(input.feature_vector[7])
	input.feature_vector[7] >= HIGH_DISTINCT_RESOURCES_CRITICAL_VOLUME
	is_number(input.feature_vector[8])
	input.feature_vector[8] > 0
	input.feature_vector[8] <= HIGH_DISTINCT_RESOURCES_CRITICAL_INTERVAL_SECONDS
}

# Terminal: deliberately NOT rescued by MFA (no rule anywhere checks
# risk_decision == "deny" and mfa.mfa_verified together -- see decision.rego).
# At this volume/pace, MFA having been verified earlier in the session says
# nothing about whether THIS mechanical burst is the legitimate MFA-holder or
# a hijacked/already-authenticated session being driven by a script -- a
# validated design decision, not an oversight.
risk_decision := "deny" if {
	high_distinct_resources_critical
}

risk_decision := "allow" if {
	bootstrap_mode
	not high_distinct_ips
	not high_distinct_resources
	not high_distinct_resources_critical
	not sensitive_action
	not monitoring_audit_access
	not model_unavailable
}

# Same value ("step_up") as the other independent-gate rules below whenever
# more than one happens to fire -- Rego only conflicts on DIFFERENT values for
# the same complete rule, safe to define unconditionally. This is what makes
# the `not model_unavailable` guard above safe: without it, a model-loss
# input (bootstrap_mode true AND model_unavailable true, simultaneously,
# since both only require score == null) would try to set risk_decision to
# "allow" here and "step_up" below at the same time -- an eval_conflict_error
# that crashes the /v1/data/authz/decision call, not a silent wrong answer.
# `not high_distinct_resources_critical` guards against the SAME class of
# conflict against the new "deny" value above: model_unavailable and
# high_distinct_resources_critical are independent dimensions (score==null
# says nothing about feature_vector[7]/[8]), so a request satisfying both
# simultaneously is a real, reachable input, not a theoretical one.
risk_decision := "step_up" if {
	model_unavailable
	not high_distinct_resources_critical
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
	not high_distinct_resources
	not high_distinct_resources_critical
	not sensitive_action
	not monitoring_audit_access
}

# `not high_distinct_resources_critical`: score and feature_vector[7]/[8] are
# independent dimensions -- a request can plausibly have BOTH a high score AND
# a mechanical enumeration burst at once (in practice the more likely case,
# not a corner case: a real attacker moving this fast would often also push
# the score up), so without this guard a real input could try to set
# risk_decision to "step_up" here and "deny" below simultaneously.
risk_decision := "step_up" if {
	not bootstrap_mode
	is_valid_probability(input.risk_ctx.score)
	is_valid_probability(input.risk_ctx.threshold)
	input.risk_ctx.score >= input.risk_ctx.threshold
	not high_distinct_resources_critical
}

# Same value ("step_up") as the score-driven rule above whenever both happen to
# fire -- Rego only conflicts on DIFFERENT values for the same complete rule,
# so this is safe to define unconditionally rather than folded into every
# branch above. `not high_distinct_resources_critical`: distinct_ips and
# feature_vector[7]/[8] are independent -- a hijacked session driven fast
# enough to also enumerate resources satisfies both high_distinct_ips and
# high_distinct_resources_critical at once, a real reachable input.
risk_decision := "step_up" if {
	high_distinct_ips
	not high_distinct_resources_critical
}

# Same value ("step_up") as the other independent-gate rules whenever more
# than one happens to fire -- Rego only conflicts on DIFFERENT values for the
# same complete rule, safe to define unconditionally. `not
# high_distinct_resources_critical` is the phase 1/phase 2 precedence
# resolution: high_distinct_resources_critical's volume floor (26) is always
# >= HIGH_DISTINCT_RESOURCES_THRESHOLD (15), so critical implies this rule's
# own condition too -- without this guard, crossing 26 at a mechanical pace
# would try to set risk_decision to "step_up" here AND "deny" above at the
# same time, on every single request that reaches phase 2's threshold. Deny
# must win.
risk_decision := "step_up" if {
	high_distinct_resources
	not high_distinct_resources_critical
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
# `not high_distinct_resources_critical`: action/route and feature_vector[7]/
# [8] are independent -- an enumeration burst that also happens to include a
# delete, or a create/update against /users, is a real reachable input.
risk_decision := "step_up" if {
	sensitive_action
	not high_distinct_resources_critical
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
# `not high_distinct_resources_critical`: feature_vector is built from the
# same 5-min sliding window regardless of route, so a user who enumerated
# resources elsewhere in the window and then hits /monitoring/audit still
# carries feature_vector[7]/[8] from that burst -- a real reachable input,
# not just monitoring_audit_access's own route check in isolation.
risk_decision := "step_up" if {
	monitoring_audit_access
	not high_distinct_resources_critical
}
