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
}

# The threshold is data-derived (the active model's p98, injected by the Gateway from
# Redis' model:active_threshold), never hardcoded here -- see CLAUDE.md. The Gateway
# always substitutes its own fallback threshold before OPA sees the input whenever a
# score is present, so `threshold == null` alongside a non-null score should never
# happen in practice. The `is_number` guards below are defense in depth for that
# desync (and for any other malformed value -- a string, boolean, or object, not just
# null), and they subsume a plain `!= null` check since is_number(null) is also false.
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
# `is_number` guards make both branches actually undefined for non-numeric operands,
# which is what falls through to decision.rego's fail-closed default (deny) instead --
# the Gateway-side warning log (for the null-threshold desync case) or the input
# schema (see policies/schemas/input.json) is what surfaces the underlying problem.
risk_decision := "allow" if {
	not bootstrap_mode
	is_number(input.risk_ctx.score)
	is_number(input.risk_ctx.threshold)
	input.risk_ctx.score < input.risk_ctx.threshold
	not high_distinct_ips
}

risk_decision := "step_up" if {
	not bootstrap_mode
	is_number(input.risk_ctx.score)
	is_number(input.risk_ctx.threshold)
	input.risk_ctx.score >= input.risk_ctx.threshold
}

# Same value ("step_up") as the score-driven rule above whenever both happen to
# fire -- Rego only conflicts on DIFFERENT values for the same complete rule,
# so this is safe to define unconditionally rather than folded into every
# branch above.
risk_decision := "step_up" if {
	high_distinct_ips
}
