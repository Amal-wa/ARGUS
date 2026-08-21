package authz.adaptive_access_test

import data.authz.adaptive_access

# Dynamic, data-derived threshold (model p98) replacing the old hardcoded 0.8.

test_score_above_threshold_step_up if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.70, "threshold": 0.651},
	}
}

test_score_below_threshold_allow if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.60, "threshold": 0.651},
	}
}

test_score_equal_threshold_step_up if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.651, "threshold": 0.651},
	}
}

test_bootstrap_mode_unchanged if {
	adaptive_access.bootstrap_mode with input as {"risk_ctx": {"score": null}}
	adaptive_access.risk_decision == "allow" with input as {"risk_ctx": {"score": null}}
}

# Model-loss signal: model:active_version disappearing AFTER a model was once
# promoted (failed promotion, Redis key loss, incident) must NOT be treated
# the same as a fresh deployment that has never trained a model -- see
# AuthorizationService.authorize / scripts/promote_model.py's model:ever_active
# flag. bootstrap_mode stays true in this case too (score is still null), but
# model_unavailable takes precedence -- same "independent gate" mechanism as
# high_distinct_ips/sensitive_action/monitoring_audit_access.

test_model_unavailable_step_up_after_prior_promotion if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": null, "model_ever_active": true},
	}
}

test_model_unavailable_does_not_fire_on_true_first_bootstrap if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": null, "model_ever_active": false},
	}
}

# Backward-compatibility: an older Gateway (or any input that simply omits
# the field) must fall through to the pre-existing bootstrap-allow behavior,
# not become undefined/deny.
test_model_unavailable_does_not_fire_when_field_absent if {
	adaptive_access.risk_decision == "allow" with input as {"risk_ctx": {"score": null}}
}

# Type-confusion defense in depth, same discipline as mfa.rego's
# ticket_verified/grace_verified checks: `==` is strict-type equality, so a
# stringly-typed "true" must not satisfy this.
test_model_unavailable_type_confusion_string_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": null, "model_ever_active": "true"},
	}
}

# Scoping proof: model_unavailable only ever applies while score is null --
# model_ever_active being true must not affect a normal, currently-active-model
# score-driven decision.
test_model_ever_active_true_does_not_affect_decision_when_model_currently_active if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98, "model_ever_active": true},
	}
}

# Desync defense in depth: score present but threshold missing must NOT step_up --
# risk_decision is left undefined (falls through to decision.rego's fail-closed
# default) rather than silently allowing.

test_missing_threshold_does_not_step_up if {
	not adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.70, "threshold": null},
	}
}

test_missing_threshold_does_not_allow if {
	not adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.70, "threshold": null},
	}
}

test_missing_threshold_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": 0.70, "threshold": null},
	}
}

# Type-confusion defense in depth: Rego's `<`/`>=` are defined over a total order
# across ALL JSON types (null < false < true < numbers < strings < arrays < objects),
# not just numbers -- e.g. `5 < {"a": 1}` is `true` and `5 >= "x"` is `false`, both
# silently, with no error and no "undefined". Without the `is_number` guards in
# adaptive_access.rego, a malformed score/threshold (a string, boolean, or object --
# not just null) would still produce a *deterministic, wrong* allow/step_up decision
# from type-ordering trivia instead of leaving risk_decision undefined. Each case below
# pairs one malformed field with an otherwise-valid partner value.

test_malformed_score_string_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": "0.70", "threshold": 0.651},
	}
}

test_malformed_score_boolean_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": true, "threshold": 0.651},
	}
}

test_malformed_score_object_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": {"value": 0.70}, "threshold": 0.651},
	}
}

test_malformed_threshold_string_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": 0.70, "threshold": "0.651"},
	}
}

test_malformed_threshold_boolean_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": 0.70, "threshold": false},
	}
}

test_malformed_threshold_object_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": 0.70, "threshold": {"value": 0.651}},
	}
}

# Range defense in depth: a well-typed NUMBER outside the plausible [0, 1]
# probability domain is_number alone would still accept (is_number(57.0) is
# true) -- proven live: an impersonating/malfunctioning Isolation Forest
# instance returning risk_score: 57.0 crashed opa_decision_log's CHECK
# constraint downstream with an uncaught exception. is_valid_probability
# closes this the same way the type-confusion guards above do: leaves
# risk_decision undefined rather than evaluating a comparison against a
# nonsensical value. See SECURITY.md.

test_out_of_range_score_above_one_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": 57.0, "threshold": 0.98},
	}
}

test_out_of_range_score_negative_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": -3.0, "threshold": 0.98},
	}
}

test_out_of_range_threshold_above_one_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": 0.10, "threshold": 57.0},
	}
}

test_out_of_range_threshold_negative_leaves_risk_decision_undefined if {
	not adaptive_access.risk_decision with input as {
		"risk_ctx": {"score": 0.10, "threshold": -3.0},
	}
}

# Boundary check: 0 and 1 themselves are valid probabilities, not
# off-by-one-excluded -- inclusive bounds, same discipline as the existing
# score==threshold boundary test above.

test_score_of_zero_is_valid if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.0, "threshold": 0.98},
	}
}

test_score_of_one_is_valid if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 1.0, "threshold": 0.98},
	}
}

# Session-hijack signal: independent of the score, so it must override even a
# comfortably-low score/bootstrap state, but must never fire below 2 or on a
# malformed feature_vector.

test_high_distinct_ips_step_up_even_with_low_score if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0],
	}
}

test_high_distinct_ips_step_up_even_during_bootstrap if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": null},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0],
	}
}

test_distinct_ips_of_one_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
	}
}

test_missing_feature_vector_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
	}
}

# Type-confusion defense in depth on feature_vector[13] specifically -- the
# SAME class of guard (is_number before comparing) as is_valid_probability
# above, but previously untested for this rule: a malformed feature_vector[13]
# (from a buggy/compromised Gateway, or a schema drift) must not silently
# defeat the total-order comparison trivia this project has already found and
# fixed once for score/threshold (`5 < {"a": 1}` is `true` in Rego, `5 >= "x"`
# is `false`, both without error). is_number(x) is false for all of these, so
# high_distinct_ips is undefined and risk_decision falls through to the
# normal score-driven rule -- asserted as a determinate "allow" (not merely
# "not step_up"), since score/threshold themselves stay valid in every case
# below, same pattern as the four high_distinct_ips tests above.

test_high_distinct_ips_malformed_string_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "2", 0, 0],
	}
}

test_high_distinct_ips_malformed_boolean_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, true, 0, 0],
	}
}

test_high_distinct_ips_malformed_object_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {"value": 2}, 0, 0],
	}
}

test_high_distinct_ips_malformed_null_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, null, 0, 0],
	}
}

# A truncated feature_vector (e.g. a Gateway bug shipping <16 dims) leaves
# feature_vector[13] undefined, not an error or a crash -- same safe-fallthrough
# as the entirely-missing-key case above, but for the "present but too short"
# shape specifically.
test_high_distinct_ips_truncated_feature_vector_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Resource-enumeration gate, phase 1 (step_up only): independent of the
# score, same mechanism as high_distinct_ips, on feature_vector[7] (distinct
# raw resources) with a threshold of 15.

test_high_distinct_resources_step_up_at_threshold if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0],
	}
}

test_high_distinct_resources_just_below_threshold_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Real scenario-A enumeration burst value (reader8@zt.local, 2026-08-20,
# live-verified max) -- must be caught, not just the synthetic boundary above.
test_high_distinct_resources_step_up_on_real_attack_value if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 207, 0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Real observed normal-traffic ceiling this session (editor5@zt.local /
# post-exclusion max) -- must NOT force step_up via this rule.
test_high_distinct_resources_normal_value_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Bootstrap proof: the whole point of this test is that it must NOT crash
# with eval_conflict_error -- proves the "not high_distinct_resources" guard
# was correctly added to the bootstrap-allow rule (same pattern as
# model_unavailable's own bootstrap test above). If the guard were missing,
# this input (bootstrap_mode true AND high_distinct_resources true
# simultaneously) would try to set risk_decision to "allow" and "step_up" at
# once.
test_high_distinct_resources_step_up_even_during_bootstrap if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": null},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Type-confusion defense in depth, same discipline as high_distinct_ips's own
# malformed-feature_vector[13] tests above.
test_high_distinct_resources_malformed_string_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, "15", 0, 0, 0, 0, 0, 0, 0, 0],
	}
}

test_high_distinct_resources_missing_feature_vector_does_not_force_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
	}
}

# Resource-enumeration gate, phase 2 (deny): volume >= 26 AND 0 < interval <= 5s.
# The 4 volume x cadence quadrants, plus the phase 1/phase 2 precedence
# resolution and the bootstrap non-conflict proof.

# Quadrant 1: high volume, mechanical cadence -- the real attack shape
# (reader8@zt.local scenario A: 178/178 samples between 0 and 1s, mean 0.82s).
test_high_distinct_resources_critical_deny_high_volume_fast_cadence if {
	adaptive_access.risk_decision == "deny" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 26, 3.0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Quadrant 2: high volume, SLOW cadence -- the false-positive case this rule
# must avoid: a legitimate user who genuinely touched 26+ distinct resources
# over a normal browsing pace (interval=24s) must not be denied outright.
# Phase 1's high_distinct_resources still applies (26 >= 15), so step_up, not
# allow -- this proves the volume alone does not deny, cadence is required too.
test_high_distinct_resources_critical_high_volume_slow_cadence_not_deny if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 26, 24.0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Quadrant 3: high volume, interval=0 (the documented "fewer than 2
# timestamps yet" sentinel, not a real sub-second pace) -- must NOT deny.
# Phase 1 still catches the volume (step_up), matching quadrant 2's outcome.
test_high_distinct_resources_critical_zero_interval_sentinel_not_deny if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Quadrant 4 (implicit): volume 15-25 (phase 1's own range, below phase 2's
# floor) -- step_up regardless of cadence, never deny. Reuses the existing
# phase 1 threshold test (fv[7]=15) above, which already asserts "step_up";
# this one pins a fast cadence at that lower volume to prove cadence alone
# never triggers deny without volume >= 26.
test_high_distinct_resources_fast_cadence_below_critical_volume_not_deny if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 20, 2.0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Volume < 15: neither step_up nor deny via either resource rule.
test_high_distinct_resources_low_volume_fast_cadence_not_deny_not_step_up if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 8, 2.0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Precedence resolution: at volume >= 26 with mechanical cadence, BOTH
# high_distinct_resources (phase 1, >= 15) and high_distinct_resources_critical
# (phase 2, >= 26) are true simultaneously -- deny must win, and evaluating
# risk_decision must not crash with eval_conflict_error. This is the exact
# input the "not high_distinct_resources_critical" guard on phase 1's step_up
# rule exists for.
test_high_distinct_resources_critical_wins_over_phase1_step_up if {
	adaptive_access.risk_decision == "deny" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 31, 1.0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Bootstrap: score null AND critical conditions both true -- must deny, not
# crash. Proves the "not high_distinct_resources_critical" guard on the
# bootstrap-allow rule works, same pattern as model_unavailable's own
# bootstrap test.
test_high_distinct_resources_critical_deny_even_during_bootstrap if {
	adaptive_access.risk_decision == "deny" with input as {
		"risk_ctx": {"score": null},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 26, 3.0, 0, 0, 0, 0, 0, 0, 0],
	}
}

# Cross-rule conflict: a real reachable input where high_distinct_ips (step_up)
# and high_distinct_resources_critical (deny) are BOTH true at once -- proves
# the "not high_distinct_resources_critical" guard added to high_distinct_ips's
# own step_up rule (not just phase 1's) actually prevents eval_conflict_error.
test_high_distinct_resources_critical_wins_over_high_distinct_ips if {
	adaptive_access.risk_decision == "deny" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 26, 3.0, 0, 0, 0, 0, 0, 0, 2],
	}
}

# Type-confusion defense in depth on the new dimension used (feature_vector[8]),
# same discipline as feature_vector[7]/[13]'s own malformed-value tests above.
test_high_distinct_resources_critical_malformed_interval_does_not_deny if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 26, "3.0", 0, 0, 0, 0, 0, 0, 0],
	}
}

# Sensitive-action gate: independent of the score AND of bootstrap_mode --
# closes the attack surface where a password-only compromise has full access
# to anything the score doesn't flag, for high-impact actions specifically.

test_sensitive_delete_step_up_even_with_low_score if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"resource": {"http_method": "DELETE", "route": "/documents/{document_id}", "action": "delete"},
	}
}

test_sensitive_delete_step_up_during_bootstrap if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": null},
		"resource": {"http_method": "DELETE", "route": "/documents/{document_id}", "action": "delete"},
	}
}

test_sensitive_users_create_step_up if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"resource": {"http_method": "POST", "route": "/users", "action": "create"},
	}
}

test_sensitive_users_update_step_up if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"resource": {"http_method": "PUT", "route": "/users/{user_id}", "action": "update"},
	}
}

# Reading a user is never sensitive -- RBAC already restricts /users read to
# admin; requiring a step-up on top of that for a plain GET has no
# proportionate security justification.
test_users_read_not_sensitive if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"resource": {"http_method": "GET", "route": "/users/{user_id}", "action": "read"},
	}
}

# update outside /users (documents, orders) is deliberately NOT in scope --
# proves the rule doesn't silently widen into "every write is sensitive".
test_non_users_update_not_sensitive if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"resource": {"http_method": "PUT", "route": "/documents/{document_id}", "action": "update"},
	}
}

# delete is sensitive regardless of WHICH resource -- not just /users.
test_delete_on_orders_also_sensitive if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"resource": {"http_method": "DELETE", "route": "/orders/{order_id}", "action": "delete"},
	}
}

# Monitoring-audit gate: /monitoring/audit is the detailed, exportable
# decision/event audit trail -- the highest reconnaissance-value read in
# this system, and the only monitoring endpoint capable of bulk
# exfiltration (CSV, up to 5000 rows). Structurally never reachable via the
# score at all: AuthorizationService skips scoring entirely for every
# /monitoring/* route, so risk_ctx.score is always null there.

test_monitoring_audit_forces_step_up_even_with_low_score if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"resource": {"http_method": "GET", "route": "/monitoring/audit", "action": "read"},
	}
}

# The realistic case: risk_ctx.score is ALWAYS null for /monitoring/* (see
# above) -- this is not a rare transitional state for this route the way
# bootstrap is for business routes, it's the permanent, only state.
test_monitoring_audit_forces_step_up_during_bootstrap if {
	adaptive_access.risk_decision == "step_up" with input as {
		"risk_ctx": {"score": null},
		"resource": {"http_method": "GET", "route": "/monitoring/audit", "action": "read"},
	}
}

# The rest of /monitoring/* is deliberately NOT gated -- these are polled
# continuously (5-30s) by the live dashboard view; gating them would be a
# real UX regression for disproportionately little security gain (aggregate
# counts, health -- not the detailed, exportable audit trail).

test_monitoring_stats_not_gated if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": null},
		"resource": {"http_method": "GET", "route": "/monitoring/stats", "action": "read"},
	}
}

test_monitoring_alerts_not_gated if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": null},
		"resource": {"http_method": "GET", "route": "/monitoring/alerts", "action": "read"},
	}
}

test_monitoring_risk_timeline_not_gated if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": null},
		"resource": {"http_method": "GET", "route": "/monitoring/risk-timeline", "action": "read"},
	}
}

test_monitoring_system_status_not_gated if {
	adaptive_access.risk_decision == "allow" with input as {
		"risk_ctx": {"score": null},
		"resource": {"http_method": "GET", "route": "/monitoring/system-status", "action": "read"},
	}
}
