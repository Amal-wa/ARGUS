package authz.decision_test

import data.authz

# decision.rego is the policy actually served at /v1/data/authz/decision --
# until now it had no Rego tests at all and was validated only indirectly
# through the gateway's Python tests. Each case here asserts the FULL
# {"decision": ..., "policy_name": ...} object, not just one field, since a
# right decision with the wrong policy_name (or vice versa) is just as real
# a bug. Threshold (0.651) and scores (0.61 below, 0.94 above) mirror
# realistic calibrated values from the live system (see
# scripts/promote_model.py / model:active_threshold).

test_rbac_deny_when_role_lacks_action if {
	authz.decision == {
		"decision": "deny",
		"policy_name": "rbac_deny",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "POST", "route": "/documents", "action": "create"},
	}
}

test_bootstrap_allow_when_no_model_trained_yet if {
	authz.decision == {
		"decision": "allow",
		"policy_name": "bootstrap_allow",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": null},
	}
}

test_risk_allow_when_score_below_threshold if {
	authz.decision == {
		"decision": "allow",
		"policy_name": "risk_allow",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.61, "threshold": 0.651},
	}
}

test_mfa_verified_allow_when_score_above_threshold_and_mfa_verified if {
	authz.decision == {
		"decision": "allow",
		"policy_name": "mfa_verified_allow",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.94, "threshold": 0.651},
		"mfa": {"verified": true},
	}
}

test_step_up_required_when_score_above_threshold_and_mfa_not_verified if {
	authz.decision == {
		"decision": "step_up",
		"policy_name": "step_up_required",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.94, "threshold": 0.651},
		"mfa": {"verified": false},
	}
}

# RBAC passes but risk_ctx is entirely absent. Note this is NOT the same as
# an empty {} input overall -- rbac.allow has its own `default allow :=
# false`, so a fully empty input resolves rbac.allow to false and hits
# rbac_deny, never malformed_input_deny (see test_rbac_deny_... above for
# that path, and the fully-empty case is deliberately not retested here to
# avoid asserting the same rbac_deny path twice). This case needs a
# genuinely RBAC-passing input with a missing/incomplete risk_ctx: bootstrap
# requires an EXPLICIT score: null (see CLAUDE.md), so a merely-missing
# risk_ctx can't satisfy it either, and no risk-based rule can fire -- the
# decision falls through to the fail-closed default.
test_malformed_input_deny_when_risk_ctx_missing if {
	authz.decision == {
		"decision": "deny",
		"policy_name": "malformed_input_deny",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
	}
}

# Boundary 1: the threshold comparison in adaptive_access.rego is `>=`, not
# `>` -- prove the boundary is inclusive (score exactly equal to threshold
# must step up, not allow).
test_score_equal_to_threshold_triggers_step_up if {
	authz.decision == {
		"decision": "step_up",
		"policy_name": "step_up_required",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.651, "threshold": 0.651},
		"mfa": {"verified": false},
	}
}

# Boundary 2: the documented desync case -- score present but threshold
# null. The Gateway always substitutes its own fallback threshold before OPA
# ever sees a non-null score without one (see AuthorizationService), so this
# should never happen in practice -- but this proves OPA's side of the
# defense-in-depth: it does NOT silently allow when it happens anyway, it
# falls through to the fail-closed default instead of guessing.
test_desync_score_present_threshold_null_falls_through_to_default_deny if {
	authz.decision == {
		"decision": "deny",
		"policy_name": "malformed_input_deny",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.94, "threshold": null},
	}
}

# Type-confusion defense in depth, at the decision layer: Rego's `<`/`>=` compare
# across ALL JSON types using a total order (null < false < true < numbers < strings <
# arrays < objects), not just numbers -- so without adaptive_access.rego's `is_number`
# guards, a malformed score/threshold would still produce a deterministic (wrong)
# allow/step_up from type-ordering trivia, a silent fail-open. These mirror
# adaptive_access_test.rego's cases one level up: rbac passes (reader/read/documents),
# so the ONLY thing that can explain the result is risk_decision staying undefined and
# falling through to the fail-closed default.

test_malformed_score_string_denies_at_decision_layer if {
	authz.decision == {
		"decision": "deny",
		"policy_name": "malformed_input_deny",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": "0.70", "threshold": 0.651},
	}
}

test_malformed_score_boolean_denies_at_decision_layer if {
	authz.decision == {
		"decision": "deny",
		"policy_name": "malformed_input_deny",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": true, "threshold": 0.651},
	}
}

test_malformed_score_object_denies_at_decision_layer if {
	authz.decision == {
		"decision": "deny",
		"policy_name": "malformed_input_deny",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": {"value": 0.70}, "threshold": 0.651},
	}
}

test_malformed_threshold_string_denies_at_decision_layer if {
	authz.decision == {
		"decision": "deny",
		"policy_name": "malformed_input_deny",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.70, "threshold": "0.651"},
	}
}

test_malformed_threshold_boolean_denies_at_decision_layer if {
	authz.decision == {
		"decision": "deny",
		"policy_name": "malformed_input_deny",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.70, "threshold": false},
	}
}

test_malformed_threshold_object_denies_at_decision_layer if {
	authz.decision == {
		"decision": "deny",
		"policy_name": "malformed_input_deny",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.70, "threshold": {"value": 0.651}},
	}
}

# Exclusivity regression: risk_allow (R3) and mfa_verified_allow (R4) share
# `rbac.allow` and differ only on `risk_decision`/`mfa_verified`. R4's guard is
# `risk_decision == "step_up"`, not just `mfa_verified` -- if that guard were ever
# dropped or weakened, this input (low risk score, but mfa.verified: true anyway,
# e.g. a stale/leftover step-up from an earlier request) would satisfy BOTH R3 and
# R4 simultaneously, which OPA resolves as an eval_conflict_error at runtime
# (crashing the /v1/data/authz/decision call, not a silent wrong answer -- but
# still a production incident). This pins the single valid outcome down.
# Session-hijack signal (adaptive_access.high_distinct_ips) at the full
# decision layer -- proves it overrides a comfortably-low score end to end,
# not just in isolation inside adaptive_access_test.rego.
test_high_distinct_ips_forces_step_up_even_with_low_score if {
	authz.decision == {
		"decision": "step_up",
		"policy_name": "step_up_required",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"feature_vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0],
		"mfa": {"verified": false},
	}
}

test_mfa_verified_does_not_conflict_with_risk_allow_when_score_below_threshold if {
	authz.decision == {
		"decision": "allow",
		"policy_name": "risk_allow",
	} with input as {
		"identity": {"subject": "u1", "role": "reader"},
		"resource": {"http_method": "GET", "route": "/documents/{document_id}", "action": "read"},
		"risk_ctx": {"score": 0.61, "threshold": 0.651},
		"mfa": {"verified": true},
	}
}

# Sensitive-action gate (adaptive_access.sensitive_action) at the full decision
# layer -- proves it overrides a comfortably-low score end to end, not just in
# isolation inside adaptive_access_test.rego, mirroring how high_distinct_ips
# is proven at both layers above. admin role used throughout: RBAC already
# restricts delete/users-write to admin, so this is the realistic scenario --
# an already-admin session, password-only, at low measured risk.

test_sensitive_action_forces_step_up_even_with_low_score_end_to_end if {
	authz.decision == {
		"decision": "step_up",
		"policy_name": "step_up_required",
	} with input as {
		"identity": {"subject": "u1", "role": "admin"},
		"resource": {"http_method": "DELETE", "route": "/documents/{document_id}", "action": "delete"},
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"mfa": {"verified": false},
	}
}

test_sensitive_action_allowed_after_mfa_verified_end_to_end if {
	authz.decision == {
		"decision": "allow",
		"policy_name": "mfa_verified_allow",
	} with input as {
		"identity": {"subject": "u1", "role": "admin"},
		"resource": {"http_method": "DELETE", "route": "/documents/{document_id}", "action": "delete"},
		"risk_ctx": {"score": 0.10, "threshold": 0.98},
		"mfa": {"verified": true},
	}
}

# Bootstrap mode: no model trained yet, risk_ctx.score is explicitly null --
# before this change, bootstrap allowed literally everything with zero
# step-up. This proves the gap is closed from day one of a fresh deployment,
# not just once a model is active.
test_sensitive_action_step_up_during_bootstrap_end_to_end if {
	authz.decision == {
		"decision": "step_up",
		"policy_name": "step_up_required",
	} with input as {
		"identity": {"subject": "u1", "role": "admin"},
		"resource": {"http_method": "DELETE", "route": "/documents/{document_id}", "action": "delete"},
		"risk_ctx": {"score": null},
		"mfa": {"verified": false},
	}
}
