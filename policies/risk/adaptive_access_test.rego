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
