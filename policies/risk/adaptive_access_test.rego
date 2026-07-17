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
