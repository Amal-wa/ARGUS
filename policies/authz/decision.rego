package authz.decision

import data.authz.rbac
import data.authz.adaptive_access
import data.authz.mfa

default decision := {
    "decision": "deny",
    "policy_name": "malformed_input_deny"
}

decision := {
    "decision": "deny",
    "policy_name": "rbac_deny"
} if {
    not rbac.allow
}

decision := {
    "decision": "allow",
    "policy_name": "bootstrap_allow"
} if {
    rbac.allow
    adaptive_access.risk_decision == "allow"
    adaptive_access.bootstrap_mode
}

decision := {
    "decision": "allow",
    "policy_name": "risk_allow"
} if {
    rbac.allow
    adaptive_access.risk_decision == "allow"
    not adaptive_access.bootstrap_mode
}

decision := {
    "decision": "allow",
    "policy_name": "mfa_verified_allow"
} if {
    rbac.allow
    adaptive_access.risk_decision == "step_up"
    mfa.mfa_verified
}

decision := {
    "decision": "step_up",
    "policy_name": "step_up_required"
} if {
    rbac.allow
    adaptive_access.risk_decision == "step_up"
    not mfa.mfa_verified
}