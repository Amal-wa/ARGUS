package authz

import data.authz.adaptive_access
import data.authz.mfa
import data.authz.rbac

default decision := {
	"decision": "deny",
	"policy_name": "malformed_input_deny",
}

decision := {
	"decision": "deny",
	"policy_name": "rbac_deny",
} if {
	not rbac.allow
}

# Phase 2 of the graduated enumeration response: a risk-originated deny,
# distinct from rbac_deny above (different policy_name, same "deny" value --
# Rego only conflicts on DIFFERENT values for the same complete rule, so two
# deny-producing bodies coexist fine). Mutually exclusive with rbac_deny by
# construction: this branch requires rbac.allow, rbac_deny requires
# not rbac.allow -- the two can never both match the same input.
#
# Deliberately fires even though rbac.allow is true: the whole point is that
# a mechanical, high-volume enumeration burst gets refused even for an action
# RBAC would otherwise permit -- a validated design decision, not a gap in
# rbac.rego. And deliberately has NO mfa.mfa_verified branch anywhere below
# that could rescue it (contrast with risk_decision=="step_up", which DOES
# have an mfa_verified_allow branch) -- this deny is terminal regardless of
# MFA state, by design: at this volume/pace, a prior MFA verification says
# nothing about whether this specific burst is the legitimate MFA-holder.
decision := {
	"decision": "deny",
	"policy_name": "risk_enumeration_deny",
} if {
	rbac.allow
	adaptive_access.risk_decision == "deny"
}

decision := {
	"decision": "allow",
	"policy_name": "bootstrap_allow",
} if {
	rbac.allow
	adaptive_access.risk_decision == "allow"
	adaptive_access.bootstrap_mode
}

decision := {
	"decision": "allow",
	"policy_name": "risk_allow",
} if {
	rbac.allow
	adaptive_access.risk_decision == "allow"
	not adaptive_access.bootstrap_mode
}

decision := {
	"decision": "allow",
	"policy_name": "mfa_verified_allow",
} if {
	rbac.allow
	adaptive_access.risk_decision == "step_up"
	mfa.mfa_verified
}

decision := {
	"decision": "step_up",
	"policy_name": "step_up_required",
} if {
	rbac.allow
	adaptive_access.risk_decision == "step_up"
	not mfa.mfa_verified
}
