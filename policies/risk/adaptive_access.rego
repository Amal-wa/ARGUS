package authz.adaptive_access

# Bootstrap: no ML model trained yet, Gateway sends risk_ctx.score = null explicitly.
# Only this exact documented shape counts as bootstrap — a missing risk_ctx entirely
# is a contract violation and must NOT be treated as bootstrap (see note below).
bootstrap_mode if {
    input.risk_ctx.score == null
}

risk_decision := "allow" if {
    bootstrap_mode
}

risk_decision := "allow" if {
    not bootstrap_mode
    input.risk_ctx.score < 0.8
}

risk_decision := "step_up" if {
    not bootstrap_mode
    input.risk_ctx.score >= 0.8
}