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

# The threshold is data-derived (the active model's p98, injected by the Gateway from
# Redis' model:active_threshold), never hardcoded here -- see CLAUDE.md. The Gateway
# always substitutes its own fallback threshold before OPA sees the input whenever a
# score is present, so `threshold == null` alongside a non-null score should never
# happen in practice. The `threshold != null` guards below are defense in depth for
# that desync: with neither rule matching, risk_decision is left undefined, which
# falls through to decision.rego's fail-closed default (deny) rather than silently
# allowing -- the Gateway-side warning log is what surfaces the underlying problem.
risk_decision := "allow" if {
    not bootstrap_mode
    input.risk_ctx.threshold != null
    input.risk_ctx.score < input.risk_ctx.threshold
}

risk_decision := "step_up" if {
    not bootstrap_mode
    input.risk_ctx.threshold != null
    input.risk_ctx.score >= input.risk_ctx.threshold
}