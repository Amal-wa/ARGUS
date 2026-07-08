# Policy input contract

`odd_hour` is treated as an input feature for the anomaly detection path, not as a standalone Rego business rule.

Current policy inputs keep `risk_ctx.score` as the only value injected for direct policy decisions. If a future Rego rule needs temporal context, it should be introduced intentionally as a separate contract change rather than by duplicating the same signal in both the model and the PDP.