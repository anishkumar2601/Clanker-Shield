# AI safety

AI is optional and never authoritative. If no provider is configured, a local
deterministic answer is generated from current findings. External prompts are
constructed from compact, redacted evidence; repository comments and filenames
are explicitly treated as untrusted data, not instructions.

Model responses are JSON-only, bounded, and checked before display. Referenced
finding IDs and evidence locations are restricted to known scan evidence.
Secret-shaped values fail closed if redaction does not remove them. Provider,
network, malformed-response, and timeout failures fall back to local analysis.

Do not send raw source or credentials to a provider. Review provider retention,
authentication, rate limits, and network policy before enabling it.
