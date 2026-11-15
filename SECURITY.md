# Security

agentwall is an early prototype and has not had an independent security review. Do not rely on it to protect anything valuable yet.

## Reporting a vulnerability
Please report security issues privately, not in a public issue: use the repository's **Security** tab, then **Report a vulnerability** (GitHub private vulnerability reporting). Include what you ran, what you expected, and what happened. Reports will be acknowledged as quickly as possible, and reporters will be credited if they wish.

## Known limits
See "What it does NOT do" in the README. In particular, the environment-variable mode is not a sandbox; the Docker Compose example in `examples/` is the stronger pattern.
