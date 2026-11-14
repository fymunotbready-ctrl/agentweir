# agentwall (working name)

> **Status: early prototype (v0.2). Not security-reviewed. Do not rely on it to protect anything valuable yet.** Feedback and bug reports are very welcome (open an issue).

Limits which internet hosts an AI agent can reach, and keeps a tamper-evident log of every connection.
Prototype of Layer 1 (enforce) and the start of Layer 3 (record) from the startup blueprint.

## Build (Linux, macOS, or Windows via WSL)
    make            # builds ./agentwall   (needs g++ and make)
    make test       # builds with sanitizers and runs all tests (needs python3)

## Use
    ./agentwall run --policy policy.example.conf -- python3 my_agent.py
    ./agentwall check --policy policy.example.conf api.github.com:443   # explain a decision, no network
    ./agentwall verify agentwall-audit.jsonl                            # prove the log was not edited
    ./agentwall report agentwall-audit.jsonl                            # table: what was contacted, allowed vs blocked
    ./agentwall suggest agentwall-audit.jsonl > mypolicy.conf           # draft an allowlist from a monitor-mode run

Typical workflow: run the agent once in `mode = monitor`, run `suggest`, REVIEW the draft line by line, then use it with `mode = enforce`.
Blocked connections print a visible `agentwall: BLOCKED host:port - reason` line, because many tools only show a confusing error.
Each connection writes two log records (open and close); `report` counts only the open records.

Start with `mode = monitor` to see what your agent touches without blocking anything.

## What it does
- Default-deny allowlist by hostname (exact or `*.suffix`) and port.
- Blocks hosts that resolve to private or internal addresses (e.g. cloud metadata 169.254.169.254) unless explicitly allowed. Connects only to the addresses it vetted, so DNS tricks cannot swap the target.
- Rewrites the Host header so a client cannot say one host in the URL and another in the header.
- Optional per-verb blocking for plain HTTP.
- Hash-chained JSONL audit log; `verify` detects edited, deleted or reordered records.

## What it does NOT do (read this)
- **It is not a sandbox.** It works by setting proxy environment variables. A program that ignores them, or uses raw sockets, bypasses it. Some tools (for example Node's built-in fetch) ignore proxy variables by default. A kernel-enforced mode is the next milestone.
- HTTPS content is not inspected: it sees the host and port, not URLs, verbs or bodies.
- IPv6 literals, user-info URLs and non-HTTP protocols are rejected, not supported.
- The audit log detects edits in the middle of the file, but someone with full write access can rebuild the whole chain or cut off the end. Ship logs off the machine for stronger guarantees.
- Not security-reviewed by an independent expert. Do not rely on it to protect anything valuable yet.

## Tested so far
58 end-to-end tests (blocking, bypass attempts, malformed input, tampering, restart, monitor mode, run mode) under AddressSanitizer and UBSan, plus a 300-connection stress test under AddressSanitizer and ThreadSanitizer. Built and run (selftest, monitor and enforce modes, pip through the proxy) on an Android phone via Termux; the full test suite ran on Linux x86_64 only.

## Quick start on Android (Termux)
    pkg install clang make python unzip git
    make CXX=clang++
    ./agentwall selftest
Build in Termux's home folder, not in the Downloads folder (Android blocks running programs from there).

## Also included
`tools/agent_scan.py` - a read-only scanner that flags risky settings in AI agent / MCP config files (hardcoded secrets, whole-disk access, unpinned packages). Run `python3 tools/agent_scan.py`.
