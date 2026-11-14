# agentwall (working name)

> **Status: early prototype (v0.2). Not security-reviewed. Do not rely on it to protect anything valuable yet.** Bug reports and honest feedback are very welcome: open an issue.

Records which servers a program connects to, helps you turn that record into an allowlist, and blocks everything else. Built for AI agents and coding assistants; works with any program that respects proxy settings.

## Install (build from source)

There are no prebuilt binaries: you compile it from the source in this repo. Building downloads nothing. It needs a C++17 compiler and `make`.

**Linux** (Debian/Ubuntu shown; use your own package manager otherwise)
```
sudo apt install g++ make curl
```

**macOS**
```
xcode-select --install
```
This installs the compiler, `make` and `curl`. (macOS support is expected to work but has not been tested yet. If the build fails, please open an issue with the error.)

**Windows**
agentwall uses Unix networking and does not build natively on Windows. Use WSL2 (Windows 10/11): open PowerShell as administrator, run `wsl --install`, restart, open the Ubuntu app, then follow the Linux steps above inside it. (Not tested on WSL yet; please report problems.)

**Then, on all three:**
```
git clone https://github.com/YOURUSERNAME/agentwall
cd agentwall
make
./agentwall selftest        # should print 4 PASS lines
```

## Try it

### 1. See a connection get blocked
The example policy allows only a few package hosts, so a request to `example.com` is blocked:
```
./agentwall run --policy policy.example.conf --log demo.jsonl -- curl -sS http://example.com
```
You should see `agentwall: BLOCKED example.com:80 - host not in allowlist`, and curl will print the same refusal.

### 2. Watch what a program touches, then draft a policy
Monitor mode logs everything and blocks nothing:
```
sed 's/^mode = .*/mode = monitor/' policy.example.conf > monitor.conf
./agentwall run --policy monitor.conf --log watch.jsonl -- sh -c "curl -s -o /dev/null https://pypi.org; curl -s -o /dev/null https://example.com"
./agentwall report watch.jsonl                    # table of hosts it contacted
./agentwall suggest watch.jsonl > mypolicy.conf   # draft allowlist; REVIEW every line
./agentwall verify watch.jsonl                    # confirm the log was not edited
```
`report` shows `pypi.org:443` as allowed and `example.com:443` as would-block, because only pypi.org is in the example policy. Use your own agent or script in place of the `sh -c ...` part: everything after `--` is the command to run. When the draft policy looks right, run it in enforce mode with `--policy mypolicy.conf`.

## Commands

| Command | What it does |
|---|---|
| `run --policy FILE [--log FILE] -- CMD...` | Runs CMD with its web traffic going through agentwall |
| `report LOGFILE` | Hosts contacted: allowed, blocked, would-block |
| `suggest LOGFILE` | Drafts a policy from what was observed |
| `check --policy FILE HOST:PORT` | Explains whether a destination would be allowed (no network used) |
| `verify LOGFILE` | Checks the hash chain; detects edited, deleted or reordered records |
| `proxy --policy FILE` | Runs just the proxy, so you can point tools at it yourself |

Policy files are a few `key = value` lines (see `policy.example.conf`). Everything not listed is denied. Blocked connections print a visible `agentwall: BLOCKED host:port - reason` line, because many tools only show a confusing error.

## What it does
- Default-deny allowlist by hostname (exact or `*.suffix`) and port.
- Blocks hosts that resolve to private or internal addresses (for example cloud metadata at 169.254.169.254) unless explicitly allowed. It connects only to the addresses it vetted, so DNS tricks cannot swap the target.
- Rewrites the Host header so a client cannot name one host in the URL and another in the header.
- Optional per-verb blocking for plain HTTP.
- Hash-chained JSONL audit log. Each connection writes two records (open and close); `report` counts only the open ones.
- Makes no network connections of its own and sends no telemetry. It writes only the log file you name.

## What it does NOT do (read this)
- **It is not a sandbox.** It works by setting proxy environment variables. A program that ignores them, or uses raw sockets, bypasses it. Some tools (for example Node's built-in fetch) ignore proxy variables by default. A kernel-enforced mode is the next milestone.
- HTTPS content is not inspected: it sees the host and port, not URLs, verbs or bodies.
- IPv6 literals, user-info URLs and non-HTTP protocols are rejected, not supported.
- The audit log detects edits in the middle of the file, but someone with full write access can rebuild the whole chain or cut off the end. Ship logs off the machine for stronger guarantees.
- Not reviewed by an independent security expert.

## Tested so far
58 end-to-end tests (blocking, bypass attempts, malformed input, tampering, restart, monitor mode, run mode) under AddressSanitizer and UBSan, plus a 300-connection stress test under AddressSanitizer and ThreadSanitizer, on Linux x86_64. Run them yourself on Linux with `make test` (needs `python3`). macOS and Windows (WSL) have not been tested.

## Also included
`tools/agent_scan.py` is a read-only scanner that flags risky settings in AI agent and MCP config files (hardcoded secrets, whole-disk access, unpinned packages). It is a single standard-library Python file: `python3 tools/agent_scan.py`.

## License
MIT. See `LICENSE`.
