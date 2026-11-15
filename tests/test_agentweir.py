#!/usr/bin/env python3
"""End-to-end tests for agentweir. Needs only Python 3 (standard library).
Usage: python3 tests/test_agentweir.py ./agentweir-asan
Starts local target servers, runs the proxy against them, and checks behaviour,
the audit-log chain (re-verified independently with hashlib), and tampering."""
import hashlib, json, os, signal, socket, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./agentweir")
TMP = tempfile.mkdtemp(prefix="aw-test-")
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("PASS", name)
    else:
        failed += 1
        print("FAIL", name, detail)


# ---- local targets -------------------------------------------------------
seen_hosts = []


class H(BaseHTTPRequestHandler):
    def _ok(self):
        seen_hosts.append(self.headers.get("Host"))
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_DELETE = _ok

    def log_message(self, *a):
        pass


httpd = HTTPServer(("127.0.0.1", 0), H)
HTTP_PORT = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()

echo = socket.socket()
echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
echo.bind(("127.0.0.1", 0))
echo.listen(16)
ECHO_PORT = echo.getsockname()[1]


def echo_loop():
    while True:
        try:
            c, _ = echo.accept()
        except OSError:
            return
        def run(c=c):
            try:
                while True:
                    d = c.recv(4096)
                    if not d:
                        break
                    c.sendall(d)
            finally:
                c.close()
        threading.Thread(target=run, daemon=True).start()


threading.Thread(target=echo_loop, daemon=True).start()


# ---- helpers -------------------------------------------------------------
def write_policy(name, text):
    p = os.path.join(TMP, name)
    open(p, "w").write(text)
    return p


def start_proxy(policy, log):
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    p = subprocess.Popen([BIN, "proxy", "--policy", policy, "--log", log, "--listen", "127.0.0.1:0"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    line = p.stdout.readline().strip()
    port = int(line.rsplit(":", 1)[1])
    return p, port


def stop_proxy(p):
    p.send_signal(signal.SIGTERM)
    try:
        _, err = p.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        _, err = p.communicate()
    return err


def raw(port, data, read_all=True, timeout=10):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    out = b""
    try:
        s.sendall(data if isinstance(data, bytes) else data.encode())
        while True:
            d = s.recv(4096)
            if not d:
                break
            out += d
            if not read_all:
                break
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    s.close()
    return out.decode(errors="replace")


def status(resp):
    return resp.split(" ", 2)[1] if resp.startswith("HTTP/") else "none"


def independent_verify(path):
    prev, seq = "0" * 64, 0
    for line in open(path).read().splitlines():
        rec = json.loads(line)
        h = rec.pop("hash")
        if rec["prev"] != prev or rec["seq"] != seq + 1:
            return False
        body = json.dumps(rec, separators=(",", ":"), ensure_ascii=True)
        if hashlib.sha256(body.encode()).hexdigest() != h:
            return False
        prev, seq = h, rec["seq"]
    return True


def run(*args):
    return subprocess.run([BIN, *args], capture_output=True, text=True,
                          env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0"))


# ---- tests ---------------------------------------------------------------
POL = write_policy("enforce.conf", f"""
mode = enforce
allow = 127.0.0.1
allow = localhost
allow_private = 127.0.0.1
allow_ports = {ECHO_PORT}
allow_ports = {HTTP_PORT}
deny_method = DELETE
""")
LOG = os.path.join(TMP, "audit.jsonl")
proxy, pport = start_proxy(POL, LOG)

r = raw(pport, f"CONNECT 127.0.0.1:{ECHO_PORT} HTTP/1.1\r\nHost: x\r\n\r\n", read_all=False)
check("CONNECT to allowlisted host succeeds", status(r) == "200", r)
s = socket.create_connection(("127.0.0.1", pport), timeout=10)
s.sendall(f"CONNECT 127.0.0.1:{ECHO_PORT} HTTP/1.1\r\n\r\n".encode())
s.recv(1024)
s.sendall(b"hello-tunnel")
check("tunnel carries data both ways", s.recv(1024) == b"hello-tunnel")
s.close()

t0 = time.time()
r = raw(pport, "CONNECT blocked.example:443 HTTP/1.1\r\n\r\n")
check("CONNECT to unlisted host is blocked (403)", status(r) == "403", r)
check("blocked host is refused before any DNS lookup (fast)", time.time() - t0 < 3)
check("trailing-dot host cannot bypass (blocked.example.)", status(raw(pport, "CONNECT blocked.example.:443 HTTP/1.1\r\n\r\n")) == "403")
check("uppercase host cannot bypass", status(raw(pport, "CONNECT BLOCKED.EXAMPLE:443 HTTP/1.1\r\n\r\n")) == "403")
check("disallowed port is blocked", status(raw(pport, "CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")) == "403")
r = raw(pport, f"CONNECT localhost:{ECHO_PORT} HTTP/1.1\r\n\r\n")
check("allowlisted name that resolves to a private IP is blocked", status(r) == "403" and "private" in r, r)

r = raw(pport, f"GET http://127.0.0.1:{HTTP_PORT}/x HTTP/1.1\r\nHost: evil.com\r\nProxy-Connection: keep-alive\r\n\r\n")
check("plain HTTP GET is forwarded", status(r) == "200" and r.endswith("hello"), r)
check("Host header is rewritten to the vetted host (no host mismatch)", seen_hosts and seen_hosts[-1] == f"127.0.0.1:{HTTP_PORT}", str(seen_hosts))
r = raw(pport, f"DELETE http://127.0.0.1:{HTTP_PORT}/x HTTP/1.1\r\n\r\n")
check("denied HTTP method (DELETE) is blocked", status(r) == "403", r)
check("unlisted host over plain HTTP is blocked", status(raw(pport, "GET http://blocked.example/ HTTP/1.1\r\n\r\n")) == "403")
check("https:// absolute URL without CONNECT is rejected", status(raw(pport, "GET https://127.0.0.1/ HTTP/1.1\r\n\r\n")) == "400")
check("garbage request gets 400", status(raw(pport, "GARBAGE\r\n\r\n")) == "400")
check("user-info in URL is rejected", status(raw(pport, "GET http://a@127.0.0.1/ HTTP/1.1\r\n\r\n")) == "400")
check("IPv6 literal rejected, not crashed", status(raw(pport, "CONNECT [::1]:443 HTTP/1.1\r\n\r\n")) == "400")
check("oversized headers rejected (431 or connection reset, never forwarded)", status(raw(pport, "GET http://127.0.0.1/ HTTP/1.1\r\nX: " + "a" * 20000)) in ("431", "none"))
check("header line folding rejected", status(raw(pport, "GET http://127.0.0.1/ HTTP/1.1\r\nX: a\r\n b\r\n\r\n")) == "400")
check("unknown method rejected", status(raw(pport, "TRACE http://127.0.0.1/ HTTP/1.1\r\n\r\n")) == "405")
r = raw(pport, 'CONNECT evil"quote\\.example:443 HTTP/1.1\r\n\r\n')
check("hostile characters get 400 and cannot break the log", status(r) == "400")

err = stop_proxy(proxy)
check("no memory errors or undefined behaviour reported (sanitizers)", "AddressSanitizer" not in err and "runtime error" not in err, err[-500:])
v = run("verify", LOG)
check("audit log chain verifies", v.returncode == 0, v.stdout)
check("independent hashlib re-verification agrees", independent_verify(LOG))
lines = open(LOG).read().splitlines()
check("audit log recorded decisions", any('"decision":"deny"' in l for l in lines) and any('"decision":"allow"' in l for l in lines))
check("close records carry byte counts", any('"event":"close"' in l and '"up":12' in l for l in lines))

# tampering
orig = open(LOG).read()
i = next(k for k, l in enumerate(lines) if '"decision":"deny"' in l)
tam = lines[:]
tam[i] = tam[i].replace('"decision":"deny"', '"decision":"allow"')
open(LOG, "w").write("\n".join(tam) + "\n")
check("tampered record is detected", run("verify", LOG).returncode == 1)
del_ = lines[:i] + lines[i + 1:]
open(LOG, "w").write("\n".join(del_) + "\n")
check("deleted record is detected", run("verify", LOG).returncode == 1)
swap = lines[:]
swap[1], swap[2] = swap[2], swap[1]
open(LOG, "w").write("\n".join(swap) + "\n")
check("reordered records are detected", run("verify", LOG).returncode == 1)
open(LOG, "w").write(orig)

# restart continues the chain; refuses a tampered log
proxy2, p2 = start_proxy(POL, LOG)
raw(p2, "CONNECT blocked.example:443 HTTP/1.1\r\n\r\n")
stop_proxy(proxy2)
check("restart continues the same verified chain", run("verify", LOG).returncode == 0 and len(open(LOG).read().splitlines()) == len(lines) + 1)
open(LOG, "w").write("\n".join(tam) + "\n")
res = run("proxy", "--policy", POL, "--log", LOG, "--listen", "127.0.0.1:0")
check("refuses to start on a tampered log", res.returncode == 2 and "failed verification" in res.stderr, res.stderr)

check("version command works", "agentweir 0." in run("version").stdout)

# policy checks (no network needed)
PW = write_policy("wild.conf", "allow = *.good.test\nallow = exact.test\nallow_ports = 443\n")
cases = [("a.good.test:443", True), ("good.test:443", False), ("evilgood.test:443", False),
         ("a.b.good.test:443", True), ("exact.test:443", True), ("x.exact.test:443", False),
         ("A.GOOD.TEST.:443", True), ("a.good.test:80", False)]
for hp, want in cases:
    c = run("check", "--policy", PW, hp)
    check(f"policy check {hp} -> {'ALLOW' if want else 'DENY'}", (c.returncode == 0) == want, c.stdout)
for bad_pol in ["allow = *.*.x\n", "alow = x.test\n", "mode = sorta\n", "allow_ports = 99999\n", "allow\n"]:
    c = run("check", "--policy", write_policy("bad.conf", bad_pol), "x.test:443")
    check("bad policy fails closed: " + bad_pol.strip(), c.returncode == 2, c.stderr)

# monitor mode: logs would-deny but lets traffic through
MPOL = write_policy("monitor.conf", f"mode = monitor\nallow = nothing.test\nallow_ports = {ECHO_PORT}\n")
MLOG = os.path.join(TMP, "monitor.jsonl")
pm, mp = start_proxy(MPOL, MLOG)
r = raw(mp, f"CONNECT 127.0.0.1:{ECHO_PORT} HTTP/1.1\r\n\r\n", read_all=False)
stop_proxy(pm)
check("monitor mode lets traffic through", status(r) == "200", r)
check("monitor mode logs what it would have denied", "monitor_would_deny" in open(MLOG).read())
check("close record keeps the real decision (not a misleading 'allow')", '"event":"close","decision":"monitor_would_deny"' in open(MLOG).read())
rp = run("report", MLOG)
check("report lists host:port with counts", f"127.0.0.1:{ECHO_PORT}" in rp.stdout and "WOULD-BLOCK" in rp.stdout, rp.stdout)
sg = run("suggest", MLOG)
check("suggest drafts allow lines from observed traffic", "allow = 127.0.0.1" in sg.stdout and f"allow_ports = {ECHO_PORT}" in sg.stdout and "REVIEW EVERY LINE" in sg.stdout, sg.stdout)
SPOL = write_policy("suggested.conf", sg.stdout)
ck = run("check", "--policy", SPOL, f"127.0.0.1:{ECHO_PORT}")
check("suggested policy loads and allows what was observed", ck.returncode == 0, ck.stdout + ck.stderr)
ck = run("check", "--policy", SPOL, "evil.example:443")
check("suggested policy still denies everything else", ck.returncode == 1)
check("report refuses an unverified log", run("report", LOG).returncode == 1)

# run mode
RLOG = os.path.join(TMP, "run.jsonl")
RPOL = write_policy("run.conf", f"allow = 127.0.0.1\nallow_private = 127.0.0.1\nallow_ports = {HTTP_PORT}\n")
res = run("run", "--policy", RPOL, "--log", RLOG, "--", "sh", "-c", "exit 7")
check("run mode returns the command's exit code", res.returncode == 7, str(res.returncode))
res = run("run", "--policy", RPOL, "--log", RLOG, "--", "sh", "-c", "echo $HTTP_PROXY")
check("run mode sets proxy variables for the command", "http://127.0.0.1:" in res.stdout, res.stdout)
code = ("import urllib.request,sys\n"
        f"print(urllib.request.urlopen('http://127.0.0.1:{HTTP_PORT}/ok').status)\n"
        "try:\n urllib.request.urlopen('http://blocked.example/')\nexcept Exception as e:\n print('blocked', getattr(e,'code',e))\n")
res = run("run", "--policy", RPOL, "--log", RLOG, "--", "python3", "-c", code)
check("a real client works through the proxy and the block is enforced",
      "200" in res.stdout and "blocked 403" in res.stdout, res.stdout + res.stderr)
check("blocked connection prints a visible notice to the user", "BLOCKED blocked.example:80" in res.stderr, res.stderr)
check("run-mode log verifies", run("verify", RLOG).returncode == 0)
check("run mode reports a missing command", run("run", "--policy", RPOL, "--log", RLOG, "--", "no-such-cmd-xyz").returncode == 127)
check("no sanitizer reports in run mode", "AddressSanitizer" not in res.stderr and "runtime error" not in res.stderr)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
