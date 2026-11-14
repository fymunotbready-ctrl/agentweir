import os, signal, socket, subprocess, sys, tempfile, threading
BIN = os.path.abspath(sys.argv[1])
tmp = tempfile.mkdtemp()
echo = socket.socket(); echo.bind(("127.0.0.1", 0)); echo.listen(512); EP = echo.getsockname()[1]
def srv():
    while True:
        try: c, _ = echo.accept()
        except OSError: return
        def r(c=c):
            try:
                while True:
                    d = c.recv(4096)
                    if not d: break
                    c.sendall(d)
            finally: c.close()
        threading.Thread(target=r, daemon=True).start()
threading.Thread(target=srv, daemon=True).start()
pol = os.path.join(tmp, "p.conf"); open(pol, "w").write(f"allow = 127.0.0.1\nallow_private = 127.0.0.1\nallow_ports = {EP}\n")
log = os.path.join(tmp, "l.jsonl")
p = subprocess.Popen([BIN, "proxy", "--policy", pol, "--log", log, "--listen", "127.0.0.1:0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                     env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0", TSAN_OPTIONS="report_signal_unsafe=0"))
port = int(p.stdout.readline().rsplit(":", 1)[1])
ok = bad = 0; lock = threading.Lock()
def worker(i):
    global ok, bad
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=20)
        deny = i % 3 == 0
        tgt = "blocked.example:443" if deny else f"127.0.0.1:{EP}"
        s.sendall(f"CONNECT {tgt} HTTP/1.1\r\n\r\n".encode())
        r = s.recv(1024).decode()
        if deny: good = " 403 " in r
        else:
            msg = f"m{i}".encode() * 50
            s.sendall(msg); got = b""
            while len(got) < len(msg): got += s.recv(4096)
            good = " 200 " in r and got == msg
        s.close()
    except Exception as e:
        good = False
    with lock:
        if good: ok += 1
        else: bad += 1
ts = [threading.Thread(target=worker, args=(i,)) for i in range(300)]
[t.start() for t in ts]; [t.join() for t in ts]
p.send_signal(signal.SIGTERM); _, err = p.communicate(timeout=20)
v = subprocess.run([BIN, "verify", log], capture_output=True, text=True).stdout.strip()
print(f"{BIN}: ok={ok} bad={bad} | {v[:60]}")
print("sanitizer reports:", "none" if ("Sanitizer" not in err and "runtime error" not in err) else err[-800:])
