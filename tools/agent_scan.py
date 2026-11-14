#!/usr/bin/env python3
"""agent_scan - read-only scanner for risky AI agent / MCP configuration.

Usage:
    python agent_scan.py                 # scan common config locations
    python agent_scan.py path/to/file    # scan a specific file or folder
    python agent_scan.py --json          # machine-readable output

It only READS files. It never changes anything and sends no data anywhere.
No findings does NOT prove a setup is safe; this checks common mistakes only.
"""
import json
import os
import re
import sys
from pathlib import Path

HOME = Path.home()
SECRET_NAME = re.compile(r"(key|token|secret|password|passwd|credential|auth)", re.I)
ENV_REF = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_.:\-]*\}?$|^\$\{.*\}$")
SECRET_FLAG = re.compile(r"^--?[\w-]*(key|token|secret|password)[\w-]*=(.+)$", re.I)
BROAD_PATHS = {"/", "~", "$HOME", "%USERPROFILE%", "C:\\", "C:/"}
RUNNERS = {"npx", "bunx", "uvx", "pipx", "pnpx"}
DANGEROUS_FLAGS = ("--dangerously", "--yolo", "--allow-all", "--no-sandbox", "--privileged")
SHELL_WORDS = re.compile(r"(shell|terminal|exec|run[-_]?command|bash)", re.I)
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def default_files():
    cwd = Path.cwd()
    appdata = os.environ.get("APPDATA")
    candidates = [
        cwd / ".mcp.json", cwd / ".cursor" / "mcp.json", cwd / ".vscode" / "mcp.json",
        HOME / ".cursor" / "mcp.json", HOME / ".claude.json",
        HOME / ".codeium" / "windsurf" / "mcp_config.json",
        HOME / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        HOME / ".config" / "Claude" / "claude_desktop_config.json",
    ]
    if appdata:
        candidates.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    return [p for p in candidates if p.is_file()]


def expand(arg):
    p = Path(arg)
    if p.is_dir():
        names = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", "mcp.json"]
        return [p / n for n in names if (p / n).is_file()]
    return [p] if p.is_file() else []


def find_servers(obj, depth=0):
    """Yield (name, config) for every MCP server entry found anywhere in the JSON."""
    if depth > 6 or not isinstance(obj, dict):
        return
    for key, val in obj.items():
        if key in ("mcpServers", "servers") and isinstance(val, dict):
            for name, cfg in val.items():
                if isinstance(cfg, dict):
                    yield name, cfg
        elif isinstance(val, dict):
            yield from find_servers(val, depth + 1)


def mask(v):
    v = str(v)
    return v[:3] + "***" if len(v) > 6 else "***"


def is_pinned(pkg):
    if pkg.endswith("@latest"):
        return False
    return bool(re.search(r"(?<!^)@[^/@]+$", pkg)) or "==" in pkg


def check(name, cfg):
    f = []
    cmd = str(cfg.get("command", ""))
    args = [str(a) for a in cfg.get("args", []) if isinstance(a, (str, int, float))]
    url = str(cfg.get("url", ""))
    base = os.path.basename(cmd).lower().replace(".cmd", "").replace(".exe", "")

    for section in ("env", "headers"):
        data = cfg.get(section, {})
        if isinstance(data, dict):
            for k, v in data.items():
                if SECRET_NAME.search(str(k)) and isinstance(v, str) and v and not ENV_REF.match(v):
                    f.append(("HIGH", "Hardcoded secret in %s: %s = %s" % (section, k, mask(v)),
                              "Move it to an environment variable or a secrets manager and rotate it, since it may already be exposed."))

    for a in args:
        m = SECRET_FLAG.match(a)
        if m and not ENV_REF.match(m.group(2)):
            f.append(("HIGH", "Secret passed as a command argument: %s=%s" % (a.split("=")[0], mask(m.group(2))),
                      "Arguments show up in process lists and logs. Use an environment variable instead."))
        if any(a.lower().startswith(d) for d in DANGEROUS_FLAGS):
            f.append(("HIGH", "Safety checks turned off: %s" % a,
                      "Remove this flag unless you are inside a throwaway sandbox."))
        if a in BROAD_PATHS or os.path.expanduser(a) == str(HOME):
            f.append(("HIGH", "Access to your whole home or root folder: %s" % a,
                      "Limit it to the one project folder this server needs."))

    if base == "sudo" or "sudo" in args:
        f.append(("HIGH", "Server runs with sudo (admin rights)", "Run it as a normal user."))
    if base == "docker" and any(re.match(r"^/:|^/\w*:/", a) for a in args):
        f.append(("HIGH", "Docker container mounts the root folder", "Mount only the folders it needs."))

    if base in RUNNERS:
        pkgs = [a for a in args if not a.startswith("-")]
        if pkgs and not is_pinned(pkgs[0]):
            f.append(("MEDIUM", "Unpinned package: %s" % pkgs[0],
                      "Every run fetches whatever version is newest, so a compromised release would run on your machine. Pin a version, like name@1.2.3."))

    if url.startswith("http://") and not re.match(r"^http://(localhost|127\.0\.0\.1|\[::1\])", url):
        f.append(("HIGH", "Unencrypted remote server: %s" % url, "Use https."))
    elif url.startswith("https://"):
        f.append(("LOW", "Remote server: %s" % url,
                  "Tool calls and the data in them leave your machine. Confirm you trust the operator."))

    if SHELL_WORDS.search(" ".join([name, cmd] + args)):
        f.append(("MEDIUM", "May be able to run commands on your machine",
                  "Check what it allows, and require approval for each command."))
    return f


def main(argv):
    as_json = "--json" in argv
    paths = [a for a in argv if not a.startswith("--")]
    files = [f for a in paths for f in expand(a)] if paths else default_files()
    if not files:
        print("No agent or MCP config files found. Pass a file or folder path: python agent_scan.py <path>")
        return 0

    results, total = [], {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for fp in files:
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            results.append({"file": str(fp), "error": str(e)})
            continue
        servers = []
        for name, cfg in find_servers(data):
            found = sorted(check(name, cfg), key=lambda x: ORDER[x[0]])
            for sev, _, _ in found:
                total[sev] += 1
            servers.append({"server": name, "findings": [
                {"severity": s, "issue": i, "fix": x} for s, i, x in found]})
        results.append({"file": str(fp), "servers": servers})

    if as_json:
        print(json.dumps({"summary": total, "results": results}, indent=2))
    else:
        for r in results:
            print("\n== %s" % r["file"])
            if "error" in r:
                print("   Could not read as JSON: %s" % r["error"])
                continue
            if not r["servers"]:
                print("   No MCP servers found in this file.")
            for s in r["servers"]:
                print("   Server: %s" % s["server"])
                if not s["findings"]:
                    print("     No issues found by these checks.")
                for x in s["findings"]:
                    print("     [%s] %s\n         Fix: %s" % (x["severity"], x["issue"], x["fix"]))
        print("\nSummary: %d high, %d medium, %d low" % (total["HIGH"], total["MEDIUM"], total["LOW"]))
        print("Note: no findings does not prove your setup is safe.")
    return 1 if total["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
