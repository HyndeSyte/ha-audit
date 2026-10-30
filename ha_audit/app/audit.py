#!/usr/bin/env python3
"""HA Audit: daily read-only drift check of Home Assistant's /config.

What it checks (GO-11 v4 item 1, next-four design B2, red team NF-11/12/24,
NF3-03):
  1. git HEAD equals the accepted commit (option "pin"), or HEAD's parent is
     the pin and HEAD changes only the accept file (the accept commit).
  2. No tracked file differs from HEAD, and no untracked or ignored file sits
     in the security paths (packages/system, packages/claude_patches) apart
     from the patch harness's own manifests and report.
  3. No *.bak* file anywhere in /config (except .storage, .git and HA's
     runtime folders).
  4. The patch harness's last_report.json is not git_dirty and has no
     commit_error.
  5. Exactly one shell_command declaration in the merged configuration
     (configuration.yaml plus every include), and it is the pinned one.
  6. The App's own options and version: any change since the last run must
     match packages/audit/accept.json, otherwise the audit fails and stays
     failed until it does.

It never writes to /config, never calls Home Assistant or Supervisor, and
uses no model. Output: one log line per run, and, once ping_url is set, a
POST to healthchecks (success or /fail) whose body carries the facts every
attended session compares with the pin recorded in SYSTEM_STATE.

Guarantee: drift detection, not tamper resistance (an actor who can change
both the App options and the committed accept file goes green; the attended
comparison of ping bodies with SYSTEM_STATE is the second observer).
"""

import fnmatch
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta

import yaml

CONFIG = os.environ.get("AUDIT_CONFIG") or (
    "/homeassistant" if os.path.isdir("/homeassistant") else "/config")
OPTIONS = os.environ.get("AUDIT_OPTIONS", "/data/options.json")
STATE = os.environ.get("AUDIT_STATE", "/data/state.json")
VERSION = os.environ.get("AUDIT_VERSION", "0.0.0")

ACCEPT_FILE = "packages/audit/accept.json"
SECURITY_PATHS = ("packages/system/", "packages/claude_patches/")
# Files the patch harness itself writes in its own folder; never a finding.
HARNESS_OWN = ("packages/claude_patches/manifest.json",
               "packages/claude_patches/manifest.op.*.json",
               "packages/claude_patches/manifest.applied.*.json",
               "packages/claude_patches/last_report.json",
               "packages/claude_patches/.harness.lock",
               "packages/claude_patches/__pycache__/*")
BAK_SKIP_DIRS = {".storage", ".git", "deps", "tts", "backups", ".cloud",
                 "custom_components", "node_modules", "__pycache__"}
SHELL_FILE = "packages/system/zz_claude_patch_harness.yaml"
SHELL_NAME = "claude_apply_patch"
SHELL_CMD = "python3 /config/packages/claude_patches/harness.py"
PING_LIMIT = 9000


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(rel):
    try:
        with open(os.path.join(CONFIG, rel), "rb") as fh:
            return sha256_bytes(fh.read())
    except OSError:
        return None


def git(*args):
    env = dict(os.environ, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.directory",
               GIT_CONFIG_VALUE_0=CONFIG, GIT_OPTIONAL_LOCKS="0")
    p = subprocess.run(["git", "--no-optional-locks", "-c", "core.quotepath=off"] + list(args),
                       cwd=CONFIG, capture_output=True, text=True, timeout=120, env=env)
    if p.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(args), (p.stderr or p.stdout).strip()[:300]))
    return p.stdout


def options_sha(opts):
    return sha256_bytes(json.dumps(opts, sort_keys=True, separators=(",", ":")).encode())


# ── YAML: HA tags become inert markers or followed includes ──────────────────
class Marker(str):
    pass


def make_loader(path_of_file, loaded):
    class L(yaml.SafeLoader):
        pass

    base = os.path.dirname(path_of_file)

    def inert(loader, node):
        return Marker("<%s>" % node.tag)

    def inc(loader, node):
        return load_file(os.path.join(base, loader.construct_scalar(node)), loaded)

    def inc_dir(kind):
        def f(loader, node):
            d = os.path.join(base, loader.construct_scalar(node))
            files = []
            for root, dirs, names in os.walk(d):
                dirs[:] = sorted(x for x in dirs if not x.startswith("."))
                files += [os.path.join(root, n) for n in sorted(names)
                          if n.endswith((".yaml", ".yml")) and not n.startswith(".")]
            if kind == "merge_named":
                out = {}
                for fp in files:
                    v = load_file(fp, loaded)
                    if isinstance(v, dict):
                        out.update(v)
                return out
            if kind == "named":
                return {os.path.splitext(os.path.basename(fp))[0]: load_file(fp, loaded)
                        for fp in files}
            if kind == "merge_list":
                out = []
                for fp in files:
                    v = load_file(fp, loaded)
                    if isinstance(v, list):
                        out += v
                return out
            return [load_file(fp, loaded) for fp in files]
        return f

    for tag in ("!secret", "!env_var", "!input"):
        L.add_constructor(tag, inert)
    L.add_constructor("!include", inc)
    L.add_constructor("!include_dir_merge_named", inc_dir("merge_named"))
    L.add_constructor("!include_dir_named", inc_dir("named"))
    L.add_constructor("!include_dir_merge_list", inc_dir("merge_list"))
    L.add_constructor("!include_dir_list", inc_dir("list"))
    L.add_multi_constructor("!", lambda loader, suffix, node: Marker("<!%s>" % suffix))
    return L


def load_file(fp, loaded):
    real = os.path.realpath(fp)
    if real in loaded["stack"]:
        raise RuntimeError("include loop at %s" % os.path.relpath(fp, CONFIG))
    loaded["stack"].append(real)
    try:
        with open(fp, "rb") as fh:
            data = yaml.load(fh.read().decode("utf-8"), Loader=make_loader(fp, loaded))
    finally:
        loaded["stack"].pop()
    rel = os.path.relpath(fp, CONFIG)
    loaded["files"][rel] = data
    return data


def shell_command_declarations():
    """Every shell_command entry, with the file whose top level declares it."""
    loaded = {"stack": [], "files": {}}
    load_file(os.path.join(CONFIG, "configuration.yaml"), loaded)
    found = []
    for rel, data in sorted(loaded["files"].items()):
        if isinstance(data, dict) and "shell_command" in data:
            sc = data["shell_command"]
            if isinstance(sc, dict):
                for name, cmd in sc.items():
                    found.append({"file": rel, "name": str(name), "command": str(cmd)})
            else:
                found.append({"file": rel, "name": "?", "command": str(sc)})
    return found


# ── checks ───────────────────────────────────────────────────────────────────
def check_head(pin):
    head = git("rev-parse", "HEAD").strip()
    if not pin:
        return head, False, "no pin set"
    full_pin = git("rev-parse", pin + "^{commit}").strip() if pin else ""
    if head == full_pin:
        return head, True, "HEAD is the pin"
    parent = git("rev-parse", "HEAD^").strip()
    changed = [x for x in git("diff", "--name-only", full_pin, head).splitlines() if x]
    if parent == full_pin and changed == [ACCEPT_FILE]:
        return head, True, "HEAD is the accept commit on the pin"
    return head, False, "HEAD %s is not the pin %s (changed: %s)" % (
        head[:10], full_pin[:10], ", ".join(changed[:8]) or "-")


def own_file(rel):
    return any(fnmatch.fnmatch(rel, p) for p in HARNESS_OWN)


def check_tree():
    lines = git("status", "--porcelain", "--untracked-files=all", "--ignored").splitlines()
    problems = []
    for line in lines:
        code, rel = line[:2], line[3:]
        if code not in ("??", "!!"):
            problems.append("changed: %s" % rel)
        elif rel.startswith(SECURITY_PATHS) and not own_file(rel):
            problems.append("%s in security path: %s" % (
                "untracked" if code == "??" else "ignored", rel))
    return problems


def check_bak():
    hits = []
    for root, dirs, names in os.walk(CONFIG):
        dirs[:] = [d for d in dirs if d not in BAK_SKIP_DIRS]
        for n in names:
            if fnmatch.fnmatch(n, "*.bak*"):
                hits.append(os.path.relpath(os.path.join(root, n), CONFIG))
    return hits


def check_last_report():
    try:
        with open(os.path.join(CONFIG, "packages/claude_patches/last_report.json"), "rb") as fh:
            rep = json.loads(fh.read().decode("utf-8"))
    except FileNotFoundError:
        return None
    if rep.get("step") == "git_dirty" or "commit_error" in rep:
        return "last_report: %s %s" % (rep.get("step"), rep.get("commit_error") or rep.get("detail"))
    return None


def check_shell(decls):
    want = [{"file": SHELL_FILE, "name": SHELL_NAME, "command": SHELL_CMD}]
    if decls == want:
        return None
    return "shell_command declarations: %s" % json.dumps(decls)[:600]


def check_options(opts, head):
    """Options/version changes must match the committed accept file."""
    cur = {"options_sha": options_sha(opts), "version": VERSION}
    try:
        with open(STATE, "rb") as fh:
            last = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError):
        last = {}
    accepted = None
    try:
        with open(os.path.join(CONFIG, ACCEPT_FILE), "rb") as fh:
            accepted = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError):
        pass
    matches = (isinstance(accepted, dict) and accepted.get("options_sha") == cur["options_sha"]
               and accepted.get("version") == cur["version"] and accepted.get("pin") == opts.get("pin"))
    changed = last.get("seen") is not None and last.get("seen") != cur
    pending = last.get("unaccepted", False) or changed
    if pending and not matches:
        result = "options or App version changed without a matching accept file"
        new_state = {"seen": cur, "unaccepted": True}
    else:
        result = None
        new_state = {"seen": cur, "unaccepted": False}
    note = "accepted change" if changed and matches else None
    return result, new_state, note, cur


def run_once(opts):
    started = datetime.now().astimezone()
    facts = {"time": started.isoformat(timespec="seconds"), "app_version": VERSION,
             "pin": opts.get("pin", ""), "options_sha": options_sha(opts)}
    failures, notes = [], []
    try:
        head, ok, why = check_head(opts.get("pin", ""))
        facts["head"] = head
        if not ok:
            failures.append(why)
        else:
            notes.append(why)
        failures += check_tree()
        bak = check_bak()
        if bak:
            failures.append("bak files: %s" % ", ".join(bak[:10]))
        lr = check_last_report()
        if lr:
            failures.append(lr)
        decls = shell_command_declarations()
        facts["shell_command"] = decls
        sc = check_shell(decls)
        if sc:
            failures.append(sc)
        facts["harness_py_sha256"] = sha256_file("packages/claude_patches/harness.py")
        facts["system_sha256"] = {f: sha256_file("packages/system/" + f)
                                  for f in sorted(os.listdir(os.path.join(CONFIG, "packages/system")))
                                  if f.endswith(".yaml")}
        res, new_state, note, cur = check_options(opts, head)
        if res:
            failures.append(res)
        if note:
            notes.append(note)
        try:
            with open(STATE + ".tmp", "w") as fh:
                json.dump(new_state, fh)
            os.replace(STATE + ".tmp", STATE)
        except OSError as exc:
            failures.append("state not saved: %s" % exc)
    except Exception as exc:  # any exception is a failure, never green
        failures.append("audit error: %s: %s" % (type(exc).__name__, str(exc)[:300]))
    facts["ok"] = not failures
    facts["failures"] = failures
    facts["notes"] = notes
    return facts


def report(facts, ping_url):
    line = "AUDIT %s ok=%s head=%s pin=%s failures=%d" % (
        facts["time"][:10], "yes" if facts["ok"] else "no", (facts.get("head") or "-")[:10],
        (facts.get("pin") or "-")[:10], len(facts["failures"]))
    print(line, flush=True)
    for f in facts["failures"]:
        print("  FAIL " + f, flush=True)
    for n in facts["notes"]:
        print("  note " + n, flush=True)
    print("  facts " + json.dumps(facts, sort_keys=True)[:4000], flush=True)
    if not ping_url:
        return
    body = json.dumps(facts, sort_keys=True).encode()[:PING_LIMIT]
    url = ping_url if facts["ok"] else ping_url.rstrip("/") + "/fail"
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                r.read(64)
            return
        except Exception as exc:
            print("  ping attempt %d failed: %s" % (attempt + 1, type(exc).__name__), flush=True)
            time.sleep(10 * (attempt + 1))


def load_options():
    with open(OPTIONS, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def seconds_until(run_at):
    h, m = (int(x) for x in run_at.split(":"))
    now = datetime.now().astimezone()
    nxt = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    return (nxt - now).total_seconds()


def main(argv):
    opts = load_options()
    report(run_once(opts), opts.get("ping_url", ""))
    if "--loop" not in argv:
        return 0
    while True:
        time.sleep(seconds_until(opts.get("run_at", "06:15")))
        opts = load_options()
        report(run_once(opts), opts.get("ping_url", ""))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
