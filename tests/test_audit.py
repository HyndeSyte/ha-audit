"""Fault tests for HA Audit (GO-11 v4 item 1 faults a-e, plus NF-11/12, NF3-03)."""
import importlib
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "ha_audit", "app"))

SHELL = 'shell_command:\n  claude_apply_patch: "python3 /config/packages/claude_patches/harness.py"\n'


def sh(cwd, *a):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=cwd, check=True,
                   capture_output=True)


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    (cfg / "packages/system").mkdir(parents=True)
    (cfg / "packages/claude_patches").mkdir(parents=True)
    (cfg / "packages/audit").mkdir(parents=True)
    (cfg / "configuration.yaml").write_text(
        "homeassistant:\n  packages:\n    system: !include_dir_merge_named packages/system/\n"
        "http: !include http.yaml\nfoo: !secret bar\n")
    (cfg / "http.yaml").write_text("server_port: 8123\n")
    (cfg / "packages/system/zz_claude_patch_harness.yaml").write_text(SHELL)
    (cfg / "packages/system/helpers.yaml").write_text("input_boolean:\n  x:\n    name: x\n")
    (cfg / "packages/claude_patches/harness.py").write_text("print('h')\n")
    (cfg / ".gitignore").write_text("packages/claude_patches/last_report.json\npackages/claude_patches/manifest.op.*.json\n")
    sh(cfg, "init", "-q")
    sh(cfg, "add", "-A")
    sh(cfg, "commit", "-qm", "base")
    pin = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cfg, capture_output=True, text=True).stdout.strip()
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("AUDIT_CONFIG", str(cfg))
    monkeypatch.setenv("AUDIT_OPTIONS", str(data / "options.json"))
    monkeypatch.setenv("AUDIT_STATE", str(data / "state.json"))
    monkeypatch.setenv("AUDIT_VERSION", "0.1.0")
    import audit
    importlib.reload(audit)
    opts = {"pin": pin, "ping_url": "", "run_at": "06:15"}
    return audit, cfg, pin, opts


def test_clean_is_green(env):
    audit, cfg, pin, opts = env
    f = audit.run_once(opts)
    assert f["ok"], f["failures"]
    assert f["shell_command"] == [{"file": "packages/system/zz_claude_patch_harness.yaml",
                                   "name": "claude_apply_patch",
                                   "command": "python3 /config/packages/claude_patches/harness.py"}]


def test_a_edit_outside_harness(env):
    audit, cfg, pin, opts = env
    (cfg / "packages/system/helpers.yaml").write_text("input_boolean: {}\n")
    assert not audit.run_once(opts)["ok"]


def test_b_commit_without_accept(env):
    audit, cfg, pin, opts = env
    (cfg / "packages/system/helpers.yaml").write_text("input_boolean: {}\n")
    sh(cfg, "commit", "-qam", "sneaky")
    f = audit.run_once(opts)
    assert not f["ok"] and "not the pin" in f["failures"][0]


def test_c_untracked_bak(env):
    audit, cfg, pin, opts = env
    (cfg / "packages/hvac.yaml.bak-1").write_text("x")
    assert any("bak" in x for x in audit.run_once(opts)["failures"])


def test_d_dirty_last_report(env):
    audit, cfg, pin, opts = env
    (cfg / "packages/claude_patches/last_report.json").write_text(json.dumps({"step": "git_dirty"}))
    assert any("last_report" in x for x in audit.run_once(opts)["failures"])


def test_e_pin_changed_without_accept(env):
    audit, cfg, pin, opts = env
    assert audit.run_once(opts)["ok"]
    (cfg / "packages/system/helpers.yaml").write_text("input_boolean: {}\n")
    sh(cfg, "commit", "-qam", "new work")
    new = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cfg, capture_output=True, text=True).stdout.strip()
    opts2 = dict(opts, pin=new)
    f = audit.run_once(opts2)
    assert not f["ok"] and any("accept" in x for x in f["failures"])
    # and it stays failed on the next run
    assert not audit.run_once(opts2)["ok"]


def test_accept_commit_turns_green(env):
    audit, cfg, pin, opts = env
    assert audit.run_once(opts)["ok"]
    (cfg / "packages/system/helpers.yaml").write_text("input_boolean: {}\n")
    sh(cfg, "commit", "-qam", "new work")
    new = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cfg, capture_output=True, text=True).stdout.strip()
    opts2 = dict(opts, pin=new)
    (cfg / "packages/audit/accept.json").write_text(json.dumps(
        {"pin": new, "options_sha": audit.options_sha(opts2), "version": "0.1.0"}))
    sh(cfg, "add", "-A")
    sh(cfg, "commit", "-qm", "accept")
    f = audit.run_once(opts2)
    assert f["ok"], f["failures"]
    assert "accepted change" in f["notes"]


def test_second_shell_command(env):
    audit, cfg, pin, opts = env
    (cfg / "configuration.yaml").write_text(
        (cfg / "configuration.yaml").read_text() + 'shell_command:\n  evil: "rm -rf /"\n')
    sh(cfg, "commit", "-qam", "x")
    f = audit.run_once(dict(opts, pin=subprocess.run(["git", "rev-parse", "HEAD"], cwd=cfg,
                                                      capture_output=True, text=True).stdout.strip()))
    assert any("shell_command" in x for x in f["failures"])


def test_untracked_in_security_path(env):
    audit, cfg, pin, opts = env
    (cfg / "packages/system/extra.yaml").write_text("shell_command:\n  x: y\n")
    f = audit.run_once(opts)
    assert any("untracked in security path" in x for x in f["failures"])


def test_harness_own_files_ignored(env):
    audit, cfg, pin, opts = env
    (cfg / "packages/claude_patches/manifest.op.20261030-1.json").write_text("{}")
    (cfg / "packages/claude_patches/last_report.json").write_text(json.dumps({"step": "done"}))
    assert audit.run_once(opts)["ok"]


def test_exception_is_failure(env, monkeypatch):
    audit, cfg, pin, opts = env
    monkeypatch.setattr(audit, "check_bak", lambda: 1 / 0)
    f = audit.run_once(opts)
    assert not f["ok"] and "audit error" in f["failures"][-1]
