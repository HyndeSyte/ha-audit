# HA Audit

A Home Assistant App that checks, once a day, that `/config` still matches the
commit the owner accepted. It reads `/config` read-only, holds no Home
Assistant, Supervisor or auth access, uses no model, and listens on no port.
Its only network use is one HTTPS POST to the healthchecks.io check named in
its options.

Checks: HEAD is the accepted commit (or the accept commit on top of it); no
tracked change and no stray file in `packages/system` or
`packages/claude_patches`; no `*.bak*` file; the patch harness's last report
is clean; exactly one `shell_command`, the pinned one; and any change to this
App's options or version matches the committed `packages/audit/accept.json`.
A failure stays failed until it is resolved; an error is a failure.

Guarantee: drift detection, not tamper resistance.

    python3 -m pytest -q tests
