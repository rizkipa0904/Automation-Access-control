# Changelog

## 1.1.0 — 2026-10-27

Production-hardening release for the local Cisco IOS / IOS XE and Palo Alto
PAN-OS access review tool.

### Read-only guarantee

- The SSH channel has exactly one write path: `_send_allowed_show_command`.
- Only literal members of the hard-coded platform allowlists can be sent:
  `show version`, `show inventory`, `show privilege`, `show ip ssh`,
  `show users`, `show ssh`, `show running-config`; and `show system info`,
  `show admins all`, `show config running`.
- No configuration mode, shell escape, SCP/SFTP, paging key, confirmation,
  `terminal length 0`, `set cli pager off`, or user-supplied command is sent.
- Regression tests reject configuration, state-changing, and injected payloads
  at the command sender.

### Fixed

- Prompt detection now ignores trailing blank lines, so prompts followed by a
  newline are recognized instead of timing out. Short terminal escapes used by
  PAN-OS (for example `ESC=` and `ESC(0`) are removed along with ANSI CSI/OSC
  sequences before prompt matching.
- Large-output handling processes only the response tail for prompt detection,
  avoiding quadratic work on multi-megabyte configurations.
- The in-memory output guard was raised from 2 MB to 16 MB for realistic PAN-OS
  and IOS configurations; exceeding it still stops collection safely.
- A session or SSH error after earlier commands now marks the device
  `partial` and keeps the sanitized evidence instead of discarding it as
  `failed`.
- Closed SSH channels report a clear session-sync error.
- PAN-OS and Cisco pager variants are detected without sending any key.
- CLI error detection is limited to the start of a command response, so banner
  text such as "Access denied" cannot mark a successful command as failed.
- PAN-OS `show admins all` accepts both one-name-per-line and table output,
  skips headings/count lines, and refuses unrecognized formats rather than
  guessing a username.
- Cisco extraction adds modern `logging host` options (transport, port, VRF,
  filter), NTP servers with options, NTP key presence, routed/SVI/loopback
  interface addresses and VRFs, legacy `radius-server host` /
  `tacacs-server host` addresses, `no login`, `ip ssh`
  timeout/retry/logging, `service password-encryption`, `clock timezone`, and
  `aaa authorization console` / `aaa authentication enable` /
  `aaa accounting system`.
- IOS XE 3.x release strings are no longer mistaken for legacy IOS.
- PAN checklist mapping now links System/Config log-forwarding, timezone, NTP,
  and interface-management-profile assignments to their controls; Cisco `no
  login` is flagged for attention.
- Input validation rejects non-string fields, control characters in usernames,
  boolean/float ports, and malformed port strings.
- Extracted facts are deduplicated and capped; evidence text and account lists
  are bounded. Truncation is recorded as a collection issue and the device is
  marked partial when a completed result was truncated.
- Report values strip bidirectional/zero-width control characters in addition
  to Excel formula prefixes and illegal XML characters.
- Unexpected HTTP handler/report failures return a safe 500 JSON response
  instead of dropping the connection or exposing internals.
- `Host`/`Origin` validation accepts `localhost` as well as `127.0.0.1` while
  remaining loopback-only; the server no longer advertises its Python version.
- The launcher verifies dependencies import after installation and refuses to
  start if they do not.
- Corrupt local state is preserved rather than overwritten; recovery steps are
  documented.
- Removed the committed macOS `.DS_Store` metadata file.

### Added

- Excel auditor sign-off columns: **Auditor decision**, **Owner**,
  **Reviewer comment**, **Review date**, with a data-validation list for the
  decision.
- Workbook metadata: tool version, report generation time, status legend, and
  document properties.
- Version display in the app footer and workbook (1.1.0).
- UI polling errors are separated from operator action errors; requests have a
  timeout, with a longer timeout for report downloads.
- Run summaries carry a revision counter, so the UI does not re-download an
  unchanged run payload on every poll; polling interval is one second.

### Verification

```bash
.venv/bin/python -m unittest discover -s tests -v   # 70 tests
node tests/test_ui.js
```

Tests are fixture-based and do not contact devices. Validate each target device
family and release with an authorized read-only account before production use.
