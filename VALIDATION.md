# Validation and Access-Control Coverage

**Version:** 1.1.1  
**Date:** 2026-10-27  
**Scope:** local Cisco IOS / IOS XE switch and Palo Alto PAN-OS firewall access review.

This document records what has been validated in the implementation and what
must still be validated against real devices before production sign-off. It is
not a claim of compliance or of universal hardware/software compatibility.

## 1. Read-only enforcement

| Requirement | Implementation | Validation |
| --- | --- | --- |
| Only literal read-only `show ...` commands | Hard-coded `COMMANDS` and `PALO_COMMANDS` allowlists | `test_command_sender_rejects_everything_except_literal_show_allowlist`, `test_only_fixed_show_commands` |
| Single device write path | `_send_allowed_show_command` is the only `channel.sendall` call; it re-checks platform allowlist membership | Source audit and command-sender tests |
| No configuration mode, shell, SCP/SFTP | No such code path or library call | Source audit |
| No pager/terminal/confirmation keys | Pager detection aborts and closes the session; no key is sent | `test_pagination_never_sends_a_key_or_another_command`, `test_output_size_limit_is_enforced` |
| No user/UI/CSV command injection | Targets only contain IP, port, username, password; commands are constants | `test_command_sender_rejects_everything_except_literal_show_allowlist`, UI/CSV tests |
| `show users` stall avoided | Intentionally excluded; it can perform reverse DNS and its output was never exported | `test_command_timeouts_prioritize_large_configs_and_session_checks`, README |
| Critical evidence runs first | Cisco order: `show version`, `show running-config`, then inventory/privilege/SSH/session | `test_command_timeouts_prioritize_large_configs_and_session_checks`, `test_show_ssh_timeout_keeps_critical_evidence_and_explains_skip` |

## 2. Cisco IOS / IOS XE control matrix

| ID | Control | Evidence extracted | Checklist result | Validation |
| --- | --- | --- | --- | --- |
| CS-01 | Administrator accounts and privileges | Local usernames/privilege, AAA authorization, AAA groups, modern and legacy RADIUS/TACACS+ servers, `show privilege` | Needs review; accounts listed | Matrix test; extraction/secret tests |
| CS-02 | AAA login and sessions | `aaa new-model`, authentication/enable methods, VTY/console login, `login block-for`, quiet-mode, on-failure/success logging | Needs review; Attention for `no login`; session review is manual | Matrix test; checklist tests |
| CS-03 | Management access sources | VTY/console access-class (IPv4/IPv6), transport, ACL rules, SVI/loopback/routed interface addresses, VRFs, `show ip ssh` | Needs review; Attention for Telnet/`all` | Matrix test; report tests |
| CS-04 | Services other than SSH | HTTP/HTTPS, HTTP authentication/access-class, SNMP presence, NETCONF/RESTCONF, `ip ssh` parameters | Needs review; secrets hidden | Matrix test; extraction tests |
| CS-05 | Logging and accounting | AAA accounting, logging host/transport/VRF/filter, buffers/console/monitor/trap, NTP/auth/trusted keys, timezone, timestamps | Needs review | Matrix test; extraction tests |
| CS-06 | Access lifecycle and emergency accounts | Accounts, enable secret/password presence, `ip ssh pubkey-chain` presence | Manual verification; accounts listed | Matrix test; report tests |

The `username` entry inside `ip ssh pubkey-chain` is **not** treated as a local
account. Banner text is skipped so it cannot inject fake accounts or enable
facts.

## 3. Palo Alto PAN-OS control matrix

| ID | Control | Evidence extracted | Checklist result | Validation |
| --- | --- | --- | --- | --- |
| PA-01 | Administrator accounts and privileges | `show admins all` names; local admin role/profile references; admin-role device permissions (CLI/XML API/REST API/Web UI) | Needs review; accounts listed | Matrix test; admin-list parser tests |
| PA-02 | Authentication and sessions | Authentication-profile methods/factors, password complexity, idle timeout, admin lockout | Needs review | Matrix test; report tests |
| PA-03 | Management access sources | Management permitted IPs (IPv4/IPv6), interface-management profiles, interface/profile assignments | Needs review | Matrix test; checklist mapping tests |
| PA-04 | Services and API access | Management service flags (SSH/Telnet/HTTP/HTTPS/SNMP), interface-profile services, API role permissions | Needs review; API key/TLS policy remains manual | Matrix test; report tests |
| PA-05 | Administrator activity logging | System/Config log-forwarding profile references, timezone, NTP server addresses | Needs review | Matrix test; checklist mapping tests |
| PA-06 | Access lifecycle | Administrator names/roles from `show admins all` and configuration | Manual verification; accounts listed | Matrix test; report tests |

`show admins all` accepts one-name-per-line and table output, skips headings,
separators, and `Total:`/summary lines, and rejects unrecognized formats rather
than guessing. `show config running` must be XML; `set` output produces a
specific issue asking for XML output.

## 4. Cross-cutting requirements

| Area | Validation |
| --- | --- |
| Credentials | Never written to state/workbook/activity/errors; masked if a value coincides with device text; tests cover state, report, live events |
| SSH host keys | System known_hosts trusted; unknown key requires explicit fingerprint approval; changed key blocked; tests cover lock/approval flow |
| Pagination | Detected for Cisco/PAN pager variants; collection stops without sending a key; test covers |
| Timeouts | 30 s normal, 60 s configuration, 10 s optional `show ssh`; elapsed/closed channel handled; tests cover |
| Partial results | Each command failure records an issue; evidence retained; cancellation/restart marked honestly; tests cover |
| Input validation | IPv4/IPv6, port, username/password, duplicates, limits, control characters; tests cover |
| State | Atomic writes, 0700 directory, 0600 file, one-instance lock, corrupt state preserved; tests cover |
| Workbook | One grouped sheet, 13 columns, 6 checklist items per platform, evidence links, auditor sign-off columns, status legend, formula/bidi/XML sanitization; matrix and report tests cover |
| API/UI | Token, Host/Origin loopback restriction, project/scan lifecycle, rerun, cancel, delete, host-key approval, CSV import, polling, revision-aware payload skipping; tests cover |
| Read-only report content | No raw output, no secrets/hashes/keys/communities; matrix tests check every extracted field |

## 5. Automated verification

```bash
.venv/bin/python -m unittest discover -s tests -v
node tests/test_ui.js
```

Latest local result:

```text
Ran 83 tests — OK
UI simulation passed
pip check — no broken requirements
compileall — OK
git diff --check — OK
```

The suite includes a full fixture matrix for every Cisco and PAN-OS control,
malformed/empty inputs, missing optional result fields, secret leak checks, and
the host-key approval UI flow.

## 6. Residual validation required before production

These items cannot be proven from fixtures and must be verified in an authorized
lab or pilot:

1. **Real device families/releases** — at least one Cisco IOS 12.x, one IOS XE,
   and one PAN-OS release. Record model, version, account privilege, commands
   supported, output format, and results in a compatibility matrix.
2. **Pager/terminal behavior** — confirm the read-only account can complete
   `show running-config` / `show config running`; configure device-side pager or
   terminal length if needed. The tool will not send setup commands.
3. **PAN-OS XML output** — confirm `show config running` returns XML under the
   audit account; adjust the account's CLI config-output-format device-side if
   it returns `set` output.
4. **Active session visibility** — `show users` is intentionally not collected;
   review active sessions directly or through AAA/logging records.
5. **External authentication/MFA** — confirm RADIUS/SAML/TACACS+ policy and
   actual MFA enforcement at the provider. Device configuration alone is not
   proof.
6. **Host-key trust** — verify fingerprints through an independent trusted
   channel before approval.
7. **Workbook acceptance** — open exported workbooks in the organization's Excel
   version and confirm auditor columns, evidence links, printing, and data
   validation.
8. **Operational limits** — run an approved pilot with the expected batch size
   and pager/privilege profile; confirm timeouts, partial results, cancellation,
   and report generation meet operational expectations.

Until these are complete, treat real-device compatibility as unverified even
though all automated checks pass.
