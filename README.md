# Network Access Review

A local, read-only SSH tool for collecting and reviewing administrative access evidence from Cisco IOS / IOS XE switches and Palo Alto Networks PAN-OS firewalls. It organizes work by project, displays per-device status and sanitized live activity, and exports an Excel workbook for review.

**Current release:** 1.1.0. See `CHANGELOG.md` for the production-hardening changes.

This is an evidence collection aid, not a compliance certification. It does not make configuration changes, test authentication against external providers, or prove that an observed control is effective.

## Requirements

- macOS or Linux with Python 3.10 or newer, `venv`, `pip`, Git, and a modern browser.
- Network reachability from this computer to the authorized devices over SSH.
- A dedicated read-only account. Restrict its command privileges on the device as a separate control.
- A trusted way to verify each SSH host key fingerprint.
- Python package index access on first setup, or an administrator-prepared offline wheelhouse.

The app binds to `127.0.0.1` on a dynamically selected port. Keep the terminal open while using it; it is not a shared or remote web server.

## Clone and run

### First-time setup

```bash
git clone https://github.com/rizkipa0904/Automation-Access-control.git
cd Automation-Access-control
python3 start.py
```

On first launch, `start.py` creates `.venv`, installs the bounded dependencies declared in `requirements.txt`, and starts the app. Later launches use the same command. The terminal prints a local URL such as `http://127.0.0.1:54321/`; the port will vary. If the browser does not open automatically, copy that URL into a browser on the same computer.

Keep the terminal open while scans run. Press **Ctrl+C** in that terminal to stop the application safely. Running scans are marked interrupted when the app shuts down and do not resume automatically.

### Pull the latest changes in an existing clone

Open a terminal and run:

```bash
cd /path/to/Automation-Access-control
git status --short
git pull --ff-only origin main
python3 start.py
```

Replace `/path/to/Automation-Access-control` with the folder where you cloned the project. `--ff-only` avoids creating a merge commit. If Git says local changes would be overwritten, back up or commit those changes before pulling; do not discard work you need. If the clone tracks another branch, check it with `git branch --show-current` and use the matching branch name after `origin`.

To refresh the app after pulling, stop the old process with **Ctrl+C**, pull the changes, and run `python3 start.py` again. The launcher installs changed dependencies when needed.

### Manual virtual-environment setup (optional)

Use this only if you want to inspect or run the application without the launcher:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

The launcher is the recommended entry point because it prepares the environment and performs startup checks.

## Create a project and run an audit

1. Enter a project name in the left sidebar and click **New project**. Select a project to open its dashboard. Projects keep their scan history separate.
2. Click **New scan**, select **Cisco Switch · IOS / IOS XE** or **Palo Alto Firewall · PAN-OS**, and choose shared credentials or per-device credentials.
3. Enter one IP address per line. An optional port can follow a comma, for example `192.0.2.10,2222`. The default port is `22`. IPv4 and IPv6 addresses are supported; hostnames are not. A scan accepts up to 200 unique IP/port targets.
4. For per-device credentials, fill the table or import a CSV with the exact header `ip,port,username,password`. An empty port uses `22`. The CSV template contains placeholder credentials only. CSV passwords are plaintext; protect and delete the source file according to your policy.
5. For a trusted legacy Cisco device only, you may enable **Legacy SSH compatibility**. It permits weaker SSHv2 algorithms when supported by the installed SSH library. Host key verification remains enabled. This option does not support SSHv1 and is unavailable for Palo Alto.
6. Click **Start review**. If a device presents an unknown host key, verify the fingerprint using a trusted, separate source before approving it. A changed trusted key is blocked and must be resolved through your normal host-key process.
7. The dashboard shows **Total devices**, **In progress**, **Needs attention**, and **Done** for the selected scan. **Needs attention** includes failed, partial, cancelled, interrupted, and host-key verification results. **Done** counts devices whose collection completed; it does not mean their controls passed. Select an IP to open its sanitized activity, current command, issues, and filtered evidence. The terminal-style panel is an activity preview, not an unrestricted raw terminal.
8. Select **Download report** after the scan completes to download the `.xlsx` workbook. The report is a snapshot of collected and sanitized evidence. A completed scan does not mean all controls passed or that all accounts were discovered.

At most five SSH connections run concurrently across all projects. Additional targets wait in a queue. Avoid repeated authentication attempts that could trigger account lockout.

### Rerun a scan or one device

Select a completed scan and click **Rerun scan** to review all its devices again. To retry only one target, open that device's details and click **Rerun this device**. The new scan form copies the previous platform, Cisco legacy SSH setting when applicable, and selected IP addresses and ports. Enter the SSH username and password again, then click **Start scan rerun** or **Start device rerun**. Credentials and CSV contents are never recovered from an earlier scan. A rerun creates a separate scan with its own live status and report; the previous result remains available.

Each project can keep up to **100 saved scans**. At that limit, download any report you need, select an old completed scan, and click **Delete scan** to make room. Deletion removes that saved scan and its locally generated report data and cannot be undone. A running scan cannot be deleted; cancel it and wait until it has finished first. Protect exported reports separately because deleting a scan does not remove files already downloaded to your computer.

## What the audit collects

**The device command channel sends only the literal, built-in `show ...` commands listed below.** It does not send configuration commands, operational commands that change state, paging keystrokes, confirmations, terminal-setup commands such as `terminal length 0` or `set cli pager off`, or user-provided commands. The command sender accepts only an exact member of the hard-coded platform allowlist and rejects any input containing a newline, semicolon, or non-allowlisted command. A regression test exercises this boundary. If output is paginated, times out, exceeds the size limit, or cannot be parsed safely, the affected collection is marked incomplete. The app records the limitation instead of sending an unapproved response to the device. A command failure or insufficient privilege is also recorded as a collection issue.

The in-memory output guard is 16 MB per command response. Very large configurations can reach that limit; when they do, collection stops safely before another command is sent and the device is marked incomplete. Configure an appropriate device-side pager/terminal length for your read-only account if long `show running-config` or `show config running` output pages.

### Cisco IOS / IOS XE

The possible command allowlist is:

- `show version`, `show inventory`: device identity, model/version and available inventory identifiers.
- `show privilege`: privilege level of the account used for this scan; it is not the level of every user.
- `show ip ssh`: SSH enabled/disabled and version where available.
- `show users`, `show ssh`: session commands are run when supported, but their session output is intentionally not exported.
- `show running-config`: a strict parser extracts visible local usernames and privilege; AAA authentication/authorization/accounting method lists; RADIUS/TACACS+ group/server references and safe server addresses/ports, including legacy `radius-server host` / `tacacs-server host` addresses; selected VTY login (`login`, `no login`, local/authentication), authorization, accounting, transport, access-class, and timeout settings; management addresses on VTY/console/aux lines and on VLAN, loopback, tunnel, port-channel, and routed physical interfaces; HTTP/SNMP/NETCONF/RESTCONF service presence; logging hosts (including transport, port, VRF, and filter options), buffers, console/monitor/trap settings; NTP servers and authentication presence; SSH version/timeout/retry parameters; `service password-encryption`; and `clock timezone`. Secret keys, SNMP credentials, NTP keys, and unrecognized lines are omitted.

The collector starts with `show version` and proceeds only if the response identifies Cisco IOS or IOS XE with a numeric version. On IOS releases before 12.1(15), it omits `show ssh` because support is not verified; IOS XE 3.x release strings are recognized as XE rather than as an old IOS release. If the account lands at an unprivileged `>` prompt, it omits `show ip ssh` and `show running-config`. These skipped checks are recorded as issues rather than inferred as absent. Unrecognized identity/version output stops the command sequence. Command support still varies by device, release, and assigned privilege; skipped or unsupported commands produce a partial result. A custom prompt that cannot be recognized safely also stops collection.

The workbook can therefore show an example such as:

| Check | Sanitized observation | Status |
| --- | --- | --- |
| Local accounts and privilege | `netops-ro — privilege: 5` | Observed |
| AAA and method lists | `aaa authentication login default group RAD-AUTH local`; `aaa authorization exec default group TAC-GROUP local` | Observed |
| VTY access and transport | `line vty 0 4 / login authentication default`; `line vty 0 4 / transport input ssh` | Observed |
| MFA enforcement | External RADIUS/TACACS+ reference found; provider MFA policy was not checked | Not Available |
| SSH status | `SSH Enabled - version 2.0` | Observed |

This is illustrative output, not a recommendation that the sample configuration is compliant. A RADIUS/TACACS+ reference does **not** prove MFA is configured or enforced. External server policies, user membership, MFA prompts, effective command authorization, ACL definitions, and authentication success are outside this snapshot. Local usernames are accounts visible in the configuration, not a complete list of remote AAA users.

### Palo Alto Networks PAN-OS

The possible command allowlist is:

- `show system info`: hostname, model, serial and PAN-OS version when recognized.
- `show admins all`: administrator names known to the firewall. Vendor documentation says this can include local, remote, and Panorama-pushed administrators, whether or not they are currently logged in. It is not the active-session list. The parser accepts either a one-name-per-line output or a table whose first column is the administrator name and whose remaining columns match recognized values (address, client type, role, date/time, idle time, or a dash). A heading row is skipped. Unrecognized output produces an incomplete result instead of a guessed name.
- `show config running`: a strict XML parser extracts local admin names and recognized role/profile references, safe password-complexity values, administrator authentication-profile references and methods when present, management permitted IPs, management service flags, idle timeout, lockout settings, interface management profiles and their assignments, and System/Config log-forwarding profile references, timezone, and NTP server addresses. Password hashes, private keys, and unrecognized fields are not exported.

The collector starts with `show system info` and proceeds only when its `sw-version` identifies a PAN-OS major version from 7 through 12 and the CLI is in operational mode (`>`). PAN-OS HA status suffix changes in the prompt are handled; unrelated prompt changes stop collection. If version or mode cannot be verified, the scan records a partial result without trying further commands. Version and role differences can make an otherwise allowed command unavailable. Non-XML `show config running` output cannot be parsed safely, so its audit fields are reported incomplete.

An illustrative workbook excerpt could look like this:

| Check | Sanitized observation | Status |
| --- | --- | --- |
| Administrators known to the device | `admin`, `sec-auditor`, `panorama.ops` | Observed |
| Administrators from configuration | `admin — superuser`; `sec-auditor — superreader` | Observed |
| Administrator authentication | `sec-auditor — authentication-profile corp-radius`; `corp-radius — method radius` | Not Available |
| MFA enforcement | External authentication is referenced; the provider's MFA policy and actual enforcement were not verified | Not Available |
| Password complexity | `enabled yes`; `minimum-length 12` | Observed |
| Management access | `permitted-ip 192.0.2.0/24`; `idle-timeout 30` | Observed |

Names and values above are fictitious examples. `show admins all` can list remote or Panorama administrators whose individual role is not exposed by the local configuration; those roles remain `unknown` rather than being guessed. Profile references are clues for follow-up, not proof of effective access.

**MFA limitation:** the report distinguishes an observed external authentication path from verified MFA enforcement. The app cannot query the RADIUS/SAML provider or validate a second-factor challenge. Palo Alto documentation also notes that additional factors configured for authentication profiles are not supported for remote GlobalProtect or PAN-OS/Panorama administrator authentication; supported MFA integrations for those uses depend on RADIUS or SAML configuration. Verify the actual administrator-authentication path and provider-side policy independently. See the vendor documentation linked below.

## Access-control checklist mapping

Each device detail and its Excel report group show six checklist items for the selected platform. The 12 IDs below map the review areas to sanitized device observations and follow-up work. A listed command is an evidence source when that command is supported, permitted, completed, and safely parsed; its presence in the table does not mean the evidence was collected for every device.

| ID | Review area | Potential device evidence | Manual or external verification |
| --- | --- | --- | --- |
| PA-01 | Administrator accounts and privileges | `show admins all`; administrator and role/profile fields from `show config running` | Reconcile local, remote, and Panorama accounts with approved owners and identity-provider groups; confirm effective Web UI, CLI, API, and virtual-system roles. |
| PA-02 | Authentication and sessions | Authentication-profile, password-complexity, idle-timeout, and lockout fields from `show config running` | Verify login paths, emergency accounts, and the identity provider's MFA policy and actual challenge. |
| PA-03 | Management access sources | Permitted management IPs, interface-management profiles, and interface/profile assignments extracted from `show config running` | Trace bastion paths, management-profile assignments, IPv4/IPv6 sources, and external network controls. |
| PA-04 | Services and API access | Recognized management SSH, Telnet, HTTP, and HTTPS service flags and interface-management profile services from `show config running` | Check each management interface, API roles, key lifetime and revocation, SNMP, TLS policy, and source restrictions. |
| PA-05 | Administrator activity logging | System/Config log-forwarding profile references, timezone, and NTP server addresses extracted from `show config running` | Sample System and Config logs; confirm log receipt, retention, timestamps, and change-ticket correlation at the destination. |
| PA-06 | Access lifecycle | Administrator names and roles from `show admins all` and `show config running` | Compare with HR records, owner approvals, transfers, departures, active sessions, and API-key revocation. |
| CS-01 | Administrator accounts and privileges | Local usernames, privilege, AAA authorization, server-group fields, and modern/legacy RADIUS/TACACS+ server references from `show running-config`; `show privilege` for the scan account | Reconcile local and RADIUS/TACACS+ users with approved owners and effective server-assigned privileges. |
| CS-02 | AAA login and sessions | AAA authentication, VTY/console, and session-related fields from `show running-config`; `show users` runs without exporting session output | Verify method-list application, fallback, failed-login controls, login behavior, and MFA at the external provider. |
| CS-03 | Management access sources | VTY ACL/transport and management-interface fields from `show running-config`; SSH state from `show ip ssh` | Trace IPv4/IPv6 ACLs, management interfaces and VRFs to approved sources; review Telnet exposure and external access paths. |
| CS-04 | Services other than SSH | Recognized HTTP, SNMP, NETCONF, and RESTCONF fields from `show running-config` | Check service authentication, least privilege, source restrictions, and whether unused services are disabled. |
| CS-05 | Logging and accounting | AAA accounting, logging host/buffer/console/trap fields, NTP, timezone, and timestamp configuration from `show running-config` | Sample login and command records; verify log delivery, time synchronization, and retention. |
| CS-06 | Access lifecycle and emergency accounts | Local accounts and privileged-secret presence from `show running-config` | Reconcile personnel and approvals; sample break-glass use, SSH-key and secret rotation, and revocation. |

Checklist statuses describe **evidence coverage**, not compliance: **Needs review** means matching sanitized observations exist; **Attention** flags a visible condition needing review; **Not collected** means no matching field was extracted; **Manual verification** marks lifecycle items that require external records. Even where device fields are present, the app does not verify HR approvals, identity-provider MFA enforcement, log receipt, or access revocation. Missing fields do not prove a control is absent.

## Excel report and status meanings

The workbook has **one Audit Results sheet**. Scan metadata, the tool version, generation time, and device-status counts appear at the top. Results are grouped by IP address and port, so each device has its collection status, identity, **Checklist** rows, access-control checks, account list, selected configuration facts, collection issues, and sanitized evidence together. Checklist rows include their IDs, status, observation, follow-up, and evidence reference. The columns are **IP / device**, **Section**, **Check / item**, **Sanitized result**, **Status**, **Evidence ID**, **Read-only command**, **Scope / follow-up**, **Collected (UTC)**, **Auditor decision**, **Owner**, **Reviewer comment**, and **Review date**. The last four columns are intentionally blank for auditor sign-off; **Auditor decision** has a data-validation list (Pass, Fail, Needs review, Not available). Evidence IDs link to the corresponding evidence row in the same sheet.

For a partial or failed device, review its **Issue** rows and the collection status before interpreting missing checks. An interrupted scan may have no device completion timestamp even if some filtered evidence was collected.

`Observed` means a field was extracted; it is not a pass. `Attention` flags a condition that merits review; it is not necessarily a failure. `Not Available` means the app could not establish the requested fact from the collected evidence. Missing data must never be treated as proof that a user, restriction, or control does not exist.

## Data handling and security

- Credentials are used in memory for the scan and are not written to the workbook or project state. Clear form credentials after use.
- Sanitized project and scan data are stored locally in `.access-review-data/` and can contain usernames, IP addresses, device identity and access configuration. Restrict access to this directory and any downloaded reports.
- Raw command output is not saved as project state or exported. The live preview only renders filtered fields and safe activity events. Per-device configuration facts, accounts, and evidence text are capped; when an extraction cap is reached the device is marked partial and the report records that extraction was truncated. The live activity transcript is also bounded to the most recent 300 events per device.
- Excel files are not encrypted by this tool. Store them in an access-controlled location.
- One app instance at a time can use the same project data directory. Do not commit `.access-review-data/`, credentials, populated CSVs, or generated reports.
- Use only on devices and networks you are authorized to audit. Restrict the device account itself to the minimum read-only commands necessary.

## Troubleshooting

- **Dependencies fail to install:** check Python/`venv`, directory write access, and package-index connectivity. For an offline installation, have an administrator prepare a wheelhouse and configure pip for it before running the launcher.
- **Browser did not open:** copy the `127.0.0.1` URL from the terminal into a browser on the same computer.
- **SSH connection or authentication fails:** verify reachability, port, credentials, device AAA policy, and that the scan account is not locked. Avoid repeated retries.
- **Host key verification required:** independently verify the fingerprint. Do not approve an unexpected key.
- **Device prompt was not detected before the timeout:** open the affected device's details and check the command named in the **Issue** rows of the **Audit Results** sheet. Confirm that the account can run that exact `show` command, the device is using the selected platform and supported OS family, and its CLI output is not paused by pagination or an interactive message. A partial result must not be treated as a completed audit. The app does not send paging keys, terminal-setup commands, or confirmation responses; resolve the device-side output, pager/terminal-length setting, or privilege issue before rerunning.
- **Paginated output cannot be collected with show-only commands:** the device returned a pager prompt. Set the read-only account's terminal length/pager preference on the device (for example through the account's VTY/line or CLI profile), then rerun. The app will not send a paging key or pager-setup command.
- **Output exceeded the size limit:** the response exceeded the 16 MB in-memory guard. Treat the device as incomplete and review its configuration directly; the app does not stream partial raw output.
- **Partial or missing fields:** check the **Issue** rows of the **Audit Results** sheet, device version, command support, privilege, and output format. Missing fields do not imply that a control is disabled. A truncation issue means the safety cap was reached, not that the device configuration is empty.
- **Local project data could not be read:** the app preserves the unreadable state file and refuses to overwrite it. Stop the app, back up `.access-review-data/projects.json` and any related files, move the damaged file aside, then restart. Investigate the backup before discarding it; it may contain audit history.
- **Excel report could not be generated:** confirm the state directory is readable and retry after restarting the app. The sanitized scan data remains in `.access-review-data/`; do not delete it before investigating.
- **Update reports local changes would be overwritten:** inspect `git status --short`, back up or commit wanted changes, then retry the fast-forward pull.

## Development and tests

```bash
.venv/bin/python -m unittest discover -s tests -v
node tests/test_ui.js
```

Fixture tests verify application behavior without contacting devices. They do not establish compatibility with every hardware model, software release, CLI customization, AAA policy, or terminal setting. Before using the tool for a production audit, validate each device family and release with authorized lab devices, including the exact read-only account, host-key verification, command output, pagination behavior, incomplete-result handling, and workbook contents. A live device that has not been validated for these conditions should be treated as unsupported until the behavior is confirmed.

## Vendor references

- [Palo Alto: CLI Cheat Sheet — Device Management](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-device-management) — explains `show admins all` coverage.
- [Palo Alto: Give Administrators Access to the CLI](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/get-started-with-the-cli/give-administrators-access-to-the-cli) — describes administrator role levels.
- [Palo Alto: Authentication Profile](https://docs.paloaltonetworks.com/ngfw/help/10-1/device/device-authentication-profile/configure-an-authentication-profile) — describes the supported scope of additional factors.
- [Palo Alto: Configure Multi-Factor Authentication](https://docs.paloaltonetworks.com/ngfw/administration/authentication/configure-multi-factor-authentication) — explains supported MFA integrations.
- [Cisco: Authentication, Authorization, and Accounting Configuration Guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/xe-16-9/sec-usr-aaa-xe-16-9-book.pdf) — Cisco IOS XE AAA concepts and method-list application.
