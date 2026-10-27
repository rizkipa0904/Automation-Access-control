# Network Access Review

A local, read-only SSH tool for collecting and reviewing administrative access evidence from Cisco IOS / IOS XE switches and Palo Alto Networks PAN-OS firewalls. It organizes work by project, displays per-device status and sanitized live activity, and exports an Excel workbook for review.

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

On first launch, `start.py` creates `.venv`, installs the pinned dependencies from `requirements.txt`, and starts the app. Later launches use the same command. The terminal prints a local URL such as `http://127.0.0.1:54321/`; the port will vary. If the browser does not open automatically, copy that URL into a browser on the same computer.

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

To refresh the app after pulling, stop the old process with **Ctrl+C**, pull the changes, and run `python3 start.py` again. The launcher installs changed pinned dependencies when needed.

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
7. The dashboard shows counts for **Total devices**, **In progress**, **Failed**, and **Done** for the selected scan. Select an IP to open its sanitized activity, current command, issues, and filtered evidence. The terminal-style panel is an activity preview, not an unrestricted raw terminal.
8. Select **Download report** after the scan completes to download the `.xlsx` workbook. The report is a snapshot of collected and sanitized evidence. A completed scan does not mean all controls passed or that all accounts were discovered.

At most five SSH connections run concurrently across all projects. Additional targets wait in a queue. Avoid repeated authentication attempts that could trigger account lockout.

## What the audit collects

**The device command channel is restricted to the literal `show ...` commands listed below.** No `configure`, `set`, `delete`, `commit`, `clear`, `request`, or other operational/configuration command is sent. The only other terminal input is a space character to advance a paginated read-only response. A command failure, unsupported output, insufficient privilege, or parser mismatch is recorded as a collection issue; the app does not fall back to arbitrary commands.

### Cisco IOS / IOS XE

The current command allowlist is:

- `show version`, `show inventory`: device identity, model/version and available inventory identifiers.
- `show privilege`: privilege level of the account used for this scan; it is not the level of every user.
- `show ip ssh`: SSH enabled/disabled and version where available.
- `show users`, `show ssh`: session commands are run, but their session output is intentionally not exported.
- `show running-config`: a strict parser extracts visible local usernames and privilege, AAA authentication/authorization/accounting method lists, RADIUS/TACACS+ group/server references and safe server addresses/ports, selected VTY login/authorization/accounting/transport/access-class/timeout settings, and configured SSH version. Secret keys and unrecognized lines are omitted.

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

The current command allowlist is:

- `show system info`: hostname, model, serial and PAN-OS version when recognized.
- `show admins all`: administrator names known to the firewall. Vendor documentation says this can include local, remote, and Panorama-pushed administrators, whether or not they are currently logged in. It is not the active-session list.
- `show config running`: a strict XML parser extracts local admin names and recognized role/profile references, safe password-complexity values, administrator authentication-profile references and methods when present, management permitted IPs, management service flags, idle timeout, and lockout settings. Password hashes, private keys, and unrecognized fields are not exported.

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

## Excel report and status meanings

The workbook contains:

- **Run Summary** — project/run metadata, platform, target totals and device statuses.
- **Device Inventory** — IP/port, platform, extracted identity, completion time, status, and completeness note.
- **Scan Results** — access-control checks, sanitized observations, evidence links, status, and limitations.
- **Accounts** — usernames and extracted privilege/role, with source command and evidence IDs.
- **Access Configuration** — sanitized AAA, management, authentication-profile, password-complexity, and related settings.
- **Evidence** — filtered command excerpts with device IDs and timestamps.
- **Collection Issues** — failed or incomplete stages and their impact.

`Observed` means a field was extracted; it is not a pass. `Attention` flags a condition that merits review; it is not necessarily a failure. `Not Available` means the app could not establish the requested fact from the collected evidence. Missing data must never be treated as proof that a user, restriction, or control does not exist.

## Data handling and security

- Credentials are used in memory for the scan and are not written to the workbook or project state. Clear form credentials after use.
- Sanitized project and scan data are stored locally in `.access-review-data/` and can contain usernames, IP addresses, device identity and access configuration. Restrict access to this directory and any downloaded reports.
- Raw command output is not saved as project state or exported. The live preview only renders filtered fields and safe activity events.
- Excel files are not encrypted by this tool. Store them in an access-controlled location.
- One app instance at a time can use the same project data directory. Do not commit `.access-review-data/`, credentials, populated CSVs, or generated reports.
- Use only on devices and networks you are authorized to audit. Restrict the device account itself to the minimum read-only commands necessary.

## Troubleshooting

- **Dependencies fail to install:** check Python/`venv`, directory write access, and package-index connectivity. For an offline installation, have an administrator prepare a wheelhouse and configure pip for it before running the launcher.
- **Browser did not open:** copy the `127.0.0.1` URL from the terminal into a browser on the same computer.
- **SSH connection or authentication fails:** verify reachability, port, credentials, device AAA policy, and that the scan account is not locked. Avoid repeated retries.
- **Host key verification required:** independently verify the fingerprint. Do not approve an unexpected key.
- **Partial or missing fields:** check the workbook's **Collection Issues** sheet, device version, command support, privilege, and output format. Missing fields do not imply that a control is disabled.
- **Update reports local changes would be overwritten:** inspect `git status --short`, back up or commit wanted changes, then retry the fast-forward pull.

## Development and tests

```bash
.venv/bin/python -m unittest discover -s tests -v
node tests/test_ui.js
```

Fixture tests do not replace verification against authorized lab devices. Before production use, validate the device models, OS versions, output formats, privileges, host-key process, partial-output behavior, and report contents used by your organization.

## Vendor references

- [Palo Alto: CLI Cheat Sheet — Device Management](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-device-management) — explains `show admins all` coverage.
- [Palo Alto: Give Administrators Access to the CLI](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/get-started-with-the-cli/give-administrators-access-to-the-cli) — describes administrator role levels.
- [Palo Alto: Authentication Profile](https://docs.paloaltonetworks.com/ngfw/help/10-1/device/device-authentication-profile/configure-an-authentication-profile) — describes the supported scope of additional factors.
- [Palo Alto: Configure Multi-Factor Authentication](https://docs.paloaltonetworks.com/ngfw/administration/authentication/configure-multi-factor-authentication) — explains supported MFA integrations.
- [Cisco: Authentication, Authorization, and Accounting Configuration Guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/xe-16-9/sec-usr-aaa-xe-16-9-book.pdf) — Cisco IOS XE AAA concepts and method-list application.
