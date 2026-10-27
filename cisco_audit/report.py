"""Create a sanitized, traceable, scan-focused audit workbook."""
from io import BytesIO
from collections import Counter
import re
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
from .core import safe_text


def _excel_value(value):
    """Treat every textual cell as untrusted data and remove XML-invalid characters."""
    if not isinstance(value, str):
        return value
    return safe_text(re.sub(r'[\ufffe\uffff\ud800-\udfff]', '', value))


def _append(ws, values):
    ws.append([_excel_value(value) for value in values])


def workbook(run):
    wb = Workbook()
    wb.remove(wb.active)
    def sheet(name, headers):
        ws = wb.create_sheet(name)
        ws.append(headers)
        return ws
    summary = sheet('Run Summary', ['Item', 'Value'])
    inventory = sheet('Device Inventory', ['Device ID', 'Platform', 'IP', 'Port', 'Hostname', 'Identity (sanitized)', 'Device collection finished (UTC)', 'Status', 'Completeness'])
    results = sheet('Scan Results', ['Device ID', 'Check', 'Status', 'Observed result', 'Evidence ID', 'Command', 'Device collection finished (UTC)', 'Scope / limitations'])
    accounts = sheet('Accounts', ['Device ID', 'Username', 'Privilege / role', 'Account evidence ID', 'Account source', 'Role evidence ID', 'Role source', 'Scope / limitations'])
    settings = sheet('Access Configuration', ['Device ID', 'Setting (sanitized)', 'Evidence ID', 'Source command', 'Scope / limitations'])
    evidence = sheet('Evidence', ['Evidence ID', 'Device ID', 'Command', 'Device collection finished (UTC)', 'Sanitized excerpt', 'Completeness'])
    issues = sheet('Collection Issues', ['Device ID', 'Command / stage', 'Issue', 'Impact / follow-up'])
    platform = run.get('platform', 'cisco')
    for key, value in [('Project', run.get('project_name', '')), ('Run ID', run['id']), ('Started (UTC)', run['started']), ('Finished (UTC)', run.get('finished', 'In progress')), ('Platform', platform), ('Tool version', '1.0.0'), ('SSH profile', 'Legacy compatibility (weaker algorithms)' if run.get('legacy') else 'Modern'), ('Targets', len(run['results'])), ('Scope', 'Snapshot and sanitized fields only; no automatic compliance conclusion. Empty data does not prove absence.')]:
        _append(summary, [safe_text(key), safe_text(value)])
    for status, count in sorted(Counter(r['status'] for r in run['results']).items()):
        _append(summary, [safe_text('Devices: ' + status), count])
    for n, result in enumerate(run['results'], 1):
        did = f'D{n:04d}'
        p = result.get('platform', platform)
        # The scan start is not an evidence-collection timestamp. An interrupted
        # scan may have live evidence without a device completion time.
        t = result.get('time') or ''
        evmap, evtext = {}, {}
        for j, ev in enumerate(result.get('evidence', []), 1):
            eid = f'{did}-E{j:02d}'
            evmap[ev['command']] = eid
            evtext[ev['command']] = ev['text']
            txt = ev['text']
            _append(evidence, [eid, did, safe_text(ev['command']), t, safe_text(txt), safe_text(ev['status'] + ('; truncated' if len(txt) > 32000 else ''))])
        identity_commands = ('show version', 'show inventory') if p == 'cisco' else ('show system info',)
        identity = '\n'.join(evtext[c] for c in identity_commands if c in evtext and not evtext[c].startswith('['))
        hostname = ''
        for line in identity.splitlines():
            if ' uptime is ' in line:
                hostname = line.split(' uptime is ', 1)[0]
            elif line.lower().startswith('hostname:'):
                hostname = line.split(':', 1)[1].strip()
        completeness = 'Filtered output; not complete evidence' if result['status'] == 'completed' else 'Collection is incomplete; see Collection Issues'
        _append(inventory, [did, safe_text(p), safe_text(result['ip']), result['port'], safe_text(hostname), safe_text(identity), t, safe_text(result['status']), completeness])
        account_source = 'show running-config' if p == 'cisco' else 'show config running'
        facts_source = account_source
        for account in result.get('accounts', []):
            source = account.get('source', account_source)
            role_source = account.get('role_source', '' if source == 'show admins all' else source)
            _append(accounts, [did, safe_text(account.get('username')), safe_text(account.get('privilege')), evmap.get(source, ''), safe_text(source), evmap.get(role_source, ''), safe_text(role_source), 'Snapshot; external accounts and effective access may not be covered'])
        for fact in result.get('facts', []):
            text = fact.get('text', '') if isinstance(fact, dict) else fact
            source = fact.get('source', facts_source) if isinstance(fact, dict) else facts_source
            _append(settings, [did, safe_text(text), evmap.get(source, ''), safe_text(source), 'Filtered fields; configuration and enforcement may be incomplete'])
        for issue in result.get('issues', []):
            _append(issues, [did, safe_text(issue.get('command')), safe_text(issue.get('message')), 'Data may be incomplete'])

        def add(check, source, value, limitation, attention=False, force_unavailable=False):
            """Never infer compliance or absence from missing/sanitized output."""
            available = bool(value and source in evmap and not evtext.get(source, '').startswith('[') and not value.startswith('['))
            state = 'Not Available' if force_unavailable else ('Attention' if attention else 'Observed') if available else 'Not Available'
            observed = value if available or force_unavailable else 'No data could be extracted from this command.'
            if len(observed) > 32000:
                limitation += ' The result was truncated at the Excel cell limit; related evidence may also be truncated.'
            _append(results, [did, check, state, safe_text(observed), evmap.get(source, '') if available or (force_unavailable and source in evmap) else '', source, t if available or (force_unavailable and source in evmap) else '', limitation])

        raw_facts = [f.get('text', '') if isinstance(f, dict) else f for f in result.get('facts', [])]
        raw_accounts = result.get('accounts', [])
        account_lines = '\n'.join(f"{a.get('username', '')} — privilege/role: {a.get('privilege', 'unknown')}" for a in raw_accounts if a.get('source', account_source) == account_source or a.get('role_source') == account_source)
        if p == 'cisco':
            add('Local accounts and privilege', account_source, account_lines, 'Only extracted local accounts are shown; status, ownership, and external AAA permissions are not proven.')
            aaa_facts = '\n'.join(f for f in raw_facts if f.lower().startswith('aaa '))
            add('AAA and method lists', facts_source, aaa_facts, 'Only visible configuration is shown; AAA server effectiveness is not proven.')
            external_aaa = '\n'.join(f for f in raw_facts if re.match(r'(?i)^(?:aaa authentication|aaa authorization|aaa accounting|aaa group server|radius server|tacacs server)', f))
            mfa_summary = ('External RADIUS/TACACS+ authentication references were observed:\n' + external_aaa + '\nMFA enforcement is controlled by the external provider and cannot be verified from this device snapshot.' if external_aaa else 'No external RADIUS/TACACS+ authentication reference was extracted. MFA enforcement cannot be determined from this snapshot.')
            add('MFA enforcement', facts_source, mfa_summary, 'The device configuration does not prove an external identity provider prompts for or enforces a second factor.', force_unavailable=True)
            vty = '\n'.join(f for f in raw_facts if f.lower().startswith('line vty '))
            attention = any(' / transport input ' in f.lower() and ('telnet' in f.lower() or f.lower().endswith(' all')) for f in raw_facts)
            add('VTY access and transport', facts_source, vty, 'Filtered VTY fields; not all lines and ACL definitions may be covered.', attention)
            ssh = evtext.get('show ip ssh', '')
            add('SSH status', 'show ip ssh', ssh, 'Other parameters and access paths are not assessed.', bool(ssh.lower().startswith('ssh disabled')))
        else:
            # PAN-OS fields depend on software, privilege, and output format.
            add('Administrators from configuration', account_source, account_lines, 'Visible fields only; effective access and administrator completeness are not proven.')
            fact_lines = '\n'.join(raw_facts)
            add('Administrator access configuration', facts_source, fact_lines, 'Filtered fields; configuration and effective access may be incomplete.')
            auth_lines = '\n'.join(f for f in raw_facts if f.lower().startswith(('admin ', 'authentication-profile ')))
            add('Administrator authentication and MFA', facts_source, auth_lines or 'No authentication-profile or per-admin authentication reference was extracted. MFA status is not established.', 'Authentication profile references are configuration clues only. External RADIUS/SAML policy and actual MFA enforcement are not verified.', force_unavailable=True)
            listed = '\n'.join(f"{a.get('username', '')}" for a in raw_accounts if a.get('source') == 'show admins all')
            add('Administrators known to the device', 'show admins all', listed, 'The list may include local, remote, and Panorama admins; it does not prove all effective permissions.')
    colors = {'Observed': 'DDEFEA', 'Attention': 'FCE8C8', 'Not Available': 'E9EEF3', 'failed': 'FCE6E6', 'partial': 'FCE8C8'}
    for ws in wb:
        ws.freeze_panes = 'A2'
        ws.auto_filter.ref = ws.dimensions
        for cell in ws[1]:
            cell.font = Font(bold=True, color='FFFFFF')
            cell.fill = PatternFill('solid', fgColor='17365D')
            cell.alignment = Alignment(wrap_text=True, vertical='top')
        for col in ws.columns:
            letter = get_column_letter(col[0].column)
            ws.column_dimensions[letter].width = min(60, max(16, max(len(str(c.value or '').split('\n')[0]) for c in col) + 2))
            for cell in col[1:]:
                cell.alignment = Alignment(wrap_text=True, vertical='top')
                if cell.value in colors:
                    cell.fill = PatternFill('solid', fgColor=colors[cell.value])
    output = BytesIO()
    wb.save(output)
    return output.getvalue()
