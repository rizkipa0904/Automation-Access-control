"""Map filtered device evidence to the supplied access-control checklist.

These rows describe collection coverage. They never assert policy compliance or
external controls such as approvals, ownership, MFA enforcement, or log receipt.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Item:
    id: str
    area: str
    prefixes: tuple[str, ...]
    commands: tuple[str, ...]
    follow_up: str
    accounts: bool = False
    manual: bool = False
    direct: tuple[str, ...] = ()


CHECKLIST = {
    'paloalto': (
        Item('PA-01', 'Administrator accounts and privileges', ('admin ', 'admin-role ', 'authentication-profile '),
             ('show admins all', 'show config running'),
             'Reconcile every local, remote, and Panorama administrator with approvals and identity-provider groups; verify Web UI, CLI, API, and virtual-system roles.', accounts=True),
        Item('PA-02', 'Authentication and sessions', ('authentication-profile ', 'password-complexity ', 'management idle-timeout ', 'management admin-lockout ', 'admin '),
             ('show config running',),
             'Verify Web UI and CLI login paths, default-password controls, MFA policy and challenge at the identity provider, failed-login behavior, and emergency accounts.'),
        Item('PA-03', 'Management access sources', ('management permitted-ip ', 'interface-management ', 'management interface ', 'ipv6 '),
             ('show config running',),
             'Trace management-profile assignments, permitted IPv4/IPv6 sources, bastion paths, and external network controls; confirm no unapproved exposure.'),
        Item('PA-04', 'Services and API access', ('management service ', 'management api ', 'interface-management ', 'snmp ', 'api-key-lifetime ', 'tls '),
             ('show config running',),
             'Review HTTPS, SSH, SNMP and API on every management interface; verify API roles, key lifetime/revocation, TLS, and source restrictions.'),
        Item('PA-05', 'Administrator activity logging', ('logging ', 'log-forwarding ', 'management time ', 'ntp '),
             ('show config running',),
             'Sample System and Config logs, match account/source/time to a change ticket, and verify forwarding, time, and retention in the log destination.'),
        Item('PA-06', 'Access lifecycle', ('admin ',), ('show admins all', 'show config running'),
             'Compare accounts and roles with HR, owners, approvals, transfers/departures, API-key revocation, and active sessions.',
             accounts=True, manual=True),
    ),
    'cisco': (
        Item('CS-01', 'Administrator accounts and privileges', ('aaa authorization ', 'username ', 'enable secret ', 'aaa group server '),
             ('show running-config', 'show privilege'),
             'Reconcile local and TACACS+/RADIUS administrators with approved owners and effective server-assigned command privileges.', accounts=True),
        Item('CS-02', 'AAA login and sessions', ('aaa authentication ', 'line vty ', 'line con ', 'login block-', 'aaa new-model'),
             ('show running-config', 'show users'),
             'Review every VTY/console method list, fallback, timeout and failed-login control; verify actual login and MFA evidence without changing AAA.'),
        Item('CS-03', 'Management access sources', ('line vty ', 'access-list ', 'ip access-list ', 'ipv6 access-list ', 'interface ', 'vrf '),
             ('show running-config', 'show ip ssh'),
             'Trace IPv4/IPv6 ACLs, management interfaces/SVIs and VRFs to approved administrator sources; confirm SSHv2 and no Telnet.',
             direct=('show ip ssh',)),
        Item('CS-04', 'Services other than SSH', ('ip http ', 'snmp-server ', 'netconf-yang', 'restconf', 'ip ssh '),
             ('show running-config',),
             'Review HTTPS/API/SNMP authentication, least privilege and source restrictions separately from VTY AAA; verify unused services are disabled.'),
        Item('CS-05', 'Logging and accounting', ('aaa accounting ', 'logging ', 'ntp ', 'service timestamps ', 'clock timezone '),
             ('show running-config',),
             'Sample login/EXEC/change records, TACACS+ command accounting where used, log delivery, device time and retention; config lines alone are not proof.'),
        Item('CS-06', 'Access lifecycle and emergency accounts', ('username ', 'enable secret ', 'ip ssh pubkey-chain '),
             ('show running-config',),
             'Reconcile accounts and SSH keys with personnel and approvals; verify break-glass controls, key/secret rotation and revocation samples.',
             accounts=True, manual=True),
    ),

}


def evaluate(result, platform, device_id='D0001'):
    """Return exactly six coverage rows for the selected device family."""
    items = CHECKLIST.get(platform, ())
    evidence = result.get('evidence', [])
    evidence_by_command = {}
    evidence_ids = {}
    for index, entry in enumerate(evidence, 1):
        command = entry.get('command', '')
        evidence_by_command[command] = entry.get('text', '')
        evidence_ids[command] = f'{device_id}-E{index:02d}'
    facts = []
    for fact in result.get('facts', []):
        if isinstance(fact, dict):
            value, source = str(fact.get('text', '')), fact.get('source', '')
        else:
            value, source = str(fact), ''
        facts.append((value, source))
    accounts = result.get('accounts', [])
    rows = []
    for item in items:
        matching = [value for value, source in facts
                    if value.lower().startswith(item.prefixes) and (not source or source in item.commands)]
        if item.accounts:
            matching += [f"Account: {account.get('username', '')} · role/group: {account.get('privilege', 'unknown')}"
                         for account in accounts if account.get('username')]
        for command in item.direct:
            value = evidence_by_command.get(command, '')
            if value and not value.startswith('['):
                matching.append(f'{command}: {value}')
        # Keep the checklist compact. The device's detailed configuration and
        # evidence rows remain available immediately below in the same report.
        observation = '\n'.join(dict.fromkeys(matching))[:8000] or 'No matching device fields were extracted.'
        ids = [evidence_ids[command] for command in item.commands if command in evidence_ids]
        if item.manual:
            status = 'Manual verification'
        elif not matching:
            status = 'Not collected'
        elif item.id == 'CS-03' and any('transport input ' in value.lower() and
                                       ('telnet' in value.lower() or value.lower().endswith(' all')) for value in matching):
            status = 'Attention'
        else:
            status = 'Needs review'
        rows.append({'id': item.id, 'area': item.area, 'status': status,
                     'observation': observation, 'follow_up': item.follow_up,
                     'evidence_ids': ids, 'commands': list(item.commands)})
    return rows
