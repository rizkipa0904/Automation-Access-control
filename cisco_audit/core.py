"""Read-only collection and conservative extraction of Cisco evidence."""
import base64
import hashlib
import ipaddress
import re
import socket
import time
import xml.etree.ElementTree as ET

import paramiko

COMMANDS = ('show version', 'show inventory', 'show privilege', 'show ip ssh',
            'show users', 'show ssh', 'show running-config')
# Keep SHA-1 key exchange/host signatures and CBC ciphers out of the default
# profile. The legacy profile uses Paramiko's available algorithms, including
# older SSHv2 algorithms; it never bypasses host-key verification.
MODERN_DISABLED = {
    'kex': ('diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1'),
    'keys': ('ssh-rsa', 'ssh-dss'),
    'pubkeys': ('ssh-rsa', 'ssh-dss'),
    'ciphers': ('aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc', 'blowfish-cbc'),
}
PALO_COMMANDS = ('show system info', 'show admins all', 'show config running')
PLATFORM_COMMANDS = {'cisco': COMMANDS, 'paloalto': PALO_COMMANDS}
MAX_OUTPUT = 2_000_000
CISCO_PROMPT = re.compile(r'^[A-Za-z0-9_.:@/-]{1,120}[#>]$')
# PAN-OS HA status is part of the prompt and may change during a session.
PALO_PROMPT = re.compile(r'^(?P<identity>[A-Za-z0-9_.-]{1,64}@[A-Za-z0-9_.:-]{1,120})(?:\([A-Za-z0-9_-]{1,48}\))?[#>]$')
ANSI_CSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
ANSI_OSC = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')


class SessionSyncError(ValueError):
    """The shell cannot safely accept another command in this session."""


def _terminal_text(raw):
    """Normalize terminal decoration for prompt matching and safe parsing."""
    text = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw
    text = ANSI_OSC.sub('', ANSI_CSI.sub('', text))
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    # Backspace-based prompt repainting is common on interactive SSH shells.
    while '\x08' in text:
        text = re.sub(r'[^\n]\x08', '', text).replace('\x08', '')
    return re.sub(r'[\x00-\x07\x0b-\x1f\x7f]', '', text)


def _last_prompt(output):
    lines = output.splitlines()
    return lines[-1].strip() if lines else ''


def _prompt_identity(prompt, platform):
    if platform == 'paloalto':
        match = PALO_PROMPT.fullmatch(prompt)
        return match.group('identity') if match else None
    return prompt if CISCO_PROMPT.fullmatch(prompt) else None


def _prompt_matches(candidate, expected, platform):
    identity = _prompt_identity(candidate, platform)
    if identity is None:
        return False
    if expected is None:
        return True
    # Only a PAN-OS HA state suffix may change. A new username, hostname, or
    # CLI mode is not a safe indication that the previous command completed.
    return candidate == expected if platform != 'paloalto' else (
        identity == _prompt_identity(expected, platform) and candidate.endswith('>') == expected.endswith('>'))


def _identity_commands(platform, raw, prompt):
    """Choose only literal documented show commands after identifying the OS."""
    if platform == 'paloalto':
        match = re.search(r'(?im)^\s*sw-version:\s*(\d+)\.(\d+)(?:[.\w-]*)\s*$', raw)
        if not match or not 7 <= int(match.group(1)) <= 12:
            raise ValueError('PAN-OS version could not be verified; no further commands were sent.')
        return PALO_COMMANDS[1:], []

    xe = re.search(r'(?im)^Cisco IOS[ -]XE Software\b[^\n]*\bVersion\s+(\d+)\.(\d+)(?:\((\d+)\))?', raw)
    ios = re.search(r'(?im)^Cisco IOS Software\b[^\n]*\bVersion\s+(\d+)\.(\d+)(?:\((\d+)\))?', raw)
    if not ios and not xe and re.search(r'(?im)^Cisco Internetwork Operating System Software\s*$', raw):
        ios = re.search(r'(?im)^IOS\s*\([^\n]*\bVersion\s+(\d+)\.(\d+)(?:\((\d+)\))?', raw)
    match = xe or ios
    if not match:
        raise ValueError('Cisco IOS or IOS XE version could not be verified; no further commands were sent.')
    commands = list(COMMANDS[1:])
    skipped = []
    if not xe and (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)) < (12, 1, 15):
        commands.remove('show ssh')
        skipped.append({'command': 'show ssh', 'message': 'This IOS release predates verified support for show ssh.'})
    if prompt.endswith('>'):
        for command in ('show ip ssh', 'show running-config'):
            commands.remove(command)
            skipped.append({'command': command, 'message': 'Privileged EXEC access is required for this show command.'})
    return tuple(commands), skipped


def _send_allowed_show_command(channel, platform, command):
    """Send only one literal, platform-specific show command to the device."""
    allowed = PLATFORM_COMMANDS.get(platform, ())
    if (command not in allowed or not isinstance(command, str)
            or not command.startswith('show ') or any(c in command for c in '\r\n;')):
        raise ValueError('Blocked non-allowlisted or non-read-only device command.')
    channel.sendall(command + '\n')

class UnknownHostKey(Exception):
    def __init__(self, key):
        self.key = key
        super().__init__('Host key is not trusted yet.')

class ChangedHostKey(Exception):
    pass


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def validate_target(row):
    raw_ip = row.get('ip', '').strip()
    # IPv6 scope IDs are not needed for routed targets and can include unsafe text.
    if '%' in raw_ip or any(ord(c) < 32 or ord(c) == 127 for c in raw_ip):
        raise ValueError('Invalid IP address.')
    ip = str(ipaddress.ip_address(raw_ip))
    port = int(row.get('port') or 22)
    if not 1 <= port <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    username = row.get('username', '').strip()
    password = row.get('password', '')
    if not username or not password or len(username) > 256 or len(password) > 1024:
        raise ValueError('Username and password are required.')
    return {'ip': ip, 'port': port, 'username': username, 'password': password}


def safe_text(value):
    value = str(value or '')
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    if value.lstrip().startswith(('=', '+', '-', '@')):
        value = "'" + value
    return value[:32000]


def _safe_aaa_fact(line):
    """Allow only known AAA method-list grammar; never copy arbitrary values."""
    if line.lower() == 'aaa new-model':
        return True
    # Method-list and server-group identifiers are configuration identifiers,
    # not server keys. An unknown method is discarded rather than guessed.
    match = re.fullmatch(
        r'aaa (authentication login|authorization exec|authorization commands \d{1,2}|accounting exec|accounting commands \d{1,2}) ([A-Za-z0-9_.-]{1,64}) (.+)',
        line, re.I)
    if not match:
        return False
    tokens = match.group(3).split()
    if not 1 <= len(tokens) <= 12:
        return False
    methods = {'local', 'local-case', 'enable', 'none', 'if-authenticated', 'radius',
               'tacacs+', 'line', 'start-stop', 'stop-only', 'wait-start', 'broadcast'}
    i = 0
    while i < len(tokens):
        token = tokens[i].lower()
        if token == 'group':
            i += 1
            if i >= len(tokens) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,64}', tokens[i]):
                return False
        elif token not in methods:
            return False
        i += 1
    return True


def _safe_acl_rule(line):
    """Retain only address/port ACL rules; discard remarks and object names."""
    tokens = line.lower().split()
    if tokens and tokens[0].isdigit() and int(tokens[0]) <= 65535:
        tokens.pop(0)
    if len(tokens) < 2 or tokens[0] not in ('permit', 'deny'):
        return False
    words = {'any', 'host', 'ip', 'ipv6', 'tcp', 'udp', 'icmp', 'icmp6',
             'gre', 'esp', 'ahp', 'ospf', 'eq', 'neq', 'lt', 'gt', 'range',
             'log', 'log-input', 'established', 'fragments', 'ssh', 'telnet',
             'www', 'https', 'domain', 'snmp', 'snmptrap', 'ntp'}
    for token in tokens[1:]:
        if token in words:
            continue
        if token.isdigit() and 0 <= int(token) <= 65535:
            continue
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError:
            return False
    return True


def extract_config(raw):
    """Strict allowlist of useful facts; never preserve arbitrary configuration lines."""
    facts, accounts = [], []
    context = ''
    for line in raw.splitlines():
        s = line.strip()
        if not line.startswith((' ', '\t')):
            if re.fullmatch(r'line (?:vty [0-9 ]+|con(?:sole)? \d+|aux \d+)', s, re.I):
                context = s
            elif re.fullmatch(r'(?:ip access-list (?:standard|extended)|ipv6 access-list) [A-Za-z0-9_.-]{1,64}', s, re.I):
                context = s
                facts.append(s)
            elif re.fullmatch(r'interface (?:Vlan|Loopback)\d{1,5}', s, re.I):
                context = s
            elif re.fullmatch(r'(?:radius|tacacs) server [A-Za-z0-9_.-]{1,64}', s, re.I):
                context = s
                facts.append(s)
            elif re.fullmatch(r'aaa group server (?:radius|tacacs\+) [A-Za-z0-9_.-]{1,64}', s, re.I):
                context = s
                facts.append(s)
            else:
                context = ''
        m = re.match(r'^username\s+(\S+)(?:\s+privilege\s+(\d+))?', s, re.I)
        if m:
            # Username is potentially attacker-controlled; limit its character set.
            name = m.group(1)
            if re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', name):
                accounts.append({'username': name, 'privilege': m.group(2) or 'unspecified'})
            continue
        if re.match(r'^enable secret(?:\s|$)', s, re.I):
            facts.append('enable secret configured [value hidden]')
            continue
        if re.match(r'^enable password(?:\s|$)', s, re.I):
            facts.append('enable password configured [value hidden]')
            continue
        # Preserve the VTY range on every fact: the method-list reference is
        # meaningful only together with the lines on which it is configured.
        name = r'[A-Za-z0-9_.-]{1,64}'
        vty_patterns = (
            r'transport input (?:ssh|telnet|none|all)(?: (?:ssh|telnet))?',
            rf'login (?:authentication {name}|local|local-case)',
            r'login',
            rf'(?:ipv6 )?access-class {name} (?:in|out)(?: vrf-also)?',
            rf'authorization (?:exec|commands \d{{1,2}}) {name}',
            rf'accounting (?:exec|commands \d{{1,2}}) {name}',
            r'exec-timeout \d{1,5}(?: \d{1,2})?',
            r'privilege level \d{1,2}',
            r'no exec',
        )
        if context.lower().startswith('line ') and any(re.fullmatch(pattern, s, re.I) for pattern in vty_patterns):
            facts.append(context + ' / ' + s)
        elif context.lower().startswith(('ip access-list ', 'ipv6 access-list ')) and _safe_acl_rule(s):
            facts.append(context + ' / ' + s)
        elif context.lower().startswith('interface ') and re.fullmatch(r'(?:ip vrf forwarding|vrf forwarding) [A-Za-z0-9_.-]{1,64}', s, re.I):
            facts.append(context + ' / ' + s)
        elif context.lower().startswith('interface ') and re.fullmatch(r'(?:ip address (?:\d{1,3}\.){3}\d{1,3} (?:\d{1,3}\.){3}\d{1,3}|ipv6 address [0-9a-fA-F:]+/\d{1,3})', s, re.I):
            parts = s.split()
            try:
                if parts[0].lower() == 'ip':
                    ipaddress.IPv4Network(parts[2] + '/' + parts[3], strict=False)
                else:
                    ipaddress.IPv6Interface(parts[2])
            except ValueError:
                pass
            else:
                facts.append(context + ' / ' + s)
        elif context.lower().startswith(('radius server ', 'tacacs server ')):
            address = re.fullmatch(r'address ipv4 ([0-9.]{7,15})(?: auth-port (\d{1,5}))?(?: acct-port (\d{1,5}))?', s, re.I)
            if address:
                try:
                    host = str(ipaddress.IPv4Address(address.group(1)))
                    ports = ''
                    for label, port in zip(('auth-port', 'acct-port'), address.groups()[1:]):
                        if port and 1 <= int(port) <= 65535:
                            ports += f' {label} {port}'
                    facts.append(context + ' address ipv4 ' + host + ports)
                except ValueError:
                    pass
        elif context.lower().startswith('aaa group server '):
            server = re.fullmatch(r'server name ([A-Za-z0-9_.-]{1,64})', s, re.I)
            if server:
                facts.append(context + ' / server name ' + server.group(1))
        elif _safe_aaa_fact(s):
            facts.append(s)
        elif re.fullmatch(r'ip ssh version [12]', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'login block-for \d{1,5} attempts \d{1,5} within \d{1,5}', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'login quiet-mode access-class [A-Za-z0-9_.-]{1,64}', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'login on-(?:failure|success) log', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'(?:no )?ip http (?:server|secure-server)', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'ip http authentication (?:aaa|local|enable|tacacs)', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'ip http access-class [A-Za-z0-9_.-]{1,64}', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'(?:no )?(?:netconf-yang|restconf)', s, re.I):
            facts.append(s)
        elif re.match(r'^snmp-server (?:community|user|group|host)(?:\s|$)', s, re.I):
            # Community strings, SNMPv3 credentials and host lines can carry
            # secrets. Only retain presence for the exact configuration class.
            facts.append('snmp-server ' + s.split()[1].lower() + ' configured [value hidden]')
        elif re.fullmatch(r'logging trap (?:emergencies|alerts|critical|errors|warnings|notifications|informational|debugging|[0-7])', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'(?:no )?logging on', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'logging (?:host )?(?:\d{1,3}\.){3}\d{1,3}', s, re.I):
            address = s.split()[-1]
            try:
                ipaddress.IPv4Address(address)
            except ValueError:
                pass
            else:
                facts.append('logging host ' + address)
        elif re.fullmatch(r'(?:no )?ntp authenticate', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'ntp server (?:\d{1,3}\.){3}\d{1,3}', s, re.I):
            address = s.split()[-1]
            try:
                ipaddress.IPv4Address(address)
            except ValueError:
                pass
            else:
                facts.append(s)
        elif re.match(r'^ntp trusted-key(?:\s|$)', s, re.I):
            facts.append('ntp trusted-key configured [key ID hidden]')
        elif re.fullmatch(r'service timestamps log (?:datetime|uptime)(?: msec| localtime| show-timezone| year)*', s, re.I):
            facts.append(s)
        elif re.fullmatch(r'access-list \d{1,3} (?:permit|deny) .+', s, re.I):
            number = s.split()[1]
            rule = ' '.join(s.split()[2:])
            if _safe_acl_rule(rule):
                facts.append('access-list ' + number + ' ' + rule)
    return facts, accounts


def sanitize_show(command, raw):
    # Other show outputs may also contain sensitive or attacker-controlled strings.
    # Keep only narrowly selected fields, never the full response.
    lines = []
    classic_ios = command == 'show version' and bool(re.search(r'(?im)^Cisco Internetwork Operating System Software\s*$', raw))
    for line in raw.splitlines():
        line = line.strip()
        if command == 'show version':
            match = re.search(r'(?i)^Cisco IOS(?:[ -]XE)? Software.*?Version\s+([A-Za-z0-9.()_-]+)', line)
            if match:
                lines.append('Cisco IOS version: ' + match.group(1))
            elif classic_ios:
                match = re.search(r'(?i)^IOS\s*\([^\n]*\bVersion\s+([A-Za-z0-9.()_-]+)', line)
                if match:
                    lines.append('Cisco IOS version: ' + match.group(1))
            match = re.fullmatch(r'([A-Za-z0-9_.:-]{1,120}) uptime is ([0-9A-Za-z, ]{1,100})', line)
            if match:
                lines.append(match.group(1) + ' uptime is ' + match.group(2))
            match = re.fullmatch(r'Processor board ID ([A-Za-z0-9_-]{1,64})', line, re.I)
            if match:
                lines.append('Processor board ID ' + match.group(1))
        elif command == 'show inventory':
            match = re.fullmatch(r'PID:\s*([\w./-]+)\s*,\s*VID:\s*([\w.-]*)\s*,\s*SN:\s*([\w.-]+)', line, re.I)
            if match:
                lines.append('PID: {}, VID: {}, SN: {}'.format(*match.groups()))
        elif command == 'show privilege':
            match = re.fullmatch(r'Current privilege level is (\d+)', line, re.I)
            if match:
                lines.append('Current privilege level is ' + match.group(1))
        elif command == 'show ip ssh':
            match = re.match(r'^SSH (Enabled|Disabled)(?: - version (\d+(?:\.\d+)?))?', line, re.I)
            if match:
                lines.append('SSH ' + match.group(1) + (' - version ' + match.group(2) if match.group(2) else ''))
    if command in ('show users', 'show ssh'):
        return '[Session output is not exported to reduce exposure; review it directly if needed.]'
    return '\n'.join(lines) or '[No approved fields could be extracted safely; review may be needed.]'



def sanitize_palo_info(raw):
    """Select only non-secret identity fields with constrained values."""
    lines = []
    for line in raw.splitlines():
        match = re.fullmatch(r'\s*(hostname|model|serial|sw-version):\s*([A-Za-z0-9_.:-]{1,128})\s*', line, re.I)
        if match:
            lines.append(match.group(1).lower() + ': ' + match.group(2))
    return '\n'.join(lines) or '[Device identity could not be extracted.]'


def extract_palo_admins(raw, prompt):
    """PAN show admins all emits names, not roles or effective entitlements."""
    names = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line == prompt or line in ('show admins all', prompt + ' show admins all'):
            continue
        if re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', line) and line.lower() not in ('administrator', 'administrators', 'username', 'name'):
            names.append(line)
        else:
            raise ValueError('The administrator list format is not recognized; no entries were extracted.')
    return list(dict.fromkeys(names))


def extract_palo_config(raw):
    """Extract limited admin information from XML; never persist raw config.

    Only complete XML is accepted. CLI output format may differ by PAN-OS or
    session settings. In that case callers must report unsupported data.
    """
    if re.search(r'<!\s*(?:DOCTYPE|ENTITY)', raw, re.I):
        raise ValueError('The XML configuration is unsafe or unrecognized.')
    start = re.search(r'<config(?:\s[^>]*)?>', raw)
    end = raw.rfind('</config>')
    if not start or end < start.start():
        raise ValueError('The PAN-OS configuration format is unrecognized or incomplete.')
    try:
        root = ET.fromstring(raw[start.start():end + len('</config>')])
    except (ET.ParseError, ValueError):
        raise ValueError('The PAN-OS configuration format is unrecognized or incomplete.') from None
    if root.tag != 'config':
        raise ValueError('The PAN-OS configuration format is unrecognized.')
    users = root.find('./mgt-config/users')
    if users is None:
        raise ValueError('The administrator section is not available in the configuration.')
    facts, accounts = [], []
    for entry in users.findall('./entry'):
        username = entry.get('name', '')
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', username):
            continue
        role = 'unknown'
        role_node = entry.find('./permissions/role-based')
        if role_node is not None:
            for node in role_node:
                if node.tag in ('superuser', 'superreader', 'deviceadmin', 'devicereader', 'vsysadmin', 'vsysreader') and ((node.text or '').strip().lower() == 'yes' or len(node) > 0):
                    role = node.tag
                    break
                if node.tag == 'custom':
                    profile = node.findtext('profile', default='').strip()
                    if re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', profile):
                        role = 'custom:' + profile
                        break
        accounts.append({'username': username, 'privilege': role, 'source': 'show config running'})
        if role != 'unknown':
            facts.append('admin ' + username + ' role ' + role)
        profile = entry.findtext('./authentication-profile', default='').strip()
        if re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', profile):
            facts.append('admin ' + username + ' authentication-profile ' + profile)
    complexity = root.find('./mgt-config/password-complexity')
    if complexity is not None:
        for node in complexity:
            value = (node.text or '').strip()
            if node.tag in ('enabled', 'minimum-length', 'minimum-uppercase-letters', 'minimum-lowercase-letters', 'minimum-numeric-letters', 'minimum-special-characters', 'minimum-different-characters', 'expiration-period', 'block-repeated-characters', 'password-history-count') and re.fullmatch(r'(?:yes|no|[0-9]{1,5})', value, re.I):
                facts.append('password-complexity ' + node.tag + ' ' + value)
    # Authentication-profile metadata is useful for tracing admin auth routes,
    # but it cannot prove that an external provider actually enforces MFA.
    auth_profiles = (root.findall('./shared/authentication-profile/entry') +
                     root.findall('./mgt-config/authentication-profile/entry'))
    if auth_profiles:
        methods = {'local', 'radius', 'ldap', 'tacplus', 'kerberos', 'saml', 'none'}
        for entry in auth_profiles:
            profile_name = entry.get('name', '')
            if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', profile_name):
                continue
            method_node = entry.find('./method')
            method = next((child.tag.lower() for child in list(method_node) if child.tag.lower() in methods), '') if method_node is not None else ''
            if method:
                facts.append('authentication-profile ' + profile_name + ' method ' + method)
            factors = entry.find('./factors')
            if factors is not None:
                enabled = factors.findtext('./enable', default='').strip().lower()
                if enabled in ('yes', 'no'):
                    facts.append('authentication-profile ' + profile_name + ' additional-factors-enabled ' + enabled)
                for factor in factors.findall('.//entry'):
                    factor_name = factor.get('name', '')
                    if re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', factor_name):
                        facts.append('authentication-profile ' + profile_name + ' additional-factor-profile ' + factor_name)
    # Role-profile names and fixed permission enums are useful audit evidence;
    # descriptions and other free-form fields are never copied.
    for entry in root.findall('./shared/admin-role/entry'):
        role_name = entry.get('name', '')
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', role_name):
            continue
        facts.append('admin-role ' + role_name + ' configured')
        device_role = entry.find('./role/device')
        if device_role is None:
            continue
        for area in ('cli', 'xmlapi', 'restapi'):
            node = device_role.find('./' + area)
            if node is None:
                continue
            value = (node.text or '').strip().lower()
            if value in ('yes', 'no', 'enable', 'disable', 'read-only', 'superuser', 'superreader', 'deviceadmin', 'devicereader'):
                facts.append('admin-role ' + role_name + ' ' + area + ' ' + value)
            for child in node:
                child_value = (child.text or '').strip().lower()
                if (re.fullmatch(r'[A-Za-z0-9_-]{1,64}', child.tag)
                        and child_value in ('yes', 'no', 'enable', 'disable', 'read-only')):
                    facts.append('admin-role ' + role_name + ' ' + area + ' ' + child.tag + ' ' + child_value)
        webui = device_role.find('./webui')
        if webui is not None:
            def add_webui_permissions(node, path):
                if len(path) > 6 or len(facts) >= 500:
                    return
                for child in node:
                    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', child.tag):
                        continue
                    child_path = path + [child.tag]
                    value = (child.text or '').strip().lower()
                    if value in ('enable', 'disable', 'read-only'):
                        facts.append('admin-role ' + role_name + ' webui ' + '/'.join(child_path) + ' ' + value)
                    add_webui_permissions(child, child_path)
            add_webui_permissions(webui, [])
    for device in root.findall('./devices/entry'):
        # Select only exact, non-secret management settings; absence remains unknown.
        system = device.find('./deviceconfig/system')
        if system is not None:
            for item in system.findall('./permitted-ip/entry'):
                value = item.get('name', '')
                try:
                    if '%' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
                        continue
                    ipaddress.ip_network(value, strict=False)
                except ValueError:
                    continue
                facts.append('management permitted-ip ' + value)
            for name in ('disable-ssh', 'disable-telnet', 'disable-http', 'disable-https', 'disable-snmp'):
                value = system.findtext('./service/' + name, default='').strip().lower()
                if value in ('yes', 'no'):
                    facts.append('management service ' + name + ' ' + value)
            timezone = system.findtext('./timezone', default='').strip()
            if re.fullmatch(r'[A-Za-z0-9_./+-]{1,64}', timezone):
                facts.append('system timezone ' + timezone)
            for server in ('primary', 'secondary'):
                address = system.findtext('./ntp-servers/' + server + '-ntp-server/ntp-server-address', default='').strip()
                if address and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', address):
                    facts.append('system ntp ' + server + ' ' + address)
        settings = device.find('./deviceconfig/setting/management')
        if settings is not None:
            value = settings.findtext('./idle-timeout', default='').strip()
            if re.fullmatch(r'\d{1,5}', value):
                facts.append('management idle-timeout ' + value)
            for name in ('failed-attempts', 'lockout-time'):
                value = settings.findtext('./admin-lockout/' + name, default='').strip()
                if re.fullmatch(r'\d{1,5}', value):
                    facts.append('management admin-lockout ' + name + ' ' + value)
        network = device.find('./network')
        if network is not None:
            for entry in network.findall('./profiles/interface-management-profile/entry'):
                profile = entry.get('name', '')
                if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', profile):
                    continue
                facts.append('interface-management-profile ' + profile + ' configured')
                for service in ('ssh', 'telnet', 'http', 'https', 'snmp', 'ping'):
                    value = entry.findtext('./' + service, default='').strip().lower()
                    if value in ('yes', 'no'):
                        facts.append('interface-management-profile ' + profile + ' ' + service + ' ' + value)
                for ip_entry in entry.findall('./permitted-ip/entry'):
                    address = ip_entry.get('name', '')
                    try:
                        if '%' in address or any(ord(c) < 32 or ord(c) == 127 for c in address):
                            continue
                        ipaddress.ip_network(address, strict=False)
                    except ValueError:
                        continue
                    facts.append('interface-management-profile ' + profile + ' permitted-ip ' + address)
            for family in ('ethernet', 'aggregate-ethernet', 'vlan', 'loopback', 'tunnel'):
                for interface in network.findall('./interface/' + family + '/entry'):
                    name = interface.get('name', '')
                    if not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,64}', name):
                        continue
                    for child in (interface, *interface.findall('./layer3/units/entry'), *interface.findall('./units/entry')):
                        child_name = child.get('name', name)
                        if not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,64}', child_name):
                            continue
                        profile = (child.findtext('./layer3/interface-management-profile', default='') or
                                   child.findtext('./interface-management-profile', default='')).strip()
                        if re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', profile):
                            facts.append('interface ' + child_name + ' management-profile ' + profile)
        for log_type in ('system', 'config'):
            for rule in device.findall('./log-settings/' + log_type + '/match-list/entry'):
                for member in rule.findall('./send-syslog/member'):
                    profile = (member.text or '').strip()
                    if re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', profile):
                        facts.append(log_type + ' log forwarding syslog-profile ' + profile)
    return facts, accounts

def _read_until_prompt(channel, timeout, cancelled, expected_prompt=None, platform='cisco', command=None):
    deadline = time.monotonic() + timeout
    data = bytearray()
    prompt_candidate_since = None
    unexpected_prompt = False
    while time.monotonic() < deadline:
        if cancelled():
            raise InterruptedError('Cancelled')
        if channel.recv_ready():
            chunk = channel.recv(65536)
            if not chunk:
                break
            data.extend(chunk)
            prompt_candidate_since = None
            unexpected_prompt = False
            if len(data) > MAX_OUTPUT:
                raise SessionSyncError('Output exceeded the size limit; collection stopped before sending another command.')
            raw_text = data.decode('utf-8', 'replace')
            # No terminal key or CLI setting is sent to advance a pager: only
            # the literal show-command allowlist may write to the SSH channel.
            if re.search(r'--\s*more\s*--', raw_text[-256:], re.I):
                raise SessionSyncError('Paginated output cannot be collected with show-only commands.')
            text = _terminal_text(raw_text)
            last = _last_prompt(text)
            if _prompt_matches(last, expected_prompt, platform):
                prompt_candidate_since = time.monotonic()
            elif expected_prompt is not None and _prompt_identity(last, platform) is not None:
                prompt_candidate_since = time.monotonic()
                unexpected_prompt = True
        elif prompt_candidate_since is not None and time.monotonic() - prompt_candidate_since >= .3:
            if unexpected_prompt:
                raise SessionSyncError('The device prompt changed unexpectedly; collection stopped before sending another command.')
            return _terminal_text(bytes(data))
        elif channel.closed:
            break
        time.sleep(.05)
    phase = ' after ' + command if command else ' after login'
    raise TimeoutError('The device prompt was not detected' + phase + ' before the timeout. Check output paging, command duration, and custom prompts.')


def collect(target, approved, cancelled, update, legacy=False, platform='cisco', on_event=None):
    if platform not in PLATFORM_COMMANDS or (legacy and platform != 'cisco'):
        raise ValueError('The platform or SSH profile is invalid.')
    result = {'platform': platform, 'ip': target['ip'], 'port': target['port'], 'status': 'failed', 'evidence': [], 'accounts': [], 'facts': [], 'issues': []}
    # Allowed fields can still coincidentally contain the login password, for
    # example as part of a hostname or administrator name. Remove that exact
    # value before any preview event or persistent result leaves the collector.
    password = target['password']
    def mask_password(value):
        return value.replace(password, '[•••]') if isinstance(value, str) and password else value

    def emit(event):
        # Only emit fixed command names, redacted evidence and safe error messages.
        # Live preview must never affect device collection if the UI disconnects.
        if on_event is not None:
            try:
                on_event(event)
            except Exception:
                pass
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    endpoint = target['ip'] if target['port'] == 22 else f"[{target['ip']}]:{target['port']}"
    # Load explicitly approved keys into this client's private in-memory store.
    for key in approved.get(endpoint, []):
        client.get_host_keys().add(endpoint, key.get_name(), key)
    class RejectUnknown(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            raise UnknownHostKey(key)
    client.set_missing_host_key_policy(RejectUnknown())
    try:
        emit({'type': 'activity', 'message': 'Opening SSH connection and verifying the host key.'})
        update('connecting')
        client.connect(target['ip'], port=target['port'], username=target['username'], password=target['password'], timeout=10, banner_timeout=10, auth_timeout=10, look_for_keys=False, allow_agent=False, disabled_algorithms={} if legacy else MODERN_DISABLED)
        emit({'type': 'activity', 'message': 'SSH connection authenticated; preparing the interactive read-only session.'})
        update('collecting')
        channel = client.invoke_shell(width=200, height=1000)
        # Bound write waits as well as reads; a disconnected peer must not hang a worker.
        channel.settimeout(10)
        greeting = _read_until_prompt(channel, 15, cancelled, None, platform)
        prompt = _last_prompt(greeting)
        if _prompt_identity(prompt, platform) is None or (platform == 'paloalto' and not prompt.endswith('>')):
            message = 'PAN-OS operational-mode prompt' if platform == 'paloalto' else 'Cisco EXEC prompt'
            raise SessionSyncError(message + ' could not be verified; no command was sent.')
        emit({'type': 'activity', 'message': 'Interactive session is ready. Starting the approved command sequence.'})
        # A device claims its platform in its first show response. Never infer
        # command support from the user's platform selector alone.
        commands = [PLATFORM_COMMANDS[platform][0]]
        for command in commands:
            if cancelled():
                raise InterruptedError('Cancelled')
            # Only literal constants above can enter the SSH channel.
            emit({'type': 'command_started', 'command': command})
            _send_allowed_show_command(channel, platform, command)
            try:
                output = _read_until_prompt(channel, 30, cancelled, prompt, platform, command)
                prompt = _last_prompt(output)
                if re.search(r'(?im)^\s*(?:%\s*)?(?:invalid syntax|unknown command|invalid command|permission denied|not authorized|invalid input|incomplete command|ambiguous command|authorization failed|access denied)', output):
                    raise ValueError('The command is unsupported or the account lacks permission.')
                if command == PLATFORM_COMMANDS[platform][0]:
                    extra, skipped = _identity_commands(platform, output, prompt)
                    commands.extend(extra)
                    for issue in skipped:
                        result['issues'].append(issue)
                        emit({'type': 'issue', 'issue': dict(issue)})
                if platform == 'paloalto' and command == 'show config running':
                    facts, accounts = extract_palo_config(output)
                    result['facts'] = facts
                    known = {x['username']: x for x in result['accounts']}
                    for account in accounts:
                        if account['username'] in known:
                            known[account['username']]['privilege'] = account['privilege']
                            known[account['username']]['role_source'] = 'show config running'
                        else:
                            result['accounts'].append(account)
                    evidence = '\n'.join(facts + ['admin ' + a['username'] + ' role ' + a['privilege'] for a in accounts if a['privilege'] == 'unknown']) or '[No administrator configuration fields could be extracted.]'
                elif platform == 'paloalto' and command == 'show admins all':
                    names = extract_palo_admins(output, prompt)
                    result['accounts'] = [{'username': name, 'privilege': 'unknown', 'source': command} for name in names]
                    evidence = '\n'.join('administrator ' + name for name in names) or '[No administrators could be extracted.]'
                elif platform == 'paloalto' and command == 'show system info':
                    evidence = sanitize_palo_info(output)
                elif command == 'show running-config':
                    facts, accounts = extract_config(output)
                    result['facts'], result['accounts'] = facts, accounts
                    evidence = '\n'.join(facts + [f"username {a['username']} privilege {a['privilege']} [secret hidden]" for a in accounts]) or '[No approved fields could be extracted safely.]'
                else:
                    evidence = sanitize_show(command, output)
                entry = {'command': command, 'text': mask_password(evidence), 'status': 'Filtered to approved fields only'}
                result['evidence'].append(entry)
                emit({'type': 'evidence', 'evidence': dict(entry)})
            except (TimeoutError, ValueError) as exc:
                issue = {'command': command, 'message': str(exc)}
                result['issues'].append(issue)
                emit({'type': 'issue', 'issue': dict(issue)})
                # Identity errors and shell-sync errors cannot be followed by
                # another command without risking an unknown CLI state.
                if command == PLATFORM_COMMANDS[platform][0] or isinstance(exc, (TimeoutError, SessionSyncError)):
                    break
        result['status'] = 'partial' if result['issues'] else 'completed'
    except UnknownHostKey as exc:
        result['status'] = 'host_key_unknown'
        result['host_key'] = {'type': exc.key.get_name(), 'fingerprint': fingerprint(exc.key), 'key': exc.key}
        issue = {'command': '', 'message': 'Host key is not trusted yet. Verify its fingerprint through a trusted channel.'}
        result['issues'].append(issue)
        emit({'type': 'issue', 'issue': dict(issue)})
    except paramiko.BadHostKeyException:
        issue = {'command': '', 'message': 'The host key changed; the connection was blocked.'}
        result['issues'].append(issue)
        emit({'type': 'issue', 'issue': dict(issue)})
    except paramiko.AuthenticationException:
        issue = {'command': '', 'message': 'Authentication failed.'}
        result['issues'].append(issue)
        emit({'type': 'issue', 'issue': dict(issue)})
    except InterruptedError:
        result['status'] = 'cancelled'
        issue = {'command': '', 'message': 'The scan was cancelled; evidence may be incomplete.'}
        result['issues'].append(issue)
        emit({'type': 'issue', 'issue': dict(issue)})
    except SessionSyncError as exc:
        issue = {'command': '', 'message': str(exc)}
        result['issues'].append(issue)
        emit({'type': 'issue', 'issue': dict(issue)})
    except (socket.error, paramiko.SSHException, TimeoutError, ValueError, EOFError):
        issue = {'command': '', 'message': 'The SSH connection or session failed. Check network access, SSH version, algorithms, and privileges. For trusted legacy devices, consider the legacy SSH compatibility option.'}
        result['issues'].append(issue)
        emit({'type': 'issue', 'issue': dict(issue)})
    finally:
        client.close()
    # Only these device-derived fields can contain arbitrary identifiers; the
    # command/source labels and host-key fingerprint are fixed metadata.
    result['facts'] = [mask_password(fact) for fact in result['facts']]
    for account in result['accounts']:
        for field in ('username', 'privilege'):
            if field in account:
                account[field] = mask_password(account[field])
    return result
