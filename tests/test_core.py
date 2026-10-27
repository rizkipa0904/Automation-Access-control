import sys
import types
import unittest
from unittest.mock import patch

# Extraction and validation can be tested without installing the SSH dependency.
try:
    import paramiko  # noqa: F401
except ImportError:
    sys.modules['paramiko'] = types.ModuleType('paramiko')

from cisco_audit.core import COMMANDS, _read_until_prompt, extract_config, safe_text, sanitize_show, validate_target

class SecurityTests(unittest.TestCase):
    def test_config_secrets_are_never_extracted(self):
        config = '''username admin privilege 15 secret 9 HASHSECRET
username ops password 7 HIDDEN
snmp-server community PRIVATESECRET RO
radius-server key VERYSECRET
aaa new-model
aaa authentication login default group radius local
line vty 0 4
 transport input ssh
 access-class MANAGEMENT in
'''
        facts, accounts = extract_config(config)
        output = repr((facts, accounts))
        for secret in ('HASHSECRET', 'HIDDEN', 'PRIVATESECRET', 'VERYSECRET'):
            self.assertNotIn(secret, output)
        self.assertIn('aaa new-model', facts)
        self.assertIn('line vty 0 4 / transport input ssh', facts)
        self.assertEqual(accounts[0], {'username': 'admin', 'privilege': '15'})

    def test_radius_and_tacacs_inventory_is_safe_and_secret_free(self):
        config = '''aaa new-model
aaa group server radius RAD-GROUP
 server name RAD-1
radius server RAD-1
 address ipv4 192.0.2.20 auth-port 1812 acct-port 1813
 key 7 DO_NOT_EXPORT
tacacs server TAC-1
 address ipv4 192.0.2.30
 key SECRET
'''
        facts, _ = extract_config(config)
        self.assertIn('aaa group server radius RAD-GROUP', facts)
        self.assertIn('aaa group server radius RAD-GROUP / server name RAD-1', facts)
        self.assertIn('radius server RAD-1 address ipv4 192.0.2.20 auth-port 1812 acct-port 1813', facts)
        self.assertIn('tacacs server TAC-1 address ipv4 192.0.2.30', facts)
        self.assertNotIn('DO_NOT_EXPORT', repr(facts))
        self.assertNotIn('SECRET', repr(facts))

    def test_vty_context_and_aaa_method_lists_are_retained_without_unrecognized_values(self):
        config = """
            aaa new-model
            aaa authentication login ADMIN group TACACS local
            aaa authorization exec ADMIN group TACACS local
            aaa accounting commands 15 ADMIN start-stop group TACACS
            aaa authentication login OTHER group RADIUS secretvalue
            line vty 0 4
             login authentication ADMIN
             authorization exec ADMIN
             accounting commands 15 ADMIN
             exec-timeout 10 30
             privilege level 15
             access-class MANAGEMENT in
             ipv6 access-class MGMT6 in
             transport input ssh
            line vty 5 15
             login local
             transport input telnet ssh
            """
        # Remove test indentation while preserving Cisco child-line indentation.
        import textwrap
        facts, _ = extract_config(textwrap.dedent(config))
        self.assertIn('aaa authentication login ADMIN group TACACS local', facts)
        self.assertIn('aaa accounting commands 15 ADMIN start-stop group TACACS', facts)
        self.assertIn('line vty 0 4 / authorization exec ADMIN', facts)
        self.assertIn('line vty 0 4 / accounting commands 15 ADMIN', facts)
        self.assertIn('line vty 0 4 / exec-timeout 10 30', facts)
        self.assertIn('line vty 0 4 / ipv6 access-class MGMT6 in', facts)
        self.assertIn('line vty 5 15 / login local', facts)
        self.assertNotIn('secretvalue', repr(facts))

    def test_formula_injection_and_controls(self):
        for value in ('=1+1', '  +cmd', '-1', '@SUM(A1)', '\x00=1'):
            self.assertTrue(safe_text(value).startswith("'"))
        self.assertNotIn('\x00', safe_text('x\x00y'))

    def test_input_validation(self):
        self.assertEqual(validate_target({'ip': '2001:db8::1', 'port': '', 'username': 'u', 'password': 'p'})['port'], 22)
        for target in ({'ip': 'not-ip', 'username': 'u', 'password': 'p'}, {'ip': 'fe80::1%eth0', 'username': 'u', 'password': 'p'}, {'ip': '192.0.2.1', 'port': 65536, 'username': 'u', 'password': 'p'}, {'ip': '192.0.2.1', 'username': 'u', 'password': ''}):
            with self.assertRaises(ValueError): validate_target(target)

    def test_prompt_must_match_session_prompt(self):
        class Channel:
            closed = False
            def __init__(self): self.parts = [b'other#\n', b'switch#']
            def recv_ready(self): return bool(self.parts)
            def recv(self, _): return self.parts.pop(0)
        text = _read_until_prompt(Channel(), 1, lambda: False, 'switch#')
        self.assertIn('other#', text)
        self.assertTrue(text.endswith('switch#'))

    def test_collection_sends_only_allowlisted_commands(self):
        from cisco_audit import core
        class Channel:
            def __init__(self): self.sent = []; self.closed = False
            def settimeout(self, value): pass
            def sendall(self, text): self.sent.append(text)
        class Client:
            def __init__(self): self.channel = Channel(); self.options = {}
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, *args, **kwargs): self.options = kwargs
            def invoke_shell(self, **kwargs): return self.channel
            def close(self): pass
        client = Client()
        class FakeParamiko:
            SSHClient = staticmethod(lambda: client)
            MissingHostKeyPolicy = type('MissingHostKeyPolicy', (), {})
            BadHostKeyException = type('BadHostKeyException', (Exception,), {})
            AuthenticationException = type('AuthenticationException', (Exception,), {})
            SSHException = type('SSHException', (Exception,), {})
        responses = iter(['switch#'] + ['Cisco IOS XE Software, Version 17.9.4\nswitch#' if command == 'show version' else 'username admin privilege 15 secret 9 secretvalue\nswitch#' if command == 'show running-config' else 'switch#' for command in COMMANDS])
        events = []
        with patch.object(core, 'paramiko', FakeParamiko), patch.object(core, '_read_until_prompt', side_effect=lambda *args: next(responses)):
            result = core.collect({'ip': '192.0.2.1', 'port': 22, 'username': 'u', 'password': 'test-ssh-password'}, {}, lambda: False, lambda _: None, on_event=events.append)
        self.assertEqual([e['command'] for e in events if e['type'] == 'command_started'], list(COMMANDS))
        self.assertEqual([e['evidence'] for e in events if e['type'] == 'evidence'], result['evidence'])
        self.assertNotIn('secretvalue', repr(events))
        self.assertEqual(client.channel.sent, [x + '\n' for x in COMMANDS])
        self.assertEqual(client.options['disabled_algorithms'], core.MODERN_DISABLED)
        self.assertEqual(result['status'], 'completed')
        self.assertNotIn('secretvalue', repr(result))
        client.channel.sent.clear()
        responses = iter(['switch#', 'Cisco IOS XE Software, Version 17.9.4\nswitch#'] + ['switch#'] * (len(COMMANDS) - 1))
        with patch.object(core, 'paramiko', FakeParamiko), patch.object(core, '_read_until_prompt', side_effect=lambda *args: next(responses)):
            core.collect({'ip': '192.0.2.1', 'port': 22, 'username': 'u', 'password': 'test-ssh-password'}, {}, lambda: False, lambda _: None, legacy=True)
        self.assertEqual(client.options['disabled_algorithms'], {})
        self.assertEqual(client.channel.sent, [x + '\n' for x in COMMANDS])

    def test_login_password_redacted_from_live_events_and_results(self):
        from cisco_audit import core
        class Channel:
            def settimeout(self, value): pass
            def sendall(self, value): pass
        class Client:
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, *args, **kwargs): pass
            def invoke_shell(self, **kwargs): return Channel()
            def close(self): pass
        class FakeParamiko:
            SSHClient = staticmethod(Client)
            MissingHostKeyPolicy = type('MissingHostKeyPolicy', (), {})
            BadHostKeyException = type('BadHostKeyException', (Exception,), {})
            AuthenticationException = type('AuthenticationException', (Exception,), {})
            SSHException = type('SSHException', (Exception,), {})
        secret = 'TEST_CREDENTIAL_319'
        outputs = ['switch#'] + ['Cisco IOS XE Software, Version 17.9.4\nswitch#' if c == 'show version' else ('username user' + secret + ' privilege 15 secret 9 otherhash\nswitch#') if c == 'show running-config' else 'switch#' for c in core.COMMANDS]
        events = []
        with patch.object(core, 'paramiko', FakeParamiko), patch.object(core, '_read_until_prompt', side_effect=outputs):
            result = core.collect({'ip':'192.0.2.1', 'port':22, 'username':'u', 'password':secret}, {}, lambda:False, lambda _:None, on_event=events.append)
        self.assertNotIn(secret, repr(events))
        self.assertNotIn(secret, repr(result))
        self.assertIn('[•••]', repr(events))
        self.assertIn('[•••]', repr(result['accounts']))

    def test_failed_command_write_stops_collection(self):
        from cisco_audit import core
        class Channel:
            def __init__(self): self.sent = []
            def settimeout(self, value): self.timeout = value
            def sendall(self, value):
                self.sent.append(value)
                raise TimeoutError('write timeout')
        class Client:
            def __init__(self): self.channel = Channel()
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, *args, **kwargs): pass
            def invoke_shell(self, **kwargs): return self.channel
            def close(self): pass
        client = Client()
        class FakeParamiko:
            SSHClient = staticmethod(lambda: client)
            MissingHostKeyPolicy = type('MissingHostKeyPolicy', (), {})
            BadHostKeyException = type('BadHostKeyException', (Exception,), {})
            AuthenticationException = type('AuthenticationException', (Exception,), {})
            SSHException = type('SSHException', (Exception,), {})
        with patch.object(core, 'paramiko', FakeParamiko), patch.object(core, '_read_until_prompt', return_value='switch#'):
            result = core.collect({'ip':'192.0.2.1', 'port':22, 'username':'u', 'password':'test-ssh-password'}, {}, lambda: False, lambda _: None)
        self.assertEqual(client.channel.timeout, 10)
        self.assertEqual(client.channel.sent, [core.COMMANDS[0] + '\n'])
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('write timeout', repr(result))

    def test_only_fixed_show_commands(self):
        self.assertTrue(all(x.startswith('show ') and '\n' not in x for x in COMMANDS))
        self.assertNotIn('secret', sanitize_show('show users', 'secret'))
        self.assertNotIn('secret', sanitize_show('show ip ssh', 'unrecognized secret'))

    def test_command_sender_rejects_everything_except_literal_show_allowlist(self):
        from cisco_audit.core import PLATFORM_COMMANDS, _send_allowed_show_command
        class Channel:
            def __init__(self): self.sent=[]
            def sendall(self, data): self.sent.append(data)
        channel=Channel()
        for platform, commands in PLATFORM_COMMANDS.items():
            for command in commands:
                self.assertTrue(command.startswith('show '))
                _send_allowed_show_command(channel, platform, command)
        for platform in PLATFORM_COMMANDS:
            for command in ('configure terminal','clear counters','set system setting','show version\nconfigure terminal','show version; clear counters','request restart system'):
                with self.assertRaises(ValueError):
                    _send_allowed_show_command(channel, platform, command)
        self.assertEqual(len(channel.sent), sum(map(len, PLATFORM_COMMANDS.values())))
        self.assertTrue(all(data.startswith('show ') and data.endswith('\n') for data in channel.sent))

if __name__ == '__main__':
    unittest.main()

class PaloTests(unittest.TestCase):
    def test_palo_commands_are_read_only_and_distinct(self):
        from cisco_audit.core import PALO_COMMANDS, PLATFORM_COMMANDS
        self.assertEqual(PALO_COMMANDS, ('show system info', 'show admins all', 'show config running'))
        self.assertEqual(PLATFORM_COMMANDS['paloalto'], PALO_COMMANDS)
        self.assertTrue(all(command.startswith('show ') and '\n' not in command for command in PALO_COMMANDS))

    def test_admin_names_and_config_roles_extract_without_secrets(self):
        from cisco_audit.core import extract_palo_admins, extract_palo_config
        names = extract_palo_admins('admin@fw> show admins all\nadmin\nremote-admin\nadmin@fw>\n', 'admin@fw>')
        self.assertEqual(names, ['admin', 'remote-admin'])
        xml = '''admin@fw> show config running
<config><mgt-config><users>
<entry name="admin"><phash>secret-hash</phash><public-key>secret-key</public-key><permissions><role-based><superuser>yes</superuser></role-based></permissions><authentication-profile>corp</authentication-profile></entry>
<entry name="reader"><password>secret-pass</password><permissions><role-based><custom><profile>readonly</profile></custom></role-based></permissions></entry>
</users><password-complexity><enabled>yes</enabled><minimum-length>12</minimum-length></password-complexity></mgt-config></config>
admin@fw>'''
        facts, accounts = extract_palo_config(xml)
        self.assertIn('admin admin role superuser', facts)
        self.assertIn('admin admin authentication-profile corp', facts)
        self.assertIn('password-complexity minimum-length 12', facts)
        self.assertEqual(accounts[1]['privilege'], 'custom:readonly')
        for secret in ('secret-hash', 'secret-key', 'secret-pass'):
            self.assertNotIn(secret, repr((facts, accounts)))

    def test_admin_authentication_profiles_and_factor_references_are_extracted_safely(self):
        from cisco_audit.core import extract_palo_config
        xml = '''<config><mgt-config><users>
        <entry name="audit-admin"><authentication-profile>corp-radius</authentication-profile><permissions><role-based><superreader>yes</superreader></role-based></permissions></entry>
        </users><authentication-profile><entry name="corp-radius"><method><radius><server-profile>corp-radius-server</server-profile></radius></method><factors><enable>yes</enable><factor><entry name="duo-mfa"/></factor></factors></entry></authentication-profile></mgt-config></config>'''
        facts, accounts = extract_palo_config(xml)
        self.assertIn('admin audit-admin authentication-profile corp-radius', facts)
        self.assertIn('authentication-profile corp-radius method radius', facts)
        self.assertIn('authentication-profile corp-radius additional-factors-enabled yes', facts)
        self.assertIn('authentication-profile corp-radius additional-factor-profile duo-mfa', facts)
        self.assertNotIn('corp-radius-server', repr(facts))
        self.assertEqual(accounts[0]['privilege'], 'superreader')

    def test_palo_management_settings_are_allowlisted(self):
        from cisco_audit.core import extract_palo_config
        xml = """<config><mgt-config><users/></mgt-config><devices><entry name="localhost.localdomain"><deviceconfig><system>
        <permitted-ip><entry name="192.0.2.0/24"/><entry name="bad secret"/><entry name="fe80::1%hidden-secret/64"/></permitted-ip>
        <service><disable-ssh>no</disable-ssh><password>DO_NOT_COPY</password></service>
        </system><setting><management><idle-timeout>30</idle-timeout><admin-lockout><failed-attempts>5</failed-attempts><lockout-time>15</lockout-time></admin-lockout></management></setting></deviceconfig></entry></devices></config>"""
        facts, _ = extract_palo_config(xml)
        for expected in ('management permitted-ip 192.0.2.0/24', 'management service disable-ssh no', 'management idle-timeout 30', 'management admin-lockout failed-attempts 5'):
            self.assertIn(expected, facts)
        self.assertNotIn('DO_NOT_COPY', repr(facts))
        self.assertNotIn('bad secret', repr(facts))
        self.assertNotIn('hidden-secret', repr(facts))

    def test_incomplete_xml_and_entity_declarations_are_rejected(self):
        from cisco_audit.core import extract_palo_config
        for raw in ('<config><mgt-config>', '<!DOCTYPE config [<!ENTITY x "secret">]><config><mgt-config><users/></mgt-config></config>', '<config><mgt-config/></config>'):
            with self.assertRaises(ValueError):
                extract_palo_config(raw)

    def test_palo_collection_uses_only_read_commands_and_attributes_evidence(self):
        from cisco_audit import core
        class Channel:
            closed = False
            def __init__(self): self.sent = []
            def settimeout(self, value): pass
            def sendall(self, text): self.sent.append(text)
        class Client:
            def __init__(self): self.channel = Channel()
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, *args, **kwargs): pass
            def invoke_shell(self, **kwargs): return self.channel
            def close(self): pass
        client = Client()
        class FakeParamiko:
            SSHClient = staticmethod(lambda: client)
            MissingHostKeyPolicy = type('MissingHostKeyPolicy', (), {})
            BadHostKeyException = type('BadHostKeyException', (Exception,), {})
            AuthenticationException = type('AuthenticationException', (Exception,), {})
            SSHException = type('SSHException', (Exception,), {})
        responses = iter(['admin@fw>', 'hostname: fw\nmodel: PA-VM\nsw-version: 11.1\nadmin@fw>', 'admin@fw> show admins all\nadmin\nadmin@fw>', '<config><mgt-config><users><entry name="admin"><phash>secret-hash</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry></users></mgt-config></config>\nadmin@fw>'])
        events = []
        with patch.object(core, 'paramiko', FakeParamiko), patch.object(core, '_read_until_prompt', side_effect=lambda *args: next(responses)):
            result = core.collect({'ip': '192.0.2.1', 'port': 22, 'username': 'u', 'password': 'test-ssh-password'}, {}, lambda: False, lambda _: None, platform='paloalto', on_event=events.append)
        self.assertEqual([event['command'] for event in events if event['type'] == 'command_started'], list(core.PALO_COMMANDS))
        self.assertNotIn('secret-hash', repr(events))
        self.assertEqual(client.channel.sent, [x + '\n' for x in core.PALO_COMMANDS])
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['accounts'][0]['source'], 'show admins all')
        self.assertEqual(result['accounts'][0]['role_source'], 'show config running')
        self.assertEqual(result['accounts'][0]['privilege'], 'superuser')
        self.assertNotIn('secret-hash', repr(result))

    def test_preview_emits_safe_parser_issue_without_raw_output(self):
        from cisco_audit import core
        class Channel:
            def settimeout(self, value): pass
            def sendall(self, text): pass
        class Client:
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, *args, **kwargs): pass
            def invoke_shell(self, **kwargs): return Channel()
            def close(self): pass
        class FakeParamiko:
            SSHClient = staticmethod(Client)
            MissingHostKeyPolicy = type('MissingHostKeyPolicy', (), {})
            BadHostKeyException = type('BadHostKeyException', (Exception,), {})
            AuthenticationException = type('AuthenticationException', (Exception,), {})
            SSHException = type('SSHException', (Exception,), {})
        responses = iter(['admin@fw>', 'hostname: fw\nsw-version: 11.1.3\nadmin@fw>', 'admin\nadmin@fw>', '<config><secret>PRIVATE-HASH</secret>'])
        events = []
        with patch.object(core, 'paramiko', FakeParamiko), patch.object(core, '_read_until_prompt', side_effect=lambda *args: next(responses)):
            result = core.collect({'ip': '192.0.2.1', 'port': 22, 'username': 'u', 'password': 'test-ssh-password'}, {}, lambda: False, lambda _: None, platform='paloalto', on_event=events.append)
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(any(e['type'] == 'issue' and e['issue']['command'] == 'show config running' for e in events))
        self.assertNotIn('PRIVATE-HASH', repr(events))

    def test_palo_non_operational_prompt_never_sends_commands(self):
        from cisco_audit import core
        class Client:
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, *args, **kwargs): pass
            def invoke_shell(self, **kwargs): return types.SimpleNamespace(settimeout=lambda _: None)
            def close(self): pass
        class FakeParamiko:
            SSHClient = staticmethod(Client)
            MissingHostKeyPolicy = type('MissingHostKeyPolicy', (), {})
            BadHostKeyException = type('BadHostKeyException', (Exception,), {})
            AuthenticationException = type('AuthenticationException', (Exception,), {})
            SSHException = type('SSHException', (Exception,), {})
        with patch.object(core, 'paramiko', FakeParamiko), patch.object(core, '_read_until_prompt', return_value='admin@fw#'):
            result = core.collect({'ip': '192.0.2.1', 'port': 22, 'username': 'u', 'password': 'test-ssh-password'}, {}, lambda: False, lambda _: None, platform='paloalto')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['evidence'], [])


class SessionCompatibilityTests(unittest.TestCase):
    def test_pan_ha_prompt_and_terminal_decoration_are_recognized(self):
        class Channel:
            closed = False
            def __init__(self, data): self.parts = [data]
            def recv_ready(self): return bool(self.parts)
            def recv(self, _): return self.parts.pop(0)
        greeting = _read_until_prompt(Channel(b'\x1b[32madmin@fw(active-primary)>\x1b[0m'), 1, lambda: False, platform='paloalto')
        self.assertEqual(greeting, 'admin@fw(active-primary)>')
        response = _read_until_prompt(Channel(b'sw-version: 11.1.3\r\nadmin@fw(passive-secondary)>'), 1, lambda: False,
                                      'admin@fw(active-primary)>', 'paloalto', 'show system info')
        self.assertTrue(response.endswith('admin@fw(passive-secondary)>'))

    def test_cisco_show_users_completes_with_ansi_colored_prompt(self):
        class Channel:
            closed = False
            def __init__(self): self.parts = [b'show users\r\nLine User Host(s)\r\n\x1b[36mswitch#\x1b[0m']
            def recv_ready(self): return bool(self.parts)
            def recv(self, _): return self.parts.pop(0)
        output = _read_until_prompt(Channel(), 1, lambda: False, 'switch#', 'cisco', 'show users')
        self.assertTrue(output.endswith('switch#'))
        self.assertNotIn('\x1b', output)

    def test_pagination_never_sends_a_key_or_another_command(self):
        from cisco_audit import core
        class Channel:
            closed = False
            def __init__(self): self.parts = [b'show users\r\n--More--']; self.sent = []
            def recv_ready(self): return bool(self.parts)
            def recv(self, _): return self.parts.pop(0)
            def sendall(self, data): self.sent.append(data)
        channel = Channel()
        with self.assertRaisesRegex(core.SessionSyncError, 'Paginated output'):
            _read_until_prompt(channel, 1, lambda: False, 'switch#', 'cisco', 'show users')
        self.assertEqual(channel.sent, [])

    def test_unknown_prompt_is_reported_before_any_next_command(self):
        from cisco_audit import core
        class Channel:
            closed = False
            def __init__(self): self.parts = [b'other-switch#']
            def recv_ready(self): return bool(self.parts)
            def recv(self, _): return self.parts.pop(0)
        with self.assertRaisesRegex(core.SessionSyncError, 'changed unexpectedly'):
            _read_until_prompt(Channel(), 1, lambda: False, 'switch#', 'cisco', 'show users')

    def test_show_users_timeout_names_the_command_without_raw_output(self):
        class Channel:
            closed = False
            def __init__(self): self.parts = [b'show users\nPRIVATE-OUTPUT']
            def recv_ready(self): return bool(self.parts)
            def recv(self, _): return self.parts.pop(0)
        with self.assertRaises(TimeoutError) as failure:
            _read_until_prompt(Channel(), .15, lambda: False, 'switch#', 'cisco', 'show users')
        self.assertIn('after show users', str(failure.exception))
        self.assertNotIn('PRIVATE-OUTPUT', str(failure.exception))

    def test_version_and_privilege_select_only_verified_show_commands(self):
        from cisco_audit.core import _identity_commands
        modern, issues = _identity_commands('cisco', 'Cisco IOS XE Software, Version 17.9.4\nswitch#', 'switch#')
        self.assertEqual(modern, COMMANDS[1:])
        self.assertEqual(issues, [])
        old, issues = _identity_commands('cisco', 'Cisco IOS Software, Version 12.1(5)T\nswitch>', 'switch>')
        self.assertNotIn('show ssh', old)
        self.assertNotIn('show ip ssh', old)
        self.assertNotIn('show running-config', old)
        self.assertEqual({issue['command'] for issue in issues}, {'show ssh', 'show ip ssh', 'show running-config'})
        classic = 'Cisco Internetwork Operating System Software\nIOS (tm) C6400 Software (C6400-M), Version 12.2(2)B2\nswitch#'
        self.assertIn('show ssh', _identity_commands('cisco', classic, 'switch#')[0])
        self.assertIn('Cisco IOS version: 12.2(2)B2', sanitize_show('show version', classic))
        with self.assertRaisesRegex(ValueError, 'could not be verified'):
            _identity_commands('cisco', 'Cisco NX-OS Software, Version 9.3(8)', 'switch#')
        self.assertEqual(_identity_commands('paloalto', 'sw-version: 11.1.3', 'admin@fw>')[0], ('show admins all', 'show config running'))
        with self.assertRaisesRegex(ValueError, 'could not be verified'):
            _identity_commands('paloalto', 'sw-version: 13.0.0', 'admin@fw>')

    def test_unsupported_cisco_family_stops_after_first_show(self):
        from cisco_audit import core
        class Channel:
            closed = False
            def __init__(self): self.sent = []; self.parts = [b'switch#']
            def settimeout(self, value): pass
            def recv_ready(self): return bool(self.parts)
            def recv(self, _): return self.parts.pop(0)
            def sendall(self, value):
                self.sent.append(value)
                self.parts = [b'Cisco NX-OS Software, Version 9.3(8)\nswitch#']
        class Client:
            def __init__(self): self.channel = Channel()
            def load_system_host_keys(self): pass
            def set_missing_host_key_policy(self, policy): pass
            def connect(self, *args, **kwargs): pass
            def invoke_shell(self, **kwargs): return self.channel
            def close(self): pass
        client = Client()
        class FakeParamiko:
            SSHClient = staticmethod(lambda: client)
            MissingHostKeyPolicy = type('MissingHostKeyPolicy', (), {})
            BadHostKeyException = type('BadHostKeyException', (Exception,), {})
            AuthenticationException = type('AuthenticationException', (Exception,), {})
            SSHException = type('SSHException', (Exception,), {})
        with patch.object(core, 'paramiko', FakeParamiko):
            result = core.collect({'ip': '192.0.2.1', 'port': 22, 'username': 'u', 'password': 'p'}, {}, lambda: False, lambda _: None)
        self.assertEqual(client.channel.sent, ['show version\n'])
        self.assertEqual(result['status'], 'partial')
        self.assertIn('could not be verified', result['issues'][0]['message'])


class ChecklistEvidenceTests(unittest.TestCase):
    def test_cisco_access_management_and_logging_are_filtered(self):
        config = '''enable secret 9 ENABLE_HASH_DO_NOT_EXPORT
enable password 7 ENCRYPTED_DO_NOT_EXPORT
line con 0
 login authentication CONSOLE
 exec-timeout 5 0
line aux 0
 transport input none
login block-for 120 attempts 3 within 60
login on-failure log
ip access-list standard MGMT
 permit 192.0.2.0 0.0.0.255
 remark SECRET_REMARK_DO_NOT_EXPORT
 permit object-group SECRET_OBJECT_DO_NOT_EXPORT
ip http server
no ip http secure-server
ip http authentication aaa
snmp-server community COMMUNITY_DO_NOT_EXPORT RO
snmp-server user monitor USERS_SECRET_DO_NOT_EXPORT auth sha SECRET
logging host 192.0.2.20
logging trap warnings
ntp server 192.0.2.30
ntp authentication-key 1 md5 NTP_SECRET_DO_NOT_EXPORT
ntp authenticate
netconf-yang
restconf
'''
        facts, _ = extract_config(config)
        for value in ('ENABLE_HASH_DO_NOT_EXPORT', 'ENCRYPTED_DO_NOT_EXPORT',
                      'SECRET_REMARK_DO_NOT_EXPORT', 'SECRET_OBJECT_DO_NOT_EXPORT',
                      'COMMUNITY_DO_NOT_EXPORT', 'USERS_SECRET_DO_NOT_EXPORT',
                      'NTP_SECRET_DO_NOT_EXPORT'):
            self.assertNotIn(value, repr(facts))
        for value in ('enable secret configured [value hidden]',
                      'line con 0 / login authentication CONSOLE',
                      'line con 0 / exec-timeout 5 0',
                      'ip access-list standard MGMT / permit 192.0.2.0 0.0.0.255',
                      'login block-for 120 attempts 3 within 60',
                      'ip http authentication aaa',
                      'snmp-server community configured [value hidden]',
                      'logging host 192.0.2.20', 'ntp server 192.0.2.30',
                      'netconf-yang', 'restconf'):
            self.assertIn(value, facts)

    def test_palo_shared_auth_profiles_roles_interfaces_and_logs_are_filtered(self):
        from cisco_audit.core import extract_palo_config
        xml = '''<config><mgt-config><users><entry name="admin"><permissions><role-based><custom><profile>auditor</profile></custom></role-based></permissions><authentication-profile>corp-radius</authentication-profile><phash>HASH_DO_NOT_EXPORT</phash></entry></users></mgt-config>
<shared><authentication-profile><entry name="corp-radius"><method><radius><server-profile>RADIUS_SECRET_DO_NOT_EXPORT</server-profile></radius></method><factors><enable>yes</enable></factors></entry></authentication-profile>
<admin-role><entry name="auditor"><role><device><cli>superreader</cli><xmlapi><enabled>yes</enabled></xmlapi><webui><monitor><logs>read-only</logs></monitor></webui></device></role><description>ROLE_SECRET_DO_NOT_EXPORT</description></entry></admin-role></shared>
<devices><entry name="localhost.localdomain"><deviceconfig><system><timezone>UTC</timezone><ntp-servers><primary-ntp-server><ntp-server-address>192.0.2.123</ntp-server-address><authentication-key>NTP_KEY_DO_NOT_EXPORT</authentication-key></primary-ntp-server></ntp-servers></system></deviceconfig>
<network><profiles><interface-management-profile><entry name="MGMT"><ssh>yes</ssh><telnet>no</telnet><permitted-ip><entry name="2001:db8::/32"/><entry name="BAD_SECRET_DO_NOT_EXPORT"/></permitted-ip><password>PROFILE_SECRET_DO_NOT_EXPORT</password></entry></interface-management-profile></profiles>
<interface><ethernet><entry name="ethernet1/1"><layer3><interface-management-profile>MGMT</interface-management-profile></layer3></entry></ethernet></interface></network>
<log-settings><system><match-list><entry name="logs"><send-syslog><member>syslog-main</member></send-syslog><secret>LOG_SECRET_DO_NOT_EXPORT</secret></entry></match-list></system></log-settings>
</entry></devices></config>'''
        facts, accounts = extract_palo_config(xml)
        self.assertEqual(accounts[0]['privilege'], 'custom:auditor')
        for value in ('HASH_DO_NOT_EXPORT', 'RADIUS_SECRET_DO_NOT_EXPORT',
                      'ROLE_SECRET_DO_NOT_EXPORT', 'NTP_KEY_DO_NOT_EXPORT',
                      'BAD_SECRET_DO_NOT_EXPORT', 'PROFILE_SECRET_DO_NOT_EXPORT',
                      'LOG_SECRET_DO_NOT_EXPORT'):
            self.assertNotIn(value, repr((facts, accounts)))
        for value in ('authentication-profile corp-radius method radius',
                      'authentication-profile corp-radius additional-factors-enabled yes',
                      'admin-role auditor configured', 'admin-role auditor cli superreader',
                      'interface-management-profile MGMT ssh yes',
                      'interface-management-profile MGMT permitted-ip 2001:db8::/32',
                      'interface ethernet1/1 management-profile MGMT',
                      'system timezone UTC', 'system ntp primary 192.0.2.123',
                      'system log forwarding syslog-profile syslog-main'):
            self.assertIn(value, facts)
