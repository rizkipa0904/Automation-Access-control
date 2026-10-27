"""Focused workbook checks; no test opens an SSH connection."""
import importlib.util
import sys
import types
import unittest
from io import BytesIO

HAS_DEPS = importlib.util.find_spec('openpyxl') is not None
try:
    import paramiko  # noqa: F401
except ImportError:
    sys.modules['paramiko'] = types.ModuleType('paramiko')


@unittest.skipUnless(HAS_DEPS, 'openpyxl is not installed')
class WorkbookTests(unittest.TestCase):
    def load(self, platform, *results, **extra):
        from openpyxl import load_workbook
        from cisco_audit.report import workbook
        run = {'id': 'scan-1', 'project_name': 'Example', 'platform': platform,
               'started': '2026-01-01T00:00:00+00:00', 'results': list(results), **extra}
        book = load_workbook(BytesIO(workbook(run)))
        self.assertEqual(book.sheetnames, ['Audit Results'])
        return book.active

    @staticmethod
    def section(ws, name):
        return [row for row in ws.values if row[1] == name]

    @staticmethod
    def check(ws, name):
        return next(row for row in ws.values if row[1] == 'Check' and row[2] == name)

    def test_single_sheet_groups_results_by_ip_and_formats_for_reading(self):
        first = {'ip': '172.0.0.2', 'port': 22, 'status': 'completed',
                 'evidence': [{'command': 'show version', 'text': 'Switch-A uptime is 1 week', 'status': 'filtered'}],
                 'accounts': [], 'facts': [], 'issues': []}
        second = {'ip': '172.0.0.3', 'port': 22, 'status': 'partial',
                  'evidence': [], 'accounts': [], 'facts': [],
                  'issues': [{'command': 'show users', 'message': 'The output was paginated.'}]}
        ws = self.load('cisco', first, second)
        self.assertEqual(ws.freeze_panes, 'D12')
        self.assertEqual([row[0] for row in self.section(ws, 'Device') if row[2] == 'Collection status'],
                         ['172.0.0.2', '172.0.0.3'])
        self.assertIn('172.0.0.2', ' '.join(str(row[0]) for row in ws.values if row[0] and 'D0001' not in str(row[0])))
        self.assertEqual(self.section(ws, 'Issue')[0][0], '172.0.0.3')
        self.assertEqual(self.section(ws, 'Issue')[0][3], 'The output was paginated.')
        self.assertEqual(ws['A11'].value, 'IP / device')
        self.assertEqual(ws['D11'].value, 'Sanitized result')

    def test_all_cisco_and_palo_checklist_controls_appear_without_auto_pass(self):
        empty = {'ip': '192.0.2.40', 'port': 22, 'status': 'failed',
                 'evidence': [], 'accounts': [], 'facts': [], 'issues': []}
        for platform, expected in (
            ('cisco', {f'CS-{number:02d}' for number in range(1, 7)}),
            ('paloalto', {f'PA-{number:02d}' for number in range(1, 7)}),
        ):
            with self.subTest(platform=platform):
                ws = self.load(platform, {**empty, 'platform': platform})
                rows = self.section(ws, 'Checklist')
                self.assertEqual(len(rows), 6)
                self.assertEqual({row[2].split(' · ', 1)[0] for row in rows}, expected)
                self.assertTrue(all(row[4] in ('Not collected', 'Manual verification') for row in rows))
                self.assertTrue(all(row[7] for row in rows))

    def test_all_text_is_excel_safe_and_xml_compatible(self):
        ws = self.load('cisco', {'ip': '=other', 'port': 22, 'status': 'failed',
                                 'evidence': [], 'accounts': [], 'facts': [], 'issues': []},
                       project_name='=danger\ufffe', started='=formula')
        self.assertEqual(ws['B4'].value, "'=danger")
        self.assertEqual(ws['F5'].value, "'=formula")
        self.assertEqual(self.section(ws, 'Device')[0][0], "'=other")
        self.assertFalse(any(cell.data_type == 'f' for row in ws for cell in row))

    def test_cisco_checks_accounts_and_evidence_links(self):
        facts = ['line vty 0 4 / transport input telnet ssh', 'line vty 0 4 / ipv6 access-class MANAGEMENT in']
        result = {'ip': '192.0.2.1', 'port': 22, 'status': 'completed',
                  'evidence': [{'command': 'show running-config', 'text': '=malicious', 'status': 'filtered'},
                               {'command': 'show ip ssh', 'text': 'SSH Enabled - version 2.0', 'status': 'filtered'}],
                  'accounts': [{'username': 'admin', 'privilege': '15'}], 'facts': facts, 'issues': []}
        ws = self.load('cisco', result)
        self.assertEqual(self.section(ws, 'Evidence')[0][3], "'=malicious")
        local = self.check(ws, 'Local accounts and privilege')
        self.assertEqual(local[4], 'Observed')
        self.assertIn('admin', local[3])
        self.assertEqual(local[5], 'D0001-E01')
        self.assertEqual(self.check(ws, 'VTY access and transport')[4], 'Attention')
        self.assertIn('ipv6 access-class', self.check(ws, 'VTY access and transport')[3])
        self.assertEqual(self.check(ws, 'SSH status')[4], 'Observed')
        self.assertEqual(self.section(ws, 'Account')[0][2], 'admin')
        linked = next(cell for row in ws for cell in row if cell.value == 'D0001-E01' and cell.hyperlink)
        self.assertIn("'Audit Results'!A", linked.hyperlink.location)

    def test_mfa_is_never_asserted_from_aaa_or_authentication_profile(self):
        cisco_facts = ['aaa authentication login default group RAD-AUTH local', 'radius server RAD-1']
        cisco = {'ip': '192.0.2.10', 'port': 22, 'status': 'completed',
                 'evidence': [{'command': 'show running-config', 'text': '\n'.join(cisco_facts), 'status': 'filtered'}],
                 'accounts': [], 'facts': cisco_facts, 'issues': []}
        ws = self.load('cisco', cisco)
        self.assertEqual(self.check(ws, 'MFA enforcement')[4], 'Not Available')
        self.assertIn('Provider MFA enforcement was not verified', self.check(ws, 'MFA enforcement')[3])
        palo_facts = ['admin admin authentication-profile corp-radius', 'authentication-profile corp-radius method radius']
        palo = {'ip': '192.0.2.30', 'port': 22, 'status': 'completed', 'platform': 'paloalto',
                'evidence': [{'command': 'show config running', 'text': '\n'.join(palo_facts), 'status': 'filtered'}],
                'accounts': [], 'facts': palo_facts, 'issues': []}
        ws = self.load('paloalto', palo)
        row = self.check(ws, 'Administrator authentication and MFA')
        self.assertEqual(row[4], 'Not Available')
        self.assertIn('RADIUS/SAML policy and actual MFA enforcement are not verified', row[7])
        self.assertIn('method radius', row[3])

    def test_large_evidence_is_marked_truncated(self):
        text = 'x' * 33000
        result = {'ip': '192.0.2.7', 'port': 22, 'status': 'completed',
                  'evidence': [{'command': 'show ip ssh', 'text': text, 'status': 'filtered'}],
                  'accounts': [], 'facts': [], 'issues': []}
        ws = self.load('cisco', result)
        evidence = self.section(ws, 'Evidence')[0]
        self.assertLessEqual(len(evidence[3]), 32000)
        self.assertIn('Truncated', evidence[7])
        self.assertIn('truncated', self.check(ws, 'SSH status')[7])

    def test_report_has_auditor_columns_version_and_status_legend(self):
        from cisco_audit import __version__
        result = {'ip': '192.0.2.50', 'port': 22, 'status': 'completed',
                  'evidence': [], 'accounts': [], 'facts': [], 'issues': []}
        ws = self.load('cisco', result)
        headers = [ws.cell(11, column).value for column in range(1, 14)]
        self.assertEqual(headers[-4:], ['Auditor decision', 'Owner', 'Reviewer comment', 'Review date'])
        self.assertEqual(ws['A10'].value, 'Tool version')
        self.assertEqual(ws['B10'].value, __version__)
        self.assertEqual(ws['E10'].value, 'Report generated (UTC)')
        self.assertIn('Status legend', ws['A9'].value)
        decisions = ws.data_validations.dataValidation
        self.assertTrue(decisions)
        self.assertTrue(any('J12' in str(rule.sqref) for rule in decisions))

    def test_interrupted_scan_does_not_fabricate_timestamp(self):
        result = {'ip': '192.0.2.8', 'port': 22, 'status': 'interrupted',
                  'evidence': [{'command': 'show ip ssh', 'text': 'SSH Enabled - version 2.0', 'status': 'filtered'}],
                  'accounts': [], 'facts': [], 'issues': []}
        ws = self.load('cisco', result)
        self.assertIsNone(self.section(ws, 'Evidence')[0][8])
        ssh = self.check(ws, 'SSH status')
        self.assertIsNone(ssh[8])
        self.assertEqual(ssh[4], 'Observed')

    def test_missing_evidence_and_collection_issue(self):
        result = {'ip': '192.0.2.2', 'port': 22, 'status': 'failed',
                  'evidence': [], 'accounts': [], 'facts': [],
                  'issues': [{'command': '', 'message': 'Authentication failed'}]}
        ws = self.load('cisco', result)
        self.assertTrue(all(row[4] == 'Not Available' and row[5] is None for row in self.section(ws, 'Check')))
        self.assertEqual(self.section(ws, 'Issue')[0][3], 'Authentication failed')

    def test_palo_administrator_list_and_configuration_roles(self):
        result = {'ip': '192.0.2.3', 'port': 22, 'status': 'completed', 'platform': 'paloalto',
                  'evidence': [{'command': 'show system info', 'text': 'hostname: pa-test', 'status': 'filtered'},
                               {'command': 'show admins all', 'text': 'admin1', 'status': 'filtered'},
                               {'command': 'show config running', 'text': 'admin admin2 role superuser', 'status': 'filtered'}],
                  'accounts': [{'username': 'admin1', 'privilege': 'superuser', 'source': 'show admins all', 'role_source': 'show config running'},
                               {'username': 'admin2', 'privilege': 'superuser', 'source': 'show config running'}],
                  'facts': ['admin admin2 role superuser'], 'issues': []}
        ws = self.load('paloalto', result)
        identity = next(row for row in self.section(ws, 'Device') if row[2] == 'Identity')
        self.assertIn('pa-test', identity[3])
        known = self.check(ws, 'Administrators known to the device')
        self.assertEqual(known[5], 'D0001-E02')
        self.assertIn('admin1', known[3])
        self.assertNotIn('superuser', known[3])
        configured = self.check(ws, 'Administrators from configuration')
        self.assertEqual(configured[5], 'D0001-E03')
        self.assertIn('superuser', configured[3])
        self.assertEqual([row[2] for row in self.section(ws, 'Account')], ['admin1', 'admin2'])


if __name__ == '__main__':
    unittest.main()
