"""HTTP handler and concurrent projects tests without contacting network devices."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

try:
    import paramiko  # noqa: F401
except ImportError:
    sys.modules['paramiko'] = types.ModuleType('paramiko')

HAS_REPORT = importlib.util.find_spec('openpyxl') is not None
if HAS_REPORT:
    import app

@unittest.skipUnless(HAS_REPORT, 'openpyxl belum terpasang')
class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = patch.multiple(app, DATA_DIR=Path(self.tmp.name) / 'data', STATE_FILE=Path(self.tmp.name) / 'data' / 'projects.json', STORAGE_ERROR=None, STORAGE_BLOCKED=False)
        self.patches.start()
        app.RUNS.clear(); app.PROJECTS.clear()
    def tearDown(self):
        self.patches.stop(); self.tmp.cleanup()
    def request(self, body=None, token=True, path='/runs', method='POST'):
        payload = json.dumps(body or {}).encode()
        handler = app.Handler.__new__(app.Handler)
        handler.server = SimpleNamespace(server_port=8912)
        handler.path = path
        handler.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(payload)), 'Host': '127.0.0.1:8912'}
        if token:
            handler.headers['X-Session-Token'] = app.TOKEN
        handler.rfile = BytesIO(payload)
        captured = []
        handler.respond = lambda obj, status=200: captured.append((status, obj))
        (handler.do_POST if method == 'POST' else handler.do_GET)()
        return captured[0]
    def project(self, name):
        status, data = self.request({'name': name}, path='/projects')
        self.assertEqual(status, 200)
        return data['id']
    def await_done(self, rid):
        for _ in range(200):
            if app.RUNS[rid]['done']: return
            time.sleep(.01)
        self.fail('worker did not finish')
    def test_rejects_missing_invalid_and_incompatible_platforms(self):
        project_id = self.project('Example')
        row = {'ip': '192.0.2.1', 'username': 'u', 'password': 'p'}
        for payload in ({'project_id': project_id, 'targets': [row]}, {'project_id': project_id, 'platform': 'unknown', 'targets': [row]}, {'project_id': project_id, 'platform': 'paloalto', 'legacy': True, 'targets': [row]}, {'project_id': project_id, 'platform': ['cisco'], 'targets': [row]}, {'platform': 'cisco', 'targets': [row]}):
            self.assertEqual(self.request(payload)[0], 400)
        self.assertEqual(self.request({'platform': 'cisco', 'targets': [row]}, token=False)[0], 403)
    def test_paloalto_platform_passes_to_collector(self):
        calls = []
        project_id = self.project('Example')
        def fake_collect(target, approved, cancelled, update, **kw):
            calls.append((target['ip'], kw['legacy'], kw['platform']))
            return {'ip': target['ip'], 'port': target['port'], 'status': 'completed', 'issues': [], 'evidence': [], 'accounts': [], 'facts': []}
        with patch.object(app, 'collect', side_effect=fake_collect):
            status, data = self.request({'project_id':project_id, 'platform':'paloalto', 'targets':[{'ip':'192.0.2.1','username':'u','password':'p'}]})
            self.assertEqual(status, 200)
            self.await_done(data['id'])
        self.assertEqual(calls, [('192.0.2.1', False, 'paloalto')])
        self.assertNotIn('password', json.dumps(app.public(app.RUNS[data['id']])))
    def test_concurrent_projects_live_preview_and_persistence(self):
        a, b = self.project('A'), self.project('B')
        release = threading.Event()
        seen = threading.Event()
        def collect(target, approved, cancelled, update, **kw):
            update('collecting')
            kw['on_event']({'type': 'command_started', 'command': 'show version'})
            kw['on_event']({'type': 'evidence', 'evidence': {'command': 'show version', 'text': 'filtered', 'status': 'sanitized'}})
            seen.set(); release.wait(3)
            return {'ip': target['ip'], 'port': target['port'], 'status': 'completed', 'issues': [], 'evidence': [{'command':'show version', 'text':'filtered', 'status':'sanitized'}], 'accounts': [], 'facts': []}
        payload = {'platform': 'cisco', 'targets': [{'ip':'192.0.2.1', 'username':'u', 'password':'secret-password'}]}
        with patch.object(app, 'collect', side_effect=collect):
            s1, r1 = self.request({**payload, 'project_id':a}); self.assertEqual(s1, 200)
            self.assertTrue(seen.wait(2))
            s2, r2 = self.request({**payload, 'project_id':b}); self.assertEqual(s2, 200)
            code, detail = self.request(path='/runs/' + r1['id'], method='GET')
            self.assertEqual(code, 200); self.assertEqual(detail['results'][0]['evidence'][0]['text'], 'filtered')
            self.assertEqual([entry['type'] for entry in detail['results'][0]['activity']], ['command', 'output'])
            self.assertNotIn('secret-password', json.dumps(detail['results'][0]['activity']))
            self.assertEqual(self.request(path='/projects/' + a, method='GET')[1]['runs'][0]['id'], r1['id'])
            self.assertEqual(self.request(path='/projects/' + b, method='GET')[1]['runs'][0]['id'], r2['id'])
            release.set(); self.await_done(r1['id']); self.await_done(r2['id'])
        raw = app.STATE_FILE.read_text()
        self.assertNotIn('secret-password', raw)
        self.assertEqual(os.stat(app.DATA_DIR).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(app.STATE_FILE).st_mode & 0o777, 0o600)
        app.RUNS.clear(); app.PROJECTS.clear(); app.load_state()
        self.assertEqual(len(app.PROJECTS), 2)
        self.assertEqual(app.RUNS[r1['id']]['results'][0]['evidence'][0]['text'], 'filtered')
        self.assertEqual([entry['type'] for entry in app.RUNS[r1['id']]['results'][0]['activity']], ['command', 'output'])
    def test_collector_failure_preserves_sanitized_live_evidence(self):
        project = self.project('Partial result')
        def failing_collect(target, approved, cancelled, update, **kw):
            update('collecting')
            kw['on_event']({'type': 'evidence', 'evidence': {'command': 'show version', 'text': 'filtered data', 'status': 'sanitized'}})
            raise RuntimeError('raw secret exception text')
        with patch.object(app, 'collect', side_effect=failing_collect):
            status, data = self.request({'project_id': project, 'platform': 'cisco', 'targets': [{'ip': '192.0.2.1', 'username': 'u', 'password': 'p'}]})
            self.assertEqual(status, 200)
            self.await_done(data['id'])
        result = app.RUNS[data['id']]['results'][0]
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['evidence'][0]['text'], 'filtered data')
        self.assertIn('internal collection error', result['issues'][-1]['message'])
        self.assertNotIn('raw secret exception text', json.dumps(app.public(app.RUNS[data['id']])))

    def test_global_limit_across_concurrent_scans(self):
        project = self.project('Parallel')
        release, five_active = threading.Event(), threading.Event()
        lock = threading.Lock()
        active, maximum = [0], [0]
        def collect(target, approved, cancelled, update, **kwargs):
            with lock:
                active[0] += 1
                maximum[0] = max(maximum[0], active[0])
                if active[0] == 5: five_active.set()
            release.wait(3)
            with lock: active[0] -= 1
            return {'ip':target['ip'], 'port':target['port'], 'status':'completed', 'evidence':[], 'issues':[], 'accounts':[], 'facts':[]}
        def payload(ip):
            return {'project_id':project, 'platform':'cisco', 'targets':[{'ip':ip, 'username':'u', 'password':'p'}]}
        ids = []
        with patch.object(app, 'collect', side_effect=collect):
            try:
                for i in range(1, 7):
                    status, data = self.request(payload(f'192.0.2.{i}'))
                    self.assertEqual(status, 200)
                    ids.append(data['id'])
                self.assertTrue(five_active.wait(2))
                time.sleep(.1)
                self.assertEqual(maximum[0], 5)
            finally:
                release.set()
                for rid in ids: self.await_done(rid)

    def test_more_than_ten_runs_and_queued_cancel(self):
        project = self.project('Many scans')
        release, five_started = threading.Event(), threading.Event()
        lock = threading.Lock()
        calls = []
        def collect(target, approved, cancelled, update, **kwargs):
            with lock:
                calls.append(target['ip'])
                if len(calls) == 5: five_started.set()
            release.wait(5)
            return {'ip': target['ip'], 'port': target['port'], 'status': 'completed', 'issues': [], 'evidence': [], 'accounts': [], 'facts': []}
        ids = []
        with patch.object(app, 'collect', side_effect=collect):
            try:
                for i in range(1, 13):
                    status, data = self.request({'project_id': project, 'platform': 'cisco', 'targets': [{'ip': f'192.0.2.{i}', 'username': 'u', 'password': 'p'}]})
                    self.assertEqual(status, 200)
                    ids.append(data['id'])
                self.assertTrue(five_started.wait(2))
                status, _ = self.request({}, path='/runs/' + ids[-1] + '/cancel')
                self.assertEqual(status, 200)
                self.await_done(ids[-1])
                self.assertEqual(app.RUNS[ids[-1]]['results'][0]['status'], 'cancelled')
                self.assertNotIn('192.0.2.12', calls)
                self.assertEqual(len(calls), 5)
            finally:
                release.set()
                for rid in ids:
                    self.await_done(rid)

    def test_only_one_instance_can_use_data_directory(self):
        first = app.acquire_instance_lock()
        try:
            self.assertEqual(os.stat(app.DATA_DIR).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(app.DATA_DIR / 'instance.lock').st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(RuntimeError, 'already running'):
                app.acquire_instance_lock()
        finally:
            os.close(first)
        second = app.acquire_instance_lock()
        os.close(second)

    def test_instance_lock_rejects_symlinks(self):
        app.DATA_DIR.mkdir()
        target = Path(self.tmp.name) / 'target'
        target.write_text('unchanged')
        (app.DATA_DIR / 'instance.lock').symlink_to(target)
        with self.assertRaises(OSError):
            app.acquire_instance_lock()
        self.assertEqual(target.read_text(), 'unchanged')

    def test_invalid_state_shape_and_references_are_not_overwritten(self):
        self.project('Valid')
        invalid = [[], {'version': 1, 'projects': [{'id': 'a', 'name': 'A', 'created': 'x', 'runs': ['missing']}], 'runs': []},
                   {'version': 1, 'projects': [{'id': 'a', 'name': 'A', 'created': 'x', 'runs': ['r']}],
                    'runs': [{'id': 'r', 'project_id': 'a', 'platform': 'cisco', 'started': 'x', 'done': True,
                              'results': [{'ip': '192.0.2.1', 'port': 22, 'status': 'completed', 'evidence': [{'command': 'show version'}]}]}]}]
        for state in invalid:
            original = json.dumps(state)
            app.STATE_FILE.write_text(original)
            app.STORAGE_BLOCKED = False
            app.load_state()
            self.assertTrue(app.STORAGE_BLOCKED)
            with app.LOCK:
                self.assertFalse(app.save_state())
            self.assertEqual(app.STATE_FILE.read_text(), original)

    def test_restore_interrupted_and_corrupt_file_not_overwritten(self):
        pid = self.project('Restore')
        rid = 'abc'
        app.RUNS[rid] = {'id': rid, 'project_id':pid, 'platform':'cisco', 'started':app.now(), 'done':False, 'cancel':threading.Event(), 'results':[{'ip':'192.0.2.10', 'port':22, 'status':'collecting', 'issues':[]}]}
        app.PROJECTS[pid]['runs'].append(rid)
        with app.LOCK: self.assertTrue(app.save_state())
        app.RUNS.clear(); app.PROJECTS.clear(); app.load_state()
        self.assertEqual(app.RUNS[rid]['results'][0]['status'], 'interrupted')
        app.STATE_FILE.write_text('{corrupt')
        app.load_state()
        self.assertTrue(app.STORAGE_BLOCKED)
        with app.LOCK: self.assertFalse(app.save_state())
        self.assertEqual(app.STATE_FILE.read_text(), '{corrupt')

if __name__ == '__main__': unittest.main()
