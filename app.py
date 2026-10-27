#!/usr/bin/env python3
"""Loopback-only local network access review UI."""
import json
import fcntl
import stat
import sys
import os
import tempfile
from collections import Counter
import secrets
import threading
import uuid
import webbrowser
from concurrent.futures import ThreadPoolExecutor, CancelledError
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from cisco_audit.core import collect, validate_target
from cisco_audit.report import workbook

ROOT = Path(__file__).resolve().parent
TOKEN = secrets.token_urlsafe(32)
RUNS = {}
PROJECTS = {}
LOCK = threading.RLock()
MAX_TARGETS = 200
MAX_PROJECTS = 100
SSH_POOL = ThreadPoolExecutor(max_workers=5, thread_name_prefix="ssh-review")
# Futures are process-local and never persisted.
FUTURES = {}
DATA_DIR = ROOT / '.access-review-data'
STATE_FILE = DATA_DIR / 'projects.json'
STORAGE_ERROR = None
STORAGE_BLOCKED = False

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def acquire_instance_lock():
    """Hold one exclusive Unix advisory lock for this project's data directory."""
    if DATA_DIR.is_symlink():
        raise OSError('The data directory cannot be a symbolic link.')
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(DATA_DIR / 'instance.lock', flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError('The lock file is invalid.')
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('The app is already running for this project directory. Use the URL shown in the running terminal.') from None
        return fd
    except BaseException:
        os.close(fd)
        raise


def save_state():
    """Called under LOCK; persist only already-sanitized snapshots, never credentials or keys."""
    global STORAGE_ERROR
    temp_name = None
    if STORAGE_BLOCKED:
        STORAGE_ERROR = 'Local project data could not be read; the existing file was not overwritten.'
        return False
    try:
        if DATA_DIR.is_symlink():
            raise OSError('Invalid data directory')
        DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(DATA_DIR, 0o700)
        projects = [{'id': p['id'], 'name': p['name'], 'created': p['created'], 'runs': list(p['runs'])} for p in PROJECTS.values()]
        state = {'version': 1, 'projects': projects, 'runs': [public(r) for r in RUNS.values()]}
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=DATA_DIR, prefix='.state-', delete=False) as temp:
            temp_name = temp.name
            os.fchmod(temp.fileno(), 0o600)
            json.dump(state, temp, ensure_ascii=False)
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_name, STATE_FILE)
        STORAGE_ERROR = None
        return True
    except (OSError, TypeError, ValueError):
        STORAGE_ERROR = 'Could not save local project data; recent results may be lost when the app closes.'
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
        return False


def validate_state(state):
    """Reject invalid saved state without replacing the last copy on disk."""
    if not isinstance(state, dict) or state.get('version') != 1:
        raise ValueError('Invalid state version')
    projects, runs = state.get('projects'), state.get('runs')
    if not isinstance(projects, list) or not isinstance(runs, list):
        raise ValueError('Invalid project or run list')
    project_ids, run_ids = set(), set()
    for project in projects:
        if (not isinstance(project, dict) or not isinstance(project.get('id'), str)
                or not isinstance(project.get('name'), str) or not isinstance(project.get('created'), str)
                or not isinstance(project.get('runs'), list)
                or not all(isinstance(rid, str) for rid in project['runs'])
                or project['id'] in project_ids or len(set(project['runs'])) != len(project['runs'])):
            raise ValueError('Invalid project')
        project_ids.add(project['id'])
    run_map = {}
    for run in runs:
        if (not isinstance(run, dict) or not isinstance(run.get('id'), str)
                or not isinstance(run.get('project_id'), str)
                or run['project_id'] not in project_ids
                or run.get('platform') not in ('cisco', 'paloalto')
                or not isinstance(run.get('started'), str)
                or type(run.get('done')) is not bool
                or not isinstance(run.get('results'), list)
                or run['id'] in run_ids):
            raise ValueError('Invalid run')
        for result in run['results']:
            if (not isinstance(result, dict) or not isinstance(result.get('status'), str)
                    or not isinstance(result.get('ip'), str)
                    or type(result.get('port')) is not int or not 1 <= result['port'] <= 65535
                    or not isinstance(result.get('issues', []), list)
                    or not isinstance(result.get('evidence', []), list)
                    or not isinstance(result.get('activity', []), list)
                    or not isinstance(result.get('accounts', []), list)
                    or not isinstance(result.get('facts', []), list)):
                raise ValueError('Invalid result')
            if not all(isinstance(item, dict) and isinstance(item.get('command'), str)
                       and isinstance(item.get('message'), str) for item in result.get('issues', [])):
                raise ValueError('Invalid collection issue')
            if not all(isinstance(item, dict) and isinstance(item.get('command'), str)
                       and isinstance(item.get('text'), str) and isinstance(item.get('status'), str)
                       for item in result.get('evidence', [])):
                raise ValueError('Invalid evidence')
            if not all(isinstance(item, dict) and isinstance(item.get('type'), str)
                       and isinstance(item.get('message', ''), str)
                       and isinstance(item.get('command', ''), str)
                       and isinstance(item.get('text', ''), str)
                       for item in result.get('activity', [])):
                raise ValueError('Invalid activity')
            if not all(isinstance(item, dict) for item in result.get('accounts', [])):
                raise ValueError('Invalid accounts')
            if not all(isinstance(item, (str, dict)) for item in result.get('facts', [])):
                raise ValueError('Invalid facts')
        run_ids.add(run['id'])
        run_map[run['id']] = run
    referenced = set()
    for project in projects:
        for rid in project['runs']:
            if rid not in run_map or run_map[rid]['project_id'] != project['id'] or rid in referenced:
                raise ValueError('Invalid project-run relationship')
            referenced.add(rid)
    if referenced != run_ids:
        raise ValueError('Orphan run')


def load_state():
    """Restore sanitized data; a process restart cannot resume an SSH session."""
    global STORAGE_ERROR, STORAGE_BLOCKED
    with LOCK:
        if not STATE_FILE.exists():
            return
        try:
            if DATA_DIR.is_symlink() or STATE_FILE.is_symlink():
                raise ValueError('Invalid state path')
            state = json.loads(STATE_FILE.read_text(encoding='utf-8'))
            validate_state(state)
            projects = {}
            runs = {}
            for project in state['projects']:
                projects[project['id']] = {**project, 'approved': {}, 'pending': {}}
            for run in state['runs']:
                run['cancel'] = threading.Event()
                for result in run['results']:
                    result.setdefault('activity', [])
                    if result.pop('host_key', None) is not None:
                        result.setdefault('issues', []).append({'command': '', 'message': 'Host key approval is not saved; rerun the target and verify it again.'})
                if not run['done']:
                    run['done'] = True
                    run['finished'] = now()
                    for result in run['results']:
                        if result.get('status') in ('queued', 'connecting', 'collecting'):
                            result['status'] = 'interrupted'
                            result['current_command'] = ''
                            result.setdefault('issues', []).append({'command': '', 'message': 'The app stopped before the scan finished.'})
                runs[run['id']] = run
            PROJECTS.clear()
            PROJECTS.update(projects)
            RUNS.clear()
            RUNS.update(runs)
            save_state()
        except (OSError, ValueError, KeyError, TypeError):
            STORAGE_BLOCKED = True
            STORAGE_ERROR = 'Local project data could not be read; the existing file was not overwritten.'

def worker(run, targets):
    """Submit targets to a shared five-worker pool; never spawn a thread per run."""
    rid = run['id']
    remaining = [len(targets)]

    def one(index, target):
        def update(status):
            with LOCK:
                run['results'][index]['status'] = status
                save_state()

        def on_event(event):
            with LOCK:
                result = run['results'][index]
                if event.get('type') == 'command_started':
                    result['current_command'] = event['command']
                    result.setdefault('activity', []).append({
                        'type': 'command', 'command': event['command'], 'time': now(),
                    })
                elif event.get('type') == 'evidence':
                    result['evidence'].append(dict(event['evidence']))
                    result.setdefault('activity', []).append({
                        'type': 'output', 'command': event['evidence']['command'],
                        'text': event['evidence']['text'], 'time': now(),
                    })
                    result['current_command'] = ''
                elif event.get('type') == 'issue':
                    result['issues'].append(dict(event['issue']))
                    result.setdefault('activity', []).append({
                        'type': 'issue', 'command': event['issue']['command'],
                        'message': event['issue']['message'], 'time': now(),
                    })
                    result['current_command'] = ''
                elif event.get('type') == 'activity':
                    item = {key: event.get(key, '') for key in ('type', 'message', 'command')}
                    item['time'] = now()
                    result.setdefault('activity', []).append(item)
                if len(result.get('activity', [])) > 300:
                    result['activity'] = result['activity'][-300:]
                save_state()

        if run['cancel'].is_set():
            return {'ip': target['ip'], 'port': target['port'], 'status': 'cancelled', 'issues': [], 'evidence': [], 'accounts': [], 'facts': []}
        with LOCK:
            approved = {k: list(v) for k, v in PROJECTS[run['project_id']]['approved'].items()}
        result = collect(target, approved, run['cancel'].is_set, update, legacy=run['legacy'], platform=run['platform'], on_event=on_event)
        result['time'] = now()
        return result

    def finish(future, index, target):
        try:
            result = future.result()
        except CancelledError:
            result = {'ip': target['ip'], 'port': target['port'], 'status': 'cancelled', 'issues': [], 'evidence': [], 'accounts': [], 'facts': []}
        except Exception:
            # Preserve only already-sanitized preview data. A failure after an
            # earlier command must not erase the evidence collected so far.
            with LOCK:
                previous = run['results'][index]
                evidence = list(previous.get('evidence', []))
                issues = list(previous.get('issues', []))
            issues.append({'command': '', 'message': 'An internal collection error occurred; results may be incomplete.'})
            result = {'ip': target['ip'], 'port': target['port'], 'status': 'partial' if evidence else 'failed', 'issues': issues, 'evidence': evidence, 'activity': list(previous.get('activity', [])), 'accounts': [], 'facts': []}
        finally:
            target['password'] = ''
        with LOCK:
            # The collector returns its sanitized findings; the event callback
            # owns the ordered live terminal transcript. Keep both snapshots.
            result['activity'] = list(run['results'][index].get('activity', []))
            if 'host_key' in result:
                key = result['host_key'].pop('key')
                endpoint = result['ip'] if result['port'] == 22 else f"[{result['ip']}]:{result['port']}"
                PROJECTS[run['project_id']]['pending'][endpoint] = key
            run['results'][index] = result
            remaining[0] -= 1
            if remaining[0] == 0:
                run['finished'] = now()
                run['done'] = True
                FUTURES.pop(rid, None)
            save_state()

    # Holding LOCK while registering futures ensures cancellation sees the
    # complete list, even when very fast tasks finish during submission.
    with LOCK:
        FUTURES[rid] = []
        for index, target in enumerate(targets):
            future = SSH_POOL.submit(one, index, target)
            FUTURES[rid].append(future)
            future.add_done_callback(lambda f, i=index, t=target: finish(f, i, t))
            if run['cancel'].is_set():
                future.cancel()


def public(run):
    return {k: v for k, v in run.items() if k != 'cancel'}

def run_summary(run):
    return {'id': run['id'], 'project_id': run['project_id'], 'platform': run['platform'],
            'started': run['started'], 'done': run['done'], 'total': len(run['results']),
            'counts': dict(Counter(r['status'] for r in run['results']))}

def project_summary(project):
    return {'id': project['id'], 'name': project['name'], 'created': project['created'],
            'runs': [run_summary(RUNS[rid]) for rid in project['runs']]}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def headers_common(self, status, typ):
        self.send_response(status)
        self.send_header('Content-Type', typ)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Referrer-Policy', 'no-referrer')
    def respond(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.headers_common(status, 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def valid(self, api=False):
        host = self.headers.get('Host', '')
        if host != f'127.0.0.1:{self.server.server_port}':
            return False
        origin = self.headers.get('Origin')
        if origin and origin != f'http://127.0.0.1:{self.server.server_port}':
            return False
        if api and not secrets.compare_digest(self.headers.get('X-Session-Token', ''), TOKEN):
            return False
        return True
    def do_GET(self):
        if not self.valid():
            return self.respond({'error': 'Forbidden'}, 403)
        path = urlparse(self.path).path
        if path in ('/', '/style.css', '/app.js'):
            file = {'/': 'index.html', '/style.css': 'style.css', '/app.js': 'app.js'}[path]
            data = (ROOT / 'static' / file).read_bytes()
            if path == '/':
                data = data.replace(b'__SESSION_TOKEN__', TOKEN.encode())
            self.headers_common(200, {'/': 'text/html; charset=utf-8', '/style.css': 'text/css; charset=utf-8', '/app.js': 'application/javascript; charset=utf-8'}[path])
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if not self.valid(True):
            return self.respond({'error': 'Forbidden'}, 403)
        parts = path.strip('/').split('/')
        if path == '/projects':
            with LOCK:
                projects = [project_summary(p) for p in PROJECTS.values()]
            return self.respond({'projects': projects, 'storage_error': STORAGE_ERROR})
        if len(parts) == 2 and parts[0] == 'projects':
            with LOCK:
                project = PROJECTS.get(parts[1])
                if not project:
                    return self.respond({'error': 'Project not found'}, 404)
                snapshot = project_summary(project)
            return self.respond(snapshot)
        if len(parts) >= 2 and parts[0] == 'runs':
            with LOCK:
                run = RUNS.get(parts[1])
                if not run:
                    return self.respond({'error': 'Scan not found'}, 404)
                snapshot = json.loads(json.dumps(public(run)))
            if len(parts) == 3 and parts[2] == 'xlsx':
                data = workbook(snapshot)
                self.headers_common(200, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                self.send_header('Content-Disposition', f'attachment; filename="Access_Review_{parts[1][:8]}.xlsx"')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                return self.wfile.write(data)
            return self.respond(snapshot)
        self.respond({'error': 'Not found'}, 404)
    def do_POST(self):
        if not self.valid(True):
            return self.respond({'error': 'Forbidden'}, 403)
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > 1_000_000:
                raise ValueError('Invalid request size.')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError('Invalid input.')
            path = urlparse(self.path).path
            if path == '/projects':
                name = body.get('name')
                if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or any(ord(c) < 32 or ord(c) == 127 for c in name):
                    raise ValueError('Enter a project name (100 characters maximum).')
                name = name.strip()
                with LOCK:
                    if len(PROJECTS) >= MAX_PROJECTS:
                        raise ValueError('The project limit has been reached.')
                    if any(p['name'].casefold() == name.casefold() for p in PROJECTS.values()):
                        raise ValueError('A project with this name already exists.')
                    project_id = uuid.uuid4().hex
                    PROJECTS[project_id] = {'id': project_id, 'name': name, 'created': now(), 'runs': [], 'approved': {}, 'pending': {}}
                    if not save_state():
                        del PROJECTS[project_id]
                        return self.respond({'error': STORAGE_ERROR}, 500)
                return self.respond({'id': project_id})
            if path == '/runs':
                project_id = body.get('project_id')
                if not isinstance(project_id, str):
                    raise ValueError('Select an available project.')
                platform = body.get('platform')
                if platform not in ('cisco', 'paloalto'):
                    raise ValueError('Select Cisco or Palo Alto as the platform.')
                legacy = body.get('legacy', False)
                if type(legacy) is not bool:
                    raise ValueError('Invalid input.')
                if platform != 'cisco' and legacy:
                    raise ValueError('Legacy SSH compatibility is available for Cisco only.')
                rows = body.get('targets', [])
                if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TARGETS:
                    raise ValueError('The target count must be between 1 and 200.')
                targets, seen = [], set()
                for i, row in enumerate(rows, 1):
                    try:
                        target = validate_target(row)
                        endpoint = (target['ip'], target['port'])
                        if endpoint in seen:
                            raise ValueError('Endpoint duplikat')
                        seen.add(endpoint)
                        targets.append(target)
                    except (ValueError, TypeError, AttributeError):
                        raise ValueError(f'Row {i} is invalid. Check the IP, port, username, password, and duplicates.')
                with LOCK:
                    project = PROJECTS.get(project_id)
                    if project is None:
                        raise ValueError('Select an available project.')
                    rid = uuid.uuid4().hex
                    run = {'id': rid, 'project_id': project_id, 'project_name': project['name'], 'started': now(), 'platform': platform, 'legacy': legacy, 'done': False, 'cancel': threading.Event(), 'results': [{'ip': t['ip'], 'port': t['port'], 'status': 'queued', 'issues': [], 'evidence': [], 'activity': [], 'accounts': [], 'facts': []} for t in targets]}
                    RUNS[rid] = run
                    project['runs'].append(rid)
                    if not save_state():
                        project['runs'].remove(rid)
                        del RUNS[rid]
                        return self.respond({'error': STORAGE_ERROR}, 500)
                worker(run, targets)
                return self.respond({'id': rid})
            if path == '/approve-key':
                endpoint = body.get('endpoint', '')
                run_id = body.get('run_id', '')
                with LOCK:
                    run = RUNS.get(run_id) if isinstance(run_id, str) else None
                    if not run:
                        raise ValueError('Scan not found.')
                    project = PROJECTS[run['project_id']]
                    key = project['pending'].get(endpoint) if isinstance(endpoint, str) else None
                    from cisco_audit.core import fingerprint
                    if not key or not isinstance(body.get('fingerprint'), str) or not secrets.compare_digest(fingerprint(key), body['fingerprint']):
                        raise ValueError('The host key is unavailable or its fingerprint does not match.')
                    project['approved'][endpoint] = [key]
                    del project['pending'][endpoint]
                return self.respond({'ok': True})
            parts = path.strip('/').split('/')
            if len(parts) == 3 and parts[0] == 'runs' and parts[2] == 'cancel':
                with LOCK:
                    run = RUNS.get(parts[1])
                    if not run:
                        return self.respond({'error': 'Scan not found'}, 404)
                    run['cancel'].set()
                    for future in list(FUTURES.get(run['id'], [])):
                        future.cancel()
                    save_state()
                return self.respond({'ok': True})
            return self.respond({'error': 'Not found'}, 404)
        except (ValueError, TypeError) as exc:
            message = str(exc) if isinstance(exc, ValueError) and (str(exc).startswith('Row ') or str(exc) in ('The target count must be between 1 and 200.', 'Select an available project.', 'Enter a project name (100 characters maximum).', 'The project limit has been reached.', 'A project with this name already exists.', 'Scan not found.', 'The host key is unavailable or its fingerprint does not match.', 'Invalid request size.', 'Select Cisco or Palo Alto as the platform.', 'Legacy SSH compatibility is available for Cisco only.')) else 'Invalid input.'
            return self.respond({'error': message}, 400)

def main():
    try:
        lock_fd = acquire_instance_lock()
    except (OSError, RuntimeError) as exc:
        print(f'Could not start the app: {exc}', file=sys.stderr)
        return 1
    try:
        load_state()
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        url = f'http://127.0.0.1:{server.server_port}/'
        print(f'Network Access Review: {url}\nPress Ctrl+C to stop.', flush=True)
        webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    finally:
        # Keep the instance lock until all workers stop writing project state.
        with LOCK:
            for run in RUNS.values():
                if not run['done']:
                    run['cancel'].set()
        SSH_POOL.shutdown(wait=True, cancel_futures=True)
        os.close(lock_fd)
    return 0

if __name__ == '__main__':
    sys.exit(main())
