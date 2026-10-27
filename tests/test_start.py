import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import start


class LauncherTests(unittest.TestCase):
    def test_first_launch_installs_then_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / '.venv'
            python = env / 'bin' / 'python'
            req = root / 'requirements.txt'
            marker = env / '.requirements-installed'
            req.write_text('example\n')
            def create(path, with_pip):
                python.parent.mkdir(parents=True)
                python.touch()
            with patch.multiple(start, ROOT=root, ENV=env, PYTHON=python, REQUIREMENTS=req, MARKER=marker), patch.object(start.sys, 'platform', 'darwin'), patch.object(start.venv, 'create', side_effect=create), patch.object(start.os, 'chdir'), patch.object(start.os, 'execv') as execute, patch.object(start.subprocess, 'run', side_effect=[SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)]) as run:
                self.assertEqual(start.main(), 0)
                self.assertEqual(run.call_count, 2)
                execute.assert_called_once()
                self.assertEqual(marker.read_bytes(), req.read_bytes())

    def test_install_failure_does_not_start_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); env = root / '.venv'; env.mkdir(); python = env / 'python'; python.touch(); req = root / 'requirements.txt'; req.write_text('example\n')
            with patch.multiple(start, ROOT=root, ENV=env, PYTHON=python, REQUIREMENTS=req, MARKER=env / 'marker'), patch.object(start.sys, 'platform', 'darwin'), patch.object(start.os, 'chdir'), patch.object(start.os, 'execv') as execute, patch.object(start.subprocess, 'run', side_effect=[SimpleNamespace(returncode=1), SimpleNamespace(returncode=1)]):
                self.assertEqual(start.main(), 1)
                execute.assert_not_called()

if __name__ == '__main__':
    unittest.main()
