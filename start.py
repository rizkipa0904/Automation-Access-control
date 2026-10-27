#!/usr/bin/env python3
"""Bootstrap and launch the local application with one Python command."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parent
ENV = ROOT / '.venv'
PYTHON = ENV / 'bin' / 'python'
REQUIREMENTS = ROOT / 'requirements.txt'
MARKER = ENV / '.requirements-installed'


def main() -> int:
    if not (sys.platform.startswith('linux') or sys.platform == 'darwin'):
        print('This app is supported on Linux and macOS.', file=sys.stderr)
        return 1
    if sys.version_info < (3, 10):
        print('Python 3.10 or newer is required.', file=sys.stderr)
        return 1
    os.chdir(ROOT)
    if not PYTHON.is_file():
        print('Preparing virtual environment...', flush=True)
        try:
            venv.create(ENV, with_pip=True)
        except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
            print(f'Could not create virtual environment: {exc}\nMake sure the Python venv module is available.', file=sys.stderr)
            return 1
    try:
        desired = REQUIREMENTS.read_bytes()
        current = MARKER.read_bytes() if MARKER.exists() else b''
        check = subprocess.run([str(PYTHON), '-c', 'import paramiko, cryptography, openpyxl'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if current != desired or check.returncode:
            print('Installing dependencies (the first install needs access to a Python package index or local wheels)...', flush=True)
            install = subprocess.run([str(PYTHON), '-m', 'pip', 'install', '-r', str(REQUIREMENTS)], check=False)
            if install.returncode:
                print('Dependency installation failed. Check package index access or offline wheel configuration.', file=sys.stderr)
                return install.returncode
            verify = subprocess.run([str(PYTHON), '-c', 'import paramiko, cryptography, openpyxl'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if verify.returncode:
                print('Dependencies were installed but could not be imported. Check the Python version and package compatibility.', file=sys.stderr)
                return 1
            MARKER.write_bytes(desired)
        os.execv(str(PYTHON), [str(PYTHON), str(ROOT / 'app.py')])
    except OSError as exc:
        print(f'Could not start the app: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
