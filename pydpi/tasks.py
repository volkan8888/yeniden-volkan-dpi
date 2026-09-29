"""Windows Gorev Zamanlayici ile oturum acilisinda otomatik baslatma."""
import os
import subprocess
import sys

TASK = "pydpi"


def _command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --auto'
    return f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" --auto'


def install():
    r = subprocess.run(["schtasks", "/Create", "/TN", TASK, "/TR", _command(),
                        "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"],
                       capture_output=True, text=True)
    print(r.stdout or r.stderr)
    return r.returncode


def remove():
    r = subprocess.run(["schtasks", "/Delete", "/TN", TASK, "/F"], capture_output=True, text=True)
    print(r.stdout or r.stderr)
    return r.returncode
