"""A running (or startable) lab, addressed by name; used by tests/lab and the tests.

A lab's files live in RUN/<name>/: state.json (pids and namespaces, written by the anchor),
anchor.log, and one directory per node for its configs, logs and pids.
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from .paths import RUN, TESTS, PREFIX, env as prefix_env
from .topology import NODES, NETWORKS, BRIDGE


class LabError(RuntimeError):
    pass


class Lab:
    def __init__(self, name='default'):
        self.name = name
        self.dir = RUN / name
        self.state = None
        self._load()

    # ---- state ------------------------------------------------------------------------------
    def _load(self):
        try:
            self.state = json.loads((self.dir / 'state.json').read_text())
        except FileNotFoundError:
            self.state = None

    def running(self):
        """Is the lab's anchor still alive (and still the same process)?"""
        if not self.state:
            return False
        try:
            return os.readlink(f'/proc/{self.state["anchor"]}/ns/user') == self.state['userns']
        except (FileNotFoundError, PermissionError):
            return False

    def require(self):
        if not self.running():
            raise LabError(f'lab "{self.name}" is not running (tests/lab up)')

    def processes(self):
        """Pids of all processes in the lab's user namespace."""
        pids = []
        for p in os.listdir('/proc'):
            if p.isdigit():
                try:
                    if os.readlink(f'/proc/{p}/ns/user') == self.state['userns']:
                        pids.append(int(p))
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    pass
        return pids

    # ---- lifecycle --------------------------------------------------------------------------
    def up(self):
        if self.running():
            raise LabError(f'lab "{self.name}" is already running')
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / 'state.json').unlink(missing_ok=True)
        for node in NODES:
            (self.dir / node).mkdir(exist_ok=True)
        log = open(self.dir / 'anchor.log', 'w')
        anchor = subprocess.Popen(
            ['unshare', '--user', '--map-root-user', '--mount', '--net', '--fork',
             sys.executable, '-m', 'netlab.anchor', str(self.dir)],
            cwd=TESTS, env=prefix_env(), stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            start_new_session=True)
        for _ in range(300):
            self._load()
            if self.state and self.state.get('ready'):
                return self
            if anchor.poll() is not None:
                raise LabError(f'lab setup failed:\n{(self.dir / "anchor.log").read_text()}')
            time.sleep(0.05)
        raise LabError('lab setup timed out, see ' + str(self.dir / 'anchor.log'))

    def down(self):
        if not self.running():
            self.state = None
            return
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for pid in self.processes():
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
            for _ in range(50):
                if not self.processes():
                    break
                time.sleep(0.05)
        (self.dir / 'state.json').unlink(missing_ok=True)
        self.state = None

    # ---- running things in nodes and networks -------------------------------------------------
    def pid(self, target):
        self.require()
        if target in self.state['nodes']:
            return self.state['nodes'][target]
        if target in self.state['networks']:
            return self.state['networks'][target]
        raise LabError(f'unknown node or network "{target}"')

    def argv(self, target, cmd):
        """argv running cmd in a node's (or network's) namespaces, as root of the lab."""
        return ['nsenter', '--preserve-credentials', '-t', str(self.pid(target)),
                '-U', '-n', '-m', '-u', '--'] + list(cmd)

    def run(self, target, cmd, check=True, timeout=60, **kw):
        """Run cmd in a node and return its stdout (text)."""
        r = subprocess.run(self.argv(target, cmd), env=prefix_env(), capture_output=True,
                           text=True, timeout=timeout, **kw)
        if check and r.returncode:
            raise LabError(f'{target}: {" ".join(cmd)} failed ({r.returncode}): {r.stderr.strip()}')
        return r.stdout

    def spawn(self, target, cmd, logname):
        """Start a long-running program in a node, detached, output into <node>/<logname>.log;
        its pid goes into <node>/<logname>.pid."""
        d = self.dir / target
        log = open(d / f'{logname}.log', 'a')
        p = subprocess.Popen(self.argv(target, cmd), env=prefix_env(), stdin=subprocess.DEVNULL,
                             stdout=log, stderr=log, start_new_session=True)
        (d / f'{logname}.pid').write_text(str(p.pid))
        return p.pid

    def shell(self, target):
        """An interactive shell in a node (replaces the current process)."""
        e = prefix_env()
        e['PS1'] = f'[lab:{target}] \\w# '
        e['LAB_NODE'] = target
        shell = os.environ.get('SHELL', '/bin/sh')
        if shell.endswith('bash'):
            argv = self.argv(target, [shell, '--norc', '-i'])
        else:
            argv = self.argv(target, [shell, '-i'])
        os.execvpe(argv[0], argv, e)

    # ---- observation --------------------------------------------------------------------------
    def logs(self, target):
        """The log files of a node, oldest first."""
        d = self.dir / target
        return sorted(d.glob('*.log'), key=lambda p: p.stat().st_mtime) if d.exists() else []

    def status(self):
        """Human-readable overview of nodes and networks."""
        self.require()
        out = [f'lab "{self.name}" ({self.dir})']
        for node, spec in NODES.items():
            out.append(f'{node} ({spec["kind"]}):')
            for line in self.run(node, ['ip', '-br', 'addr']).splitlines():
                if not line.startswith('lo '):
                    out.append('    ' + ' '.join(line.split()))
        for net in NETWORKS:
            ports = [l.split()[0].split('@')[0] for l in
                     self.run(net, ['ip', '-br', 'link', 'show', 'master', BRIDGE]).splitlines()]
            out.append(f'network {net}: ' + ', '.join(ports))
        return '\n'.join(out)
