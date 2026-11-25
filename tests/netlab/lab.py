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
from .topology import ROUTERS, UPSTREAM
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
                break
            if anchor.poll() is not None:
                raise LabError(f'lab setup failed:\n{(self.dir / "anchor.log").read_text()}')
            time.sleep(0.05)
        else:
            raise LabError('lab setup timed out, see ' + str(self.dir / 'anchor.log'))
        try:
            for node, spec in NODES.items():
                if spec['kind'] == 'odhcpd':
                    self.start_odhcpd_node(node)
            self.start_uplink()
            for node, spec in NODES.items():
                if spec['kind'] == 'client':
                    self.start_client_node(node)
        except Exception:
            self.down()
            raise
        return self

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

    # ---- odhcpd nodes ----------------------------------------------------------------------
    def wait_for(self, pred, timeout=10, what='condition'):
        end = time.time() + timeout
        while time.time() < end:
            if pred():
                return
            time.sleep(0.05)
        raise LabError(f'timed out waiting for {what}')

    def configure_odhcpd_node(self, node):
        """Copy the node's configs (tests/configs/<node>) into its lab directory."""
        d = self.dir / node
        cfg = d / 'cfg'
        cfg.mkdir(parents=True, exist_ok=True)
        (d / 'hosts').mkdir(exist_ok=True)
        (d / 'pio').mkdir(exist_ok=True)
        src = TESTS / 'configs' / node
        (cfg / 'dhcp').write_text((src / 'dhcp').read_text().replace('@DIR@', str(d)))
        for f in ('network', 'system'):
            (cfg / f).touch()
        (d / 'netifd.json').write_text((src / 'netifd.json').read_text())

    def start_odhcpd_node(self, node):
        """ubusd, netifd-stub and odhcpd in a node, each waiting for the previous one."""
        d = self.dir / node
        self.configure_odhcpd_node(node)
        if node in ROUTERS:
            for key in ('net/ipv4/ip_forward', 'net/ipv6/conf/all/forwarding'):
                self.run(node, ['sh', '-c', f'echo 1 > /proc/sys/{key}'])
        if node == UPSTREAM['node']:
            dev = UPSTREAM['device']
            self.run(node, ['ip', 'link', 'add', 'name', dev, 'type', 'dummy'])
            self.run(node, ['ip', 'link', 'set', 'dev', dev, 'up'])
            for fam in ('-4', '-6'):
                self.run(node, ['ip', fam, 'route', 'add', 'default', 'dev', dev])
        self.spawn(node, ['ubusd'], 'ubusd')
        self.wait_for(lambda: self._sock(node), what=f'{node} ubusd')
        self.spawn(node, ['netifd-stub', '-c', str(d / 'netifd.json')], 'netifd')
        self.run(node, ['ubus', '-t', '10', 'wait_for', 'network.interface'])
        self.start_odhcpd(node)

    def _sock(self, node):
        return subprocess.run(self.argv(node, ['test', '-S', '/run/ubus/ubus.sock'])).returncode == 0

    def start_odhcpd(self, node):
        d = self.dir / node
        self.spawn(node, ['odhcpd', '-c', str(d / 'cfg'), '-f', '-l', '7'], 'odhcpd')
        self.run(node, ['ubus', '-t', '10', 'wait_for', 'dhcp'])

    # ---- DHCP clients ---------------------------------------------------------------------------
    SCRIPT = TESTS / 'scripts' / 'dhcp-client-script'

    def start_udhcpc(self, node, dev, name, iface=None):
        """busybox udhcpc as OpenWrt's netifd runs it (-R: release on exit)."""
        env = {'LAB_CLIENT': 'udhcpc', 'LAB_STATE': str(self.dir / node / 'client-state.json')}
        if iface:
            env['LAB_IFACE'] = iface
        self.spawn(node, ['udhcpc', '-f', '-t', '0', '-R', '-i', dev, '-x', f'hostname:{node}',
                          '-s', str(self.SCRIPT)], name, env=env)

    def start_odhcp6c(self, node, dev, name, iface=None, pd_len=None):
        env = {'LAB_CLIENT': 'odhcp6c', 'LAB_STATE': str(self.dir / node / 'client-state.json')}
        if iface:
            env['LAB_IFACE'] = iface
        cmd = ['odhcp6c', '-l', '7', '-e', '-s', str(self.SCRIPT)]
        if pd_len:
            cmd += ['-P', str(pd_len)]
        self.spawn(node, cmd + [dev], name, env=env)

    def start_uplink(self):
        """The router's wan (DHCPv4) and wan6 (DHCPv6 with a /56 PD) clients."""
        self.start_udhcpc('router', 'wan', 'wan', iface='wan')
        self.start_odhcp6c('router', 'wan', 'wan6', iface='wan6', pd_len=56)

    def start_client_node(self, node):
        """udhcpc (dhcp4) and odhcp6c (dhcp6) on the node's eth0; like netifd, the kernel's own
        SLAAC is off, odhcp6c handles RAs."""
        self.run(node, ['sh', '-c', 'echo 0 > /proc/sys/net/ipv6/conf/eth0/accept_ra'])
        self.start_udhcpc(node, 'eth0', 'dhcp4')
        self.start_odhcp6c(node, 'eth0', 'dhcp6')

    def dhcp_clients(self, node):
        """Names of a node's DHCP client daemons (wan/wan6 on the router, dhcp4/dhcp6 on clients)."""
        if node == 'router':
            return ['wan', 'wan6']
        if NODES[node]['kind'] == 'client':
            return ['dhcp4', 'dhcp6']
        return []

    def client_action(self, node, action, which=None):
        """renew (SIGUSR1), release (SIGUSR2) or restart a node's DHCP clients (all, or one)."""
        self.require()
        names = self.dhcp_clients(node)
        if which:
            if which not in names:
                raise LabError(f'{node} has no client "{which}" ({", ".join(names) or "none"})')
            names = [which]
        for name in names:
            if action == 'renew':
                self.signal(node, name, signal.SIGUSR1)
            elif action == 'release':
                self.signal(node, name, signal.SIGUSR2)
            elif action == 'restart':
                self.stop_daemon(node, name)
                spec = json.loads((self.dir / node / f'{name}.cmd').read_text())
                self.spawn(node, spec['cmd'], name, env=spec['env'])
            else:
                raise LabError(f'unknown client action "{action}"')

    # ---- crafted packets (tests/netlab/probe.py) -------------------------------------------------
    def default_dev(self, node):
        links = list(NODES[node]['links'])
        return links[0]

    def probe(self, node, kind, steps, dev=None, timeout=60):
        """Crafted exchanges from a node (see probe.py for the step syntax); returns the decoded
        results, one dict per step. The exchange is saved as <node>/probe-<time>.pcap."""
        dev = dev or self.default_dev(node)
        pcap = self.dir / node / f'probe-{time.strftime("%H%M%S")}-{kind}.pcap'
        out = self.run(node, [sys.executable, str(TESTS / 'netlab' / 'probe.py'), dev, str(pcap),
                              kind] + list(steps), timeout=timeout)
        return [json.loads(line) for line in out.splitlines() if line.startswith('{')]

    def odhcpd_alive(self):
        """{node: bool} for the odhcpd nodes."""
        return {n: self.daemon_pid(n, 'odhcpd') is not None
                for n, s in NODES.items() if s['kind'] == 'odhcpd'}

    def fuzz(self, node, kind, count, seed=1, dev=None):
        """count seeded mutations of valid messages from a node, then check that every odhcpd is
        still running and that a normal exchange from the node still gets an answer."""
        dev = dev or self.default_dev(node)
        res = self.run(node, [sys.executable, str(TESTS / 'netlab' / 'probe.py'), dev, '',
                              'fuzz', kind, str(count), str(seed)], timeout=600)
        result = json.loads(res.strip().splitlines()[-1])
        time.sleep(1)
        result['alive'] = self.odhcpd_alive()
        check = {'dhcp6': ['sol:rc,na=1'], 'dhcp4': ['disc'], 'rs': ['rs']}[kind]
        result['answered'] = bool(self.probe(node, kind, check, dev=dev)[0]['replies'])
        return result

    # isp's PD pools: prefix-change moves the delegation to the other one
    PD_POOLS = ['2001:db8:100::1/40', '2001:db8:200::1/40']

    def prefix_change(self):
        """isp hands out /56s from the other PD pool (as when an ISP renumbers)."""
        self.require()
        have = self.run('isp', ['ip', '-6', '-br', 'addr', 'show', 'dev', 'wan'])
        old = next(p for p in self.PD_POOLS if p in have)
        new = self.PD_POOLS[1 - self.PD_POOLS.index(old)]
        self.run('isp', ['ip', '-6', 'addr', 'add', new, 'dev', 'wan'])
        self.run('isp', ['ip', '-6', 'addr', 'del', old, 'dev', 'wan'])
        return old, new

    def daemon_pid(self, node, name):
        try:
            pid = int((self.dir / node / f'{name}.pid').read_text())
        except (FileNotFoundError, ValueError):
            return None
        try:
            os.kill(pid, 0)
            return pid
        except ProcessLookupError:
            return None

    def signal(self, node, name, sig):
        pid = self.daemon_pid(node, name)
        if not pid:
            raise LabError(f'{node}: {name} is not running')
        os.kill(pid, sig)

    def stop_daemon(self, node, name, timeout=5):
        pid = self.daemon_pid(node, name)
        if not pid:
            return
        os.kill(pid, signal.SIGTERM)
        try:
            self.wait_for(lambda: self.daemon_pid(node, name) is None, timeout, f'{node} {name} to stop')
        except LabError:
            os.kill(pid, signal.SIGKILL)

    def reload(self, node):
        """odhcpd rereads its config (SIGHUP), as on OpenWrt's reload."""
        self.require()
        self.signal(node, 'odhcpd', signal.SIGHUP)

    def restart(self, node):
        self.require()
        self.stop_daemon(node, 'odhcpd')
        self.start_odhcpd(node)

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

    def spawn(self, target, cmd, logname, env=None):
        """Start a long-running program in a node, detached, output into <node>/<logname>.log;
        its pid goes into <node>/<logname>.pid."""
        d = self.dir / target
        log = open(d / f'{logname}.log', 'a')
        e = prefix_env()
        e.update(env or {})
        p = subprocess.Popen(self.argv(target, cmd), env=e, stdin=subprocess.DEVNULL,
                             stdout=log, stderr=log, start_new_session=True)
        (d / f'{logname}.cmd').write_text(json.dumps({'cmd': list(cmd), 'env': env or {}}))
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
