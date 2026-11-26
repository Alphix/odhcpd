"""The client stacks of the client nodes (`<network>-c<stack>`).

openwrt (busybox udhcpc + odhcp6c, built by the lab) is always there. systemd (systemd-networkd)
and nm (NetworkManager, with its internal DHCP clients) come from the host and are used when
they are installed and start in a namespace (a short trial start, cached per binary).
ODHCPD_LAB_NETWORKD and ODHCPD_LAB_NETWORKMANAGER (with ODHCPD_LAB_NMCLI) point to other
binaries, e.g. self-built ones.

Each node of these stacks has its own user namespace nested in the lab's: networkd runs as the
host's systemd-network user (it skips its privilege drop then), NetworkManager as root. Both see
a read-only sysfs (no udev in the lab) and get a fixed identity per node: machine-id, DUID-UUID
derived from the node name, IAID 1, the node name as hostname.
"""
import glob
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import tempfile
from pathlib import Path

from .paths import WORK

OPTIONAL = ['systemd', 'nm']
STACKS = ['openwrt'] + OPTIONAL

IAID = 1


class StackError(RuntimeError):
    pass


# ---- binaries ---------------------------------------------------------------------------------
def _first(*paths):
    return next((p for p in paths if p and os.access(p, os.X_OK)), None)


def networkd_binary():
    return _first(os.environ.get('ODHCPD_LAB_NETWORKD'), '/usr/lib/systemd/systemd-networkd',
                  '/lib/systemd/systemd-networkd')


def networkctl_binary():
    return _first(os.environ.get('ODHCPD_LAB_NETWORKCTL'), shutil.which('networkctl'))


def nm_binary():
    return _first(os.environ.get('ODHCPD_LAB_NETWORKMANAGER'), '/usr/sbin/NetworkManager',
                  shutil.which('NetworkManager') or '')


def nmcli_binary():
    return _first(os.environ.get('ODHCPD_LAB_NMCLI'), shutil.which('nmcli'))


def dbus_binary():
    return _first(shutil.which('dbus-daemon'), '/usr/bin/dbus-daemon')


def networkd_user():
    """uid/gid networkd runs as in its node (networkd only drops privileges when started as root)."""
    try:
        pw = pwd.getpwnam('systemd-network')
        return pw.pw_uid, pw.pw_gid
    except KeyError:
        return 998, 998


def userns_args(stack):
    """unshare arguments for a node's own user namespace (nested in the lab's)."""
    if stack == 'systemd':
        uid, gid = networkd_user()
        return ['--user', f'--map-user={uid}', f'--map-group={gid}', '--keep-caps']
    if stack == 'nm':
        return ['--user', '--map-root-user']
    return []


def _version(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.splitlines()[0].strip() if out.strip() else None


def binaries(stack):
    """{role: path} of a stack's programs, or a reason why it can't be used."""
    if stack == 'systemd':
        b = {'networkd': networkd_binary(), 'networkctl': networkctl_binary(),
             'dbus-daemon': dbus_binary()}
    else:
        b = {'NetworkManager': nm_binary(), 'nmcli': nmcli_binary(), 'dbus-daemon': dbus_binary()}
    missing = [k for k, v in b.items() if not v]
    if missing:
        return None, 'not installed (' + ', '.join(missing) + ')'
    return b, None


def version(stack, bins):
    if stack == 'systemd':
        v = _version([bins['networkd'], '--version'])
        return v.split(' (')[0] if v else None   # "systemd 257 (257.13-1)" -> "systemd 257"
    v = _version([bins['NetworkManager'], '--version'])
    return f'NetworkManager {v}' if v else None


# ---- per-node configuration -----------------------------------------------------------------
def machine_id(node):
    return hashlib.sha256(f'odhcpd-lab {node}'.encode()).hexdigest()[:32]


def duid(node):
    """DUID-UUID (RFC 6355) from the node's machine-id, as colon-separated hex."""
    raw = '0004' + machine_id(node)
    return ':'.join(raw[i:i + 2] for i in range(0, len(raw), 2))


def client_id(node):
    """DHCPv4 client identifier per RFC 4361: 0xff, IAID, DUID."""
    return 'ff:' + ':'.join(f'{b:02x}' for b in IAID.to_bytes(4, 'big')) + ':' + duid(node)


def networkd_files(d, node):
    """The node's .network file (written into <d>, copied into /run/systemd/network)."""
    raw = duid(node)[len('00:04:'):]
    (d / '10-lab.network').write_text(f"""[Match]
Name=eth0

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
ClientIdentifier=duid
IAID={IAID}
DUIDType=uuid
DUIDRawData={raw}
Hostname={node}

[DHCPv6]
IAID={IAID}
DUIDType=uuid
DUIDRawData={raw}
""")


DBUS_CONF = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=/run/dbus/system_bus_socket</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
"""


def nm_files(d, node):
    """NetworkManager's config, the eth0 profile, an empty state directory and dbus config in <d>."""
    for sub in ('connections', 'state', 'empty'):
        (d / sub).mkdir(parents=True, exist_ok=True)
    (d / 'NetworkManager.conf').write_text(f"""[main]
plugins=keyfile
dhcp=internal
auth-polkit=false
hostname-mode=none
dns=none
no-auto-default=*

[keyfile]
path={d / 'connections'}
unmanaged-devices=except:interface-name:eth0

[logging]
level=DEBUG
domains=PLATFORM,DEVICE,DHCP,DHCP4,DHCP6,IP4,IP6,CORE
""")
    prof = d / 'connections' / 'eth0.nmconnection'
    prof.write_text(f"""[connection]
id=eth0
type=ethernet
interface-name=eth0
autoconnect-retries=0

[ipv4]
method=auto
dhcp-client-id={client_id(node)}
dhcp-hostname={node}
dhcp-send-release=1
dhcp-timeout=2147483647

[ipv6]
method=auto
dhcp-duid={duid(node)}
dhcp-iaid={IAID}
dhcp-hostname={node}
dhcp-send-release=1
dhcp-timeout=2147483647
""")
    prof.chmod(0o600)


def nm_plugin_dir(bins):
    """NetworkManager's directory of device plugins (wifi, bluetooth, ...), if any: hidden in the
    nodes, they aren't needed and belong to the real root (NM warns about their owner)."""
    v = _version([bins['NetworkManager'], '--version'])
    if not v:
        return None
    for p in glob.glob(f'/usr/lib*/NetworkManager/{v}') + glob.glob(f'/usr/lib/*/NetworkManager/{v}'):
        if os.path.isdir(p):
            return p
    return None


def nm_command(bins, d):
    return [bins['NetworkManager'], '--debug', f'--config={d / "NetworkManager.conf"}',
            f'--config-dir={d / "empty"}', f'--system-config-dir={d / "empty"}',
            '--intern-config=/run/nm-intern.conf', f'--state-file={d / "state" / "NetworkManager.state"}']


def node_mounts(stack, bins, d):
    """Bind mounts [(source, target)] for a node of the stack."""
    m = [(d / 'machine-id', '/etc/machine-id')] if os.path.exists('/etc/machine-id') else []
    if stack == 'systemd':
        # the host's own .network files would apply too
        if os.path.isdir('/etc/systemd/network'):
            m.append((d / 'empty', '/etc/systemd/network'))
    else:
        if os.path.isdir('/var/lib/NetworkManager'):
            m.append((d / 'state', '/var/lib/NetworkManager'))
        plugins = nm_plugin_dir(bins)
        if plugins:
            m.append((d / 'empty', plugins))
    return m


def prepare(stack, bins, d, node):
    """Write a node's files into <d>; returns its bind mounts."""
    d.mkdir(parents=True, exist_ok=True)
    (d / 'empty').mkdir(exist_ok=True)
    (d / 'machine-id').write_text(machine_id(node) + '\n')
    (d / 'dbus.conf').write_text(DBUS_CONF)
    if stack == 'systemd':
        networkd_files(d, node)
    else:
        nm_files(d, node)
    return node_mounts(stack, bins, d)


# ---- detection ----------------------------------------------------------------------------------
TRIAL_SECONDS = 2


def trial(stack, bins):
    """Start the stack's daemon(s) for a moment in throwaway namespaces like a node's; return
    None if it keeps running, else the reason."""
    WORK.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='trial-', dir=WORK) as tmp:
        d = Path(tmp)
        mounts = prepare(stack, bins, d, 'trial')
        sh = ['mount -t tmpfs -o mode=0755 tmpfs /run', 'mount -t sysfs -o ro sysfs /sys']
        sh += [f'mount --bind "{s}" "{t}"' for s, t in mounts]
        sh += ['mkdir -p /run/dbus',
               f'"{bins["dbus-daemon"]}" --config-file="{d}/dbus.conf" --nofork --nopidfile &',
               'for i in $(seq 50); do [ -S /run/dbus/system_bus_socket ] && break; sleep 0.1; done']
        if stack == 'systemd':
            sh += ['mkdir -p /run/systemd/network /run/systemd/netif',
                   f'cp "{d}/10-lab.network" /run/systemd/network/',
                   f'exec "{bins["networkd"]}"']
        else:
            sh += ['exec ' + ' '.join(f'"{a}"' for a in nm_command(bins, d))]
        log = open(d / 'trial.log', 'w')
        p = subprocess.Popen(['unshare'] + userns_args(stack) +
                             ['--net', '--mount', '--uts', '--propagation', 'private', '--fork',
                              'sh', '-ec', '\n'.join(sh)],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             start_new_session=True)
        try:
            p.wait(TRIAL_SECONDS)
        except subprocess.TimeoutExpired:
            return None
        finally:
            try:
                os.killpg(p.pid, 9)  # also the background dbus-daemon
            except ProcessLookupError:
                pass
            p.wait()
        lines = [l for l in (d / 'trial.log').read_text().splitlines() if l.strip()]
        return 'trial start failed: ' + (lines[-1] if lines else f'exit code {p.returncode}')


CACHE = WORK / 'stacks.json'


def _key(bins):
    return [[p, os.stat(p).st_mtime, os.stat(p).st_size] for p in sorted(bins.values())]


def probe(stack):
    """(version, None) if the stack can be used, else (None, reason); trial results are cached."""
    bins, reason = binaries(stack)
    if not bins:
        return None, reason
    try:
        cache = json.loads(CACHE.read_text())
    except (FileNotFoundError, ValueError):
        cache = {}
    key = _key(bins)
    hit = cache.get(stack)
    if not hit or hit['key'] != key:
        reason = trial(stack, bins)
        hit = {'key': key, 'reason': reason, 'version': version(stack, bins)}
        cache[stack] = hit
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(cache, indent=1))
    if hit['reason']:
        return None, hit['reason']
    return hit['version'] or stack, None


def _env_list(name):
    return [s for s in os.environ.get(name, '').replace(',', ' ').split() if s]


def detect(without=None, require=None):
    """The stacks to use: ({stack: version}, {stack: reason it is skipped}). without/require
    default to ODHCPD_LAB_WITHOUT/ODHCPD_LAB_REQUIRE (comma- or space-separated); a required
    stack that can't be used raises StackError."""
    without = set(_env_list('ODHCPD_LAB_WITHOUT') if without is None else without)
    require = set(_env_list('ODHCPD_LAB_REQUIRE') if require is None else require)
    for s in without | require:
        if s not in OPTIONAL:
            raise StackError(f'unknown client stack "{s}" (optional stacks: {", ".join(OPTIONAL)})')
    if without & require:
        raise StackError(f'stack(s) both excluded and required: {", ".join(without & require)}')
    active, skipped = {'openwrt': 'udhcpc + odhcp6c'}, {}
    for s in OPTIONAL:
        if s in without:
            skipped[s] = 'excluded'
            continue
        v, reason = probe(s)
        if v:
            active[s] = v
        elif s in require:
            raise StackError(f'client stack "{s}" is required but {reason}')
        else:
            skipped[s] = reason
    return active, skipped

