"""The lab's anchor process: runs inside the lab's user, mount and network namespace.

Started by Lab.up() through `unshare --user --map-root-user --mount --net --fork`. It gives the
lab a private /run, starts one holder process per node and per network (each in its own network,
mount and UTS namespace; client nodes of the systemd and nm stacks also in their own user
namespace), connects them with veth pairs, writes the lab's state file and then waits. The nodes
to start are in the run directory's config.json (written by Lab.up()). Everything else (daemons, clients, shells) joins a holder's namespaces with nsenter.
The lab ends when all its processes are gone (Lab.down() kills them).

usage: python3 -m netlab.anchor <run dir>
"""
import json
import os
import signal
import subprocess
import sys
import time

from .stacks import userns_args
from .topology import NODES, NETWORKS, BRIDGE, members, mac


HOLDERS = []


def sh(*cmd):
    subprocess.run(cmd, check=True)


def holder(name, stack=None):
    """Start a process in new network/mount/UTS namespaces (and for the host's client stacks a
    user namespace) with its own /run; return its pid."""
    # /proc/sys/kernel/hostname belongs to the real root, so set the hostname via the syscall
    # sysfs shows the devices of the namespace that mounts it, so each node gets its own; the
    # host's client stacks wait for udev if it is writable
    ro = ' -o ro' if userns_args(stack) else ''
    script = (f'mount -t tmpfs -o mode=0755 tmpfs /run && mkdir -p /run/ubus && '
              f'mount -t sysfs{ro} sysfs /sys && '
              f'{sys.executable} -c "import socket; socket.sethostname(\'{name}\')" && '
              f'exec sleep infinity')
    p = subprocess.Popen(['unshare'] + userns_args(stack) +
                         ['--net', '--mount', '--uts', '--propagation', 'private',
                          'sh', '-c', script])
    HOLDERS.append(p)
    own = os.readlink('/proc/self/ns/net')
    for _ in range(200):
        try:
            if os.readlink(f'/proc/{p.pid}/ns/net') != own and \
               open(f'/proc/{p.pid}/cmdline').read().startswith('sleep'):
                return p.pid
        except FileNotFoundError:
            break
        time.sleep(0.01)
    raise RuntimeError(f'holder for {name} did not start')


def inside(pid, *cmd):
    """Run a command in a holder's namespaces (we are already in the lab's user namespace)."""
    sh('nsenter', '-t', str(pid), '-n', '-m', '-u', '--', *cmd)


def sysctl(pid, key, value):
    inside(pid, 'sh', '-c', f'echo {value} > /proc/sys/{key.replace(".", "/")}')


def main():
    rundir = sys.argv[1]
    sh('mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', '/run')

    nodes = json.load(open(os.path.join(rundir, 'config.json')))['nodes']
    state = {'anchor': os.getpid(), 'userns': os.readlink('/proc/self/ns/user'),
             'nodes': {}, 'networks': {}, 'node_userns': {}}
    for net in NETWORKS:
        pid = holder(f'net-{net}')
        state['networks'][net] = pid
        inside(pid, 'ip', 'link', 'set', 'dev', 'lo', 'up')
        sysctl(pid, 'net.ipv6.conf.all.disable_ipv6', 1)
        inside(pid, 'ip', 'link', 'add', 'name', BRIDGE, 'type', 'bridge', 'mcast_snooping', '0')
        inside(pid, 'ip', 'link', 'set', 'dev', BRIDGE, 'up')
    for node in nodes:
        pid = holder(node, NODES[node].get('stack'))
        state['nodes'][node] = pid
        if NODES[node].get('stack') in ('systemd', 'nm'):
            state['node_userns'][node] = os.readlink(f'/proc/{pid}/ns/user')
        inside(pid, 'ip', 'link', 'set', 'dev', 'lo', 'up')
        for key in ('all', 'default'):
            sysctl(pid, f'net.ipv6.conf.{key}.accept_dad', 0)

    n = 0
    for net in NETWORKS:
        npid = state['networks'][net]
        for node, ifname in members(net, nodes):
            n += 1
            a, b = f'lab{n}a', f'lab{n}b'
            sh('ip', 'link', 'add', 'name', a, 'type', 'veth', 'peer', 'name', b)
            sh('ip', 'link', 'set', 'dev', a, 'netns', str(state['nodes'][node]))
            sh('ip', 'link', 'set', 'dev', b, 'netns', str(npid))
            inside(state['nodes'][node], 'ip', 'link', 'set', 'dev', a, 'name', ifname,
                   'address', mac(node, ifname))
            inside(state['nodes'][node], 'ip', 'link', 'set', 'dev', ifname, 'up')
            inside(npid, 'ip', 'link', 'set', 'dev', b, 'name', node, 'master', BRIDGE, 'up')

    state['ready'] = True
    tmp = os.path.join(rundir, 'state.json.tmp')
    with open(tmp, 'w') as fp:
        json.dump(state, fp, indent=1)
    os.rename(tmp, os.path.join(rundir, 'state.json'))

    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    while True:
        signal.pause()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:  # report setup failures to Lab.up() through the anchor's log
        print(f'anchor: {e}', file=sys.stderr, flush=True)
        for p in HOLDERS:   # don't leave the namespaces behind
            p.kill()
        sys.exit(1)
