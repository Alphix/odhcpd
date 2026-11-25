"""pytest fixtures for the odhcpd network lab (LAB.md).

lab: one lab per test module, started once and torn down afterwards; fresh_lab: one per test.
Each has a unique name, so test runs and manually started labs don't interfere. The lab's
files (logs, configs, pcaps) stay in lab/run/<name>/ for inspection.
"""
import ipaddress
import os
import subprocess
import time

import pytest

from netlab import build
from netlab.lab import Lab
from netlab.paths import REPO

_counter = iter(range(1, 1 << 30))


def pytest_configure(config):
    config.addinivalue_line('markers', 'requires(subject): needs this odhcpd commit (by subject)')


def subjects():
    out = subprocess.run(['git', '-C', str(REPO), 'log', '--format=%s'], capture_output=True,
                         text=True).stdout
    return set(out.splitlines())


def pytest_collection_modifyitems(config, items):
    have = None
    for item in items:
        for mark in item.iter_markers('requires'):
            have = subjects() if have is None else have
            if mark.args[0] not in have:
                item.add_marker(pytest.mark.skip(reason=f'needs odhcpd commit "{mark.args[0]}"'))


@pytest.fixture(scope='session', autouse=True)
def built():
    missing = build.check_requirements(need_pytest=True)
    if missing:
        pytest.exit('missing requirements: ' + ', '.join(missing))
    build.build()


def settled(lab):
    """Wait until the network is up and stable: the router has its /56, and both direct clients
    have an IPv4 address and exactly the DHCPv6 addresses the router has leased to them (with a
    /64 of the delegated prefix; odhcp6c starts over once that prefix appears in the RAs)."""
    iface = {'guest-client': 'guest', 'lan-client': 'lan'}

    def ready():
        dump = lab.ubus('router', 'network.interface', 'dump')['interface']
        wan6 = next(i for i in dump if i['interface'] == 'wan6')
        if not wan6.get('ipv6-prefix'):
            return False
        pd = f"{wan6['ipv6-prefix'][0]['address']}/{wan6['ipv6-prefix'][0]['mask']}"
        leases = lab.leases('router')
        for node, ifc in iface.items():
            if not lab.addresses(node, family=4):
                return False
            have = {a.split('/')[0] for a in lab.addresses(node) if a.endswith('/128')}
            leased = {a['address'] for l in leases.get(ifc, []) if l.get('hostname') == node
                      for a in l.get('ipv6-addr', [])}
            if not have or have != leased or not any(in_prefix(a, pd) for a in have):
                return False
        return True
    # odhcp6c releases and starts over once the delegated prefix shows up in the RAs, so the
    # condition has to hold for a while
    stable_since = [None]

    def stable():
        if not ready():
            stable_since[0] = None
            return False
        stable_since[0] = stable_since[0] or time.time()
        return time.time() - stable_since[0] >= 5
    lab.wait_for(stable, timeout=60, what='the network to settle')
    return lab


def new_lab(tag):
    lab = Lab(f'pytest-{os.getpid()}-{tag}-{next(_counter)}')
    lab.up()
    return lab


@pytest.fixture(scope='module')
def lab(request):
    lab = new_lab(request.module.__name__.replace('test_', ''))
    try:
        yield settled(lab)
    finally:
        lab.down()


@pytest.fixture
def fresh_lab(request):
    lab = new_lab(request.node.name[:20])
    try:
        yield settled(lab)
    finally:
        lab.down()


def in_prefix(addr, prefix):
    return ipaddress.ip_address(addr.split('/')[0]) in ipaddress.ip_network(prefix, strict=False)
