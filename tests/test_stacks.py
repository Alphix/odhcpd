"""The client nodes of the host's client stacks (systemd-networkd, NetworkManager), when used.

They get their leases with the fixed identity of netlab/stacks.py (DUID-UUID, IAID 1, the node
name as hostname). They may start before the router has its delegated prefix and then only get
a ULA address; a renew (which reapplies their configuration) adds one from the delegated /64.
"""
import pytest

from conftest import in_prefix
from netlab import stacks

SUBNET4 = {'guest': '192.168.2.0/24', 'lan': '192.168.1.0/24'}
NODES = [f'{net}-c{stack}' for stack in stacks.OPTIONAL for net in ('guest', 'lan')]


def need(lab, node):
    if node not in lab.nodes:
        st = node.split('-c')[1]
        pytest.skip(f'client stack {st}: {lab.config["skipped"].get(st, "not used")}')


def lease(lab, node, family):
    net = node.split('-')[0]
    return next((l for l in lab.leases('router', family).get(net, []) if l.get('hostname') == node),
                None)


@pytest.mark.parametrize('node', NODES)
def test_stack_client_gets_ipv4(lab, node):
    need(lab, node)
    net = node.split('-')[0]
    lab.wait_for(lambda: any(in_prefix(a, SUBNET4[net]) for a in lab.addresses(node, family=4)),
                 30, f'{node} to get an IPv4 address')
    if net == 'lan':
        return  # the relay's DHCPv4 server competes on lan (LAB.md, known issues)
    lab.wait_for(lambda: lease(lab, node, 4), 10, f'the router\'s lease for {node}')
    l = lease(lab, node, 4)
    assert l['duid'] == stacks.duid(node).replace(':', ''), l
    assert l['iaid'] == stacks.IAID, l


@pytest.mark.parametrize('node', NODES)
def test_stack_client_gets_dhcpv6(lab, node):
    need(lab, node)
    net = node.split('-')[0]
    lab.wait_for(lambda: lease(lab, node, 6), 30, f'the router\'s DHCPv6 lease for {node}')
    l = lease(lab, node, 6)
    assert l['duid'] == stacks.duid(node).replace(':', ''), l
    assert l['iaid'] == stacks.IAID, l
    delegated = [a for a in lab.addresses('router', net) if a.startswith('2001:db8:')][0]

    def have():
        return any(a.endswith('/128') and in_prefix(a, delegated) for a in lab.addresses(node))
    if not have():
        lab.client_action(node, 'renew')
    lab.wait_for(have, 30, f'{node} to get a DHCPv6 address in {delegated}')
    assert any(a.endswith('/128') and in_prefix(a, 'fd00:1::/48') for a in lab.addresses(node))
