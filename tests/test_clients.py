"""guest-client and lan-client get their addresses from the router."""
import pytest

from conftest import in_prefix

SUBNET4 = {'guest-client': '192.168.2.0/24', 'lan-client': '192.168.1.0/24'}
IFACE = {'guest-client': 'guest', 'lan-client': 'lan'}


@pytest.mark.parametrize('node', ['guest-client', 'lan-client'])
def test_client_gets_dhcpv6_and_slaac(lab, node):
    lan64 = [a for a in lab.addresses('router', IFACE[node]) if a.startswith('2001:db8:')][0]
    # the SLAAC address of the delegated /64 comes with the next RA
    lab.wait_for(lambda: any(a.endswith('/64') and in_prefix(a, lan64) for a in lab.addresses(node)),
                 20, f'{node} to get a SLAAC address in {lan64}')
    addrs = lab.addresses(node)
    assert any(a.endswith('/128') and in_prefix(a, lan64) for a in addrs), addrs
    assert any(a.endswith('/128') and in_prefix(a, 'fd00:1::/48') for a in addrs), addrs
    hostnames = [l.get('hostname') for l in lab.leases('router')[IFACE[node]]]
    assert node in hostnames, hostnames


def test_guest_client_gets_ipv4_from_router(lab):
    addrs = lab.addresses('guest-client', family=4)
    assert any(in_prefix(a, SUBNET4['guest-client']) for a in addrs), addrs
    assert 'guest-client' in [l.get('hostname') for l in lab.leases('router', 4)['guest']]


@pytest.mark.xfail(reason='the relay node runs a DHCPv4 server on lan (odhcpd has no DHCPv4 relay '
                          'yet), so lan-client may get its lease from the relay', strict=False)
def test_lan_client_gets_ipv4_from_router(lab):
    assert 'lan-client' in [l.get('hostname') for l in lab.leases('router', 4)['lan']]
