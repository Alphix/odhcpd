"""Crafted and malformed packets (tests/netlab/probe.py)."""
import pytest


def lease_addrs(lab, node):
    return [a.split('/')[0] for a in lab.addresses(node) if a.endswith('/128')]


def test_confirm_with_the_clients_identity_succeeds(lab):
    r = lab.probe('lan-client', 'dhcp6', ['conf:as=client'])[0]
    assert [(x['msg'], x['status']) for x in r['replies']] == [('rep', 0)], r


@pytest.mark.requires('dhcpv6-ia: reply UnspecFail to Confirms with duplicate IA_NA IAIDs')
def test_win10_confirm_with_duplicate_iaids(lab):
    """odhcpd#447: one IA_NA per address, all with the same IAID."""
    # a lease from the ULA and one from the delegated prefix (which can come a bit later)
    lab.wait_for(lambda: len(lease_addrs(lab, 'lan-client')) >= 2, 20, 'two leases on lan-client')
    a1, a2 = lease_addrs(lab, 'lan-client')[:2]
    r = lab.probe('lan-client', 'dhcp6', [f'conf:as=client,na=client/{a1},na=client/{a2}'])[0]
    assert [(x['msg'], x['status']) for x in r['replies']] == [('rep', 1)], r


@pytest.mark.parametrize('kind', ['dhcp6', 'dhcp4', 'rs'])
def test_fuzz(lab, kind):
    r = lab.fuzz('guest-client', kind, 200, seed=1)
    assert all(r['alive'].values()), r
    assert r['answered'], r
