"""slan-copenwrt, behind the relay node (transparent relay: slan shares lan's subnets)."""
import pytest

from conftest import in_prefix


def lan64(lab):
    return [a for a in lab.addresses('router', 'lan') if a.startswith('2001:db8:')][0]


def test_relayed_ra_gives_slaac_addresses(lab):
    prefix = lan64(lab)
    lab.wait_for(lambda: any(a.endswith('/64') and in_prefix(a, prefix)
                             for a in lab.addresses('slan-copenwrt')), 20, 'a SLAAC address')


@pytest.mark.xfail(reason='DHCPv6 through the relay does not reach slan-copenwrt yet', strict=True)
def test_dhcpv6_lease_through_the_relay(lab):
    prefix = lan64(lab)
    lab.wait_for(lambda: any(a.endswith('/128') and in_prefix(a, prefix)
                             for a in lab.addresses('slan-copenwrt')), 15, 'a DHCPv6 lease')


@pytest.mark.xfail(reason='odhcpd has no DHCPv4 relay yet', strict=True)
def test_ipv4_through_the_relay(lab):
    lab.wait_for(lambda: lab.addresses('slan-copenwrt', family=4), 15, 'an IPv4 address')
