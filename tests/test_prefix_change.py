"""isp renumbers: the router's /56 changes, lan gets a /64 of the new one, clients follow."""
from conftest import in_prefix


def test_prefix_change_reaches_the_clients(fresh_lab):
    lab = fresh_lab
    old, new = lab.prefix_change()
    new40 = new.replace('::1/40', '::/40')
    old40 = old.replace('::1/40', '::/40')
    lab.client_action('router', 'renew', 'wan6')
    lab.wait_for(lambda: any(in_prefix(a, new40) for a in lab.addresses('router', 'lan')), 20,
                 'the router\'s lan to get a /64 of the new prefix')
    assert not any(in_prefix(a, old40) for a in lab.addresses('router', 'lan'))
    lab.client_action('lan-copenwrt', 'renew', 'dhcp6')
    lab.wait_for(lambda: any(a.endswith('/128') and in_prefix(a, new40)
                             for a in lab.addresses('lan-copenwrt')), 20,
                 'lan-copenwrt to get a lease from the new prefix')
