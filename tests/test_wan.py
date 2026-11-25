"""The router's uplink: DHCPv4 and DHCPv6 with prefix delegation from isp, and netifd-like
ip6assign of the delegated /56 to lan and guest."""
from conftest import in_prefix


def iface(lab, name):
    return next(i for i in lab.ubus('router', 'network.interface', 'dump')['interface']
                if i['interface'] == name)


def test_router_gets_ipv4(lab):
    addrs = lab.addresses('router', 'wan', family=4)
    assert any(in_prefix(a, '192.0.2.0/24') for a in addrs), addrs
    assert 'default via 192.0.2.1' in lab.run('router', ['ip', '-4', 'route'])


def test_router_gets_a_56(lab):
    prefixes = iface(lab, 'wan6')['ipv6-prefix']
    assert len(prefixes) == 1, prefixes
    p = prefixes[0]
    assert p['mask'] == 56 and in_prefix(p['address'], '2001:db8:100::/40'), p


def test_router_has_an_ipv6_default_route(lab):
    assert lab.run('router', ['ip', '-6', 'route', 'show', 'default']).startswith('default via fe80::')


def test_lan_and_guest_get_a_64_each(lab):
    pd = iface(lab, 'wan6')['ipv6-prefix'][0]
    pd = f"{pd['address']}/{pd['mask']}"
    seen = set()
    for name in ('lan', 'guest'):
        mine = [f"{a['address']}/{a['mask']}" for a in iface(lab, name)['ipv6-prefix-assignment']
                if a['mask'] == 64 and in_prefix(a['address'], pd)]
        assert len(mine) == 1, (name, mine)
        seen.add(mine[0])
        assert any(in_prefix(a, mine[0]) for a in lab.addresses('router', name)), name
    assert len(seen) == 2
