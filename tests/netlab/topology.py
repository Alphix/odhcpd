"""The lab's network: nodes (each in its own namespaces) and networks (a bridge each).

See LAB.md for the picture. Interface names are what the node sees: the router's uplink is
`wan`, a client's only interface is `eth0`.
"""
import re

# node -> kind and links {interface name in the node: network}
NODES = {
    'isp': {'kind': 'odhcpd', 'links': {'wan': 'wan'}},
    'router': {'kind': 'odhcpd', 'links': {'wan': 'wan', 'lan': 'lan', 'guest': 'guest'}},
    'relay': {'kind': 'odhcpd', 'links': {'lan': 'lan', 'slan': 'slan'}},
    'guest-copenwrt': {'kind': 'client', 'links': {'eth0': 'guest'}},
    'lan-copenwrt': {'kind': 'client', 'links': {'eth0': 'lan'}},
    'slan-copenwrt': {'kind': 'client', 'links': {'eth0': 'slan'}},
}

NETWORKS = ['wan', 'guest', 'lan', 'slan']

# nodes that forward between their interfaces
ROUTERS = ['router', 'relay']

# isp's stand-in for the rest of the internet: a dummy device with the default routes (without
# a default route, odhcpd announces a router lifetime of 0)
UPSTREAM = {'node': 'isp', 'device': 'internet'}

# the bridge in each network's namespace; its ports are named after the member nodes
BRIDGE = 'br'

# node names are interface names (bridge ports) and hostnames
for _name in NODES:
    assert re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?', _name), \
        f'node name "{_name}" must be a hostname label of at most 15 characters (IFNAMSIZ)'


def members(network):
    """[(node, interface)] attached to a network."""
    return [(node, ifname) for node, n in NODES.items()
            for ifname, net in n['links'].items() if net == network]


def mac(node, ifname):
    """A fixed, locally administered MAC per node interface (reproducible captures)."""
    names = list(NODES)
    ifaces = list(NODES[node]['links'])
    return f'02:00:00:{names.index(node) + 1:02x}:{ifaces.index(ifname) + 1:02x}:01'
