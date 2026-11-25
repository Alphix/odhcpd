"""The lab's network: nodes (each in its own namespaces) and networks (a bridge each).

See LAB.md for the picture. Interface names are what the node sees: the router's uplink is
`wan`, a client's only interface is `eth0`.
"""

# node -> kind and links {interface name in the node: network}
NODES = {
    'isp': {'kind': 'odhcpd', 'links': {'wan': 'wan'}},
    'router': {'kind': 'odhcpd', 'links': {'wan': 'wan', 'lan': 'lan', 'guest': 'guest'}},
    'relay': {'kind': 'odhcpd', 'links': {'lan': 'lan', 'sublan': 'sublan'}},
    'guest-client': {'kind': 'client', 'links': {'eth0': 'guest'}},
    'lan-client': {'kind': 'client', 'links': {'eth0': 'lan'}},
    'sublan-client': {'kind': 'client', 'links': {'eth0': 'sublan'}},
}

NETWORKS = ['wan', 'guest', 'lan', 'sublan']

# nodes that forward between their interfaces
ROUTERS = ['router', 'relay']

# the bridge in each network's namespace; its ports are named after the member nodes
BRIDGE = 'br'


def members(network):
    """[(node, interface)] attached to a network."""
    return [(node, ifname) for node, n in NODES.items()
            for ifname, net in n['links'].items() if net == network]


def mac(node, ifname):
    """A fixed, locally administered MAC per node interface (reproducible captures)."""
    names = list(NODES)
    ifaces = list(NODES[node]['links'])
    return f'02:00:00:{names.index(node) + 1:02x}:{ifaces.index(ifname) + 1:02x}:01'
