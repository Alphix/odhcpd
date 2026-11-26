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
}

NETWORKS = ['wan', 'guest', 'lan', 'slan']

# client nodes: one per network and client stack (netlab/stacks.py), <network>-c<stack>
CLIENT_NETWORKS = ['guest', 'lan', 'slan']
CLIENT_STACKS = ['openwrt', 'systemd', 'nm']
for _stack in CLIENT_STACKS:
    for _net in CLIENT_NETWORKS:
        NODES[f'{_net}-c{_stack}'] = {'kind': 'client', 'stack': _stack, 'links': {'eth0': _net}}

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


def members(network, nodes=None):
    """[(node, interface)] attached to a network (of the given nodes, default: all)."""
    return [(node, ifname) for node, n in NODES.items() if nodes is None or node in nodes
            for ifname, net in n['links'].items() if net == network]


def client_node(network, stack):
    return f'{network}-c{stack}'


def mac(node, ifname):
    """A fixed, locally administered MAC per node interface (reproducible captures)."""
    names = list(NODES)
    ifaces = list(NODES[node]['links'])
    return f'02:00:00:{names.index(node) + 1:02x}:{ifaces.index(ifname) + 1:02x}:01'
