# odhcpd network lab

A complete home network on your own machine, for testing odhcpd by hand and
(later) automatically. It runs in Linux network namespaces inside a user
namespace, so it needs no root privileges, no VMs and no OpenWrt image, and it
builds everything it needs itself.

## Topology

```mermaid
flowchart TB
    isp{{"isp<br/>odhcpd: DHCPv4, DHCPv6 + PD /56"}}
    wan(("wan"))
    router{{"router<br/>odhcpd: home router<br/>udhcpc + odhcp6c on wan/wan6"}}
    guest(("guest"))
    lan(("lan"))
    relay{{"relay<br/>odhcpd: relay mode"}}
    slan(("slan"))
    go("guest-copenwrt<br/>udhcpc + odhcp6c")
    gs("guest-csystemd<br/>systemd-networkd")
    gn("guest-cnm<br/>NetworkManager")
    lo("lan-copenwrt<br/>udhcpc + odhcp6c")
    ls("lan-csystemd<br/>systemd-networkd")
    ln("lan-cnm<br/>NetworkManager")
    so("slan-copenwrt<br/>udhcpc + odhcp6c")
    ss("slan-csystemd<br/>systemd-networkd")
    sn("slan-cnm<br/>NetworkManager")

    classDef odhcpd fill:#f6c177,stroke:#b4770e,color:#000
    classDef network fill:#a6d8a8,stroke:#3f8f47,color:#000
    classDef client fill:#a9c8f0,stroke:#3d6fb4,color:#000
    classDef optional fill:#dbe7f8,stroke:#3d6fb4,color:#000,stroke-width:2px,stroke-dasharray: 6 4
    class isp,router,relay odhcpd
    class wan,guest,lan,slan network
    class go,lo,so client
    class gs,gn,ls,ln,ss,sn optional

    isp --- wan --- router
    router --- guest
    guest --- go & gs & gn
    router --- lan
    lan --- relay
    lan --- lo & ls & ln
    relay --- slan
    slan --- so & ss & sn
```

Hexagons are the odhcpd nodes and rounded boxes the client nodes, each in its
own network namespace; dashed client nodes are only there when their client
stack is installed (see "Client stacks"). Circles are networks (a Linux bridge
each, which is also where packets can be captured).

* **isp**: odhcpd as the ISP's DHCPv4 and DHCPv6 server, delegating a /56 to
  the router.
* **router**: odhcpd as a typical home router, with a `wan`/`wan6` uplink
  (OpenWrt's DHCP clients: busybox `udhcpc` and `odhcp6c`) and the `lan` and
  `guest` networks, each getting a /64 from the delegated /56.
* **relay**: a second odhcpd relaying DHCPv4, DHCPv6, RA and NDP from `lan` to
  `slan` (transparently: `slan` shares `lan`'s subnets).
* **`<network>-c<stack>`**: the client nodes, one per network and client stack
  (see "Client stacks"): `guest-copenwrt`, `lan-copenwrt` and `slan-copenwrt`
  always, `-csystemd` and `-cnm` when systemd-networkd and NetworkManager are
  installed.

Each odhcpd node has its own ubusd and a minimal stand-in for netifd
(`tests/netifd-stub/`), which provides the interface information odhcpd normally
gets from netifd (`network.interface`, `dump` and update notifications), puts
the interfaces' addresses on their devices and, like netifd's `ip6assign`,
gives interfaces a /64 of the ULA prefix and of delegated prefixes. DHCP client
scripts report their results to it with
`ubus call network.interface update '{"interface": ..., ...}'`.

## Client stacks

Each network has a client node per client stack:

| Stack | Nodes | DHCP clients |
| :---- | :---- | :----------- |
| `openwrt` | `*-copenwrt` | busybox `udhcpc` and `odhcp6c`, as OpenWrt's netifd runs them (built by the lab) |
| `systemd` | `*-csystemd` | `systemd-networkd` from your machine |
| `nm` | `*-cnm` | NetworkManager from your machine (its internal DHCP clients) |

`systemd` and `nm` are optional: they are used when they are installed and
start in a namespace (checked with a short trial start when the lab comes up,
cached in `lab/stacks.json` until the binaries change); otherwise their nodes
are left out and their tests skipped, and `tests/lab status` (and the test
output) says why. `tests/lab up --without STACK` leaves a stack out,
`--require STACK` fails instead of leaving it out (for the tests:
`ODHCPD_LAB_WITHOUT` and `ODHCPD_LAB_REQUIRE`, comma-separated). Other
binaries, e.g. self-built ones, can be used with `ODHCPD_LAB_NETWORKD`,
`ODHCPD_LAB_NETWORKCTL`, `ODHCPD_LAB_NETWORKMANAGER` and `ODHCPD_LAB_NMCLI`.

These nodes run their stack's daemon with a private D-Bus system bus (for
`networkctl` and `nmcli`), a read-only `/sys` (there is no udev in the lab) and
their own configuration in `lab/run/<name>/<node>/<stack>/` (also bind-mounted
over the host's `/etc/systemd/network`, `/var/lib/NetworkManager` and
`/etc/machine-id` inside the node, so the host's own configuration doesn't
apply). Each has a fixed identity: a machine-id and a DUID-UUID derived from the
node name, IAID 1 (DHCPv4 uses the RFC 4361 client identifier with the same
DUID and IAID) and the node name as hostname. The `openwrt` nodes have fixed
MAC addresses, so their DUID-LLs are fixed too.

networkd only drops its privileges when started as root, and NetworkManager
insists on root, so each of these nodes also has its own user namespace,
nested in the lab's: in `*-csystemd` you are the `systemd-network` user (with
all capabilities in the node), in `*-cnm` root.

## Addressing

| Network | IPv4 | IPv6 |
| :------ | :--- | :--- |
| wan | 192.0.2.0/24 | 2001:db8:ff::/64; isp delegates /56s from 2001:db8:100::/40 |
| lan | 192.168.1.0/24 | a /64 of the delegated /56, a /64 of fd00:1::/48 |
| guest | 192.168.2.0/24 | a /64 of the delegated /56, a /64 of fd00:1::/48 |
| slan | (lan's subnet, relayed) | (lan's /64s, relayed) |

## Crafted and malformed packets

The real clients only send correct packets. `probe` sends hand-made DHCPv6,
DHCPv4 or RS messages from any node and shows the decoded replies; `fuzz` sends
seeded random mutations of valid messages and then checks that every odhcpd is
still running and still answers:

```
tests/lab <node> probe [--dev DEV] dhcp6|dhcp4|rs <step> [<step> ...]
tests/lab <node> fuzz [--dev DEV] dhcp6|dhcp4|rs <count> [seed]
```

Packets are built byte by byte (so any option or length can be wrong) and sent
as raw frames, so the probe doesn't disturb the node's real clients. Each probe
is saved as `lab/run/<name>/<node>/probe-*.pcap`. Steps look like
`sol:rc,na=1`, `req`, `ren`, `conf:na=1/2001:db8::1`, `inf`; flags include
`opt=CODE:HEX` (a raw option), `rawopt=HEX`, `raw=HEX` (the whole message),
`trid=HEX`, `nosid`, `duid=HEX`, `relay` (wrapped in a Relay-Forward) and
`as=client` (the node's real client's identity: its MAC, DUID and IAID, and its
current leases). The full syntax is at the top of `tests/netlab/probe.py`.
Example: the Windows 10 Confirm from odhcpd issue #447 (one IA_NA per address,
all with the same IAID), sent with lan-copenwrt's identity:

```
tests/lab lan-copenwrt probe dhcp6 "conf:as=client,na=client/<lease 1>,na=client/<lease 2>"
```

## Automated tests

```
python3 -m pytest -c tests/pytest.ini tests
```

builds what's missing, then runs the tests in `tests/test_*.py` (about four
minutes). They use the same Python library as `tests/lab` (`tests/netlab/`),
so whatever you do by hand can become a test: the `lab` fixture starts one lab
per test module, `fresh_lab` one per test, each under a unique name (their
files stay in `lab/run/pytest-*/`), and both wait until the network has
settled. A test marked `@pytest.mark.requires('<commit subject>')` is skipped
unless that odhcpd commit is in the checkout; behaviour odhcpd doesn't have yet
is marked `xfail`. The CI runs the same build and tests (`.github/workflows/ci.yml`,
job "Network lab tests").

## Known issues (in odhcpd, found with the lab)

* The relay node is meant to relay DHCPv4 (`option dhcpv4 'relay'`), which
  odhcpd doesn't support yet. Instead it runs a DHCPv4 server on `lan` (pool
  from its own address), competing with the router; `slan-copenwrt` gets no
  IPv4 address.
* DHCPv6 through the relay doesn't reach `slan-copenwrt` yet (it gets SLAAC
  addresses through the relayed RAs, but no DHCPv6 lease). The relay also
  treats other clients' messages it sees on `lan` as relay replies.
* isp delegates from an address on its `wan` interface (`2001:db8:100::1/40`),
  so it also announces `2001:db8:100::/64` as on-link there.

## Requirements

From your distribution: a C compiler, `cmake`, `make`, `git`, `pkg-config`,
Python 3 with `scapy` (and `pytest` for the tests), `iproute2`, `util-linux`
(`unshare`, `nsenter`) and kernel support for bridges and veth devices.
`tcpdump` is optional (packet captures), as are systemd-networkd and
NetworkManager (with `dbus-daemon`; see "Client stacks"). Unprivileged user namespaces must be
allowed (the default on most distributions; on Ubuntu 24.04 and later:
`sysctl kernel.apparmor_restrict_unprivileged_userns=0`).

`tests/lab check` reports anything that is missing.

## Building

```
tests/lab build
```

downloads and builds everything else into the lab's work directory: json-c,
libnl-tiny, libubox, ubus, uci (as in odhcpd's CI), odhcp6c, busybox with only
`udhcpc`, and odhcpd from this checkout. Later runs only rebuild what changed
(odhcpd incrementally). Options:

* `--asan`: build odhcpd with AddressSanitizer and UndefinedBehaviorSanitizer
* `--ref NAME=REF`: pin a dependency to a git ref, e.g. `--ref libubox=<sha>`
* `--only NAME`: build only one component
* `--clean`: rebuild everything (downloads are kept)

## Using the lab

```
tests/lab up                     # build if needed, start the lab, show its status
                                 # (--without/--require STACK: see "Client stacks")
tests/lab status                 # nodes with their addresses, networks with their members
tests/lab <node> shell           # a shell in a node (root inside the lab, not on your machine)
tests/lab <node> exec <cmd...>   # run one command in a node
tests/lab <node> log [-f]        # the node's logs
tests/lab down                   # stop the lab (its logs stay in lab/run/<name>/)

tests/lab <odhcpd node> ubus <args...>   # e.g. ubus call dhcp ipv6leases
tests/lab <odhcpd node> reload           # odhcpd rereads its config (SIGHUP)
tests/lab <odhcpd node> restart          # restart odhcpd
tests/lab <odhcpd node> config           # edit the node's odhcpd config, then reload
```

```
tests/lab <client node> renew | release | restart [4|6]    udhcpc (4) and/or odhcp6c (6),
                                                           or networkd/NetworkManager
tests/lab router wan|wan6 renew | release | restart | log  the router's uplink clients
tests/lab isp prefix-change                                isp delegates from its other pool
tests/lab <network> capture [tcpdump args...]              tcpdump on the network's bridge
tests/lab clients renew | release | restart [4|6]          all client nodes (with 4|6: the
                                                           openwrt ones)
tests/lab servers log [-f]                                 the three odhcpd logs
```

`renew` and `release` send SIGUSR1/SIGUSR2 to the clients (both udhcpc and
odhcp6c renew/release on those). On the `systemd` and `nm` nodes, which have no
DHCPv6 renew command, `renew` reapplies the configuration (`networkctl
reconfigure`, `nmcli connection up`) and `release` takes `eth0` down (both send
releases); `restart` restarts networkd or NetworkManager. Their logs are
`networkd.log` and `nm.log`, plus `dbus.log`. The OpenWrt clients run as on
OpenWrt: the router's
`wan`/`wan6` report to its netifd stand-in, the client nodes' script
(`tests/scripts/dhcp-client-script`) applies addresses and routes itself; the
kernel's own SLAAC is off, odhcp6c handles RAs. Their logs are `wan.log`,
`wan6.log` (router) and `dhcp4.log`, `dhcp6.log` (client nodes).

The odhcpd nodes' configurations come from `tests/configs/<node>/` (`dhcp` is the
UCI config, `netifd.json` the netifd stand-in's interfaces) and are copied into
`lab/run/<name>/<node>/` when the lab starts; `config` edits that copy.

Nodes: `isp`, `router`, `relay` and the client nodes `guest-c<stack>`,
`lan-c<stack>`, `slan-c<stack>` (`openwrt`, and `systemd` and `nm` if used).
Networks (`shell`/`exec` run in the network's bridge namespace, e.g. for
captures): `wan`, `guest`, `lan`, `slan`. `--name NAME` (before the other
arguments) runs a separate lab; several labs can run at the same time.

How it works: `up` starts an anchor process in a new user namespace (you are
root inside it, but only for the lab's namespaces) with its own mount and
network namespace and a private `/run`. Each node and each network gets a
holder process in its own network, mount and UTS namespace (own `/run`, so its
own ubusd later, and its own hostname). veth pairs connect the nodes to the
networks' bridges. Commands join a node with `nsenter`. `down` stops every
process in the lab's user namespace, which also removes all its namespaces.

## Work directory

Everything the lab downloads, builds or produces stays in `lab/` at the top of
the checkout (ignored by git; `ODHCPD_LAB_DIR` moves it elsewhere):

| Directory | Contents |
| :-------- | :------- |
| `lab/src/` | downloaded sources |
| `lab/build/` | build trees (`build.log` has the build output) |
| `lab/prefix/` | built libraries and programs, only used by the lab |
| `lab/run/<name>/` | configs, logs, pids and captures of a lab |

`tests/lab clean` removes the run state, `tests/lab clean --all` the whole
work directory. Nothing is installed outside it.
