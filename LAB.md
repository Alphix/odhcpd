# odhcpd network lab

A complete home network on your own machine, for testing odhcpd by hand and
(later) automatically. It runs in Linux network namespaces inside a user
namespace, so it needs no root privileges, no VMs and no OpenWrt image, and it
builds everything it needs itself.

*Status: under construction. Implemented so far: `tests/lab build`, the network
(namespaces, bridges, links), the three odhcpd nodes (with ubusd and the netifd
stand-in) and the commands below. Not yet: the DHCP clients (router uplink and
the three client nodes).*

## Topology

```mermaid
flowchart TB
    isp["isp<br/>odhcpd: DHCPv4, DHCPv6 + PD /56"]
    wan(("wan"))
    router["router<br/>odhcpd: home router<br/>udhcpc + odhcp6c on wan/wan6"]
    guest(("guest"))
    lan(("lan"))
    relay["relay<br/>odhcpd: relay mode"]
    sublan(("sublan"))
    gc["guest-client<br/>udhcpc + odhcp6c"]
    lc["lan-client<br/>udhcpc + odhcp6c"]
    sc["sublan-client<br/>udhcpc + odhcp6c"]

    isp --- wan --- router
    router --- guest --- gc
    router --- lan
    lan --- lc
    lan --- relay
    relay --- sublan --- sc
```

Round nodes are networks (a Linux bridge each, which is also where packets can
be captured); the others are nodes, each in its own network namespace.

* **isp**: odhcpd as the ISP's DHCPv4 and DHCPv6 server, delegating a /56 to
  the router.
* **router**: odhcpd as a typical home router, with a `wan`/`wan6` uplink
  (OpenWrt's DHCP clients: busybox `udhcpc` and `odhcp6c`) and the `lan` and
  `guest` networks, each getting a /64 from the delegated /56.
* **relay**: a second odhcpd relaying DHCPv4, DHCPv6, RA and NDP from `lan` to
  `sublan` (transparently: `sublan` shares `lan`'s subnets).
* **guest-client**, **lan-client**, **sublan-client**: DHCPv4/DHCPv6 clients
  (`udhcpc` and `odhcp6c`).

Each odhcpd node has its own ubusd and a minimal stand-in for netifd
(`tests/netifd-stub/`), which provides the interface information odhcpd normally
gets from netifd (`network.interface`, `dump` and update notifications), puts
the interfaces' addresses on their devices and, like netifd's `ip6assign`,
gives interfaces a /64 of the ULA prefix and of delegated prefixes. DHCP client
scripts report their results to it with
`ubus call network.interface update '{"interface": ..., ...}'`.

## Addressing

| Network | IPv4 | IPv6 |
| :------ | :--- | :--- |
| wan | 192.0.2.0/24 | 2001:db8:ff::/64; isp delegates /56s from 2001:db8:100::/40 |
| lan | 192.168.1.0/24 | a /64 of the delegated /56, a /64 of fd00:1::/48 |
| guest | 192.168.2.0/24 | a /64 of the delegated /56, a /64 of fd00:1::/48 |
| sublan | (lan's subnet, relayed) | (lan's /64s, relayed) |

## Requirements

From your distribution: a C compiler, `cmake`, `make`, `git`, `pkg-config`,
Python 3 with `scapy` (and `pytest` for the tests), `iproute2`, `util-linux`
(`unshare`, `nsenter`) and kernel support for bridges and veth devices.
`tcpdump` is optional (packet captures). Unprivileged user namespaces must be
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

The odhcpd nodes' configurations come from `tests/configs/<node>/` (`dhcp` is the
UCI config, `netifd.json` the netifd stand-in's interfaces) and are copied into
`lab/run/<name>/<node>/` when the lab starts; `config` edits that copy.

Nodes: `isp`, `router`, `relay`, `guest-client`, `lan-client`, `sublan-client`.
Networks (`shell`/`exec` run in the network's bridge namespace, e.g. for
captures): `wan`, `guest`, `lan`, `sublan`. `--name NAME` (before the other
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
