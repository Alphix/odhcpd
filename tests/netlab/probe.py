#!/usr/bin/env python3
"""Crafted (and malformed) DHCPv6 / DHCPv4 / RS exchanges from inside a lab node.

Runs in the node's namespaces (tests/lab <node> probe ...). Packets are built as bytes (so any
option, length or field can be wrong on purpose); scapy only frames, sends (layer 2) and sniffs.
That keeps the probe out of the real clients' way (they hold the DHCP ports).

usage: probe.py <dev> <pcap> dhcp6|dhcp4|rs <step> [<step> ...]
       probe.py <dev> <pcap> fuzz dhcp6|dhcp4|rs <count> <seed>

DHCPv6 steps: <msg>[:flag,flag,...], msg = sol req ren reb rel dec conf inf
  na=IAID[/ADDR[/ADDR...]]   IA_NA (repeatable; same IAID twice is allowed, e.g. #447)
  pd=IAID[/LEN[/PREFIX]]     IA_PD (repeatable)
  rc                         Rapid Commit
  duid=HEX                   client DUID (default: DUID-LL of the probe's MAC)
  sid=HEX | nosid            server ID (default: the last one received)
  oro=CODE[/CODE...]         Option Request (default 23/24)
  opt=CODE:HEX               append a raw option (repeatable; HEX may be empty)
  rawopt=HEX                 append raw bytes after the options (e.g. a truncated option)
  raw=HEX                    the whole DHCPv6 message instead of building one
  trid=HEX                   transaction ID (default: random)
  relay[=LINKADDR]           wrap in a Relay-Forward (sent from port 547, as a relay)
  as=client                  the node's identity: its MAC and DUID-LL; without na=/pd=, also
                             its IA_NA (odhcp6c's IAID) with its current /128 leases
  na=client/...              odhcp6c's IAID of the node (for borrowed-identity IAs)
  wait=SEC                   sleep before sending; timeout=SEC to wait for replies (default 2)
  A step without na=/pd= reuses the previous step's IAs (with what the last reply assigned).
DHCPv4 steps: disc req rel dec inf, flags mac=MAC ip=ADDR ciaddr=ADDR sid=ADDR|nosid
  cid=HEX opt=CODE:HEX raw=HEX as=client timeout=SEC
RS steps: rs, flags opt=TYPE:HEX mac=MAC timeout=SEC

Prints one JSON line per step: {"step": ..., "sent": hex, "replies": [decoded ...]}.
"""
import hashlib
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time

from scapy.all import (AsyncSniffer, Ether, IP, IPv6, UDP, Raw, ICMPv6ND_RS, sendp, wrpcap,
                       conf as scapy_conf)

scapy_conf.verb = 0

MSG6 = {'sol': 1, 'adv': 2, 'req': 3, 'conf': 4, 'ren': 5, 'reb': 6, 'rep': 7, 'rel': 8,
        'dec': 9, 'reconf': 10, 'inf': 11, 'relay-forw': 12, 'relay-repl': 13}
MSG6_NAMES = {v: k for k, v in MSG6.items()}
MSG4 = {'disc': 1, 'offer': 2, 'req': 3, 'dec': 4, 'ack': 5, 'nak': 6, 'rel': 7, 'inf': 8}
MSG4_NAMES = {v: k for k, v in MSG4.items()}
ALL_DHCP = 'ff02::1:2'


def opt6(code, data):
    return struct.pack('!HH', code, len(data)) + data


def parse_opts6(buf):
    out, i = [], 0
    while i + 4 <= len(buf):
        code, length = struct.unpack('!HH', buf[i:i + 4])
        out.append((code, buf[i + 4:i + 4 + length]))
        i += 4 + length
    return out


def decode6(msg):
    """A DHCPv6 message (or relay message, unwrapped) as a dict."""
    if not msg:
        return None
    mtype = msg[0]
    if mtype in (12, 13):
        d = {'msg': MSG6_NAMES.get(mtype, mtype), 'hops': msg[1],
             'link': socket.inet_ntop(socket.AF_INET6, msg[2:18]),
             'peer': socket.inet_ntop(socket.AF_INET6, msg[18:34])}
        for code, data in parse_opts6(msg[34:]):
            if code == 9:
                d['inner'] = decode6(data)
            else:
                d.setdefault('options', {})[str(code)] = data.hex()
        return d
    d = {'msg': MSG6_NAMES.get(mtype, mtype), 'trid': msg[1:4].hex(), 'status': None, 'ia': [],
         'options': {}}
    for code, data in parse_opts6(msg[4:]):
        if code in (3, 25) and len(data) >= 12:
            ia = {'type': 'na' if code == 3 else 'pd', 'iaid': data[:4].hex(),
                  't1': struct.unpack('!I', data[4:8])[0], 't2': struct.unpack('!I', data[8:12])[0],
                  'addrs': [], 'status': None}
            for sc, sd in parse_opts6(data[12:]):
                if sc == 5 and len(sd) >= 24:
                    ia['addrs'].append({'address': socket.inet_ntop(socket.AF_INET6, sd[:16]),
                                        'preferred': struct.unpack('!I', sd[16:20])[0],
                                        'valid': struct.unpack('!I', sd[20:24])[0]})
                elif sc == 26 and len(sd) >= 25:
                    ia['addrs'].append({'prefix': socket.inet_ntop(socket.AF_INET6, sd[9:25]),
                                        'len': sd[8],
                                        'preferred': struct.unpack('!I', sd[:4])[0],
                                        'valid': struct.unpack('!I', sd[4:8])[0]})
                elif sc == 13 and len(sd) >= 2:
                    ia['status'] = struct.unpack('!H', sd[:2])[0]
            d['ia'].append(ia)
        elif code == 13 and len(data) >= 2:
            d['status'] = struct.unpack('!H', data[:2])[0]
        elif code == 2:
            d['serverid'] = data.hex()
        elif code == 1:
            d['clientid'] = data.hex()
        else:
            d['options'][str(code)] = data.hex()
    return d


def flags_of(spec):
    msg, _, rest = spec.partition(':')
    flags = []
    for f in rest.split(',') if rest else []:
        k, _, v = f.partition('=')
        flags.append((k, v))
    return msg, flags


def odhcp6c_iaid(dev):
    """The IAID odhcp6c uses on dev: the first 4 bytes of the MD5 of the interface name."""
    return hashlib.md5(dev.encode()).digest()[:4]


def own_mac(dev):
    return open(f'/sys/class/net/{dev}/address').read().strip()


def node_globals(dev):
    """The node's current global /128 addresses on dev (DHCPv6 leases)."""
    out = subprocess.run(['ip', '-6', '-o', 'addr', 'show', 'dev', dev, 'scope', 'global'],
                         capture_output=True, text=True).stdout.split('\n')
    return [l.split()[3].split('/')[0] for l in out if l and '/128' in l]


def lladdr(dev):
    out = subprocess.run(['ip', '-6', '-o', 'addr', 'show', 'dev', dev, 'scope', 'link'],
                         capture_output=True, text=True).stdout.split()
    return out[out.index('inet6') + 1].split('/')[0]


class Prober:
    def __init__(self, dev, pcap):
        self.dev, self.pcap = dev, pcap
        self.mac = own_mac(dev)
        # by default a probe identity distinct from the node's real client
        self.probe_mac = '02:aa:' + self.mac[6:]
        self.sid = None
        self.ias = []        # [(code, iaid bytes, [sub-option bytes])]
        self.frames = []
        self.dry = False     # build only (fuzz seeds), don't send

    def exchange(self, frame, match, timeout):
        if self.dry:
            return []
        sn = AsyncSniffer(iface=self.dev, store=True, filter='udp or icmp6')
        sn.start()
        time.sleep(0.1)
        sendp(frame, iface=self.dev)
        time.sleep(timeout)
        pkts = sn.stop() or []
        self.frames.append(frame)
        self.frames.extend(pkts)
        return [p for p in pkts if match(p)]

    # ---- DHCPv6 ----------------------------------------------------------------------------
    def dhcp6(self, spec):
        msg, flags = flags_of(spec)
        mac, duid, trid = self.probe_mac, None, os.urandom(3)
        nosid, sid, oro = False, None, [23, 24]
        extra, rawopt, raw, relay, timeout = b'', b'', None, None, 2.0
        ias, explicit_ias, rc, as_client = [], False, False, False
        for k, v in flags:
            if k == 'as' and v == 'client':
                as_client = True
                mac = self.mac
                duid = bytes.fromhex('00030001' + mac.replace(':', ''))
            elif k == 'na' or k == 'pd':
                explicit_ias = True
                parts = v.split('/')
                iaid = odhcp6c_iaid(self.dev) if parts[0] == 'client' else struct.pack('!I', int(parts[0] or 1))
                subs = []
                if k == 'na':
                    subs = [opt6(5, socket.inet_pton(socket.AF_INET6, a) + bytes(8)) for a in parts[1:]]
                    ias.append((3, iaid, subs))
                else:
                    if len(parts) > 1:
                        plen = int(parts[1])
                        pfx = socket.inet_pton(socket.AF_INET6, parts[2]) if len(parts) > 2 else bytes(16)
                        subs = [opt6(26, bytes(8) + bytes([plen]) + pfx)]
                    ias.append((25, iaid, subs))
            elif k == 'rc':
                rc = True
            elif k == 'duid':
                duid = bytes.fromhex(v)
            elif k == 'sid':
                sid = bytes.fromhex(v)
            elif k == 'nosid':
                nosid = True
            elif k == 'oro':
                oro = [int(x) for x in v.split('/') if x]
            elif k == 'opt':
                code, _, data = v.partition(':')
                extra += opt6(int(code), bytes.fromhex(data))
            elif k == 'rawopt':
                rawopt += bytes.fromhex(v)
            elif k == 'raw':
                raw = bytes.fromhex(v)
            elif k == 'trid':
                trid = bytes.fromhex(v)[:3]
            elif k == 'relay':
                relay = v or None
                relay = relay if relay is not None else ''
            elif k == 'wait':
                time.sleep(float(v))
            elif k == 'timeout':
                timeout = float(v)
            elif k == 'mac':
                mac = v
        if duid is None:
            duid = bytes.fromhex('00030001' + mac.replace(':', ''))
        if as_client and not explicit_ias:
            # the real client's binding: its IA_NA with its current leased addresses
            ias = [(3, odhcp6c_iaid(self.dev),
                    [opt6(5, socket.inet_pton(socket.AF_INET6, a) + bytes(8))
                     for a in node_globals(self.dev)])]
            explicit_ias = True
        if not explicit_ias:
            ias = self.ias
        self.ias = ias

        if raw is not None:
            payload = raw
        else:
            payload = bytes([MSG6[msg]]) + trid + opt6(1, duid) + opt6(8, b'\0\0')
            if msg not in ('sol', 'reb', 'conf', 'inf') and not nosid:
                use = sid or self.sid
                if use:
                    payload += opt6(2, use)
            if rc:
                payload += opt6(14, b'')
            if oro:
                payload += opt6(6, b''.join(struct.pack('!H', c) for c in oro))
            for code, iaid, subs in ias:
                payload += opt6(code, iaid + bytes(8) + b''.join(subs))
            payload += extra + rawopt

        src = lladdr(self.dev)
        sport, dport = 546, 547
        if relay is not None:
            link = socket.inet_pton(socket.AF_INET6, relay) if relay else bytes(16)
            peer = socket.inet_pton(socket.AF_INET6, src)
            payload = bytes([12, 0]) + link + peer + opt6(9, payload)
            sport = 547
        frame = (Ether(src=mac, dst='33:33:00:01:00:02') /
                 IPv6(src=src, dst=ALL_DHCP, hlim=1 if relay is None else 32) /
                 UDP(sport=sport, dport=dport) / Raw(payload))
        replies = self.exchange(frame, lambda p: p.haslayer(UDP) and p[UDP].sport == 547 and
                                p[UDP].dport == sport and bytes(p[UDP].payload)[:1] != b'\x0c', timeout)
        out = []
        for p in replies:
            d = decode6(bytes(p[UDP].payload))
            if d is None:
                continue
            inner = d.get('inner', d)
            if relay is None and inner.get('trid') != trid.hex():
                continue
            if inner.get('serverid'):
                self.sid = bytes.fromhex(inner['serverid'])
            # carry assigned addresses/prefixes into the next step's IAs
            new = []
            for ia in inner.get('ia', []):
                code = 3 if ia['type'] == 'na' else 25
                subs = []
                for a in ia['addrs']:
                    if 'address' in a:
                        subs.append(opt6(5, socket.inet_pton(socket.AF_INET6, a['address']) + bytes(8)))
                    else:
                        subs.append(opt6(26, bytes(8) + bytes([a['len']]) +
                                         socket.inet_pton(socket.AF_INET6, a['prefix'])))
                new.append((code, bytes.fromhex(ia['iaid']), subs))
            if new and not explicit_ias:
                self.ias = new
            elif new:
                self.ias = new
            out.append(d)
        return {'step': spec, 'sent': payload.hex(), 'replies': out}

    # ---- DHCPv4 ----------------------------------------------------------------------------
    def dhcp4(self, spec):
        msg, flags = flags_of(spec)
        mac, ip, ciaddr, sid, nosid = self.probe_mac, None, '0.0.0.0', None, False
        cid, extra, raw, timeout = None, b'', None, 2.0
        for k, v in flags:
            if k == 'as' and v == 'client':
                mac = self.mac
            elif k == 'mac':
                mac = v
            elif k == 'ip':
                ip = v
            elif k == 'ciaddr':
                ciaddr = v
            elif k == 'sid':
                sid = v
            elif k == 'nosid':
                nosid = True
            elif k == 'cid':
                cid = bytes.fromhex(v)
            elif k == 'opt':
                code, _, data = v.partition(':')
                d = bytes.fromhex(data)
                extra += bytes([int(code), len(d)]) + d
            elif k == 'raw':
                raw = bytes.fromhex(v)
            elif k == 'timeout':
                timeout = float(v)
        xid = os.urandom(4)
        chaddr = bytes.fromhex(mac.replace(':', ''))
        if raw is not None:
            payload = raw
        else:
            payload = struct.pack('!BBBB4sHH4s4s4s4s16s64s128s', 1, 1, 6, 0, xid, 0, 0x8000,
                                  socket.inet_aton(ciaddr), bytes(4), bytes(4), bytes(4),
                                  chaddr + bytes(10), b'', b'')
            payload += b'\x63\x82\x53\x63' + bytes([53, 1, MSG4[msg]])
            if ip:
                payload += bytes([50, 4]) + socket.inet_aton(ip)
            use = sid or getattr(self, 'sid4', None)
            if use and not nosid and msg in ('req', 'rel', 'dec'):
                payload += bytes([54, 4]) + socket.inet_aton(use)
            if cid:
                payload += bytes([61, len(cid)]) + cid
            payload += extra + b'\xff'
        frame = (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
                 IP(src=ciaddr, dst='255.255.255.255') / UDP(sport=68, dport=67) / Raw(payload))
        replies = self.exchange(frame, lambda p: p.haslayer(UDP) and p[UDP].sport == 67 and
                                bytes(p[UDP].payload)[4:8] == xid, timeout)
        out = []
        for p in replies:
            b = bytes(p[UDP].payload)
            d = {'msg': None, 'yiaddr': socket.inet_ntoa(b[16:20]), 'options': {}}
            i = 240
            while i < len(b) and b[i] != 255:
                if b[i] == 0:
                    i += 1
                    continue
                code, length = b[i], b[i + 1]
                data = b[i + 2:i + 2 + length]
                if code == 53:
                    d['msg'] = MSG4_NAMES.get(data[0], data[0])
                elif code == 54:
                    d['serverid'] = socket.inet_ntoa(data)
                    self.sid4 = d['serverid']
                else:
                    d['options'][str(code)] = data.hex()
                i += 2 + length
            out.append(d)
        return {'step': spec, 'sent': payload.hex(), 'replies': out}

    # ---- RS --------------------------------------------------------------------------------
    def rs(self, spec):
        _, flags = flags_of(spec)
        mac, extra, timeout = self.probe_mac, b'', 2.0
        for k, v in flags:
            if k == 'mac':
                mac = v
            elif k == 'opt':
                t, _, data = v.partition(':')
                d = bytes.fromhex(data)
                extra += bytes([int(t), (len(d) + 2 + 7) // 8]) + d
            elif k == 'timeout':
                timeout = float(v)
        frame = (Ether(src=mac, dst='33:33:00:00:00:02') /
                 IPv6(src=lladdr(self.dev), dst='ff02::2', hlim=255) / ICMPv6ND_RS() / Raw(extra))
        replies = self.exchange(frame, lambda p: p.haslayer(IPv6) and p[IPv6].nh == 58 and
                                bytes(p[IPv6].payload)[:1] == b'\x86', timeout)
        out = []
        for p in replies:
            b = bytes(p[IPv6].payload)
            out.append({'msg': 'ra', 'from': p[IPv6].src, 'hoplimit': b[4], 'flags': b[5],
                        'lifetime': struct.unpack('!H', b[6:8])[0], 'options': b[16:].hex()})
        return {'step': spec, 'sent': bytes(frame[IPv6].payload).hex(), 'replies': out}

    def save(self):
        if self.frames and self.pcap:
            wrpcap(self.pcap, self.frames)


# ---- fuzz -------------------------------------------------------------------------------------
def mutate(rng, payload):
    b = bytearray(payload)
    for _ in range(rng.randint(1, 4)):
        what = rng.random()
        if what < 0.4 and b:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif what < 0.6 and len(b) > 4:
            del b[rng.randrange(4, len(b)):]
        elif what < 0.8:
            pos = rng.randrange(len(b) + 1)
            b[pos:pos] = os.urandom(rng.randint(1, 16))
        elif len(b) > 8:
            # corrupt a length field of an option near a random position
            pos = rng.randrange(4, len(b) - 3)
            b[pos:pos + 2] = struct.pack('!H', rng.choice([0, 1, 0xffff, rng.randrange(65536)]))
    return bytes(b)


def fuzz(prober, kind, count, seed):
    """Send count seeded mutations of valid messages (built, not sent, as seeds)."""
    rng = random.Random(seed)
    prober.dry = True
    if kind == 'dhcp6':
        seeds = [prober.dhcp6(s)['sent'] for s in
                 ('sol:rc,na=1,pd=2/60', 'req:na=1', 'ren:na=1', 'inf', 'conf:na=1/2001:db8::1')]
        frame = lambda raw: (Ether(src=prober.probe_mac, dst='33:33:00:01:00:02') /
                             IPv6(src=lladdr(prober.dev), dst=ALL_DHCP) /
                             UDP(sport=546, dport=547) / Raw(raw))
    elif kind == 'dhcp4':
        seeds = [prober.dhcp4(s)['sent'] for s in ('disc', 'req:ip=192.168.1.150', 'inf:ciaddr=192.168.1.150')]
        frame = lambda raw: (Ether(src=prober.probe_mac, dst='ff:ff:ff:ff:ff:ff') /
                             IP(src='0.0.0.0', dst='255.255.255.255') / UDP(sport=68, dport=67) / Raw(raw))
    else:
        seeds = [prober.rs('rs')['sent']]
        frame = lambda raw: (Ether(src=prober.probe_mac, dst='33:33:00:00:00:02') /
                             IPv6(src=lladdr(prober.dev), dst='ff02::2', hlim=255) / Raw(raw))
    prober.dry = False
    frames = [frame(mutate(rng, bytes.fromhex(rng.choice(seeds)))) for _ in range(count)]
    sendp(frames, iface=prober.dev, inter=0.002)
    return {'fuzz': kind, 'count': count, 'seed': seed}


def main():
    dev, pcap, kind = sys.argv[1], sys.argv[2], sys.argv[3]
    prober = Prober(dev, pcap)
    try:
        if kind == 'fuzz':
            print(json.dumps(fuzz(prober, sys.argv[4], int(sys.argv[5]), int(sys.argv[6]))), flush=True)
            return
        fn = {'dhcp6': prober.dhcp6, 'dhcp4': prober.dhcp4, 'rs': prober.rs}[kind]
        for step in sys.argv[4:]:
            print(json.dumps(fn(step)), flush=True)
    finally:
        if prober.frames:
            prober.save()


if __name__ == '__main__':
    main()
