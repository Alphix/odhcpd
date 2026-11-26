#!/usr/bin/env python3
"""Run a command in a node's namespaces, keeping all capabilities (like `nsenter
--preserve-credentials --keep-caps`, which needs util-linux 2.40).

Used for the systemd nodes, where we are the systemd-network user rather than root: without
ambient capabilities, the command would lose them on exec.

usage: enter.py <pid> <cmd> [args...]
"""
import ctypes
import os
import sys

CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWNET = 0x10000000, 0x20000, 0x4000000, 0x40000000
PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE = 47, 2
CAP_V3 = 0x20080522

libc = ctypes.CDLL(None, use_errno=True)


class CapHeader(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]


class CapData(ctypes.Structure):
    _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                ('inheritable', ctypes.c_uint32)]


def check(ret, what):
    if ret != 0:
        e = ctypes.get_errno()
        sys.exit(f'enter: {what}: {os.strerror(e)}')


def main():
    pid, cmd = sys.argv[1], sys.argv[2:]
    for ns, flag in (('user', CLONE_NEWUSER), ('net', CLONE_NEWNET), ('mnt', CLONE_NEWNS),
                     ('uts', CLONE_NEWUTS)):
        fd = os.open(f'/proc/{pid}/ns/{ns}', os.O_RDONLY)
        check(libc.setns(fd, flag), f'setns {ns}')
        os.close(fd)
    hdr, data = CapHeader(CAP_V3, 0), (CapData * 2)()
    check(libc.capget(ctypes.byref(hdr), data), 'capget')
    for d in data:
        d.inheritable = d.permitted
    check(libc.capset(ctypes.byref(hdr), data), 'capset')
    last = int(open('/proc/sys/kernel/cap_last_cap').read())
    for cap in range(last + 1):
        check(libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0), f'ambient cap {cap}')
    os.execvp(cmd[0], cmd)


if __name__ == '__main__':
    main()
