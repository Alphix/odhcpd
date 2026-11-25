"""Build everything the lab needs into WORK/prefix (tests/lab build).

Mirrors odhcpd's CI (.github/workflows/ci.yml): json-c, libnl-tiny, libubox, ubus and uci from
their git repositories, plus odhcp6c and busybox (udhcpc only) as the lab's clients, the
netifd-stub and odhcpd itself from this checkout. Sources are cached in WORK/src, builds in
WORK/build; a component is rebuilt when its source revision or build options change.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request

from .paths import REPO, TESTS, SRC, BUILD, PREFIX

# name -> (git URL, extra cmake options), built in this order
GIT_COMPONENTS = {
    'json-c': ('https://github.com/json-c/json-c.git',
               ['-DBUILD_SHARED_LIBS=ON', '-DBUILD_STATIC_LIBS=OFF', '-DDISABLE_EXTRA_LIBS=ON',
                '-DBUILD_TESTING=OFF']),
    'libnl-tiny': ('https://github.com/openwrt/libnl-tiny.git', []),
    'libubox': ('https://github.com/openwrt/libubox.git', ['-DBUILD_LUA=OFF', '-DBUILD_EXAMPLES=OFF']),
    'ubus': ('https://github.com/openwrt/ubus.git',
             ['-DBUILD_LUA=OFF', '-DBUILD_STATIC=OFF', '-DBUILD_EXAMPLES=OFF']),
    'uci': ('https://github.com/openwrt/uci.git', ['-DBUILD_LUA=OFF', '-DBUILD_STATIC=OFF']),
    'odhcp6c': ('https://github.com/openwrt/odhcp6c.git', []),
}

BUSYBOX_VERSION = '1.37.0'
BUSYBOX_URL = f'https://busybox.net/downloads/busybox-{BUSYBOX_VERSION}.tar.bz2'
BUSYBOX_SHA256 = '3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4'
# Applets/features on top of allnoconfig: udhcpc as OpenWrt uses it
BUSYBOX_CONFIG = ['CONFIG_UDHCPC', 'CONFIG_FEATURE_UDHCPC_ARPING', 'CONFIG_FEATURE_UDHCPC_SANITIZEOPT',
                  'CONFIG_LONG_OPTS', 'CONFIG_SHOW_USAGE', 'CONFIG_FEATURE_VERBOSE_USAGE']

# Tools and Python modules that have to come from the distribution
REQUIRED_TOOLS = ['cc', 'cmake', 'make', 'git', 'pkg-config', 'ip', 'unshare', 'nsenter']
REQUIRED_MODULES = ['scapy']
OPTIONAL_TOOLS = ['tcpdump']


def log(msg):
    print(f'lab build: {msg}', flush=True)


def check_requirements(need_pytest=False):
    """Return a list of missing requirements (empty if everything is there)."""
    missing = [t for t in REQUIRED_TOOLS if not shutil.which(t)]
    for mod in REQUIRED_MODULES + (['pytest'] if need_pytest else []):
        try:
            __import__(mod)
        except ImportError:
            missing.append(f'python3 module {mod}')
    return missing


def run(cmd, cwd=None, logfile=None, stdin=None):
    """Run a build command, appending its output to logfile; raise with the log tail on failure."""
    with open(logfile, 'a') as fp:
        fp.write(f'$ {" ".join(str(c) for c in cmd)}\n')
        fp.flush()
        rc = subprocess.run([str(c) for c in cmd], cwd=cwd, stdout=fp, stderr=subprocess.STDOUT,
                            input=stdin.encode() if stdin else None,
                            stdin=None if stdin else subprocess.DEVNULL).returncode
    if rc:
        with open(logfile) as fp:
            tail = fp.readlines()[-25:]
        raise RuntimeError(f'{cmd[0]} failed (exit {rc}), see {logfile}:\n' + ''.join(tail))


def stamp_ok(stamp, key):
    try:
        return stamp.read_text() == key
    except FileNotFoundError:
        return False


def git_source(name, url, ref, logfile):
    """Clone/update the source of a component; return (source dir, revision)."""
    src = SRC / name
    if not (src / '.git').exists():
        log(f'{name}: cloning {url}')
        run(['git', 'clone', '-q', url, src], logfile=logfile)
    elif ref:
        run(['git', 'fetch', '-q', 'origin'], cwd=src, logfile=logfile)
    if ref:
        run(['git', 'checkout', '-q', '--detach', ref], cwd=src, logfile=logfile)
    rev = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=src, capture_output=True, text=True,
                         check=True).stdout.strip()
    return src, rev


def cmake_build(name, src, options, key, logfile, force=False):
    """Configure, build and install a CMake project into PREFIX unless its stamp is current."""
    bdir = BUILD / name
    stamp = bdir / '.lab-stamp'
    if not force and stamp_ok(stamp, key):
        return False
    log(f'{name}: building')
    shutil.rmtree(bdir, ignore_errors=True)
    bdir.mkdir(parents=True)
    run(['cmake', f'-DCMAKE_PREFIX_PATH={PREFIX}', f'-DCMAKE_INSTALL_PREFIX={PREFIX}',
         '-DCMAKE_INSTALL_LIBDIR=lib'] + options + ['-S', src, '-B', bdir], logfile=logfile)
    run(['make', '-C', bdir, f'-j{os.cpu_count() or 2}'], logfile=logfile)
    run(['make', '-C', bdir, 'install'], logfile=logfile)
    stamp.write_text(key)
    return True


def build_busybox(logfile, force=False):
    """busybox with only udhcpc (OpenWrt's DHCPv4 client)."""
    key = json.dumps([BUSYBOX_VERSION, BUSYBOX_CONFIG])
    bdir = BUILD / 'busybox'
    stamp = bdir / '.lab-stamp'
    if not force and stamp_ok(stamp, key) and (PREFIX / 'bin' / 'udhcpc').exists():
        return False
    tarball = SRC / f'busybox-{BUSYBOX_VERSION}.tar.bz2'
    if not tarball.exists():
        log(f'busybox: downloading {BUSYBOX_URL}')
        tmp = tarball.with_suffix('.part')
        with urllib.request.urlopen(BUSYBOX_URL) as r, open(tmp, 'wb') as fp:
            shutil.copyfileobj(r, fp)
        tmp.rename(tarball)
    digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    if digest != BUSYBOX_SHA256:
        raise RuntimeError(f'{tarball}: sha256 {digest}, expected {BUSYBOX_SHA256}')
    log('busybox: building (udhcpc only)')
    shutil.rmtree(bdir, ignore_errors=True)
    bdir.mkdir(parents=True)
    with tarfile.open(tarball) as tf:
        tf.extractall(bdir, filter='tar')
    src = bdir / f'busybox-{BUSYBOX_VERSION}'
    run(['make', 'allnoconfig'], cwd=src, logfile=logfile)
    cfg = src / '.config'
    lines = cfg.read_text().splitlines()
    want = set(BUSYBOX_CONFIG)
    lines = [f'{line[2:].split(" ")[0]}=y' if line.startswith('# ') and line[2:].split(' ')[0] in want
             else line for line in lines]
    cfg.write_text('\n'.join(lines) + '\n')
    # resolve dependencies of the enabled options, taking the defaults for new prompts
    run(['make', 'oldconfig'], cwd=src, logfile=logfile, stdin='\n' * 2000)
    run(['make', f'-j{os.cpu_count() or 2}', 'busybox'], cwd=src, logfile=logfile)
    (PREFIX / 'bin').mkdir(parents=True, exist_ok=True)
    shutil.copy2(src / 'busybox', PREFIX / 'bin' / 'busybox')
    udhcpc = PREFIX / 'bin' / 'udhcpc'
    if udhcpc.is_symlink() or udhcpc.exists():
        udhcpc.unlink()
    udhcpc.symlink_to('busybox')
    stamp.write_text(key)
    return True


def build_local(name, src, options, logfile):
    """A CMake project from this checkout: always run make (incremental), install the binary."""
    bdir = BUILD / name
    key = json.dumps(options)
    stamp = bdir / '.lab-stamp'
    if not stamp_ok(stamp, key):
        log(f'{name}: configuring')
        shutil.rmtree(bdir, ignore_errors=True)
        bdir.mkdir(parents=True)
        run(['cmake', f'-DCMAKE_PREFIX_PATH={PREFIX}'] + options + ['-S', src, '-B', bdir], logfile=logfile)
        stamp.write_text(key)
    run(['make', '-C', bdir, f'-j{os.cpu_count() or 2}'], logfile=logfile)
    (PREFIX / 'sbin').mkdir(parents=True, exist_ok=True)
    shutil.copy2(bdir / name, PREFIX / 'sbin' / name)


def build(refs=None, clean=False, sanitize=False, only=None):
    """Build everything (or only the named components); refs pins git components {name: ref}."""
    refs = refs or {}
    missing = check_requirements()
    if missing:
        raise RuntimeError('missing requirements: ' + ', '.join(missing))
    if clean:
        for d in (BUILD, PREFIX):
            shutil.rmtree(d, ignore_errors=True)
    for d in (SRC, BUILD, PREFIX):
        d.mkdir(parents=True, exist_ok=True)
    logfile = BUILD / 'build.log'

    rebuilt = False
    for name, (url, options) in GIT_COMPONENTS.items():
        if only and name not in only:
            continue
        src, rev = git_source(name, url, refs.get(name), logfile)
        # a rebuilt library invalidates everything built after it
        rebuilt |= cmake_build(name, src, options, json.dumps([rev, options]), logfile, force=rebuilt)
    if not only or 'busybox' in only:
        build_busybox(logfile)

    stub = TESTS / 'netifd-stub'
    if (stub / 'CMakeLists.txt').exists() and (not only or 'netifd-stub' in only):
        build_local('netifd-stub', stub, [], logfile)
    if not only or 'odhcpd' in only:
        options = ['-DUBUS=ON', '-DDHCPV4_SUPPORT=ON']
        if sanitize:
            options.append('-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer -O1')
        build_local('odhcpd', REPO, options, logfile)
    log(f'done, everything is in {PREFIX}')


def built():
    """Is everything the lab runs there?"""
    need = [PREFIX / 'sbin' / 'odhcpd', PREFIX / 'sbin' / 'ubusd', PREFIX / 'bin' / 'ubus',
            PREFIX / 'sbin' / 'netifd-stub',
            PREFIX / 'sbin' / 'odhcp6c', PREFIX / 'bin' / 'udhcpc']
    return all(p.exists() for p in need)


if __name__ == '__main__':
    try:
        build()
    except RuntimeError as e:
        sys.exit(f'lab build: {e}')
