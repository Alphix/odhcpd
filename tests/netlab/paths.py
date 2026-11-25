"""Locations used by the lab: the odhcpd checkout and the lab's work directory."""
import os
from pathlib import Path

# The odhcpd checkout this lab belongs to (tests/netlab/paths.py -> top level)
REPO = Path(__file__).resolve().parents[2]
TESTS = REPO / 'tests'

# Everything the lab downloads, builds or produces lives below WORK
WORK = Path(os.environ.get('ODHCPD_LAB_DIR', REPO / 'lab')).resolve()
SRC = WORK / 'src'
BUILD = WORK / 'build'
PREFIX = WORK / 'prefix'
RUN = WORK / 'run'


def env():
    """Environment for programs built into PREFIX."""
    e = dict(os.environ)
    e['PATH'] = f"{PREFIX / 'sbin'}:{PREFIX / 'bin'}:{e.get('PATH', '/usr/sbin:/usr/bin:/sbin:/bin')}"
    e['LD_LIBRARY_PATH'] = str(PREFIX / 'lib')
    return e
