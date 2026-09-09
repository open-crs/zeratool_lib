# Pickle-compatible re-exports for the host side of the gRPC round-trip.
#
# The docker container puts /zeratool_lib/zeratool_lib on PYTHONPATH, which
# makes zeratool_lib.py import as a *top-level module* named `zeratool_lib`.
# Classes defined there get __module__ == "zeratool_lib", so the pickled
# exploit returned over gRPC references e.g. `zeratool_lib.ZeratoolExploit`.
#
# On the host, `zeratool_lib` is installed as a *package* (this directory).
# We can't `from zeratool_lib.zeratool_lib import ...` here because that
# submodule does `import formatDetector` etc. (unqualified, docker-only),
# which would explode at import time on the host. So we redefine the small
# pickle-relevant classes here instead. Pickle resolves classes by
# (module, qualname) lookup and rebuilds dataclass/enum instances by field,
# so structural equivalence is enough.
from dataclasses import dataclass
from enum import Enum


class ZeratoolInputStreams(Enum):
    """Sync names with commons.input_streams.InputStreams."""

    STDIN = "STDIN"
    ARGUMENTS = "ARG"


@dataclass
class ZeratoolExploit:
    class Outcomes(Enum):
        SHELL = "SHELL"
        CALL_TO_WIN = "CALL_TO_WIN"
        LEAK = "LEAK"

    payload: bytes
    outcome: Outcomes


__all__ = ["ZeratoolExploit", "ZeratoolInputStreams"]
