# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
Aggregate top level objects from all Scapy modules.
"""

from scapy.compat import raw  # noqa: F401

from scapy.scapypipes import *

if conf.ipv6_enabled:  # noqa: F405
    from scapy.utils6 import *  # noqa: F401
    from scapy.route6 import *  # noqa: F401

