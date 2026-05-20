"""Fast CN IP matcher using pre-built binary cache from gen_geo_cache.py.

Run gen_geo_cache.py once to build .cn_ip_cache.bin from geoip.dat.
After that, this module loads it instantly.
"""

import os
import sys
import struct
import ipaddress

if getattr(sys, 'frozen', False):
    _SCRIPT_DIR = os.path.dirname(sys.executable)
else:
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_ip_cache():
    v4, v6 = [], []
    path = os.path.join(_SCRIPT_DIR, ".cn_ip_cache.bin")
    if not os.path.exists(path):
        return v4, v6
    with open(path, "rb") as f:
        while True:
            hdr = f.read(1)
            if not hdr: break
            if hdr == b'\x04':
                addr = struct.unpack(">I", f.read(4))[0]
                prefix = struct.unpack("B", f.read(1))[0]
                f.read(2)
                v4.append((addr, prefix))
            elif hdr == b'\x06':
                hi = struct.unpack(">Q", f.read(8))[0]
                lo = struct.unpack(">Q", f.read(8))[0]
                prefix = struct.unpack("B", f.read(1))[0]
                v6.append((hi, lo, prefix))
    return v4, v6


class GeoMatcher:
    def __init__(self):
        self._v4, self._v6 = _load_ip_cache()
        self._cache = {}

    def is_cn_ip(self, ip_str):
        if ip_str in self._cache:
            return self._cache[ip_str]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        result = False
        if isinstance(addr, ipaddress.IPv4Address):
            val = int(addr)
            for net_addr, prefix in self._v4:
                shift = 32 - prefix
                if (val >> shift) == (net_addr >> shift):
                    result = True; break
        else:
            val = int(addr)
            hi, lo = val >> 64, val & 0xFFFFFFFFFFFFFFFF
            for nhi, nlo, npref in self._v6:
                if npref == 0: result = True; break
                if npref <= 64:
                    shift = 64 - npref
                    if hi >> shift == nhi >> shift: result = True; break
                else:
                    if hi == nhi: result = True; break
        self._cache[ip_str] = result
        return result


_geo = None

def get_geo():
    global _geo
    if _geo is None:
        _geo = GeoMatcher()
    return _geo
