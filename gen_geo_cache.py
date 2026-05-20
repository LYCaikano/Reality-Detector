#!/usr/bin/env python3
"""Build .cn_ip_cache.bin from geoip.dat (CN IP ranges only).

Skip if cache already exists and is newer than source file.
"""

import os
import struct
import ipaddress
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class _FR:
    __slots__ = ('d', 'p', 'e')
    def __init__(self, d): self.d = d; self.p = 0; self.e = len(d)
    def vu(self):
        r, s = 0, 0
        while self.p < self.e:
            b = self.d[self.p]; self.p += 1
            r |= (b & 0x7F) << s
            if not (b & 0x80): return r
            s += 7
            if s > 63: raise ValueError(f"varint overflow at {self.p}")
        return 0
    def raw(self, n):
        r = bytes(self.d[self.p:self.p + n]); self.p += n; return r
    def sk(self, w):
        if w == 0: self.vu()
        elif w == 1: self.p += 8
        elif w == 2: self.p += self.vu()
        elif w == 5: self.p += 4


def parse_cn_cidrs(path):
    t0 = time.time()
    with open(path, "rb") as f:
        data = memoryview(f.read())
    r = _FR(data)
    found = []
    while r.p < r.e:
        t = r.vu()
        if t == 0: break
        fn, wt = t >> 3, t & 7
        if fn == 1 and wt == 2:
            elen = r.vu()
            ep = r.p
            t2 = r.vu()
            if (t2 >> 3) == 1 and (t2 & 7) == 2:
                sl = r.vu()
                cc = r.raw(sl).decode()
                if cc == 'CN':
                    while r.p < ep + elen:
                        t3 = r.vu()
                        if t3 == 0: break
                        fn3, wt3 = t3 >> 3, t3 & 7
                        if fn3 == 2 and wt3 == 2:
                            cl = r.vu(); ce = r.p + cl
                            ipb, prefix = None, 0
                            while r.p < ce:
                                t4 = r.vu()
                                if t4 == 0: break
                                fn4, wt4 = t4 >> 3, t4 & 7
                                if fn4 == 1 and wt4 == 2: ipb = r.raw(r.vu())
                                elif fn4 == 2 and wt4 == 0: prefix = r.vu()
                                else: r.sk(wt4)
                            r.p = ce
                            if ipb and prefix:
                                found.append((ipaddress.ip_address(ipb), prefix))
                        else: r.sk(wt3)
                    break
                else:
                    r.p = ep + elen
            else:
                r.p = ep + elen
        else:
            r.sk(wt)
    print(f"       {len(found)} CN CIDRs in {time.time()-t0:.1f}s")
    return found


def main():
    geoip = os.path.join(SCRIPT_DIR, "geoip.dat")
    cache = os.path.join(SCRIPT_DIR, ".cn_ip_cache.bin")

    if not os.path.exists(geoip):
        print(f"[SKIP] {geoip} not found")
        return
    if os.path.exists(cache) and os.path.getmtime(cache) >= os.path.getmtime(geoip):
        print(f"[SKIP] .cn_ip_cache.bin up-to-date")
        return

    print(f"[RUN]  Parsing geoip.dat ({os.path.getsize(geoip)/1024/1024:.1f} MB)...")
    cidrs = parse_cn_cidrs(geoip)
    with open(cache, "wb") as f:
        for a, prefix in cidrs:
            if isinstance(a, ipaddress.IPv4Address):
                f.write(b'\x04')
                f.write(struct.pack(">I", int(a)))
                f.write(struct.pack("B", prefix))
                f.write(b'\x00\x00')
            else:
                f.write(b'\x06')
                v = int(a)
                f.write(struct.pack(">QQ", v >> 64, v & 0xFFFFFFFFFFFFFFFF))
                f.write(struct.pack("B", prefix))
    print(f"       Saved {os.path.getsize(cache)} bytes")
    print("[DONE]")


if __name__ == "__main__":
    main()
