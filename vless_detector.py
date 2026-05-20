#!/usr/bin/env python3
"""
VLESS/REALITY Traffic Detector — Python Port with GUI.
Windows: requires Npcap (https://npcap.com/) with "WinPcap API-compatible Mode".
"""

import os
import sys
import time
import struct
import socket
import select
import subprocess
import threading
import queue
import binascii
import ipaddress
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from collections import OrderedDict, deque

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, get_if_list, IP, IPv6, TCP

from geo_matcher import get_geo
# Auto-generate geo cache on first run
if getattr(sys, 'frozen', False):
    _SCRIPT_DIR = os.path.dirname(sys.executable)
else:
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_cache_ip = os.path.join(_SCRIPT_DIR, ".cn_ip_cache.bin")
_geoip_dat = os.path.join(_SCRIPT_DIR, "geoip.dat")
if not os.path.exists(_cache_ip) and os.path.exists(_geoip_dat):
    print("[geo] Building IP cache...", flush=True)
    try:
        from gen_geo_cache import main as _gen_cache
        _gen_cache()
    except Exception as e:
        print(f"[geo] FAILED ({e}) — geo bypass disabled!", flush=True)
    print("[geo] Done.", flush=True)
_geo = get_geo()
if len(_geo._v4) == 0 and len(_geo._v6) == 0:
    print("[geo] WARNING: No CN CIDRs loaded — check geoip.dat in same folder")

MAX_STREAMS = 1024
MAX_STREAM_BYTES = 32768
MAX_REPLAY_RESPONSE_BYTES = 65536
REPLAY_TIMEOUT_MS = 3000
PROBE_OBSERVE_TIMEOUT_MS = 4000
STREAM_IDLE_SECONDS = 30
TLS13_ENCRYPTED_ALERT_RECORD_LEN = 19
REQUIRED_CONFIRMATION_ROUNDS = 3
PROBE_COOLDOWN_SEC = 5      # cooldown between probe batches
WHITELIST_FAIL_THRESHOLD = 15  # consecutive non-detection batches before whitelist

class ProbeStatus:
    NONE = 0; ALERT = 1; FIN = 2; RST = 3; TIMEOUT = 4
    @classmethod
    def name(cls, s): return {0: "NONE", 1: "ALERT", 2: "FIN", 3: "RST", 4: "TO"}.get(s, "?")

class ReplayStatus:
    OK = 0; CONNECT_FAILED = 5; SEND_FAILED = 6; TIMEOUT = 7
    @classmethod
    def is_conn_error(cls, s): return s in (2, 3, 4, 5)

class ProbeSet:
    def __init__(self, name, probes):
        self.name = name
        self.probes = probes

def _read_be16(data, off): return struct.unpack_from('>H', data, off)[0]
def _read_be24(data, off): return struct.unpack_from('>L', b'\x00' + data[off:off+3])[0]

def find_tls_handshake_record(data, handshake_type):
    off = 0
    while off + 9 <= len(data):
        if data[off] != 0x16 or data[off + 1] != 0x03: off += 1; continue
        tls_len = _read_be16(data, off + 3)
        if tls_len < 4 or off + 5 + tls_len > len(data): off += 1; continue
        if data[off + 5] == handshake_type: return bytes(data[off:off + 5 + tls_len])
        off += 5 + tls_len
    return None

def parse_extensions(ext_data):
    sni = ""
    off = 0
    while off + 4 <= len(ext_data):
        ext_type = _read_be16(ext_data, off)
        ext_len = _read_be16(ext_data, off + 2)
        off += 4
        if off + ext_len > len(ext_data): break
        ext = ext_data[off:off + ext_len]
        if ext_type == 0 and ext_len >= 5:
            list_len = _read_be16(ext, 0)
            pos = 2
            while pos + 3 <= ext_len and pos < list_len + 2:
                name_type = ext[pos]
                name_len = _read_be16(ext, pos + 1)
                pos += 3
                if pos + name_len > ext_len: break
                if name_type == 0:
                    try: sni = ext[pos:pos + name_len].decode('ascii', errors='replace')
                    except: pass
                    break
                pos += name_len
        off += ext_len
    return sni

def extract_client_hello_info(record):
    if len(record) < 9 or record[0] != 0x16 or record[1] != 0x03 or record[5] != 0x01: return None
    tls_len = _read_be16(record, 3)
    hs_len = _read_be24(record, 6)
    if tls_len + 5 > len(record) or hs_len + 9 > tls_len + 5: return None
    body = record[9:9 + hs_len]
    if len(body) < 38: return None
    off = 34
    session_id_len = body[off]; off += 1
    if off + session_id_len + 2 > len(body): return None
    off += session_id_len
    cipher_len = _read_be16(body, off); off += 2
    if off + cipher_len + 1 > len(body): return None
    off += cipher_len
    comp_len = body[off]; off += 1
    if off + comp_len > len(body): return None
    off += comp_len
    sni = ""
    if off + 2 <= len(body):
        ext_len = _read_be16(body, off); off += 2
        if off + ext_len <= len(body): sni = parse_extensions(body[off:off + ext_len])
    return sni

def find_server_hello_selected_version(data):
    record = find_tls_handshake_record(data, 0x02)
    if not record or len(record) < 9: return 0
    hs_len = _read_be24(record, 6)
    body = record[9:9 + hs_len]
    if len(body) < 38: return 0
    version = _read_be16(body, 0)
    off = 34
    session_id_len = body[off]; off += 1
    if off + session_id_len + 3 > len(body): return version
    off += session_id_len + 3
    if off + 2 > len(body): return version
    ext_len = _read_be16(body, off); off += 2
    end = off + ext_len
    while off + 4 <= end:
        ext_type = _read_be16(body, off)
        elen = _read_be16(body, off + 2)
        off += 4
        if off + elen > end: return 0
        if ext_type == 43 and elen == 2: return _read_be16(body, off)
        off += elen
    return version

def randomize_client_hello_legacy_session_id(record):
    rec = bytearray(record)
    if len(rec) < 9 or rec[0] != 0x16 or rec[1] != 0x03 or rec[5] != 0x01: return bytes(rec)
    hs_len = _read_be24(rec, 6)
    if hs_len < 35: return bytes(rec)
    session_id_len = rec[9 + 34]
    if session_id_len == 0: return bytes(rec)
    start = 9 + 34 + 1
    if start + session_id_len > len(rec): return bytes(rec)
    rec[start:start + session_id_len] = os.urandom(session_id_len)
    return bytes(rec)

def buffer_contains_record_from_tail(data, record_type, record_len):
    full_len = 5 + record_len
    if len(data) < full_len: return False
    for pos in range(len(data) - full_len, -1, -1):
        if data[pos] == record_type and data[pos + 1] == 0x03 and data[pos + 2] == 0x03:
            if _read_be16(data, pos + 3) == record_len: return True
    return False

def _reverse_key(key):
    return (key[0], key[3], key[4], key[1], key[2])

_LAN_V4 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("169.254.0.0/16"),
]
_LAN_V6 = [
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("::1/128"),
]

def _is_lan_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _LAN_V4)
    return any(addr in net for net in _LAN_V6)

class TcpStream:
    def __init__(self, key, now):
        self.key = key
        self.client_hello_printed = False
        self.expect_server_response = False
        self.server_response_printed = False
        self.replay_done = False
        self.data = bytearray()
        self.sni = ""
        self.last_seen = now
        self.server_ip = key[3]
        self._is_lan_cached = None

    @property
    def is_lan(self):
        if self._is_lan_cached is None:
            self._is_lan_cached = _is_lan_ip(self.server_ip)
        return self._is_lan_cached

    def append(self, seq, payload):
        if len(self.data) < MAX_STREAM_BYTES:
            self.data.extend(payload)
            if len(self.data) > MAX_STREAM_BYTES:
                self.data = self.data[:MAX_STREAM_BYTES]

class CoreApp:
    def __init__(self, ui_queue):
        self.probe_sets = []
        self.running = False
        self.ui_queue = ui_queue
        self.lock = threading.RLock()
        self.streams = OrderedDict()
        self.replay_ignores = []
        self.last_probe_time = {}      # probe_key → timestamp (cooldown)
        self.in_flight_probes = set()  # probe_key currently probing
        self.alerted_targets = set()   # (server_ip, sni) already alerted
        self.last_hello_log = {}       # anti-flood for verbose logging
        # Auto whitelist / blacklist (24h expiry)
        self._white = {}  # (server_ip, server_port, sni) → expiry_ts
        self._black = {}  # (client_ip, server_ip, server_port, sni) → expiry_ts
        self._fail_count = {}  # (server_ip, server_port, sni) → consecutive_fails
        self._probe_status = {}  # probe_key → (round_done, round_total, ip, port, sni, start_time, batch_num)
        self._pending_queue = []  # list of (task_dict, probe_key, trigger_time_mono, batch_num)
        self._pending_tasks = {}  # probe_key → task_dict (kept for auto-continue)
        self._pending_cond = threading.Condition(self.lock)
        self.bind_addr = None  # (ip, 0) tuple to bind probe sockets, bypasses TUN/VPN
        self._load_lists()
        # Start background pending-probe worker
        threading.Thread(target=self._pending_worker, daemon=True).start()

    def _cleanup_lists(self, now):
        self._white = {k: v for k, v in self._white.items() if v > now}
        self._black = {k: v for k, v in self._black.items() if v > now}

    def _can_probe(self, probe_key, task=None):
        """Check if probe_key is allowed. Returns True if probe starts now.
        If blocked by cooldown and task is provided, schedules auto-retry.
        """
        now = time.monotonic()
        with self.lock:
            if probe_key in self.in_flight_probes:
                return False
            last = self.last_probe_time.get(probe_key, 0)
            if now - last < PROBE_COOLDOWN_SEC:
                # Enqueue for auto-retry when cooldown expires
                if task is not None:
                    remaining = PROBE_COOLDOWN_SEC - (now - last)
                    trigger_at = now + remaining + 0.5
                    wk = (probe_key[0], probe_key[1], probe_key[2])
                    batch_num = self._fail_count.get(wk, 0) + 1
                    if not any(pk == probe_key for _, pk, _, _ in self._pending_queue):
                        self._pending_queue.append((task, probe_key, trigger_at, batch_num))
                        self._pending_tasks[probe_key] = task
                        self._pending_cond.notify()
                return False
            # Check whitelist / blacklist
            wk = (probe_key[0], probe_key[1], probe_key[2])
            if wk in self._white and self._white[wk] > time.time():
                return False
            for bk, exp in self._black.items():
                if bk[1] == wk[0] and bk[2] == wk[1] and bk[3] == wk[2] and exp > time.time():
                    return False
            self.last_probe_time[probe_key] = now
            self.in_flight_probes.add(probe_key)
            wk = (probe_key[0], probe_key[1], probe_key[2])
            batch_num = self._fail_count.get(wk, 0) + 1
            self._probe_status[probe_key] = (0, REQUIRED_CONFIRMATION_ROUNDS,
                probe_key[0], probe_key[1], probe_key[2], time.monotonic(), batch_num)
            self._push_status()
            return True

    def _pending_worker(self):
        """Background thread: fire pending probes when cooldown expires."""
        while True:
            with self._pending_cond:
                # Wait for items or 1s timeout
                self._pending_cond.wait(1.0)
                now = time.monotonic()
                ready = []
                remaining = []
                for item in self._pending_queue:
                    task, pk, trigger_at, batch_num = item
                    if now >= trigger_at:
                        ready.append((task, pk, batch_num))
                    else:
                        remaining.append(item)
                self._pending_queue = remaining
            for task, pk, batch_num in ready:
                if self.running:
                    if self._can_probe(pk, task):
                        threading.Thread(target=_run_confirmation_batch,
                                         args=(self, task, pk), daemon=True).start()
                    else:
                        # Re-enqueue for retry if not permanently blocked
                        wk = (pk[0], pk[1], pk[2])
                        if wk not in self._white and not any(
                            bk[1] == wk[0] and bk[2] == wk[1] and bk[3] == wk[2]
                            for bk in self._black):
                            with self._pending_cond:
                                self._pending_queue.append((task, pk, time.monotonic() + 1.0, batch_num))
                                self._pending_cond.notify()

    def _finish_probe_batch(self, probe_key, per_set_results, total_matched, server_ip, server_port, sni, client_ip):
        """Called when a concurrent 3-round batch completes.
        per_set_results: list of (probe_set_name, matches_in_3_rounds)
        total_matched: max matches by any single probe set (used for detection threshold)
        """
        with self.lock:
            self.in_flight_probes.discard(probe_key)
            self._probe_status.pop(probe_key, None)
        now = time.time()
        self._cleanup_lists(now)
        wk = (server_ip, server_port, sni)

        if total_matched >= REQUIRED_CONFIRMATION_ROUNDS and self.running:
            bk = (client_ip, server_ip, server_port, sni)
            self._black[bk] = now + 86400
            self._fail_count.pop(wk, None)
            self._pending_tasks.pop(probe_key, None)
            self._save_lists()
            alert_key = (server_ip, sni)
            with self.lock:
                if alert_key not in self.alerted_targets:
                    self.alerted_targets.add(alert_key)
                    for name, count in per_set_results:
                        self.log("DETECT", f"  {name}: {count}/3 rounds matched")
                    self.log("ALERT",
                            f"Detected VLESS: {client_ip} -> {server_ip}:{server_port} sni={sni} ({total_matched}/3 confirmations) -> blacklisted 24h")
        else:
            fc = self._fail_count.get(wk, 0) + 1
            self._fail_count[wk] = fc
            if fc >= WHITELIST_FAIL_THRESHOLD:
                self._white[wk] = now + 86400
                self._fail_count.pop(wk, None)
                self._pending_tasks.pop(probe_key, None)
                self._save_lists()
                self.log("SYS", f"Auto-whitelist: {server_ip}:{server_port} {sni} ({WHITELIST_FAIL_THRESHOLD} consecutive non-detections, 24h)")
            elif self.running:
                # Auto-continue: re-enqueue for next batch after cooldown
                task = self._pending_tasks.get(probe_key)
                if task:
                    with self.lock:
                        self._pending_queue.append((task, probe_key, time.monotonic() + PROBE_COOLDOWN_SEC + 0.5, fc + 1))
                        self._pending_cond.notify()
        self._push_status()

    def log(self, level, msg):
        self.ui_queue.put({"type": "log", "level": level, "msg": msg})

    def _push_status(self):
        """Push current probe status to UI queue."""
        now_m = time.monotonic()
        active = []
        waiting = []
        pending = []
        with self.lock:
            for pk, (rd, rt, ip, port, sni, st, bn) in list(self._probe_status.items()):
                if pk in self.in_flight_probes:
                    active.append((ip, port, sni, rd, rt, st, bn))
                else:
                    del self._probe_status[pk]
            for pk, lt in list(self.last_probe_time.items()):
                if pk not in self.in_flight_probes:
                    age = now_m - lt
                    if age < PROBE_COOLDOWN_SEC:
                        wk = (pk[0], pk[1], pk[2])
                        bn = self._fail_count.get(wk, 0) + 1
                        waiting.append((pk[0], pk[1], pk[2], PROBE_COOLDOWN_SEC - age, bn))
            for _, pk, _, bn in self._pending_queue:
                if pk not in self.in_flight_probes:
                    pending.append((pk[0], pk[1], pk[2], bn))
            wc = len(self._white)
            bc = len(self._black)
            wl = [(k[0], k[1], k[2]) for k in list(self._white.keys())[:6]]
            bl = [(k[1], k[2], k[3]) for k in list(self._black.keys())[:6]]
        self.ui_queue.put({"type": "STATUS", "active": active, "waiting": waiting,
                           "pending": pending, "white": wc, "black": bc,
                           "white_list": wl, "black_list": bl})

    def _save_lists(self):
        """Persist blacklist/whitelist to JSON files."""
        import json as _json
        now = time.time()
        self._cleanup_lists(now)
        try:
            wl = [[k[0], k[1], k[2], v] for k, v in self._white.items() if v > now]
            with open(os.path.join(_SCRIPT_DIR, ".whitelist.json"), "w") as f:
                _json.dump({"entries": wl}, f, indent=2)
            bl = [[k[0], k[1], k[2], k[3], v] for k, v in self._black.items() if v > now]
            with open(os.path.join(_SCRIPT_DIR, ".blacklist.json"), "w") as f:
                _json.dump({"entries": bl}, f, indent=2)
        except Exception:
            pass

    def _load_lists(self):
        """Load persisted blacklist/whitelist from JSON files."""
        import json as _json
        now = time.time()
        for fname, target in [(".whitelist.json", self._white), (".blacklist.json", self._black)]:
            path = os.path.join(_SCRIPT_DIR, fname)
            if not os.path.exists(path): continue
            try:
                with open(path, "r") as f:
                    data = _json.load(f)
                for entry in data.get("entries", []):
                    if len(entry) < 4: continue
                    if target is self._white:
                        key = (str(entry[0]), int(entry[1]), str(entry[2]))
                    else:
                        key = (str(entry[0]), str(entry[1]), int(entry[2]), str(entry[3]))
                    expiry = float(entry[-1])
                    if expiry > now:
                        target[key] = expiry
            except Exception:
                pass

def _get_stream(app, key, ts):
    with app.lock:
        if key in app.streams:
            s = app.streams[key]
            s.last_seen = ts
            return s
        stale = [k for k, v in app.streams.items() if ts - v.last_seen > STREAM_IDLE_SECONDS]
        for k in stale:
            del app.streams[k]
        if len(app.streams) >= MAX_STREAMS:
            oldest = min(app.streams.keys(), key=lambda k: app.streams[k].last_seen)
            del app.streams[oldest]
        s = TcpStream(key, ts)
        app.streams[key] = s
        return s

def _replay_client_hello_once(app, server_key, client_hello_record, probe):
    ip_ver, src, sport, _, _ = server_key
    family = socket.AF_INET if ip_ver == 4 else socket.AF_INET6
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(REPLAY_TIMEOUT_MS / 1000.0)

    # Bind to interface IP to bypass TUN/VPN routing
    if app.bind_addr and app.bind_addr[0]:
        try:
            s.bind(app.bind_addr)
        except Exception:
            pass

    try:
        s.connect((src, sport))
        s.sendall(client_hello_record)
    except Exception:
        s.close(); return False, ProbeStatus.NONE, ReplayStatus.CONNECT_FAILED

    got_response = False
    probe_sent = False
    probe_status = ProbeStatus.NONE
    alert_buf = bytearray()
    post_probe_buf = bytearray()
    probe_start = 0.0

    while True:
        to_ms = PROBE_OBSERVE_TIMEOUT_MS if probe_sent else REPLAY_TIMEOUT_MS
        if probe_sent:
            elapsed = (time.monotonic() - probe_start) * 1000
            if elapsed >= PROBE_OBSERVE_TIMEOUT_MS:
                probe_status = ProbeStatus.TIMEOUT; break
            to_ms = PROBE_OBSERVE_TIMEOUT_MS - int(elapsed)
            if to_ms < 0: to_ms = 0

        try:
            readable, _, _ = select.select([s], [], [], to_ms / 1000.0)
        except Exception:
            break

        if not readable:
            if probe_sent:
                probe_status = ProbeStatus.TIMEOUT
            break

        try:
            chunk = s.recv(4096)
        except ConnectionResetError:
            probe_status = ProbeStatus.RST if probe_sent else ProbeStatus.NONE; break
        except Exception:
            break

        if not chunk:
            if probe_sent and probe_status == ProbeStatus.NONE:
                probe_status = ProbeStatus.FIN
            break

        alert_buf.extend(chunk)
        if buffer_contains_record_from_tail(alert_buf, 0x15, 2):
            probe_status = ProbeStatus.ALERT; break
        if probe_sent:
            post_probe_buf.extend(chunk)
            if buffer_contains_record_from_tail(post_probe_buf, 0x17, TLS13_ENCRYPTED_ALERT_RECORD_LEN):
                probe_status = ProbeStatus.ALERT; break

        if not got_response:
            got_response = True
            try:
                s.sendall(probe)
                probe_sent = True
                probe_start = time.monotonic()
            except Exception:
                break

        if len(alert_buf) >= MAX_REPLAY_RESPONSE_BYTES:
            if probe_sent: probe_status = ProbeStatus.TIMEOUT
            break

    s.close()
    return got_response, probe_status, ReplayStatus.OK


def _run_probe_round(app, task, probes, client_hello):
    results = [None] * len(probes)
    lock = threading.Lock()

    def _worker(idx, p):
        g, s, f = _replay_client_hello_once(app, task['server_key'], client_hello, p)
        with lock: results[idx] = {'pstat': s, 'got': g}

    threads = [threading.Thread(target=_worker, args=(i, p)) for i, p in enumerate(probes)]
    for t in threads: t.start()
    for t in threads: t.join()

    valid = all(r is not None for r in results)
    has_signal = any(r['pstat'] != ProbeStatus.NONE for r in results) if valid else False
    return (valid and has_signal), results


def _replay_probe_matches_alarm(a_res):
    if not a_res or a_res[0]['pstat'] != ProbeStatus.TIMEOUT:
        return False
    for r in a_res[1:]:
        if r['pstat'] != ProbeStatus.ALERT:
            return False
    return True


_SNI_EXCLUDE_PATTERNS = [
    ".tailscale.com",
]

def _is_sni_excluded(sni):
    if not sni: return False
    sni_lower = sni.lower()
    return any(pat in sni_lower for pat in _SNI_EXCLUDE_PATTERNS)

def _run_probe_round_sequential(app, task, probes, client_hello, spacing=1.0):
    """Send probes sequentially with spacing (1s), returns (valid, results)."""
    results = [None] * len(probes)
    for i, p in enumerate(probes):
        g, s, f = _replay_client_hello_once(app, task['server_key'], client_hello, p)
        results[i] = {'pstat': s, 'got': g}
        if i < len(probes) - 1:
            time.sleep(spacing)
    valid = all(r is not None for r in results)
    has_signal = any(r['pstat'] != ProbeStatus.NONE for r in results) if valid else False
    return (valid and has_signal), results


def _run_confirmation_batch(app, task, probe_key):
    """Run 3 sequential probe rounds. Two probe sets run concurrently within each round."""
    server_ip = task['server_key'][1]
    server_port = task['server_key'][2]
    sni = task['sni']
    n_sets = len(app.probe_sets)

    per_set_matches = [0] * n_sets  # per-probe-set match count across 3 rounds

    for round_idx in range(REQUIRED_CONFIRMATION_ROUNDS):
        # Round A + B: two probe sets run concurrently
        results_a = [None] * n_sets
        results_b = [None] * n_sets
        lock = threading.Lock()

        def _run_set_a(set_idx, ps):
            valid, res = _run_probe_round_sequential(app, task, ps.probes, task['client_hello'], spacing=0.8)
            with lock: results_a[set_idx] = (valid, res)

        def _run_set_b(set_idx, ps):
            c_hello = randomize_client_hello_legacy_session_id(task['client_hello'])
            valid, res = _run_probe_round_sequential(app, task, ps.probes, c_hello, spacing=0.8)
            with lock: results_b[set_idx] = (valid, res)

        set_threads = []
        for si, ps in enumerate(app.probe_sets):
            set_threads.append(threading.Thread(target=_run_set_a, args=(si, ps)))
            set_threads.append(threading.Thread(target=_run_set_b, args=(si, ps)))
        for t in set_threads: t.start()
        for t in set_threads: t.join()

        # Evaluate per-set for this round
        for si, ps in enumerate(app.probe_sets):
            a = results_a[si]
            b = results_b[si]
            if a and b and a[0] and b[0]:
                if any(a[1][j]['pstat'] != b[1][j]['pstat'] for j in range(len(ps.probes))):
                    if _replay_probe_matches_alarm(a[1]):
                        per_set_matches[si] += 1

        # Update progress
        old = app._probe_status.get(probe_key, (0, 3, server_ip, server_port, sni, 0, 1))
        app._probe_status[probe_key] = (round_idx + 1, REQUIRED_CONFIRMATION_ROUNDS,
            server_ip, server_port, sni, old[5], old[6])
        app._push_status()

    # Aggregate results
    total_matched_rounds = max(per_set_matches) if per_set_matches else 0
    per_set = [(app.probe_sets[si].name, per_set_matches[si]) for si in range(n_sets)]

    app._finish_probe_batch(probe_key, per_set, total_matched_rounds, server_ip, server_port, sni, task['client_key'][1])


def process_packet(app, pkt, exclude_lan):
    if not app.running or TCP not in pkt: return

    if IP in pkt: ip_ver, src, dst = 4, pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt: ip_ver, src, dst = 6, pkt[IPv6].src, pkt[IPv6].dst
    else: return

    sport, dport = pkt[TCP].sport, pkt[TCP].dport
    key = (ip_ver, src, sport, dst, dport)
    ts = time.time()
    payload = bytes(pkt[TCP].payload)
    if not payload: return

    stream = _get_stream(app, key, ts)

    # Fix server_ip for s→c direction (TLS ServerHello → src is the server)
    if payload and len(payload) >= 9 and payload[0:3] == b'\x16\x03' and payload[5] == 0x02:
        if stream.server_ip != src:
            stream.server_ip = src
            stream._is_lan_cached = None  # invalidate cache

    # ── LAN exclusion: check the server IP (dst of initial c→s connection) ──
    if exclude_lan and _is_lan_ip(stream.server_ip):
        return

    stream.append(pkt[TCP].seq, payload)

    if not stream.client_hello_printed:
        ch = find_tls_handshake_record(stream.data, 0x01)
        if ch:
            sni = extract_client_hello_info(ch)
            if sni is not None:
                stream.sni = sni
                stream.client_hello_printed = True
                stream.server_ip = dst
                stream._is_lan_cached = _is_lan_ip(dst)
                
                log_key = (dst, sni)
                last = app.last_hello_log.get(log_key, 0)
                if ts - last > 10:
                    app.last_hello_log[log_key] = ts
                    app.log("CLIENT", f"TLS ClientHello {src}:{sport} -> {dst}:{dport} sni={sni}")
                
                s_key = _reverse_key(key)
                s_stream = _get_stream(app, s_key, ts)
                s_stream.expect_server_response = True
                s_stream.server_ip = dst  # s→c stream: correct server IP (dst of c→s)

    if stream.expect_server_response and not stream.server_response_printed:
        sv = find_server_hello_selected_version(payload)
        if sv == 0x0304:
            stream.server_response_printed = True
            sh_key = (dst, stream.sni)
            last = app.last_hello_log.get(sh_key, 0)
            if ts - last > 10:
                app.last_hello_log[sh_key] = ts
                app.log("SERVER", f"TLS ServerHello {src}:{sport} -> {dst}:{dport} version=0x0304")
            
            if not stream.replay_done:
                stream.replay_done = True
                c_stream = _get_stream(app, _reverse_key(key), ts)
                c_stream.server_ip = dst  # correct server IP for the c→s reverse stream
                c_hello = find_tls_handshake_record(c_stream.data, 0x01)
                if c_hello and c_stream.sni and not _is_sni_excluded(c_stream.sni):
                    # Skip Chinese IPs/domains via geo match
                    geo = get_geo()
                    if geo.is_cn_ip(src):
                        app.log("IP_SKIP", f"TLS skip: CN IP {src} ({c_stream.sni})")
                        return
                    probe_key = (src, sport, c_stream.sni)
                    task = {
                        'server_key': key,
                        'client_key': _reverse_key(key),
                        'client_hello': c_hello,
                        'sni': c_stream.sni,
                    }
                    if not app._can_probe(probe_key, task):
                        return
                    app._pending_tasks[probe_key] = task
                    threading.Thread(target=_run_confirmation_batch, args=(app, task, probe_key), daemon=True).start()

def _get_windows_adapter_map():
    if sys.platform != "win32": return {}
    try:
        kwargs = dict(timeout=10, stderr=subprocess.DEVNULL)
        # Prevent console window popup and hang in --windowed PyInstaller builds
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-NetAdapter | Select-Object Name, Status, InterfaceGuid | ConvertTo-Json"],
            **kwargs
        ).decode("utf-8", errors="replace")
    except Exception: return {}

    import json as _json
    try: items = _json.loads(out)
    except Exception: return {}
    if isinstance(items, dict): items = [items]

    result = {}
    for ad in items:
        guid_raw = ad.get("InterfaceGuid", "").strip("{}").lower()
        if guid_raw: result[guid_raw] = (ad.get("Name", ""), ad.get("Status", ""))
    return result

class AppUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VLESS/REALITY Traffic Detector")
        self.ui_queue = queue.Queue()
        self.app = CoreApp(self.ui_queue)
        self.show_client  = tk.BooleanVar(value=False)
        self.show_server  = tk.BooleanVar(value=False)
        self.show_detect  = tk.BooleanVar(value=True)
        self.show_skip    = tk.BooleanVar(value=False)
        self.auto_scroll  = tk.BooleanVar(value=True)
        self.exclude_lan  = tk.BooleanVar(value=True)
        self.sniffer_thread = None
        self._all_logs = []  # list of (level, msg, tag) for post-hoc filtering

        # Re-render on filter toggle
        self.show_client.trace_add('write', lambda *_: self._render_logs())
        self.show_server.trace_add('write', lambda *_: self._render_logs())
        self.show_detect.trace_add('write', lambda *_: self._render_logs())
        self.show_skip.trace_add('write', lambda *_: self._render_logs())

        ctrl = ttk.Frame(root, padding=10)
        ctrl.pack(fill=tk.X)

        ttk.Label(ctrl, text="Interface:").grid(row=0, column=0, sticky=tk.W)
        self._iface_values = list(get_if_list())
        self.iface_cb = ttk.Combobox(ctrl, values=self._iface_values, width=35)
        if self.iface_cb['values']: self.iface_cb.current(0)
        self.iface_cb.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.btn_refresh = ttk.Button(ctrl, text="↻", width=3, command=self._refresh_interfaces)
        self.btn_refresh.grid(row=0, column=2, padx=2)

        ttk.Label(ctrl, text="Probes:").grid(row=1, column=0, sticky=tk.W)
        self.probe_label = ttk.Label(ctrl, text="0 loaded")
        self.probe_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Button(ctrl, text="Load...", command=self.load_probe).grid(row=1, column=2, padx=5)

        ttk.Label(ctrl, text="Log filter:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.cb_client = ttk.Checkbutton(ctrl, text="ClientHello", variable=self.show_client)
        self.cb_client.grid(row=2, column=1, sticky=tk.W, padx=5)
        self.cb_server = ttk.Checkbutton(ctrl, text="ServerHello", variable=self.show_server)
        self.cb_server.grid(row=2, column=1, padx=(110,0), sticky=tk.W)
        self.cb_detect = ttk.Checkbutton(ctrl, text="Detections", variable=self.show_detect)
        self.cb_detect.grid(row=2, column=1, padx=(210,0), sticky=tk.W)
        self.cb_scroll = ttk.Checkbutton(ctrl, text="Auto-scroll", variable=self.auto_scroll)
        self.cb_scroll.grid(row=2, column=1, padx=(300,0), sticky=tk.W)
        self.cb_skip = ttk.Checkbutton(ctrl, text="Skip", variable=self.show_skip)
        self.cb_skip.grid(row=2, column=1, padx=(390,0), sticky=tk.W)

        ttk.Checkbutton(ctrl, text="Exclude LAN IPs (10/172/192/100.64.x)", variable=self.exclude_lan).grid(row=3, column=0, columnspan=2, sticky=tk.W)
        
        btn_frame = ttk.Frame(ctrl)
        btn_frame.grid(row=2, column=2, sticky=tk.E, padx=5)
        self.btn_start = ttk.Button(btn_frame, text="Start Capture", command=self.toggle)
        self.btn_start.pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Clear Log", command=self._clear_log).pack(side=tk.LEFT, padx=2)

        # Bottom area: log (left) + status (right)
        bottom = ttk.Frame(root)
        bottom.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.log_area = scrolledtext.ScrolledText(bottom, bg="black", fg="lightgray", font=("Consolas", 10))
        self.log_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log_area.tag_config("alert", foreground="red")
        self.log_area.tag_config("server", foreground="cyan")
        self.log_area.tag_config("client", foreground="lightgreen")
        self.log_area.tag_config("sys", foreground="gray")
        self.log_area.tag_config("skip", foreground="dim gray")

        # Status panel (right side)
        status_frame = ttk.LabelFrame(bottom, text="Probe Status", padding=5)
        status_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        self.status_area = tk.Text(status_frame, width=36, height=20, bg="#1a1a2e", fg="#e0e0e0",
                                    font=("Consolas", 9), state=tk.DISABLED, wrap=tk.WORD)
        self.status_area.pack(fill=tk.BOTH, expand=True)
        self.status_area.tag_config("active", foreground="#4fc3f7")
        self.status_area.tag_config("waiting", foreground="#ffb74d")
        self.status_area.tag_config("header", foreground="#81c784")
        self.status_area.tag_config("count", foreground="#e0e0e0")

        self._last_status_data = None
        self.root.after(100, self.process_queue)
        self.root.after(1000, self._status_auto_refresh)
        self._refresh_interfaces()

        for fn in ["characteristic_combined.txt", "characteristic_alert.txt", "characteristic_original.txt"]:
            if os.path.exists(fn): self.load_probe_file(fn)

    def _refresh_interfaces(self):
        """Refresh interface list in a background thread to avoid blocking the UI."""
        self.btn_refresh.config(state="disabled")

        def _worker():
            scapy_ifaces = get_if_list()
            win_map = _get_windows_adapter_map()
            display_map = {}
            display = []

            for si in scapy_ifaces:
                guid = ""
                if "NPF_{" in si:
                    gs = si.index("NPF_{") + 4
                    ge = si.index("}", gs) if "}" in si[gs:] else len(si)
                    guid = si[gs:ge].lower()
                win_name, status = win_map.get(guid, ("", ""))
                if win_name:
                    short_guid = guid[:8] + "..." if len(guid) > 8 else guid
                    display_str = f"[{status}] {win_name}  (GUID:{short_guid})"
                else:
                    display_str = si
                display.append(display_str)
                display_map[display_str] = si

            # Update UI on main thread
            self.root.after(0, lambda: self._apply_interfaces(display, display_map))

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_interfaces(self, display, display_map):
        """Apply interface list to combobox (must be called on main thread)."""
        self._display_map = display_map
        self._iface_values = display
        self.iface_cb['values'] = display
        if display:
            first = next((d for d in display if "(" in d), display[0])
            self.iface_cb.current(display.index(first))
        self.btn_refresh.config(state="normal")

    def _clear_log(self):
        self._all_logs.clear()
        self.log_area.delete("1.0", tk.END)

    def _render_logs(self):
        """Re-render all log entries based on current filter checkboxes."""
        self.log_area.delete("1.0", tk.END)
        show = {
            'CLIENT': self.show_client.get(),
            'SERVER': self.show_server.get(),
            'ALERT':  self.show_detect.get(),
            'DETECT': self.show_detect.get(),
            'SYS':    True,
            'INFO':   True,
            'DEBUG':  self.show_client.get(),
            'IP_SKIP': self.show_skip.get(),
        }
        for level, msg, tag in self._all_logs:
            if show.get(level, True):
                self.log_area.insert(tk.END, msg + "\n", tag)
        if self.auto_scroll.get():
            self.log_area.see(tk.END)

    def _render_status(self, data):
        """Update the status panel with current probe info."""
        self._last_status_data = data
        now = time.monotonic()
        scroll_pos = self.status_area.yview()
        self.status_area.config(state=tk.NORMAL)
        self.status_area.delete("1.0", tk.END)

        active = data.get("active", [])
        waiting = data.get("waiting", [])
        pending = data.get("pending", [])
        white = data.get("white", 0)
        black = data.get("black", 0)
        white_list = data.get("white_list", [])
        black_list = data.get("black_list", [])

        if black_list:
            self.status_area.insert(tk.END, f"Blacklist ({black})\n", "header")
            for ip, port, sni in black_list[:6]:
                self.status_area.insert(tk.END, f"  {ip}:{port}\n  {sni}\n", "active")

        if white_list:
            self.status_area.insert(tk.END, f"Whitelist ({white})\n", "header")
            for ip, port, sni in white_list[:6]:
                self.status_area.insert(tk.END, f"  {ip}:{port}\n  {sni}\n", "waiting")

        if not black_list and not white_list:
            self.status_area.insert(tk.END, f"Lists  B:{black} W:{white}\n\n", "count")

        self.status_area.insert(tk.END, f"Active ({len(active)})\n", "header")
        for ip, port, sni, rd, rt, st, bn in active:
            elapsed = now - st if st else 0
            bar = "#" * rd + "." * (rt - rd)
            self.status_area.insert(tk.END, f"  {ip}:{port}\n", "active")
            self.status_area.insert(tk.END, f"  {sni}\n", "active")
            self.status_area.insert(tk.END, f"  [{bar}] {rd}/{rt}  Batch {bn}/{WHITELIST_FAIL_THRESHOLD}  ({elapsed:.0f}s)\n\n", "active")

        pending = data.get("pending", [])
        if pending:
            self.status_area.insert(tk.END, f"Pending ({len(pending)})\n", "header")
            for ip, port, sni, bn in pending[:6]:
                self.status_area.insert(tk.END, f"  {ip}:{port}  Batch {bn}/{WHITELIST_FAIL_THRESHOLD}  {sni}\n", "waiting")

        if waiting:
            self.status_area.insert(tk.END, f"Cooldown ({len(waiting)})\n", "header")
            for item in waiting[:8]:
                ip, port, sni, remain = item[0], item[1], item[2], item[3]
                bn = item[4] if len(item) > 4 else 1
                self.status_area.insert(tk.END, f"  {ip}:{port}  Batch {bn}/{WHITELIST_FAIL_THRESHOLD}  {remain:.0f}s\n", "waiting")

        if not active and not waiting and not pending:
            self.status_area.insert(tk.END, "\n  Idle\n", "count")

        self.status_area.config(state=tk.DISABLED)
        # Restore scroll position
        if scroll_pos and scroll_pos[0] > 0:
            self.status_area.yview_moveto(scroll_pos[0])

    def _status_auto_refresh(self):
        """Refresh status panel every second for real-time elapsed/remaining times."""
        if self._last_status_data is not None:
            self._render_status(self._last_status_data)
        self.root.after(1000, self._status_auto_refresh)

    def load_probe(self):
        paths = filedialog.askopenfilenames(filetypes=[("Probe files", "*.txt"), ("All files", "*.*")])
        for path in paths: self.load_probe_file(path)

    def load_probe_file(self, path):
        try:
            probes = []
            with open(path, 'rb') as f:
                for line in f:
                    h = line.split(b'#')[0].replace(b' ', b'').replace(b':', b'').strip()
                    if h: probes.append(binascii.unhexlify(h))
            if probes:
                ps = ProbeSet(os.path.basename(path), probes)
                self.app.probe_sets.append(ps)
                self.probe_label.config(text=f"{len(self.app.probe_sets)} set(s)")
                self.log(f"[SYS] Loaded '{ps.name}' ({len(probes)} probes)")
        except Exception as e:
            self.log(f"[ERR] Failed to load {path}: {e}")

    def toggle(self):
        if not self.app.running:
            if not self.app.probe_sets:
                messagebox.showwarning("Warning", "Load at least one probe file first.")
                return
            iface_raw = self.iface_cb.get()
            iface = self._display_map.get(iface_raw, iface_raw)
            if not iface: return

            self.app.running = True
            self.btn_start.config(text="Stop Capture")
            self.iface_cb.config(state="disabled")
            # Bind probe sockets to this interface to bypass TUN/VPN routing
            try:
                from scapy.all import get_if_addr
                self.app.bind_addr = (get_if_addr(iface), 0)
            except Exception:
                self.app.bind_addr = None
            self.sniffer_thread = threading.Thread(
                target=lambda: sniff(
                    iface=iface,
                    prn=lambda p: process_packet(self.app, p,
                        self.exclude_lan.get()),
                    store=0,
                    stop_filter=lambda _: not self.app.running,
                ), daemon=True)
            self.sniffer_thread.start()
            self.log("[SYS] Capture started.")
            self.app._push_status()
        else:
            self.app.running = False
            self.btn_start.config(text="Start Capture")
            self.iface_cb.config(state="normal")
            self.log("[SYS] Capture stopped.")
            self.app._push_status()

    def log(self, msg, level="INFO"):
        self.ui_queue.put({"type": "log", "level": level, "msg": msg})

    def process_queue(self):
        while not self.ui_queue.empty():
            item = self.ui_queue.get()
            itype = item.get('type', 'log')

            if itype == 'STATUS':
                self._render_status(item)
                continue

            level = item.get('level', 'INFO')
            msg = item['msg']

            # Determine tag and whether to skip display
            if level == "ALERT":
                tag = "alert"
            elif level == "DETECT":
                tag = "alert"
            elif level == "SERVER":
                tag = "server"
            elif level == "CLIENT":
                tag = "client"
            elif level in ("SYS", "INFO"):
                tag = "sys"
            elif level in ("IP_SKIP", "DEBUG"):
                tag = "skip"
            else:
                tag = None

            self._all_logs.append((level, msg, tag))

            # Check filter for this level
            show = {
                'CLIENT': self.show_client.get(),
                'SERVER': self.show_server.get(),
                'ALERT':  self.show_detect.get(),
                'DETECT': self.show_detect.get(),
                'SYS':    True, 'INFO': True,
                'DEBUG':  self.show_client.get(),
                'IP_SKIP': self.show_skip.get(),
            }
            if show.get(level, True):
                self.log_area.insert(tk.END, msg + "\n", tag)
                if self.auto_scroll.get():
                    self.log_area.see(tk.END)
        self.root.after(100, self.process_queue)

if __name__ == "__main__":
    root = tk.Tk()
    ui = AppUI(root)
    root.mainloop()
