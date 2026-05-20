#!/usr/bin/env python3
"""VLESS/REALITY Detector — one-click launcher.

Runs:
  1. gen_geo_cache.py  — build CN IP/domain cache (skips if up-to-date)
  2. vless_detector.py — start GUI
"""

import os
import sys
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def step(name, script):
    path = os.path.join(SCRIPT_DIR, script)
    if not os.path.exists(path):
        print(f"[SKIP] {name} — {script} not found")
        return
    print(f"[RUN]  {name}")
    subprocess.run([sys.executable, path], cwd=SCRIPT_DIR, check=True)
    print(f"[DONE] {name}\n")


def main():
    # gen_geo_cache is auto-run by vless_detector.py on import
    step("Start detector GUI", "vless_detector.py")


if __name__ == "__main__":
    main()
