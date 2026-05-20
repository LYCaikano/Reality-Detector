#!/usr/bin/env python3
"""VLESS/REALITY Detector — one-click launcher.

Runs the detector GUI directly (PyInstaller compatible).
"""

import os
import sys
import traceback

# Set working directory to exe directory for PyInstaller compatibility
if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))
else:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))


def main():
    try:
        import tkinter as tk
        from vless_detector import AppUI
        root = tk.Tk()
        AppUI(root)
        root.mainloop()
    except Exception as e:
        error_msg = f"Startup error:\n\n{e}\n\n{traceback.format_exc()}"
        try:
            import tkinter as tk
            from tkinter import messagebox
            err_root = tk.Tk()
            err_root.withdraw()
            messagebox.showerror("Reality Detector - Error", error_msg)
            err_root.destroy()
        except Exception:
            print(error_msg, file=sys.stderr)
            input("Press Enter to exit...")


if __name__ == "__main__":
    main()
