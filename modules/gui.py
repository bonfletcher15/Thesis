import os
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import traceback

import pandas as pd

from scanner import scan_networks

class WiFiScannerGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Scannix")
        self.root.geometry("320x150")
        self.root.resizable(False, False)

        self.scanning = False
        self.scan_thread = None
        self.stop_window = None

        ttk.Label(root, text="Scan interval (seconds):").pack(pady=5)
        self.interval_var = tk.StringVar(value="10")
        ttk.Entry(root, textvariable=self.interval_var, width=10).pack()

        ttk.Button(root, text="Start", command=self.start_scanning).pack(pady=15)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        self.stop_scanning(from_close=True)  
        self.root.destroy()

    def start_scanning(self):
        if self.scanning:
            return

        try:
            interval = int(self.interval_var.get())
            if interval <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid positive integer.")
            return

        self.scanning = True

        self.root.withdraw()
        self.open_stop_window()

        self.scan_thread = threading.Thread(target=self.scan_loop, args=(interval,), daemon=False)
        self.scan_thread.start()
        

    def scan_loop(self, interval):
        while self.scanning:
            try:
                df = scan_networks()
                self.save_scan(df)
            except PermissionError:
                messagebox.showerror(
                "Permission Denied",
                "Wi-Fi scanning requires root privileges.\n\n"
                "Run this program with: sudo python3 gui.py"
                )
                self.stop_scanning()
                return
            except Exception as e:
                print("Scan failed:", e)
                traceback.print_exc()


            waited = 0
            while self.scanning and waited < interval:
                time.sleep(0.1)
                waited += 0.1

    def save_scan(self, df):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        data_dir = os.path.join(project_root, "data")
        os.makedirs(data_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = os.path.join(data_dir, f"{timestamp}.csv")
        df.to_csv(path, index=False)
        print(f"Saved scan → {path}")

    def open_stop_window(self):
        self.stop_window = tk.Toplevel(self.root)
        self.stop_window.title("Stop")
        self.stop_window.geometry("120x70")
        self.stop_window.resizable(False, False)
        self.stop_window.attributes("-topmost", True)
        self.stop_window.protocol("WM_DELETE_WINDOW", self.stop_scanning)

        ttk.Button(self.stop_window, text="Stop", command=self.stop_scanning).pack(expand=True)

    def stop_scanning(self, from_close=False):
        self.scanning = False
        if self.stop_window:
            self.stop_window.destroy()
            self.stop_window = None
        if not from_close:
            self.root.deiconify()
            messagebox.showinfo("Stopped", "Scanning stopped.")

if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiScannerGUI(root)
    root.mainloop()