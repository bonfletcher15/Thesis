import os
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import traceback
import sys
import subprocess

import pandas as pd

from scanner import scan_networks, detect_anomalies
from history_manager import HistoryManager
from threat_detector import ThreatDetector

class WiFiScannerGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Scannix")
        self.root.geometry("320x150")
        self.root.resizable(False, False)

        self.scanning = False
        self.scan_thread = None
        self.stop_window = None

        # Initialize history and threat detection
        self.history = HistoryManager()
        self.threat_detector = ThreatDetector(self.history)

        ttk.Label(root, text="Scan interval (seconds):").pack(pady=5)
        self.interval_var = tk.StringVar(value="10")
        ttk.Entry(root, textvariable=self.interval_var, width=10).pack()

        ttk.Button(root, text="Start", command=self.start_scanning).pack(pady=10)
        ttk.Button(root, text="Manage Whitelist", command=self.open_whitelist_manager).pack(pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        self.stop_scanning(from_close=True)  
        self.root.destroy()

    def start_scanning(self):
        if self.scanning:
            return

        try:
            interval = int(self.interval_var.get())
            if interval < 3 or interval > 600:
                raise ValueError("out_of_range")
        except ValueError as e:
            if str(e) == "out_of_range":
                messagebox.showerror(
                    "Invalid Input",
                    "Scan interval must be between 3 and 600 seconds."
                )
            else:
                messagebox.showerror(
                    "Invalid Input",
                    "Please enter a valid number."
                )
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
                path = self.save_scan(df)

                # Add scan to history database
                self.history.add_scan(df)

                # Detect anomalies
                anomalies = detect_anomalies(df)

                # Detect advanced threats
                threats = self.threat_detector.detect_all_threats(df)

                # Show anomaly popups first
                if anomalies:
                    # Show popups sequentially (one per anomaly type) with delay
                    for i, anomaly in enumerate(anomalies):
                        # Delay each popup by 500ms to prevent overlap
                        delay = i * 500
                        self.root.after(delay, lambda a=anomaly, p=path: self.show_anomaly_popup([a], p))

                # Show threat popups after anomalies (with additional delay)
                if threats:
                    base_delay = len(anomalies) * 500
                    for i, threat in enumerate(threats):
                        delay = base_delay + (i * 500)
                        self.root.after(delay, lambda t=threat, p=path: self.show_threat_popup(t, p))
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

        # Enhanced terminal output
        from scanner import format_scan_summary
        print("\n" + "="*60)
        print(f"Scan saved: file://{os.path.abspath(path)}")
        print("="*60)
        print(format_scan_summary(df))
        print(f"\nFull results: file://{os.path.abspath(path)}")
        print("="*60 + "\n")

        return path

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

    def show_anomaly_popup(self, anomalies, file_path):
        """
        Show alert popup for anomaly/anomalies

        Args:
            anomalies: List containing ONE anomaly dict (for Phase 2)
            file_path: Path to scan CSV file
        """
        if not anomalies:
            return

        anomaly = anomalies[0]  # Phase 2: one popup per anomaly type
        anomaly_type = anomaly['type']

        win = tk.Toplevel(self.root)
        win.title(f"Threat Alert - {anomaly_type}")
        win.geometry("500x400")
        win.resizable(False, False)
        win.attributes("-topmost", True)

        # Severity indicator
        severity = anomaly.get('severity', 'unknown').upper()
        severity_colors = {
            'CRITICAL': '#ff4444',
            'HIGH': '#ff8800',
            'MEDIUM': '#ffbb00',
            'LOW': '#88ff88'
        }
        bg_color = severity_colors.get(severity, '#cccccc')

        # Header frame with severity
        header_frame = tk.Frame(win, bg=bg_color, height=50)
        header_frame.pack(fill='x')
        tk.Label(
            header_frame,
            text=f"⚠️  {anomaly['type']}",
            bg=bg_color,
            font=("Arial", 14, "bold")
        ).pack(pady=10)

        # Details frame
        details_frame = tk.Frame(win)
        details_frame.pack(fill='both', expand=True, padx=20, pady=10)

        details = anomaly.get('details')
        count = len(details) if details is not None else 0

        info_text = f"Found {count} network(s)\n\n"

        # Device type breakdown
        if details is not None and 'DeviceType' in details.columns:
            device_types = details['DeviceType'].value_counts()
            info_text += "Device Types:\n"
            for dtype, cnt in device_types.items():
                info_text += f"  • {dtype}: {cnt}\n"
            info_text += "\n"

        # Show first 5 networks
        if details is not None:
            info_text += "Networks:\n"
            for _, row in details.head(5).iterrows():
                ssid = str(row.get('SSID', 'Unknown'))[:30]
                bssid = str(row.get('BSSID', 'Unknown'))
                info_text += f"  • {ssid}\n    {bssid}\n"

            if count > 5:
                info_text += f"\n... and {count - 5} more (see CSV file)"

        tk.Label(
            details_frame,
            text=info_text,
            justify="left",
            font=("monospace", 9)
        ).pack(anchor='w')

        # Button frame
        button_frame = tk.Frame(win)
        button_frame.pack(fill='x', padx=20, pady=15)

        # Check if network is already whitelisted
        from scanner import load_whitelist
        whitelist = load_whitelist()
        is_whitelisted = False

        if details is not None and not details.empty:
            if anomaly_type == "Evil Twin" or anomaly_type == "Trusted Network - New Device":
                ssid = details['SSID'].iloc[0]
                is_whitelisted = ssid in whitelist.get("trusted_networks", {})
            elif anomaly_type == "Unencrypted Networks":
                bssid = details['BSSID'].iloc[0].lower()
                is_whitelisted = bssid in whitelist.get("trusted_open_networks", {})
            elif anomaly_type == "Weak Encryption":
                bssid = details['BSSID'].iloc[0].lower()
                is_whitelisted = bssid in whitelist.get("trusted_weak_encryption", {})

        # Trust/Untrust button
        if is_whitelisted and anomaly_type != "Trusted Network - New Device":
            # Show Untrust button for already whitelisted networks
            trust_btn = tk.Button(
                button_frame,
                text="Untrust This Network",
                command=lambda: self.untrust_network(anomaly, win),
                bg='#ff6666',
                fg='white',
                font=("Arial", 10, "bold")
            )
        else:
            # Show Trust button for non-whitelisted networks
            trust_btn = tk.Button(
                button_frame,
                text="Trust This Network",
                command=lambda: self.trust_network(anomaly, win),
                bg='#4CAF50',
                fg='white',
                font=("Arial", 10, "bold")
            )
        trust_btn.pack(side='left', padx=5)

        # Open file button
        def open_file():
            try:
                if sys.platform.startswith("linux"):
                    subprocess.call(["xdg-open", file_path])
                elif sys.platform == "darwin":
                    subprocess.call(["open", file_path])
                else:
                    os.startfile(file_path)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(
            button_frame,
            text="Open File",
            command=open_file
        ).pack(side='left', padx=5)

        # Close button
        tk.Button(
            button_frame,
            text="Close",
            command=win.destroy
        ).pack(side='right', padx=5)

    def show_threat_popup(self, threat, file_path):
        """
        Show alert popup for advanced threat detection

        Args:
            threat: Threat dict with type, severity, details, context
            file_path: Path to scan CSV file
        """
        threat_type = threat['type']
        severity = threat.get('severity', 'medium').upper()
        context = threat.get('context', {})

        win = tk.Toplevel(self.root)
        win.title(f"Advanced Threat - {threat_type}")
        win.geometry("600x500")
        win.resizable(True, True)
        win.attributes("-topmost", True)

        # Severity colors
        severity_colors = {
            'CRITICAL': '#ff0000',
            'HIGH': '#ff6600',
            'MEDIUM': '#ffaa00',
            'LOW': '#ffdd00'
        }
        bg_color = severity_colors.get(severity, '#cccccc')

        # Header
        header_frame = tk.Frame(win, bg=bg_color, height=60)
        header_frame.pack(fill='x')
        tk.Label(
            header_frame,
            text=f"🛡️  {threat_type}",
            bg=bg_color,
            fg='white',
            font=("Arial", 16, "bold")
        ).pack(pady=5)
        tk.Label(
            header_frame,
            text=f"Severity: {severity}",
            bg=bg_color,
            fg='white',
            font=("Arial", 10)
        ).pack()

        # Scrollable details frame
        canvas = tk.Canvas(win)
        scrollbar = ttk.Scrollbar(win, orient="vertical", command=canvas.yview)
        details_frame = ttk.Frame(canvas)

        details_frame.bind(
            "<Configure>",
            lambda _: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=details_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Build threat details
        self._build_threat_details(details_frame, threat)

        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)

        # Button frame
        button_frame = tk.Frame(win)
        button_frame.pack(fill='x', padx=20, pady=15)

        # Mark as False Positive button
        tk.Button(
            button_frame,
            text="Mark False Positive",
            command=lambda: self.mark_false_positive(threat, win),
            bg='#888888',
            fg='white',
            font=("Arial", 10)
        ).pack(side='left', padx=5)

        # Open file button
        def open_file():
            try:
                if sys.platform.startswith("linux"):
                    subprocess.call(["xdg-open", file_path])
                elif sys.platform == "darwin":
                    subprocess.call(["open", file_path])
                else:
                    os.startfile(file_path)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(
            button_frame,
            text="Open Scan File",
            command=open_file,
            font=("Arial", 10)
        ).pack(side='left', padx=5)

        # Close button
        tk.Button(
            button_frame,
            text="Close",
            command=win.destroy,
            font=("Arial", 10)
        ).pack(side='right', padx=5)

    def _build_threat_details(self, parent, threat):
        """Build detailed threat information display"""
        threat_type = threat['type']
        context = threat.get('context', {})
        details = threat.get('details')

        # Threat description
        descriptions = {
            'Vendor Spoofing': "A network's MAC address vendor doesn't match its SSID, suggesting possible spoofing or rogue AP.",
            'Encryption Downgrade': "A known network has switched to weaker encryption, possibly indicating an attack or misconfiguration.",
            'Suspicious SSID': "Network name contains suspicious characters that could indicate a spoofing attempt.",
            'Signal Strength Anomaly': "Network signal strength has increased significantly from baseline, possibly indicating a rogue AP nearby.",
            'Beacon Flood': "Unusually high number of networks detected on a single channel, possible DoS attack or WiFi scanner."
        }

        desc = descriptions.get(threat_type, "Advanced threat detected.")

        tk.Label(
            parent,
            text="Description:",
            font=("Arial", 11, "bold")
        ).pack(anchor='w', pady=(10, 5))

        tk.Label(
            parent,
            text=desc,
            font=("Arial", 10),
            wraplength=550,
            justify="left"
        ).pack(anchor='w', padx=10)

        # Context details
        if context:
            tk.Label(
                parent,
                text="\nTechnical Details:",
                font=("Arial", 11, "bold")
            ).pack(anchor='w', pady=(10, 5))

            context_text = ""
            for key, value in context.items():
                if key == 'reasons' and isinstance(value, list):
                    context_text += f"Reasons:\n"
                    for reason in value:
                        context_text += f"  • {reason}\n"
                elif key not in ['char_analysis']:
                    context_text += f"{key.replace('_', ' ').title()}: {value}\n"

            tk.Label(
                parent,
                text=context_text,
                font=("monospace", 9),
                justify="left"
            ).pack(anchor='w', padx=10)

        # Network details
        if details is not None and not details.empty:
            tk.Label(
                parent,
                text="\nAffected Network(s):",
                font=("Arial", 11, "bold")
            ).pack(anchor='w', pady=(10, 5))

            # Show network details in a formatted way
            for _, row in details.head(10).iterrows():
                network_text = f"SSID: {row.get('SSID', 'Unknown')}\n"
                network_text += f"BSSID: {row.get('BSSID', 'Unknown')}\n"
                if 'Encryption' in row:
                    network_text += f"Encryption: {row['Encryption']}\n"
                if 'Vendor' in row:
                    network_text += f"Vendor: {row['Vendor']}\n"
                if 'Signal' in row:
                    network_text += f"Signal: {row['Signal']} dBm\n"

                frame = tk.LabelFrame(parent, text="Network", padx=10, pady=5)
                frame.pack(fill='x', padx=10, pady=5)

                tk.Label(
                    frame,
                    text=network_text,
                    font=("monospace", 8),
                    justify="left"
                ).pack(anchor='w')

            if len(details) > 10:
                tk.Label(
                    parent,
                    text=f"... and {len(details) - 10} more networks",
                    font=("Arial", 9, "italic"),
                    fg="gray"
                ).pack(anchor='w', padx=10, pady=5)

        # Remediation suggestions
        remediations = {
            'Vendor Spoofing': "• Verify this is a legitimate network\n• Check physical device to confirm vendor\n• Avoid connecting if unrecognized",
            'Encryption Downgrade': "• Do NOT connect to this network\n• Contact network administrator\n• Verify router configuration hasn't been compromised",
            'Suspicious SSID': "• Verify network name with administrator\n• Check for lookalike networks\n• Avoid connecting if suspicious",
            'Signal Strength Anomaly': "• Check for unauthorized devices nearby\n• Verify network BSSID matches expected\n• May indicate Evil Twin attack",
            'Beacon Flood': "• May be in high-density area (normal)\n• Could indicate DoS attack\n• Monitor for network disruption"
        }

        if threat_type in remediations:
            tk.Label(
                parent,
                text="\nRecommended Actions:",
                font=("Arial", 11, "bold")
            ).pack(anchor='w', pady=(10, 5))

            tk.Label(
                parent,
                text=remediations[threat_type],
                font=("Arial", 10),
                justify="left",
                fg="#cc0000"
            ).pack(anchor='w', padx=10)

    def mark_false_positive(self, threat, popup_window):
        """Mark threat as false positive (for future tuning)"""
        response = messagebox.askyesno(
            "Mark False Positive",
            f"Mark this '{threat['type']}' detection as a false positive?\n\n"
            "This will be logged for future detection tuning.",
            parent=popup_window
        )

        if response:
            # Log as false positive
            # In future, this could adjust detection thresholds
            messagebox.showinfo(
                "Logged",
                "Marked as false positive. Thank you for the feedback!",
                parent=popup_window
            )
            popup_window.destroy()

    def trust_network(self, anomaly, popup_window):
        """
        Handle "Trust This Network" button click

        Args:
            anomaly: Anomaly dict with 'type' and 'details'
            popup_window: Tkinter window to close after trusting
        """
        anomaly_type = anomaly['type']
        details = anomaly.get('details')

        if details is None or details.empty:
            messagebox.showerror("Error", "No network details available")
            return

        # Different handling per anomaly type
        if anomaly_type == "Evil Twin":
            self.trust_evil_twin(details, popup_window)
        elif anomaly_type == "Unencrypted Networks":
            self.trust_open_network(details, popup_window)
        elif anomaly_type == "Weak Encryption":
            self.trust_weak_encryption(details, popup_window)
        elif anomaly_type == "Trusted Network - New Device":
            self.trust_new_bssid(anomaly, popup_window)

    def untrust_network(self, anomaly, popup_window):
        """
        Handle "Untrust This Network" button click

        Args:
            anomaly: Anomaly dict with 'type' and 'details'
            popup_window: Tkinter window to close after untrusting
        """
        from scanner import load_whitelist, save_whitelist

        anomaly_type = anomaly['type']
        details = anomaly.get('details')

        if details is None or details.empty:
            messagebox.showerror("Error", "No network details available")
            return

        try:
            whitelist = load_whitelist()

            # Different handling per anomaly type
            if anomaly_type == "Evil Twin":
                ssid = details['SSID'].iloc[0]
                confirm_msg = f"Remove network '{ssid}' from whitelist?\n\n"
                confirm_msg += "Future scans will trigger Evil Twin alerts for this network."

                # Bring window to front before showing dialog
                popup_window.lift()
                popup_window.focus_force()
                response = messagebox.askyesno("Untrust Network", confirm_msg, parent=popup_window)

                if response and ssid in whitelist["trusted_networks"]:
                    del whitelist["trusted_networks"][ssid]
                    save_whitelist(whitelist)
                    messagebox.showinfo("Success", f"Network '{ssid}' removed from whitelist", parent=popup_window)
                    popup_window.destroy()

            elif anomaly_type == "Unencrypted Networks":
                bssid = details['BSSID'].iloc[0].lower()
                ssid = details['SSID'].iloc[0]
                confirm_msg = f"Remove open network '{ssid}' ({bssid}) from whitelist?\n\n"
                confirm_msg += "Future scans will trigger unencrypted network alerts."

                popup_window.lift()
                popup_window.focus_force()
                response = messagebox.askyesno("Untrust Network", confirm_msg, parent=popup_window)

                if response and bssid in whitelist["trusted_open_networks"]:
                    del whitelist["trusted_open_networks"][bssid]
                    save_whitelist(whitelist)
                    messagebox.showinfo("Success", f"Network '{ssid}' removed from whitelist", parent=popup_window)
                    popup_window.destroy()

            elif anomaly_type == "Weak Encryption":
                bssid = details['BSSID'].iloc[0].lower()
                ssid = details['SSID'].iloc[0]
                confirm_msg = f"Remove weak encryption network '{ssid}' ({bssid}) from whitelist?\n\n"
                confirm_msg += "Future scans will trigger weak encryption alerts."

                popup_window.lift()
                popup_window.focus_force()
                response = messagebox.askyesno("Untrust Network", confirm_msg, parent=popup_window)

                if response and bssid in whitelist["trusted_weak_encryption"]:
                    del whitelist["trusted_weak_encryption"][bssid]
                    save_whitelist(whitelist)
                    messagebox.showinfo("Success", f"Network '{ssid}' removed from whitelist", parent=popup_window)
                    popup_window.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove from whitelist: {e}", parent=popup_window)

    def trust_evil_twin(self, details_df, popup_window):
        """Trust an SSID with its current BSSIDs"""
        from scanner import load_whitelist, save_whitelist

        # Get SSID and all BSSIDs for this evil twin
        ssid = details_df['SSID'].iloc[0]
        bssids = details_df['BSSID'].tolist()
        vendors = details_df['Vendor'].tolist()

        # Build confirmation message
        confirm_msg = f"Trust network '{ssid}'?\n\n"
        confirm_msg += "This will whitelist the following BSSIDs:\n"
        for bssid, vendor in zip(bssids, vendors):
            confirm_msg += f"  • {bssid} ({vendor})\n"
        confirm_msg += "\nFuture alerts will only trigger if NEW devices join this network.\n\n"
        confirm_msg += "Are you sure?"

        # Bring window to front before showing dialog
        popup_window.lift()
        popup_window.focus_force()
        response = messagebox.askyesno("Trust Network", confirm_msg, parent=popup_window)

        if not response:
            return

        try:
            # Load current whitelist
            whitelist = load_whitelist()

            # Add or update trusted network
            whitelist["trusted_networks"][ssid] = {
                "allowed_bssids": [b.lower() for b in bssids],
                "added_date": datetime.now().isoformat(),
                "added_method": "user_trust_button",
                "note": f"Trusted Evil Twin with {len(bssids)} BSSIDs"
            }

            # Save whitelist
            save_whitelist(whitelist)

            messagebox.showinfo("Success", f"Network '{ssid}' added to whitelist")
            popup_window.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save whitelist: {e}")

    def trust_open_network(self, details_df, popup_window):
        """Trust an unencrypted network (per-BSSID)"""
        from scanner import load_whitelist, save_whitelist

        # For simplicity, trust the first network (user can call multiple times for multiple networks)
        row = details_df.iloc[0]
        ssid = row['SSID']
        bssid = row['BSSID'].lower()

        confirm_msg = f"⚠️ WARNING ⚠️\n\n"
        confirm_msg += f"Network '{ssid}' ({bssid}) has NO ENCRYPTION.\n\n"
        confirm_msg += "All traffic on this network can be intercepted.\n\n"
        confirm_msg += "Trust this network anyway?"

        # Bring window to front before showing dialog
        popup_window.lift()
        popup_window.focus_force()
        response = messagebox.askyesno("Trust Unencrypted Network", confirm_msg, parent=popup_window)

        if not response:
            return

        try:
            whitelist = load_whitelist()

            whitelist["trusted_open_networks"][bssid] = {
                "ssid": ssid,
                "added_date": datetime.now().isoformat(),
                "added_method": "user_trust_button",
                "note": "User-trusted open network"
            }

            save_whitelist(whitelist)

            messagebox.showinfo("Success", f"Open network '{ssid}' added to whitelist")
            popup_window.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save whitelist: {e}")

    def trust_weak_encryption(self, details_df, popup_window):
        """Trust a network with weak encryption (per-BSSID)"""
        from scanner import load_whitelist, save_whitelist

        row = details_df.iloc[0]
        ssid = row['SSID']
        bssid = row['BSSID'].lower()
        encryption = row['Encryption']

        confirm_msg = f"⚠️ WARNING ⚠️\n\n"
        confirm_msg += f"Network '{ssid}' ({bssid}) uses weak {encryption} encryption.\n\n"
        confirm_msg += "This encryption can be cracked. Recommend upgrading to WPA2/WPA3.\n\n"
        confirm_msg += "Trust this network anyway?"

        # Bring window to front before showing dialog
        popup_window.lift()
        popup_window.focus_force()
        response = messagebox.askyesno("Trust Weak Encryption", confirm_msg, parent=popup_window)

        if not response:
            return

        try:
            whitelist = load_whitelist()

            whitelist["trusted_weak_encryption"][bssid] = {
                "ssid": ssid,
                "encryption": encryption,
                "added_date": datetime.now().isoformat(),
                "added_method": "user_trust_button"
            }

            save_whitelist(whitelist)

            messagebox.showinfo("Success", f"Weak encryption network '{ssid}' added to whitelist")
            popup_window.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save whitelist: {e}")

    def trust_new_bssid(self, anomaly, popup_window):
        """Add new BSSID to existing trusted network"""
        from scanner import load_whitelist, save_whitelist

        details_df = anomaly['details']
        context = anomaly.get('context', {})

        ssid = details_df['SSID'].iloc[0]
        new_bssids = context.get('new_bssids', [])
        known_bssids = context.get('known_bssids', [])

        confirm_msg = f"Add new device(s) to trusted network '{ssid}'?\n\n"
        confirm_msg += f"Known BSSIDs ({len(known_bssids)}):\n"
        for bssid in known_bssids:
            confirm_msg += f"  ✓ {bssid}\n"
        confirm_msg += f"\nNew BSSIDs ({len(new_bssids)}):\n"
        for bssid in new_bssids:
            vendor = details_df[details_df['BSSID'].str.lower() == bssid]['Vendor'].iloc[0]
            confirm_msg += f"  ⚠️ {bssid} ({vendor})\n"
        confirm_msg += "\nOnly add if you recognize these devices!\n\nContinue?"

        # Bring window to front before showing dialog
        popup_window.lift()
        popup_window.focus_force()
        response = messagebox.askyesno("Add New Device to Trusted Network", confirm_msg, parent=popup_window)

        if not response:
            return

        try:
            whitelist = load_whitelist()

            # Update existing trusted network
            if ssid in whitelist["trusted_networks"]:
                current_bssids = whitelist["trusted_networks"][ssid].get("allowed_bssids", [])
                updated_bssids = list(set(current_bssids + new_bssids))
                whitelist["trusted_networks"][ssid]["allowed_bssids"] = updated_bssids
                whitelist["trusted_networks"][ssid]["last_updated"] = datetime.now().isoformat()

            save_whitelist(whitelist)

            messagebox.showinfo("Success", f"Added {len(new_bssids)} new device(s) to '{ssid}' whitelist")
            popup_window.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to update whitelist: {e}")

    def open_whitelist_manager(self):
        """Open whitelist management window"""
        from scanner import load_whitelist

        manager_win = tk.Toplevel(self.root)
        manager_win.title("Scannix - Whitelist Manager")
        manager_win.geometry("600x450")
        manager_win.resizable(True, True)

        # Load current whitelist
        whitelist = load_whitelist()

        # Header
        header = tk.Frame(manager_win, bg='#2c3e50', height=50)
        header.pack(fill='x')
        tk.Label(
            header,
            text="Trusted Networks Whitelist",
            bg='#2c3e50',
            fg='white',
            font=("Arial", 14, "bold")
        ).pack(pady=10)

        # Create notebook (tabbed interface)
        notebook = ttk.Notebook(manager_win)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Tab 1: Trusted Networks (Evil Twin exceptions)
        trusted_frame = ttk.Frame(notebook)
        notebook.add(trusted_frame, text=f"Evil Twin Exceptions ({len(whitelist.get('trusted_networks', {}))})")
        self.build_whitelist_tab(trusted_frame, whitelist, "trusted_networks", manager_win)

        # Tab 2: Open Networks
        open_frame = ttk.Frame(notebook)
        notebook.add(open_frame, text=f"Open Networks ({len(whitelist.get('trusted_open_networks', {}))})")
        self.build_whitelist_tab(open_frame, whitelist, "trusted_open_networks", manager_win)

        # Tab 3: Weak Encryption
        weak_frame = ttk.Frame(notebook)
        notebook.add(weak_frame, text=f"Weak Encryption ({len(whitelist.get('trusted_weak_encryption', {}))})")
        self.build_whitelist_tab(weak_frame, whitelist, "trusted_weak_encryption", manager_win)

        # Bottom buttons
        button_frame = tk.Frame(manager_win)
        button_frame.pack(fill='x', padx=10, pady=10)

        tk.Button(
            button_frame,
            text="Refresh",
            command=lambda: self.refresh_whitelist_manager(manager_win),
            bg='#3498db',
            fg='white',
            font=("Arial", 10)
        ).pack(side='left', padx=5)

        tk.Button(
            button_frame,
            text="Close",
            command=manager_win.destroy,
            font=("Arial", 10)
        ).pack(side='right', padx=5)

    def build_whitelist_tab(self, parent, whitelist, category, manager_win):
        """Build a whitelist category tab"""
        # Scrollable frame
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda _: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Display entries
        entries = whitelist.get(category, {})

        if not entries:
            tk.Label(
                scrollable_frame,
                text="No entries in this category",
                fg="gray",
                font=("Arial", 11)
            ).pack(pady=30)
        else:
            for key, data in entries.items():
                self.create_whitelist_entry(scrollable_frame, key, data, whitelist, category, manager_win)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def create_whitelist_entry(self, parent, key, data, whitelist, category, manager_win):
        """Create a single whitelist entry widget"""
        from scanner import save_whitelist

        frame = tk.LabelFrame(parent, text=key, padx=10, pady=5, font=("Arial", 10, "bold"))
        frame.pack(fill='x', padx=10, pady=5)

        # Display details based on category
        if category == "trusted_networks":
            # Evil Twin exception - show SSID and BSSIDs
            bssids = data.get("allowed_bssids", [])
            tk.Label(
                frame,
                text=f"SSID: {key}",
                font=("Arial", 9, "bold")
            ).pack(anchor='w', pady=2)
            tk.Label(
                frame,
                text=f"Allowed BSSIDs ({len(bssids)}):",
                font=("Arial", 9)
            ).pack(anchor='w', pady=2)
            for bssid in bssids:
                tk.Label(
                    frame,
                    text=f"  • {bssid}",
                    font=("monospace", 8)
                ).pack(anchor='w')
        else:
            # Open/Weak - show BSSID and SSID
            ssid = data.get("ssid", "Unknown")
            tk.Label(
                frame,
                text=f"SSID: {ssid}",
                font=("Arial", 9)
            ).pack(anchor='w', pady=2)
            tk.Label(
                frame,
                text=f"BSSID: {key}",
                font=("monospace", 8)
            ).pack(anchor='w', pady=2)
            if "encryption" in data:
                tk.Label(
                    frame,
                    text=f"Encryption: {data['encryption']}",
                    font=("Arial", 8)
                ).pack(anchor='w', pady=2)

        # Metadata
        added_date = data.get("added_date", "Unknown")
        added_method = data.get("added_method", "Unknown")
        tk.Label(
            frame,
            text=f"Added: {added_date[:10]} ({added_method})",
            font=("Arial", 8),
            fg="gray"
        ).pack(anchor='w', pady=2)

        if "note" in data:
            tk.Label(
                frame,
                text=f"Note: {data['note']}",
                font=("Arial", 8, "italic"),
                fg="gray"
            ).pack(anchor='w', pady=2)

        # Remove button
        def remove_entry():
            category_names = {
                "trusted_networks": "Evil Twin exception",
                "trusted_open_networks": "open network",
                "trusted_weak_encryption": "weak encryption network"
            }
            response = messagebox.askyesno(
                "Confirm Remove",
                f"Remove {category_names.get(category, 'entry')} '{key}' from whitelist?\n\n"
                f"Future scans will trigger alerts for this network.",
                parent=manager_win
            )
            if response:
                try:
                    del whitelist[category][key]
                    save_whitelist(whitelist)
                    messagebox.showinfo("Success", f"Removed '{key}' from whitelist", parent=manager_win)
                    # Refresh the manager window
                    self.refresh_whitelist_manager(manager_win)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to remove: {e}", parent=manager_win)

        tk.Button(
            frame,
            text="Remove",
            command=remove_entry,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 9, "bold")
        ).pack(anchor='e', pady=5)

    def refresh_whitelist_manager(self, manager_win):
        """Reload whitelist from file and refresh UI"""
        import scanner
        scanner._whitelist_cache = None  # Invalidate cache

        manager_win.destroy()
        self.open_whitelist_manager()

if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiScannerGUI(root)
    root.mainloop()