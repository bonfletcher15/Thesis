import os
import re
import time
import datetime
import subprocess
import traceback
import json

import pandas as pd
import requests
from pywifi import PyWiFi, const

_vendor_cache = {}
_whitelist_cache = None

def is_SSID_Hidden(ssid):
    if not ssid or not ssid.strip():
        return "Hidden SSID"
    return ssid

def get_encryption(network):
    try:
        akm = getattr(network, "akm", [])
        if not akm:
            return "Open"
        if hasattr(const, "AKM_TYPE_WPA3PSK") and const.AKM_TYPE_WPA3PSK in akm:
            return "WPA3"
        elif const.AKM_TYPE_WPA2PSK in akm:
            return "WPA2"
        elif const.AKM_TYPE_WPAPSK in akm:
            return "WPA"
        else:
            return "Other"
    except Exception:
        return "Other"

def get_freq(network):
    try:
        f = int(network.freq)
        if f > 100000:
            f //= 1000
    except Exception:
        return None, None, None

    if 2412 <= f <= 2472:
        channel = (f - 2407) // 5
        band = "2.4GHz"
    elif f == 2484:
        channel = 14
        band = "2.4GHz"
    elif 5000 <= f <= 6000:
        channel = (f - 5000) // 5
        band = "5GHz"
    elif 5925 <= f <= 7125:
        channel = (f - 5000) // 5  
        band = "6GHz"
    else:
        channel = None
        band = None

    return f, band, channel

def lookup_vendor(bssid):
    if not bssid or ":" not in bssid:
        return "Unknown"

    prefix = ":".join(bssid.split(":")[:3]).upper()
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]

    try:
        url = f"https://api.macvendors.com/{prefix}"
        response = requests.get(url, timeout=1.0)
        vendor = response.text.strip() if response.status_code == 200 else "Unknown"
    except Exception:
        vendor = "Unknown"

    _vendor_cache[prefix] = vendor
    return vendor

def rssi_to_quality(rssi_dbm):
    if rssi_dbm is None:
        return None
    q = 2 * (rssi_dbm + 100)
    return max(0, min(100, int(q)))

def load_whitelist():
    global _whitelist_cache

    if _whitelist_cache is not None:
        return _whitelist_cache

    whitelist_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "config", "whitelist.json")
    )

    default = {
        "trusted_networks": {},
        "trusted_open_networks": {},
        "trusted_weak_encryption": {}
    }

    try:
        if not os.path.exists(whitelist_path):
            print(f"Warning: Whitelist file not found at {whitelist_path}")
            print("Create config/whitelist.json to configure trusted networks")
            _whitelist_cache = default
            return default

        with open(whitelist_path, 'r') as f:
            data = json.load(f)

            _whitelist_cache = {
                "trusted_networks": {k: v for k, v in data.get("trusted_networks", {}).items() if not k.startswith("_")},
                "trusted_open_networks": {k: v for k, v in data.get("trusted_open_networks", {}).items() if not k.startswith("_")},
                "trusted_weak_encryption": {k: v for k, v in data.get("trusted_weak_encryption", {}).items() if not k.startswith("_")}
            }

            for network_data in _whitelist_cache["trusted_networks"].values():
                if "allowed_bssids" in network_data:
                    network_data["allowed_bssids"] = [b.lower() for b in network_data["allowed_bssids"]]

            return _whitelist_cache

    except Exception as e:
        print(f"Error loading whitelist: {e}")
        traceback.print_exc()
        _whitelist_cache = default
        return default

def save_whitelist(whitelist_data):
    global _whitelist_cache

    whitelist_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "config", "whitelist.json")
    )

    try:
        os.makedirs(os.path.dirname(whitelist_path), exist_ok=True)

        output_data = {
            "_comment": "Scannix Whitelist Configuration - Auto-managed via GUI or manual editing",
            "_instructions": "Restart Scannix after manual edits to reload configuration",
            **whitelist_data
        }

        with open(whitelist_path, 'w') as f:
            json.dump(output_data, f, indent=2)

        _whitelist_cache = None

    except Exception as e:
        print(f"Error saving whitelist: {e}")
        traceback.print_exc()
        raise

def parse_iw_scan(iface):
    try:
        raw = subprocess.check_output(["iw", "dev", iface, "scan"], stderr=subprocess.DEVNULL).decode(errors="ignore")
    except Exception:
        return {}

    blocks = re.split(r'\n(?=BSS )', raw)
    info = {}
    for blk in blocks:
        bssid_m = re.match(r'BSS\s+([0-9a-f:]{17})', blk)
        if not bssid_m:
            continue
        bssid = bssid_m.group(1).lower()
        sig_m = re.search(r'signal:\s*([-0-9.]+)\s*dBm', blk)
        signal_dbm = float(sig_m.group(1)) if sig_m else None
        rsn = None
        if 'wpa' in blk.lower() or 'rsn' in blk.lower():
            rsn = 'present'
        ht = 'HT' if 'HT capabilities' in blk else None
        vht = 'VHT' if 'VHT capabilities' in blk else None
        raw_ie = None
        raw_m = re.search(r'Information elements:\s*(.*)', blk, re.DOTALL)
        if raw_m:
            raw_ie = raw_m.group(1).strip()[:2000]

        info[bssid] = {
            "signal_dbm": signal_dbm,
            "rsn_summary": rsn,
            "ht": ht,
            "vht": vht,
            "raw_ies": raw_ie,
        }
    return info

def estimate_distance_meters(rssi_dbm, freq_mhz, rssi_at_1m=-40.0, path_loss_exp=3.0):
    if rssi_dbm is None or freq_mhz is None:
        return None
    exponent = (rssi_at_1m - rssi_dbm) / (10.0 * path_loss_exp)
    d_m = 10 ** exponent
    return max(0.5, min(int(round(d_m)), 10000))

def detect_device_type(ssid, vendor, bssid):
    ssid_lower = ssid.lower() if ssid else ""
    vendor_lower = vendor.lower() if vendor and vendor != "Unknown" else ""

    router_vendors = [
        "tp-link", "d-link", "cisco", "netgear", "asus", "linksys",
        "ubiquiti", "mikrotik", "huawei", "zte", "tenda", "tplink"
    ]
    router_patterns = [
        "router", "gateway", "-5g", "_5g", "cgates", "telia",
        "movistar", "vodafone", "telekom"
    ]

    for rv in router_vendors:
        if rv in vendor_lower:
            return "Router"

    for pattern in router_patterns:
        if pattern in ssid_lower:
            return "Router"

    mobile_patterns = ["iphone", "android", "galaxy", "pixel", "oneplus", "xiaomi"]
    mobile_vendors = ["apple", "samsung", "google", "xiaomi", "oppo", "vivo"]

    for mp in mobile_patterns:
        if mp in ssid_lower:
            return "Mobile Hotspot"

    for mv in mobile_vendors:
        if mv in vendor_lower:
            return "Mobile Hotspot"

    if "4g-gateway" in ssid_lower or "portable" in ssid_lower or "mifi" in ssid_lower:
        return "Portable Hotspot"

    try:
        first_octet = int(bssid.split(":")[0], 16)
        if first_octet & 0x02:
            return "Mobile Hotspot"
    except:
        pass

    return "Unknown"

def detect_anomalies(df):
    anomalies = []
    whitelist = load_whitelist()

    df_visible = df[df["SSID"] != "Hidden SSID"]
    duplicate_ssids = df_visible[df_visible.duplicated("SSID", keep=False)]

    if not duplicate_ssids.empty:
        trusted_networks = whitelist.get("trusted_networks", {})
        suspicious_networks = []

        for ssid in duplicate_ssids['SSID'].unique():
            ssid_df = duplicate_ssids[duplicate_ssids['SSID'] == ssid]
            current_bssids = set(ssid_df['BSSID'].str.lower())

            if ssid in trusted_networks:
                allowed_bssids = set(trusted_networks[ssid].get('allowed_bssids', []))
                new_bssids = current_bssids - allowed_bssids

                if new_bssids:
                    new_bssid_data = ssid_df[ssid_df['BSSID'].str.lower().isin(new_bssids)]
                    anomalies.append({
                        "type": "Trusted Network - New Device",
                        "details": new_bssid_data[['SSID', 'BSSID', 'Encryption', 'Vendor', 'DeviceType', 'SignalQuality%']],
                        "severity": "critical",
                        "context": {
                            "known_bssids": list(allowed_bssids),
                            "new_bssids": list(new_bssids)
                        }
                    })
            else:
                suspicious_networks.append(ssid_df)

        if suspicious_networks:
            combined_df = pd.concat(suspicious_networks)
            anomalies.append({
                "type": "Evil Twin",
                "details": combined_df[['SSID', 'BSSID', 'Encryption', 'Channel', 'Vendor', 'DeviceType', 'SignalQuality%']],
                "severity": "critical"
            })

    open_nets = df[df["Encryption"].str.upper() == "OPEN"]

    if not open_nets.empty:
        trusted_open = whitelist.get("trusted_open_networks", {})
        trusted_open_bssids = set(trusted_open.keys())
        untrusted_open = open_nets[~open_nets["BSSID"].str.lower().isin(trusted_open_bssids)]

        if not untrusted_open.empty:
            anomalies.append({
                "type": "Unencrypted Networks",
                "details": untrusted_open[['SSID', 'BSSID', 'Vendor', 'DeviceType', 'SignalQuality%', 'Channel']],
                "severity": "high"
            })

    weak = df[df["Encryption"].str.contains("WEP|WPA$", case=False, regex=True, na=False)]

    if not weak.empty:
        trusted_weak = whitelist.get("trusted_weak_encryption", {})
        trusted_weak_bssids = set(trusted_weak.keys())
        untrusted_weak = weak[~weak["BSSID"].str.lower().isin(trusted_weak_bssids)]

        if not untrusted_weak.empty:
            anomalies.append({
                "type": "Weak Encryption",
                "details": untrusted_weak[['SSID', 'BSSID', 'Encryption', 'Vendor', 'DeviceType', 'SignalQuality%']],
                "severity": "medium"
            })

    return anomalies

def scan_networks():
    wifi = PyWiFi()
    interfaces = wifi.interfaces()
    if not interfaces:
        raise Exception("No wireless interfaces found.")
    iface = interfaces[0]
    iface.scan()
    time.sleep(1)
    results = iface.scan_results()

    iw_info = parse_iw_scan(iface.name) if iface.name else {}

    networks = []
    for network in results:

        ssid = is_SSID_Hidden(network.ssid)
        bssid = network.bssid
        signal = network.signal
        encryption = get_encryption(network)  
        mhz, band, channel = get_freq(network)
        vendor = lookup_vendor(bssid)

        extra = iw_info.get(bssid, {})
        signal_dbm = extra.get("signal_dbm") if extra.get("signal_dbm") is not None else signal
        quality = rssi_to_quality(signal_dbm)
        est_dist = estimate_distance_meters(signal_dbm, mhz)
        device_type = detect_device_type(ssid, vendor, bssid)

        networks.append({
            "SSID": ssid,
            "BSSID": bssid,
            "SignalStrength": signal,
            "Encryption": encryption,
            "Frequency": mhz,
            "Band": band,
            "Channel": channel,
            "Vendor": vendor,
            "Signal_dBm": signal_dbm,
            "SignalQuality%": quality,
            "EstimatedDistance_m": round(est_dist),
            "DeviceType": device_type
        })
    return pd.DataFrame(networks)

def format_scan_summary(df):
    if df.empty:
        return "No networks detected"

    total = len(df)
    visible = len(df[df["SSID"] != "Hidden SSID"])
    hidden = total - visible

    encryption_counts = df["Encryption"].value_counts().to_dict()

    summary = f"""
╔══════════════════════════════════════════════════════╗
║           SCAN SUMMARY - {total} Networks Found           ║
╚══════════════════════════════════════════════════════╝

Networks:  {visible} visible, {hidden} hidden
Encryption: {encryption_counts.get('WPA2', 0)} WPA2, {encryption_counts.get('WPA3', 0)} WPA3, {encryption_counts.get('WPA', 0)} WPA, {encryption_counts.get('Open', 0)} Open

Top Networks by Signal:
"""

    top_df = df.nlargest(min(5, len(df)), 'SignalQuality%')[['SSID', 'BSSID', 'SignalQuality%', 'Encryption', 'Channel', 'Vendor']]

    for _, row in top_df.iterrows():
        ssid = str(row['SSID'])[:20] if len(str(row['SSID'])) > 20 else str(row['SSID'])
        vendor = str(row['Vendor'])[:25] if len(str(row['Vendor'])) > 25 else str(row['Vendor'])
        summary += f"  • {ssid:20} | {row['SignalQuality%']:3}% | {row['Encryption']:5} | Ch{row['Channel']:2} | {vendor}\n"

    return summary

def run_scan():
    try:
        df = scan_networks()
        if df.empty:
            print("No networks found.")
            return
        
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        data_dir = os.path.join(project_root, "data")
        os.makedirs(data_dir, exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_path = os.path.join(data_dir, f"scan_{timestamp}.csv")
        df.to_csv(output_path, index=False)
        print(df.to_string(index=False))

    except Exception as e:
        print("Scan failed:", e)
        traceback.print_exc()

if __name__ == "__main__":
    run_scan()