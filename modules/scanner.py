import os
import re
import time
import datetime
import subprocess
import traceback

import pandas as pd
import requests
from pywifi import PyWiFi, const

_vendor_cache = {}

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

def detect_anomalies(df):
    anomalies = []

    df_visible = df[df["SSID"] != "Hidden SSID"]
    duplicate_ssids = df_visible[df_visible.duplicated("SSID", keep=False)]
    if not duplicate_ssids.empty:
        anomalies.append({
            "type": "Evil Twin",
            "details": duplicate_ssids
        })

    open_nets = df[df["Encryption"].str.upper() == "OPEN"]
    if not open_nets.empty:
        anomalies.append({
            "type": "Unencrypted Networks",
            "details": open_nets
        })

    weak = df[df["Encryption"].str.contains("WEP|WPA$", case=False, regex=True)]
    if not weak.empty:
        anomalies.append({
            "type": "Weak Encryption",
            "details": weak
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
            "EstimatedDistance_m": round(est_dist)
        })
    return pd.DataFrame(networks)

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