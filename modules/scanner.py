import time
import pandas as pd
from pywifi import PyWiFi, const
import os
import requests
import traceback
import subprocess, re
import math
_vendor_cache = {}

def is_SSID_Hidden(ssid):
    if not ssid or ssid.strip() == "":
        return "Hidden SSID"
    return ssid

def get_encryption(network):
    if not getattr(network, "akm", None):
        return "Open"
    try:
        if hasattr(const, "AKM_TYPE_WPA3PSK") and const.AKM_TYPE_WPA3PSK in network.akm:
            return "WPA3"
        elif const.AKM_TYPE_WPA2PSK in network.akm:
            return "WPA2"
        elif const.AKM_TYPE_WPAPSK in network.akm:
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
    elif f == 2484:
        channel = 14
    elif 5000 <= f <= 6000:
        channel = (f - 5000) // 5
    else:
        channel = None

    if f < 3000:
        band = "2.4GHz"
    elif f < 6000:
        band = "5GHz"
    else:
        band = "6GHz"

    return f, band, channel

def lookup_vendor(bssid):
    if not bssid or ":" not in bssid:
        return "Unknown"

    prefix = ":".join(bssid.split(":")[:3]).upper()
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]

    try:
        url = f"https://api.macvendors.com/{prefix}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            vendor = response.text.strip()
        else:
            vendor = "Unknown"
    except Exception:
        vendor = "Unknown"

    _vendor_cache[prefix] = vendor
    return vendor

def get_system_iface_name():
    out = subprocess.check_output(["iw", "dev"]).decode(errors="ignore")
    m = re.search(r'Interface\s+([^\s]+)', out)
    return m.group(1) if m else None

def rssi_to_quality(rssi_dbm):
    if rssi_dbm is None: return None
    q = 2 * (rssi_dbm + 100)
    return max(0, min(100, int(q)))

def parse_iw_scan(iface):
    raw = subprocess.check_output(["sudo", "iw", "dev", iface, "scan"]).decode(errors="ignore")
    blocks = re.split(r'\n(?=BSS )', raw)
    info = {}
    for blk in blocks:
        bssid_m = re.match(r'BSS\s+([0-9a-f:]{17})', blk)
        if not bssid_m:
            continue
        bssid = bssid_m.group(1).lower()
        sig_m = re.search(r'signal:\s*([-0-9.]+)\s*dBm', blk)
        signal_dbm = float(sig_m.group(1)) if sig_m else None
        last_m = re.search(r'last seen:\s*(\d+)\s*ms', blk)
        last_seen_ms = int(last_m.group(1)) if last_m else None
        beacon_m = re.search(r'capability:.*\n.*beacon interval:\s*(\d+)', blk, re.IGNORECASE)
        beacon_m = re.search(r'beacon interval:\s*(\d+)', blk) or beacon_m
        beacon_interval = int(beacon_m.group(1)) if beacon_m else None
        rsn = None
        rsn_m = re.search(r'IE:\s+IEEE 802.11i/WPA2', blk) or re.search(r'WPA Version', blk)
        if rsn_m:
            rsn_lines = "\n".join([l.strip() for l in blk.splitlines() if 'RSN:' in l or 'WPA:' in l or 'AKM' in l or 'Pairwise' in l])
            rsn = rsn_lines if rsn_lines else 'present'
        ht = 'HT' if 'HT capabilities' in blk else None
        vht = 'VHT' if 'VHT capabilities' in blk else None
        raw_ie = None
        raw_m = re.search(r'Information elements:\s*(.*)', blk, re.DOTALL)
        if raw_m:
            raw_ie = raw_m.group(1).strip()[:2000]
        info[bssid] = {
            "signal_dbm": signal_dbm,
            "last_seen_ms": last_seen_ms,
            "beacon_interval": beacon_interval,
            "rsn_summary": rsn,
            "ht": ht,
            "vht": vht,
            "raw_ies": raw_ie,
        }
    return info

def estimate_distance_meters(rssi_dbm, freq_mhz, rssi_at_1m=None, path_loss_exp=3.0):
    if rssi_dbm is None:
        return None

    if rssi_at_1m is None:
        rssi_at_1m = -40.0

    exponent = (rssi_at_1m - rssi_dbm) / (10.0 * path_loss_exp)
    d_m = 10 ** (exponent)

    d_m = max(0.5, min(d_m, 10000))
    return int(round(d_m))

def scan_networks():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(3)
    results = iface.scan_results()

    system_iface = get_system_iface_name()
    iw_info = parse_iw_scan(system_iface) if system_iface else {}

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
            "EstimatedDistance_m": round(est_dist),
            "BeaconInterval": extra.get("beacon_interval"),
            "LastSeen_ms": extra.get("last_seen_ms")
        })
    return pd.DataFrame(networks)

def run_scan():
    try:
        df = scan_networks()
        output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/field_scan.csv"))
        df.to_csv(output_path, index=False)
        print(df.to_string(index=False))

    except Exception as e:
        print("Scan failed:", e)
        traceback.print_exc()

if __name__ == "__main__":
    run_scan()