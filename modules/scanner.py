import time
import pandas as pd
from pywifi import PyWiFi, const
import scorer
import os


def scan_networks():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(3)
    results = iface.scan_results()

    networks = []
    for network in results:
        ssid = network.ssid
        bssid = network.bssid
        signal = network.signal
        encryption = "Open"

        if network.akm:
            if hasattr(const, "AKM_TYPE_WPA3PSK") and const.AKM_TYPE_WPA3PSK in network.akm:
                encryption = "WPA3"
            elif const.AKM_TYPE_WPA2PSK in network.akm:
                encryption = "WPA2"
            elif const.AKM_TYPE_WPAPSK in network.akm:
                encryption = "WPA"
            else:
                encryption = "Other"

        networks.append({
            "SSID": ssid,
            "BSSID": bssid,
            "SignalStrength": signal,
            "Encryption": encryption
        })

    return pd.DataFrame(networks)

def run_scan():
    df = scan_networks()
    df = scorer.score_networks(df)
    df.to_csv("../data/field_scan.csv", index=False)
    print(df)

if __name__ == "__main__":
    run_scan()