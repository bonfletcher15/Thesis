"""
Threat Detector - Advanced threat detection for WiFi networks
"""

import re
import unicodedata
from datetime import datetime, timedelta


class ThreatDetector:
    """Detects advanced WiFi security threats"""

    def __init__(self, history_manager):
        """
        Initialize threat detector

        Args:
            history_manager: HistoryManager instance for temporal analysis
        """
        self.history = history_manager

        # Encryption strength ranking (higher = stronger)
        self.encryption_strength = {
            'Open': 0,
            'WEP': 1,
            'WPA': 2,
            'WPA2': 3,
            'WPA3': 4,
            'WPA2/WPA3': 4
        }

        # Known router vendor patterns
        self.vendor_patterns = {
            'TP-LINK': ['tplink', 'tp-link', 'archer'],
            'D-Link': ['dlink', 'd-link', 'dir-'],
            'Netgear': ['netgear', 'wnr', 'r6'],
            'Linksys': ['linksys', 'wrt'],
            'ASUS': ['asus', 'rt-'],
            'Cisco': ['cisco', 'linksys'],
            'Apple': ['airport', 'time capsule'],
            'Ubiquiti': ['ubiquiti', 'unifi'],
            'MikroTik': ['mikrotik']
        }

    def detect_all_threats(self, current_df):
        """
        Run all threat detection algorithms

        Args:
            current_df: Current scan results DataFrame

        Returns:
            List of threat dicts with keys: type, severity, details, context
        """
        threats = []

        # Tier 1 detectors (high priority)
        threats.extend(self.detect_vendor_spoofing(current_df))
        threats.extend(self.detect_encryption_downgrade(current_df))
        threats.extend(self.detect_suspicious_ssids(current_df))

        # Tier 2 detectors
        threats.extend(self.detect_signal_anomalies(current_df))
        threats.extend(self.detect_beacon_flood(current_df))

        # Log all threats
        for threat in threats:
            self.history.log_threat(
                threat['type'],
                threat['severity'],
                threat.get('ssid'),
                threat.get('bssid'),
                str(threat.get('context', ''))
            )

        return threats

    # ==================== TIER 1 DETECTORS ====================

    def detect_vendor_spoofing(self, df):
        """
        Detect vendor/SSID mismatches (Tier 1)

        Example: SSID "TP-Link_5G" but vendor is "Apple"

        Returns:
            List of threat dicts
        """
        threats = []

        for _, row in df.iterrows():
            ssid = row['SSID'].lower()
            vendor = row.get('Vendor', '').lower()
            bssid = row['BSSID']
            device_type = row.get('DeviceType', 'Unknown')

            # Skip if device is mobile hotspot (legitimate to have different vendor)
            if device_type in ['Mobile Hotspot', 'Portable Hotspot']:
                continue

            # Check for vendor/SSID mismatches
            for expected_vendor, ssid_patterns in self.vendor_patterns.items():
                # Check if SSID contains any of the patterns
                for pattern in ssid_patterns:
                    if pattern in ssid:
                        # SSID suggests this vendor, check if actual vendor matches
                        if expected_vendor.lower() not in vendor and vendor != 'unknown':
                            threats.append({
                                'type': 'Vendor Spoofing',
                                'severity': 'high',
                                'ssid': row['SSID'],
                                'bssid': bssid,
                                'details': df[df['BSSID'] == bssid],
                                'context': {
                                    'expected_vendor': expected_vendor,
                                    'actual_vendor': row.get('Vendor', 'Unknown'),
                                    'reason': f"SSID suggests {expected_vendor} but MAC vendor is {row.get('Vendor', 'Unknown')}"
                                }
                            })
                            break

        return threats

    def detect_encryption_downgrade(self, df):
        """
        Detect encryption downgrades for known networks (Tier 1)

        Example: Network was WPA2 yesterday, now showing WPA

        Returns:
            List of threat dicts
        """
        threats = []

        for _, row in df.iterrows():
            bssid = row['BSSID'].lower()
            current_encryption = row.get('Encryption', 'Unknown')

            # Get encryption history
            history = self.history.get_encryption_history(bssid, days=30)

            if len(history) < 2:
                # Not enough history to detect downgrade
                continue

            # Get previous encryption (second most recent)
            previous_encryption = history[-2][0]  # (encryption, timestamp)

            # Check if downgrade occurred
            current_strength = self.encryption_strength.get(current_encryption, -1)
            previous_strength = self.encryption_strength.get(previous_encryption, -1)

            if current_strength < previous_strength:
                threats.append({
                    'type': 'Encryption Downgrade',
                    'severity': 'critical',
                    'ssid': row['SSID'],
                    'bssid': bssid,
                    'details': df[df['BSSID'] == row['BSSID']],
                    'context': {
                        'previous_encryption': previous_encryption,
                        'current_encryption': current_encryption,
                        'downgrade_detected': history[-2][1],  # timestamp
                        'reason': f"Network encryption downgraded from {previous_encryption} to {current_encryption}"
                    }
                })

        return threats

    def detect_suspicious_ssids(self, df):
        """
        Detect SSIDs with suspicious patterns (Tier 1)

        Detects:
        - Homograph attacks (lookalike characters)
        - Invisible/zero-width characters
        - Excessive special characters

        Returns:
            List of threat dicts
        """
        threats = []

        for _, row in df.iterrows():
            ssid = row['SSID']
            bssid = row['BSSID']
            suspicious_reasons = []

            # Check for non-printable/invisible characters
            if self._has_invisible_chars(ssid):
                suspicious_reasons.append("Contains invisible/zero-width characters")

            # Check for homograph characters
            if self._has_homograph_chars(ssid):
                suspicious_reasons.append("Contains lookalike characters (possible homograph attack)")

            # Check for excessive special characters
            if self._has_excessive_special_chars(ssid):
                suspicious_reasons.append("Excessive special characters")

            # Check for hidden Unicode
            if self._has_hidden_unicode(ssid):
                suspicious_reasons.append("Contains hidden Unicode characters")

            if suspicious_reasons:
                threats.append({
                    'type': 'Suspicious SSID',
                    'severity': 'high',
                    'ssid': ssid,
                    'bssid': bssid,
                    'details': df[df['BSSID'] == bssid],
                    'context': {
                        'reasons': suspicious_reasons,
                        'ssid_bytes': ssid.encode('unicode_escape').decode('ascii'),
                        'char_analysis': self._analyze_ssid_chars(ssid)
                    }
                })

        return threats

    # ==================== TIER 2 DETECTORS ====================

    def detect_signal_anomalies(self, df):
        """
        Detect unusual signal strength changes (Tier 2)

        Example: Network normally at -70dBm now at -30dBm (possible Evil Twin nearby)

        Returns:
            List of threat dicts
        """
        threats = []

        SPIKE_THRESHOLD = 30  # dBm increase

        for _, row in df.iterrows():
            bssid = row['BSSID'].lower()
            current_signal = row.get('Signal', None)

            if current_signal is None:
                continue

            # Get signal baseline
            baseline = self.history.get_signal_baseline(bssid)

            if baseline is None or baseline['sample_count'] < 5:
                # Not enough history to establish baseline
                continue

            # Check for unusual spike
            signal_increase = current_signal - baseline['avg']

            if signal_increase >= SPIKE_THRESHOLD:
                threats.append({
                    'type': 'Signal Strength Anomaly',
                    'severity': 'high',
                    'ssid': row['SSID'],
                    'bssid': bssid,
                    'details': df[df['BSSID'] == row['BSSID']],
                    'context': {
                        'current_signal': current_signal,
                        'baseline_avg': baseline['avg'],
                        'baseline_min': baseline['min'],
                        'baseline_max': baseline['max'],
                        'spike_amount': signal_increase,
                        'reason': f"Signal increased {signal_increase:.0f} dBm from baseline (possible rogue AP nearby)"
                    }
                })

        return threats

    def detect_beacon_flood(self, df):
        """
        Detect abnormally high number of networks on same channel (Tier 2)

        Possible DoS attack or WiFi scanner in area

        Returns:
            List of threat dicts
        """
        threats = []

        THRESHOLD_2_4GHZ = 20
        THRESHOLD_5GHZ = 30

        # Count networks per channel
        channel_counts = df.groupby('Channel').size()

        for channel, count in channel_counts.items():
            if channel is None or channel == 'N/A':
                continue

            # Determine threshold based on frequency band
            threshold = THRESHOLD_5GHZ if int(channel) > 14 else THRESHOLD_2_4GHZ

            if count > threshold:
                networks_on_channel = df[df['Channel'] == channel]

                threats.append({
                    'type': 'Beacon Flood',
                    'severity': 'medium',
                    'ssid': None,
                    'bssid': None,
                    'details': networks_on_channel,
                    'context': {
                        'channel': channel,
                        'network_count': int(count),
                        'threshold': threshold,
                        'band': '5GHz' if int(channel) > 14 else '2.4GHz',
                        'reason': f"Detected {count} networks on channel {channel} (threshold: {threshold}). Possible beacon flood attack or WiFi scanner."
                    }
                })

        return threats

    # ==================== HELPER METHODS ====================

    def _has_invisible_chars(self, ssid):
        """Check if SSID contains invisible/zero-width characters"""
        invisible_chars = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\ufeff',  # Zero-width no-break space
            '\u00ad',  # Soft hyphen
        ]

        return any(char in ssid for char in invisible_chars)

    def _has_homograph_chars(self, ssid):
        """Check if SSID contains homograph characters (lookalike chars from different scripts)"""
        # Check for mixing Latin with Cyrillic/Greek characters
        has_latin = False
        has_cyrillic = False
        has_greek = False

        for char in ssid:
            if '\u0041' <= char <= '\u005A' or '\u0061' <= char <= '\u007A':  # Latin
                has_latin = True
            elif '\u0400' <= char <= '\u04FF':  # Cyrillic
                has_cyrillic = True
            elif '\u0370' <= char <= '\u03FF':  # Greek
                has_greek = True

        # Mixing scripts is suspicious
        return (has_latin and has_cyrillic) or (has_latin and has_greek)

    def _has_excessive_special_chars(self, ssid):
        """Check if SSID has too many special characters"""
        special_char_count = sum(1 for char in ssid if not char.isalnum() and char not in [' ', '-', '_'])
        return special_char_count > len(ssid) * 0.3  # >30% special chars

    def _has_hidden_unicode(self, ssid):
        """Check for unusual Unicode categories"""
        for char in ssid:
            category = unicodedata.category(char)
            # Check for control characters, format characters, etc.
            if category in ['Cc', 'Cf', 'Cn', 'Co', 'Cs']:
                return True
        return False

    def _analyze_ssid_chars(self, ssid):
        """Analyze SSID character composition for debugging"""
        analysis = {
            'length': len(ssid),
            'printable': sum(1 for c in ssid if c.isprintable()),
            'alphanumeric': sum(1 for c in ssid if c.isalnum()),
            'spaces': sum(1 for c in ssid if c.isspace()),
            'special': sum(1 for c in ssid if not c.isalnum() and not c.isspace())
        }
        return analysis
