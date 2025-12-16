"""
History Manager - Stores and manages WiFi scan history for temporal analysis
"""

import sqlite3
import os
from datetime import datetime, timedelta
import pandas as pd


class HistoryManager:
    """Manages historical WiFi scan data in SQLite database"""

    def __init__(self, db_path=None):
        """
        Initialize history manager

        Args:
            db_path: Path to SQLite database file (default: data/_history.db)
        """
        if db_path is None:
            db_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "data", "_history.db")
            )

        self.db_path = db_path
        self._ensure_data_dir()
        self._init_db()

    def _ensure_data_dir(self):
        """Create data directory if it doesn't exist"""
        data_dir = os.path.dirname(self.db_path)
        os.makedirs(data_dir, exist_ok=True)

    def _init_db(self):
        """Create database tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Network history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_timestamp DATETIME NOT NULL,
                ssid TEXT NOT NULL,
                bssid TEXT NOT NULL,
                encryption TEXT,
                channel INTEGER,
                frequency INTEGER,
                signal_dbm INTEGER,
                vendor TEXT,
                device_type TEXT
            )
        """)

        # Signal strength baseline table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS signal_baselines (
                bssid TEXT PRIMARY KEY,
                avg_signal_dbm REAL,
                min_signal_dbm REAL,
                max_signal_dbm REAL,
                sample_count INTEGER,
                last_updated DATETIME
            )
        """)

        # Encryption history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS encryption_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                encryption TEXT NOT NULL,
                timestamp DATETIME NOT NULL
            )
        """)

        # Channel history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS channel_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                channel INTEGER NOT NULL,
                timestamp DATETIME NOT NULL
            )
        """)

        # Threat detection log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_timestamp DATETIME NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                ssid TEXT,
                bssid TEXT,
                details TEXT,
                user_action TEXT,
                action_timestamp DATETIME
            )
        """)

        # Create indices for performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bssid
            ON network_history(bssid)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp
            ON network_history(scan_timestamp)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_bssid
            ON threat_log(bssid)
        """)

        conn.commit()
        conn.close()

    def add_scan(self, df):
        """
        Add scan results to history database

        Args:
            df: pandas DataFrame with scan results
        """
        if df is None or df.empty:
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()

        for _, row in df.iterrows():
            bssid = row['BSSID'].lower()
            ssid = row['SSID']
            encryption = row.get('Encryption', 'Unknown')
            channel = row.get('Channel', None)
            frequency = row.get('Frequency', None)
            signal_dbm = row.get('Signal_dBm', None)
            vendor = row.get('Vendor', 'Unknown')
            device_type = row.get('DeviceType', 'Unknown')

            # Insert into network_history
            cursor.execute("""
                INSERT INTO network_history
                (scan_timestamp, ssid, bssid, encryption, channel, frequency,
                 signal_dbm, vendor, device_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, ssid, bssid, encryption, channel, frequency,
                  signal_dbm, vendor, device_type))

            # Track encryption changes
            self._track_encryption_change(cursor, bssid, encryption, timestamp)

            # Track channel changes
            if channel:
                self._track_channel_change(cursor, bssid, channel, timestamp)

        conn.commit()

        # Update signal baselines
        self._update_signal_baselines(conn)

        conn.close()

    def _track_encryption_change(self, cursor, bssid, encryption, timestamp):
        """Track encryption type changes for a BSSID"""
        # Get last known encryption
        cursor.execute("""
            SELECT encryption FROM encryption_history
            WHERE bssid = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (bssid,))

        result = cursor.fetchone()
        last_encryption = result[0] if result else None

        # Only log if encryption changed
        if last_encryption != encryption:
            cursor.execute("""
                INSERT INTO encryption_history (bssid, encryption, timestamp)
                VALUES (?, ?, ?)
            """, (bssid, encryption, timestamp))

    def _track_channel_change(self, cursor, bssid, channel, timestamp):
        """Track channel changes for a BSSID"""
        # Get last known channel
        cursor.execute("""
            SELECT channel FROM channel_history
            WHERE bssid = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (bssid,))

        result = cursor.fetchone()
        last_channel = result[0] if result else None

        # Only log if channel changed
        if last_channel != channel:
            cursor.execute("""
                INSERT INTO channel_history (bssid, channel, timestamp)
                VALUES (?, ?, ?)
            """, (bssid, channel, timestamp))

    def _update_signal_baselines(self, conn):
        """Update signal strength statistics for all BSSIDs"""
        cursor = conn.cursor()

        # Calculate baseline statistics from last 7 days
        cursor.execute("""
            INSERT OR REPLACE INTO signal_baselines
            (bssid, avg_signal_dbm, min_signal_dbm, max_signal_dbm,
             sample_count, last_updated)
            SELECT
                bssid,
                AVG(signal_dbm) as avg_signal_dbm,
                MIN(signal_dbm) as min_signal_dbm,
                MAX(signal_dbm) as max_signal_dbm,
                COUNT(*) as sample_count,
                datetime('now') as last_updated
            FROM network_history
            WHERE scan_timestamp >= datetime('now', '-7 days')
                AND signal_dbm IS NOT NULL
            GROUP BY bssid
        """)

        conn.commit()

    def get_signal_baseline(self, bssid):
        """
        Get signal strength baseline for a BSSID

        Args:
            bssid: BSSID to lookup

        Returns:
            dict with avg, min, max, sample_count or None
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT avg_signal_dbm, min_signal_dbm, max_signal_dbm, sample_count
            FROM signal_baselines
            WHERE bssid = ?
        """, (bssid.lower(),))

        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                'avg': result[0],
                'min': result[1],
                'max': result[2],
                'sample_count': result[3]
            }
        return None

    def get_encryption_history(self, bssid, days=30):
        """
        Get encryption change history for a BSSID

        Args:
            bssid: BSSID to lookup
            days: Number of days to look back

        Returns:
            List of (encryption, timestamp) tuples
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        cursor.execute("""
            SELECT encryption, timestamp
            FROM encryption_history
            WHERE bssid = ? AND timestamp >= ?
            ORDER BY timestamp ASC
        """, (bssid.lower(), cutoff))

        results = cursor.fetchall()
        conn.close()

        return results

    def get_channel_history(self, bssid, days=30):
        """
        Get channel change history for a BSSID

        Args:
            bssid: BSSID to lookup
            days: Number of days to look back

        Returns:
            List of (channel, timestamp) tuples
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        cursor.execute("""
            SELECT channel, timestamp
            FROM channel_history
            WHERE bssid = ? AND timestamp >= ?
            ORDER BY timestamp ASC
        """, (bssid.lower(), cutoff))

        results = cursor.fetchall()
        conn.close()

        return results

    def get_network_history(self, bssid, days=30):
        """
        Get all historical data for a BSSID

        Args:
            bssid: BSSID to lookup
            days: Number of days to look back

        Returns:
            pandas DataFrame with history
        """
        conn = sqlite3.connect(self.db_path)

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        query = """
            SELECT * FROM network_history
            WHERE bssid = ? AND scan_timestamp >= ?
            ORDER BY scan_timestamp DESC
        """

        df = pd.read_sql_query(query, conn, params=(bssid.lower(), cutoff))
        conn.close()

        return df

    def get_ssid_bssid_history(self, ssid, days=7):
        """
        Get all BSSIDs ever associated with an SSID

        Args:
            ssid: SSID to lookup
            days: Number of days to look back

        Returns:
            List of unique BSSIDs
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        cursor.execute("""
            SELECT DISTINCT bssid
            FROM network_history
            WHERE ssid = ? AND scan_timestamp >= ?
        """, (ssid, cutoff))

        results = [row[0] for row in cursor.fetchall()]
        conn.close()

        return results

    def log_threat(self, threat_type, severity, ssid, bssid, details):
        """
        Log a detected threat

        Args:
            threat_type: Type of threat detected
            severity: Severity level (critical, high, medium, low)
            ssid: SSID involved
            bssid: BSSID involved
            details: Additional details (string or dict)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        timestamp = datetime.now().isoformat()

        # Convert details to string if it's a dict
        if isinstance(details, dict):
            details = str(details)

        cursor.execute("""
            INSERT INTO threat_log
            (detection_timestamp, threat_type, severity, ssid, bssid, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, threat_type, severity, ssid, bssid, details))

        conn.commit()
        conn.close()

    def get_threat_history(self, days=30):
        """
        Get recent threat detections

        Args:
            days: Number of days to look back

        Returns:
            pandas DataFrame with threat history
        """
        conn = sqlite3.connect(self.db_path)

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        query = """
            SELECT * FROM threat_log
            WHERE detection_timestamp >= ?
            ORDER BY detection_timestamp DESC
        """

        df = pd.read_sql_query(query, conn, params=(cutoff,))
        conn.close()

        return df

    def cleanup_old_data(self, days=90):
        """
        Remove scan history older than specified days

        Args:
            days: Keep data newer than this many days
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        # Delete old network history
        cursor.execute("""
            DELETE FROM network_history
            WHERE scan_timestamp < ?
        """, (cutoff,))

        # Delete old encryption history
        cursor.execute("""
            DELETE FROM encryption_history
            WHERE timestamp < ?
        """, (cutoff,))

        # Delete old channel history
        cursor.execute("""
            DELETE FROM channel_history
            WHERE timestamp < ?
        """, (cutoff,))

        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()

        return deleted_count
