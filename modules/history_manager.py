import sqlite3
import os
from datetime import datetime, timedelta
import pandas as pd

class HistoryManager:

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "data", "_history.db")
            )

        self.db_path = db_path
        self._ensure_data_dir()
        self._init_db()

    def _ensure_data_dir(self):
        data_dir = os.path.dirname(self.db_path)
        os.makedirs(data_dir, exist_ok=True)

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS encryption_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                encryption TEXT NOT NULL,
                timestamp DATETIME NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS channel_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                channel INTEGER NOT NULL,
                timestamp DATETIME NOT NULL
            )
        """)

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

            cursor.execute("""
                INSERT INTO network_history
                (scan_timestamp, ssid, bssid, encryption, channel, frequency,
                 signal_dbm, vendor, device_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, ssid, bssid, encryption, channel, frequency,
                  signal_dbm, vendor, device_type))

            self._track_encryption_change(cursor, bssid, encryption, timestamp)

            if channel:
                self._track_channel_change(cursor, bssid, channel, timestamp)

        conn.commit()
        self._update_signal_baselines(conn)

        conn.close()

    def _track_encryption_change(self, cursor, bssid, encryption, timestamp):
        cursor.execute("""
            SELECT encryption FROM encryption_history
            WHERE bssid = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (bssid,))

        result = cursor.fetchone()
        last_encryption = result[0] if result else None

        if last_encryption != encryption:
            cursor.execute("""
                INSERT INTO encryption_history (bssid, encryption, timestamp)
                VALUES (?, ?, ?)
            """, (bssid, encryption, timestamp))

    def _track_channel_change(self, cursor, bssid, channel, timestamp):
        cursor.execute("""
            SELECT channel FROM channel_history
            WHERE bssid = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (bssid,))

        result = cursor.fetchone()
        last_channel = result[0] if result else None

        if last_channel != channel:
            cursor.execute("""
                INSERT INTO channel_history (bssid, channel, timestamp)
                VALUES (?, ?, ?)
            """, (bssid, channel, timestamp))

    def _update_signal_baselines(self, conn):
        cursor = conn.cursor()

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
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        timestamp = datetime.now().isoformat()

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
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        cursor.execute("""
            DELETE FROM network_history
            WHERE scan_timestamp < ?
        """, (cutoff,))

        cursor.execute("""
            DELETE FROM encryption_history
            WHERE timestamp < ?
        """, (cutoff,))

        cursor.execute("""
            DELETE FROM channel_history
            WHERE timestamp < ?
        """, (cutoff,))

        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()

        return deleted_count