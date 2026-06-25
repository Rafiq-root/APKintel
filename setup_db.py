import sqlite3
import os

def setup_database():
    db_name = "threat_intel.db"
    
    # Connect to SQLite. This creates the file if it does not exist.
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create the table to hold indicators
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malicious_network (
            indicator TEXT UNIQUE,
            type TEXT
        )
    """)

    # Seed the database with test data so the tool has something to detect
    test_data = [
        ('192.168.1.99', 'malware'),
        ('evil-phishing-domain.com', 'phishing'),
        ('track.appsflyer.com', 'tracker'),
        ('firebase-logging.google.com', 'tracker')
    ]

    # Insert the test data, ignoring errors if data already exists
    cursor.executemany("""
        INSERT OR IGNORE INTO malicious_network (indicator, type)
        VALUES (?, ?)
    """, test_data)

    conn.commit()
    conn.close()

    print(f"Database setup complete. File created: {os.path.abspath(db_name)}")

if __name__ == "__main__":
    setup_database()
