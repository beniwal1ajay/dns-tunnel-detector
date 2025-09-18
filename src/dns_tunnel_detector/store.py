"""Simple SQLite persistence for detections."""
from __future__ import annotations

import sqlite3
from typing import Dict, Iterable


def init_db(path: str) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        qname TEXT,
        score REAL,
        components TEXT,
        ts DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()


def insert_detection(path: str, qname: str, score: float, components: Dict) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute('INSERT INTO detections (qname, score, components) VALUES (?, ?, ?)',
                (qname, float(score), str(components)))
    conn.commit()
    conn.close()


def list_recent(path: str, limit: int = 100) -> Iterable[Dict]:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute('SELECT id, qname, score, components, ts FROM detections ORDER BY ts DESC LIMIT ?', (limit,))
    rows = cur.fetchall()
    conn.close()
    for r in rows:
        yield {'id': r[0], 'qname': r[1], 'score': r[2], 'components': r[3], 'ts': r[4]}
