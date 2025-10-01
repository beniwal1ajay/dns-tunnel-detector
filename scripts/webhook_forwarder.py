#!/usr/bin/env python3
"""Read detections.jsonl and forward each detection as a POST to a webhook URL.

Usage:
  python scripts/webhook_forwarder.py --in detections.jsonl --url https://example.com/ingest
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import requests


def forward(in_file: Path, url: str, headers: dict | None = None, batch: int = 1):
    headers = headers or {'Content-Type': 'application/json'}
    with open(in_file, 'r') as fh:
        batch_items = []
        for line in fh:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            batch_items.append(obj)
            if len(batch_items) >= batch:
                resp = requests.post(url, json=batch_items if batch>1 else batch_items[0], headers=headers)
                print('POST', resp.status_code)
                batch_items = []
        if batch_items:
            resp = requests.post(url, json=batch_items if batch>1 else batch_items[0], headers=headers)
            print('POST', resp.status_code)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--in', dest='in_file', required=True)
    parser.add_argument('--url', required=True)
    parser.add_argument('--batch', type=int, default=1)
    args = parser.parse_args(argv)
    in_file = Path(args.in_file)
    if not in_file.exists():
        print('Input file not found:', in_file)
        return
    forward(in_file, args.url, batch=args.batch)


if __name__ == '__main__':
    main()
