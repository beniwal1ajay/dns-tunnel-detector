#!/usr/bin/env python3
"""Simple triage runner that processes pcaps with the project's sniffer and
produces detections.jsonl and a short report.md for quick delivery to clients.

Usage:
  python scripts/triage_report.py --pcap /path/to/file.pcap --out-dir /tmp/out
  python scripts/triage_report.py --pcap-dir /path/to/pcaps --out-dir /tmp/out --workers 2
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import shutil
import datetime

# Ensure project root is on path when executed from scripts/
ROOT = Path(__file__).resolve().parents[1]
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_sniffer import run_sniffer, list_pcaps


def collect_detections_from_dir(tmp_dir: Path, out_dir: Path):
    detections = []
    for p in tmp_dir.glob('detections_*.jsonl'):
        with open(p, 'r') as fh:
            for line in fh:
                try:
                    detections.append(json.loads(line))
                except Exception:
                    pass
    out_file = out_dir / 'detections.jsonl'
    with open(out_file, 'w') as fh:
        for d in detections:
            fh.write(json.dumps(d) + '\n')
    return out_file, detections


def write_report(out_dir: Path, detections: list, summary_csv: Path | None = None):
    report = []
    report.append(f"DNS Triage Report\nGenerated: {datetime.datetime.utcnow().isoformat()}Z\n")
    report.append(f"Total detections: {len(detections)}\n")
    if detections:
        report.append("Top detections:\n")
        for d in detections[:20]:
            report.append(f" - {d.get('qname')} score={d.get('score'):.3f} components={d.get('components')}\n")
    if summary_csv and summary_csv.exists():
        report.append(f"\nSummary CSV: {summary_csv}\n")
    report_path = out_dir / 'report.md'
    with open(report_path, 'w') as fh:
        fh.write('\n'.join(report))
    return report_path


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', default=None)
    parser.add_argument('--pcap-dir', default=None)
    parser.add_argument('--out-dir', default='out')
    parser.add_argument('--workers', type=int, default=1)
    parser.add_argument('--threshold', type=float, default=0.6)
    parser.add_argument('--model', default=None)
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    if out_dir.exists():
        # clear previous outputs to avoid confusion
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # run the existing run_sniffer logic
    if args.pcap:
        run_sniffer(iface=None, threshold=args.threshold, test=False, pcap=args.pcap, db=None, model_path=args.model, verbose=args.verbose, pcap_dir=None, recursive=False, workers=1, summary_csv=str(out_dir / 'summary.csv'), debug=args.debug, print_all=False)
    elif args.pcap_dir:
        run_sniffer(iface=None, threshold=args.threshold, test=False, pcap=None, db=None, model_path=args.model, verbose=args.verbose, pcap_dir=args.pcap_dir, recursive=True, workers=args.workers, summary_csv=str(out_dir / 'summary.csv'), debug=args.debug, print_all=False)
    else:
        print('Provide --pcap or --pcap-dir')
        return

    # collect temporary detection files created by worker processes
    tmp_dir = Path(tempfile.gettempdir())
    det_file, detections = collect_detections_from_dir(tmp_dir, out_dir)
    report = write_report(out_dir, detections, out_dir / 'summary.csv')
    print('Wrote:', det_file, report)


if __name__ == '__main__':
    main()
