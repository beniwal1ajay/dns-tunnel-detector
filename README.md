## DNS Tunneling Detector

A small, practical tool to detect DNS tunneling indicators in PCAPs or live DNS traffic.

Quick start
-----------

Clone and install (recommended inside a virtualenv):

```bash
git clone https://github.com/beniwal1ajay/dns-tunnel-detector.git
cd dns-tunnel-detector
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Run a quick dry-run (no root required):

```bash
python3 scripts/run_sniffer.py --test
```

Process a single pcap file (example):

```bash
python3 scripts/run_sniffer.py --pcap /path/to/capture.pcap --threshold 0.6 --db /tmp/detections.db
```

The command prints JSON Lines to stdout for each detection (qname + score + components). Use `--summary-csv /tmp/summary.csv` to collect per-file and aggregate summaries.

Process CSVs
------------

In addition to PCAPs, `run_sniffer.py` can scan CSV files containing qnames (one per row) or a directory of CSVs. Supported header names: `qname`, `query`, or `domain` — otherwise the first column is treated as the qname.

Examples:

- Scan a single CSV and print detections:
	```bash
	python3 scripts/run_sniffer.py --csv /path/to/queries.csv --threshold 0.6
	```

- Scan a directory of CSV files in parallel and write a summary CSV:
	```bash
	python3 scripts/run_sniffer.py --csv-dir /data/csvs --workers 4 --summary-csv /tmp/summary.csv
	```

Useful quick examples
---------------------

- Dry-run test: `python3 scripts/run_sniffer.py --test`
- One pcap, write DB: `python3 scripts/run_sniffer.py --pcap /tmp/capture.pcap --db /tmp/detections.db` 
- Process a folder of pcaps in parallel: `python3 scripts/run_sniffer.py --pcap-dir /data/pcaps --workers 4 --summary-csv /tmp/summary.csv`
- Print every processed qname (for dataset collection): `--print-all`

Next steps & contribution
-------------------------

This project is a strong prototype intended to be extended with model improvements, a web UI, or packaged for appliance-style deployment for customers. Contributions are welcome — open issues or submit a PR with tests.

License & contact
-----------------

See `LICENSE` for license terms. For commercial or consulting enquiries, open an issue or contact the maintainer via the GitHub repo.
