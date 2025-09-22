# DNS Tunneling Detector

Minimal project skeleton for an advanced DNS tunneling detection tool. Contains
feature extraction and a heuristic scoring function as a baseline. Designed to be
extended into a larger project (ML model, PCAP ingestion, distributed logging).

Quick start

1. Install dependencies (optional, only needed for live sniffing):

```bash
pip install -r requirements.txt
```

2. Run a dry-run test (no root):

You can run a dry-run using the new top-level script `DnsTunnelingDetection.py` or the CLI runner:

```bash
# using the legacy CLI runner
python scripts/run_sniffer.py --test

# or using the top-level renamed script
python DnsTunnelingDetection.py --test
```

3. Live sniffing (usually requires root):

```bash
# using the CLI runner
sudo python scripts/run_sniffer.py --iface eth0 --threshold 0.6

# or using the top-level script
sudo python DnsTunnelingDetection.py --iface eth0 --threshold 0.6
```

Next steps
- Add persistent storage (Elasticsearch/InfluxDB)
- Replace heuristic scoring with a trained ML model
- Add packet capture replay support (pcap input)
- Improve feature set (byte-entropy, n-gram model, temporal features)


Linux notes (Debian/Ubuntu)
---------------------------
To run live sniffing on Linux you typically need libpcap development headers and root privileges. On Debian/Ubuntu install system deps:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev python3-dev
# optional: if using virtualenv, create and activate it, then:
pip install -r requirements.txt
```

If you prefer not to run as root for packet capture, you can allow the Python interpreter to capture packets by granting the binary `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities (use with care):

```bash
# if using system python, use the path to your python binary
sudo setcap 'cap_net_raw,cap_net_admin+eip' $(which python3)
# if using a virtualenv, point to the virtualenv python binary
sudo setcap 'cap_net_raw,cap_net_admin+eip' /path/to/venv/bin/python
```

Note: cap adjustments require root and may be refused by some hardened systems. Otherwise run with `sudo`.

Flags & Usage (detailed)
------------------------
The CLI runner `scripts/run_sniffer.py` supports many modes. Below are all the flags, what they do, and example commands so there's no confusion.

Common flags
- `--iface IFACE` : Network interface to listen on for live sniffing (e.g. `eth0`, `wlan0`). Requires capture permission.
- `--threshold N` : Detection score threshold (0.0 - 1.0). Only qnames with `score >= threshold` are printed to stdout as JSON lines. Default is `0.6` (recommended for production). Use a low value (e.g. `0.01`) when debugging to show more output.
- `--test` : Dry-run mode. Prints two example qnames and their heuristic scores; useful when scapy or capture privileges are not available.
- `--pcap FILE` : Read and process a single pcap file instead of live capture.
- `--pcap-dir DIR` : Process all pcaps found under `DIR`. Use with `--workers` to parallelize.
- `--recursive` : With `--pcap-dir`, search recursively for pcap files.
- `--db PATH` : Path to SQLite DB to persist detections. Parent process performs inserts to avoid concurrent writes when using workers.
- `--model PATH` : Joblib model path. If provided and compatible, model probability will override the heuristic score.
- `--verbose` : Increase logging verbosity. Prints INFO/DEBUG logs (not the JSON detection lines which are controlled by `--threshold` and `--print-all`).
- `--debug` : Print per-processed-qname debug lines to stderr to help debugging; does not change JSON output on stdout.
- `--print-all` : Print every processed DNS query as a JSON line to stdout regardless of the score; useful for short-term debugging or building labeled datasets.
- `--workers N` : When processing a pcap directory, number of worker processes for CPU-bound work. Workers produce temporary JSONL detection files; the parent reads them and inserts into the DB sequentially.
- `--summary-csv PATH` : Write per-file and aggregate CSV summary rows to `PATH`.

How output streams are used
- stdout: JSON lines for detections (or all processed qnames when `--print-all` is used). This is the primary machine-readable output.
- stderr: debug and logging output (when `--debug` or `--verbose` are used). Keep stderr separate when collecting JSON.

Examples
- Dry-run (no root, quick check):
```bash
python3 scripts/run_sniffer.py --test
```

- Live sniffing (production-style, default threshold):
```bash
sudo python3 scripts/run_sniffer.py --iface wlan0 --threshold 0.6 --db /var/lib/dns-detector/detections.db
```

- Live sniffing (debugging, show every qname to stdout and debug to stderr):
```bash
# prints JSON for every qname (stdout) and debug lines to stderr
sudo python3 scripts/run_sniffer.py --iface wlan0 --print-all --debug
```

- Process a directory of pcaps with 4 workers and a CSV summary:
```bash
python3 scripts/run_sniffer.py --pcap-dir /data/pcaps --workers 4 --summary-csv /tmp/summary.csv --db /tmp/detections.db
```

- Process a single pcap and write detections to DB (no live capture privileges needed):
```bash
python3 scripts/run_sniffer.py --pcap /tmp/capture.pcap --db /tmp/detections.db --threshold 0.4
```

Notes about `--threshold` and tuning
- The `--threshold` value controls which qnames are considered 'detections' and therefore printed on stdout (unless `--print-all` is used). The heuristic score ranges 0..1; higher means more suspicious. Use a conservative threshold (0.6) in production to reduce false positives, and lower it only when debugging or collecting labeled data.
- `--print-all` is useful for short-term capture to collect examples to label, but do not use it on busy networks continuously as it will produce large volumes of output.

Database & worker behaviour
- When `--pcap-dir` and `--workers` > 1 are used, worker processes avoid writing to the SQLite DB directly. Each worker writes a temporary JSONL file with detections; the parent process reads those files and inserts rows into the DB sequentially to avoid SQLite write conflicts.

If you prefer the docs as a single manual, see `MANUAL.md` which contains longer installation steps, troubleshooting and examples.
