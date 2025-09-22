DNS Tunnel Detector — Learning Notes

Purpose
-------
These notes capture everything you learned while building and iterating on the `dns-tunnel-detector` project and the chat-based session that produced it. They include: high-level architecture, step-by-step commands you ran, explanations of why changes were made, troubleshooting steps you used, and suggested areas for further study.

Contents
- Project summary
- Chronological log of important commands (copyable)
- Files and roles
- Key changes and motivations
- Troubleshooting log (errors + solutions)
- How to update on another machine (Kali)
- Repro steps to rebuild environment
- Tests and quality gates
- Notes for further study / fields to explore
- Quick reference (common commands)

Project summary
---------------
This project is a Python-based DNS tunneling detector. It's structured into a small package with:
- `src/dns_tunnel_detector/detector.py`: feature extraction and heuristics
- `src/dns_tunnel_detector/store.py`: SQLite persistence helper
- `scripts/run_sniffer.py`: CLI runner for live sniffing, pcap and pcap-dir processing (parallel), CSV summaries, DB persistence
- `scripts/train_model.py`: helper to train a RandomForest model using labeled data
- `DnsTunnelingDetection.py`: legacy top-level wrapper with `--test` dry-run

Key features implemented
- Heuristic scoring: n-gram entropy, subdomain entropy, pronounceability, longest repeated substring, label randomness, TLD heuristics
- Optional ML model support: joblib model probability overrides heuristic
- Worker/parent parallel processing: workers process pcaps and write temporary JSONL detections; parent inserts them into SQLite to avoid concurrent writes
- Per-file and aggregate CSV summaries
- Unit tests and smoke tests
- Linux-friendly adjustments (shebangs, README, MANUAL.md)

Chronological command log (most useful / copyable)
-------------------------------------------------
# Repo operations (clone, pull, push)
cd ~/projects
git clone https://github.com/beniwal1ajay/dns-tunnel-detector.git
cd dns-tunnel-detector
# fetch and update later
git fetch origin
git checkout master
git pull --ff-only origin master

# Virtualenv & dependencies
defaults:
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Run tests
python3 -m pytest -q

# Dry-run CLI
python3 scripts/run_sniffer.py --test
python3 DnsTunnelingDetection.py --test

# Run pcap processing (single file)
python3 scripts/run_sniffer.py --pcap data/example.pcap --threshold 0.6 --db data/detections.db --verbose

# Process directory of pcaps (parallel) and write CSV summary
python3 scripts/run_sniffer.py --pcap-dir data/pcaps --workers 4 --summary-csv /tmp/summary.csv --db data/detections.db

# Train model
python3 scripts/train_model.py labelled.csv model.joblib

# Grant capability to run sniffing without root (optional; be careful)
sudo setcap cap_net_raw+ep $(readlink -f .venv/bin/python)

Files and their roles
---------------------
- `DnsTunnelingDetection.py` — compatibility wrapper; small CLI with `--test`
- `scripts/run_sniffer.py` — main runner. Important functions:
  - `run_sniffer(...)` — orchestrates modes: test, pcap, pcap-dir, live sniffing
  - `process_pcap_file(pcap_path, threshold, model_path, verbose)` — worker function that writes `detections_file` temp JSONL and returns stats
  - `write_summary_csv(csv_path, stats, label, pcap_path)` — writes per-file/aggregate CSV rows
  - `list_pcaps(directory, recursive)` — find pcaps
- `src/dns_tunnel_detector/detector.py` — core feature extraction functions
- `src/dns_tunnel_detector/store.py` — DB init and insert helper
- `scripts/train_model.py` — simple trainer using scikit-learn
- `tests/` — unit tests covering CSV writer and pcap listing and other components

Key code changes and why
------------------------
- Robust qname decoding: avoid exceptions when qname is bytes
- `--test` dry-run mode: prints example outputs and allows running the script without scapy or root
- Parallel worker persistence: workers write JSONL temp files; the parent process sequentially reads those and inserts into SQLite to avoid concurrent DB writes/locks
- Insert project root into `sys.path` in `scripts/run_sniffer.py` so that running script directly (python scripts/run_sniffer.py) can import `src` modules
- Fixed `NameError: Path` by importing `Path` before using it at top-level
- Created `MANUAL.md` and `LEARNING_NOTES.md` for long-term reference and learning

Troubleshooting log (observed errors and concrete fixes)
-------------------------------------------------------
1) "ModuleNotFoundError: No module named 'src'"
   - Cause: running `python scripts/run_sniffer.py` doesn't place repo root on `sys.path`.
   - Fix: at top of `scripts/run_sniffer.py` insert project root into `sys.path`:
     ```python
     from pathlib import Path
     ROOT = Path(__file__).resolve().parents[1]
     if str(ROOT) not in sys.path:
         sys.path.insert(0, str(ROOT))
     ```

2) "NameError: name 'Path' is not defined"
   - Cause: used `Path` before importing it.
   - Fix: add `from pathlib import Path` at top of file before `ROOT = Path(...)`

3) pip install / venv permission errors (OSError [Errno 13] Permission denied on `.venv`)
   - Cause: Files or `.venv` created by `root` due to using `sudo` incorrectly.
   - Fixes:
     - Best: delete and re-create `.venv` as your user.
     - If files are root-owned, `sudo chown -R $(whoami):$(whoami) /path/to/repo` then recreate venv and reinstall packages.

4) scapy exceptions or cannot open device for live sniffing
   - Cause: raw socket permissions
   - Fixes:
     - Run `sudo python3 scripts/run_sniffer.py --iface eth0`
     - Or set capability on `.venv` python: `sudo setcap cap_net_raw+ep $(readlink -f .venv/bin/python)`
     - Ensure `libpcap-dev` installed: `sudo apt-get install -y libpcap-dev`

5) SQLite locking with multiple writers
   - Cause: concurrent writers to SQLite
   - Fix implemented: workers write results to temp JSONL files; parent reads files and inserts sequentially. If you still see locks, consider setting WAL mode in the DB.

6) model loading errors (joblib/pandas missing)
   - Cause: model specified but dependencies missing
   - Fix: `pip install joblib pandas` or ensure `pip install -r requirements.txt` was run.

How to update the project on Kali
---------------------------------
- If your local clone is healthy, use `git pull` to update.
- Re-clone only when the local tree is corrupted (root-owned files or inconsistent state).
- Reinstall dependencies only if packages are missing or `requirements.txt` changed.

Repro steps (clean setup on new machine)
----------------------------------------
1. Clone as user: `git clone ...`
2. `python3 -m venv .venv`
3. `source .venv/bin/activate`
4. `pip install -r requirements.txt`
5. Run tests and smoke-run
   - `python3 -m pytest -q`
   - `python3 scripts/run_sniffer.py --test`

Tests and quality gates
-----------------------
- Unit tests exist in `tests/` and should be run with `pytest`.
- Quality gates used during development:
  - Run tests: `pytest`
  - Smoke test CLI: `python3 scripts/run_sniffer.py --test`

Fields to study next (recommended learning path)
-----------------------------------------------
1. Networking & DNS internals
   - DNS packet format (RFC 1035)
   - DNS name encoding (labels, compression)
   - How DNS tunnelling works (exfiltration techniques, encoding schemes)
2. Packet capture & libpcap / scapy
   - Packet capture semantics and scapy basics
   - Pcap vs pcapng differences
3. Feature engineering for network traffic
   - String entropy, n-gram analysis, pronounceability metrics
   - Heuristic vs ML-based detection trade-offs
4. Machine learning for security
   - Feature selection, model explainability, false positives/negatives
   - Dataset labeling for network data and cross-validation methods
5. Systems & deployment
   - Virtualenvs, capabilities (`setcap`), systemd service for long-running capture
   - Safe handling of raw sockets and privilege separation
6. Databases for telemetry
   - SQLite concurrency (WAL), time-series DBs (InfluxDB), message queues for scalable ingestion
7. CI/CD and packaging
   - GitHub Actions for testing, packaging with `pyproject.toml`, console scripts

Quick reference (most-used commands)
------------------------------------
# install
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# tests
python3 -m pytest -q

# dry-run
python3 scripts/run_sniffer.py --test

# process pcaps
python3 scripts/run_sniffer.py --pcap-dir /path/to/pcaps --workers 4 --summary-csv /tmp/summary.csv

# live sniff (root)
sudo python3 scripts/run_sniffer.py --iface eth0

Closing notes
-------------
I assembled these notes from the conversation history and the repository contents. If you want, I can:
- Convert this Markdown to PDF and add `LEARNING_NOTES.pdf` to the repository (I will check for `pandoc` or other converters and try to generate the PDF automatically), or
- Create a shorter printable cheat-sheet PDF instead.

Tell me whether you want me to attempt PDF generation now (I will try `pandoc` and fall back to other methods), or whether you prefer to generate the PDF locally (I'll provide the command).
