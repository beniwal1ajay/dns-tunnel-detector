DNS Tunnel Detector — Manual

This document is a complete manual for the dns-tunnel-detector project. It explains: prerequisites; installation; how to run the scripts; arguments and behaviour; troubleshooting; expected errors and fixes; examples; developer notes; and CI notes.

Table of contents
- Quick summary
- System prerequisites
- Python dependencies (what each does)
- Install steps (normal user and Kali/Debian notes)
- Running the detector
  - `DnsTunnelingDetection.py --test`
  - `python3 scripts/run_sniffer.py --test`
  - Live sniffing
  - Processing pcap / pcap-dir (parallel workers)
  - Writing summaries and DB persistence
  - Training a model
- Files and directories overview
- Tests
- Troubleshooting: error messages and their solutions
  - ImportError / ModuleNotFoundError for `src` when running scripts
  - Permission errors when creating `.venv` or installing packages
  - Scapy-related runtime errors
  - SQLite locking or write errors
  - Missing joblib/pandas when using a model
  - setcap / raw sockets / running as non-root
  - Windows-specific notes (not primary target)
- Advanced deployment notes
- FAQ / common questions
 - Full CLI reference (flags and meanings)
 - Use-case recipes (live sensor, forensic, batch, SIEM integration, model training)
 - Systemd installation & install script
 - Webhook/SIEM example (Splunk HEC, generic HTTP)
 - Log management and rotation
 - How to update on another machine (pulling changes and tests)
 - Privacy, data retention, and security notes

Quick summary
This project is a modular DNS-tunneling detection tool written in Python 3. Features include:
- Heuristic scoring (entropy, pronounceability, longest repeated substring, label randomness)
- Optional ML model scoring (joblib RandomForest probability)
- CLI runner for live sniffing or processing pcaps and directories of pcaps
- Parallel worker processing with parent-side SQLite persistence to avoid DB races
- Summary CSV output and per-file reports

System prerequisites
- Linux (Debian/Ubuntu/Kali recommended for live sniffing). Running live sniffing requires access to raw sockets.
- Python 3.8+ (3.10/3.11/3.12/3.13 tested)
- Development tools for building Python packages on Debian based systems:
  - `sudo apt-get update && sudo apt-get install -y build-essential python3-dev libpcap-dev libffi-dev` (some systems may require `libssl-dev`)

Python dependencies (purpose)
- `scapy` — packet parsing and live sniffing / pcap reading.
- `scikit-learn` — optional; used in `scripts/train_model.py` to train a classifier.
- `joblib` — load/save scikit-learn models.
- `pandas` — optional; used when handing features to a model (converting dict to DataFrame).
- `pytest` — development/test framework.
- `tqdm` — optional; displays progress bars when processing pcaps.

Note: All Python packages are listed in `requirements.txt`. If you need pinned versions, create `requirements.lock` or use `pip freeze > requirements.lock` after installing.

Install steps (user-friendly)
1) Clone the repo (do NOT use `sudo`):
```bash
cd ~/src
git clone https://github.com/beniwal1ajay/dns-tunnel-detector.git
cd dns-tunnel-detector
```

2) Create and activate a virtualenv as your user:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

3) If you will use live sniffing without root, give your venv python capability to open raw sockets (optional and system-specific):
```bash
# Be careful: grants a capability to the python binary in your venv; only do this if you understand the security implications
sudo setcap cap_net_raw+ep $(readlink -f .venv/bin/python)
```
Alternatively run the script with `sudo`.

Kali-specific notes
- Kali typically has `libpcap` already and development tools preinstalled. Still prefer using a virtualenv and avoid running `git` as root so file ownership remains your user.
- If a repository or `.venv` is root-owned due to accidentally running `sudo` during clone or venv creation, fix with:
```bash
sudo chown -R $(whoami):$(whoami) /path/to/dns-tunnel-detector
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Running the detector (summary)
- Dry-run (no scapy required):
```bash
python3 scripts/run_sniffer.py --test
# Or the legacy top-level wrapper
python3 DnsTunnelingDetection.py --test
```
- Live sniffing (requires scapy and raw socket permissions):
```bash
# run as root or with capabilities set on python binary
sudo python3 scripts/run_sniffer.py --iface eth0
```
- Read a single pcap:
```bash
python3 scripts/run_sniffer.py --pcap /path/to/file.pcap
```
- Process a directory of pcaps (parallel):
```bash
python3 scripts/run_sniffer.py --pcap-dir /path/to/pcaps --workers 4 --summary-csv /tmp/summary.csv
```
- Persist detections to SQLite:
```bash
python3 scripts/run_sniffer.py --pcap my.pcap --db data/detections.db
```
Notes on model usage
- Train a model using `scripts/train_model.py` (expects labeled CSV with features and `label` column):
```bash
python3 scripts/train_model.py train.csv model.joblib
```
- Use the model when processing:
```bash
python3 scripts/run_sniffer.py --pcap-dir data/pcaps --model model.joblib
```

Files and directories overview
- `DnsTunnelingDetection.py` — legacy top-level wrapper (kept for compat); has `--test` dry-run.
- `scripts/run_sniffer.py` — main CLI runner (pcap, pcap-dir, live sniffing, CSV summary, DB persistence, parallel workers)
- `scripts/train_model.py` — simple trainer using scikit-learn
- `src/dns_tunnel_detector/detector.py` — core feature extraction and heuristics
- `src/dns_tunnel_detector/store.py` — SQLite helper
- `tests/` — unit tests

Tests
- Run `pytest` from the repo root:
```bash
source .venv/bin/activate
python3 -m pytest -q
```

Troubleshooting: errors and solutions

1) Error: ModuleNotFoundError: No module named 'src'
Cause: When you run `python scripts/run_sniffer.py` directly, Python's import path doesn't include the repository root, so `from src.dns_tunnel_detector...` fails.
Solutions:
- Run via the package context (install the package) or use the wrapper top-level script (which ensures `sys.path`), or run from the repo root where `src` is a top-level package.
- The repository's `scripts/run_sniffer.py` now inserts the project root into `sys.path` at runtime. If you still see the error, ensure you are running the script from the cloned repository and the file has been updated:
```bash
git pull origin master
python3 scripts/run_sniffer.py --test
```

2) Error: Permission denied when installing packages into `.venv` or writing to site-packages
Cause: You created `.venv` or repo files as root earlier (used `sudo`), or file permissions are incorrect.
Solutions:
- Remove root-owned venv and recreate as your user:
```bash
sudo chown -R $(whoami):$(whoami) /path/to/dns-tunnel-detector
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3) Error: scapy raises exception (cannot open device, or permission denied for raw sockets)
Cause: Running live sniffing requires raw socket capability (root or capabilities) and access to libpcap.
Solutions:
- Run the script with `sudo`:
```bash
sudo python3 scripts/run_sniffer.py --iface eth0
```
- Or grant `cap_net_raw` to your venv python binary:
```bash
sudo setcap cap_net_raw+ep $(readlink -f .venv/bin/python)
```
- Ensure `libpcap` is installed: `sudo apt-get install -y libpcap-dev`

4) Error: SQLite database locked or insertion fails under parallel workers
Cause: Multiple processes attempting to write to SQLite concurrently.
Solution implemented in this project:
- Worker processes write detections to a temporary JSONL file; the parent process opens each temp file sequentially and inserts rows into SQLite. Ensure you run the parent process (the CLI) as the orchestrator and do not have other programs writing to the same DB concurrently.
- If you still get locks, ensure `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL` are set on the DB to improve concurrency (edit `src/dns_tunnel_detector/store.py` to set them if needed).

5) Error: joblib / pandas missing when using model
Cause: The model path was provided but `joblib`/`pandas` are not installed.
Solution:
- Install `joblib` and `pandas` into your environment:
```bash
pip install joblib pandas
```
- If model loading fails, the script falls back to heuristics and prints a warning; check logs when using `--verbose`.

6) Running scapy on Python versions with missing wheels / build failures
Cause: Some platforms require building scapy dependencies from source.
Solution:
- Install `build-essential` and `python3-dev`, and `libpcap-dev` (Debian/Ubuntu/Kali):
```bash
sudo apt-get install -y build-essential python3-dev libpcap-dev libffi-dev
```
- Then reinstall scapy in your venv: `pip install --upgrade scapy`

7) Unexpected results / False positives
Cause: Heuristic and model-based detection isn't perfect. DNS traffic from CDNs, fast-flux, or valid large subdomain names may look suspicious.
Solution:
- Use `--threshold` to tune detection sensitivity. Lower threshold -> more detections. Higher threshold -> fewer false positives.
- Collect labeled data and train a model with `scripts/train_model.py`.

8) Common git issues after editing files with sudo
- If `git` refuses to commit because of ownership, fix ownership as above, or clone the repo again without `sudo`.

Advanced deployment notes
- CI: add GitHub Actions to run tests and linting on push (I can add this if you want).
- Packaging: to avoid `sys.path` workarounds, add a `pyproject.toml` and install the package into the venv with `pip install -e .` so CLI scripts work without path hacks.

Full CLI reference (flags and meanings)
------------------------------------
This is the authoritative list of flags supported by `scripts/run_sniffer.py` (and the same options are available via the top-level wrapper when applicable):

- `--iface IFACE` : Network interface to listen on (live sniffing). Example: `--iface wlan0`.
- `--threshold N` : Float 0..1. Detections with score >= threshold will be printed to stdout. Default `0.6`.
- `--test` : Dry-run; print example qnames and exit.
- `--pcap FILE` : Process a single pcap file instead of live capture.
- `--pcap-dir DIR` : Process all pcaps in a directory; combine with `--workers` to parallelize.
- `--recursive` : With `--pcap-dir`, recurse into subdirectories.
- `--db PATH` : SQLite database path used to persist detections. Parent orchestrator manages writes when workers are used.
- `--model PATH` : Path to a `joblib`-serialized model. When available, model probability is used for final score.
- `--workers N` : Number of worker processes for `--pcap-dir` processing. Default: 1.
- `--summary-csv PATH` : Append per-file and aggregate summary rows to this CSV.
- `--verbose` : Set logging to DEBUG/INFO, useful for runtime information.
- `--debug` : Print per-processed-qname debug info to stderr (includes qname, score, components).
- `--print-all` : Print every processed qname as a JSON line to stdout regardless of score (useful for label collection).

Use-case recipes (copy-paste)
------------------------------
1) Quick dry-run (no root required):
```bash
python3 scripts/run_sniffer.py --test
```

2) Single-host live sensor (systemd)
```bash
# create venv, install deps
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# ensure service dirs
sudo useradd -r -s /usr/sbin/nologin dnsdetector || true
sudo mkdir -p /var/lib/dns-detector /var/log/dns-detector
sudo chown dnsdetector:dnsdetector /var/lib/dns-detector /var/log/dns-detector

# grant capability to venv python (alternative to running whole service as root)
sudo setcap cap_net_raw+ep $(readlink -f .venv/bin/python)

# run manually for a sanity check
sudo .venv/bin/python3 scripts/run_sniffer.py --iface wlan0 --db /var/lib/dns-detector/detections.db --summary-csv /var/log/dns-detector/summary.csv --threshold 0.6
```

3) As a service (systemd unit example)
Create `/etc/systemd/system/dns-detector.service` (example below):
```
[Unit]
Description=DNS Tunneling Detector
After=network.target

[Service]
Type=simple
User=dnsdetector
Group=dnsdetector
WorkingDirectory=/opt/dns-tunnel-detector
Environment=PATH=/opt/dns-tunnel-detector/.venv/bin:/usr/bin:/bin
ExecStart=/opt/dns-tunnel-detector/.venv/bin/python3 scripts/run_sniffer.py --iface wlan0 --db /var/lib/dns-detector/detections.db --summary-csv /var/log/dns-detector/summary.csv --threshold 0.6
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dns-detector.service
sudo journalctl -u dns-detector -f
```

4) Forensic workflow: capture then process
```bash
# capture 30 seconds of DNS traffic to pcap
sudo timeout 30 tcpdump -i wlan0 udp port 53 -w /tmp/capture.pcap

# process pcap offline (no capture privileges required)
python3 scripts/run_sniffer.py --pcap /tmp/capture.pcap --db /tmp/detections.db --summary-csv /tmp/summary.csv --threshold 0.4
```

5) Batch processing many pcaps with workers and aggregate CSV
```bash
python3 scripts/run_sniffer.py --pcap-dir /data/pcaps --workers 4 --summary-csv /tmp/summary.csv --db /tmp/detections.db
```

6) Collect labeled data (low threshold or print-all)
```bash
# collect all processed qnames to a file for manual labeling
python3 scripts/run_sniffer.py --pcap-dir /data/pcaps --workers 4 --print-all > all_qnames.jsonl
```

Webhook / SIEM example (posting detections)
------------------------------------------
This repo doesn't ship a built-in webhook sender by default, but here are two tiny examples you can use to forward detections.

# Simple bash forwarder (reads JSONL, posts each line)
```bash
while read -r line; do
  curl -s -X POST -H 'Content-Type: application/json' -d "$line" https://siem.example.com/ingest
done < detections.jsonl
```

# Python example (Splunk HEC)
```python
import requests
HEC_URL = 'https://splunk.example.com:8088/services/collector/event'
HEC_TOKEN = 'REPLACE_WITH_TOKEN'
with open('detections.jsonl') as fh:
    for line in fh:
        resp = requests.post(HEC_URL, headers={'Authorization': f'Splunk {HEC_TOKEN}'}, json={'event': line})
        resp.raise_for_status()
```

Systemd install script (example `install.sh`)
--------------------------------------------
This script automates common installation steps (adjust paths and user names to taste). Drop it in repo root and run as root to set up the service.
```bash
#!/usr/bin/env bash
set -euo pipefail
REPO=/opt/dns-tunnel-detector
USER=dnsdetector
GROUP=dnsdetector
SERVICE=/etc/systemd/system/dns-detector.service

# copy code
mkdir -p $REPO
cp -a . $REPO
cd $REPO

# create venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# create user
id -u $USER >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin $USER
mkdir -p /var/lib/dns-detector /var/log/dns-detector
chown -R $USER:$GROUP /var/lib/dns-detector /var/log/dns-detector || true

# grant capability to venv python
setcap cap_net_raw+ep $(readlink -f .venv/bin/python) || true

# write systemd unit (adjust if necessary)
cat > $SERVICE <<'EOF'
[Unit]
Description=DNS Tunneling Detector
After=network.target

[Service]
Type=simple
User=dnsdetector
Group=dnsdetector
WorkingDirectory=/opt/dns-tunnel-detector
Environment=PATH=/opt/dns-tunnel-detector/.venv/bin:/usr/bin:/bin
ExecStart=/opt/dns-tunnel-detector/.venv/bin/python3 scripts/run_sniffer.py --iface wlan0 --db /var/lib/dns-detector/detections.db --summary-csv /var/log/dns-detector/summary.csv --threshold 0.6
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now dns-detector.service
echo "Installed and started dns-detector.service"
```

Log management & rotation
-------------------------
If you run the detector as a systemd service, logs will go to `journalctl -u dns-detector`. If your service writes files under `/var/log/dns-detector/` configure `logrotate` to rotate them:

Example `/etc/logrotate.d/dns-detector`:
```
/var/log/dns-detector/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
```

Saving outputs and exports
-------------------------
- JSONL: run with `--print-all` (all processed qnames) or collect detections stdout to a file:
```bash
sudo python3 scripts/run_sniffer.py --iface wlan0 --threshold 0.6 > detections.jsonl
```
- Debug/logs: use `--debug` and/or `--verbose` to send additional info to stderr. Keep stdout/stderr separate when saving machine-readable output.
- SQLite export to CSV/JSON (example):
```bash
sqlite3 -json /var/lib/dns-detector/detections.db "SELECT * FROM detections;" > all_detections.json
sqlite3 -header -csv /var/lib/dns-detector/detections.db "SELECT * FROM detections;" > all_detections.csv
```

How to update on another machine (pull changes & run tests)
---------------------------------------------------------
If you already cloned the repo on Kali or other hosts, prefer `git pull` over re-clone unless files are corrupted or root-owned.

Commands to update and test:
```bash
cd /path/to/dns-tunnel-detector
git fetch origin
git checkout master
git pull --ff-only origin master

# if you use venv
python3 -m venv .venv || true
source .venv/bin/activate
pip install -r requirements.txt

# run unit tests
python3 -m pytest -q
```

Privacy, data retention and security
----------------------------------
- DNS qnames may contain sensitive data (identifiers, tokens). Treat detection logs as potentially sensitive.
- Apply retention policies: purge old DB entries older than X days using cron/SQL, or archive and encrypt.
- Secure the DB directory (`/var/lib/dns-detector`) with appropriate ownership and filesystem access controls.
- If shipping to external SIEM, consider anonymization/redaction before sending.

Appendix: advanced troubleshooting & tips
---------------------------------------
- If you see no JSON output, confirm `--threshold` value is appropriate (lower for debugging). Use `--print-all` to verify packet pipeline.
- If running under containers, ensure container has `CAP_NET_RAW` or is started with `--cap-add=NET_RAW --cap-add=NET_ADMIN` and network=host if you need host interface access.
- If SQLite writes fail under heavy load, consider switching to WAL mode by adding `PRAGMA journal_mode=WAL` to `store.init_db()`; for large-scale deployments consider central ingestion instead of local SQLite.

Change history & authorship
--------------------------------
- This manual was generated and expanded during iterative development. Keep this file current when adding flags or behavior.

-- end of MANUAL

FAQ
Q: Do I need to re-clone to get the latest updates on another machine (Kali)?
A: No — `git pull` is sufficient. Re-clone only if your local copy is broken (e.g., root-owned files causing permission issues).

Q: If `requirements.txt` is short and unpinned, should I pin versions?
A: Yes, for reproducibility you can pin versions after testing with your target environment:
```bash
pip install -r requirements.txt
pip freeze > requirements.lock
```
Then commit `requirements.lock` and use it when reproducing environments.

Contact / contribution notes
- If you want me to add a CI workflow, an `install_kali.sh` helper script, or to deeply expand `requirements.txt` to include pinned versions, say which you prefer and I'll add it and push.


-- end of MANUAL
