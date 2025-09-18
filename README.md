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
