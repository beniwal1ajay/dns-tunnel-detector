import tempfile
import sys
import os
from pathlib import Path

# ensure project root on sys.path for imports
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.dns_tunnel_detector import store
from collections import Counter


def test_list_pcaps(tmp_path):
    # create some dummy files
    (tmp_path / 'a.pcap').write_text('')
    (tmp_path / 'b.txt').write_text('')
    sub = tmp_path / 'sub'
    sub.mkdir()
    (sub / 'c.pcapng').write_text('')

    from scripts.run_sniffer import list_pcaps

    files = list_pcaps(str(tmp_path), recursive=False)
    assert any(p.name == 'a.pcap' for p in files)

    files_rec = list_pcaps(str(tmp_path), recursive=True)
    names = [p.name for p in files_rec]
    assert 'a.pcap' in names and 'c.pcapng' in names


def test_write_summary_csv(tmp_path):
    # create a fake stats dict
    stats = {
        'dns_queries': 10,
        'detections': 2,
        'sum_score': 1.8,
        'sum_subdomain_entropy': 12.0,
        'sum_pronounceability': 3.5,
        'min_score': 0.1,
        'max_score': 0.9,
        'tld_counts': Counter({'com': 5})
    }

    csv_path = tmp_path / 'summary.csv'
    from scripts.run_sniffer import write_summary_csv

    write_summary_csv(str(csv_path), stats, 'testlabel', pcap_path='a.pcap')

    assert csv_path.exists()
    content = csv_path.read_text()
    assert 'label,pcap,dns_queries' in content
    assert 'testlabel' in content
