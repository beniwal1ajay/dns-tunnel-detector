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


def test_list_csvs(tmp_path):
    (tmp_path / 'a.csv').write_text('qname\nfoo.example.com.')
    (tmp_path / 'b.txt').write_text('x')
    sub = tmp_path / 'sub'
    sub.mkdir()
    (sub / 'c.csv').write_text('domain\nbar.example.net.')

    from scripts.run_sniffer import list_csvs

    files = list_csvs(str(tmp_path), recursive=False)
    assert any(p.name == 'a.csv' for p in files)

    files_rec = list_csvs(str(tmp_path), recursive=True)
    names = [p.name for p in files_rec]
    assert 'a.csv' in names and 'c.csv' in names


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


def test_process_csv_file(tmp_path):
    # create a CSV with qname header and one suspicious-looking qname
    csv_path = tmp_path / 'sample.csv'
    csv_path.write_text('qname\nsubdata.example.com.\na4b6c7d8e9f0.example.net.')

    from scripts.run_sniffer import process_csv_file

    stats = process_csv_file(str(csv_path), threshold=0.01, model_path=None, verbose=False, debug=False, print_all=False)

    # expect dns_queries to be 2 and a detections file to exist
    assert stats.get('dns_queries', 0) == 2
    det_file = stats.get('detections_file')
    assert det_file is not None
    assert tmp_path.parent.joinpath(Path(det_file).name).exists() or Path(det_file).exists()


def test_suppress_printing_for_csv(tmp_path, capsys):
    # Provide a small CSV with one suspicious qname and one benign qname
    csv_path = tmp_path / 'sample2.csv'
    csv_path.write_text('qname\nsubdata.example.com.\na4b6c7d8e9f0.example.net.')

    from scripts.run_sniffer import process_csv_file

    # When print_all=True and suppress_print=False we should see printed JSON lines
    stats = process_csv_file(str(csv_path), threshold=0.01, model_path=None, verbose=False, debug=False, print_all=True, suppress_print=False)
    captured = capsys.readouterr()
    assert captured.out.strip() != ''

    # When suppress_print=True there should be no stdout output even when print_all=True
    stats = process_csv_file(str(csv_path), threshold=0.01, model_path=None, verbose=False, debug=False, print_all=True, suppress_print=True)
    captured = capsys.readouterr()
    assert captured.out.strip() == ''


def test_run_sniffer_auto_suppresses_when_summary_csv(tmp_path, capsys):
    # Create a CSV and run run_sniffer with --summary-csv; per-detection prints
    # should be suppressed automatically unless --print-all is also given.
    csv_path = tmp_path / 'sample3.csv'
    csv_path.write_text('qname\nsubdata.example.com.\na4b6c7d8e9f0.example.net.')

    out_summary = str(tmp_path / 'out_summary.csv')

    from scripts.run_sniffer import run_sniffer

    # Call run_sniffer directly with summary_csv; it should auto-suppress printing
    run_sniffer(iface=None, threshold=0.01, test=False, pcap=None, db=None, model_path=None, verbose=False, pcap_dir=None, csv=str(csv_path), csv_dir=None, recursive=False, workers=1, summary_csv=out_summary, debug=False, print_all=False, suppress_print=False)
    captured = capsys.readouterr()
    assert captured.out.strip() == ''
