#!/usr/bin/env python3
"""CLI runner for DNS tunneling detector.

Usage:
  python scripts/run_sniffer.py [--iface IFACE] [--threshold N] [--test]

Outputs JSON lines with detection score and features.
"""
from __future__ import annotations

import argparse
import json
import sys
import logging
import signal
from collections import Counter
from typing import Any, Optional
from pathlib import Path

try:
    from scapy.all import sniff, DNS, DNSQR
except Exception:
    sniff = None
    DNS = None
    DNSQR = None

from src.dns_tunnel_detector.detector import domain_features, score_tunneling
from src.dns_tunnel_detector import store

try:
    import joblib
except Exception:
    joblib = None

from scapy.utils import PcapReader
try:
    from tqdm import tqdm
except Exception:
    tqdm = None
from typing import List
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import tempfile
import json as _json
import csv
from typing import Tuple


def format_output(qname: str, score: float, components: dict) -> str:
    out = {'qname': qname, 'score': score, 'components': components}
    return json.dumps(out)


def packet_handler(packet: Any, threshold: float, db: Optional[str] = None, model=None, logger=None, stats: dict = None):
    if not (packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and packet.haslayer(DNSQR)):
        return

    try:
        dns_layer = packet.getlayer(DNS)
        dns_query = dns_layer[DNSQR]
        qname = getattr(dns_query, 'qname', '')
        if isinstance(qname, (bytes, bytearray)):
            qname = qname.decode(errors='ignore')
    except Exception:
        return

    features = domain_features(qname)
    # model scoring overrides heuristic if available
    if model is not None:
        try:
            import pandas as pd
            df = pd.DataFrame([features])
            score = float(model.predict_proba(df)[0, 1])
            components = {'model': 'probability'}
        except Exception:
            score, components = score_tunneling(features)
    else:
        score, components = score_tunneling(features)

    # update stats if provided
    if stats is not None:
        stats.setdefault('packets', 0)
        stats.setdefault('dns_queries', 0)
        stats.setdefault('detections', 0)
        stats.setdefault('sum_score', 0.0)
        stats.setdefault('qname_counts', Counter())
        stats.setdefault('min_score', float('inf'))
        stats.setdefault('max_score', float('-inf'))
        stats.setdefault('sum_subdomain_entropy', 0.0)
        stats.setdefault('sum_pronounceability', 0.0)
        stats.setdefault('tld_counts', Counter())

        stats['packets'] += 1
        stats['dns_queries'] += 1
        stats['sum_score'] += float(score)
        stats['qname_counts'][qname] += 1
        stats['min_score'] = min(stats['min_score'], score)
        stats['max_score'] = max(stats['max_score'], score)
        stats['sum_subdomain_entropy'] += features.get('subdomain_entropy', 0.0)
        stats['sum_pronounceability'] += features.get('avg_pronounceability', 0.0)
        # tld
        labels = qname.rstrip('.').split('.') if qname else []
        tld = labels[-1].lower() if labels else ''
        if tld:
            stats['tld_counts'][tld] += 1

    if logger:
        logger.debug('Detected qname %s score=%.3f', qname, score)

    if score >= threshold:
        out = format_output(qname, score, components)
        print(out)
        if db:
            try:
                store.insert_detection(db, qname, score, components)
            except Exception:
                if logger:
                    logger.exception('Failed to persist detection')
        if stats is not None:
            stats['detections'] += 1


def process_pcap_file(pcap_path: str, threshold: float, model_path: Optional[str] = None, verbose: bool = False) -> dict:
    """Process a single pcap file in a worker process. Returns stats dict.

    This function avoids DB writes; it returns stats to be merged by the parent.
    """
    # worker-local imports and model loading
    local_model = None
    if model_path and joblib is not None:
        try:
            local_model = joblib.load(model_path)
        except Exception:
            local_model = None

    stats = {}
    detections = []
    try:
        with PcapReader(pcap_path) as rdr:
            for pkt in rdr:
                # collect detections by having packet_handler update stats and return printed detections
                # we capture detections by inspecting when score >= threshold inside packet_handler
                # to avoid changing packet_handler signature, we replicate scoring here
                if not (pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and pkt.haslayer(DNSQR)):
                    continue
                try:
                    dns_layer = pkt.getlayer(DNS)
                    dns_query = dns_layer[DNSQR]
                    qname = getattr(dns_query, 'qname', '')
                    if isinstance(qname, (bytes, bytearray)):
                        qname = qname.decode(errors='ignore')
                except Exception:
                    continue

                features = domain_features(qname)
                if local_model is not None:
                    try:
                        import pandas as pd
                        df = pd.DataFrame([features])
                        score = float(local_model.predict_proba(df)[0, 1])
                        components = {'model': 'probability'}
                    except Exception:
                        score, components = score_tunneling(features)
                else:
                    score, components = score_tunneling(features)

                # update stats
                packet_stats = {}
                # let packet_handler logic fill stats for reuse
                packet_handler(pkt, threshold, db=None, model=local_model, logger=None, stats=stats)

                if score >= threshold:
                    detections.append({'qname': qname, 'score': float(score), 'components': components})
    except Exception:
        pass

    # write detections to a temp jsonl file (may be empty)
    tmp = tempfile.NamedTemporaryFile(delete=False, prefix='detections_', suffix='.jsonl')
    tmp_path = tmp.name
    with open(tmp_path, 'w') as fh:
        for d in detections:
            fh.write(_json.dumps(d) + '\n')

    # include path to detections file in returned stats
    stats['detections_file'] = tmp_path
    return stats


def write_summary_csv(csv_path: str, stats: dict, label: str, pcap_path: Optional[str] = None, logger: Optional[logging.Logger] = None):
    # Ensure parent dir exists
    try:
        Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    total = stats.get('dns_queries', 0)
    det = stats.get('detections', 0)
    avg_score = (stats.get('sum_score', 0.0) / total) if total else 0.0
    min_score = stats.get('min_score', None)
    max_score = stats.get('max_score', None)
    avg_sub_entropy = (stats.get('sum_subdomain_entropy', 0.0) / total) if total else 0.0
    avg_pron = (stats.get('sum_pronounceability', 0.0) / total) if total else 0.0
    top_tlds = stats.get('tld_counts', Counter()).most_common(1)
    top_tld = top_tlds[0][0] if top_tlds else ''

    header = ['label', 'pcap', 'dns_queries', 'detections', 'avg_score', 'min_score', 'max_score', 'avg_subdomain_entropy', 'avg_pronounceability', 'top_tld']
    row = {
        'label': label,
        'pcap': pcap_path or '',
        'dns_queries': total,
        'detections': det,
        'avg_score': f"{avg_score:.6f}",
        'min_score': f"{min_score:.6f}" if min_score is not None and min_score != float('inf') else '',
        'max_score': f"{max_score:.6f}" if max_score is not None and max_score != float('-inf') else '',
        'avg_subdomain_entropy': f"{avg_sub_entropy:.6f}",
        'avg_pronounceability': f"{avg_pron:.6f}",
        'top_tld': top_tld,
    }

    write_header = not Path(csv_path).exists()
    try:
        with open(csv_path, 'a', newline='') as fh:
            writer = csv.DictWriter(fh, fieldnames=header)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
    except Exception:
        if logger:
            logger.exception('Failed to write summary CSV %s', csv_path)


def run_sniffer(iface: str | None, threshold: float, test: bool, pcap: Optional[str] = None, db: Optional[str] = None, model_path: Optional[str] = None, verbose: bool = False, pcap_dir: Optional[str] = None, recursive: bool = False, workers: int = 1, summary_csv: Optional[str] = None):
    logger = logging.getLogger('dns_sniffer')
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)

    model = None
    if model_path:
        if joblib is None:
            logger.warning('joblib not available, cannot load model')
        else:
            try:
                model = joblib.load(model_path)
                logger.info('Loaded model %s', model_path)
            except Exception:
                logger.exception('Failed to load model')

    if db:
        Path(db).parent.mkdir(parents=True, exist_ok=True)
        store.init_db(db)

    if test:
        # quick dry-run
        qnames = ["subdata.example.com.", "a4b6c7d8e9f0.example.net."]
        for q in qnames:
            features = domain_features(q)
            if model is not None:
                try:
                    import pandas as pd
                    df = pd.DataFrame([features])
                    score = float(model.predict_proba(df)[0, 1])
                    comps = {'model': 'probability'}
                except Exception:
                    score, comps = score_tunneling(features)
            else:
                score, comps = score_tunneling(features)
            print(format_output(q, score, comps))
        return

    def print_summary(stats: dict, label: str):
        if not stats:
            print(f"Summary for {label}: no DNS packets processed")
            return
        total = stats.get('dns_queries', 0)
        det = stats.get('detections', 0)
        avg_score = (stats.get('sum_score', 0.0) / total) if total else 0.0
        min_score = stats.get('min_score', None)
        max_score = stats.get('max_score', None)
        avg_sub_entropy = (stats.get('sum_subdomain_entropy', 0.0) / total) if total else 0.0
        avg_pron = (stats.get('sum_pronounceability', 0.0) / total) if total else 0.0
        top_tlds = stats.get('tld_counts', Counter()).most_common(5)
        top = stats.get('qname_counts', Counter()).most_common(5)
        print('\n' + '='*60)
        print(f"Summary for {label}:")
        print(f"  DNS queries processed: {total}")
        print(f"  Detections (score >= threshold): {det}")
        print(f"  Average score: {avg_score:.3f}")
        if min_score is not None and max_score is not None:
            print(f"  Score range: {min_score:.3f} - {max_score:.3f}")
        print(f"  Avg subdomain entropy: {avg_sub_entropy:.3f}")
        print(f"  Avg pronounceability: {avg_pron:.3f}")
        print("  Top queries:")
        for q, c in top:
            print(f"    {q} ({c})")
        print("  Top TLDs:")
        for t, c in top_tlds:
            print(f"    {t} ({c})")
        print('='*60 + '\n')

    def write_summary_csv(csv_path: str, stats: dict, label: str, pcap_path: Optional[str] = None):
        # Ensure parent dir exists
        try:
            Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        total = stats.get('dns_queries', 0)
        det = stats.get('detections', 0)
        avg_score = (stats.get('sum_score', 0.0) / total) if total else 0.0
        min_score = stats.get('min_score', None)
        max_score = stats.get('max_score', None)
        avg_sub_entropy = (stats.get('sum_subdomain_entropy', 0.0) / total) if total else 0.0
        avg_pron = (stats.get('sum_pronounceability', 0.0) / total) if total else 0.0
        top_tlds = stats.get('tld_counts', Counter()).most_common(1)
        top_tld = top_tlds[0][0] if top_tlds else ''

        header = ['label', 'pcap', 'dns_queries', 'detections', 'avg_score', 'min_score', 'max_score', 'avg_subdomain_entropy', 'avg_pronounceability', 'top_tld']
        row = {
            'label': label,
            'pcap': pcap_path or '',
            'dns_queries': total,
            'detections': det,
            'avg_score': f"{avg_score:.6f}",
            'min_score': f"{min_score:.6f}" if min_score is not None and min_score != float('inf') else '',
            'max_score': f"{max_score:.6f}" if max_score is not None and max_score != float('-inf') else '',
            'avg_subdomain_entropy': f"{avg_sub_entropy:.6f}",
            'avg_pronounceability': f"{avg_pron:.6f}",
            'top_tld': top_tld,
        }

        write_header = not Path(csv_path).exists()
        try:
            with open(csv_path, 'a', newline='') as fh:
                writer = csv.DictWriter(fh, fieldnames=header)
                if write_header:
                    writer.writeheader()
                writer.writerow(row)
        except Exception:
            logger.exception('Failed to write summary CSV %s', csv_path)

    if pcap:
        if sniff is None:
            logger.error('Scapy not available, cannot read pcap')
            return
        pstats = {}
        with PcapReader(pcap) as rdr:
            if verbose and tqdm:
                for pkt in tqdm(rdr, desc=f'Processing {pcap}'):
                    packet_handler(pkt, threshold, db=db, model=model, logger=logger, stats=pstats)
            else:
                for pkt in rdr:
                    packet_handler(pkt, threshold, db=db, model=model, logger=logger, stats=pstats)
        if verbose:
            print_summary(pstats, pcap)
        return
    parser_summary_csv = None
    if pcap_dir:
        pcaps = list_pcaps(pcap_dir, recursive=recursive)
        if not pcaps:
            logger.info('No pcaps found in %s', pcap_dir)
            return

        if workers and workers > 1:
            # parallel processing: disable DB writes in workers
            max_workers = min(workers, max(1, multiprocessing.cpu_count()))
            logger.info('Processing %d pcaps with %d workers', len(pcaps), max_workers)
            agg = {
                'dns_queries': 0,
                'detections': 0,
                'sum_score': 0.0,
                'qname_counts': Counter(),
                'tld_counts': Counter(),
                'sum_subdomain_entropy': 0.0,
                'sum_pronounceability': 0.0,
                'min_score': float('inf'),
                'max_score': float('-inf')
            }
            futures = {}
            with ProcessPoolExecutor(max_workers=max_workers) as ex:
                for p in pcaps:
                    futures[ex.submit(process_pcap_file, str(p), threshold, model_path, verbose)] = p
                for fut in as_completed(futures):
                    p = futures[fut]
                    try:
                        pstats = fut.result()
                    except Exception:
                        logger.exception('Worker failed for %s', p)
                        pstats = {}
                    # merge stats
                    agg['dns_queries'] += pstats.get('dns_queries', 0)
                    agg['detections'] += pstats.get('detections', 0)
                    agg['sum_score'] += pstats.get('sum_score', 0.0)
                    agg['qname_counts'].update(pstats.get('qname_counts', Counter()))
                    agg['tld_counts'].update(pstats.get('tld_counts', Counter()))
                    agg['sum_subdomain_entropy'] += pstats.get('sum_subdomain_entropy', 0.0)
                    agg['sum_pronounceability'] += pstats.get('sum_pronounceability', 0.0)
                    if 'min_score' in pstats:
                        agg['min_score'] = min(agg.get('min_score', float('inf')), pstats.get('min_score'))
                    if 'max_score' in pstats:
                        agg['max_score'] = max(agg.get('max_score', float('-inf')), pstats.get('max_score'))
                    # persist detections returned via temp file
                    det_file = pstats.get('detections_file')
                    if det_file and db:
                        try:
                            with open(det_file, 'r') as fh:
                                for line in fh:
                                    d = _json.loads(line)
                                    store.insert_detection(db, d['qname'], d['score'], d.get('components', {}))
                        except Exception:
                            logger.exception('Failed to persist detections from %s', det_file)
                        finally:
                            try:
                                Path(det_file).unlink()
                            except Exception:
                                pass
                    # write per-file CSV summary if requested
                    if summary_csv:
                        try:
                            write_summary_csv(summary_csv, pstats, str(p), pcap_path=str(p))
                        except Exception:
                            logger.exception('Failed to write CSV summary for %s', p)
                    if verbose:
                        print_summary(pstats, str(p))
            if verbose:
                print_summary(agg, f'aggregate:{pcap_dir}')
            if summary_csv:
                try:
                    write_summary_csv(summary_csv, agg, f'aggregate:{pcap_dir}', pcap_path='')
                except Exception:
                    logger.exception('Failed to write aggregate CSV summary for %s', pcap_dir)
            # optional: persist aggregate detections if db provided (not implemented here to avoid races)
            return
        else:
            # sequential processing (existing behavior)
            agg = {'dns_queries': 0, 'detections': 0, 'sum_score': 0.0, 'qname_counts': Counter()}
            for p in pcaps:
                logger.info('Processing pcap %s', p)
                pstats = {}
                with PcapReader(str(p)) as rdr:
                    if verbose and tqdm:
                        for pkt in tqdm(rdr, desc=f'Processing {p}'):
                            packet_handler(pkt, threshold, db=db, model=model, logger=logger, stats=pstats)
                    else:
                        for pkt in rdr:
                            packet_handler(pkt, threshold, db=db, model=model, logger=logger, stats=pstats)
                # merge into aggregate
                agg['dns_queries'] += pstats.get('dns_queries', 0)
                agg['detections'] += pstats.get('detections', 0)
                agg['sum_score'] += pstats.get('sum_score', 0.0)
                agg['qname_counts'].update(pstats.get('qname_counts', Counter()))
                if summary_csv:
                    try:
                        write_summary_csv(summary_csv, pstats, str(p), pcap_path=str(p))
                    except Exception:
                        logger.exception('Failed to write CSV summary for %s', p)
                if verbose:
                    print_summary(pstats, str(p))
            if verbose:
                print_summary(agg, f"aggregate:{pcap_dir}")
            if summary_csv:
                try:
                    write_summary_csv(summary_csv, agg, f"aggregate:{pcap_dir}", pcap_path='')
                except Exception:
                    logger.exception('Failed to write aggregate CSV summary for %s', pcap_dir)
            return

    if sniff is None:
        logger.error('Scapy not available. Install scapy or run with --test.')
        return

    # live sniffing: collect stats and optionally print summary on SIGINT
    live_stats = {}

    def _handle_sigint(signum, frame):
        print_summary(live_stats, 'live')
        raise KeyboardInterrupt

    if verbose:
        signal.signal(signal.SIGINT, _handle_sigint)

    try:
        sniff(filter="udp port 53", prn=lambda p: packet_handler(p, threshold, db=db, model=model, logger=logger, stats=live_stats), store=0, iface=iface)
    except KeyboardInterrupt:
        # print final summary
        print_summary(live_stats, 'live')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', default=None)
    parser.add_argument('--threshold', type=float, default=0.6)
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--pcap', default=None, help='Read from pcap file instead of live capture')
    parser.add_argument('--pcap-dir', default=None, help='Directory containing pcap/pcapng files to process')
    parser.add_argument('--recursive', action='store_true', help='Recursively search for pcaps in --pcap-dir')
    parser.add_argument('--db', default=None, help='SQLite DB path to persist detections')
    parser.add_argument('--model', default=None, help='Joblib model path')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--workers', type=int, default=1, help='Number of worker processes for parallel pcap processing')
    parser.add_argument('--summary-csv', default=None, help='Path to write per-file and aggregate summary CSV')
    args = parser.parse_args(argv)
    run_sniffer(args.iface, args.threshold, args.test, pcap=args.pcap, db=args.db, model_path=args.model, verbose=args.verbose, pcap_dir=args.pcap_dir, recursive=args.recursive, workers=args.workers, summary_csv=args.summary_csv)


def list_pcaps(directory: str, recursive: bool = False) -> List[Path]:
    """Return list of pcap/pcapng files in a directory. Returns Path objects.

    If recursive is True, walk subdirectories.
    """
    p = Path(directory)
    exts = {'.pcap', '.pcapng'}
    files = []
    if recursive:
        for fp in p.rglob('*'):
            if fp.suffix.lower() in exts and fp.is_file():
                files.append(fp)
    else:
        for fp in p.iterdir():
            if fp.suffix.lower() in exts and fp.is_file():
                files.append(fp)
    return sorted(files)


if __name__ == '__main__':
    main()
