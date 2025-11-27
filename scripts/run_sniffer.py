#!/usr/bin/env python3
"""CLI runner for DNS tunneling detector.

Usage:
  python scripts/run_sniffer.py [--iface IFACE] [--threshold N] [--test]

Outputs JSON lines with detection score and features.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# When running this script directly (python scripts/run_sniffer.py) the package
# imports like `from src.dns_tunnel_detector...` may fail because the project root
# is not on sys.path. Ensure the project root is inserted.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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


def packet_handler(packet: Any, threshold: float, db: Optional[str] = None, model=None, logger=None, stats: dict = None, debug: bool = False, print_all: bool = False, suppress_print: bool = False, out_dir: Optional[str] = None, out_file: Optional[str] = None):
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

    # Debug: print every processed qname and score (to stderr) if requested
    if debug:
        try:
            print(f"[DEBUG] qname={qname} score={float(score):.6f} components={components}", file=sys.stderr)
        except Exception:
            pass

    # If print_all is set and printing is not suppressed, always print the processed qname (stdout) regardless of threshold
    if print_all and not suppress_print:
        try:
            print(format_output(qname, score, components))
        except Exception:
            pass

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
        # persist to a JSONL file in out_dir if requested
        if out_file:
            write_target = Path(out_file)
        elif out_dir:
            write_target = Path(out_dir) / 'live.detections.jsonl'

        if out_file or out_dir:
            try:
                write_target.parent.mkdir(parents=True, exist_ok=True)
                with open(write_target, 'a') as fh:
                    fh.write(out + '\n')
            except Exception:
                if logger:
                    logger.exception('Failed to write detection to %s', write_target)
        elif not suppress_print:
            print(out)
            try:
                Path(out_dir).mkdir(parents=True, exist_ok=True)
                # create a per-source file name: live / pcap basename / csv basename
                # If packet has no filename context, caller should pass proper out_dir and label
                out_fn = Path(out_dir) / 'live.detections.jsonl'
                with open(out_fn, 'a') as fh:
                    fh.write(out + '\n')
            except Exception:
                if logger:
                    logger.exception('Failed to write detection to %s', out_dir)
        elif not suppress_print:
            print(out)
        if db:
            try:
                store.insert_detection(db, qname, score, components)
            except Exception:
                if logger:
                    logger.exception('Failed to persist detection')
        if stats is not None:
            stats['detections'] += 1


def process_pcap_file(pcap_path: str, threshold: float, model_path: Optional[str] = None, verbose: bool = False, debug: bool = False, print_all: bool = False, suppress_print: bool = False, out_dir: Optional[str] = None) -> dict:
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
    out_file_path = None
    if out_dir:
        out_file_path = str(Path(out_dir) / (Path(pcap_path).name + '.detections.jsonl'))

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
                packet_handler(pkt, threshold, db=None, model=local_model, logger=None, stats=stats, debug=debug, print_all=print_all, suppress_print=suppress_print, out_file=out_file_path)

                if score >= threshold:
                    detections.append({'qname': qname, 'score': float(score), 'components': components})
    except Exception:
        pass

    # write detections to a JSONL file. If out_dir is provided, write to a
    # deterministic file named after the source pcap; otherwise use a temp file.
    if out_dir:
        try:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            out_file = Path(out_dir) / (Path(pcap_path).name + '.detections.jsonl')
            with open(out_file, 'a') as fh:
                for d in detections:
                    fh.write(_json.dumps(d) + '\n')
            tmp_path = str(out_file)
        except Exception:
            tmp = tempfile.NamedTemporaryFile(delete=False, prefix='detections_', suffix='.jsonl')
            tmp_path = tmp.name
            with open(tmp_path, 'w') as fh:
                for d in detections:
                    fh.write(_json.dumps(d) + '\n')
    else:
        tmp = tempfile.NamedTemporaryFile(delete=False, prefix='detections_', suffix='.jsonl')
        tmp_path = tmp.name
        with open(tmp_path, 'w') as fh:
            for d in detections:
                fh.write(_json.dumps(d) + '\n')

    # include path to detections file in returned stats
    stats['detections_file'] = tmp_path
    return stats


def process_csv_file(csv_path: str, threshold: float, model_path: Optional[str] = None, verbose: bool = False, debug: bool = False, print_all: bool = False, suppress_print: bool = False, out_dir: Optional[str] = None) -> dict:
    """Process a single CSV file in a worker process. Returns stats dict.

    CSV should contain a column with qnames (preferred header names: 'qname','query','domain').
    If no header is found, the first column is treated as the qname column.
    """
    # worker-local model load
    local_model = None
    if model_path and joblib is not None:
        try:
            local_model = joblib.load(model_path)
        except Exception:
            local_model = None

    stats = {}
    detections = []
    try:
        with open(csv_path, 'r', newline='') as fh:
            # try csv.DictReader, fall back to simple reader
            reader = csv.reader(fh)
            # Peek the first row to determine headers
            fh.seek(0)
            first = next(reader, None)
            if first is None:
                return stats
            # Reset file
            fh.seek(0)
            # Decide if header exists (simple heuristic)
            has_header = any(h.lower() in ('qname', 'query', 'domain') for h in first)
            if has_header:
                fh.seek(0)
                dreader = csv.DictReader(fh)
                for row in dreader:
                    # pick a qname field
                    qname = ''
                    for candidate in ('qname', 'query', 'domain'):
                        if candidate in row and row[candidate]:
                            qname = row[candidate]
                            break
                    if not qname:
                        # try any column
                        for v in row.values():
                            if v:
                                qname = v
                                break
                    if isinstance(qname, (bytes, bytearray)):
                        qname = qname.decode(errors='ignore')
                    if not qname:
                        continue

                    # compute features and score
                    qname_str = str(qname)
                    features = domain_features(qname_str)
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

                    # update stats similarly to packet_handler
                    stats.setdefault('dns_queries', 0)
                    stats.setdefault('detections', 0)
                    stats.setdefault('sum_score', 0.0)
                    stats.setdefault('qname_counts', Counter())
                    stats.setdefault('min_score', float('inf'))
                    stats.setdefault('max_score', float('-inf'))
                    stats.setdefault('sum_subdomain_entropy', 0.0)
                    stats.setdefault('sum_pronounceability', 0.0)
                    stats.setdefault('tld_counts', Counter())

                    stats['dns_queries'] += 1
                    stats['sum_score'] += float(score)
                    stats['qname_counts'][qname_str] += 1
                    stats['min_score'] = min(stats['min_score'], score)
                    stats['max_score'] = max(stats['max_score'], score)
                    stats['sum_subdomain_entropy'] += features.get('subdomain_entropy', 0.0)
                    stats['sum_pronounceability'] += features.get('avg_pronounceability', 0.0)
                    labels = qname_str.rstrip('.').split('.') if qname_str else []
                    tld = labels[-1].lower() if labels else ''
                    if tld:
                        stats['tld_counts'][tld] += 1

                    if print_all and not suppress_print:
                        try:
                            print(format_output(qname_str, score, components))
                        except Exception:
                            pass

                    if score >= threshold:
                        detections.append({'qname': qname_str, 'score': float(score), 'components': components})
            else:
                # no header — treat first column as qname
                fh.seek(0)
                r = csv.reader(fh)
                for row in r:
                    if not row:
                        continue
                    qname = row[0]
                    if isinstance(qname, (bytes, bytearray)):
                        qname = qname.decode(errors='ignore')
                    qname_str = str(qname)
                    features = domain_features(qname_str)
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

                    stats.setdefault('dns_queries', 0)
                    stats.setdefault('detections', 0)
                    stats.setdefault('sum_score', 0.0)
                    stats.setdefault('qname_counts', Counter())
                    stats.setdefault('min_score', float('inf'))
                    stats.setdefault('max_score', float('-inf'))
                    stats.setdefault('sum_subdomain_entropy', 0.0)
                    stats.setdefault('sum_pronounceability', 0.0)
                    stats.setdefault('tld_counts', Counter())

                    stats['dns_queries'] += 1
                    stats['sum_score'] += float(score)
                    stats['qname_counts'][qname_str] += 1
                    stats['min_score'] = min(stats['min_score'], score)
                    stats['max_score'] = max(stats['max_score'], score)
                    stats['sum_subdomain_entropy'] += features.get('subdomain_entropy', 0.0)
                    stats['sum_pronounceability'] += features.get('avg_pronounceability', 0.0)
                    labels = qname_str.rstrip('.').split('.') if qname_str else []
                    tld = labels[-1].lower() if labels else ''
                    if tld:
                        stats['tld_counts'][tld] += 1

                    if print_all and not suppress_print:
                        try:
                            print(format_output(qname_str, score, components))
                        except Exception:
                            pass

                    if score >= threshold:
                        detections.append({'qname': qname_str, 'score': float(score), 'components': components})
    except Exception:
        pass

    # write detections to file. If out_dir provided write to out_dir/<csv_basename>.detections.jsonl
    if out_dir:
        try:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            out_file = Path(out_dir) / (Path(csv_path).name + '.detections.jsonl')
            with open(out_file, 'a') as fh:
                for d in detections:
                    fh.write(_json.dumps(d) + '\n')
            tmp_path = str(out_file)
        except Exception:
            tmp = tempfile.NamedTemporaryFile(delete=False, prefix='detections_csv_', suffix='.jsonl')
            tmp_path = tmp.name
            with open(tmp_path, 'w') as fh:
                for d in detections:
                    fh.write(_json.dumps(d) + '\n')
    else:
        tmp = tempfile.NamedTemporaryFile(delete=False, prefix='detections_csv_', suffix='.jsonl')
        tmp_path = tmp.name
        with open(tmp_path, 'w') as fh:
            for d in detections:
                fh.write(_json.dumps(d) + '\n')

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
        import csv as _csv
        with open(csv_path, 'a', newline='') as fh:
            writer = _csv.DictWriter(fh, fieldnames=header)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
    except Exception:
        if logger:
            logger.exception('Failed to write summary CSV %s', csv_path)


def run_sniffer(iface: str | None, threshold: float, test: bool, pcap: Optional[str] = None, db: Optional[str] = None, model_path: Optional[str] = None, verbose: bool = False, pcap_dir: Optional[str] = None, csv: Optional[str] = None, csv_dir: Optional[str] = None, recursive: bool = False, workers: int = 1, summary_csv: Optional[str] = None, debug: bool = False, print_all: bool = False, suppress_print: bool = False, out_dir: Optional[str] = None):

    logger = logging.getLogger('dns_sniffer')
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)

    # If a summary CSV is requested and the user did not explicitly ask to
    # print every detection, suppress per-detection printing to avoid flooding
    # the terminal with many JSON lines (common when processing large pcaps).
    if summary_csv and not print_all:
        suppress_print = True

    # Startup info so operator knows effective configuration
    logger.info('Starting dns-sniffer: iface=%s threshold=%.3f test=%s pcap=%s pcap_dir=%s workers=%d model=%s db=%s print_all=%s suppress_print=%s out_dir=%s debug=%s',
                iface, threshold, test, pcap, pcap_dir, workers, model_path, db, print_all, suppress_print, out_dir, debug)

    # Initialize model if model_path is provided
    model = None
    if model_path and joblib is not None:
        try:
            model = joblib.load(model_path)
        except Exception:
            model = None



    if pcap:
        if sniff is None:
            logger.error('Scapy not available, cannot read pcap')
            return
        pstats = {}
        out_file_for_pcap = str(Path(out_dir) / (Path(pcap).name + '.detections.jsonl')) if out_dir else None
        with PcapReader(pcap) as rdr:
            if verbose and tqdm:
                for pkt in tqdm(rdr, desc=f'Processing {pcap}'):
                        packet_handler(pkt, threshold, db=db, model=model, logger=logger, stats=pstats, debug=debug, print_all=print_all, suppress_print=suppress_print, out_file=out_file_for_pcap)
            else:
                for pkt in rdr:
                    packet_handler(pkt, threshold, db=db, model=model, logger=logger, stats=pstats, debug=debug, print_all=print_all, suppress_print=suppress_print, out_file=out_file_for_pcap)
        if verbose:
            if summary_csv:
                try:
                    write_summary_csv(summary_csv, pstats, str(pcap), pcap_path=str(pcap))
                except Exception:
                    logger.exception('Failed to write PCAP summary for %s', pcap)
            # Optionally print summary to console (if desired)
            # print_summary(pstats, pcap)  # Uncomment if you want console output
        return
    if csv:
        # csv single-file processing
        pstats = process_csv_file(csv, threshold, model_path, verbose, debug, print_all, suppress_print=suppress_print, out_dir=out_dir)
        if verbose:
            print_summary(pstats, csv)
        # persist detections if db provided
        if db and pstats.get('detections_file'):
            try:
                with open(pstats['detections_file'], 'r') as fh:
                    for line in fh:
                        d = _json.loads(line)
                        store.insert_detection(db, d['qname'], d['score'], d.get('components', {}))
            except Exception:
                logger.exception('Failed to persist csv detections')
            finally:
                try:
                    # Only remove tmp detections files if they are not part of an explicit
                    # out_dir provided by the user. Workers write to out_dir if given and
                    # those files should be kept.
                    det_fp = Path(pstats['detections_file'])
                    if not out_dir or not det_fp.resolve().is_relative_to(Path(out_dir).resolve()):
                        det_fp.unlink()
                except Exception:
                    pass
        if summary_csv:
            try:
                write_summary_csv(summary_csv, pstats, str(csv), pcap_path=str(csv))
            except Exception:
                logger.exception('Failed to write CSV summary for %s', csv)
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
                    futures[ex.submit(process_pcap_file, str(p), threshold, model_path, verbose, debug, print_all, suppress_print, out_dir)] = p
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
                                det_fp = Path(det_file)
                                if not out_dir or not det_fp.resolve().is_relative_to(Path(out_dir).resolve()):
                                    det_fp.unlink()
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
                out_file_for_pcap = str(Path(out_dir) / (Path(p).name + '.detections.jsonl')) if out_dir else None
                with PcapReader(str(p)) as rdr:
                    if verbose and tqdm:
                        for pkt in tqdm(rdr, desc=f'Processing {p}'):
                            packet_handler(pkt, threshold, db=db, model=model, logger=logger, stats=pstats, debug=debug, print_all=print_all, suppress_print=suppress_print, out_file=out_file_for_pcap)
                    else:
                        for pkt in rdr:
                            packet_handler(pkt, threshold, db=db, model=model, logger=logger, stats=pstats, debug=debug, print_all=print_all, suppress_print=suppress_print, out_file=out_file_for_pcap)
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

    # CSV directory processing
    if csv_dir:
        csvs = list_csvs(csv_dir, recursive=recursive)
        if not csvs:
            logger.info('No CSV files found in %s', csv_dir)
            return

        if workers and workers > 1:
            max_workers = min(workers, max(1, multiprocessing.cpu_count()))
            logger.info('Processing %d csv files with %d workers', len(csvs), max_workers)
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
                for p in csvs:
                    futures[ex.submit(process_csv_file, str(p), threshold, model_path, verbose, debug, print_all, suppress_print, out_dir)] = p
                for fut in as_completed(futures):
                    p = futures[fut]
                    try:
                        pstats = fut.result()
                    except Exception:
                        logger.exception('Worker failed for %s', p)
                        pstats = {}
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
                                det_fp = Path(det_file)
                                if not out_dir or not det_fp.resolve().is_relative_to(Path(out_dir).resolve()):
                                    det_fp.unlink()
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
                print_summary(agg, f'aggregate:{csv_dir}')
            if summary_csv:
                try:
                    write_summary_csv(summary_csv, agg, f'aggregate:{csv_dir}', pcap_path='')
                except Exception:
                    logger.exception('Failed to write aggregate CSV summary for %s', csv_dir)
            return
        else:
            agg = {'dns_queries': 0, 'detections': 0, 'sum_score': 0.0, 'qname_counts': Counter()}
            for p in csvs:
                logger.info('Processing csv %s', p)
                pstats = process_csv_file(str(p), threshold, model_path, verbose, debug, print_all, suppress_print=suppress_print, out_dir=out_dir)
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
                print_summary(agg, f"aggregate:{csv_dir}")
            if summary_csv:
                try:
                    write_summary_csv(summary_csv, agg, f"aggregate:{csv_dir}", pcap_path='')
                except Exception:
                    logger.exception('Failed to write aggregate CSV summary for %s', csv_dir)
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
        out_file_for_live = str(Path(out_dir) / 'live.detections.jsonl') if out_dir else None
        sniff(filter="udp port 53", prn=lambda p: packet_handler(p, threshold, db=db, model=model, logger=logger, stats=live_stats, debug=debug, print_all=print_all, suppress_print=suppress_print, out_file=out_file_for_live), store=0, iface=iface)
    except KeyboardInterrupt:
        # print final summary
        print_summary(live_stats, 'live')

def print_summary(stats: dict, label: str, logger: Optional[logging.Logger] = None):
    """Print a concise human-readable summary for stats and label.

    This function is called in several places in the script; previously it was
    missing which caused a NameError. Keep it lightweight and robust.
    """
    if logger is None:
        logger = logging.getLogger('dns_sniffer')

    total = stats.get('dns_queries', 0)
    det = stats.get('detections', 0)
    avg_score = (stats.get('sum_score', 0.0) / total) if total else 0.0
    min_score = stats.get('min_score', None)
    max_score = stats.get('max_score', None)

    # Build a short summary line
    parts = [f'label={label}', f'queries={total}', f'detections={det}', f'avg_score={avg_score:.6f}']
    if min_score is not None and min_score != float('inf'):
        parts.append(f'min={min_score:.6f}')
    if max_score is not None and max_score != float('-inf'):
        parts.append(f'max={max_score:.6f}')

    # Top TLD (if available)
    top_tlds = stats.get('tld_counts', Counter()).most_common(1)
    if top_tlds:
        parts.append(f'top_tld={top_tlds[0][0]}')

    logger.info('Summary: %s', ' '.join(parts))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', default=None)
    parser.add_argument('--threshold', type=float, default=0.6)
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--pcap', default=None, help='Read from pcap file instead of live capture')
    parser.add_argument('--pcap-dir', default=None, help='Directory containing pcap/pcapng files to process')
    parser.add_argument('--csv', default=None, help='Path to a CSV file containing qnames/queries to scan')
    parser.add_argument('--csv-dir', default=None, help='Directory containing CSV files to process')
    parser.add_argument('--recursive', action='store_true', help='Recursively search for pcaps in --pcap-dir')
    parser.add_argument('--db', default=None, help='SQLite DB path to persist detections')
    parser.add_argument('--model', default=None, help='Joblib model path')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--workers', type=int, default=1, help='Number of worker processes for parallel pcap processing')
    parser.add_argument('--summary-csv', default=None, help='Path to write per-file and aggregate summary CSV')
    parser.add_argument('--debug', action='store_true', help='Print debug info for every processed DNS query to stderr')
    parser.add_argument('--print-all', action='store_true', help='Print every processed DNS query to stdout regardless of threshold')
    parser.add_argument('--suppress-detections', action='store_true', help='Suppress printing individual detections to stdout')
    parser.add_argument('--out-dir', default=None, help='Directory to write detection JSONL files into (no DB needed)')
    args = parser.parse_args(argv)
    run_sniffer(args.iface, args.threshold, args.test, pcap=args.pcap, db=args.db, model_path=args.model, verbose=args.verbose, pcap_dir=args.pcap_dir, csv=args.csv, csv_dir=args.csv_dir, recursive=args.recursive, workers=args.workers, summary_csv=args.summary_csv, debug=args.debug, print_all=args.print_all, suppress_print=args.suppress_detections, out_dir=args.out_dir)


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


def list_csvs(directory: str, recursive: bool = False) -> List[Path]:
    """Return list of .csv files in a directory. Returns Path objects."""
    p = Path(directory)
    exts = {'.csv'}
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
