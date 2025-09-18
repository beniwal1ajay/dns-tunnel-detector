"""Advanced DNS tunneling detector utilities.

This module provides feature extraction from DNS query names and a simple
scoring-based detector that combines heuristics (entropy, length, label randomness,
and uncommon TLDs) to flag likely DNS tunneling.

It's intentionally dependency-light so you can run core logic without scapy
for unit testing and CI.
"""
from __future__ import annotations

import math
import re
from typing import Dict, Tuple
from collections import Counter
from itertools import islice
from math import log2

LABEL_RE = re.compile(r"[A-Za-z0-9_-]+$")


def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
    return entropy


def ngram_entropy(s: str, n: int = 3) -> float:
    """Calculate entropy over n-grams of the string (useful for detecting structured vs random)."""
    if not s or n <= 0:
        return 0.0
    s = s if len(s) >= n else s + ('_' * (n - len(s)))
    grams = [s[i:i+n] for i in range(len(s) - n + 1)]
    counts = Counter(grams)
    total = sum(counts.values())
    return -sum((c/total) * log2(c/total) for c in counts.values())


def longest_repeated_substring(s: str) -> int:
    """Return length of the longest repeated substring (simple O(n^2) approach)."""
    if not s:
        return 0
    n = len(s)
    longest = 0
    for i in range(n):
        for j in range(i+1, n):
            l = 0
            while j + l < n and s[i + l] == s[j + l]:
                l += 1
            if l > longest:
                longest = l
    return longest


VOWELS = set('aeiou')


def pronounceability_score(label: str) -> float:
    """Simple heuristic: higher for readable labels, lower for random ones (0..1).

    Uses vowel-consonant runs and proportion of vowels to estimate pronounceability.
    """
    if not label:
        return 0.0
    lab = label.lower()
    vowel_count = sum(1 for ch in lab if ch in VOWELS)
    vowel_ratio = vowel_count / len(lab)
    # penalize extremely low or high vowel ratios
    score = 1.0 - abs(vowel_ratio - 0.35)
    # penalize many repeated substrings
    lrs = longest_repeated_substring(lab)
    score *= (1.0 - min(0.5, lrs / max(1, len(lab))))
    return max(0.0, min(1.0, score))


def analyze_dns_answer(packet) -> Dict[str, float]:
    """Lightweight analysis of DNS answers (if packet includes answers).

    Returns counts and a 'suspicious_txt' flag if TXT records look encoded.
    This function expects scapy DNS packet objects but is defensive for tests.
    """
    res = {'answer_count': 0.0, 'suspicious_txt': 0.0}
    try:
        ans = getattr(packet, 'an', None) or getattr(packet, 'anr', None)
        # scapy uses DNS.an for answer; but test callers may pass dict-like objects
        if not ans:
            return res
        # count answer records if iterable
        if hasattr(ans, '__len__'):
            res['answer_count'] = float(len(ans))
        # look for TXT-like entries
        for a in ans:
            txt = getattr(a, 'rdata', None) or getattr(a, 'txt', None)
            if txt:
                # if txt looks base64-like or has high entropy -> suspicious
                txts = txt if isinstance(txt, (list, tuple)) else [txt]
                for t in txts:
                    tstr = t.decode(errors='ignore') if isinstance(t, (bytes, bytearray)) else str(t)
                    if calculate_entropy(tstr) > 4.0:
                        res['suspicious_txt'] = 1.0
    except Exception:
        pass
    return res


def label_entropy_scores(domain: str) -> Dict[str, float]:
    """Return entropy-related scores for each label in a domain.

    domain: e.g. 'abcd.efgh.example.com.'
    returns: {'subdomain_entropy': float, 'avg_label_entropy': float, 'max_label_entropy': float}
    """
    labels = [l for l in domain.rstrip('.').split('.') if l]
    if not labels:
        return {'subdomain_entropy': 0.0, 'avg_label_entropy': 0.0, 'max_label_entropy': 0.0}

    # consider subdomain labels (exclude last two labels as the registered domain)
    if len(labels) > 2:
        sub_labels = labels[:-2]
    else:
        sub_labels = []

    entropies = [calculate_entropy(l) for l in sub_labels]
    subdomain_entropy = calculate_entropy('.'.join(sub_labels)) if sub_labels else 0.0
    avg = float(sum(entropies) / len(entropies)) if entropies else 0.0
    mx = float(max(entropies)) if entropies else 0.0
    return {'subdomain_entropy': subdomain_entropy, 'avg_label_entropy': avg, 'max_label_entropy': mx}


def label_randomness_score(label: str) -> float:
    """Score how 'random' a label looks (0..1).

    Uses heuristics: character class mixtures, proportion of non-alphanumerics,
    and length. This is a lightweight replacement for an ML model.
    """
    if not label:
        return 0.0
    score = 0.0
    length = len(label)
    # reward long labels
    score += min(1.0, length / 32.0)

    # character diversity
    sets = [any(ch.islower() for ch in label), any(ch.isupper() for ch in label),
            any(ch.isdigit() for ch in label), any(not ch.isalnum() for ch in label)]
    score += (sum(sets) - 1) * 0.25

    # penalize if it matches typical readable patterns
    if LABEL_RE.match(label):
        score *= 0.7

    return max(0.0, min(1.0, score))


COMMON_TLDS = {"com", "org", "net", "edu", "gov", "io", "co"}


def domain_features(qname: str) -> Dict[str, float]:
    """Extract a compact feature dict from a query name string.

    qname: 'sub.data.example.com.' or bytes already decoded.
    Returns features used by the simple heuristic detector.
    """
    if isinstance(qname, (bytes, bytearray)):
        qname = qname.decode(errors='ignore')

    q = qname.rstrip('.')
    labels = q.split('.') if q else []

    features = {
        'query_length': len(qname),
        'label_count': len(labels),
        'has_subdomain': 1.0 if len(labels) > 2 else 0.0,
    }

    # entropy features
    ent = label_entropy_scores(qname)
    features.update(ent)

    # label randomness (max over subdomain labels)
    if len(labels) > 2:
        sub_labels = labels[:-2]
    else:
        sub_labels = []
    randomness_scores = [label_randomness_score(l) for l in sub_labels]
    features['max_label_randomness'] = max(randomness_scores) if randomness_scores else 0.0
    features['avg_label_randomness'] = float(sum(randomness_scores) / len(randomness_scores)) if randomness_scores else 0.0

    # tld check
    tld = labels[-1].lower() if labels else ''
    features['uncommon_tld'] = 0.0 if tld in COMMON_TLDS else 1.0

    # additional features
    # n-gram entropy for the joined subdomain
    features['ngram_entropy'] = ngram_entropy('.'.join(sub_labels), n=3) if sub_labels else 0.0
    # longest repeated substring in the subdomain (max over labels)
    features['longest_repeated'] = max((longest_repeated_substring(l) for l in sub_labels), default=0)
    # pronounceability (avg over labels)
    pron = [pronounceability_score(l) for l in sub_labels]
    features['avg_pronounceability'] = float(sum(pron) / len(pron)) if pron else 0.0

    return features


def score_tunneling(features: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
    """Combine features into a single tunneling score (0..1) and return breakdown.

    This is a deterministic heuristic scoring function suitable as a baseline.
    """
    # weights (tunable)
    w = {
        'subdomain_entropy': 0.35,
        'max_label_randomness': 0.25,
        'query_length': 0.15,
        'uncommon_tld': 0.1,
        'avg_label_entropy': 0.15,
    }

    # normalize query_length (expect reasonable max ~200)
    qlen_n = min(1.0, features.get('query_length', 0) / 200.0)

    components = {
        'subdomain_entropy': min(1.0, features.get('subdomain_entropy', 0) / 6.0),
        'max_label_randomness': features.get('max_label_randomness', 0),
        'query_length': qlen_n,
        'uncommon_tld': features.get('uncommon_tld', 0),
        'avg_label_entropy': min(1.0, features.get('avg_label_entropy', 0) / 6.0),
    }

    score = sum(components[k] * w[k] for k in w)
    # clip
    score = max(0.0, min(1.0, score))
    return score, components


__all__ = ["calculate_entropy", "domain_features", "score_tunneling"]
