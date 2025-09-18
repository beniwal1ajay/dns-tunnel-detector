import math
import sys
import os

# Ensure project src directory is on sys.path for pytest runs
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.dns_tunnel_detector.detector import calculate_entropy, domain_features, score_tunneling


def test_entropy_basic():
    assert calculate_entropy('') == 0.0
    assert math.isclose(calculate_entropy('aaaa'), 0.0, abs_tol=1e-9)
    e = calculate_entropy('abcd')
    assert e > 0.0


def test_domain_features_and_score():
    q = 'subdata.example.com.'
    f = domain_features(q)
    assert 'subdomain_entropy' in f
    score, comps = score_tunneling(f)
    assert 0.0 <= score <= 1.0


def test_new_features():
    from src.dns_tunnel_detector.detector import ngram_entropy, longest_repeated_substring, pronounceability_score

    assert ngram_entropy('abcdabcd', n=2) > 0
    assert longest_repeated_substring('abcabc') >= 3
    assert 0.0 <= pronounceability_score('google') <= 1.0
