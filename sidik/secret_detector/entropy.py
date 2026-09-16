"""Shannon entropy calculation and character distribution analysis for secret candidate verification."""

import math
from collections import Counter
from typing import Dict, Tuple


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character.
    
    Formula: H(X) = -sum(P(x) * log2(P(x)))
    Higher values signify greater randomness/unpredictability.
    """
    if not data:
        return 0.0
    
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def analyze_charset_distribution(data: str) -> Dict[str, float]:
    """Calculates the proportion of character subsets in a candidate string."""
    if not data:
        return {"digit": 0.0, "lower": 0.0, "upper": 0.0, "symbol": 0.0}
    
    total = len(data)
    digits = sum(1 for c in data if c.isdigit())
    lowers = sum(1 for c in data if c.islower())
    uppers = sum(1 for c in data if c.isupper())
    symbols = total - (digits + lowers + uppers)
    
    return {
        "digit": round(digits / total, 3),
        "lower": round(lowers / total, 3),
        "upper": round(uppers / total, 3),
        "symbol": round(symbols / total, 3)
    }


def is_high_entropy_candidate(data: str, threshold: float = 3.0) -> Tuple[bool, float]:
    """Evaluates whether the given string exceeds the minimum randomness threshold."""
    entropy = calculate_shannon_entropy(data)
    return (entropy >= threshold), entropy
