"""
Attack vector generation and strategy definitions.

Builds a prioritized list of brute-force vectors ordered from most
likely (short, common charsets) to exhaustive (long, wide charsets).
"""

import string
from typing import List, Tuple

from .models import AttackVector


LOWER = string.ascii_lowercase
LETTERS = string.ascii_letters
DIGITS = string.digits
ALNUM = LETTERS + DIGITS
SYMBOLS = "!@#$%"

AttackPlan = Tuple[int, int, str]

ATTACK_PLAN: Tuple[AttackPlan, ...] = (
    # Priority 1: Quick wins
    (1, 1, LOWER + DIGITS),
    (1, 2, LOWER + DIGITS),
    (1, 3, LOWER + DIGITS),
    (1, 4, LOWER),
    (1, 4, LOWER + DIGITS),

    # Priority 2: Moderate complexity
    (2, 3, ALNUM),
    (2, 4, LETTERS),
    (2, 5, LOWER),
    (2, 5, DIGITS),
    (2, 6, DIGITS),

    # Priority 3: Wider charsets
    (3, 4, ALNUM + SYMBOLS),
    (3, 5, LOWER + DIGITS),
    (3, 5, LETTERS),
    (3, 6, LOWER),
    (3, 7, DIGITS),
    (3, 8, DIGITS),

    # Priority 4: Extended search
    (4, 5, ALNUM),
    (4, 6, LOWER + DIGITS),
    (4, 7, LOWER),
    (4, 9, DIGITS),
    (4, 10, DIGITS),

    # Priority 5: Deep search
    (5, 6, LETTERS),
    (5, 7, LOWER + DIGITS),
    (5, 8, LOWER),
    (5, 11, DIGITS),
    (5, 12, DIGITS),

    # Priority 6: Very deep search
    (6, 7, LETTERS),
    (6, 8, LOWER + DIGITS),
    (6, 9, LOWER),

    # Priority 7: Exhaustive
    (7, 8, LETTERS),
    (7, 9, LOWER + DIGITS),
    (7, 10, LOWER),
)


def build_attack_vectors(prefix: str) -> List[AttackVector]:
    """Generate a prioritized list of attack vectors for the given prefix.

    Strategy overview:
        Priority 1 : Short suffixes, common charsets (lowercase, digits)
        Priority 2 : Moderate length, mixed case / digit-only
        Priority 3 : Wider charsets, symbols
        Priority 4-5 : Deep search, extended lengths
        Priority 6-7 : Exhaustive sweeps

    Returns vectors sorted by (priority ASC, search_space ASC) so the
    cheapest, most-likely vectors run first.
    """
    vectors = [
        AttackVector(
            prefix=prefix,
            suffix_length=suffix_length,
            charset=charset,
            priority=priority,
        )
        for priority, suffix_length, charset in ATTACK_PLAN
    ]
    vectors.sort(key=lambda vector: (vector.priority, vector.search_space))
    return vectors
