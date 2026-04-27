"""
Attack vector generation and strategy definitions.

Builds a prioritized list of brute-force vectors ordered from most
likely (short, common charsets) to exhaustive (long, wide charsets).
"""

import string
from typing import List

from .models import AttackVector


# ─── Charset Shortcuts ──────────────────────────────────────────────────
LOWER   = string.ascii_lowercase
LETTERS = string.ascii_letters
DIGITS  = string.digits
ALNUM   = LETTERS + DIGITS
SYMBOLS = "!@#$%"


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
        # ── Priority 1: Quick wins ──────────────────────────────────
        AttackVector(prefix, suffix_length=1,  charset=LOWER + DIGITS,  priority=1),
        AttackVector(prefix, suffix_length=2,  charset=LOWER + DIGITS,  priority=1),
        AttackVector(prefix, suffix_length=3,  charset=LOWER + DIGITS,  priority=1),
        AttackVector(prefix, suffix_length=4,  charset=LOWER,           priority=1),
        AttackVector(prefix, suffix_length=4,  charset=LOWER + DIGITS,  priority=1),

        # ── Priority 2: Moderate complexity ─────────────────────────
        AttackVector(prefix, suffix_length=3,  charset=ALNUM,           priority=2),
        AttackVector(prefix, suffix_length=4,  charset=LETTERS,         priority=2),
        AttackVector(prefix, suffix_length=5,  charset=LOWER,           priority=2),
        AttackVector(prefix, suffix_length=5,  charset=DIGITS,          priority=2),
        AttackVector(prefix, suffix_length=6,  charset=DIGITS,          priority=2),

        # ── Priority 3: Wider charsets ──────────────────────────────
        AttackVector(prefix, suffix_length=4,  charset=ALNUM + SYMBOLS, priority=3),
        AttackVector(prefix, suffix_length=5,  charset=LOWER + DIGITS,  priority=3),
        AttackVector(prefix, suffix_length=5,  charset=LETTERS,         priority=3),
        AttackVector(prefix, suffix_length=6,  charset=LOWER,           priority=3),
        AttackVector(prefix, suffix_length=7,  charset=DIGITS,          priority=3),
        AttackVector(prefix, suffix_length=8,  charset=DIGITS,          priority=3),

        # ── Priority 4: Extended search ─────────────────────────────
        AttackVector(prefix, suffix_length=5,  charset=ALNUM,           priority=4),
        AttackVector(prefix, suffix_length=6,  charset=LOWER + DIGITS,  priority=4),
        AttackVector(prefix, suffix_length=7,  charset=LOWER,           priority=4),
        AttackVector(prefix, suffix_length=9,  charset=DIGITS,          priority=4),
        AttackVector(prefix, suffix_length=10, charset=DIGITS,          priority=4),

        # ── Priority 5: Deep search ────────────────────────────────
        AttackVector(prefix, suffix_length=6,  charset=LETTERS,         priority=5),
        AttackVector(prefix, suffix_length=7,  charset=LOWER + DIGITS,  priority=5),
        AttackVector(prefix, suffix_length=8,  charset=LOWER,           priority=5),
        AttackVector(prefix, suffix_length=11, charset=DIGITS,          priority=5),
        AttackVector(prefix, suffix_length=12, charset=DIGITS,          priority=5),

        # ── Priority 6: Very deep search ───────────────────────────
        AttackVector(prefix, suffix_length=7,  charset=LETTERS,         priority=6),
        AttackVector(prefix, suffix_length=8,  charset=LOWER + DIGITS,  priority=6),
        AttackVector(prefix, suffix_length=9,  charset=LOWER,           priority=6),

        # ── Priority 7: Exhaustive ─────────────────────────────────
        AttackVector(prefix, suffix_length=8,  charset=LETTERS,         priority=7),
        AttackVector(prefix, suffix_length=9,  charset=LOWER + DIGITS,  priority=7),
        AttackVector(prefix, suffix_length=10, charset=LOWER,           priority=7),
    ]

    # Process easiest vectors first within each priority tier
    vectors.sort(key=lambda v: (v.priority, v.search_space))
    return vectors
