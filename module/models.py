"""
Data models for attack configuration.

AttackVector — brute-force a suffix of known length against a charset.
MaskPattern  — positional charsets (e.g. ?l?l?d?d = 2 lowercase + 2 digits).
"""

import string
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class AttackVector:
    """A brute-force attack: try every suffix of `suffix_length` characters
    drawn from `charset`, appended to `prefix`."""

    prefix: str
    suffix_length: int
    charset: str
    priority: int = 1

    @property
    def search_space(self) -> int:
        """Total number of candidate passwords for this vector."""
        return len(self.charset) ** self.suffix_length


@dataclass
class MaskPattern:
    """Mask-based attack where each position has its own character class.

    Pattern tokens:
        ?l = lowercase    ?u = uppercase    ?d = digits
        ?s = symbols      ?a = all printable
    """

    pattern: str
    charset_map: Dict[str, str] = field(default_factory=lambda: {
        '?l': string.ascii_lowercase,
        '?u': string.ascii_uppercase,
        '?d': string.digits,
        '?s': "!@#$%^&*()_+-=[]{}|;:,.<>?",
        '?a': (string.ascii_letters + string.digits
               + "!@#$%^&*()_+-=[]{}|;:,.<>?"),
    })
