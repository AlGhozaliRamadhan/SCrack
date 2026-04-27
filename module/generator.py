"""
Efficient candidate password generation.

Converts a numeric index into a password by treating it as a base-N
number over the charset, prepended with the known prefix.
"""

from typing import List


class CandidateGenerator:
    """Generates candidate passwords by enumerating suffix permutations.

    Uses a reusable bytearray buffer to minimise memory allocations
    during batch generation.
    """

    def __init__(self, prefix: str, suffix_length: int, charset: str):
        self._prefix_bytes = prefix.encode('utf-8')
        self._suffix_length = suffix_length
        self._charset_bytes = charset.encode('utf-8')
        self._charset_size = len(self._charset_bytes)

        # Pre-allocate a mutable buffer: [prefix | suffix]
        total_length = len(self._prefix_bytes) + suffix_length
        self._buffer = bytearray(total_length)
        self._buffer[:len(self._prefix_bytes)] = self._prefix_bytes
        self._suffix_offset = len(self._prefix_bytes)

    @property
    def total_combinations(self) -> int:
        """Total number of unique suffixes that can be generated."""
        return self._charset_size ** self._suffix_length

    def generate_batch(self, start_index: int, batch_size: int) -> List[bytes]:
        """Return up to `batch_size` candidates starting from `start_index`.

        Each candidate is the prefix followed by a unique suffix derived
        from the index (treated as a base-N number over the charset).
        """
        candidates = []
        max_index = self.total_combinations

        for i in range(batch_size):
            index = start_index + i
            if index >= max_index:
                break

            # Decompose index into charset digits (least-significant last)
            remaining = index
            for pos in range(self._suffix_length - 1, -1, -1):
                self._buffer[self._suffix_offset + pos] = (
                    self._charset_bytes[remaining % self._charset_size]
                )
                remaining //= self._charset_size

            candidates.append(bytes(self._buffer))

        return candidates
