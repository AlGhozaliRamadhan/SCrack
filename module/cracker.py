"""
Core SHA-1 hash cracking logic.

SHA1Cracker validates the target hash, then runs brute-force suffix
attacks or mask attacks using the best available backend (GPU or CPU).
"""

import re
import hashlib
import itertools
import time
from typing import Optional
from concurrent.futures import ProcessPoolExecutor, as_completed

from .config import MAX_SEARCH_SPACE, CPU_BATCH_SIZE, GPU_BATCH_SIZE, NUM_CPU_WORKERS
from .gpu import GPU_AVAILABLE, GPU_NAME
from .models import MaskPattern
from .workers import stop_signal, cpu_worker, gpu_worker

# Regex for a valid 40-hex-char SHA-1 digest
_SHA1_PATTERN = re.compile(r'^[a-f0-9]{40}$')


class SHA1Cracker:
    """Performs SHA-1 hash recovery via brute-force (GPU or CPU)."""

    def __init__(self, target_hash: str):
        self.target_hash = self._validate_and_normalise(target_hash)

    # ─── Validation ──────────────────────────────────────────────────

    @staticmethod
    def _validate_and_normalise(hash_hex: str) -> str:
        """Return a normalised lowercase hex string, or raise on bad input."""
        normalised = hash_hex.strip().lower()
        if not _SHA1_PATTERN.match(normalised):
            raise ValueError(
                f"Invalid SHA-1 hash (expected 40 hex chars): '{hash_hex}'"
            )
        return normalised

    def verify(self, plaintext: str) -> bool:
        """Check whether `plaintext` hashes to the target."""
        return hashlib.sha1(plaintext.encode('utf-8')).hexdigest() == self.target_hash

    # ─── Suffix Attack ───────────────────────────────────────────────

    def crack_suffix(self, prefix: str, suffix_length: int,
                     charset: str) -> Optional[str]:
        """Brute-force every possible suffix appended to `prefix`.

        Automatically selects GPU or CPU backend.
        Returns the recovered plaintext, or None.
        """
        search_space = len(charset) ** suffix_length
        backend_label = (f"GPU ({GPU_NAME})" if GPU_AVAILABLE
                         else f"CPU ({NUM_CPU_WORKERS} cores)")

        print(f"Initiating suffix analysis: prefix='{prefix}', "
              f"length={suffix_length}")
        print(f"Search space complexity: {search_space:,} combinations")
        print(f"Using {backend_label} acceleration")

        if search_space > MAX_SEARCH_SPACE:
            print("Complexity exceeds threshold, skipping...")
            return None

        start_time = time.time()

        if GPU_AVAILABLE:
            return self._run_gpu(prefix, suffix_length, charset,
                                 search_space, start_time)
        return self._run_cpu(prefix, suffix_length, charset,
                             search_space, start_time)

    # ── GPU path ─────────────────────────────────────────────────────

    def _run_gpu(self, prefix, suffix_length, charset,
                 search_space, start_time) -> Optional[str]:
        """Dispatch index ranges to the GPU kernel.

        No candidate data is transferred — the kernel generates
        candidates on-GPU from (prefix, charset, index).
        """
        for batch_start in range(0, search_space, GPU_BATCH_SIZE):
            if stop_signal.value:
                break

            batch_size = min(GPU_BATCH_SIZE, search_space - batch_start)

            result = gpu_worker(
                prefix, charset, suffix_length,
                batch_start, batch_size, self.target_hash,
            )
            if result:
                stop_signal.value = True
                return result

            self._print_progress(batch_start + batch_size, search_space,
                                 start_time)

        print()  # newline after progress bar
        return None

    # ── CPU path ─────────────────────────────────────────────────────

    def _run_cpu(self, prefix, suffix_length, charset,
                 search_space, start_time) -> Optional[str]:
        """Distribute index ranges across CPU worker processes.

        Workers generate and hash their own candidates locally —
        no large byte arrays are serialised across process boundaries.
        """
        with ProcessPoolExecutor(max_workers=NUM_CPU_WORKERS) as pool:
            pending = {}

            for batch_start in range(0, search_space, CPU_BATCH_SIZE):
                if stop_signal.value:
                    break

                batch_size = min(CPU_BATCH_SIZE, search_space - batch_start)

                future = pool.submit(
                    cpu_worker,
                    (prefix, charset, suffix_length,
                     batch_start, batch_size, self.target_hash),
                )
                pending[future] = batch_start + batch_size

                # Drain completed futures one at a time to keep the pool fed
                for done_future in as_completed(pending):
                    result = done_future.result()
                    if result:
                        stop_signal.value = True
                        for f in pending:
                            f.cancel()
                        return result

                    progress = pending.pop(done_future)
                    self._print_progress(progress, search_space, start_time)
                    break  # submit next batch before draining more

        print()  # newline after progress bar
        return None

    # ─── Mask Attack ─────────────────────────────────────────────────

    def crack_mask(self, mask: MaskPattern) -> Optional[str]:
        """Positional brute-force using a mask pattern (CPU only).

        Each ``?x`` token in the mask is replaced by every character in
        the corresponding charset; literal characters are kept as-is.
        """
        print(f"Executing mask attack with pattern: {mask.pattern}")

        charsets, fixed_chars = self._parse_mask(mask)
        search_space = 1
        for cs in charsets:
            search_space *= len(cs)

        print(f"Mask search space: {search_space:,} combinations")
        if search_space > MAX_SEARCH_SPACE:
            print("Mask complexity exceeds threshold, skipping...")
            return None

        # Identify which positions are variable vs. fixed
        base = [c for c in fixed_chars if c is not None]
        var_positions = [
            i for i, c in enumerate(fixed_chars)
            if c is None and (i == 0 or fixed_chars[i - 1] is not None)
        ]

        start_time = time.time()
        target_digest = bytes.fromhex(self.target_hash)

        for count, combo in enumerate(itertools.product(*charsets), 1):
            if stop_signal.value:
                break

            candidate = list(base)
            for i, ch in enumerate(combo):
                candidate.insert(var_positions[i], ch)

            if hashlib.sha1("".join(candidate).encode()).digest() == target_digest:
                return "".join(candidate)

            if count % 100_000 == 0:
                self._print_progress(count, search_space, start_time)

        print()
        return None

    @staticmethod
    def _parse_mask(mask: MaskPattern):
        """Split a mask pattern into (list_of_charsets, fixed_char_slots)."""
        charsets = []
        fixed = list(mask.pattern)
        i = 0
        while i < len(mask.pattern):
            if mask.pattern[i] == '?' and i + 1 < len(mask.pattern):
                token = mask.pattern[i:i + 2]
                if token in mask.charset_map:
                    charsets.append(mask.charset_map[token])
                    fixed[i] = None
                    fixed[i + 1] = None
                    i += 2
                    continue
            i += 1
        return charsets, fixed

    # ─── Progress Reporting ──────────────────────────────────────────

    @staticmethod
    def _print_progress(current: int, total: int, start_time: float):
        """Print an in-place progress line with rate and ETA."""
        elapsed = time.time() - start_time
        pct = (current / total) * 100
        rate = current / elapsed if elapsed > 0 else 0

        if rate > 0 and current < total:
            remaining = (total - current) / rate
            if remaining < 60:
                eta = f"{remaining:.1f}s"
            elif remaining < 3600:
                eta = f"{remaining / 60:.1f}m"
            else:
                eta = f"{remaining / 3600:.1f}h"
        else:
            eta = "calculating..."

        print(
            f"\rProgress: {current:,}/{total:,} ({pct:.2f}%) | "
            f"Rate: {rate:,.0f} ops/sec | ETA: {eta}",
            end="",
        )
