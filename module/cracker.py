"""
Core SHA-1 hash cracking logic.

SHA1Cracker validates the target hash, then runs brute-force suffix
attacks or mask attacks using the best available backend (GPU or CPU).
"""

import re
import hashlib
import itertools
import time
from typing import List, Optional, Tuple
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, wait

from .config import (
    MAX_SEARCH_SPACE,
    CPU_BATCH_SIZE,
    GPU_BATCH_SIZE,
    NUM_CPU_WORKERS,
    PROGRESS_INTERVAL,
)
from .gpu import GPU_AVAILABLE, GPU_DEVICE_IDS, GPU_NAME
from .models import MaskPattern
from .workers import cpu_worker, gpu_worker, set_stop_signal, stop_signal

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

        if GPU_AVAILABLE and len(prefix.encode('utf-8')) + suffix_length <= 55:
            return self._run_gpu(prefix, suffix_length, charset,
                                 search_space, start_time)

        if GPU_AVAILABLE:
            print("Candidate length exceeds GPU single-block SHA-1 limit; using CPU.")

        return self._run_cpu(prefix, suffix_length, charset,
                             search_space, start_time)

    # ── GPU path ─────────────────────────────────────────────────────

    def _run_gpu(self, prefix, suffix_length, charset,
                 search_space, start_time) -> Optional[str]:
        """Dispatch index ranges to the GPU kernel.

        No candidate data is transferred — the kernel generates
        candidates on-GPU from (prefix, charset, index).
        """
        device_ids = GPU_DEVICE_IDS or [0]

        if len(device_ids) == 1:
            for batch_start in range(0, search_space, GPU_BATCH_SIZE):
                if stop_signal.value:
                    break

                batch_size = min(GPU_BATCH_SIZE, search_space - batch_start)
                result = gpu_worker(
                    prefix, charset, suffix_length,
                    batch_start, batch_size, self.target_hash, device_ids[0],
                )
                if result:
                    stop_signal.value = True
                    return result

                self._print_progress(
                    batch_start + batch_size,
                    search_space,
                    start_time,
                )

            print()  # newline after progress bar
            return None

        with ThreadPoolExecutor(max_workers=len(device_ids)) as pool:
            pending = {}
            batch_starts = iter(range(0, search_space, GPU_BATCH_SIZE))
            completed = 0

            def submit_next(device_id: int) -> bool:
                if stop_signal.value:
                    return False

                try:
                    batch_start = next(batch_starts)
                except StopIteration:
                    return False

                batch_size = min(GPU_BATCH_SIZE, search_space - batch_start)
                future = pool.submit(
                    gpu_worker,
                    prefix,
                    charset,
                    suffix_length,
                    batch_start,
                    batch_size,
                    self.target_hash,
                    device_id,
                )
                pending[future] = (batch_size, device_id)
                return True

            for device_id in device_ids:
                submit_next(device_id)

            while pending and not stop_signal.value:
                done_futures, _ = wait(pending, return_when=FIRST_COMPLETED)

                for done_future in done_futures:
                    batch_size, device_id = pending.pop(done_future)
                    result = done_future.result()

                    if result:
                        stop_signal.value = True
                        for future in pending:
                            future.cancel()
                        return result

                    completed += batch_size
                    self._print_progress(completed, search_space, start_time)
                    submit_next(device_id)

        print()  # newline after progress bar
        return None

    # ── CPU path ─────────────────────────────────────────────────────

    def _run_cpu(self, prefix, suffix_length, charset,
                 search_space, start_time) -> Optional[str]:
        """Distribute index ranges across CPU worker processes.

        Workers generate and hash their own candidates locally —
        no large byte arrays are serialised across process boundaries.
        """
        with ProcessPoolExecutor(
            max_workers=NUM_CPU_WORKERS,
            initializer=set_stop_signal,
            initargs=(stop_signal,),
        ) as pool:
            pending = {}
            batch_starts = iter(range(0, search_space, CPU_BATCH_SIZE))
            completed = 0

            def submit_next() -> bool:
                if stop_signal.value:
                    return False

                try:
                    batch_start = next(batch_starts)
                except StopIteration:
                    return False

                batch_size = min(CPU_BATCH_SIZE, search_space - batch_start)
                future = pool.submit(
                    cpu_worker,
                    (prefix, charset, suffix_length,
                     batch_start, batch_size, self.target_hash),
                )
                pending[future] = batch_size
                return True

            for _ in range(NUM_CPU_WORKERS):
                if not submit_next():
                    break

            while pending and not stop_signal.value:
                done_futures, _ = wait(pending, return_when=FIRST_COMPLETED)

                for done_future in done_futures:
                    batch_size = pending.pop(done_future)
                    result = done_future.result()

                    if result:
                        stop_signal.value = True
                        for future in pending:
                            future.cancel()
                        return result

                    completed += batch_size
                    self._print_progress(completed, search_space, start_time)

                    if not submit_next():
                        continue

        print()  # newline after progress bar
        return None

    # ─── Mask Attack ─────────────────────────────────────────────────

    def crack_mask(self, mask: MaskPattern) -> Optional[str]:
        """Positional brute-force using a mask pattern (CPU only).

        Each ``?x`` token in the mask is replaced by every character in
        the corresponding charset; literal characters are kept as-is.
        """
        print(f"Executing mask attack with pattern: {mask.pattern}")

        parts, charsets = self._parse_mask(mask)
        search_space = 1
        for cs in charsets:
            search_space *= len(cs)

        print(f"Mask search space: {search_space:,} combinations")
        if search_space > MAX_SEARCH_SPACE:
            print("Mask complexity exceeds threshold, skipping...")
            return None

        start_time = time.time()
        target_digest = bytes.fromhex(self.target_hash)

        for count, combo in enumerate(itertools.product(*charsets), 1):
            if stop_signal.value:
                break

            combo_iter = iter(combo)
            candidate = ''.join(
                next(combo_iter) if part is None else part
                for part in parts
            )

            if hashlib.sha1(candidate.encode()).digest() == target_digest:
                return candidate

            if count % PROGRESS_INTERVAL == 0:
                self._print_progress(count, search_space, start_time)

        print()
        return None

    @staticmethod
    def _parse_mask(mask: MaskPattern) -> Tuple[List[Optional[str]], List[str]]:
        """Split a mask pattern into output parts and variable charsets."""
        parts: List[Optional[str]] = []
        charsets: List[str] = []
        i = 0
        while i < len(mask.pattern):
            if mask.pattern[i] == '?' and i + 1 < len(mask.pattern):
                token = mask.pattern[i:i + 2]
                if token in mask.charset_map:
                    parts.append(None)
                    charsets.append(mask.charset_map[token])
                    i += 2
                    continue
            parts.append(mask.pattern[i])
            i += 1
        return parts, charsets

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
