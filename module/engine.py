"""
Top-level orchestration engine.

CrackEngine validates configuration, iterates through attack vectors,
and prints summary reports on success or failure.
"""

import hashlib
import time
import sys
from typing import Optional

from .config import MAX_SEARCH_SPACE, GPU_BATCH_SIZE, CPU_BATCH_SIZE, NUM_CPU_WORKERS
from .gpu import GPU_AVAILABLE, GPU_NAME
from .cracker import SHA1Cracker
from .attacks import build_attack_vectors
from .workers import stop_signal, reset_stop_signal


class CrackEngine:
    """Orchestrates a full cracking session across all attack vectors."""

    def __init__(self, target_hash: str, target_prefix: str):
        self._target_hash = target_hash
        self._target_prefix = target_prefix
        self._cracker: Optional[SHA1Cracker] = None
        self._session_start: Optional[float] = None

    # ─── Configuration ───────────────────────────────────────────────

    def validate_config(self) -> bool:
        """Sanity-check the target hash and prefix before running."""
        try:
            SHA1Cracker(self._target_hash)
        except ValueError as exc:
            print(f"Configuration Error: {exc}")
            return False

        if not self._target_prefix:
            print("Configuration Warning: Target prefix is empty.")

        if MAX_SEARCH_SPACE < 1:
            print("Configuration Error: Maximum search space must be positive")
            return False

        return True

    # ─── Main Entry Point ────────────────────────────────────────────

    def run(self) -> Optional[str]:
        """Execute all attack vectors and return the recovered password."""
        self._print_banner()

        self._cracker = SHA1Cracker(self._target_hash)
        self._session_start = time.time()
        reset_stop_signal()

        vectors = build_attack_vectors(self._target_prefix)

        for index, vector in enumerate(vectors, 1):
            if stop_signal.value:
                print("\nAnalysis stopped by early termination flag.")
                break

            complexity = vector.search_space
            print(f"\n--- Vector {index}/{len(vectors)} "
                  f"[Priority: {vector.priority}] ---")
            print(f"Pattern: {vector.prefix} + {vector.suffix_length} chars "
                  f"from a set of {len(vector.charset)}")
            print(f"Computational complexity: {complexity:,}")

            if complexity > MAX_SEARCH_SPACE:
                print("Complexity exceeds threshold, skipping...")
                continue

            vector_start = time.time()
            result = self._cracker.crack_suffix(
                vector.prefix, vector.suffix_length, vector.charset,
            )
            elapsed = time.time() - vector_start

            if result:
                return self._report_success(result, elapsed)

            if not stop_signal.value:
                print(f"Vector completed without success in {elapsed:.1f}s")

        self._report_failure()
        return None

    # ─── Reporting ───────────────────────────────────────────────────

    def _print_banner(self):
        """Print a startup banner with session configuration."""
        sep = "=" * 70
        print(sep)
        print("SHA-1 CRYPTOGRAPHIC ANALYSIS ENGINE - GPU OPTIMIZED")
        print(sep)
        print(f"Target Hash: {self._target_hash}")
        print(f"Analysis Prefix: {self._target_prefix}")
        print(f"Maximum Search Space: {MAX_SEARCH_SPACE:,} combinations")

        if GPU_AVAILABLE:
            backend = f"GPU ({GPU_NAME})"
            opts = [
                "Custom CUDA C++ SHA-1 kernel",
                "Cached kernel compilation",
                f"GPU batch size: {GPU_BATCH_SIZE:,}",
            ]
        else:
            backend = f"CPU ({NUM_CPU_WORKERS} cores)"
            opts = [
                "ProcessPool for CPU parallelism",
                f"CPU batch size: {CPU_BATCH_SIZE:,}",
            ]

        opts += [
            "Memory-efficient candidate generation",
            "Early stopping with atomic flags",
            "Accurate progress tracking",
        ]

        print(f"Acceleration: {backend}")
        print(f"Optimizations: {', '.join(opts)}")
        print(sep)

    def _report_success(self, plaintext: str, vector_time: float) -> str:
        """Print a verification report and return the recovered password."""
        total_time = time.time() - self._session_start
        computed_hash = hashlib.sha1(plaintext.encode()).hexdigest()
        match = computed_hash == self._cracker.target_hash

        sep = "=" * 70
        print(f"\n{sep}")
        print("PASSWORD FOUND!")
        print(f"Recovered Plaintext: {plaintext}")
        print(f"Time to Crack Vector: {vector_time:.2f} seconds")
        print(f"Total Analysis Time: {total_time:.2f} seconds")
        print(f"\n--- Verification ---")
        print(f"  Target Hash: {self._target_hash}")
        print(f"   Found Hash: {computed_hash}")
        print(f"        Match: {match}")
        print(sep)
        return plaintext

    def _report_failure(self):
        """Print a summary when no vector found a match."""
        if stop_signal.value:
            return  # stopped early, not a true failure

        total_time = time.time() - self._session_start
        sep = "=" * 70
        print(f"\n{sep}")
        print("Analysis completed without successful recovery.")
        print(f"Total analysis time: {total_time:.2f} seconds")
        print(f"\nPotential factors:")
        print(f"  - Password not covered by the defined charsets and lengths.")
        print(f"  - Prefix '{self._target_prefix}' may be incorrect.")
        print(f"  - Consider adding more complex attack vectors or masks.")
        print(sep)
