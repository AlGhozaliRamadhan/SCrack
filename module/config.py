"""
Configuration constants for the SHA-1 hash recovery engine.

Modify TARGET_HASH and TARGET_PREFIX before running.
Performance constants can be tuned based on your hardware.
"""

import multiprocessing as mp


# ─── Target Configuration ───────────────────────────────────────────────
# The SHA-1 hash to recover and any known prefix of the plaintext.
TARGET_HASH   = "Here"   # 40-character hex SHA-1 hash to crack
TARGET_PREFIX = "Here"   # Known prefix of the password (exclude wildcard chars)


# ─── Performance Tuning ─────────────────────────────────────────────────
MAX_SEARCH_SPACE   = 100_000_000_000   # Skip vectors larger than this
PROGRESS_INTERVAL  = 10_000            # Print progress every N candidates
CPU_BATCH_SIZE     = 100_000           # Candidates per CPU batch
GPU_BATCH_SIZE     = 40_000_000        # Candidates per GPU batch
NUM_CPU_WORKERS    = mp.cpu_count()    # Parallel CPU worker processes
