"""
Hash computation workers for CPU and GPU backends.

V2: Workers receive generation PARAMETERS instead of pre-built candidate
lists.  This eliminates pickle serialisation overhead (CPU) and the
bulk data transfer bottleneck (GPU).
"""

import hashlib
import ctypes
import multiprocessing as mp
from typing import Optional

import numpy as np

from .gpu import GPU_AVAILABLE

if GPU_AVAILABLE:
    import cupy as cp
    from .gpu import get_sha1_kernel


# ─── Shared Stop Signal ─────────────────────────────────────────────────
stop_signal = mp.Value(ctypes.c_bool, False)


def reset_stop_signal():
    """Clear the stop signal before starting a new cracking session."""
    stop_signal.value = False


# ─── Password Reconstruction ────────────────────────────────────────────

def _reconstruct_password(prefix: str, charset: str,
                          suffix_length: int, candidate_index: int) -> str:
    """Rebuild the plaintext from its numeric index in the search space."""
    suffix = []
    temp = candidate_index
    charset_len = len(charset)
    for _ in range(suffix_length):
        suffix.append(charset[temp % charset_len])
        temp //= charset_len
    return prefix + ''.join(reversed(suffix))


# ─── CPU Worker ──────────────────────────────────────────────────────────

def cpu_worker(args) -> Optional[str]:
    """Generate and hash candidates locally — no large data transfer.

    Receives only lightweight parameters:
      (prefix, charset, suffix_length, start_index, batch_size, target_hash_hex)

    Uses a reusable bytearray buffer to avoid per-candidate allocations.
    """
    prefix, charset, suffix_length, start_index, batch_size, target_hash_hex = args
    target_digest = bytes.fromhex(target_hash_hex)

    prefix_bytes = prefix.encode('utf-8')
    charset_bytes = charset.encode('utf-8')
    charset_len = len(charset_bytes)
    max_index = charset_len ** suffix_length

    # Pre-allocate a reusable buffer: [prefix | suffix]
    buf = bytearray(len(prefix_bytes) + suffix_length)
    buf[:len(prefix_bytes)] = prefix_bytes
    suffix_offset = len(prefix_bytes)

    for i in range(batch_size):
        if stop_signal.value:
            return None

        index = start_index + i
        if index >= max_index:
            break

        # Base-N decomposition directly into the buffer
        remaining = index
        for pos in range(suffix_length - 1, -1, -1):
            buf[suffix_offset + pos] = charset_bytes[remaining % charset_len]
            remaining //= charset_len

        if hashlib.sha1(buf).digest() == target_digest:
            stop_signal.value = True
            return buf.decode('utf-8')

    return None


# ─── GPU Worker ──────────────────────────────────────────────────────────

def gpu_worker(prefix: str, charset: str, suffix_length: int,
               start_index: int, batch_size: int,
               target_hash_hex: str) -> Optional[str]:
    """Launch the GPU kernel to generate + hash candidates entirely on-GPU.

    Only sends prefix (~10 B), charset (~36 B), and scalar parameters
    instead of the previous 40M × 64 B candidate array.
    """
    if stop_signal.value:
        return None

    kernel = get_sha1_kernel()

    # Small, constant-size GPU arrays (transferred once per batch)
    d_prefix  = cp.array(np.frombuffer(prefix.encode(), dtype=np.uint8))
    d_charset = cp.array(np.frombuffer(charset.encode(), dtype=np.uint8))
    d_target  = cp.array(np.frombuffer(bytes.fromhex(target_hash_hex), dtype='>u4'))
    d_result  = cp.full(1, -1, dtype=cp.int32)

    # Launch kernel
    threads_per_block = 256
    blocks_per_grid = (batch_size + threads_per_block - 1) // threads_per_block

    kernel(
        (blocks_per_grid,), (threads_per_block,),
        (
            d_prefix,
            np.int32(len(prefix)),
            d_charset,
            np.int32(len(charset)),
            np.int32(suffix_length),
            np.int64(start_index),
            np.int32(batch_size),
            d_target,
            d_result,
        ),
    )

    found_offset = d_result.get()[0]
    if found_offset != -1:
        return _reconstruct_password(
            prefix, charset, suffix_length, start_index + found_offset
        )

    return None
