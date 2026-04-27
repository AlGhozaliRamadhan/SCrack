"""
GPU detection and CUDA SHA-1 kernel management.

On import, this module probes for CuPy + a compatible CUDA GPU.
The CUDA kernel generates candidates AND hashes them entirely on-GPU,
eliminating the CPU→GPU data transfer bottleneck.
"""

# ─── GPU Capability Detection ───────────────────────────────────────────
GPU_AVAILABLE = False
GPU_NAME = None

try:
    import cupy as cp

    if cp.cuda.runtime.getDeviceCount() > 0:
        GPU_AVAILABLE = True
        GPU_NAME = "CuPy"
        print("GPU acceleration enabled (CuPy)")
    else:
        print("CuPy found, but no compatible GPU detected - using CPU with multiprocessing")
except ImportError:
    print("CuPy not found - GPU acceleration not available - using CPU with multiprocessing")


# ─── CUDA SHA-1 Kernel Source ────────────────────────────────────────────
# V2: Each thread generates its OWN candidate from a global index,
# then hashes and compares it.  No candidate data is transferred
# from the CPU — only prefix, charset, and numeric parameters.

SHA1_KERNEL_SOURCE = r'''
extern "C" {

    __device__ unsigned int rotl(unsigned int value, unsigned int shift) {
        return (value << shift) | (value >> (32 - shift));
    }

    __device__ void sha1_transform(unsigned int state[5],
                                   const unsigned char block[64]) {
        unsigned int w[80];

        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i*4] << 24) | (block[i*4+1] << 16)
                 | (block[i*4+2] << 8) | block[i*4+3];
        }

        for (int i = 16; i < 80; ++i) {
            w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }

        unsigned int a = state[0], b = state[1], c = state[2],
                     d = state[3], e = state[4];

        for (int i = 0; i < 80; ++i) {
            unsigned int f, k;
            if      (i < 20) { f = (b & c) | ((~b) & d);         k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8F1BBCDC; }
            else              { f = b ^ c ^ d;                    k = 0xCA62C1D6; }

            unsigned int temp = rotl(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl(b, 30); b = a; a = temp;
        }

        state[0] += a; state[1] += b; state[2] += c;
        state[3] += d; state[4] += e;
    }

    // V2 kernel: generates candidates on-GPU from index parameters.
    // No bulk candidate transfer from CPU required.
    __global__ void sha1_crack_kernel(
        const unsigned char* prefix,       // known password prefix
        int                  prefix_len,   // length of prefix
        const unsigned char* charset,      // character set for suffix
        int                  charset_len,  // length of charset
        int                  suffix_len,   // number of suffix characters
        long long            start_index,  // global start index for this batch
        int                  num_candidates,
        const unsigned int*  target_hash,  // target SHA-1 (5 x uint32)
        int*                 result_index  // output: thread index of match (-1)
    ) {
        int idx = blockIdx.x * blockDim.x + threadIdx.x;
        if (idx >= num_candidates || result_index[0] != -1) return;

        long long candidate_index = start_index + (long long)idx;

        // ── Build candidate password in a local buffer ──────────────
        unsigned char block[64];
        int msg_len = prefix_len + suffix_len;

        // Copy prefix
        for (int i = 0; i < prefix_len; ++i)
            block[i] = prefix[i];

        // Generate suffix via base-N decomposition of candidate_index
        long long temp = candidate_index;
        for (int i = suffix_len - 1; i >= 0; --i) {
            block[prefix_len + i] = charset[(int)(temp % charset_len)];
            temp /= charset_len;
        }

        // ── SHA-1 single-block padding ──────────────────────────────
        block[msg_len] = 0x80;
        for (int i = msg_len + 1; i < 56; ++i) block[i] = 0;

        unsigned long long bit_len = (unsigned long long)msg_len * 8;
        for (int i = 0; i < 8; ++i)
            block[63 - i] = (bit_len >> (i * 8)) & 0xFF;

        // ── Hash and compare ────────────────────────────────────────
        unsigned int state[5] = {
            0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
        };
        sha1_transform(state, block);

        if (state[0] == target_hash[0] && state[1] == target_hash[1] &&
            state[2] == target_hash[2] && state[3] == target_hash[3] &&
            state[4] == target_hash[4]) {
            atomicExch(&result_index[0], idx);
        }
    }
}
'''


# ─── Kernel Cache ────────────────────────────────────────────────────────
_compiled_kernel = None


def get_sha1_kernel():
    """Compile and cache the CUDA SHA-1 kernel (one-time cost)."""
    global _compiled_kernel
    if _compiled_kernel is None:
        print("Compiling CUDA kernel for GPU... (this happens only once)")
        _compiled_kernel = cp.RawKernel(SHA1_KERNEL_SOURCE, 'sha1_crack_kernel')
        print("Kernel compiled successfully.")
    return _compiled_kernel
