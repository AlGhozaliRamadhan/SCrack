# SCrack

Version 2.1

SHA-1 partial password recovery tool with CPU multiprocessing and CUDA acceleration through CuPy.

SCrack takes a SHA-1 hash and a known password prefix, then brute-forces candidate suffixes using prioritized attack vectors.

## Features

- SHA-1 suffix brute force from a known prefix
- CUDA GPU acceleration with a custom CuPy kernel
- Multi-GPU scheduling when multiple CUDA devices are visible
- CPU multiprocessing fallback
- Prioritized attack vectors by suffix length, charset, and search cost
- Live progress, rate, and ETA reporting

## Requirements

- Python 3.8+
- Optional for GPU: NVIDIA CUDA runtime and `cupy-cuda12x`

CPU mode works without CuPy. GPU mode requires a CUDA-compatible NVIDIA GPU.

## Install

```bash
git clone https://github.com/AlGhozaliRamadhan/SCrack.git
cd SCrack
python -m venv .venv
```

GPU install on Windows:

```bash
.venv\Scripts\activate
pip install -r requirements.txt
```

Linux/macOS:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

CPU-only mode has no third-party runtime dependency:

```bash
python main.py --sha <SHA1_HASH> --pw <KNOWN_PREFIX>
```

## Usage

```bash
python main.py --sha <SHA1_HASH> --pw <KNOWN_PREFIX>
```

Example:

```bash
python main.py --sha 40b25eac438260c9ad4e3142adc38a8d0885e5f3 --pw a
```

Expected result:

```text
Recovered Plaintext: a0
Analysis Status: SUCCESS
```

Arguments:

| Flag | Required | Description |
|---|---:|---|
| `--sha` | yes | 40-character SHA-1 hash |
| `--pw` | yes | Known password prefix |

## Multi-GPU

SCrack automatically uses every CUDA GPU visible to CuPy. Each GPU receives separate candidate batches.

Limit GPUs with `CUDA_VISIBLE_DEVICES`:

```bash
CUDA_VISIBLE_DEVICES=0,1 python main.py --sha <SHA1_HASH> --pw <KNOWN_PREFIX>
```

On Windows PowerShell:

```powershell
$env:CUDA_VISIBLE_DEVICES="0,1"
python main.py --sha <SHA1_HASH> --pw <KNOWN_PREFIX>
```

Notes:

- Multi-GPU speedup depends on GPU model, batch size, driver overhead, and search space size.
- The current CUDA kernel supports candidates up to 55 bytes. Longer candidates automatically fall back to CPU.
- `GPU_BATCH_SIZE` in `module/config.py` is applied per GPU batch.

## Kaggle

1. Create a notebook.
2. Enable GPU in notebook settings.
3. Use a GPU accelerator. Multi-GPU runs only when Kaggle exposes more than one CUDA device to the notebook.
4. Run:

```python
!git clone https://github.com/AlGhozaliRamadhan/SCrack.git
%cd SCrack
!pip install -q cupy-cuda12x numpy
!python main.py --sha 40b25eac438260c9ad4e3142adc38a8d0885e5f3 --pw a
```

Check visible GPUs:

```python
!nvidia-smi
```

## Google Colab

1. Open Runtime > Change runtime type.
2. Select a GPU runtime.
3. Run:

```python
!git clone https://github.com/AlGhozaliRamadhan/SCrack.git
%cd SCrack
!pip install -q cupy-cuda12x numpy
!python main.py --sha 40b25eac438260c9ad4e3142adc38a8d0885e5f3 --pw a
```

Check the assigned GPU:

```python
!nvidia-smi
```

Colab usually provides one GPU. If more than one CUDA device is visible, SCrack will use all visible devices automatically.

## Configuration

Tune performance constants in `module/config.py`:

```python
MAX_SEARCH_SPACE = 100_000_000_000
CPU_BATCH_SIZE = 100_000
GPU_BATCH_SIZE = 40_000_000
NUM_CPU_WORKERS = mp.cpu_count()
```

Edit attack vectors in `module/attacks.py`.

## Safety

Use this tool only for hashes you own or have explicit authorization to test.

## License

MIT License. See `LICENSE`.
