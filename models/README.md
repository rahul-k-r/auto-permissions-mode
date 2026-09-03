# Local Models for Auto Permissions Mode

Place your downloaded GGUF model files in this directory (or anywhere on your machine and specify the path). All `.gguf` and `.bin` files inside this directory are automatically ignored by Git.

---

## Benchmarked Hardware Matrix & Downloads

| VRAM Tier | Model Selection | Model File (GGUF) | Drafter / Multimodal | Download Source | Key Strength |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **4GB** | **Gemma 4 E2B** | `gemma-4-E2B-it-UD-Q3_K_XL.gguf` (2.92 GB) | — | [Unsloth / Gemma-4-E2B-it-GGUF](https://huggingface.co/unsloth/gemma-4-E2B-it-GGUF) | Ultra-light edge; leaves >1GB for OS |
| **6GB** | **Gemma 4 E4B QAT** | `gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf` (4.22 GB) | `mtp-gemma-4-E4B-it.gguf` (59.7 MB) | [Unsloth / Gemma-4-E4B-it-GGUF](https://huggingface.co/unsloth/gemma-4-E4B-it-GGUF) | ⚡ <20ms gatekeeper latency via MTP speculative decoding |
| **8GB (Sweet Spot)** | **Qwen 3.5 9B** | `Qwen3.5-9B-UD-Q4_K_XL.gguf` (5.97 GB) | `mmproj-BF16.gguf` (922 MB) | [Unsloth / Qwen3.5-9B-GGUF](https://huggingface.co/unsloth/Qwen3.5-9B-GGUF) | 🏆 82.7% LiveCodeBench; full multimodal vision support |
| **12GB** | **Gemma 4 12B QAT** | `gemma-4-12B-it-qat-UD-Q4_K_XL.gguf` (6.72 GB) | `mtp-gemma-4-12B-it.gguf` (254 MB) | [Unsloth / Gemma-4-12B-it-GGUF](https://huggingface.co/unsloth/gemma-4-12B-it-GGUF) | Maximum threat reasoning on 12GB cards; zero false positives |
| **16GB** | **Gemma 4 26B A4B QAT** | `gemma-4-26B-A4B-it-qat-UD-Q4_K_XL.gguf` (~13.5 GB) | — | [Unsloth / Gemma-4-26B-A4B-GGUF](https://huggingface.co/unsloth/gemma-4-26B-A4B-it-GGUF) | Mixture-of-Experts (4B active speed with 26B intelligence) |
| **24GB+** | **Qwen 3.8 35B** or **Gemma 4 31B** | `Qwen3.8-35B-UD-Q4_K_XL.gguf` (~19.8 GB) | MTP Speculative | [Unsloth / Qwen3.8-35B-GGUF](https://huggingface.co/unsloth/Qwen3.8-35B-GGUF) | Enterprise flagship reasoning; massive codebase audits |

---

## Recommended Launch Commands (`llama.cpp`)

> [!TIP]
> **Never use legacy uncompressed FP16 KV cache.** Always specify `-ctk q4_0 -ctv q4_0` (or `q8_0`) and `--flash-attn on`. This compresses KV cache by 50%–75% with zero quality loss and doubles prompt evaluation speed.

### 1. Daily Driver: Qwen 3.5 9B (Multimodal + Multi-Agent Team)
Configured for **3 parallel agents** with **12,288 context tokens each** (`3 x 12288 = 36864` total tokens) using only ~650 MB of KV cache on dedicated port `9931`:
```powershell
llama serve -m "models/Qwen3.5-9B-UD-Q4_K_XL.gguf" `
  --mmproj "models/mmproj-BF16.gguf" `
  --port 9931 `
  -c 36864 `
  -ctk q4_0 -ctv q4_0 `
  -np 3 `
  -ngl 99 `
  --flash-attn on
```

#### Single Agent / Deep Context (32k Tokens, Single Slot):
```powershell
llama serve -m "models/Qwen3.5-9B-UD-Q4_K_XL.gguf" `
  --mmproj "models/mmproj-BF16.gguf" `
  --port 9931 `
  -c 32768 `
  -ctk q4_0 -ctv q4_0 `
  -np 1 `
  -ngl 99 `
  --flash-attn on
```

---

### 2. Ultra-Low Latency Gatekeeper: Gemma 4 E4B QAT (with MTP)
Uses Multi-Token Prediction (MTP) speculative decoding for <20ms gatekeeper decisions:
```powershell
llama serve -m "models/gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf" `
  -md "models/mtp-gemma-4-E4B-it.gguf" `
  -c 16384 `
  -ctk q4_0 -ctv q4_0 `
  -np 1 `
  -ngl 99 `
  --flash-attn on
```

---

### 3. Maximum Capability on 12GB: Gemma 4 12B QAT (with MTP)
```powershell
llama serve -m "models/gemma-4-12B-it-qat-UD-Q4_K_XL.gguf" `
  -md "models/mtp-gemma-4-12B-it.gguf" `
  -c 32768 `
  -ctk q4_0 -ctv q4_0 `
  -np 2 `
  -ngl 99 `
  --flash-attn on
```

---

### 4. Lightweight Edge: Gemma 4 E2B (4GB GPUs)
Leaves >1.0 GB VRAM headroom for Windows DWM and display server:
```powershell
llama serve -m "models/gemma-4-E2B-it-UD-Q3_K_XL.gguf" `
  -c 8192 `
  -ctk q4_0 -ctv q4_0 `
  -np 1 `
  -ngl 99 `
  --flash-attn on
```

---

### 5. Frontier MoE: Gemma 4 26B A4B QAT (16GB GPUs)
```powershell
llama serve -m "models/gemma-4-26B-A4B-it-qat-UD-Q4_K_XL.gguf" `
  -c 32768 `
  -ctk q4_0 -ctv q4_0 `
  -np 2 `
  -ngl 99 `
  --flash-attn on
```

---

## Flag Explanations

- **`-c` / `--ctx-size`**: Total context window allocated. When running multiple slots (`-np`), each slot receives `-c / -np` tokens.
- **`-np` / `--parallel`**: Number of parallel execution slots. Each slot keeps its own cached context so parallel agents never thrash or evict each other's memory.
- **`-ctk` / `--cache-type-k`**: Precision of the attention **Key** cache (`q4_0` or `q8_0`).
- **`-ctv` / `--cache-type-v`**: Precision of the attention **Value** cache (`q4_0` or `q8_0`).
- **`-ngl 99` / `--n-gpu-layers 99`**: Offloads all transformer layers directly to GPU VRAM.
- **`--flash-attn on`**: Enables Flash Attention (tiled SRAM attention), reducing memory footprint and doubling prompt evaluation speed.
- **`--mmproj`**: Loads the multimodal vision projector for processing images, screenshots, and visual artifacts.
- **`-md` / `--model-draft`**: Loads a speculative drafting model (like MTP) for speculative decoding speedups.
