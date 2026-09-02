# Local Models for Auto Permissions Mode

Place your downloaded GGUF model files in this directory. All `.gguf` and `.bin` files are ignored by git.

## Recommended Launch Commands (llama.cpp)

### 4GB Tier (Gemma 4 E2B)
```powershell
llama serve -m "models/gemma-4-E2B-it-UD-Q3_K_XL.gguf" -c 8192 -ngl 99 --flash-attn on
```

### 6GB Tier (Gemma 4 E4B QAT with MTP)
```powershell
llama serve -m "models/gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf" -md "models/mtp-gemma-4-E4B-it.gguf" -c 8192 -ngl 99 --flash-attn on
```

### 8GB Tier (Qwen 3.5 9B - Daily Driver)
```powershell
llama serve -m "models/Qwen3.5-9B-UD-Q4_K_XL.gguf" -c 8192 -ngl 99 --flash-attn on
```

### 12GB Tier (Gemma 4 12B QAT with MTP)
```powershell
llama serve -m "models/gemma-4-12B-it-qat-UD-Q4_K_XL.gguf" -md "models/mtp-gemma-4-12B-it.gguf" -c 8192 -ngl 99 --flash-attn on
```

### 16GB Tier (Gemma 4 26B A4B MoE)
```powershell
llama serve -m "models/gemma-4-26B-A4B-it-qat-UD-Q4_K_XL.gguf" -c 8192 -ngl 99 --flash-attn on
```

### 24GB+ Tier (Qwen 3.8 35B / Gemma 4 31B)
```powershell
llama serve -m "models/Qwen3.8-35B-UD-Q4_K_XL.gguf" -c 8192 -ngl 99 --flash-attn on
```
