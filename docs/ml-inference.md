# MAILTRACE AI — Machine Learning Inference Engine (Chunk 4/7)

## Overview

Chunk 4 integrates the **existing trained DistilBERT model (`dataset3_v1.0.0`)** for email content threat classification. The model was trained on the finalized Dataset 3 corpus to classify emails as `BENIGN` or `MALICIOUS`.

```
ParsedEmail (from Chunk 2)
    ↓
Preprocessing (ml/inference/preprocessing.py)
    → Subject + Body
    ↓
ModelLoader (ml/inference/loader.py)
    → dataset3_v1.0.0 (lazy loaded in memory)
    ↓
Classifier (ml/inference/classifier.py)
    → torch.no_grad() & model.eval()
    ↓
MlClassificationResult (label, confidence, probabilities)
```

---

## Strict Invariants

> [!IMPORTANT]
> **Existing Model Only**:
> - **DO NOT TRAIN A NEW MODEL.**
> - **DO NOT RETRAIN.**
> - **DO NOT MODIFY DATASET SPLITS.**
> - **DO NOT CHANGE MODEL WEIGHTS.**
> - **DO NOT ADD GROK.**
>
> The model `dataset3_v1.0.0` is already trained and finalized. Chunk 4 provides the production inference wrapper only.

> [!IMPORTANT]
> **Input Boundary: Subject + Body Only**:
> The model input is strictly **Subject + Body**.
> The model does **NOT** consume:
> - SPF, DKIM, or DMARC authentication results
> - IP reputation or connecting IP
> - GeoIP
> - URLs as separate forensic features
> - Campaign labels
> - Risk scores
>
> Risk fusion in later chunks will combine ML predictions with forensic and threat intelligence signals.

---

## 1. Input Preprocessing

The preprocessing module (`ml/inference/preprocessing.py`) prepares the input text:

```
Subject: <subject>

Body:
<body>
```

### Normalization Rules
1. **Subject**: Stripped of leading/trailing whitespace. If missing, formats as `Subject: `.
2. **Body**: Stripped of leading/trailing whitespace.
   - If `body_text` is present, it is used directly.
   - If `body_text` is missing or empty, HTML tags are stripped from `body_html` and entities unescaped.
   - If both are missing, formats as `Body:\n`.
3. **Truncation**: The tokenizer truncates inputs to `max_length=512` tokens per the DistilBERT architecture.

---

## 2. Model Loading (`ml/inference/loader.py`)

- **Lazy Loading**: Neither PyTorch nor Hugging Face model weights are loaded on package import. Loading occurs only when `load()` or `classify_email()` is called.
- **Local Files Only**: `local_files_only=True` ensures weights are loaded strictly from the local filesystem and never downloaded unexpectedly at runtime.
- **Device Management**: Uses CUDA GPU if available; otherwise falls back cleanly to CPU.
- **Evaluation Mode**: Calls `model.eval()` to disable dropout and ensure deterministic inference.
- **In-Memory Caching**: Caches the loaded model and tokenizer in memory to avoid repeated disk reads.

---

## 3. Classification & Output Schema

The classifier (`ml/inference/classifier.py`) runs inference under `torch.no_grad()`:

```python
from ml.inference import classify_email

result = classify_email(parsed_email)
print(result.label)         # 'BENIGN' or 'MALICIOUS'
print(result.confidence)    # 0.9852
print(result.probabilities) # {'BENIGN': 0.0148, 'MALICIOUS': 0.9852}
```

### `MlClassificationResult` Schema
- `label`: `BENIGN` or `MALICIOUS`.
- `confidence`: Probability of the predicted class (0.0 to 1.0).
- `probabilities`: Full probability distribution across both classes.
- `model_version`: Always `"dataset3_v1.0.0"`.
- `inference_metadata`: Operational metadata including execution device, latency in milliseconds, and input character/token length.

---

## 4. Local Model Setup & Git Exclusion

### Expected Model Directory
```
ml/models/dataset3_v1.0.0/
    config.json
    model.safetensors (or pytorch_model.bin)
    tokenizer.json
    tokenizer_config.json
    vocab.txt
```

### Git Handling
Model weights (`*.safetensors`, `*.bin`, `*.pt`, `*.onnx`) are strictly excluded from version control via `.gitignore`:
```gitignore
# ML model files (never commit model weights)
ml/models/*/model.safetensors
ml/models/**/*.safetensors
ml/models/**/*.bin
ml/models/**/*.pt
ml/models/**/*.onnx
```

### Configuration
The model path is configurable via:
- Environment variable: `ML_MODEL_PATH`
- Application settings: `Settings.ML_MODEL_PATH` in `backend/app/core/config.py` (default: `ml/models/dataset3_v1.0.0`)
- Explicit argument: `ModelLoader(model_path=...)`

---

## 5. Error Handling

- **`ModelNotFoundError`**: Raised when the model directory does not exist, or required files (`config.json`, weights) are missing. Never falls back to dummy/random predictions.
- **`ModelInputError`**: Raised when the input cannot be preprocessed.
- **`MlInferenceError`**: Raised when a runtime error occurs during tokenization or tensor computation.

---

## 6. Privacy & In-Memory Guarantee

- All inference tensors, tokenized inputs, and intermediate logits remain strictly in memory.
- No inputs or outputs are written to disk.
- `tempfile` is not imported.
