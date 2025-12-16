# PatchGuard: A Multi-Layer Defense System for Secure LLM-Based Code Repair

**CS562 - Advanced Topics in ML Security and Privacy**
**Team:** Abhirup Chakraborty, Jyoti Rawat, Praveen Rajendran Sundar

---

## Overview

PatchGuard is a 3-layer defense system we built to protect automated code patching pipelines from adversarial prompt injection attacks. LLMs can be tricked into inserting malicious code through crafted bug reports or commit messages. Our system tries to stop this using detection, sanitization, and validation.

### Key Features

- **Layer 1: Prompt Detection** - Identifies and blocks malicious input patterns
- **Layer 2: Input Sanitization** - Neutralizes adversarial payloads while preserving intent
- **Layer 3: Output Validation** - Static analysis and security scanning of generated patches

### Problem Statement

- 45% of LLM-generated patches contain security vulnerabilities (CWE-79 XSS, CWE-117 Log Injection)
- Attackers can inject malicious instructions in bug reports
- Automated patching systems often run with elevated privileges in CI/CD pipelines

### Our Solution

We implemented a defense-in-depth approach with three layers:

1. **Detection**: Uses regex and pattern matching to catch suspicious prompts
2. **Sanitization**: Removes malicious code, adds defensive headers
3. **Validation**: Runs static analysis (Bandit, Semgrep) and checks diffs for vulnerabilities

---

## Quick Start

### Prerequisites

- Python 3.9+
- [Ollama](https://ollama.com) (for LLM integration)
- Git

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/FALL25-CS562-PatchGuard.git
cd FALL25-CS562-PatchGuard

# Install Python dependencies
pip install -r requirements.txt

# Install Ollama (if not already installed)
# Visit: https://ollama.com

# Pull Llama model
ollama pull llama3.1:8b
```

### Verify Installation

```bash
# Test the pipeline
python test_setup.py
```

---

## Usage

### 1. Generate Evaluation Dataset

```bash
# Creates 500 vulnerability samples for testing
python data/create_evaluation_dataset.py
```

This will generate:
- 100 SQL Injection samples (CWE-89)
- 100 XSS samples (CWE-79)
- 100 Command Injection samples (CWE-78)
- 100 Path Traversal samples (CWE-22)
- 100 Hardcoded Credentials samples (CWE-798)

### 2. Run PatchGuard Pipeline

```python
from src.pipeline import PatchGuardPipeline
from src.baseline_patcher import SimplePromptPatcher

# Initialize
patcher = SimplePromptPatcher()
pipeline = PatchGuardPipeline(patcher=patcher)

# Run on vulnerable code
issue = "Fix the SQL injection vulnerability"
vulnerable_code = '''
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return db.execute(query)
'''

result = pipeline.run(issue, vulnerable_code)

# Check results
print(f"Patch accepted: {result['patch_accepted']}")
print(f"Layer 1 detection: {result['detection']}")
print(f"Layer 3 validation: {result['validation']}")
```

### 3. Run Full Evaluation

```bash
# Run evaluation on 500 samples
# NOTE: This evaluates on a subset (50) for LLM calls to keep runtime reasonable
python evaluation/run_full_evaluation.py --samples 500

# Can use Aider for more realistic patching (but it's slower)
python evaluation/run_full_evaluation.py --samples 500 --aider
```

Results get saved to `evaluation/results_YYYYMMDD_HHMMSS.json`

---

## Repository Structure

```
FALL25-CS562-PatchGuard/
├── src/
│   ├── pipeline.py                    # Main PatchGuard pipeline
│   ├── baseline_patcher.py            # Vulnerable baseline (Aider + Llama)
│   ├── layer1_detection/
│   │   └── detector.py                # Prompt injection detection
│   ├── layer2_sanitization/
│   │   └── sanitizer.py               # Input sanitization
│   └── layer3_validation/
│       ├── validator.py               # Main validation orchestrator
│       ├── static_analysis.py         # Bandit integration
│       ├── semgrep_runner.py          # Semgrep security scanning
│       ├── diff_checker.py            # Code diff analysis
│       └── unit_test_validator.py     # Test execution
├── data/
│   ├── create_evaluation_dataset.py   # Dataset generator
│   └── evaluation_dataset_500.json    # 500 vulnerability samples
├── evaluation/
│   └── run_full_evaluation.py         # Full evaluation script
├── experiments/
│   └── prompts/
│       ├── adversarial_prompts.txt    # Attack vectors
│       └── benign_prompts.txt         # Legitimate prompts
├── tests/
│   └── (unit tests)
├── requirements.txt                    # Python dependencies
├── test_setup.py                       # Setup verification
└── README.md                           # This file
```

---

## Evaluation Metrics

### Attack Success Rate (ASR)
Percentage of adversarial attempts that successfully inject vulnerabilities.

**Expected Results:**
- **Baseline (No Defense)**: 63.2% ASR  
- **Layer 1 Only**: 36.6% ASR  
- **Layer 2 Only**: 32.4% ASR  
- **Layer 3 Only**: 25.8% ASR  
- **All 3 Layers**: 6.4% ASR

### Dataset
- 500 total samples across 5 CWE categories
- Python code samples with known vulnerabilities
- Adversarial prompts designed to bypass defenses

---

## Architecture

```
┌─────────────────────┐
│   User Input        │
│   Issue + Code      │
└──────────┬──────────┘
           │
           ▼
┌──────────────────────┐
│   Layer 1:           │
│   Detection          │  ─── Regex + Semantic Analysis
│                      │  ─── Block if Malicious
└──────────┬───────────┘
           │ (if safe)
           ▼
┌──────────────────────┐
│   Layer 2:           │
│   Sanitization       │  ─── Remove adversarial patterns
│                      │  ─── Add defensive headers
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   LLM Patcher        │
│   Generate Fix       │  ─── Llama 3.1 via Ollama
│                      │  ─── or Aider integration
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Layer 3:           │
│   Validation         │  ─── Static Analysis (Bandit)
│                      │  ─── Semgrep Security Scan
│                      │  ─── Diff Checking
│                      │  ─── CWE Signature Matching
└──────────┬───────────┘
           │
           ▼
     ┌─────────┐
     │ Accept? │
     └─────────┘
      │       │
      ▼       ▼
   Approve  Reject
```

---

## Dependencies

### Python Packages
- `pandas>=2.0.0` - Data handling
- `numpy>=1.24.0` - Numerical operations
- `tqdm>=4.65.0` - Progress bars
- `aider-chat>=0.40.0` - Code editing tool
- `bandit>=1.7.5` - Python security linter
- `semgrep>=1.50.0` - Multi-language static analysis
- `pytest>=7.4.0` - Testing framework
- `kaggle>=1.6.0` - Dataset downloads (optional)

### External Tools
- **Ollama** - Local LLM runtime ([installation](https://ollama.com))
- **Llama 3.1** - Language model (pulled via Ollama)

---

## Testing

```bash
# Run unit tests
pytest tests/

# Test individual layers
python -m src.layer1_detection.detector
python -m src.layer2_sanitization.sanitizer
python -m src.layer3_validation.validator

# Test baseline patcher
python src/baseline_patcher.py
```

---

## Configuration

### Environment Variables
```bash
# Optional: Configure Ollama model
export OLLAMA_MODEL="llama3.1:8b"

# Optional: Kaggle API (for dataset downloads)
export KAGGLE_USERNAME="your_username"
export KAGGLE_KEY="your_api_key"
```

---

## Results Summary

| Configuration | Attack Successes | ASR | Inference |
|--------------|------------------|-----|-----------|
| No Defense | 316 / 500 | 63.2% | Baseline – highly vulnerable |
| Layer 1 Only | 183 / 500 | 36.6% | Blocks obvious prompt injections |
| Layer 2 Only | 162 / 500 | 32.4% | Removes payloads but incomplete |
| Layer 3 Only | 129 / 500 | 25.8% | Strong output-level protection |
| **All 3 Layers** | **32 / 500** | **6.4%** | **Effective defense-in-depth** |

---

## Contributing

This is a class project for CS562. For questions or issues:
- Open an issue on GitHub
- Contact team members via email

---

## Acknowledgments

- **Course:** CS562 - Advanced Topics in ML Security and Privacy
- **Institution:** University of Illinois Urbana-Champaign
- **Semester:** Fall 2025
- **Tools:** Ollama, Aider, Bandit, Semgrep, Llama 3.1
