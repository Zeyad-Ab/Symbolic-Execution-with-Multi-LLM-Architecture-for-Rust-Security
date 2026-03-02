# Symbolic Execution with Multi-LLM Architecture for Rust Security

This repository contains the dataset and analyzers for replicating experiments on memory vulnerability detection in Rust using a 4-agent multi-LLM pipeline and KLEE symbolic execution.

## Repository Structure

```
Positive/                             # Dataset: Rust CVE snippet files (.rs)
core_analyzer_4agent_multimodel.py    # 4-agent pipeline (Oracle, Safety Checker, Code Specialist, Fast Filter)
core_analyzer_working_fixed.py        # Single-agent baseline (one LLM per run)
run_memory_datasets.py                # Run 4-agent on all Positive files
test_all_models.py                   # Run single-agent with each of 7 LLM models
requirements.txt
```

## Requirements

- Python 3.9+
- Rust toolchain (rustc)
- LLVM and Clang (e.g. LLVM 16)
- KLEE symbolic execution engine (e.g. 3.x)
- API keys: OpenAI, Anthropic, Google (for single-agent baselines)

## Setup

1. Clone the repository.

2. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the project root with your API keys (do not commit this file):
   ```
   OPENAI_API_KEY=your_openai_key
   ANTHROPIC_API_KEY=your_anthropic_key
   GEMINI_API_KEY=your_google_key
   ```

4. Ensure KLEE, LLVM, and Rust are installed and on your PATH. The scripts expect `rustc`, `clang`, `llvm-link`, and `klee` to be available. Paths to KLEE include and LLVM tools can be adjusted inside the analyzer files if needed.

## Replicating Experiments

### 4-agent pipeline (main approach)

Run the full dataset through the 4-agent analyzer:

```
python run_memory_datasets.py
```

Outputs are written under `4agent_output/`. The script processes all `.rs` files in `Positive/`.

### Single-agent baselines (7 models)

Run each of the 7 LLM models on the same dataset:

```
python test_all_models.py
```

Outputs are written under `{model_name}_output/` (e.g. `gpt4-turbo_output/`, `claude-sonnet_output/`).

### Single file (4-agent)

```python
from core_analyzer_4agent_multimodel import CoreAnalyzer4AgentMultiModel

analyzer = CoreAnalyzer4AgentMultiModel()
result = analyzer.analyze_single_file_4agent("Positive/CVE-2020-35904_CWE-131.rs", "positive")
```

### Single file (single-agent)

```python
from core_analyzer_working_fixed import CoreAnalyzerWorking

analyzer = CoreAnalyzerWorking(model_name="gpt4o-mini")
result = analyzer.analyze_single_file_working("Positive/CVE-2020-35904_CWE-131.rs", "positive")
```

## Dataset

`Positive/` contains Rust CVE files. Each file is an incomplete CVE code snippet (missing imports, type definitions, or context). The analyzers use LLMs to generate compilable FFI wrappers and then run KLEE to detect memory violations.

## Output Layout

- **4-agent:** `4agent_output/positive/` with `ffi/`, `wrappers/`, and `klee_output/` subdirs.
- **Single-agent:** `{model_name}_output/positive/` with the same structure.

KLEE produces `.ptr.err`, `.external.err`, and related files; the scripts aggregate these into vulnerability counts.

## License

See LICENSE file if present.
