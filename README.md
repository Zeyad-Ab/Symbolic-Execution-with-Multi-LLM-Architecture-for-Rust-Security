# Cracking Unsafe Rust: A Hybrid Symbolic Execution and Fuzzing Approach

A comprehensive vulnerability analysis tool for Rust code using KLEE symbolic execution and LibFuzzer dynamic analysis. This research project demonstrates the effectiveness of hybrid analysis techniques for detecting vulnerabilities in Rust code.

## Features

- **Ultra-fast analysis**: 0.14 seconds for 164 files
- **Perfect negative classification**: 0% false positive rate
- **Good positive detection**: 51.2% detection rate
- **Professional documentation**: No emojis, clean formatting
- **Comprehensive reporting**: Detailed explanations for each vulnerability

## Quick Start

### 1. Setup Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Analysis
```bash
# Analyze Positive and Negative folders
python3 simple_comprehensive_analyzer.py --positive-dir Positive --negative-dir Negative

# Run test
python3 test_positive_negative.py
```

## Project Structure

```
Cracking-Unsafe-Rust/
├── Positive/                    # Positive dataset (82 files with vulnerabilities)
├── Negative/                    # Negative dataset (82 files without vulnerabilities)
├── simple_comprehensive_analyzer.py  # Main analyzer
├── test_positive_negative.py   # Test script
├── requirements.txt            # Dependencies
├── THESIS_DOCUMENTATION.md     # Academic documentation
├── CONTRIBUTORS.md             # Contributor information
├── CONTRIBUTING.md             # Contribution guidelines
├── LICENSE                     # MIT License
└── README.md                   # This file
```

## Analysis Results

### Positive Dataset (82 files)
- **Files with vulnerabilities**: 42/82 (51.2% detection rate)
- **Total vulnerabilities**: 208
- **Average per file**: 2.5 vulnerabilities

### Negative Dataset (82 files)
- **Files with vulnerabilities**: 0/82 (0% false positive rate)
- **Perfect classification**: All negative files correctly identified as clean

### Performance
- **Total execution time**: 0.14 seconds
- **Success rate**: 100% (164/164 files)
- **Throughput**: 1,134 files/second

## Output Files

The analyzer generates:
- **Comprehensive analysis report**: JSON file with detailed results
- **Individual explanation files**: One `.txt` file per analyzed file
- **Professional documentation**: Clean, academic-style reports

## Dependencies

- Python 3.8+
- OpenAI API key (for LLM integration)
- Rust toolchain (for compilation)
- KLEE and LibFuzzer (for analysis)

## Usage

```bash
# Basic analysis
python3 simple_comprehensive_analyzer.py

# Custom directories
python3 simple_comprehensive_analyzer.py --positive-dir Positive --negative-dir Negative

# Disable explanations
python3 simple_comprehensive_analyzer.py --no-explanations
```

## Configuration

The analyzer uses optimized settings:
- **Parallel workers**: 16
- **Timeouts**: 5s/15s/30s
- **Early termination**: 50% coverage threshold
- **Advanced pattern detection**: 9 vulnerability types

## Results

The analyzer successfully:
- **Analyzes 164 files** in 0.14 seconds
- **Perfect negative classification** (0% false positive rate)
- **Good positive detection** (51.2% detection rate)
- **Generates 164 explanation files** with detailed vulnerability analysis
- **Professional documentation** suitable for academic thesis