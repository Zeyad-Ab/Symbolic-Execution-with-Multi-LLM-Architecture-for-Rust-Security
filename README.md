# Cracking Unsafe Rust: A Hybrid Symbolic Execution and Fuzzing Approach

A comprehensive vulnerability analysis tool for Rust code using KLEE symbolic execution and LibFuzzer dynamic analysis.

## Features

- **Single File Analysis**: Analyze individual Rust files for vulnerabilities
- **Batch Analysis**: Process entire folders of Rust code
- **Hybrid Approach**: Combines KLEE symbolic execution with LibFuzzer fuzzing
- **Dataset Evaluation**: Test on Positive and Negative vulnerability datasets
- **Comprehensive Reporting**: Detailed vulnerability reports with metrics

## Project Structure

```
PROJECT ZOBRE/
├── onefile.py              # Single file analyzer
├── allrust.py              # Folder analyzer
├── evaluate_datasets.py    # Dataset evaluation script
├── config.yaml             # Configuration file
├── requirements.txt        # Python dependencies
├── setup.py               # Project setup script
├── env.template           # Environment variables template
├── LICENSE                # MIT License
├── Positive/              # Vulnerable Rust files (82 files)
├── Negative/              # Clean Rust files (82 files)
└── README.md              # This file
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd PROJECT-ZOBRE
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Setup environment**:
   ```bash
   cp env.template .env
   # Edit .env with your API keys
   ```

## Usage

### Single File Analysis
```bash
python3 onefile.py example.rs
```

### Folder Analysis
```bash
python3 allrust.py ./rust_code/
```

### Dataset Evaluation
```bash
python3 evaluate_datasets.py
```

## Results

The tools generate comprehensive reports including:
- **Vulnerability Detection**: KLEE errors and fuzzing crashes
- **Performance Metrics**: Analysis time and throughput
- **Confusion Matrix**: TP, TN, FP, FN metrics
- **Quality Assessment**: Accuracy, precision, recall, specificity

## Requirements

- **Rust Compiler** (`rustc`)
- **KLEE** symbolic execution engine
- **LibFuzzer** (via `cargo fuzz`)
- **Python 3.6+**
- **OpenAI API Key** (for LLM-based code generation)

## Performance

- **Analysis Speed**: 200-300 files/second
- **Detection Rate**: 67.1% on vulnerability datasets
- **Accuracy**: 83.5% overall performance
- **Precision**: 100% (no false positives)
- **Recall**: 67.1% (good vulnerability detection)

## Use Cases

- **Security Auditing**: Identify vulnerabilities in Rust codebases
- **Research**: Academic research on vulnerability detection
- **CI/CD Integration**: Automated security testing in pipelines
- **Code Review**: Assist developers in finding security issues

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For questions or issues, please open an issue on GitHub.

---

**Author**: Zeyad Abdelrazek  
**Advisor**: Young Lee  
**Institution**: Texas A&M San Antonio  
**Research**: Cracking Unsafe Rust: A Hybrid Symbolic Execution and Fuzzing Approach
