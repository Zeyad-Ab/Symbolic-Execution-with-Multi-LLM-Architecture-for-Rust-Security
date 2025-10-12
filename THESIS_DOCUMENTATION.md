# Cracking Unsafe Rust: A Hybrid Symbolic Execution and Fuzzing Approach with LLM

## Academic Documentation

**Author**: Zeyad Abdelrazek  
**Advisor**: Young Lee  
**Institution**: Texas A&M San Antonio  
**Research Title**: Cracking Unsafe Rust: A Hybrid Symbolic Execution and Fuzzing Approach with LLM  
**GitHub Repository**: https://github.com/Zeyad-Ab/Cracking-Unsafe-Rust-A-Hybrid-Symbolic-Execution-and-Fuzzing-Approach-with-LLM

## Abstract

This research presents a novel hybrid approach for vulnerability detection in Rust code by combining symbolic execution (KLEE) with dynamic fuzzing (LibFuzzer) and Large Language Model (LLM) assistance. The system achieves 67.1% detection rate with 100% precision on real-world vulnerability datasets, demonstrating the effectiveness of combining multiple analysis techniques for comprehensive security assessment.

## Research Contributions

1. **Hybrid Analysis Framework**: First system to combine KLEE symbolic execution with LibFuzzer fuzzing for Rust vulnerability detection
2. **LLM-Assisted Code Generation**: Automated generation of FFI wrappers and test harnesses using Large Language Models
3. **Comprehensive Evaluation**: Extensive testing on 164 real-world Rust files (82 vulnerable, 82 clean)
4. **Performance Optimization**: Achieved 200-300 files/second analysis throughput
5. **High Precision Detection**: 100% precision with 67.1% recall on vulnerability datasets

## Methodology

### 1. Code Preprocessing
- **FFI Conversion**: Automatic conversion of Rust code to C-compatible FFI functions
- **LLM Integration**: GPT-3.5-turbo for intelligent code transformation
- **Wrapper Generation**: Automated creation of KLEE and LibFuzzer harnesses

### 2. Symbolic Execution (KLEE)
- **Path Exploration**: Systematic exploration of all possible execution paths
- **Constraint Solving**: Z3 SMT solver for path feasibility analysis
- **Error Detection**: Identification of buffer overflows, null pointer dereferences, and memory safety violations

### 3. Dynamic Fuzzing (LibFuzzer)
- **Input Generation**: Automated generation of test inputs
- **Crash Detection**: Identification of runtime crashes and exceptions
- **Coverage Analysis**: Code coverage-guided fuzzing for comprehensive testing

### 4. Result Fusion
- **Multi-Tool Integration**: Combining results from both analysis techniques
- **Confidence Scoring**: Weighted scoring based on vulnerability type and detection method
- **False Positive Reduction**: Cross-validation between symbolic execution and fuzzing results

## Experimental Results

### Dataset
- **Positive Dataset**: 82 real-world vulnerable Rust files from CVE database
  - **Source**: Authentic security vulnerabilities from CVE database
  - **Content**: Buffer overflows, use-after-free, memory leaks, integer overflows, race conditions
  - **Format**: Rust source files (.rs) with detailed vulnerability analysis (.txt)
  - **Purpose**: Test vulnerability detection capabilities and recall rates

- **Negative Dataset**: 82 clean Rust files with no known vulnerabilities
  - **Source**: Well-written, secure Rust code examples
  - **Content**: Best practices, safe Rust patterns, proper error handling
  - **Format**: Rust source files (.rs) with corresponding analysis files (.txt)
  - **Purpose**: Test false positive rates and precision

- **Total Files**: 164 Rust files for comprehensive evaluation
- **Evaluation Coverage**: Complete vulnerability spectrum from critical to low-severity issues

### Performance Metrics
- **Detection Rate**: 67.1% (55/82 vulnerable files detected)
- **Precision**: 100% (no false positives)
- **Specificity**: 100% (all clean files correctly identified)
- **Accuracy**: 83.5% overall performance
- **F1 Score**: 80.4% balanced performance

### Analysis Performance
- **Throughput**: 200-300 files/second
- **Analysis Time**: 0.48 seconds for 164 files
- **Success Rate**: 100% (all files processed successfully)

## Technical Implementation

### Core Components
1. **Single File Analyzer** (`onefile.py`): Individual Rust file analysis
2. **Batch Analyzer** (`allrust.py`): Folder-wide analysis with parallel processing
3. **Dataset Evaluator** (`evaluate_datasets.py`): Comprehensive evaluation framework
4. **LLM Integration**: OpenAI GPT-3.5-turbo for code transformation

### Dependencies
- **Rust Compiler**: LLVM bitcode generation
- **KLEE**: Symbolic execution engine
- **LibFuzzer**: Dynamic fuzzing framework
- **Python 3.6+**: Analysis framework
- **OpenAI API**: LLM-based code generation

## Usage Examples

### Single File Analysis
```bash
python3 onefile.py example.rs
```

### Batch Analysis
```bash
python3 allrust.py ./rust_code/
```

### Dataset Evaluation
```bash
python3 evaluate_datasets.py
```

## Future Work

1. **Enhanced LLM Integration**: Integration with more advanced language models
2. **Pattern Learning**: Machine learning-based vulnerability pattern recognition
3. **Scalability Improvements**: Distributed analysis for large codebases
4. **Additional Languages**: Extension to other systems programming languages
5. **Real-time Integration**: CI/CD pipeline integration for continuous security assessment

## Citation

```bibtex
@thesis{abdelrazek2024cracking,
  title={Cracking Unsafe Rust: A Hybrid Symbolic Execution and Fuzzing Approach with LLM},
  author={Abdelrazek, Zeyad},
  year={2024},
  school={Texas A\&M San Antonio},
  advisor={Lee, Young},
  url={https://github.com/Zeyad-Ab/Cracking-Unsafe-Rust-A-Hybrid-Symbolic-Execution-and-Fuzzing-Approach-with-LLM}
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

**Author**: Zeyad Abdelrazek  
**Email**: zgad01@jaguar.tamu.edu  
**Institution**: Texas A&M San Antonio  
**Advisor**: Young Lee  
**GitHub**: https://github.com/Zeyad-Ab/Cracking-Unsafe-Rust-A-Hybrid-Symbolic-Execution-and-Fuzzing-Approach-with-LLM
