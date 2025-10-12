# Contributing to Cracking Unsafe Rust

Thank you for your interest in contributing to the Cracking Unsafe Rust project! This document provides guidelines for contributing to this academic research project.

## Academic Context

This project is part of academic research conducted at Texas A&M San Antonio. All contributions should align with the research objectives and maintain the academic integrity of the work.

## How to Contribute

### 1. Fork the Repository
```bash
git clone https://github.com/Zeyad-Ab/Cracking-Unsafe-Rust-A-Hybrid-Symbolic-Execution-and-Fuzzing-Approach-with-LLM.git
cd Cracking-Unsafe-Rust-A-Hybrid-Symbolic-Execution-and-Fuzzing-Approach-with-LLM
```

### 2. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 3. Make Your Changes
- Follow the existing code style and conventions
- Add appropriate tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 4. Submit a Pull Request
- Provide a clear description of your changes
- Reference any related issues
- Ensure your code follows the project guidelines

## Contribution Guidelines

### Code Style
- Use Python 3.6+ syntax
- Follow PEP 8 style guidelines
- Add type hints where appropriate
- Include docstrings for functions and classes

### Testing
- Add tests for new functionality
- Ensure existing tests continue to pass
- Test with both Positive and Negative datasets
- Verify performance metrics are maintained

### Documentation
- Update README.md for significant changes
- Add docstrings to new functions
- Update THESIS_DOCUMENTATION.md for research-related changes
- Maintain academic citation standards

## Research Contributions

### Academic Contributions
- **Methodology Improvements**: Enhance the hybrid analysis approach
- **Performance Optimizations**: Improve analysis speed and accuracy
- **New Vulnerability Types**: Add detection for additional vulnerability patterns
- **Evaluation Metrics**: Improve evaluation and reporting capabilities

### Technical Contributions
- **Bug Fixes**: Fix issues in the analysis pipeline
- **Feature Enhancements**: Add new analysis capabilities
- **Documentation**: Improve project documentation
- **Testing**: Add comprehensive test cases

## Areas for Contribution

### High Priority
1. **Performance Optimization**: Improve analysis speed and memory usage
2. **Accuracy Enhancement**: Reduce false positives and false negatives
3. **Pattern Recognition**: Add detection for new vulnerability types
4. **LLM Integration**: Improve LLM-based code generation

### Medium Priority
1. **User Interface**: Add command-line interface improvements
2. **Configuration**: Enhance configuration options
3. **Reporting**: Improve result reporting and visualization
4. **Documentation**: Expand academic documentation

### Low Priority
1. **Code Refactoring**: Improve code organization and maintainability
2. **Testing**: Add more comprehensive test coverage
3. **Examples**: Add more usage examples and tutorials
4. **Localization**: Add support for multiple languages

## Academic Guidelines

### Research Integrity
- Maintain academic honesty and integrity
- Properly cite all sources and references
- Follow ethical guidelines for research
- Respect intellectual property rights

### Citation Requirements
- Cite all external libraries and tools used
- Acknowledge contributions from other researchers
- Follow academic citation standards
- Maintain proper attribution

### Documentation Standards
- Use clear, academic writing style
- Provide comprehensive documentation
- Include methodology descriptions
- Document experimental results

## Development Setup

### Prerequisites
- Python 3.6+
- Rust compiler
- KLEE symbolic execution engine
- LibFuzzer (via cargo fuzz)
- OpenAI API key (for LLM features)

### Installation
```bash
# Clone the repository
git clone https://github.com/Zeyad-Ab/Cracking-Unsafe-Rust-A-Hybrid-Symbolic-Execution-and-Fuzzing-Approach-with-LLM.git

# Install dependencies
pip install -r requirements.txt

# Run setup
python3 setup.py

# Test installation
python3 test_setup.py
```

### Testing
```bash
# Test single file analysis
python3 onefile.py example.rs

# Test folder analysis
python3 allrust.py ./rust_code/

# Test dataset evaluation
python3 evaluate_datasets.py
```

## Issue Reporting

### Bug Reports
- Use the GitHub issue tracker
- Provide detailed reproduction steps
- Include system information and error messages
- Attach relevant log files

### Feature Requests
- Describe the proposed feature clearly
- Explain the academic or practical benefit
- Provide implementation suggestions if possible
- Consider the research objectives

### Academic Questions
- Use the GitHub discussions feature
- Tag issues with "academic" label
- Provide context about your research interests
- Include relevant academic background

## Code Review Process

### Review Criteria
- **Functionality**: Does the code work as intended?
- **Performance**: Does it maintain or improve performance?
- **Academic Value**: Does it contribute to the research objectives?
- **Documentation**: Is the code well-documented?
- **Testing**: Are there appropriate tests?

### Review Timeline
- Initial review within 1 week
- Follow-up reviews as needed
- Final decision within 2 weeks
- Academic review for research-related changes

## License and Copyright

### Code Contributions
- All code contributions are subject to the MIT License
- Contributors retain copyright to their contributions
- Academic use is encouraged and supported

### Academic Use
- Research use is permitted and encouraged
- Proper citation is required
- Academic integrity must be maintained
- Commercial use requires separate agreement

## Contact Information

### Primary Contact
- **Name**: Zeyad Abdelrazek
- **Institution**: Texas A&M San Antonio
- **GitHub**: @Zeyad-Ab
- **Email**: zgad01@jaguar.tamu.edu

### Academic Advisor
- **Name**: Young Lee
- **Institution**: Texas A&M San Antonio
- **Role**: Academic Supervisor

## Recognition

### Contributor Recognition
- Contributors will be acknowledged in CONTRIBUTORS.md
- Significant contributions will be cited in academic publications
- GitHub contributors will be automatically recognized
- Academic collaborators will be properly credited

### Academic Credit
- Research contributions will be properly cited
- Academic publications will acknowledge contributors
- Thesis and dissertation work will credit collaborators
- Conference presentations will acknowledge contributions

---

Thank you for your interest in contributing to this academic research project. Your contributions help advance the field of automated vulnerability detection and improve the security of Rust applications.
