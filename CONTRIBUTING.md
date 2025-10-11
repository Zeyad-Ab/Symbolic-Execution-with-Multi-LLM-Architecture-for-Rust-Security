# Contributing to Rust Vulnerability Analyzer

Thank you for your interest in contributing to the Rust Vulnerability Analyzer! This document provides guidelines for contributing to this project.

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Rust toolchain (for testing)
- OpenAI API key (for LLM integration)

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/rust-vulnerability-analyzer.git
   cd rust-vulnerability-analyzer
   ```

3. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Create a `.env` file:
   ```bash
   echo "OPENAI_API_KEY=your_api_key_here" > .env
   ```

## How to Contribute

### Reporting Issues

- Use the GitHub issue tracker
- Provide a clear description of the problem
- Include steps to reproduce the issue
- Specify your environment (OS, Python version, etc.)

### Suggesting Enhancements

- Use the GitHub issue tracker with the "enhancement" label
- Describe the proposed feature clearly
- Explain why it would be useful
- Consider the impact on existing functionality

### Submitting Changes

1. Create a new branch for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the coding standards below

3. Test your changes:
   ```bash
   python3 test_positive_negative.py
   ```

4. Commit your changes:
   ```bash
   git add .
   git commit -m "Add your descriptive commit message"
   ```

5. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. Create a Pull Request

## Coding Standards

### Python Code

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings for all functions and classes
- Keep functions focused and single-purpose
- Use type hints where appropriate

### Documentation

- Update README.md for user-facing changes
- Add docstrings for new functions
- Include examples in documentation
- Keep comments clear and concise

### Testing

- Test your changes with the existing test suite
- Add new tests for new functionality
- Ensure all tests pass before submitting

## Project Structure

```
rust-vulnerability-analyzer/
├── Positive/                    # Positive dataset (vulnerable code)
├── Negative/                    # Negative dataset (clean code)
├── simple_comprehensive_analyzer.py  # Main analyzer
├── rust_vulnerability_analyzer.py   # Original analyzer
├── test_positive_negative.py  # Test script
├── requirements.txt            # Dependencies
├── config.yaml                 # Configuration
├── README.md                   # Main documentation
├── CONTRIBUTING.md             # This file
└── LICENSE                     # MIT License
```

## Areas for Contribution

### High Priority

- **Performance optimization**: Improve analysis speed
- **Vulnerability detection**: Add new vulnerability patterns
- **Error handling**: Improve robustness and error messages
- **Documentation**: Enhance user guides and API documentation

### Medium Priority

- **Testing**: Expand test coverage
- **Configuration**: Add more configuration options
- **Reporting**: Improve output formats and visualization
- **Integration**: Better integration with CI/CD pipelines

### Low Priority

- **UI/UX**: Command-line interface improvements
- **Internationalization**: Multi-language support
- **Advanced features**: Machine learning integration

## Pull Request Process

1. Ensure your code follows the coding standards
2. Test your changes thoroughly
3. Update documentation if needed
4. Submit a clear and descriptive pull request
5. Respond to feedback promptly
6. Keep your branch up to date with the main branch

## Review Process

- All submissions require review
- Maintainers will review within 1-2 weeks
- Address feedback promptly
- Be open to suggestions and improvements

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

## Questions?

If you have questions about contributing, please:
- Open an issue with the "question" label
- Contact the maintainers
- Check existing issues and discussions

Thank you for contributing to the Rust Vulnerability Analyzer!
