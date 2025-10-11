# LaTeX Thesis Report

This directory contains a comprehensive LaTeX report for the research project "Cracking Unsafe Rust: A Hybrid Symbolic Execution and Fuzzing Approach".

## Files

- **`thesis_report.tex`** - Main LaTeX document
- **`Makefile`** - Build automation
- **`compile_report.sh`** - Compilation script
- **`LATEX_REPORT_README.md`** - This file

## Quick Start

### Option 1: Using the Compilation Script
```bash
./compile_report.sh
```

### Option 2: Using Make
```bash
make all
```

### Option 3: Manual Compilation
```bash
pdflatex thesis_report.tex
pdflatex thesis_report.tex  # Run twice for references
```

## Prerequisites

### macOS
```bash
brew install --cask mactex
```

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install texlive-full
```

### Windows
Download and install MiKTeX or TeX Live from:
- MiKTeX: https://miktex.org/
- TeX Live: https://www.tug.org/texlive/

## Report Contents

The LaTeX report includes:

### 1. **Abstract**
- Research overview and key findings
- Performance metrics and achievements

### 2. **Introduction**
- Problem statement and motivation
- Research objectives

### 3. **Related Work**
- Symbolic execution for security analysis
- Dynamic analysis and fuzzing
- Rust security analysis

### 4. **Methodology**
- Hybrid analysis framework
- Dataset construction
- Analysis pipeline

### 5. **Experimental Setup**
- Performance configuration
- Evaluation metrics

### 6. **Results**
- Performance analysis
- Vulnerability detection results
- Comparative analysis

### 7. **Technical Implementation**
- LLM integration
- KLEE integration
- LibFuzzer integration

### 8. **Discussion**
- Key contributions
- Limitations
- Future work

### 9. **Conclusion**
- Research impact
- Applications

### 10. **Appendices**
- Repository information
- Reproducibility instructions

## Features

- **Professional Formatting**: Academic paper style with proper citations
- **Code Listings**: Syntax-highlighted code examples
- **Tables**: Performance metrics and vulnerability distributions
- **Figures**: Analysis pipeline diagrams
- **Bibliography**: Proper academic citations
- **Hyperlinks**: Clickable references and URLs

## Customization

To customize the report:

1. **Author Information**: Edit the `\author{}` section
2. **Institution**: Update the institution name
3. **Results**: Modify the results tables with your data
4. **Bibliography**: Add or remove references
5. **Styling**: Adjust colors, fonts, and layout

## Troubleshooting

### Common Issues

1. **Missing LaTeX**: Install LaTeX distribution
2. **Missing Packages**: Install required packages
3. **Compilation Errors**: Check LaTeX syntax
4. **Font Issues**: Install required fonts

### Error Messages

- **"pdflatex not found"**: Install LaTeX distribution
- **"Package not found"**: Install missing packages
- **"File not found"**: Check file paths and names

## Output

The compilation produces:
- **`thesis_report.pdf`** - Main report (professional PDF)
- Auxiliary files (automatically cleaned up)

## Academic Use

This report is designed for:
- **Thesis Submission**: Academic thesis documentation
- **Conference Papers**: Research paper format
- **Journal Articles**: Journal publication format
- **Presentations**: Professional presentation material

## Citation

When using this report, cite as:

```bibtex
@software{cracking_unsafe_rust,
  title={Cracking Unsafe Rust: A Hybrid Symbolic Execution and Fuzzing Approach},
  author={Zeyad Abdelrazek},
  year={2025},
  url={https://github.com/Zeyad-Ab/Cracking-Unsafe-Rust-A-Hybrid-Symbolic-Execution-and-Fuzzing-Approach},
  note={Thesis Research Project - Texas A&M San Antonio}
}
```

## Support

For issues with the LaTeX report:
1. Check the compilation logs
2. Verify LaTeX installation
3. Check package dependencies
4. Review LaTeX syntax

## License

This LaTeX report is part of the MIT-licensed research project.
