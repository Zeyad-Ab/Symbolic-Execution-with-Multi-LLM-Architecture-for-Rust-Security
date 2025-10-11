#!/bin/bash

# LaTeX Report Compilation Script
# For "Cracking Unsafe Rust: A Hybrid Symbolic Execution and Fuzzing Approach"

echo "🔧 Compiling LaTeX thesis report..."

# Check if pdflatex is available
if ! command -v pdflatex &> /dev/null; then
    echo "❌ Error: pdflatex not found. Please install LaTeX:"
    echo "   macOS: brew install --cask mactex"
    echo "   Ubuntu: sudo apt-get install texlive-full"
    exit 1
fi

# Compile the document
echo "📝 Running pdflatex (first pass)..."
pdflatex thesis_report.tex

echo "📝 Running pdflatex (second pass for references)..."
pdflatex thesis_report.tex

# Check if PDF was created
if [ -f "thesis_report.pdf" ]; then
    echo "✅ PDF generated successfully: thesis_report.pdf"
    echo "📊 File size: $(du -h thesis_report.pdf | cut -f1)"
    
    # Open PDF if on macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "🔍 Opening PDF..."
        open thesis_report.pdf
    fi
else
    echo "❌ Error: PDF generation failed"
    exit 1
fi

# Clean up auxiliary files
echo "🧹 Cleaning up auxiliary files..."
rm -f *.aux *.log *.out *.toc *.bbl *.blg *.fdb_latexmk *.fls *.synctex.gz

echo "🎉 Compilation complete!"
