# Makefile for LaTeX thesis report compilation

# Main document
MAIN = thesis_report
TEX = $(MAIN).tex
PDF = $(MAIN).pdf

# LaTeX compiler
LATEX = pdflatex
BIBTEX = bibtex

# Default target
all: $(PDF)

# Compile PDF
$(PDF): $(TEX)
	$(LATEX) $(TEX)
	$(LATEX) $(TEX)  # Run twice for references
	@echo "PDF generated: $(PDF)"

# Clean auxiliary files
clean:
	rm -f *.aux *.log *.out *.toc *.bbl *.blg *.fdb_latexmk *.fls *.synctex.gz

# Clean everything including PDF
distclean: clean
	rm -f $(PDF)

# View PDF (macOS)
view: $(PDF)
	open $(PDF)

# View PDF (Linux)
view-linux: $(PDF)
	xdg-open $(PDF)

# Install LaTeX dependencies (macOS)
install-macos:
	brew install --cask mactex

# Install LaTeX dependencies (Ubuntu)
install-ubuntu:
	sudo apt-get update
	sudo apt-get install texlive-full

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Compile the PDF"
	@echo "  clean        - Remove auxiliary files"
	@echo "  distclean     - Remove all generated files"
	@echo "  view         - Open PDF (macOS)"
	@echo "  view-linux   - Open PDF (Linux)"
	@echo "  install-macos - Install LaTeX on macOS"
	@echo "  install-ubuntu - Install LaTeX on Ubuntu"
	@echo "  help         - Show this help"

.PHONY: all clean distclean view view-linux install-macos install-ubuntu help
