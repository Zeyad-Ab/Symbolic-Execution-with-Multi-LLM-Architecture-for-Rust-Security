#!/usr/bin/env python3
"""Run single-agent analyzer with each of the 7 LLM models on the Positive_Memory dataset."""

import os
import sys
import time
from pathlib import Path

from core_analyzer_working_fixed import CoreAnalyzerWorking

MODELS = ['gpt4-turbo', 'gpt4o-mini', 'gpt5.2', 'claude-opus', 'claude-sonnet', 'gemini-2', 'gemini-3']

def main():
    test_dir = Path('Positive_Memory')
    if not test_dir.exists():
        print("Error: Positive_Memory directory not found")
        return
    files = sorted(test_dir.glob('*.rs'))
    if not files:
        print("No .rs files in Positive_Memory")
        return
    print(f"Testing {len(MODELS)} models on {len(files)} files from Positive_Memory")
    for model in MODELS:
        print(f"\n--- Model: {model} ---")
        try:
            analyzer = CoreAnalyzerWorking(model_name=model)
            for i, fp in enumerate(files[:3]):  # first 3 files per model as sample
                t0 = time.time()
                result = analyzer.analyze_single_file_working(str(fp), 'positive')
                elapsed = time.time() - t0
                vulns = result.get('total_vulnerabilities', 0)
                print(f"  {fp.name}: {vulns} vulns ({elapsed:.1f}s)")
        except Exception as e:
            print(f"  Error: {e}")

if __name__ == "__main__":
    main()
