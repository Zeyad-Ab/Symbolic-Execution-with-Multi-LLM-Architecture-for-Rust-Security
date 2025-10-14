#!/usr/bin/env python3
"""
Single File Vulnerability Analyzer
Uses real LLM + KLEE + Fuzzing approach from rust_vulnerability_analyzer.py
Usage: python3 onefile.py example.rs
"""
import os
import sys
import time
import json
from pathlib import Path
from datetime import datetime
from core_analyzer import CoreAnalyzer

class RealSingleFileAnalyzer:
    """Real analyzer using LLM + KLEE + Fuzzing approach from rust_vulnerability_analyzer.py"""
    
    def __init__(self, api_key=None):
        try:
            self.core_analyzer = CoreAnalyzer(api_key)
        except ValueError as e:
            print(f"ERROR: {e}")
            sys.exit(1)
        
    
    def analyze_file(self, file_path):
        """Analyze a single Rust file using real LLM + KLEE + Fuzzing approach"""
        print(f"Analyzing: {Path(file_path).name}")
        
        # Use the core analyzer from rust_vulnerability_analyzer.py
        results = self.core_analyzer.analyze_single_file_comprehensive(file_path)
        
        if results and results.get('success', False):
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = f"analysis_results_{timestamp}.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"SUCCESS: Analysis completed. Results saved to {results_file}")
            return results
        else:
            print(f"ERROR: Analysis failed: {results.get('error', 'Unknown error')}")
            return None

def main():
    """Main entry point"""
    if len(sys.argv) != 2:
        print("Usage: python3 onefile.py <rust_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"ERROR: File not found: {file_path}")
        sys.exit(1)
    
    if not file_path.endswith('.rs'):
        print("ERROR: File must be a Rust source file (.rs)")
        sys.exit(1)
    
    # Check for API key
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY environment variable not set")
        print("Please set your OpenAI API key: export OPENAI_API_KEY='your-key-here'")
        sys.exit(1)
    
    # Run analysis
    analyzer = RealSingleFileAnalyzer()
    results = analyzer.analyze_file(file_path)
    
    if results:
        print("\n" + "="*60)
        print("ANALYSIS RESULTS")
        print("="*60)
        print(f"File: {results['file_name']}")
        print(f"Vulnerabilities Detected: {results['vulnerabilities_detected']}")
        print(f"Total Vulnerabilities: {results['total_vulnerabilities']}")
        print(f"KLEE Errors: {results['klee_results']['errors']}")
        print(f"KLEE Warnings: {results['klee_results']['warnings']}")
        print(f"KLEE Test Cases: {results['klee_results']['test_cases']}")
        print(f"Fuzzing Crashes: {results['fuzz_results']['crashes']}")
        print(f"Fuzzing Executions: {results['fuzz_results']['executions']}")
        print("="*60)
    else:
        print("ERROR: Analysis failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
