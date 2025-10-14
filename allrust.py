#!/usr/bin/env python3
"""
All Rust Files Analyzer
Uses real LLM + KLEE + Fuzzing approach from rust_vulnerability_analyzer.py
Usage: python3 allrust.py <folder_path>
"""
import os
import sys
import time
from pathlib import Path
import json
from datetime import datetime
import concurrent.futures
from threading import Lock
from core_analyzer import CoreAnalyzer

class RealAllRustAnalyzer:
    """Real analyzer for all Rust files using LLM + KLEE + Fuzzing approach from rust_vulnerability_analyzer.py"""
    
    def __init__(self, max_workers=4, api_key=None):
        self.max_workers = max_workers
        try:
            self.core_analyzer = CoreAnalyzer(api_key)
        except ValueError as e:
            print(f"ERROR: {e}")
            sys.exit(1)
        
        self.results = {}
        self.lock = Lock()
        
    def find_rust_files(self, folder_path):
        """Find all Rust files in the folder"""
        rust_files = []
        folder = Path(folder_path)
        
        if not folder.exists():
            print(f"ERROR: Folder not found: {folder_path}")
            return rust_files
        
        for file_path in folder.rglob("*.rs"):
            rust_files.append(str(file_path))
        
        print(f"Found {len(rust_files)} Rust files in {folder_path}")
        return rust_files
    
    def analyze_single_file(self, file_path):
        """Analyze a single Rust file using real LLM + KLEE + Fuzzing approach"""
        print(f"Analyzing: {Path(file_path).name}")
        
        # Use the core analyzer from rust_vulnerability_analyzer.py
        return self.core_analyzer.analyze_single_file_comprehensive(file_path)
    
    def analyze_folder(self, folder_path):
        """Analyze all Rust files in a folder using real LLM + KLEE + Fuzzing approach"""
        print("REAL HYBRID ANALYSIS - LLM + KLEE + FUZZING")
        print("="*60)
        
        # Find all Rust files
        rust_files = self.find_rust_files(folder_path)
        if not rust_files:
            print("No Rust files found!")
            return
        
        print(f"Analyzing {len(rust_files)} Rust files...")
        print(f"Using {self.max_workers} parallel workers")
        print()
        
        # Analyze files in parallel
        start_time = time.time()
        all_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self.analyze_single_file, file_path): file_path 
                for file_path in rust_files
            }
            
            # Process completed tasks
            for i, future in enumerate(concurrent.futures.as_completed(future_to_file), 1):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    all_results.append(result)
                    
                    if result and result.get('success', False):
                        vuln_status = "VULNERABLE" if result.get('vulnerabilities_detected', False) else "SAFE"
                        print(f"[{i}/{len(rust_files)}] {Path(file_path).name}: {vuln_status}")
                    else:
                        print(f"[{i}/{len(rust_files)}] {Path(file_path).name}: ERROR")
                        
                except Exception as e:
                    print(f"[{i}/{len(rust_files)}] {Path(file_path).name}: EXCEPTION - {e}")
                    all_results.append({
                        'file_path': file_path,
                        'file_name': Path(file_path).name,
                        'error': str(e),
                        'success': False
                    })
        
        # Calculate summary statistics
        total_files = len(all_results)
        successful_analyses = sum(1 for r in all_results if r.get('success', False))
        vulnerable_files = sum(1 for r in all_results if r.get('vulnerabilities_detected', False))
        total_vulnerabilities = sum(r.get('total_vulnerabilities', 0) for r in all_results if r.get('success', False))
        
        analysis_time = time.time() - start_time
        
        # Create summary
        summary = {
            'folder_path': folder_path,
            'analysis_time': datetime.now().isoformat(),
            'total_files': total_files,
            'successful_analyses': successful_analyses,
            'vulnerable_files': vulnerable_files,
            'total_vulnerabilities': total_vulnerabilities,
            'analysis_duration_seconds': analysis_time,
            'files_per_second': total_files / analysis_time if analysis_time > 0 else 0,
            'results': all_results
        }
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"folder_analysis_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Print summary
        print()
        print("="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        print(f"Folder: {folder_path}")
        print(f"Total files: {total_files}")
        print(f"Successful analyses: {successful_analyses}")
        print(f"Vulnerable files: {vulnerable_files}")
        print(f"Total vulnerabilities found: {total_vulnerabilities}")
        print(f"Analysis time: {analysis_time:.2f} seconds")
        print(f"Files per second: {total_files / analysis_time:.2f}")
        print(f"Results saved to: {results_file}")
        
        return summary

def main():
    """Main entry point"""
    if len(sys.argv) != 2:
        print("Usage: python3 allrust.py <folder_path>")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    
    if not os.path.exists(folder_path):
        print(f"ERROR: Folder not found: {folder_path}")
        sys.exit(1)
    
    # Create analyzer
    analyzer = RealAllRustAnalyzer(max_workers=4)
    
    # Analyze folder
    results = analyzer.analyze_folder(folder_path)
    
    if results:
        print("\nAnalysis completed successfully!")
    else:
        print("\nAnalysis failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
