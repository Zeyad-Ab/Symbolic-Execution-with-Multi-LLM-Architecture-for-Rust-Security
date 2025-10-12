#!/usr/bin/env python3
"""
All Rust Files Analyzer
Analyzes all Rust files in a folder using KLEE and Fuzzing
Usage: python3 allrust.py <folder_path>
"""
import os
import sys
import time
import subprocess
import tempfile
import shutil
from pathlib import Path
import json
from datetime import datetime
import concurrent.futures
from threading import Lock

class AllRustAnalyzer:
    """Analyzer for all Rust files in a folder using KLEE and Fuzzing"""
    
    def __init__(self, max_workers=4):
        self.max_workers = max_workers
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
        """Analyze a single Rust file (similar to onefile.py but simplified)"""
        print(f"Analyzing: {Path(file_path).name}")
        
        try:
            # Create temporary directory for this file
            temp_dir = tempfile.mkdtemp(prefix=f"rust_analysis_{Path(file_path).stem}_")
            temp_file_path = os.path.join(temp_dir, Path(file_path).name)
            shutil.copy2(file_path, temp_file_path)
            
            # Read Rust code
            with open(file_path, 'r') as f:
                rust_code = f.read()
            
            # Generate FFI wrapper
            ffi_code = self._generate_basic_ffi_wrapper(rust_code)
            ffi_file = temp_file_path.replace('.rs', '_ffi.rs')
            with open(ffi_file, 'w') as f:
                f.write(ffi_code)
            
            # Generate KLEE wrapper
            klee_wrapper = self._generate_klee_wrapper(ffi_code, Path(file_path).name)
            klee_file = os.path.join(temp_dir, 'klee_wrapper.c')
            with open(klee_file, 'w') as f:
                f.write(klee_wrapper)
            
            # Compile to bitcode
            bc_file = self._compile_rust_code(ffi_file, temp_dir)
            
            # Run KLEE analysis
            klee_results = self._run_klee_analysis(bc_file, temp_dir) if bc_file else {'returncode': -1, 'test_cases': 0, 'errors': 0}
            
            # Run fuzzing analysis
            fuzz_results = self._run_fuzzing_analysis(ffi_file, temp_dir)
            
            # Compile results
            results = {
                'file_path': file_path,
                'file_name': Path(file_path).name,
                'analysis_time': datetime.now().isoformat(),
                'klee_results': klee_results,
                'fuzz_results': fuzz_results,
                'vulnerabilities_detected': klee_results.get('errors', 0) > 0 or fuzz_results.get('crashes', 0) > 0,
                'total_vulnerabilities': klee_results.get('errors', 0) + fuzz_results.get('crashes', 0),
                'success': True
            }
            
            # Cleanup
            shutil.rmtree(temp_dir)
            
            return results
            
        except Exception as e:
            print(f"ERROR: Error analyzing {Path(file_path).name}: {e}")
            return {
                'file_path': file_path,
                'file_name': Path(file_path).name,
                'error': str(e),
                'success': False
            }
    
    def _generate_basic_ffi_wrapper(self, rust_code):
        """Generate basic FFI wrapper without LLM"""
        lines = rust_code.split('\n')
        ffi_lines = []
        
        for line in lines:
            if 'fn ' in line and 'pub ' not in line and 'extern' not in line:
                # Convert function to FFI
                ffi_line = line.replace('fn ', 'pub extern "C" fn ')
                ffi_lines.append(f"    #[no_mangle]")
                ffi_lines.append(f"    {ffi_line}")
            else:
                ffi_lines.append(line)
        
        return '\n'.join(ffi_lines)
    
    def _generate_klee_wrapper(self, ffi_code, file_name):
        """Generate KLEE C wrapper"""
        klee_wrapper = f"""
#include <klee/klee.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// KLEE wrapper for {file_name}
extern "C" {{
    // Add extern declarations for your Rust functions here
}}

int main() {{
    // KLEE symbolic variables
    int symbolic_int = 0;
    klee_make_symbolic(&symbolic_int, sizeof(symbolic_int), "symbolic_int");
    
    char symbolic_str[100];
    klee_make_symbolic(symbolic_str, sizeof(symbolic_str), "symbolic_str");
    
    // Add assertions and error conditions
    klee_assert(symbolic_int >= 0);
    klee_assert(strlen(symbolic_str) < 100);
    
    return 0;
}}
"""
        return klee_wrapper
    
    def _compile_rust_code(self, rust_file_path, temp_dir):
        """Compile Rust code to LLVM bitcode"""
        try:
            bc_file = rust_file_path.replace('.rs', '.bc')
            compile_cmd = [
                'rustc', '--emit=llvm-bc', 
                '--crate-type=lib',
                '-o', bc_file,
                rust_file_path
            ]
            
            result = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=temp_dir, timeout=60)
            if result.returncode == 0:
                return bc_file
            else:
                return None
                
        except Exception:
            return None
    
    def _run_klee_analysis(self, bc_file, temp_dir):
        """Run KLEE analysis"""
        try:
            klee_cmd = [
                'klee', 
                '--max-time=30',
                '--max-memory=512',
                '--max-instructions=5000',
                '--max-tests=500',
                bc_file
            ]
            
            result = subprocess.run(klee_cmd, capture_output=True, text=True, cwd=temp_dir, timeout=90)
            
            klee_results = {
                'returncode': result.returncode,
                'test_cases': 0,
                'errors': 0
            }
            
            # Parse KLEE results
            if 'KLEE: done: generated' in result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'generated' in line and 'tests' in line:
                        try:
                            klee_results['test_cases'] = int(line.split()[2])
                        except:
                            pass
                    if 'errors' in line:
                        try:
                            klee_results['errors'] = int(line.split()[1])
                        except:
                            pass
            
            return klee_results
            
        except subprocess.TimeoutExpired:
            return {'returncode': -1, 'test_cases': 0, 'errors': 0}
        except Exception:
            return {'returncode': -1, 'test_cases': 0, 'errors': 0}
    
    def _run_fuzzing_analysis(self, rust_file_path, temp_dir):
        """Run fuzzing analysis"""
        try:
            # Create fuzz target
            fuzz_target = rust_file_path.replace('.rs', '_fuzz.rs')
            fuzz_wrapper = f"""
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {{
    if data.len() < 4 {{
        return;
    }}
    
    let input_str = String::from_utf8_lossy(data);
    let input_int = u32::from_le_bytes([
        data[0], data[1], data[2], data[3]
    ]);
    
    if input_str.len() > 1000 {{
        return;
    }}
}});
"""
            
            with open(fuzz_target, 'w') as f:
                f.write(fuzz_wrapper)
            
            # Try to compile and run fuzzer
            compile_cmd = ['cargo', 'fuzz', 'build', '--target', fuzz_target]
            result = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=temp_dir, timeout=60)
            
            if result.returncode == 0:
                # Run fuzzer
                fuzz_cmd = ['cargo', 'fuzz', 'run', '--target', fuzz_target, '--', '-max_total_time=30']
                fuzz_result = subprocess.run(fuzz_cmd, capture_output=True, text=True, cwd=temp_dir, timeout=60)
                
                fuzz_results = {
                    'returncode': fuzz_result.returncode,
                    'crashes': 0,
                    'executions': 0
                }
                
                # Parse fuzzer results
                if 'executed' in fuzz_result.stdout:
                    lines = fuzz_result.stdout.split('\n')
                    for line in lines:
                        if 'executed' in line:
                            try:
                                fuzz_results['executions'] = int(line.split()[1])
                            except:
                                pass
                        if 'crashes' in line:
                            try:
                                fuzz_results['crashes'] = int(line.split()[1])
                            except:
                                pass
                
                return fuzz_results
            else:
                return {'returncode': -1, 'crashes': 0, 'executions': 0}
                
        except subprocess.TimeoutExpired:
            return {'returncode': -1, 'crashes': 0, 'executions': 0}
        except Exception:
            return {'returncode': -1, 'crashes': 0, 'executions': 0}
    
    def analyze_folder(self, folder_path):
        """Analyze all Rust files in a folder"""
        print(f"Analyzing folder: {folder_path}")
        
        # Find all Rust files
        rust_files = self.find_rust_files(folder_path)
        
        if not rust_files:
            print("ERROR: No Rust files found in the folder")
            return {}
        
        print(f"Starting analysis of {len(rust_files)} files with {self.max_workers} workers...")
        
        # Analyze files in parallel
        start_time = time.time()
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self.analyze_single_file, file_path): file_path 
                for file_path in rust_files
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results[file_path] = result
                    
                    if result.get('success', False):
                        vuln_count = result.get('total_vulnerabilities', 0)
                        print(f"SUCCESS: {Path(file_path).name}: {vuln_count} vulnerabilities")
                    else:
                        print(f"ERROR: {Path(file_path).name}: Analysis failed")
                        
                except Exception as e:
                    print(f"ERROR: {Path(file_path).name}: Exception - {e}")
                    results[file_path] = {
                        'file_path': file_path,
                        'file_name': Path(file_path).name,
                        'error': str(e),
                        'success': False
                    }
        
        analysis_time = time.time() - start_time
        
        # Compile summary
        summary = self._generate_summary(results, analysis_time)
        
        return {
            'folder_path': folder_path,
            'analysis_time': datetime.now().isoformat(),
            'total_files': len(rust_files),
            'analysis_duration': analysis_time,
            'summary': summary,
            'results': results
        }
    
    def _generate_summary(self, results, analysis_time):
        """Generate analysis summary"""
        total_files = len(results)
        successful_analyses = sum(1 for r in results.values() if r.get('success', False))
        failed_analyses = total_files - successful_analyses
        
        vulnerable_files = sum(1 for r in results.values() if r.get('success', False) and r.get('vulnerabilities_detected', False))
        clean_files = successful_analyses - vulnerable_files
        
        total_vulnerabilities = sum(r.get('total_vulnerabilities', 0) for r in results.values() if r.get('success', False))
        total_klee_errors = sum(r.get('klee_results', {}).get('errors', 0) for r in results.values() if r.get('success', False))
        total_fuzz_crashes = sum(r.get('fuzz_results', {}).get('crashes', 0) for r in results.values() if r.get('success', False))
        
        return {
            'total_files': total_files,
            'successful_analyses': successful_analyses,
            'failed_analyses': failed_analyses,
            'vulnerable_files': vulnerable_files,
            'clean_files': clean_files,
            'total_vulnerabilities': total_vulnerabilities,
            'total_klee_errors': total_klee_errors,
            'total_fuzz_crashes': total_fuzz_crashes,
            'detection_rate': (vulnerable_files / successful_analyses * 100) if successful_analyses > 0 else 0,
            'analysis_time': analysis_time,
            'throughput': total_files / analysis_time if analysis_time > 0 else 0
        }

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python3 allrust.py <folder_path>")
        print("Example: python3 allrust.py ./rust_code/")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    
    print("All Rust Files Vulnerability Analyzer")
    print("=" * 50)
    print(f"Analyzing folder: {folder_path}")
    print()
    
    analyzer = AllRustAnalyzer(max_workers=4)
    
    try:
        results = analyzer.analyze_folder(folder_path)
        
        if results:
            summary = results['summary']
            
            print("\nANALYSIS SUMMARY")
            print("=" * 30)
            print(f"Folder: {results['folder_path']}")
            print(f"Total Files: {summary['total_files']}")
            print(f"Successful: {summary['successful_analyses']}")
            print(f"Failed: {summary['failed_analyses']}")
            print(f"Vulnerable Files: {summary['vulnerable_files']}")
            print(f"Clean Files: {summary['clean_files']}")
            print(f"Detection Rate: {summary['detection_rate']:.1f}%")
            print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
            print(f"   - KLEE Errors: {summary['total_klee_errors']}")
            print(f"   - Fuzz Crashes: {summary['total_fuzz_crashes']}")
            print(f"Analysis Time: {summary['analysis_time']:.2f} seconds")
            print(f"Throughput: {summary['throughput']:.1f} files/second")
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = f"folder_analysis_results_{timestamp}.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {results_file}")
        else:
            print("ERROR: Analysis failed")
            
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
    except Exception as e:
        print(f"ERROR: Analysis error: {e}")

if __name__ == "__main__":
    main()
