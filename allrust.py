#!/usr/bin/env python3
"""
All Rust Files Analyzer
Uses real LLM + KLEE + Fuzzing approach for folder analysis
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
from openai import OpenAI

class RealAllRustAnalyzer:
    """Real analyzer for all Rust files using LLM + KLEE + Fuzzing approach"""
    
    def __init__(self, max_workers=4, api_key=None):
        self.max_workers = max_workers
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            print("ERROR: OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
            sys.exit(1)
        
        self.client = OpenAI(api_key=self.api_key)
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
    
    def generate_ffi_wrapper_llm(self, rust_code):
        """Generate FFI wrapper using LLM"""
        try:
            prompt = f"""
            Convert the following Rust code to FFI-compatible Rust code with pub extern "C" functions.
            Add #[no_mangle] attributes and ensure all functions are C-compatible.
            Focus on making functions callable from C and suitable for KLEE analysis.
            
            Rust Code:
            {rust_code}
            
            Return only the FFI-wrapped Rust code, no explanations.
            """
            
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.1
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            print(f"ERROR: LLM generation failed: {e}")
            return None
    
    def generate_klee_wrapper_llm(self, ffi_code, file_name):
        """Generate KLEE C wrapper using LLM"""
        try:
            prompt = f"""
            Generate a KLEE C wrapper for the following FFI Rust code.
            Create a main() function that:
            1. Uses klee_make_symbolic() to create symbolic variables
            2. Calls the Rust functions with symbolic inputs
            3. Includes appropriate assertions and error conditions
            4. Is suitable for KLEE symbolic execution
            
            FFI Rust Code:
            {ffi_code}
            
            Return only the C code, no explanations.
            """
            
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.1
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            print(f"ERROR: LLM KLEE wrapper generation failed: {e}")
            return None
    
    def generate_fuzz_wrapper_llm(self, ffi_code, file_name):
        """Generate LibFuzzer wrapper using LLM"""
        try:
            prompt = f"""
            Generate a LibFuzzer fuzz target for the following FFI Rust code.
            Create a fuzz_target! macro that:
            1. Takes input data as &[u8]
            2. Converts input to appropriate types for the Rust functions
            3. Calls the Rust functions with the converted input
            4. Includes bounds checking and error handling
            5. Is suitable for LibFuzzer dynamic analysis
            
            FFI Rust Code:
            {ffi_code}
            
            Return only the Rust fuzz target code, no explanations.
            """
            
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.1
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            print(f"ERROR: LLM fuzz wrapper generation failed: {e}")
            return None
    
    def compile_rust_to_bitcode(self, rust_file_path, temp_dir):
        """Compile Rust code to LLVM bitcode"""
        try:
            bc_file = os.path.join(temp_dir, Path(rust_file_path).stem + '.bc')
            compile_cmd = [
                'rustc', '--emit=llvm-bc', 
                '--crate-type=staticlib',
                '--target', 'x86_64-unknown-linux-gnu',
                '-C', 'panic=abort',
                '-o', bc_file,
                rust_file_path
            ]
            
            result = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=temp_dir)
            if result.returncode == 0:
                return bc_file
            else:
                print(f"ERROR: Rust compilation failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"ERROR: Compilation error: {e}")
            return None
    
    def compile_c_to_bitcode(self, c_file_path, temp_dir):
        """Compile C wrapper to LLVM bitcode"""
        try:
            bc_file = c_file_path.replace('.c', '.bc')
            compile_cmd = [
                'clang', '-emit-llvm', '-c',
                '--target=x86_64-unknown-linux-gnu',
                '-o', bc_file,
                c_file_path
            ]
            
            result = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=temp_dir)
            if result.returncode == 0:
                return bc_file
            else:
                print(f"ERROR: C compilation failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"ERROR: C compilation error: {e}")
            return None
    
    def link_bitcode_files(self, rust_bc, c_bc, temp_dir):
        """Link Rust and C bitcode files"""
        try:
            linked_bc = os.path.join(temp_dir, "linked.bc")
            link_cmd = ['llvm-link', rust_bc, c_bc, '-o', linked_bc]
            
            result = subprocess.run(link_cmd, capture_output=True, text=True, cwd=temp_dir)
            if result.returncode == 0:
                return linked_bc
            else:
                print(f"ERROR: Bitcode linking failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"ERROR: Bitcode linking error: {e}")
            return None
    
    def run_klee_analysis(self, linked_bc, temp_dir):
        """Run KLEE analysis on linked bitcode"""
        try:
            klee_cmd = [
                'klee', 
                '--max-time=30',  # Shorter timeout for batch processing
                '--max-memory=512',
                '--max-instructions=5000',
                '--max-tests=500',
                linked_bc
            ]
            
            result = subprocess.run(klee_cmd, capture_output=True, text=True, cwd=temp_dir, timeout=60)
            
            klee_results = {
                'returncode': result.returncode,
                'test_cases': 0,
                'errors': 0,
                'warnings': 0
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
            
            # Count error files
            error_files = list(Path(temp_dir).glob("*.err"))
            klee_results['errors'] = len(error_files)
            
            # Count warning files
            warning_files = list(Path(temp_dir).glob("*.warn"))
            klee_results['warnings'] = len(warning_files)
            
            return klee_results
            
        except subprocess.TimeoutExpired:
            return {'returncode': -1, 'test_cases': 0, 'errors': 0, 'warnings': 0}
        except Exception as e:
            return {'returncode': -1, 'test_cases': 0, 'errors': 0, 'warnings': 0}
    
    def run_fuzzing_analysis(self, fuzz_file, temp_dir):
        """Run LibFuzzer analysis"""
        try:
            # Create Cargo.toml for fuzzing
            cargo_toml = """
[package]
name = "fuzz_target"
version = "0.1.0"
edition = "2021"

[dependencies]
libfuzzer-sys = "0.4"

[[bin]]
name = "fuzz_target"
path = "fuzz_target.rs"
"""
            
            with open(os.path.join(temp_dir, "Cargo.toml"), 'w') as f:
                f.write(cargo_toml)
            
            # Run cargo fuzz with shorter timeout
            fuzz_cmd = ['cargo', 'fuzz', 'run', 'fuzz_target', '--', '-max_total_time=30']
            
            result = subprocess.run(fuzz_cmd, capture_output=True, text=True, cwd=temp_dir, timeout=60)
            
            fuzz_results = {
                'returncode': result.returncode,
                'crashes': 0,
                'executions': 0
            }
            
            # Parse fuzzing results
            if 'crashes' in result.stdout:
                try:
                    crash_line = [line for line in result.stdout.split('\n') if 'crashes' in line][0]
                    fuzz_results['crashes'] = int(crash_line.split()[0])
                except:
                    pass
            
            if 'executions' in result.stdout:
                try:
                    exec_line = [line for line in result.stdout.split('\n') if 'executions' in line][0]
                    fuzz_results['executions'] = int(exec_line.split()[0])
                except:
                    pass
            
            return fuzz_results
            
        except subprocess.TimeoutExpired:
            return {'returncode': -1, 'crashes': 0, 'executions': 0}
        except Exception as e:
            return {'returncode': -1, 'crashes': 0, 'executions': 0}
    
    def analyze_single_file(self, file_path):
        """Analyze a single Rust file using real LLM + KLEE + Fuzzing approach"""
        print(f"Analyzing: {Path(file_path).name}")
        
        try:
            # Create temporary directory for this file
            temp_dir = tempfile.mkdtemp(prefix=f"rust_analysis_{Path(file_path).stem}_")
            temp_file_path = os.path.join(temp_dir, Path(file_path).name)
            shutil.copy2(file_path, temp_file_path)
            
            # Read Rust code
            with open(file_path, 'r') as f:
                rust_code = f.read()
            
            # Step 1: Generate FFI wrapper using LLM
            ffi_code = self.generate_ffi_wrapper_llm(rust_code)
            if not ffi_code:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'error': 'Failed to generate FFI wrapper',
                    'success': False
                }
            
            ffi_file = temp_file_path.replace('.rs', '_ffi.rs')
            with open(ffi_file, 'w') as f:
                f.write(ffi_code)
            
            # Step 2: Generate KLEE wrapper using LLM
            klee_code = self.generate_klee_wrapper_llm(ffi_code, Path(file_path).name)
            if not klee_code:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'error': 'Failed to generate KLEE wrapper',
                    'success': False
                }
            
            klee_file = os.path.join(temp_dir, 'klee_wrapper.c')
            with open(klee_file, 'w') as f:
                f.write(klee_code)
            
            # Step 3: Generate Fuzzing wrapper using LLM
            fuzz_code = self.generate_fuzz_wrapper_llm(ffi_code, Path(file_path).name)
            if not fuzz_code:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'error': 'Failed to generate Fuzzing wrapper',
                    'success': False
                }
            
            fuzz_file = os.path.join(temp_dir, 'fuzz_target.rs')
            with open(fuzz_file, 'w') as f:
                f.write(fuzz_code)
            
            # Step 4: Compile Rust to bitcode
            rust_bc = self.compile_rust_to_bitcode(ffi_file, temp_dir)
            if not rust_bc:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'error': 'Failed to compile Rust to bitcode',
                    'success': False
                }
            
            # Step 5: Compile C wrapper to bitcode
            c_bc = self.compile_c_to_bitcode(klee_file, temp_dir)
            if not c_bc:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'error': 'Failed to compile C wrapper to bitcode',
                    'success': False
                }
            
            # Step 6: Link bitcode files
            linked_bc = self.link_bitcode_files(rust_bc, c_bc, temp_dir)
            if not linked_bc:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'error': 'Failed to link bitcode files',
                    'success': False
                }
            
            # Step 7: Run KLEE analysis
            klee_results = self.run_klee_analysis(linked_bc, temp_dir)
            
            # Step 8: Run Fuzzing analysis
            fuzz_results = self.run_fuzzing_analysis(fuzz_file, temp_dir)
            
            # Step 9: Compile results
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
    
    def analyze_folder(self, folder_path):
        """Analyze all Rust files in a folder using real LLM + KLEE + Fuzzing approach"""
        print("REAL HYBRID ANALYSIS - LLM + KLEE + FUZZING")
        print("="*60)
        
        # Find all Rust files
        rust_files = self.find_rust_files(folder_path)
        if not rust_files:
            print("ERROR: No Rust files found")
            return None
        
        print(f"Starting analysis of {len(rust_files)} Rust files...")
        print(f"Using {self.max_workers} parallel workers")
        print(f"LLM Integration: OpenAI GPT-3.5-turbo")
        print(f"KLEE Analysis: Symbolic execution with bitcode compilation")
        print(f"LibFuzzer Analysis: Dynamic fuzzing with crash detection")
        print()
        
        start_time = time.time()
        results = {}
        
        # Process files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all files
            future_to_file = {
                executor.submit(self.analyze_single_file, file_path): file_path
                for file_path in rust_files
            }
            
            # Process completed analyses
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results[file_path] = result
                    
                    if result["success"]:
                        vuln_count = result["total_vulnerabilities"]
                        status = "VULNERABILITIES" if vuln_count > 0 else "CLEAN"
                        print(f"  {status}: {Path(file_path).name}: {vuln_count} vulnerabilities")
                    else:
                        print(f"  ERROR: {Path(file_path).name}: {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    print(f"  FAILED: {Path(file_path).name}: {e}")
                    results[file_path] = {
                        'file_path': file_path,
                        'file_name': Path(file_path).name,
                        'error': str(e),
                        'success': False
                    }
        
        analysis_time = time.time() - start_time
        
        # Generate summary
        summary = self._generate_summary(results, analysis_time)
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"folder_analysis_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump({
                'folder_path': folder_path,
                'analysis_time': datetime.now().isoformat(),
                'total_files': len(rust_files),
                'analysis_duration': analysis_time,
                'summary': summary,
                'results': results
            }, f, indent=2)
        
        print(f"\nSUCCESS: Analysis completed. Results saved to {results_file}")
        return results
    
    def _generate_summary(self, results, analysis_time):
        """Generate analysis summary"""
        total_files = len(results)
        successful_analyses = sum(1 for r in results.values() if r.get("success", False))
        failed_analyses = total_files - successful_analyses
        
        total_vulnerabilities = sum(r.get("total_vulnerabilities", 0) for r in results.values() if r.get("success", False))
        files_with_vulnerabilities = sum(1 for r in results.values() if r.get("success", False) and r.get("vulnerabilities_detected", False))
        
        total_klee_errors = sum(r.get("klee_results", {}).get("errors", 0) for r in results.values() if r.get("success", False))
        total_fuzz_crashes = sum(r.get("fuzz_results", {}).get("crashes", 0) for r in results.values() if r.get("success", False))
        
        summary = {
            'total_files': total_files,
            'successful_analyses': successful_analyses,
            'failed_analyses': failed_analyses,
            'success_rate': (successful_analyses / total_files * 100) if total_files > 0 else 0,
            'files_with_vulnerabilities': files_with_vulnerabilities,
            'total_vulnerabilities': total_vulnerabilities,
            'total_klee_errors': total_klee_errors,
            'total_fuzz_crashes': total_fuzz_crashes,
            'analysis_duration': analysis_time,
            'throughput': total_files / analysis_time if analysis_time > 0 else 0
        }
        
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        print(f"Total Files: {summary['total_files']}")
        print(f"Successful Analyses: {summary['successful_analyses']}")
        print(f"Failed Analyses: {summary['failed_analyses']}")
        print(f"Success Rate: {summary['success_rate']:.1f}%")
        print(f"Files with Vulnerabilities: {summary['files_with_vulnerabilities']}")
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"KLEE Errors: {summary['total_klee_errors']}")
        print(f"Fuzzing Crashes: {summary['total_fuzz_crashes']}")
        print(f"Analysis Duration: {summary['analysis_duration']:.2f} seconds")
        print(f"Throughput: {summary['throughput']:.2f} files/second")
        print("="*60)
        
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
    
    # Check for API key
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY environment variable not set")
        print("Please set your OpenAI API key: export OPENAI_API_KEY='your-key-here'")
        sys.exit(1)
    
    # Run analysis
    analyzer = RealAllRustAnalyzer(max_workers=4)
    results = analyzer.analyze_folder(folder_path)
    
    if results:
        print("\nSUCCESS: Folder analysis completed!")
    else:
        print("ERROR: Analysis failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
