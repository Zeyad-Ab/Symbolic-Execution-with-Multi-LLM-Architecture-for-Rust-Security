#!/usr/bin/env python3
"""
Real Single File Vulnerability Analyzer
Uses actual LLM + KLEE + Fuzzing approach
Usage: python3 onefile_new.py example.rs
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
from openai import OpenAI

class RealSingleFileAnalyzer:
    """Real analyzer using LLM + KLEE + Fuzzing approach"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            print("ERROR: OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
            sys.exit(1)
        
        self.client = OpenAI(api_key=self.api_key)
        self.temp_dir = None
        
    def setup_temp_environment(self):
        """Setup temporary directory for analysis"""
        self.temp_dir = tempfile.mkdtemp(prefix="rust_analysis_")
        print(f"Created temporary directory: {self.temp_dir}")
        return self.temp_dir
    
    def copy_file_to_temp(self, file_path):
        """Copy the Rust file to temporary directory"""
        file_name = Path(file_path).name
        temp_file_path = os.path.join(self.temp_dir, file_name)
        shutil.copy2(file_path, temp_file_path)
        print(f"Copied {file_name} to temporary directory")
        return temp_file_path
    
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
    
    def compile_rust_to_bitcode(self, rust_file_path):
        """Compile Rust code to LLVM bitcode"""
        try:
            bc_file = rust_file_path.replace('.rs', '.bc')
            compile_cmd = [
                'rustc', '--emit=llvm-bc', 
                '--crate-type=staticlib',
                '--target', 'x86_64-unknown-linux-gnu',
                '-C', 'panic=abort',
                '-o', bc_file,
                rust_file_path
            ]
            
            result = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=self.temp_dir)
            if result.returncode == 0:
                print(f"SUCCESS: Compiled to bitcode: {bc_file}")
                return bc_file
            else:
                print(f"ERROR: Rust compilation failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"ERROR: Compilation error: {e}")
            return None
    
    def compile_c_to_bitcode(self, c_file_path):
        """Compile C wrapper to LLVM bitcode"""
        try:
            bc_file = c_file_path.replace('.c', '.bc')
            compile_cmd = [
                'clang', '-emit-llvm', '-c',
                '--target=x86_64-unknown-linux-gnu',
                '-o', bc_file,
                c_file_path
            ]
            
            result = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=self.temp_dir)
            if result.returncode == 0:
                print(f"SUCCESS: Compiled C to bitcode: {bc_file}")
                return bc_file
            else:
                print(f"ERROR: C compilation failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"ERROR: C compilation error: {e}")
            return None
    
    def link_bitcode_files(self, rust_bc, c_bc):
        """Link Rust and C bitcode files"""
        try:
            linked_bc = "linked.bc"
            link_cmd = ['llvm-link', rust_bc, c_bc, '-o', linked_bc]
            
            result = subprocess.run(link_cmd, capture_output=True, text=True, cwd=self.temp_dir)
            if result.returncode == 0:
                print(f"SUCCESS: Linked bitcode files: {linked_bc}")
                return linked_bc
            else:
                print(f"ERROR: Bitcode linking failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"ERROR: Bitcode linking error: {e}")
            return None
    
    def run_klee_analysis(self, linked_bc):
        """Run KLEE analysis on linked bitcode"""
        try:
            print("Running KLEE analysis...")
            klee_cmd = [
                'klee', 
                '--max-time=60',
                '--max-memory=1024',
                '--max-instructions=10000',
                '--max-tests=1000',
                linked_bc
            ]
            
            result = subprocess.run(klee_cmd, capture_output=True, text=True, cwd=self.temp_dir, timeout=120)
            
            klee_results = {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
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
                    if 'errors' in line.lower():
                        try:
                            klee_results['errors'] = int(line.split()[1])
                        except:
                            pass
            
            # Count error files
            error_files = list(Path(self.temp_dir).glob("*.err"))
            klee_results['errors'] = len(error_files)
            
            # Count warning files
            warning_files = list(Path(self.temp_dir).glob("*.warn"))
            klee_results['warnings'] = len(warning_files)
            
            print(f"KLEE Results: {klee_results['test_cases']} test cases, {klee_results['errors']} errors, {klee_results['warnings']} warnings")
            return klee_results
            
        except subprocess.TimeoutExpired:
            print("WARNING: KLEE analysis timed out")
            return {'returncode': -1, 'test_cases': 0, 'errors': 0, 'warnings': 0}
        except Exception as e:
            print(f"ERROR: KLEE analysis failed: {e}")
            return {'returncode': -1, 'test_cases': 0, 'errors': 0, 'warnings': 0}
    
    def run_fuzzing_analysis(self, fuzz_file):
        """Run LibFuzzer analysis"""
        try:
            print("Running LibFuzzer analysis...")
            
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
            
            with open(os.path.join(self.temp_dir, "Cargo.toml"), 'w') as f:
                f.write(cargo_toml)
            
            # Run cargo fuzz
            fuzz_cmd = ['cargo', 'fuzz', 'run', 'fuzz_target', '--', '-max_total_time=60']
            
            result = subprocess.run(fuzz_cmd, capture_output=True, text=True, cwd=self.temp_dir, timeout=120)
            
            fuzz_results = {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
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
            
            print(f"Fuzzing Results: {fuzz_results['crashes']} crashes, {fuzz_results['executions']} executions")
            return fuzz_results
            
        except subprocess.TimeoutExpired:
            print("WARNING: Fuzzing analysis timed out")
            return {'returncode': -1, 'crashes': 0, 'executions': 0}
        except Exception as e:
            print(f"ERROR: Fuzzing analysis failed: {e}")
            return {'returncode': -1, 'crashes': 0, 'executions': 0}
    
    def analyze_file(self, file_path):
        """Analyze a single Rust file using real LLM + KLEE + Fuzzing approach"""
        print(f"Analyzing: {Path(file_path).name}")
        
        try:
            # Setup
            self.setup_temp_environment()
            temp_file_path = self.copy_file_to_temp(file_path)
            
            # Read Rust code
            with open(file_path, 'r') as f:
                rust_code = f.read()
            
            # Step 1: Generate FFI wrapper using LLM
            print("Step 1: Generating FFI wrapper using LLM...")
            ffi_code = self.generate_ffi_wrapper_llm(rust_code)
            if not ffi_code:
                print("ERROR: Failed to generate FFI wrapper")
                return None
            
            ffi_file = temp_file_path.replace('.rs', '_ffi.rs')
            with open(ffi_file, 'w') as f:
                f.write(ffi_code)
            print("SUCCESS: FFI wrapper generated")
            
            # Step 2: Generate KLEE wrapper using LLM
            print("Step 2: Generating KLEE wrapper using LLM...")
            klee_code = self.generate_klee_wrapper_llm(ffi_code, Path(file_path).name)
            if not klee_code:
                print("ERROR: Failed to generate KLEE wrapper")
                return None
            
            klee_file = os.path.join(self.temp_dir, 'klee_wrapper.c')
            with open(klee_file, 'w') as f:
                f.write(klee_code)
            print("SUCCESS: KLEE wrapper generated")
            
            # Step 3: Generate Fuzzing wrapper using LLM
            print("Step 3: Generating Fuzzing wrapper using LLM...")
            fuzz_code = self.generate_fuzz_wrapper_llm(ffi_code, Path(file_path).name)
            if not fuzz_code:
                print("ERROR: Failed to generate Fuzzing wrapper")
                return None
            
            fuzz_file = os.path.join(self.temp_dir, 'fuzz_target.rs')
            with open(fuzz_file, 'w') as f:
                f.write(fuzz_code)
            print("SUCCESS: Fuzzing wrapper generated")
            
            # Step 4: Compile Rust to bitcode
            print("Step 4: Compiling Rust to bitcode...")
            rust_bc = self.compile_rust_to_bitcode(ffi_file)
            if not rust_bc:
                print("ERROR: Failed to compile Rust to bitcode")
                return None
            
            # Step 5: Compile C wrapper to bitcode
            print("Step 5: Compiling C wrapper to bitcode...")
            c_bc = self.compile_c_to_bitcode(klee_file)
            if not c_bc:
                print("ERROR: Failed to compile C wrapper to bitcode")
                return None
            
            # Step 6: Link bitcode files
            print("Step 6: Linking bitcode files...")
            linked_bc = self.link_bitcode_files(rust_bc, c_bc)
            if not linked_bc:
                print("ERROR: Failed to link bitcode files")
                return None
            
            # Step 7: Run KLEE analysis
            print("Step 7: Running KLEE symbolic execution...")
            klee_results = self.run_klee_analysis(linked_bc)
            
            # Step 8: Run Fuzzing analysis
            print("Step 8: Running LibFuzzer dynamic analysis...")
            fuzz_results = self.run_fuzzing_analysis(fuzz_file)
            
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
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = f"analysis_results_{timestamp}.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"SUCCESS: Analysis completed. Results saved to {results_file}")
            return results
            
        except Exception as e:
            print(f"ERROR: Analysis failed: {e}")
            return None
        finally:
            # Cleanup
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                print("Cleaned up temporary directory")

def main():
    """Main entry point"""
    if len(sys.argv) != 2:
        print("Usage: python3 onefile_new.py <rust_file>")
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
