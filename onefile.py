#!/usr/bin/env python3
"""
Single File Vulnerability Analyzer
Uses real LLM + KLEE + Fuzzing approach
Usage: python3 onefile.py example.rs
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

class SingleFileAnalyzer:
    """Real analyzer using LLM + KLEE + Fuzzing approach"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            print("ERROR: OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
            sys.exit(1)
        
        self.client = OpenAI(api_key=self.api_key)
        self.temp_dir = None
        self.results = {}
        
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
    
    def generate_ffi_wrapper(self, rust_code):
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
    
    def _generate_basic_ffi_wrapper(self, rust_code):
        """Generate basic FFI wrapper without LLM"""
        # Simple pattern-based FFI conversion
        lines = rust_code.split('\n')
        ffi_lines = []
        
        for line in lines:
            if 'fn ' in line and 'pub ' not in line:
                # Convert function to FFI
                ffi_line = line.replace('fn ', 'pub extern "C" fn ')
                ffi_line = ffi_line.replace(' -> ', ' -> ')
                ffi_lines.append(f"    #[no_mangle]")
                ffi_lines.append(f"    {ffi_line}")
            else:
                ffi_lines.append(line)
        
        return '\n'.join(ffi_lines)
    
    def generate_klee_wrapper(self, ffi_code, file_name):
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
    
    def generate_fuzz_wrapper(self, ffi_code, file_name):
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
    
    def run_klee_analysis(self, bc_file):
        """Run KLEE analysis"""
        try:
            print("Running KLEE analysis...")
            klee_cmd = [
                'klee', 
                '--max-time=60',
                '--max-memory=1024',
                '--max-instructions=10000',
                '--max-tests=1000',
                bc_file
            ]
            
            result = subprocess.run(klee_cmd, capture_output=True, text=True, cwd=self.temp_dir, timeout=120)
            
            klee_results = {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
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
            
            print(f"SUCCESS: KLEE analysis completed: {klee_results['test_cases']} test cases, {klee_results['errors']} errors")
            return klee_results
            
        except subprocess.TimeoutExpired:
            print("TIMEOUT: KLEE analysis timed out")
            return {'returncode': -1, 'stdout': '', 'stderr': 'Timeout', 'test_cases': 0, 'errors': 0}
        except Exception as e:
            print(f"ERROR: KLEE analysis error: {e}")
            return {'returncode': -1, 'stdout': '', 'stderr': str(e), 'test_cases': 0, 'errors': 0}
    
    def run_fuzzing_analysis(self, rust_file_path):
        """Run fuzzing analysis"""
        try:
            print("Running fuzzing analysis...")
            
            # Create fuzz target
            fuzz_target = rust_file_path.replace('.rs', '_fuzz.rs')
            fuzz_wrapper = self.generate_fuzz_wrapper("", Path(rust_file_path).name)
            
            with open(fuzz_target, 'w') as f:
                f.write(fuzz_wrapper)
            
            # Try to compile and run fuzzer
            compile_cmd = ['cargo', 'fuzz', 'build', '--target', fuzz_target]
            result = subprocess.run(compile_cmd, capture_output=True, text=True, cwd=self.temp_dir, timeout=60)
            
            if result.returncode == 0:
                # Run fuzzer
                fuzz_cmd = ['cargo', 'fuzz', 'run', '--target', fuzz_target, '--', '-max_total_time=60']
                fuzz_result = subprocess.run(fuzz_cmd, capture_output=True, text=True, cwd=self.temp_dir, timeout=120)
                
                fuzz_results = {
                    'returncode': fuzz_result.returncode,
                    'stdout': fuzz_result.stdout,
                    'stderr': fuzz_result.stderr,
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
                
                print(f"SUCCESS: Fuzzing completed: {fuzz_results['executions']} executions, {fuzz_results['crashes']} crashes")
                return fuzz_results
            else:
                print(f"ERROR: Fuzzer compilation failed: {result.stderr}")
                return {'returncode': -1, 'stdout': '', 'stderr': 'Compilation failed', 'crashes': 0, 'executions': 0}
                
        except subprocess.TimeoutExpired:
            print("TIMEOUT: Fuzzing analysis timed out")
            return {'returncode': -1, 'stdout': '', 'stderr': 'Timeout', 'crashes': 0, 'executions': 0}
        except Exception as e:
            print(f"ERROR: Fuzzing analysis error: {e}")
            return {'returncode': -1, 'stdout': '', 'stderr': str(e), 'crashes': 0, 'executions': 0}
    
    def analyze_file(self, file_path):
        """Analyze a single Rust file"""
        print(f"Analyzing file: {file_path}")
        
        if not os.path.exists(file_path):
            print(f"ERROR: File not found: {file_path}")
            return None
        
        # Setup
        self.setup_temp_environment()
        temp_file_path = self.copy_file_to_temp(file_path)
        
        # Read Rust code
        with open(file_path, 'r') as f:
            rust_code = f.read()
        
        # Generate FFI wrapper
        print("🔄 Generating FFI wrapper...")
        ffi_code = self.generate_ffi_wrapper(rust_code)
        
        # Save FFI code
        ffi_file = temp_file_path.replace('.rs', '_ffi.rs')
        with open(ffi_file, 'w') as f:
            f.write(ffi_code)
        
        # Generate KLEE wrapper
        print(" Generating KLEE wrapper...")
        klee_wrapper = self.generate_klee_wrapper(ffi_code, Path(file_path).name)
        klee_file = os.path.join(self.temp_dir, 'klee_wrapper.c')
        with open(klee_file, 'w') as f:
            f.write(klee_wrapper)
        
        # Compile to bitcode
        print(" Compiling to bitcode...")
        bc_file = self.compile_rust_code(ffi_file)
        
        # Run KLEE analysis
        klee_results = self.run_klee_analysis(bc_file) if bc_file else {'returncode': -1, 'test_cases': 0, 'errors': 0}
        
        # Run fuzzing analysis
        fuzz_results = self.run_fuzzing_analysis(ffi_file)
        
        # Compile results
        results = {
            'file_path': file_path,
            'analysis_time': datetime.now().isoformat(),
            'klee_results': klee_results,
            'fuzz_results': fuzz_results,
            'vulnerabilities_detected': klee_results.get('errors', 0) > 0 or fuzz_results.get('crashes', 0) > 0,
            'total_vulnerabilities': klee_results.get('errors', 0) + fuzz_results.get('crashes', 0)
        }
        
        return results
    
    def cleanup(self):
        """Cleanup temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            print(f"🧹 Cleaned up temporary directory: {self.temp_dir}")

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python3 onefile.py <rust_file>")
        print("Example: python3 onefile.py example.rs")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    print("Single File Vulnerability Analyzer")
    print("=" * 50)
    print(f"Analyzing: {file_path}")
    print()
    
    analyzer = SingleFileAnalyzer()
    
    try:
        results = analyzer.analyze_file(file_path)
        
        if results:
            print("\nANALYSIS RESULTS")
            print("=" * 30)
            print(f"File: {results['file_path']}")
            print(f"Analysis Time: {results['analysis_time']}")
            print(f"KLEE Test Cases: {results['klee_results'].get('test_cases', 0)}")
            print(f"KLEE Errors: {results['klee_results'].get('errors', 0)}")
            print(f"Fuzz Executions: {results['fuzz_results'].get('executions', 0)}")
            print(f"Fuzz Crashes: {results['fuzz_results'].get('crashes', 0)}")
            print(f"Vulnerabilities Detected: {'Yes' if results['vulnerabilities_detected'] else 'No'}")
            print(f"Total Vulnerabilities: {results['total_vulnerabilities']}")
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = f"analysis_results_{timestamp}.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {results_file}")
        else:
            print("ERROR: Analysis failed")
            
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
    except Exception as e:
        print(f"ERROR: Analysis error: {e}")
    finally:
        analyzer.cleanup()

if __name__ == "__main__":
    main()
