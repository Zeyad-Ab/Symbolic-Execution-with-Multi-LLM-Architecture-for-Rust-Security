#!/usr/bin/env python3
"""
Core Analyzer Module
Extracts essential components from rust_vulnerability_analyzer.py
for use in onefile.py, allrust.py, and evaluate_datasets.py
"""
import os
import time
import json
import paramiko
import textwrap
import traceback
import re
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from openai import OpenAI

class CoreAnalyzer:
    """Core analyzer with real LLM + KLEE + Fuzzing approach"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
        
        self.client = OpenAI(api_key=self.api_key)
    
    def generate_rust_ffi_wrapper(self, rust_code):
        """Generate FFI wrapper using LLM"""
        system_content = """You are an expert in Rust security analysis and FFI. Your task is to analyze real-world Rust code and create FFI wrapper functions for vulnerability testing.

CRITICAL REQUIREMENTS:
1. Identify the most vulnerable functions in the code
2. Create pub extern "C" wrapper functions for these vulnerable functions
3. Add #[no_mangle] attributes to make functions callable from C
4. Handle Rust types (String, Vec, etc.) by converting to C-compatible types
5. Focus on functions that handle user input, memory operations, or arithmetic
6. Do not include any explanation, just the raw Rust code with FFI wrappers"""

        user_prompt = textwrap.dedent(f"""
        Analyze this real-world Rust code and create FFI wrapper functions for vulnerability testing.
        Identify vulnerable functions and create pub extern "C" wrappers for them.

        Rust Code:
        ---
        {rust_code}
        ---

        Generate FFI wrapper functions that expose the vulnerable functionality to C code.
        """)

        print("Calling OpenAI for FFI wrapper generation...")

        for attempt in range(3):
            try:
                response = self.client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system_content},
                        {"role": "user", "content": user_prompt}
                    ],
                    max_tokens=2048,
                    temperature=0.0
                )

                generated_code = response.choices[0].message.content.strip()
                if "```" in generated_code:
                    generated_code = generated_code.split("```")[1]
                    if generated_code.startswith("rust\n"):
                        generated_code = "\n".join(generated_code.split('\n')[1:])

                return generated_code

            except Exception as e:
                print(f"ERROR: API Request Failed (Attempt {attempt + 1}): {e}")
                if attempt < 2:
                    delay = 2 ** attempt
                    print(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    print("ERROR: Final attempt failed. Skipping FFI generation.")
                    return None
        return None

    def generate_klee_wrapper(self, ffi_code):
        """Generate KLEE C wrapper using LLM"""
        system_content = """You are an expert in symbolic execution and KLEE. Your task is to generate a C wrapper for KLEE symbolic execution.

CRITICAL REQUIREMENTS:
1. Include <klee/klee.h> and use klee_make_symbolic
2. Entry point must be int main() { ... }
3. Create symbolic variables with reasonable constraints
4. Add klee_assume() constraints to limit search space
5. Call the FFI functions with symbolic inputs
6. Use klee_report_error with 4 arguments: (file, line, message, suffix)
7. Limit execution time and test cases
8. Do not include any explanation, just the raw C code"""

        user_prompt = textwrap.dedent(f"""
        Create a KLEE C wrapper for these Rust FFI functions.
        Generate symbolic inputs and call the FFI functions to test for vulnerabilities.

        FFI Code:
        ---
        {ffi_code}
        ---

        Generate the complete, runnable C code for klee_wrapper.c with optimized constraints.
        """)

        print("Calling OpenAI for KLEE wrapper generation...")

        for attempt in range(3):
            try:
                response = self.client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system_content},
                        {"role": "user", "content": user_prompt}
                    ],
                    max_tokens=2048,
                    temperature=0.0
                )

                generated_code = response.choices[0].message.content.strip()
                if "```" in generated_code:
                    generated_code = generated_code.split("```")[1]
                    if generated_code.startswith("c\n"):
                        generated_code = "\n".join(generated_code.split('\n')[1:])

                return generated_code

            except Exception as e:
                print(f"ERROR: API Request Failed (Attempt {attempt + 1}): {e}")
                if attempt < 2:
                    delay = 2 ** attempt
                    print(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    print("ERROR: Final attempt failed. Skipping KLEE generation.")
                    return None
        return None

    def generate_fuzz_wrapper(self, ffi_code):
        """Generate LibFuzzer harness using LLM"""
        system_content = """You are an expert in dynamic analysis and LibFuzzer. Your task is to generate a LibFuzzer harness.

CRITICAL REQUIREMENTS:
1. Use #![no_std] and #![no_main]
2. Create LLVMFuzzerTestOneInput function with signature: pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32
3. Convert raw pointer to slice safely using unsafe
4. Call the FFI functions with fuzzed input
5. Include panic handler and alloc error handler
6. Make it dependency-free for static linking
7. Do not include any explanation, just the raw Rust code"""

        user_prompt = textwrap.dedent(f"""
        Create a LibFuzzer harness for these Rust FFI functions.
        Generate a fuzzing harness that calls the FFI functions with fuzzed input.

        FFI Code:
        ---
        {ffi_code}
        ---

        Generate the complete, runnable Rust code for the fuzzing harness.
        """)

        print("Calling OpenAI for fuzzing harness generation...")

        for attempt in range(3):
            try:
                response = self.client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system_content},
                        {"role": "user", "content": user_prompt}
                    ],
                    max_tokens=2048,
                    temperature=0.0
                )

                generated_code = response.choices[0].message.content.strip()
                if "```" in generated_code:
                    generated_code = generated_code.split("```")[1]
                    if generated_code.startswith("rust\n"):
                        generated_code = "\n".join(generated_code.split('\n')[1:])

                return generated_code

            except Exception as e:
                print(f"ERROR: API Request Failed (Attempt {attempt + 1}): {e}")
                if attempt < 2:
                    delay = 2 ** attempt
                    print(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    print("ERROR: Final attempt failed. Skipping fuzzing generation.")
                    return None
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
                '--max-time=30',
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

    def analyze_single_file_comprehensive(self, file_path, dataset_type=None):
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
            print("Step 1: Generating FFI wrapper using LLM...")
            ffi_code = self.generate_rust_ffi_wrapper(rust_code)
            if not ffi_code:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'dataset_type': dataset_type,
                    'error': 'Failed to generate FFI wrapper',
                    'success': False
                }
            
            ffi_file = temp_file_path.replace('.rs', '_ffi.rs')
            with open(ffi_file, 'w') as f:
                f.write(ffi_code)
            print("SUCCESS: FFI wrapper generated")
            
            # Step 2: Generate KLEE wrapper using LLM
            print("Step 2: Generating KLEE wrapper using LLM...")
            klee_code = self.generate_klee_wrapper(ffi_code)
            if not klee_code:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'dataset_type': dataset_type,
                    'error': 'Failed to generate KLEE wrapper',
                    'success': False
                }
            
            klee_file = os.path.join(temp_dir, 'klee_wrapper.c')
            with open(klee_file, 'w') as f:
                f.write(klee_code)
            print("SUCCESS: KLEE wrapper generated")
            
            # Step 3: Generate Fuzzing wrapper using LLM
            print("Step 3: Generating Fuzzing wrapper using LLM...")
            fuzz_code = self.generate_fuzz_wrapper(ffi_code)
            if not fuzz_code:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'dataset_type': dataset_type,
                    'error': 'Failed to generate Fuzzing wrapper',
                    'success': False
                }
            
            fuzz_file = os.path.join(temp_dir, 'fuzz_target.rs')
            with open(fuzz_file, 'w') as f:
                f.write(fuzz_code)
            print("SUCCESS: Fuzzing wrapper generated")
            
            # Step 4: Compile Rust to bitcode
            print("Step 4: Compiling Rust to bitcode...")
            rust_bc = self.compile_rust_to_bitcode(ffi_file, temp_dir)
            if not rust_bc:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'dataset_type': dataset_type,
                    'error': 'Failed to compile Rust to bitcode',
                    'success': False
                }
            
            # Step 5: Compile C wrapper to bitcode
            print("Step 5: Compiling C wrapper to bitcode...")
            c_bc = self.compile_c_to_bitcode(klee_file, temp_dir)
            if not c_bc:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'dataset_type': dataset_type,
                    'error': 'Failed to compile C wrapper to bitcode',
                    'success': False
                }
            
            # Step 6: Link bitcode files
            print("Step 6: Linking bitcode files...")
            linked_bc = self.link_bitcode_files(rust_bc, c_bc, temp_dir)
            if not linked_bc:
                return {
                    'file_path': file_path,
                    'file_name': Path(file_path).name,
                    'dataset_type': dataset_type,
                    'error': 'Failed to link bitcode files',
                    'success': False
                }
            
            # Step 7: Run KLEE analysis
            print("Step 7: Running KLEE symbolic execution...")
            klee_results = self.run_klee_analysis(linked_bc, temp_dir)
            
            # Step 8: Run Fuzzing analysis
            print("Step 8: Running LibFuzzer dynamic analysis...")
            fuzz_results = self.run_fuzzing_analysis(fuzz_file, temp_dir)
            
            # Step 9: Compile results
            results = {
                'file_path': file_path,
                'file_name': Path(file_path).name,
                'dataset_type': dataset_type,
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
                'dataset_type': dataset_type,
                'error': str(e),
                'success': False
            }
