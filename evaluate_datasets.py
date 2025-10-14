#!/usr/bin/env python3
"""
Dataset Evaluation
Uses real LLM + KLEE + Fuzzing approach for dataset evaluation
Usage: python3 evaluate_datasets.py
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

class RealDatasetEvaluator:
    """Real evaluator using LLM + KLEE + Fuzzing approach for dataset evaluation"""
    
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
    
    def analyze_single_file(self, file_path, dataset_type):
        """Analyze a single Rust file using real LLM + KLEE + Fuzzing approach"""
        print(f"Analyzing: {Path(file_path).name} ({dataset_type})")
        
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
                    'dataset_type': dataset_type,
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
                    'dataset_type': dataset_type,
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
                    'dataset_type': dataset_type,
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
                    'dataset_type': dataset_type,
                    'error': 'Failed to compile Rust to bitcode',
                    'success': False
                }
            
            # Step 5: Compile C wrapper to bitcode
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
            klee_results = self.run_klee_analysis(linked_bc, temp_dir)
            
            # Step 8: Run Fuzzing analysis
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
    
    def evaluate_datasets(self):
        """Evaluate Positive and Negative datasets using real LLM + KLEE + Fuzzing approach"""
        print("REAL DATASET EVALUATION - LLM + KLEE + FUZZING")
        print("="*60)
        print("Evaluating Positive and Negative datasets")
        print()
        
        # Check if datasets exist
        if not os.path.exists("Positive") or not os.path.exists("Negative"):
            print("ERROR: Positive or Negative dataset folders not found!")
            print("Please ensure you have 'Positive' and 'Negative' folders with .rs files")
            return None
        
        # Find all files
        positive_files = self.find_rust_files("Positive")
        negative_files = self.find_rust_files("Negative")
        
        if not positive_files and not negative_files:
            print("ERROR: No Rust files found in datasets")
            return None
        
        print(f"Found {len(positive_files)} positive files and {len(negative_files)} negative files")
        print("Using real LLM + KLEE + Fuzzing approach")
        print()
        
        start_time = time.time()
        results = {}
        
        # Process all files
        all_files = []
        for file_path in positive_files:
            all_files.append((file_path, "positive"))
        for file_path in negative_files:
            all_files.append((file_path, "negative"))
        
        # Process files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all files
            future_to_file = {
                executor.submit(self.analyze_single_file, file_path, dataset_type): (file_path, dataset_type)
                for file_path, dataset_type in all_files
            }
            
            # Process completed analyses
            for future in concurrent.futures.as_completed(future_to_file):
                file_path, dataset_type = future_to_file[future]
                try:
                    result = future.result()
                    results[file_path] = result
                    
                    if result["success"]:
                        vuln_count = result["total_vulnerabilities"]
                        status = "VULNERABILITIES" if vuln_count > 0 else "CLEAN"
                        print(f"  {status}: {Path(file_path).name} ({dataset_type}): {vuln_count} vulnerabilities")
                    else:
                        print(f"  ERROR: {Path(file_path).name} ({dataset_type}): {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    print(f"  FAILED: {Path(file_path).name} ({dataset_type}): {e}")
                    results[file_path] = {
                        'file_path': file_path,
                        'file_name': Path(file_path).name,
                        'dataset_type': dataset_type,
                        'error': str(e),
                        'success': False
                    }
        
        analysis_time = time.time() - start_time
        
        # Separate positive and negative results
        positive_results = {k: v for k, v in results.items() if v.get("dataset_type") == "positive"}
        negative_results = {k: v for k, v in results.items() if v.get("dataset_type") == "negative"}
        
        # Calculate confusion matrix using real analysis results
        tp = sum(1 for r in positive_results.values() if r.get("success", False) and r.get("vulnerabilities_detected", False))
        tn = sum(1 for r in negative_results.values() if r.get("success", False) and not r.get("vulnerabilities_detected", False))
        fp = sum(1 for r in negative_results.values() if r.get("success", False) and r.get("vulnerabilities_detected", False))
        fn = sum(1 for r in positive_results.values() if r.get("success", False) and not r.get("vulnerabilities_detected", False))
        
        # Calculate metrics
        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\n" + "="*60)
        print("REAL ANALYSIS RESULTS")
        print("="*60)
        print(f"Total Files: {total}")
        print(f"Positive Files: {len(positive_results)}")
        print(f"Negative Files: {len(negative_results)}")
        print()
        
        print("CONFUSION MATRIX")
        print("="*30)
        print(f"True Positives (TP):   {tp} - Vulnerable files correctly identified")
        print(f"True Negatives (TN):   {tn} - Clean files correctly identified")
        print(f"False Positives (FP):  {fp} - Clean files incorrectly flagged")
        print(f"False Negatives (FN):  {fn} - Vulnerable files missed")
        
        print("\nPERFORMANCE METRICS")
        print("="*30)
        print(f"Accuracy:     {accuracy:.3f} ({accuracy:.1%})")
        print(f"Precision:    {precision:.3f} ({precision:.1%})")
        print(f"Recall:       {recall:.3f} ({recall:.1%})")
        print(f"Specificity:  {specificity:.3f} ({specificity:.1%})")
        print(f"F1 Score:     {f1_score:.3f}")
        
        print("\nPERFORMANCE")
        print("="*30)
        print(f"Analysis Time: {analysis_time:.2f} seconds")
        print(f"Throughput: {total / analysis_time:.1f} files/second" if analysis_time > 0 else "Throughput: N/A")
        
        print("\nQUALITY ASSESSMENT")
        print("="*30)
        if accuracy > 0.8:
            print(f"SUCCESS: Excellent accuracy: {accuracy:.1%}")
        elif accuracy > 0.6:
            print(f"GOOD: Good accuracy: {accuracy:.1%}")
        else:
            print(f"WARNING: Poor accuracy: {accuracy:.1%}")
        
        if precision > 0.9:
            print(f"SUCCESS: Excellent precision: {precision:.1%}")
        elif precision > 0.7:
            print(f"GOOD: Good precision: {precision:.1%}")
        else:
            print(f"WARNING: Poor precision: {precision:.1%}")
        
        if recall > 0.8:
            print(f"SUCCESS: Excellent recall: {recall:.1%}")
        elif recall > 0.6:
            print(f"FAIR: Fair recall: {recall:.1%}")
        else:
            print(f"WARNING: Poor recall: {recall:.1%}")
        
        # Save evaluation report
        evaluation_report = {
            "timestamp": datetime.now().isoformat(),
            "methodology": "Real LLM + KLEE + Fuzzing",
            "metrics": {
                "tp": tp, "tn": tn, "fp": fp, "fn": fn,
                "total_files": total,
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "specificity": specificity,
                "f1_score": f1_score
            },
            "analysis_time": analysis_time,
            "throughput": total / analysis_time if analysis_time > 0 else 0,
            "results": results
        }
        
        report_filename = f"real_dataset_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(evaluation_report, f, indent=2)
        print(f"\nEvaluation report saved to: {report_filename}")
        
        return evaluation_report

def main():
    """Main entry point"""
    # Check for API key
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY environment variable not set")
        print("Please set your OpenAI API key: export OPENAI_API_KEY='your-key-here'")
        sys.exit(1)
    
    # Run evaluation
    evaluator = RealDatasetEvaluator(max_workers=4)
    results = evaluator.evaluate_datasets()
    
    if results:
        print("\nSUCCESS: Real dataset evaluation completed!")
    else:
        print("ERROR: Evaluation failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
