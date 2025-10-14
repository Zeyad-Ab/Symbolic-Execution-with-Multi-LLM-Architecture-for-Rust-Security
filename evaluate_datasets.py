#!/usr/bin/env python3
"""
Dataset Evaluation Script
Evaluates Positive and Negative datasets using the original enhanced analyzer
"""
import os
import sys
import time
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from simple_comprehensive_analyzer import analyze_comprehensive_dataset

def analyze_single_file_enhanced(file_path):
    """Enhanced analysis of a single Rust file with sophisticated vulnerability detection"""
    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix="rust_analysis_")
        temp_file_path = os.path.join(temp_dir, Path(file_path).name)
        shutil.copy2(file_path, temp_file_path)
        
        # Read Rust code
        with open(file_path, 'r') as f:
            rust_code = f.read()
        
        # Enhanced vulnerability detection using sophisticated patterns
        vulnerabilities = 0
        vulnerability_types = []
        
        # Advanced vulnerability patterns
        vulnerability_patterns = {
            'buffer_overflow': [
                r'unsafe\s*\{[^}]*ptr::[^}]*\}',  # unsafe pointer operations
                r'std::ptr::(write|read|copy|copy_nonoverlapping)',  # direct memory operations
                r'std::slice::from_raw_parts',  # raw slice creation
                r'std::mem::(transmute|forget|uninitialized)',  # dangerous memory operations
            ],
            'integer_overflow': [
                r'\.wrapping_add\(',  # wrapping arithmetic
                r'\.wrapping_sub\(',  # wrapping subtraction
                r'\.wrapping_mul\(',  # wrapping multiplication
                r'std::num::Wrapping',  # wrapping types
            ],
            'use_after_free': [
                r'std::ptr::(drop_in_place|read)',  # manual memory management
                r'std::mem::(forget|drop)',  # memory lifecycle issues
                r'Box::from_raw',  # raw pointer to box conversion
            ],
            'null_pointer_dereference': [
                r'\.unwrap\(\)',  # unwrap calls
                r'\.expect\(',  # expect calls
                r'std::ptr::null',  # null pointer creation
                r'std::ptr::null_mut',  # null mutable pointer
            ],
            'memory_leak': [
                r'std::mem::forget',  # memory forgetting
                r'std::rc::Rc::new',  # reference counting
                r'std::sync::Arc::new',  # atomic reference counting
                r'Box::leak',  # box leaking
            ],
            'unsafe_pointer_operations': [
                r'unsafe\s*\{[^}]*\*[^}]*\}',  # unsafe dereferencing
                r'std::ptr::(offset|add|sub)',  # pointer arithmetic
                r'std::ptr::(as_ref|as_mut)',  # pointer to reference conversion
            ],
            'string_vulnerabilities': [
                r'std::str::from_utf8_unchecked',  # unchecked UTF-8
                r'std::str::from_utf8_lossy',  # lossy UTF-8 conversion
                r'std::ffi::(CString|CStr)::from_raw',  # raw C string operations
            ],
            'concurrency_issues': [
                r'std::sync::(Mutex|RwLock)::new',  # synchronization primitives
                r'std::thread::spawn',  # thread spawning
                r'std::sync::atomic',  # atomic operations
            ]
        }
        
        # Check each vulnerability type
        for vuln_type, patterns in vulnerability_patterns.items():
            for pattern in patterns:
                import re
                matches = re.findall(pattern, rust_code, re.IGNORECASE | re.MULTILINE)
                if matches:
                    vulnerabilities += len(matches)
                    vulnerability_types.append(vuln_type)
        
        # Additional sophisticated checks
        lines = rust_code.split('\n')
        for i, line in enumerate(lines):
            line_lower = line.lower().strip()
            
            # Check for unsafe blocks with specific patterns
            if 'unsafe' in line_lower and '{' in line:
                # Look for dangerous operations in unsafe blocks
                unsafe_content = []
                brace_count = 0
                j = i
                while j < len(lines) and brace_count >= 0:
                    current_line = lines[j]
                    unsafe_content.append(current_line)
                    brace_count += current_line.count('{') - current_line.count('}')
                    j += 1
                
                unsafe_text = '\n'.join(unsafe_content)
                if any(dangerous in unsafe_text for dangerous in ['ptr::', 'mem::', 'transmute', 'forget']):
                    vulnerabilities += 1
                    vulnerability_types.append('unsafe_block')
            
            # Check for specific vulnerability indicators
            if 'unwrap()' in line or 'expect(' in line:
                vulnerabilities += 1
                vulnerability_types.append('potential_panic')
            
            if 'transmute' in line_lower:
                vulnerabilities += 1
                vulnerability_types.append('type_transmutation')
        
        # Sophisticated vulnerability assessment
        # This mimics the original enhanced analyzer approach
        
        # Calculate risk score based on multiple factors
        risk_score = 0.0
        
        # Factor 1: Raw vulnerability count (weighted)
        risk_score += min(0.4, vulnerabilities * 0.1)
        
        # Factor 2: High-risk vulnerability types
        high_risk_types = ['buffer_overflow', 'use_after_free', 'unsafe_pointer_operations', 'memory_leak']
        high_risk_count = sum(1 for vt in vulnerability_types if vt in high_risk_types)
        risk_score += min(0.3, high_risk_count * 0.15)
        
        # Factor 3: Code complexity and unsafe usage density
        unsafe_blocks = rust_code.count('unsafe')
        ptr_operations = rust_code.count('ptr::')
        mem_operations = rust_code.count('mem::')
        complexity_score = (unsafe_blocks + ptr_operations + mem_operations) / max(1, len(rust_code.split('\n')))
        risk_score += min(0.2, complexity_score * 0.5)
        
        # Factor 4: Specific dangerous patterns
        dangerous_patterns = [
            'transmute', 'forget', 'uninitialized', 'from_raw', 'as_ptr',
            'offset', 'add', 'sub', 'copy_nonoverlapping', 'write', 'read'
        ]
        dangerous_count = sum(rust_code.count(pattern) for pattern in dangerous_patterns)
        risk_score += min(0.1, dangerous_count * 0.05)
        
        # Normalize risk score to 0-1 range
        confidence = min(1.0, risk_score)
        
        # Use a more sophisticated threshold
        # Positive files should have higher risk scores
        # Adjust threshold based on the original system's performance
        is_vulnerable = confidence > 0.2
        
        # Cleanup
        shutil.rmtree(temp_dir)
        
        return {
            'file_path': file_path,
            'file_name': Path(file_path).name,
            'total_vulnerabilities': vulnerabilities,
            'vulnerabilities_detected': is_vulnerable,
            'vulnerability_types': list(set(vulnerability_types)),
            'confidence': confidence,
            'success': True
        }
        
    except Exception as e:
        return {
            'file_path': file_path,
            'file_name': Path(file_path).name,
            'error': str(e),
            'success': False
        }

def evaluate_datasets():
    """Evaluate Positive and Negative datasets using the original enhanced analyzer"""
    print("DATASET EVALUATION")
    print("=" * 50)
    print("Evaluating Positive and Negative datasets")
    print()
    
    # Check if datasets exist
    if not os.path.exists("Positive") or not os.path.exists("Negative"):
        print("ERROR: Positive or Negative dataset folders not found!")
        print("Please ensure you have 'Positive' and 'Negative' folders with .rs files")
        return None
    
    # Run the original enhanced comprehensive analysis
    print("Running original enhanced comprehensive analysis...")
    start_time = time.time()
    
    # Use the original enhanced analyzer
    report = analyze_comprehensive_dataset("Positive", "Negative")
    
    analysis_time = time.time() - start_time
    
    if not report:
        print("ERROR: Analysis failed")
        return None
    
    # Extract results from the comprehensive report
    detailed_results = report.get("detailed_results", {})
    
    # Separate positive and negative results
    positive_results = {k: v for k, v in detailed_results.items() if v.get("dataset_type") == "positive"}
    negative_results = {k: v for k, v in detailed_results.items() if v.get("dataset_type") == "negative"}
    
    # Calculate confusion matrix using the original analyzer's format
    tp = sum(1 for r in positive_results.values() if r.get("success", False) and len(r.get("vulnerabilities", [])) > 0)
    tn = sum(1 for r in negative_results.values() if r.get("success", False) and len(r.get("vulnerabilities", [])) == 0)
    fp = sum(1 for r in negative_results.values() if r.get("success", False) and len(r.get("vulnerabilities", [])) > 0)
    fn = sum(1 for r in positive_results.values() if r.get("success", False) and len(r.get("vulnerabilities", [])) == 0)
    
    # Calculate metrics
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Display results
    print(f"\nCONFUSION MATRIX")
    print(f"=" * 30)
    print(f"SUCCESS: True Positives (TP):  {tp:3d} - Vulnerable files correctly identified")
    print(f"SUCCESS: True Negatives (TN):  {tn:3d} - Clean files correctly identified")
    print(f"ERROR: False Positives (FP): {fp:3d} - Clean files incorrectly flagged")
    print(f"ERROR: False Negatives (FN): {fn:3d} - Vulnerable files missed")
    print(f"Total Files:          {total:3d}")
    
    print(f"\nPERFORMANCE METRICS")
    print(f"=" * 30)
    print(f"Accuracy:     {accuracy:.3f} ({accuracy*100:.1f}%)")
    print(f"Precision:    {precision:.3f} ({precision*100:.1f}%)")
    print(f"Recall:       {recall:.3f} ({recall*100:.1f}%)")
    print(f"Specificity:  {specificity:.3f} ({specificity*100:.1f}%)")
    print(f"F1 Score:     {f1_score:.3f}")
    
    print(f"\nPERFORMANCE")
    print(f"=" * 30)
    print(f"Analysis Time: {analysis_time:.2f} seconds")
    print(f"Throughput: {total / analysis_time:.1f} files/second")
    
    # Quality assessment
    print(f"\nQUALITY ASSESSMENT")
    print(f"=" * 30)
    if accuracy >= 0.8:
        print(f"SUCCESS: Excellent accuracy: {accuracy*100:.1f}%")
    elif accuracy >= 0.7:
        print(f"SUCCESS: Good accuracy: {accuracy*100:.1f}%")
    elif accuracy >= 0.6:
        print(f"FAIR: Fair accuracy: {accuracy*100:.1f}%")
    else:
        print(f"WARNING: Poor accuracy: {accuracy*100:.1f}%")
    
    if precision >= 0.8:
        print(f"SUCCESS: Excellent precision: {precision*100:.1f}%")
    elif precision >= 0.7:
        print(f"SUCCESS: Good precision: {precision*100:.1f}%")
    elif precision >= 0.6:
        print(f"FAIR: Fair precision: {precision*100:.1f}%")
    else:
        print(f"WARNING: Poor precision: {precision*100:.1f}%")
    
    if recall >= 0.8:
        print(f"SUCCESS: Excellent recall: {recall*100:.1f}%")
    elif recall >= 0.7:
        print(f"SUCCESS: Good recall: {recall*100:.1f}%")
    elif recall >= 0.6:
        print(f"FAIR: Fair recall: {recall*100:.1f}%")
    else:
        print(f"WARNING: Poor recall: {recall*100:.1f}%")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"dataset_evaluation_{timestamp}.json"
    
    evaluation_data = {
        "confusion_matrix": {
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn
        },
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "specificity": specificity,
            "f1_score": f1_score
        },
        "performance": {
            "analysis_time": analysis_time,
            "throughput": total / analysis_time,
            "total_files": total
        },
        "dataset_info": {
            "positive_files": len(positive_results),
            "negative_files": len(negative_results),
            "successful_positive": sum(1 for r in positive_results.values() if r.get("success", False)),
            "successful_negative": sum(1 for r in negative_results.values() if r.get("success", False))
        }
    }
    
    with open(report_file, 'w') as f:
        json.dump(evaluation_data, f, indent=2)
    
    print(f"\nEvaluation report saved to: {report_file}")
    
    return evaluation_data

if __name__ == "__main__":
    results = evaluate_datasets()
