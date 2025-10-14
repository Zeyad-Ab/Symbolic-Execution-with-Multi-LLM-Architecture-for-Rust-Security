#!/usr/bin/env python3
"""
Dataset Evaluation Script
Evaluates Positive and Negative datasets using the analyzer
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

def analyze_single_file_simple(file_path):
    """Simple analysis of a single Rust file"""
    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix="rust_analysis_")
        temp_file_path = os.path.join(temp_dir, Path(file_path).name)
        shutil.copy2(file_path, temp_file_path)
        
        # Read Rust code
        with open(file_path, 'r') as f:
            rust_code = f.read()
        
        # Simple vulnerability detection using pattern matching
        vulnerabilities = 0
        
        # Check for common vulnerability patterns
        unsafe_patterns = [
            r'unsafe\s*{',  # unsafe blocks
            r'std::ptr::',   # raw pointer operations
            r'std::mem::',   # memory operations
            r'std::slice::', # slice operations
            r'std::str::from_utf8_unchecked',  # unchecked string operations
            r'std::str::from_utf8_lossy',      # lossy string operations
            r'std::ffi::CString::from_raw',    # raw C string operations
            r'std::ffi::CStr::from_ptr',       # raw C string pointer operations
        ]
        
        for pattern in unsafe_patterns:
            import re
            matches = re.findall(pattern, rust_code, re.IGNORECASE)
            vulnerabilities += len(matches)
        
        # Check for specific vulnerability types
        if 'unsafe' in rust_code.lower():
            vulnerabilities += 1
        if 'ptr::' in rust_code:
            vulnerabilities += 1
        if 'mem::' in rust_code:
            vulnerabilities += 1
        
        # Cleanup
        shutil.rmtree(temp_dir)
        
        return {
            'file_path': file_path,
            'file_name': Path(file_path).name,
            'total_vulnerabilities': vulnerabilities,
            'vulnerabilities_detected': vulnerabilities > 0,
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
    """Evaluate Positive and Negative datasets"""
    print("DATASET EVALUATION")
    print("=" * 50)
    print("Evaluating Positive and Negative datasets")
    print()
    
    # Check if datasets exist
    if not os.path.exists("Positive") or not os.path.exists("Negative"):
        print("ERROR: Positive or Negative dataset folders not found!")
        print("Please ensure you have 'Positive' and 'Negative' folders with .rs files")
        return None
    
    # Find all Rust files
    positive_files = []
    negative_files = []
    
    for file_path in Path("Positive").rglob("*.rs"):
        positive_files.append(str(file_path))
    
    for file_path in Path("Negative").rglob("*.rs"):
        negative_files.append(str(file_path))
    
    print(f"Found {len(positive_files)} positive files and {len(negative_files)} negative files")
    
    # Run analysis
    print("Running analysis on both datasets...")
    start_time = time.time()
    
    # Analyze positive files
    positive_results = {}
    for file_path in positive_files:
        result = analyze_single_file_simple(file_path)
        positive_results[file_path] = result
    
    # Analyze negative files
    negative_results = {}
    for file_path in negative_files:
        result = analyze_single_file_simple(file_path)
        negative_results[file_path] = result
    
    analysis_time = time.time() - start_time
    
    # Calculate confusion matrix
    tp = sum(1 for r in positive_results.values() if r.get("success", False) and r.get("total_vulnerabilities", 0) > 0)
    tn = sum(1 for r in negative_results.values() if r.get("success", False) and r.get("total_vulnerabilities", 0) == 0)
    fp = sum(1 for r in negative_results.values() if r.get("success", False) and r.get("total_vulnerabilities", 0) > 0)
    fn = sum(1 for r in positive_results.values() if r.get("success", False) and r.get("total_vulnerabilities", 0) == 0)
    
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
