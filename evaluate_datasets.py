#!/usr/bin/env python3
"""
Dataset Evaluation Tool
Evaluates Positive and Negative datasets using real LLM + KLEE + Fuzzing approach from rust_vulnerability_analyzer.py
Usage: python3 evaluate_datasets.py
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

class RealDatasetEvaluator:
    """Real evaluator using LLM + KLEE + Fuzzing approach from rust_vulnerability_analyzer.py"""
    
    def __init__(self, max_workers=4, api_key=None):
        self.max_workers = max_workers
        try:
            self.core_analyzer = CoreAnalyzer(api_key)
        except ValueError as e:
            print(f"ERROR: {e}")
            sys.exit(1)
        
        self.results = {}
        self.lock = Lock()
        
    def find_dataset_files(self, dataset_path, dataset_type):
        """Find all Rust files in the dataset"""
        rust_files = []
        dataset = Path(dataset_path)
        
        if not dataset.exists():
            print(f"ERROR: Dataset not found: {dataset_path}")
            return rust_files
        
        for file_path in dataset.rglob("*.rs"):
            rust_files.append((str(file_path), dataset_type))
        
        print(f"Found {len(rust_files)} Rust files in {dataset_type} dataset")
        return rust_files
    
    def analyze_single_file(self, file_path, dataset_type):
        """Analyze a single Rust file using real LLM + KLEE + Fuzzing approach"""
        print(f"Analyzing: {Path(file_path).name} ({dataset_type})")
        
        # Use the core analyzer from rust_vulnerability_analyzer.py
        result = self.core_analyzer.analyze_single_file_comprehensive(file_path, dataset_type)
        return result
    
    def evaluate_datasets(self):
        """Evaluate Positive and Negative datasets using real LLM + KLEE + Fuzzing approach"""
        print("REAL HYBRID DATASET EVALUATION - LLM + KLEE + FUZZING")
        print("="*70)
        
        # Find dataset files
        positive_files = self.find_dataset_files("Positive", "positive")
        negative_files = self.find_dataset_files("Negative", "negative")
        
        all_files = positive_files + negative_files
        
        if not all_files:
            print("No dataset files found!")
            return
        
        print(f"Evaluating {len(all_files)} files ({len(positive_files)} positive, {len(negative_files)} negative)...")
        print(f"Using {self.max_workers} parallel workers")
        print()
        
        # Analyze files in parallel
        start_time = time.time()
        all_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self.analyze_single_file, file_path, dataset_type): (file_path, dataset_type)
                for file_path, dataset_type in all_files
            }
            
            # Process completed tasks
            for i, future in enumerate(concurrent.futures.as_completed(future_to_file), 1):
                file_path, dataset_type = future_to_file[future]
                try:
                    result = future.result()
                    all_results.append(result)
                    
                    if result and result.get('success', False):
                        vuln_status = "VULNERABLE" if result.get('vulnerabilities_detected', False) else "SAFE"
                        print(f"[{i}/{len(all_files)}] {Path(file_path).name} ({dataset_type}): {vuln_status}")
                    else:
                        print(f"[{i}/{len(all_files)}] {Path(file_path).name} ({dataset_type}): ERROR")
                        
                except Exception as e:
                    print(f"[{i}/{len(all_files)}] {Path(file_path).name} ({dataset_type}): EXCEPTION - {e}")
                    all_results.append({
                        'file_path': file_path,
                        'file_name': Path(file_path).name,
                        'dataset_type': dataset_type,
                        'error': str(e),
                        'success': False
                    })
        
        # Calculate confusion matrix
        tp = 0  # True Positive: Vulnerable files correctly identified as vulnerable
        tn = 0  # True Negative: Safe files correctly identified as safe
        fp = 0  # False Positive: Safe files incorrectly identified as vulnerable
        fn = 0  # False Negative: Vulnerable files incorrectly identified as safe
        
        for result in all_results:
            if not result.get('success', False):
                continue
                
            dataset_type = result.get('dataset_type', '')
            vulnerabilities_detected = result.get('vulnerabilities_detected', False)
            
            if dataset_type == 'positive':
                if vulnerabilities_detected:
                    tp += 1
                else:
                    fn += 1
            elif dataset_type == 'negative':
                if vulnerabilities_detected:
                    fp += 1
                else:
                    tn += 1
        
        # Calculate metrics
        total_files = len(all_results)
        successful_analyses = sum(1 for r in all_results if r.get('success', False))
        total_vulnerabilities = sum(r.get('total_vulnerabilities', 0) for r in all_results if r.get('success', False))
        
        # Confusion matrix metrics
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        analysis_time = time.time() - start_time
        
        # Create evaluation summary
        evaluation_summary = {
            'evaluation_time': datetime.now().isoformat(),
            'total_files': total_files,
            'successful_analyses': successful_analyses,
            'total_vulnerabilities': total_vulnerabilities,
            'analysis_duration_seconds': analysis_time,
            'files_per_second': total_files / analysis_time if analysis_time > 0 else 0,
            'confusion_matrix': {
                'true_positives': tp,
                'true_negatives': tn,
                'false_positives': fp,
                'false_negatives': fn
            },
            'metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'specificity': specificity,
                'f1_score': f1_score
            },
            'results': all_results
        }
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"dataset_evaluation_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(evaluation_summary, f, indent=2)
        
        # Print evaluation summary
        print()
        print("="*70)
        print("DATASET EVALUATION SUMMARY")
        print("="*70)
        print(f"Total files: {total_files}")
        print(f"Successful analyses: {successful_analyses}")
        print(f"Total vulnerabilities found: {total_vulnerabilities}")
        print(f"Analysis time: {analysis_time:.2f} seconds")
        print(f"Files per second: {total_files / analysis_time:.2f}")
        print()
        print("CONFUSION MATRIX:")
        print(f"True Positives (TP):  {tp:3d} - Vulnerable files correctly identified")
        print(f"True Negatives (TN): {tn:3d} - Safe files correctly identified")
        print(f"False Positives (FP): {fp:3d} - Safe files incorrectly identified as vulnerable")
        print(f"False Negatives (FN): {fn:3d} - Vulnerable files incorrectly identified as safe")
        print()
        print("PERFORMANCE METRICS:")
        print(f"Accuracy:    {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"Precision:   {precision:.4f} ({precision*100:.2f}%)")
        print(f"Recall:      {recall:.4f} ({recall*100:.2f}%)")
        print(f"Specificity: {specificity:.4f} ({specificity*100:.2f}%)")
        print(f"F1 Score:    {f1_score:.4f} ({f1_score*100:.2f}%)")
        print()
        print(f"Results saved to: {results_file}")
        
        return evaluation_summary

def main():
    """Main entry point"""
    print("Starting dataset evaluation...")
    
    # Check if datasets exist
    if not os.path.exists("Positive"):
        print("ERROR: Positive dataset not found!")
        sys.exit(1)
    
    if not os.path.exists("Negative"):
        print("ERROR: Negative dataset not found!")
        sys.exit(1)
    
    # Create evaluator
    evaluator = RealDatasetEvaluator(max_workers=4)
    
    # Evaluate datasets
    results = evaluator.evaluate_datasets()
    
    if results:
        print("\nDataset evaluation completed successfully!")
    else:
        print("\nDataset evaluation failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
