#!/usr/bin/env python3
"""
Dataset Evaluation Script
Evaluates Positive and Negative datasets using the enhanced analyzer
"""
import os
import sys
import time
import json
from pathlib import Path
from datetime import datetime
from enhanced_comprehensive_analyzer import EnhancedComprehensiveAnalyzer, ComprehensiveAnalysisConfig

def evaluate_datasets():
    """Evaluate Positive and Negative datasets"""
    print("🔬 DATASET EVALUATION")
    print("=" * 50)
    print("📊 Evaluating Positive and Negative datasets")
    print()
    
    # Check if datasets exist
    if not os.path.exists("Positive") or not os.path.exists("Negative"):
        print("❌ Positive or Negative dataset folders not found!")
        print("Please ensure you have 'Positive' and 'Negative' folders with .rs files")
        return None
    
    # Initialize analyzer with optimized settings
    config = ComprehensiveAnalysisConfig()
    config.max_parallel_workers = 8
    config.confidence_threshold = 0.1
    config.early_termination_threshold = 0.15
    
    analyzer = EnhancedComprehensiveAnalyzer(config)
    
    # Run analysis
    print("🔍 Running analysis on both datasets...")
    start_time = time.time()
    
    results = analyzer.run_enhanced_analysis("Positive", "Negative")
    
    analysis_time = time.time() - start_time
    
    # Extract results
    positive_results = results["positive"]
    negative_results = results["negative"]
    
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
    print(f"\n📊 CONFUSION MATRIX")
    print(f"=" * 30)
    print(f"✅ True Positives (TP):  {tp:3d} - Vulnerable files correctly identified")
    print(f"✅ True Negatives (TN):  {tn:3d} - Clean files correctly identified")
    print(f"❌ False Positives (FP): {fp:3d} - Clean files incorrectly flagged")
    print(f"❌ False Negatives (FN): {fn:3d} - Vulnerable files missed")
    print(f"📊 Total Files:          {total:3d}")
    
    print(f"\n📈 PERFORMANCE METRICS")
    print(f"=" * 30)
    print(f"🎯 Accuracy:     {accuracy:.3f} ({accuracy*100:.1f}%)")
    print(f"🎯 Precision:    {precision:.3f} ({precision*100:.1f}%)")
    print(f"🎯 Recall:       {recall:.3f} ({recall*100:.1f}%)")
    print(f"🎯 Specificity:  {specificity:.3f} ({specificity*100:.1f}%)")
    print(f"🎯 F1 Score:     {f1_score:.3f}")
    
    print(f"\n⚡ PERFORMANCE")
    print(f"=" * 30)
    print(f"⏱️  Analysis Time: {analysis_time:.2f} seconds")
    print(f"🚀 Throughput: {total / analysis_time:.1f} files/second")
    
    # Quality assessment
    print(f"\n🔍 QUALITY ASSESSMENT")
    print(f"=" * 30)
    if accuracy >= 0.8:
        print(f"✅ Excellent accuracy: {accuracy*100:.1f}%")
    elif accuracy >= 0.7:
        print(f"✅ Good accuracy: {accuracy*100:.1f}%")
    elif accuracy >= 0.6:
        print(f"📈 Fair accuracy: {accuracy*100:.1f}%")
    else:
        print(f"⚠️  Poor accuracy: {accuracy*100:.1f}%")
    
    if precision >= 0.8:
        print(f"✅ Excellent precision: {precision*100:.1f}%")
    elif precision >= 0.7:
        print(f"✅ Good precision: {precision*100:.1f}%")
    elif precision >= 0.6:
        print(f"📈 Fair precision: {precision*100:.1f}%")
    else:
        print(f"⚠️  Poor precision: {precision*100:.1f}%")
    
    if recall >= 0.8:
        print(f"✅ Excellent recall: {recall*100:.1f}%")
    elif recall >= 0.7:
        print(f"✅ Good recall: {recall*100:.1f}%")
    elif recall >= 0.6:
        print(f"📈 Fair recall: {recall*100:.1f}%")
    else:
        print(f"⚠️  Poor recall: {recall*100:.1f}%")
    
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
        },
        "config": {
            "confidence_threshold": config.confidence_threshold,
            "early_termination_threshold": config.early_termination_threshold,
            "max_parallel_workers": config.max_parallel_workers
        }
    }
    
    with open(report_file, 'w') as f:
        json.dump(evaluation_data, f, indent=2)
    
    print(f"\n📄 Evaluation report saved to: {report_file}")
    
    return evaluation_data

if __name__ == "__main__":
    results = evaluate_datasets()
