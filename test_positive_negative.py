#!/usr/bin/env python3
"""
Simple Test Script for Positive and Negative Folders
Tests the comprehensive analyzer on both datasets
"""
import os
import sys
import time
from pathlib import Path

def test_positive_negative_analysis():
    """Test the comprehensive analyzer on Positive and Negative folders"""
    print("TESTING POSITIVE AND NEGATIVE FOLDERS")
    print("="*50)
    
    # Check if folders exist
    positive_dir = Path("Positive")
    negative_dir = Path("Negative")
    
    if not positive_dir.exists():
        print("ERROR: Positive folder not found")
        return False
    
    if not negative_dir.exists():
        print("ERROR: Negative folder not found")
        return False
    
    # Count files in each folder
    positive_files = list(positive_dir.glob("*.rs"))
    negative_files = list(negative_dir.glob("*.rs"))
    
    print(f"SUCCESS: Found {len(positive_files)} positive files")
    print(f"SUCCESS: Found {len(negative_files)} negative files")
    
    # Run the comprehensive analyzer
    print("\nRunning comprehensive analysis...")
    start_time = time.time()
    
    try:
        # Import and run the analyzer
        from simple_comprehensive_analyzer import analyze_comprehensive_dataset
        
        # Run analysis
        report = analyze_comprehensive_dataset("Positive", "Negative")
        
        execution_time = time.time() - start_time
        
        if report:
            print(f"\nSUCCESS: Analysis completed in {execution_time:.2f} seconds")
            print(f"Total files analyzed: {report['metadata']['total_files']}")
            print(f"Positive files: {report['metadata']['positive_files']}")
            print(f"Negative files: {report['metadata']['negative_files']}")
            print(f"Success rate: {report['metadata']['success_rate']:.1f}%")
            print(f"Total vulnerabilities: {report['metadata']['total_vulnerabilities']}")
            print(f"Detection rate (positive): {report['positive_dataset_analysis']['detection_rate']:.1f}%")
            print(f"False positive rate (negative): {report['negative_dataset_analysis']['false_positive_rate']:.1f}%")
            
            return True
        else:
            print("ERROR: Analysis failed")
            return False
            
    except Exception as e:
        print(f"ERROR: {e}")
        return False

def main():
    """Main test function"""
    print("Starting Positive/Negative folder test...")
    
    success = test_positive_negative_analysis()
    
    if success:
        print("\nTEST PASSED: Positive and Negative analysis working correctly!")
        sys.exit(0)
    else:
        print("\nTEST FAILED: Analysis encountered errors")
        sys.exit(1)

if __name__ == "__main__":
    main()
