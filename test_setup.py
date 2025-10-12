#!/usr/bin/env python3
"""
Test Setup Script
Tests the project setup and basic functionality
"""
import os
import sys
from pathlib import Path

def test_imports():
    """Test if required modules can be imported"""
    print("Testing imports...")
    
    try:
        import json
        import time
        import subprocess
        import tempfile
        import shutil
        from datetime import datetime
        print("SUCCESS: Standard library imports: OK")
    except ImportError as e:
        print(f"ERROR: Standard library import failed: {e}")
        return False
    
    try:
        import openai
        print("SUCCESS: OpenAI import: OK")
    except ImportError:
        print("WARNING: OpenAI not installed (optional for LLM features)")
    
    return True

def test_files():
    """Test if required files exist"""
    print("\nTesting files...")
    
    required_files = [
        'onefile.py',
        'allrust.py', 
        'evaluate_datasets.py',
        'config.yaml',
        'requirements.txt',
        'README.md',
        'LICENSE'
    ]
    
    missing_files = []
    
    for file in required_files:
        if os.path.exists(file):
            print(f"SUCCESS: {file}: Found")
        else:
            missing_files.append(file)
            print(f"ERROR: {file}: Missing")
    
    if missing_files:
        print(f"\nERROR: Missing files: {missing_files}")
        return False
    
    return True

def test_datasets():
    """Test if datasets exist"""
    print("\nTesting datasets...")
    
    if os.path.exists('Positive') and os.path.exists('Negative'):
        pos_files = len(list(Path('Positive').glob('*.rs')))
        neg_files = len(list(Path('Negative').glob('*.rs')))
        
        print(f"SUCCESS: Positive dataset: {pos_files} files")
        print(f"SUCCESS: Negative dataset: {neg_files} files")
        
        if pos_files > 0 and neg_files > 0:
            return True
        else:
            print("ERROR: Dataset folders are empty")
            return False
    else:
        print("ERROR: Dataset folders not found")
        return False

def test_scripts():
    """Test if scripts are executable"""
    print("\nTesting scripts...")
    
    scripts = ['onefile.py', 'allrust.py', 'evaluate_datasets.py', 'setup.py']
    
    for script in scripts:
        if os.path.exists(script):
            if os.access(script, os.X_OK):
                print(f"SUCCESS: {script}: Executable")
            else:
                print(f"WARNING: {script}: Not executable (run: chmod +x {script})")
        else:
            print(f"ERROR: {script}: Not found")
    
    return True

def main():
    """Main test function"""
    print("Cracking Unsafe Rust - Setup Test")
    print("=" * 50)
    
    tests = [
        ("Imports", test_imports),
        ("Files", test_files),
        ("Datasets", test_datasets),
        ("Scripts", test_scripts)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\nTesting {test_name}...")
        if test_func():
            print(f"SUCCESS: {test_name}: PASSED")
            passed += 1
        else:
            print(f"ERROR: {test_name}: FAILED")
    
    print(f"\nTest Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("SUCCESS: All tests passed! Project is ready to use.")
        print("\nQuick start:")
        print("1. Run setup: python3 setup.py")
        print("2. Test single file: python3 onefile.py example.rs")
        print("3. Test folder: python3 allrust.py ./rust_code/")
        print("4. Evaluate datasets: python3 evaluate_datasets.py")
    else:
        print("WARNING: Some tests failed. Please check the issues above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
