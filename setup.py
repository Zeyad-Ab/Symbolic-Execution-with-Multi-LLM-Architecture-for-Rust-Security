#!/usr/bin/env python3
"""
Project Setup Script
Sets up the Cracking Unsafe Rust vulnerability analyzer
"""
import os
import sys
import subprocess
from pathlib import Path

def check_requirements():
    """Check if required tools are installed"""
    print("Checking requirements...")
    
    requirements = {
        'python3': 'Python 3.6+',
        'rustc': 'Rust compiler',
        'klee': 'KLEE symbolic execution engine',
        'cargo': 'Cargo package manager'
    }
    
    missing = []
    
    for tool, description in requirements.items():
        try:
            result = subprocess.run([tool, '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"SUCCESS: {description}: Found")
            else:
                missing.append(f"{description} ({tool})")
        except FileNotFoundError:
            missing.append(f"{description} ({tool})")
    
    if missing:
        print(f"\nERROR: Missing requirements:")
        for req in missing:
            print(f"   - {req}")
        print(f"\nPlease install the missing requirements and run setup again.")
        return False
    
    print("SUCCESS: All requirements satisfied!")
    return True

def install_python_dependencies():
    """Install Python dependencies"""
    print("\nInstalling Python dependencies...")
    
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)
        print("SUCCESS: Python dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to install Python dependencies: {e}")
        return False

def setup_environment():
    """Setup environment variables"""
    print("\nSetting up environment...")
    
    if not os.path.exists('.env'):
        if os.path.exists('env.template'):
            import shutil
            shutil.copy('env.template', '.env')
            print("SUCCESS: Created .env file from template")
            print("Please edit .env file with your API keys")
        else:
            print("WARNING: env.template not found, skipping environment setup")
    else:
        print("SUCCESS: .env file already exists")

def create_directories():
    """Create necessary directories"""
    print("\nCreating directories...")
    
    directories = ['results', 'reports', 'temp']
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"SUCCESS: Created directory: {directory}")

def main():
    """Main setup function"""
    print("Cracking Unsafe Rust - Project Setup")
    print("=" * 50)
    
    # Check requirements
    if not check_requirements():
        print("\nERROR: Setup failed due to missing requirements")
        sys.exit(1)
    
    # Install Python dependencies
    if not install_python_dependencies():
        print("\nERROR: Setup failed during dependency installation")
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    
    # Create directories
    create_directories()
    
    print("\nSUCCESS: Setup completed successfully!")
    print("\nNext steps:")
    print("1. Edit .env file with your API keys")
    print("2. Test with: python3 onefile.py example.rs")
    print("3. Evaluate datasets: python3 evaluate_datasets.py")
    print("4. Analyze folder: python3 allrust.py ./rust_code/")

if __name__ == "__main__":
    main()