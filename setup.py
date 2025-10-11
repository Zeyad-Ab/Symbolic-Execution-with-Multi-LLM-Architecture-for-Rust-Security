#!/usr/bin/env python3
"""
Setup script for Rust Vulnerability Analyzer
Automated installation and configuration
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"Running: {description}")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✓ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✓ Python {sys.version.split()[0]} detected")

def create_virtual_environment():
    """Create virtual environment"""
    if os.path.exists("venv"):
        print("Virtual environment already exists")
        return True
    
    return run_command("python3 -m venv venv", "Creating virtual environment")

def activate_and_install():
    """Activate virtual environment and install dependencies"""
    if os.name == 'nt':  # Windows
        activate_cmd = "venv\\Scripts\\activate"
        pip_cmd = "venv\\Scripts\\pip"
    else:  # Unix/Linux/macOS
        activate_cmd = "source venv/bin/activate"
        pip_cmd = "venv/bin/pip"
    
    # Install dependencies
    return run_command(f"{pip_cmd} install -r requirements.txt", "Installing dependencies")

def create_env_file():
    """Create .env file from template"""
    if os.path.exists(".env"):
        print(".env file already exists")
        return True
    
    if os.path.exists("env.template"):
        shutil.copy("env.template", ".env")
        print("✓ Created .env file from template")
        print("⚠️  Please edit .env file and add your OpenAI API key")
        return True
    else:
        print("⚠️  env.template not found, creating basic .env file")
        with open(".env", "w") as f:
            f.write("OPENAI_API_KEY=your_openai_api_key_here\n")
        return True

def create_directories():
    """Create necessary directories"""
    directories = ["results", "cache", "logs"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def run_tests():
    """Run basic tests to verify installation"""
    print("\nRunning installation tests...")
    return run_command("python3 test_positive_negative.py", "Running installation tests")

def main():
    """Main setup function"""
    print("Rust Vulnerability Analyzer - Setup Script")
    print("=" * 50)
    
    # Check Python version
    check_python_version()
    
    # Create virtual environment
    if not create_virtual_environment():
        print("Failed to create virtual environment")
        sys.exit(1)
    
    # Install dependencies
    if not activate_and_install():
        print("Failed to install dependencies")
        sys.exit(1)
    
    # Create .env file
    create_env_file()
    
    # Create directories
    create_directories()
    
    # Run tests
    if run_tests():
        print("\n" + "=" * 50)
        print("✓ Setup completed successfully!")
        print("\nNext steps:")
        print("1. Edit .env file and add your OpenAI API key")
        print("2. Run: python3 simple_comprehensive_analyzer.py")
        print("3. Check README.md for detailed usage instructions")
    else:
        print("\n" + "=" * 50)
        print("⚠️  Setup completed with warnings")
        print("Please check the error messages above")

if __name__ == "__main__":
    main()
