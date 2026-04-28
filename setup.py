import subprocess
import sys
import importlib.util

def install_dependencies():
    dependencies = ["pyperclip"]
    
    print("--- Checking Dependencies ---")
    
    for package in dependencies:
        spec = importlib.util.find_spec(package)
        if spec is None:
            print(f"{package} not found. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        
        else:
            print(f"{package} is already installed.")

if __name__ == "__main__":
    install_dependencies()
    print("\nEverything is ready!")