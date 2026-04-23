import sys
import time
from src.app import run_checker

VERSION = "v1.1.1"

if __name__ == "__main__":
    if "main.py" in sys.argv[0]:
        print(f"Version: {VERSION}")
        run_checker()
    else:
        print("Error: The file name is wrong.")
        print("Have you changed it to anything that's not 'main.py'?")
        time.sleep(3)
        sys.exit()