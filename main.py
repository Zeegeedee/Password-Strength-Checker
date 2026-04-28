import sys
import time
from src.app import run_checker

VERSION = "v2.0.0"

if __name__ == "__main__":
    if "main.py" in sys.argv[0]:
        from src.p03_passGen import gen_strong_pass
        print(f"Version: {VERSION}")
        while True:
            choice = input("Would you like to check your password, or generate a new password? (1/2)")
            if choice in ["1", "one"]:
                run_checker()
                break
            elif choice in ["2", "two"]:
                gen_strong_pass()
                break
            else:
                print("Invalid input. Please try again."); 
    else:
        print("Error: The file name is wrong.")
        print("Have you changed it to anything that's not 'main.py'?")
        time.sleep(3)
        sys.exit()