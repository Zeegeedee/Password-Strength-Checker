def gen_strong_pass():
    import time

    try:
        import secrets, pyperclip
    except ImportError:
        print("\nNOTE: please run the setup.py installer first.\n")
        return 0

    def pass_gen():
        secPass = "" 
        secureRand = secrets.SystemRandom()
        secCharList = []

        while True:
            secPassLen_str = input("\nHow many characters? (min 10): ")
            try:
                secPassLen_int = int(secPassLen_str)
                if secPassLen_int < 10:
                    print("\nMinimum of 10 required.")
                else:
                    break
            except ValueError:
                print("\nInvalid input. Use numbers only.")

        for i in range(secPassLen_int):
            secCharList.append(secureRand.randint(32, 126))
        
        secPass = "".join(chr(c) for c in secCharList)
        print(f"\n{secPass} is your password.")


        while True:
            choice = input("\nChoose another password? (y/n): ").lower()
            if choice in ["y", "yes"]:
                pass_gen() 
            elif choice in ["n", "no"]:
                break 
            else:
                print("Invalid input.")

        
        while True:
            choice = input("\nCopy this password? (y/n): ").lower()
            if choice in ["y", "yes"]:
                pyperclip.copy(secPass)
                print("Password copied!")
                break
            elif choice in ["n", "no"]:
                break
            else:
                print("Invalid input. Please try again.")
        
        while True:
            from . import app

            choice = input("\nWould you like to check a password's strength? (y/n): ").lower()
            if choice.lower() in ["y", "yes"]:
                app.run_checker()
            elif choice.lower() in ["n", "no"]:
                print("Goodbye!")
                time.sleep(1.5)
                break
            else:
                print("Invalid input. Please try again.")


            
    pass_gen()