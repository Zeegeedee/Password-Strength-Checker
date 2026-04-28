import os
import sys
import time

script_dir = os.path.dirname(os.path.abspath(__file__))

commonPasswords = set()
mathConstants = []
englishDictionary = []

# Verify file names match your local files (If you happen to change the name of the files, change the second argument of PathCP and PathED to match the new names)
filePathCP = os.path.join(script_dir, "..", "checkers_text_folder", "01_10k_most_common.txt")
filePathED = os.path.join(script_dir, "..", "checkers_text_folder", "02_words_alpha.txt")
filePathMC = os.path.join(script_dir, "..", "checkers_text_folder", "03_master_constants.txt")

# Load common passwords
if os.path.exists(filePathCP):
    with open(filePathCP, "r", encoding="utf-8") as f:
        for line in f:
            commonPasswords.add(line.strip().lower())

# Load math common math constants
if os.path.exists(filePathMC):
    with open(filePathMC, "r", encoding="utf-8") as f:
        for line in f:
            mathConstants.append(line.strip())

# Load dictionary and sort by length (longest words first to remove longer dictionary words from the password)
if os.path.exists(filePathED):
    with open(filePathED, "r", encoding="utf-8-sig") as f:
        for line in f:
            word = line.strip().lower()
            if len(word) >= 3:
                englishDictionary.append(word)
    englishDictionary.sort(key=len, reverse=True)

def pot_crash_checker(passIn):
    while True:
        if len(passIn) > 5000:
            print(f"WARNING: Your passwrd is very long. Checking a password of this length ({passIn} characters) is like running a DoS attack on your own RAM")
            change = input("Would you like to change your password? (y/n): ")
            if change.lower() == "y" or change == "yes":
                print("")
            else:
                break

def blank_pass_checker(passIn):
    while True:      
        if not passIn:
            print("\nPassword can not be blank.")
            passIn = input("\nInput Password to check its strength: ").strip()
        else:
            return passIn
        
def common_pass_checker(passIn, isV):
    tempPassword = passIn.lower()

    # Check against 10k most common passwords list
    original_len = len(passIn)
    for common in commonPasswords:
        if common in tempPassword:
            if (original_len - len(common)) < 8:
                isV = True
                print("This is a very common password making it very weak.")
                return isV
            
def pass_len_checker(passIn, isV):
    # Checks if the password is shorter than 8 characters
    if len(passIn) < 8:
        isV = True
        print("This password is very weak because it is shorter than 8 characters. I suggest adding more characters.")
        return isV
    
def pass_rep_checker(passIn, isV):
    original_len = len(passIn)
    tempPassword = passIn.lower()

    # Skip if password is 50+ characters
    if original_len < 50:
        uniqueCharSet = set(tempPassword)
        uniqueCS_len = len(uniqueCharSet)

        isSpammy = False

        if original_len <= 10:
            if uniqueCS_len < 4: 
                isSpammy = True
        elif original_len <= 20:
            if uniqueCS_len < 6:
                isSpammy = True
        else:
            # If unique chars are less than 25% of the total length
            if uniqueCS_len < (original_len / 4):
                isSpammy = True
        
        if isSpammy:
            isV = True
            print("Your password has too many repeated characters. I suggest adding more unique characters.")

    return isV

def dictAttack_vul_checker(passIn, isV):
    tempPassword = passIn.lower()
    wordsFound = 0
    requiredLen = 8
    original_len = len(passIn)
    passwordNW = ""
    
    for word in englishDictionary:
        if word in tempPassword:
            wordsFound += 1
            requiredLen += len(word)
            
            # The while loop is for removing all occurrences of a word found.
            while word in tempPassword:
                start = tempPassword.find(word)
                end = start + len(word)
                passwordNW = passwordNW[:start] + passwordNW[end:]
                tempPassword = tempPassword[:start] + tempPassword[end:]

    result = ""
    if len(passIn) < requiredLen and wordsFound < 5:
        isV = True
        print(f"This password is weak. Using {wordsFound} dictionary word/s requires at least {requiredLen} characters as the length of the dictionary words add up to {requiredLen - 8}.")
        return original_len, result
    elif wordsFound >= 5:
        final_len = original_len
        result = "final_len"
        return final_len, result
    else:
        final_len = original_len - (requiredLen - 8) + (wordsFound * 2)
        result = final_len
        return final_len, result


def math_const_checker(passIn, isV):
    tempPassword = passIn.lower()

    constantNames = ["Pi", "Euler's Number", "The Golden Ratio", "The Silver Ratio", "The Bronze Ratio," "Square root of 2", "Square root of 3", "Tau (2x Pi)"]
    if len(tempPassword) >= 5:
        for index, constant in enumerate(mathConstants):
            cleanConst = constant.strip()
            noDotConst = cleanConst.replace(".", "")

            if tempPassword in cleanConst or tempPassword in noDotConst:
                isV = True

                name = constantNames[index] 
                print(f"This password is weak as it is part of a famous mathematical constant called {name}")
                #break 
                
        return isV


def res_exit_checker():
    while True:
        choice = input("\nCheck another password? (y/n): ").lower().strip()
        if choice in ["y", "yes"]:
            break
        elif choice in ["n", "no"]:
            print("Goodbye!")
            time.sleep(1)
            sys.exit()
        else: 
            print("\nInvalid input. Please try again.")
            