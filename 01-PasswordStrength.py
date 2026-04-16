import sys
import os

# Set limit for large integer to string conversions (important for big illion names)
sys.set_int_max_str_digits(1000000)
script_dir = os.path.dirname(os.path.abspath(__file__))

commonPasswords = set()
englishDictionary = []

# Verify file names match your local files
filePathCP = os.path.join(script_dir, "02-10k-most-common.txt")
filePathED = os.path.join(script_dir, "03-words_alpha.txt")

# Load common passwords
if os.path.exists(filePathCP):
    with open(filePathCP, "r", encoding="utf-8") as f:
        for line in f:
            commonPasswords.add(line.strip().lower())

# Load dictionary and sort by length (longest words first to remove longer dictionary words from the password)
if os.path.exists(filePathED):
    with open(filePathED, "r", encoding="utf-8") as f:
        for line in f:
            word = line.strip().lower()
            if len(word) > 3:
                englishDictionary.append(word)
    englishDictionary.sort(key=len, reverse=True)

while True:
    while True:      
        passwordInput = input("\nInput Password to check its strength: ").strip()
        if not passwordInput:
            print("Password can not be blank.")
        else:
            break

    # Setup variables
    passwordNW = passwordInput  # This copy will have the dictionary words removed
    original_len = len(passwordInput)
    tempPassword = passwordInput.lower()
    isVulnerable = False

    # Calculates the character pool
    has_lower = False
    has_upper = False
    has_digit = False
    has_special = False

    # 2. Look at every single character one by one
    for char in passwordInput:
        if char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif char.isdigit():
            has_digit = True
        elif not char.isalnum():
            has_special = True

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_special:
        pool += 33
    if not pool:
        pool = 1


    # Check against 10k most common passwords list
    for common in commonPasswords:
        if common in tempPassword:
            if (original_len - len(common)) < 8:
                isVulnerable = True
                print("This is a very common password making it very weak.")
                break

    if not isVulnerable:
        # Skip if password is 50+ characters
        if original_len < 50:
            uniqueCharSet = set()
            charList = []

            for char in tempPassword:
                charList.append(char)

            uniqueCharSet.update(charList)
            uniqueCS_len = len(uniqueCharSet)

            isSpammy = False
            if original_len <= 10:
                if uniqueCS_len < 4: 
                    isSpammy = True
            elif original_len <= 20:
                if uniqueCS_len < 6:
                    isSpammy = True
            else:
                # If unique chars are less than 25% of total length
                if uniqueCS_len < (original_len / 4):
                    isSpammy = True
            
            if isSpammy:
                isVulnerable = True
                print("Your password has too many repeated characters. I suggest adding more unique characters.")
        else:
            print("Your password is very long (50+ chars), skipping the mass repetition test!")
   
   # Checks if the password is shorter than 8 characters
    if not isVulnerable and original_len < 8:
        isVulnerable = True
        print("This password is very weak. I suggest adding more characters.")

    # Removes dictionary words from the password as passwords may be prone to dictionary attacks.
    if not isVulnerable:
            wordsFound = 0
            
            for word in englishDictionary:
                if word in tempPassword:
                    wordsFound += 1
                    # The while loop is for removing all occurrences of a word found.
                    while word in tempPassword:
                        start = tempPassword.find(word)
                        end = start + len(word)
                        passwordNW = passwordNW[:start] + passwordNW[end:]
                        tempPassword = tempPassword[:start] + tempPassword[end:]

            # The first word found adds 8 more needed characters. After the first word, it only adds 2
            requiredLen = 8
            if wordsFound > 1:
                requiredLen += (wordsFound - 1) * 2
                
            if len(passwordInput) < requiredLen:
                isVulnerable = True
                print(f"This password is weak. Using {wordsFound} dictionary word/s requires at least {requiredLen} characters.")

    # Time Calculations (Only if it meets the safety treshold)
    if not isVulnerable:
        poss = pool ** original_len
        timeToCrack = poss // 4000000000000  # Based on your speed estimate

        timeInDays = int(timeToCrack / (60 * 60 * 24))
        timeInYears = int(timeToCrack / (60 * 60 * 24 * 365))

        # For Big Numbers
        names = ["", "Thousand", "Million", "Billion", "Trillion", "Quadrillion", "Quintillion", "Sextillion", "Septillion", "Octillion", "Nonillion"]
        units = ["", "Un", "Duo", "Tre", "Quattuor", "Quin", "Sex", "Septen", "Octo", "Novem"]
        tens = ["decillion", "vigintillion", "trigintillion", "quadragintillion", "quinquagintillion", "sexagintillion", "septuagintillion", "octogintillion", "nonagintillion"]
        hundreds = ["centillion", "ducentillion", "trecentillion", "quadringentillion", "quingentillion", "sescentillion", "septingentillion", "octingentillion", "nongentillion"]

        # Append the names list with bigger numbers
        for h in hundreds:
            for t in tens:
                for u in units:
                    names.append(u + t + h)

        time_data = [
            ("Seconds", timeToCrack),
            ("Days", timeInDays),
            ("Years", timeInYears)
        ]

        # Final Output
        for label, value in time_data:
            num_str = str(value)
            groupIndex = (len(num_str) - 1) // 3
            rem = len(num_str) % 3
            front = num_str[0 : (rem if rem != 0 else 3)]

            try:
                print(f"{label} to crack: {front} {names[groupIndex]} {label}")
            except IndexError:
                print(f"{label} to crack: Beyond human comprehension! (The number has {len(num_str)-1} zeros)")
            except Exception:
                print(f"{label} to crack: Too big to calculate.")


        if timeInYears < 1:
            print("This password is weak. I suggest adding more numbers and symbols.")
        elif timeInYears < 1000:
            print("This password is decent, but it could be stronger.")
        elif timeInYears < 10 ** 6:
            print("This is a strong password.")
        else:
            print("This password is very strong! Absolutely Nice Password!")
    # Restart or Exit
    while True:
        choice = input("\nCheck another password? (y/n): ").lower().strip()
        if choice in ["y", "yes"]:
            break
        elif choice in ["n", "no"]:
            print("Goodbye!")
            sys.exit()
        else: 
            print("\nInvalid input. Please try again.")

# End of Version 1.0 and somehow exactly 200 lines (Nice!). 