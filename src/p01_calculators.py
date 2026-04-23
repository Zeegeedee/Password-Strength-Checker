def pool_calculator(passIn):
    # Setup variable that helps calculate the character pool
    has_lower = False
    has_upper = False
    has_digit = False
    has_special = False

    # Checks each character to accurately measure the pool
    for char in passIn:
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

    return pool

def init_calcs_calculator(pool, final_len):
    time_data = []
    poss = pool ** final_len

    try:
        timeToCrack = poss // 4000000000000  # Speed estimate (4 trillion guesses a second)
        timeInDays = int(timeToCrack / (60 * 60 * 24))
        timeInYears = int(timeToCrack / (60 * 60 * 24 * 365))

        time_data = [
        ("Seconds", timeToCrack),
        ("Days", timeInDays),
        ("Years", timeInYears)
        ]
    except (OverflowError, MemoryError):
        print("Your password is unbelievably strong as the time it takes can't even be calculated!")  

    return time_data, timeInYears

def big_name_generator():
    names = ["", "Thousand", "Million", "Billion", "Trillion", "Quadrillion", "Quintillion", "Sextillion", "Septillion", "Octillion", "Nonillion"]
    units = ["", "Un", "Duo", "Tre", "Quattuor", "Quin", "Sex", "Septen", "Octo", "Novem"]
    tens = ["deci", "vigint", "trigint", "quadragint", "quinquagint", "sexagint", "septuagint", "octogint", "nonagint"]
    hundreds = ["Centillion", "Ducentillion", "Trecentillion", "Quadringentillion", "Quingentillion", "Sescentillion", "Septingentillion", "Octingentillion", "Nongentillion"]

    for t in tens:
        for u in units:
            names.append(u + t + "illion")

    for h in hundreds:
        names.append(h)
        for t in tens:
            for u in units:
                if u == "" and t == "":
                    continue
                names.append(u + t + h)

    return names

def final_output_calculator(time_data, names, timeInYears):
    for label, value in time_data:
        num_str = str(value)
        groupIndex = (len(num_str) - 1) // 3
        rem = len(num_str) % 3
        front = num_str[0 : (rem if rem != 0 else 3)]

    try:
        print(f"{label} to crack: {front} {names[groupIndex]} {label}")
    except IndexError:
        print(f"{label} to crack: Beyond human comprehension! (The number has {len(num_str)-1} zeros)")


    if timeInYears < 1:
        print("This password is weak. I suggest adding more numbers and symbols.")
    elif timeInYears < 1000:
        print("This password is decent, but it could be stronger.")
    elif timeInYears < 10 ** 6:
        print("This is a strong password.")
    else:
        print("This password is very strong! Absolutely Nice Password!")
