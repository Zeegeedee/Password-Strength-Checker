def run_checker():
    import sys
    from . import p01_calculators as calculators
    from . import p02_checkers as checkers

    # Set limit for large integer to string conversions (important for big number names)
    sys.set_int_max_str_digits(1000000)

    while True:
        passwordInput = input("\nInput Password to check its strength: ").strip()
        passwordInput = checkers.blank_pass_checker(passwordInput)

        # Setup variable
        isVulnerable = False

        pool = calculators.pool_calculator(passwordInput)

        # Check against 10k most common passwords list
        isVulnerable = checkers.common_pass_checker(passwordInput, isVulnerable)

        # Checks if the password is shorter than 8 characters
        if not isVulnerable:
            isVulnerable = checkers.pass_len_checker(passwordInput, isVulnerable)

        # Checks if the password has too many repeated characters
        if not isVulnerable:
            isVulnerable = checkers.pass_rep_checker(passwordInput, isVulnerable)
    
        if not isVulnerable:
            isVulnerable = checkers.math_const_checker(passwordInput, isVulnerable)

        # Removes dictionary words from the password as passwords may be prone to dictionary attacks.
        final_len, result = checkers.dictAttack_vul_checker(passwordInput, isVulnerable)
        if result == "isV":
            isVulnerable = True
    
        # Time Calculations (Only if it meets the safety treshold)
        if not isVulnerable:
            time_data, timeInYears = calculators.init_calcs_calculator(pool, final_len)

            names = calculators.big_name_generator()

            # Final Output
            calculators.final_output_calculator(time_data, names, timeInYears)

        # Restart or Exit
        checkers.res_exit_checker()
    