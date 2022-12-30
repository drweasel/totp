#pragma once
#include <string>

/**
 * Generation of time-based one-time passwords (TOTP) according to RFC6238.
 * This code is based on HMACSHA512 and offers OTPs with 6 to 9 digits.
 *
 * @param b32_secret a BASE32-encoded secret
 * @param period the interval in which a key stays valid
 * @param digits the number of digits to generate
 * @param t0 the time shift in seconds
 * @return a string containing the TOTP
 */
std::string generateHMACSHA512_TOTP(const char * b32_secret,
    unsigned int period,
    unsigned int digits,
    int t0);

