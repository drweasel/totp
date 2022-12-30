#pragma once
#include <cstdint>
#include <string>

enum class HMAC
{
	SHA256,
	SHA512
};

/**
 * Generation of counter-based one-time passwords (HOTP) according to RFC 4226.
 * This code is based on HMACSHA512 and offers OTPs with 6 to 9 digits.
 *
 * @param b32_secret a BASE32-encoded secret
 * @param digits the number of digits to generate
 * @param counter a counter value, used only once
 * @return a uint32_t containing the OTP
 */
uint32_t generate_HOTP(const char * b32_secret,
    unsigned int digits,
    uint64_t counter,
    HMAC hash_algo);

/**
 * Generation of time-based one-time passwords (TOTP) according to RFC6238.
 * This code is based on HMACSHA512 and offers OTPs with 6 to 9 digits.
 *
 * @param b32_secret a BASE32-encoded secret
 * @param digits the number of digits to generate
 * @param period the interval in which a key stays valid
 * @param t0 the time shift in seconds
 * @return a uint32_t containing the TOTP
 */
uint32_t generate_TOTP(const char * b32_secret,
    unsigned int digits,
    unsigned int period,
    int t0,
    HMAC hash_algo);

