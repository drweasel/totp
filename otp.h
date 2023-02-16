#pragma once
#include <cstdint>

enum class HMAC
{
	SHA1,
	SHA256,
	SHA512
};

/**
 * Generation of HMAC-based one-time passwords (HOTP) according to RFC 4226.
 * This code is based on HMAC SHA256 or HMAC SHA512 and offers OTPs with
 * 6 to 9 digits.
 *
 * @param b32_secret a BASE32-encoded secret
 * @param digits the number of digits to generate
 * @param counter a counter value, used only once
 * @return a uint32_t containing the OTP
 */
extern "C" uint32_t generate_HOTP(const char * b32_secret,
    unsigned int digits,
    uint64_t counter,
    HMAC hash_algo);

/**
 * Generation of time-based one-time passwords (TOTP) according to RFC 6238.
 * This code is based on HMAC SHA256 or HMAC SHA512 and offers OTPs with
 * 6 to 9 digits.
 *
 * The last allows to provide a timestamp - if omitted, the system's current
 * timestamp (in UTC) is used.
 *
 * @param b32_secret a BASE32-encoded secret
 * @param digits the number of digits to generate
 * @param period the interval in which a key stays valid
 * @param t0 the time shift in seconds
 * @param seconds_since_epoch optional UNIX timestamp
 * @return a uint32_t containing the TOTP
 */
extern "C" uint32_t generate_TOTP(const char * b32_secret,
    unsigned int digits,
    unsigned int period,
    int t0,
    HMAC hash_algo,
    int64_t seconds_since_epoch = -1);

/**
 * Authenticate using HOTP or TOTP.
 *
 * @param uri   an otpauth URI
 * @param passwd a password to compare
 * @param cts    a counter value or a timestamp (-1 uses the current timestamp
 *    for TOTP)
 * @return true, if the provided password is correct
 */
extern "C" bool otp_authenticate(const char * uri,
    uint32_t passwd,
    int64_t cts = -1);

/**
 * Generate a random, BASE32-encoded secret of given length.
 *
 * @param buffer        pre-allocated memory for storing the secret
 * @param buffer_length length of the pre-allocated memory
 */
extern "C" void generate_b32_secret(char * buffer, unsigned int buffer_length);

