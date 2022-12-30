#include "otp.h"
extern "C"
{
#include <sodium.h>
}

#include <bit>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace
{

/** Compute the number of bytes for a given BASE32 encoding */
inline constexpr std::size_t base32_length_decoded(std::size_t n_b32_chars)
{
	// each base32 symbol encodes 5 bit
	auto n_bits = n_b32_chars * 5;
	auto n_bytes = n_bits / 8;
	return n_bytes;
}

/** BASE32 decoding according to RFC 4648 */
ssize_t base32_decode(const char * b32, void * decoded)
{
	int bitbuf = 0;
	int bits_rem = 0;
	ssize_t count = 0;
	uint8_t * dec = reinterpret_cast<uint8_t *>(decoded);

	for (const char * ptr = b32; *ptr; ++ptr)
	{
		char ch = *ptr;
		if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-' ||
		    ch == '=')
			continue;
		bitbuf <<= 5;

		// handle commonly mistyped characters
		if (ch == '0')
			ch = 'O';
		else if (ch == '1')
			ch = 'L';
		else if (ch == '8')
			ch = 'B';

		// compute code of base32 digit
		if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
			ch = (ch & 0b1'1111) - 1;
		else if (ch >= '2' && ch <= '7')
			ch -= '2' - 26;
		else
			return -1;

		bitbuf |= ch;
		bits_rem += 5;
		if (bits_rem >= 8)
		{
			dec[count++] = bitbuf >> (bits_rem - 8);
			bits_rem -= 8;
		}
	}
	return count;
}

/**
 * Dynamic truncation according to RFC 4226.
 *
 * This extracts 31 bits from the hash value starting from some offset value.
 * The offset value is given by the lower nibble of the hash's last byte, i.e.
 * a number [0,15]. While this makes sense and works well for (HMAC)SHA1 it is
 * somehow strange for (HMAC)SHA256 or (HMAC)SHA512. HMACSHA512 hash values,
 * for example, are 64 bytes long.
 *
 * Another issue is that tools offering more than 9 digits makes no sense,
 * since floor(log10(2^31)) = 9.
 */
uint32_t dyn_truncate(const uint8_t * in, int in_len)
{
	int offset = in[in_len - 1] & 0xf;
	uint32_t hdigits = in[offset] & 0x7f;

	for (int k = 1; k < 4; ++k)
		hdigits = (hdigits << 8) | (in[(offset + k) % in_len] & 0xff);
	return hdigits;
}

/** Computes b^e */
inline constexpr uint64_t ipow(uint64_t b, uint64_t e)
{
	uint64_t v = 1;
	for (uint64_t k = 1; k <= e; ++k) v *= b;
	return v;
}

/** Convert between little and big endian */
inline constexpr uint64_t byteswap(uint64_t ull)
{
	return (ull >> 56) | ((ull << 40) & 0x00FF000000000000) |
	       ((ull << 24) & 0x0000FF0000000000) |
	       ((ull << 8) & 0x000000FF00000000) |
	       ((ull >> 8) & 0x00000000FF000000) |
	       ((ull >> 24) & 0x0000000000FF0000) |
	       ((ull >> 40) & 0x000000000000FF00) | (ull << 56);
}

uint64_t generate_TOTP_UTC_counter_value(unsigned int period, int t0)
{
	if (period == 0) throw std::invalid_argument("period must be non-zero");

	// get a UTC timestamp (std::system_clock::now() returns UTC!)
	auto ts_utc = std::chrono::duration_cast<std::chrono::seconds>(
	    std::chrono::system_clock::now().time_since_epoch())
	                  .count();
	// shift timestamp by given offset and divide it by the period.
	// Originally, t0 is subtracted - this makes slightly more sense.
	if (int64_t(ts_utc) + t0 < 0)
	{
		throw std::invalid_argument(
		    "invalid shift value - would result in a negative timestamp");
	}
	return (ts_utc + t0) / period;
}

} // anonymous namespace

uint32_t generate_HOTP(const char * b32_secret,
    unsigned int digits,
    uint64_t counter,
    HMAC hash_algo)
{
	std::size_t hmac_bytes, key_bytes;

	switch (hash_algo)
	{
	case HMAC::SHA256:
		hmac_bytes = crypto_auth_hmacsha256_BYTES;
		key_bytes = crypto_auth_hmacsha256_KEYBYTES;
		break;
	case HMAC::SHA512:
		hmac_bytes = crypto_auth_hmacsha512_BYTES;
		key_bytes = crypto_auth_hmacsha512_KEYBYTES;
		break;
	};

	if (digits > 9)
		throw std::invalid_argument("digits must not exceed the value 9");

	if (sodium_init() < 0) throw std::runtime_error("sodium_init() failed");

	// decode the secret
	auto key_plain_len_max = base32_length_decoded(std::strlen(b32_secret));
	auto key_plain = std::make_unique<uint8_t[]>(key_plain_len_max);
	ssize_t key_len = base32_decode(b32_secret, key_plain.get());
	if (key_len < 0)
		throw std::invalid_argument("BASE32-decoding of secret failed");

	// prepare a key for the HMAC algorithm
	if (key_len < ssize_t(key_bytes))
	{
		std::cerr << "W: your secret key is too short (" << key_len
		          << " bytes) - it should have exactly " << key_bytes
		          << " bytes" << std::endl;
	}
	if (key_len > ssize_t(key_bytes))
	{
		std::cerr << "W: your secret key is too long (" << key_len
		          << " bytes) - it should have exactly " << key_bytes
		          << " bytes" << std::endl;
	}
	auto key = std::make_unique<unsigned char[]>(key_bytes);
	std::memcpy(
	    key.get(), key_plain.get(), key_len < key_bytes ? key_len : key_bytes);

	// convert the counter to big endian (if required)
	if constexpr (std::endian::native == std::endian::little)
		counter = byteswap(counter);

	// compute the HMAC
	auto hmac = std::make_unique<unsigned char[]>(hmac_bytes);
	switch (hash_algo)
	{
	case HMAC::SHA256:
		crypto_auth_hmacsha256(hmac.get(), (const unsigned char *)&counter,
		    sizeof(counter), key.get());
		break;
	case HMAC::SHA512:
		crypto_auth_hmacsha512(hmac.get(), (const unsigned char *)&counter,
		    sizeof(counter), key.get());
		break;
	}

	// pick some digits and return them as OTP
	uint64_t otp_digits = dyn_truncate(hmac.get(), hmac_bytes);
	return static_cast<uint32_t>(otp_digits % ipow(10, digits));
}

uint32_t generate_TOTP(const char * b32_secret,
    unsigned int digits,
    unsigned int period,
    int t0,
    HMAC hash_algo,
    int64_t seconds_since_epoch)
{
	uint64_t counter = seconds_since_epoch >= 0
	                       ? static_cast<uint64_t>(seconds_since_epoch)
	                       : generate_TOTP_UTC_counter_value(period, t0);

	return generate_HOTP(b32_secret, digits, counter, hash_algo);
}

