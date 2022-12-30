extern "C"
{
#include <sodium.h>
}

#include <bit>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

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

#if 0
	uint32_t dbc = (in[offset] & 0x7f) << 24 | (in[offset + 1] & 0xff) << 16 |
	               (in[offset + 2] & 0xff) << 8 | (in[offset + 3] & 0xff);
#else
	uint32_t dbc = in[offset] & 0x7f;
	for (int k = 1; k < 4; ++k)
		dbc = (dbc << 8) | (in[(offset + k) % in_len] & 0xff);
#endif
	return dbc;
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

} // anonymous namespace

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
    int t0)
{
	if (period == 0) throw std::invalid_argument("period must be non-zero");
	if (digits > 9)
		throw std::invalid_argument("digits must not exceed the value 9");
	if (sodium_init() < 0) throw std::runtime_error("sodium_init() failed");

	// decode the secret
	auto key_plain_len_max = base32_length_decoded(std::strlen(b32_secret));
	auto key_plain = std::make_unique<uint8_t[]>(key_plain_len_max);
	ssize_t key_len = base32_decode(b32_secret, key_plain.get());
	if (key_len < 0)
		throw std::invalid_argument("BASE32-decoding of secret failed");

	// prepare a key for the HMACSHA512 algorithm
	unsigned char key[crypto_auth_hmacsha512_KEYBYTES] = {};
	if (key_len < ssize_t(crypto_auth_hmacsha512_KEYBYTES))
	{
		std::cerr << "W: your secret key is too short (" << key_len
		          << " bytes) - it should have exactly "
		          << crypto_auth_hmacsha512_KEYBYTES << " bytes" << std::endl;
	}
	if (key_len > ssize_t(crypto_auth_hmacsha512_KEYBYTES))
	{
		std::cerr << "W: your secret key is too long (" << key_len
		          << " bytes) - it should have exactly "
		          << crypto_auth_hmacsha512_KEYBYTES << " bytes" << std::endl;
	}
	std::memcpy(key, key_plain.get(),
	    key_len < crypto_auth_hmacsha512_KEYBYTES
	        ? key_len
	        : crypto_auth_hmacsha512_KEYBYTES);

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
	uint64_t ts = (ts_utc + t0) / period;

	// convert the timestamp to big endian (if required)
	if constexpr (std::endian::native == std::endian::little) ts = byteswap(ts);

	// compute the HMACSHA512
	unsigned char hmac[crypto_auth_hmacsha512_BYTES] = {};
	crypto_auth_hmacsha512(hmac, (const unsigned char *)&ts, sizeof(ts), key);

	// pick some digits and return them as OTP
	uint64_t dbc = dyn_truncate(hmac, crypto_auth_hmacsha512_BYTES);
	uint64_t totp = dbc % ipow(10, digits);

	std::stringstream sstr;
	sstr << std::setw(digits) << std::setfill('0') << std::to_string(totp);
	return sstr.str();
}

