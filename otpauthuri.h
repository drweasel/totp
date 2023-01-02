#pragma once

#include <chrono>
#include <string>
#include <string_view>

/**
 * Parser / generator for otpauth URIs
 */
class OTPAuthURI
{
public:
	enum class Type
	{
		HOTP,
		TOTP
	};

	enum class Algorithm
	{
		SHA1,
		SHA256,
		SHA512
	};

private:
	Type type_ = Type::TOTP;
	Algorithm algorithm_ = Algorithm::SHA256;

	unsigned int digits_ = 6;
	unsigned int period_ = 30;

	std::string account_;
	std::string issuer_;
	std::string b32_secret_;

public:
	OTPAuthURI() = default;

	OTPAuthURI(std::string account,
	    std::string b32_secret,
	    Algorithm algorithm = Algorithm::SHA256,
	    std::string issuer = std::string(),
	    unsigned int digits = 8,
	    std::chrono::seconds period = std::chrono::seconds(30));

	static OTPAuthURI ParseURI(const std::string_view uri);
	std::string ToString() const;
};

