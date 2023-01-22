#pragma once

#include "otp.h"

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

private:
	Type type_ = Type::TOTP;
	HMAC algorithm_ = HMAC::SHA256;

	unsigned int digits_ = 6;
	unsigned int period_ = 30;

	std::string account_;
	std::string issuer_;
	std::string b32_secret_;

public:
	OTPAuthURI() = default;

	OTPAuthURI(std::string account,
	    std::string b32_secret,
	    HMAC algorithm = HMAC::SHA256,
	    std::string issuer = std::string(),
	    unsigned int digits = 8,
	    std::chrono::seconds period = std::chrono::seconds(30));

	static OTPAuthURI ParseURI(const std::string_view uri);
	std::string ToString() const;

	Type GetType() const { return type_; }
	HMAC GetAlgorithm() const { return algorithm_; }
	unsigned int GetDigits() const { return digits_; }
	unsigned int GetPeriod() const { return period_; }
	const std::string & GetAccount() const { return account_; }
	const std::string & GetIssuer() const { return issuer_; }
	const std::string & GetBase32Secret() const { return b32_secret_; }
};

