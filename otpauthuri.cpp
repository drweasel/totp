#include "otpauthuri.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>

OTPAuthURI::OTPAuthURI(std::string account,
    std::string b32_secret,
    Algorithm algorithm,
    std::string issuer,
    unsigned int digits,
    std::chrono::seconds period)
    : algorithm_(algorithm)
    , digits_(digits)
    , period_(static_cast<unsigned int>(period.count()))
    , account_(std::move(account))
    , issuer_(std::move(issuer))
    , b32_secret_(std::move(b32_secret))
{
}

OTPAuthURI OTPAuthURI::ParseURI(const std::string_view uri)
{
	OTPAuthURI otpauth;

	if (!uri.starts_with("otpauth://"))
		throw std::invalid_argument("URI does not start with otpauth://");

	if (uri.compare(10, 5, "hotp/") == 0)
		otpauth.type_ = Type::HOTP;
	else if (uri.compare(10, 5, "totp/") == 0)
		otpauth.type_ = Type::TOTP;
	else
		throw std::invalid_argument("URI uses unknown type");

	auto pos = uri.find_first_of('?', 15);
	if (pos == std::string_view::npos)
		throw std::invalid_argument("URI lacks obligatory parameters");

	auto label = uri.substr(15, pos - 15);

	if (label.empty())
		throw std::invalid_argument("URI lacks an account name / issuer");

	auto params = uri.substr(pos + 1);
	if ((pos = label.find_first_of(':')) != std::string_view::npos ||
	    (pos = label.find_first_of("%3A")) != std::string_view::npos)
	{
		otpauth.issuer_ = label.substr(0, pos);
		otpauth.account_ = label.substr(pos + 1);
	}
	else { otpauth.account_ = label; }

	// std::cout << "issuer_:" << otpauth.issuer_ << std::endl;
	// std::cout << "account_:" << otpauth.account_ << std::endl;
	// std::cout << "params:" << params << std::endl;

	while (!params.empty())
	{
		pos = params.find_first_of('&');
		std::string_view key_value;
		if (pos != std::string_view::npos)
		{
			key_value = params.substr(0, pos);
			params = params.substr(pos + 1);
		}
		else
		{
			key_value = params;
			params = std::string_view();
		}

		auto pos_eq = key_value.find_first_of('=');
		if (pos_eq == std::string_view::npos)
		{
			throw std::invalid_argument(
			    "error parsing parameter - missing '='");
		}

		auto key = key_value.substr(0, pos_eq);
		auto value = key_value.substr(pos_eq + 1);

		// std::cout << "key: [" << key << "] value: [" << value << "]"
		//           << std::endl;
		if (key == "algorithm")
		{
			if (value == "SHA1" || value == "sha1")
				otpauth.algorithm_ = Algorithm::SHA1;
			else if (value == "SHA256" || value == "sha256")
				otpauth.algorithm_ = Algorithm::SHA256;
			else if (value == "SHA512" || value == "sha512")
				otpauth.algorithm_ = Algorithm::SHA512;
			else
				throw std::invalid_argument("invalid HMAC algorithm specified; "
				                            "expecting (SHA1|SHA256|SHA512)");
		}
		else if (key == "secret")
			otpauth.b32_secret_ = value;
		else if (key == "digits")
		{
			otpauth.digits_ = std::atoi(std::string(value).c_str());
			if (otpauth.digits_ < 6u || otpauth.digits_ > 9u)
				throw std::invalid_argument(
				    "invalid value for 'digits'; expecting (6|7|8|9)");
		}
		else if (key == "period")
		{
			otpauth.period_ = std::atoi(std::string(value).c_str());
			if (otpauth.period_ < 1u)
				throw std::invalid_argument(
				    "invalid value for 'period'; expecting a value >=1");
		}
		else
		{
			std::cerr << "W: ignoring attribute '" << key << "'" << std::endl;
		}
	} // while

	if (otpauth.b32_secret_.empty())
		throw std::invalid_argument("parameter 'secret' is missing");
	return otpauth;
}

std::string OTPAuthURI::ToString() const
{
	std::string uri("otpauth://");
	uri += type_ == Type::HOTP ? "hotp/" : "totp/";
	if (issuer_.empty())
		uri += account_;
	else
	{
		uri += issuer_;
		uri += ':';
		uri += account_;
	}
	uri += "?secret=";
	uri += b32_secret_;
	uri += "&algorithm=";
	switch (algorithm_)
	{
	case Algorithm::SHA1: uri += "SHA1"; break;
	case Algorithm::SHA256: uri += "SHA256"; break;
	case Algorithm::SHA512: uri += "SHA512"; break;
	}
	uri += "&digits=" + std::to_string(digits_);
	uri += "&period=" + std::to_string(period_);
	return uri;
}

