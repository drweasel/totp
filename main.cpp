#include "otp.h"
#include "otpauthuri.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

int main(int argc, char ** argv)
{
	if (argc != 2)
	{
		std::cerr << "please provide an otpauth URI as command line argument"
		          << std::endl;
		return EXIT_FAILURE;
	}

	OTPAuthURI otpauth_uri;
	try
	{
		otpauth_uri = OTPAuthURI::ParseURI(argv[1]);
	}
	catch (const std::invalid_argument & ex)
	{
		std::cerr << "error: " << ex.what() << std::endl;
		return EXIT_FAILURE;
	}

	if (otpauth_uri.GetType() != OTPAuthURI::Type::TOTP)
	{
		std::cerr << "error: only TOTP is currently supported" << std::endl;
		return EXIT_FAILURE;
	}

	unsigned int digits = otpauth_uri.GetDigits();
	unsigned int period = otpauth_uri.GetPeriod();
	constexpr int t0 = 0;

	try
	{
		uint32_t totp = generate_TOTP(otpauth_uri.GetBase32Secret().c_str(),
		    digits, period, t0, otpauth_uri.GetAlgorithm());

		std::stringstream sstr;
		sstr << std::setw(digits) << std::setfill('0') << std::to_string(totp);
		std::cout << sstr.str() << std::endl;

		if (otp_authenticate(argv[1], totp))
			std::cout << "success" << std::endl;
		else
			std::cout << "failed" << std::endl;
	}
	catch (const std::exception & ex)
	{
		std::cerr << "TOTP computation failed: " << ex.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

