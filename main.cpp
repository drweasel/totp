#include "otp.h"

#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <sstream>
#include <iomanip>

int main()
{
	char b32_secret[] =
	    "JF2CA2LTEBXG65BAMEQGQ2LHNBWHSIDTMVRXK4TFEBYGC43TO5SA"; // padding ===

	constexpr unsigned int digits = 8u;
	constexpr unsigned int period = 30u;
	constexpr int t0 = 0;

	try
	{
		uint32_t totp = generateHMACSHA512_TOTP(b32_secret, digits, period, t0);

		std::stringstream sstr;
		sstr << std::setw(digits) << std::setfill('0') << std::to_string(totp);
		std::cout << sstr.str() << std::endl;
	}
	catch (const std::exception & ex)
	{
		std::cerr << "TOTP computation failed: " << ex.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

