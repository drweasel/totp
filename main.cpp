#include "totp.h"

#include <iostream>
#include <stdexcept>
#include <string>

int main()
{
	char b32_secret[] =
	    "JF2CA2LTEBXG65BAMEQGQ2LHNBWHSIDTMVRXK4TFEBYGC43TO5SA"; // padding ===
	                                                            // omitted

	std::string totp;

	try
	{
		// for (int t0 = -10; t0 <= 20; ++t0)
		int t0 = 0;
		{
			totp = generateHMACSHA512_TOTP(b32_secret, 30, 8, t0);
			std::cout << totp << std::endl;
		}
	}
	catch (const std::exception & ex)
	{
		std::cerr << "TOTP computation failed: " << ex.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

