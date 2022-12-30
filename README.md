# TOTP
Basic C++ TOTP implementation based on libsodium (<https://doc.libsodium.org/>).

The OTPs generated with this application are compatible with FreeOTP
(<https://freeotp.github.io>), Google Authenticator, pyotp
(<https://github.com/pyauth/pyotp>), and possibly other implementations of
RFC 4226 (HOTP) and RFC 6238 (TOTP).

## Limitations
This implementation uses supports HMAC algorithms based on SHA256 and SHA512 only.
HMAC SHA1 is currently not supported since it is not provided by libsodium.

This project is not intended for production use. Use it on your own risk.

