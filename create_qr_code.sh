#!/bin/sh

# see https://github.com/google/google-authenticator/wiki/Key-Uri-Format

TYPE=totp
SECRET="Die wahnsinnige Kuh lief unablaessig um den Stall"

# number of digits to generate; possible values: 6, 7, 8, 9
DIGITS=6
# time period
PERIOD=30

# possible values: SHA1, SHA256, SHA512
ALGORITHM=SHA256

# an account (mandatory)
ACCOUNT="john.doe@acme.com"
# an issuer (optional)
ISSUER="ACME Co"

# -----------------------------------------------------------------------------

# encode secret
SECRET=$(<<<$SECRET base32 -w 0)
# remove padding
SECRET=${SECRET%%=*}
# urlencode special characters
urlencode() {
  local s="$1"
  s=${s//%/%25}
  s=${s// /%20}
  s=${s//\"/%22}
  s=${s//\#/%23}
  s=${s//\$/%24}
  s=${s//\&/%26}
  s=${s//+/%2B}
  s=${s//,/%2C}
  s=${s//\//%2F}
  s=${s//:/%3A}
  s=${s//;/%3B}
  s=${s//=/%3D}
  s=${s//\?/%3F}
  s=${s//@/%40}
  s=${s//\[/%5B}
  s=${s//\]/%5D}
  echo $s
}

ACCOUNT=$(urlencode "$ACCOUNT")
if test -n "$ISSUER"; then
  ISSUER=$(urlencode "$ISSUER")
  LABEL=${ISSUER}:${ACCOUNT}
else
  LABEL=${ACCOUNT}
fi

PARAMETERS="secret=${SECRET}&algorithm=${ALGORITHM}&digits=${DIGITS}&period=${PERIOD}"

URL="otpauth://${TYPE}/${LABEL}?${PARAMETERS}"

# echo the URL to stderr
>&2 echo $URL

# emit a SVG file to stdout
echo -n $URL | qrencode -t UTF8 -o -

