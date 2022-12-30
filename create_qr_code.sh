#!/bin/sh

# see https://github.com/google/google-authenticator/wiki/Key-Uri-Format

# if the secret is not given on command line it will be read here:
if test -z "$1"; then
  echo -n "enter secret password (press enter for a default one): "
  read -s SECRET
  if test -z "$SECRET"; then
    SECRET="Die wahnsinnige Kuh lief unablaessig um den Stall"
  fi
else
  SECRET="$1"
fi

# type is always totp - hotp not supported by this script
TYPE=totp

# number of digits to generate; possible values: 6, 7, 8, 9
DIGITS=8
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

# emit a UTF8-encoded QR code to stdout
echo -n $URL | qrencode -l M -t UTF8 -o -

