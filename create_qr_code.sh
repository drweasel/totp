#!/bin/sh

PRG="$0"
# see https://github.com/google/google-authenticator/wiki/Key-Uri-Format

usage() {
  >&2 echo
  >&2 echo "Usage:"
  >&2 echo "$PRG
    -a <SHA256|SHA512> (default: SHA256)
    -d <DIGITS>        (default: 6)
    -i <ISSUER>        (optional; queried by FreeOTP if omitted)
    -l                 (optional; add 'lock=true', e.g. FaceID in FreeOTP/IOS)
    -p <PERIOD>        (default: 30)
    -u <ACCOUNT>       (required)
    <SECRET>           (will be queried if omitted)"
}

PARGS=$(getopt -a -n ${PRG} -o a:d:i:lp:u: -- "$@")
if test "$?" != "0"; then
  usage
  exit 2
fi

_ALGORITHM=SHA256
_DIGITS=6
_ISSUER=
_LOCK=
_PERIOD=30
_ACCOUNT=
_SECRET=

eval set -- "$PARGS"
while :
do
  case "$1" in
    -a) _ALGORITHM="$2"; shift 2;;
    -d) _DIGITS="$2"; shift 2;;
    -i) _ISSUER="$2"; shift 2;;
    -l) _LOCK=1; shift 1;;
    -p) _PERIOD="$2"; shift 2;;
    -u) _ACCOUNT="$2"; shift 2;;
    --) shift; break;;
    *) echo "unexpected option $1"; usage; exit 2;;
  esac
done

if test -z "$_SECRET"; then
  _SECRET="$@"
fi

if test -z "$_ACCOUNT"; then
  >&2 echo
  >&2 echo "Error: you have to provide argument -u"
  usage
  exit 2
fi

# if the secret is not given on command line it will be read here:
if test -z "$_SECRET"; then
  >&2 echo -n "enter secret password (press enter for a random one): "
  read -s SECRET
  >&2 echo
  if test -z "$SECRET"; then
    SECRET=$(head -c 20 /dev/random | base64 -w 0)
  fi
else
  SECRET=$_SECRET
fi

# type is always totp - hotp not supported by this script
TYPE=totp

# possible values: SHA1, SHA256, SHA512
ALGORITHM="$_ALGORITHM"
# number of digits to generate; possible values: 6, 7, 8, 9
DIGITS="$_DIGITS"
# an issuer (optional)
ISSUER="$_ISSUER"
# locking
LOCK="$_LOCK"
# time period
PERIOD="$_PERIOD"
# an account (mandatory)
ACCOUNT="$_ACCOUNT"

# -----------------------------------------------------------------------------

# encode secret
#SECRET=$(<<<$SECRET base32 -w 0)
SECRET=$(echo -n $SECRET | base32 -w 0)
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
if test -n "$LOCK"; then
  PARAMETERS="${PARAMETERS}&lock=true"
fi

URL="otpauth://${TYPE}/${LABEL}?${PARAMETERS}"

# echo the URL to stderr
>&2 echo $URL

# emit a UTF8-encoded QR code to stdout
echo -n $URL | qrencode -l M -t UTF8 -o -

