#!/bin/sh
# GitHub Releases installer. Unknown architecture = STOP. No guesses.
set -eu

echo "blacktemple-kn installer"
if [ ! -d /opt ]; then
  echo "STOP: /opt not found (Entware required)"
  exit 1
fi
if ! command -v opkg >/dev/null 2>&1; then
  echo "STOP: opkg not found"
  exit 1
fi

ARCH="$(opkg print-architecture 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
echo "opkg architectures: $ARCH"

case " $ARCH " in
  *" mipsel-3.4_kn "*) TARGET="mipsel-3.4_kn" ;;
  *" mipsel-3.4 "*) TARGET="mipsel-3.4" ;;
  *" mips-3.4 "*) TARGET="mips-3.4" ;;
  *)
    echo "STOP: unknown architecture, no guesses"
    exit 1
    ;;
esac

echo "selected target=$TARGET"
echo "download/verify/install not implemented in R0 hello installer"
exit 2
