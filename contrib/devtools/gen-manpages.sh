#!/usr/bin/env bash

export LC_ALL=C
TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
BUILDDIR=${BUILDDIR:-$TOPDIR}

BINDIR=${BINDIR:-$BUILDDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

SATCOIND=${BITCOIND:-$BINDIR/satcoind}
SATCOINCLI=${BITCOINCLI:-$BINDIR/satcoin-cli}
SATCOINTX=${BITCOINTX:-$BINDIR/satcoin-tx}
SATCOINQT=${BITCOINQT:-$BINDIR/qt/satcoin-qt}

[ ! -x $SATCOIND ] && echo "$SATCOIND not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
STCVER=($($SATCOINCLI --version | head -n1 | awk -F'[ -]' '{ print $6, $7 }'))

# Create a footer file with copyright content.
# This gets autodetected fine for bitcoind if --version-string is not set,
# but has different outcomes for bitcoin-qt and bitcoin-cli.
echo "[COPYRIGHT]" > footer.h2m
$SATCOIND --version | sed -n '1!p' >> footer.h2m

for cmd in $SATCOIND $SATCOINCLI $SATCOINTX $SATCOINQT; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=${STCVER[0]} --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-${STCVER[1]}//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
