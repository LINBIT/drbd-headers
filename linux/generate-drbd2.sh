#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Generate the uapi header and the kernel-side netlink code of the drbd2
# family from linux/drbd2.yaml with the UNMODIFIED YNL generator of a Linux
# kernel source tree.
#
# The stock generator assumes it runs inside a kernel tree: it resolves the
# JSON schema relative to the spec and derives the "auto-generated from:"
# comment from the tree root. Rather than mimicking that layout here, the
# spec is copied to $KDIR/Documentation/netlink/specs/drbd2.yaml for the
# duration of the run -- exactly where it will live once upstream -- so the
# output is byte-identical to what tools/net/ynl/ynl-regen.sh produces there.
#
#   KDIR=/path/to/linux linux/generate-drbd2.sh          regenerate in place
#   KDIR=/path/to/linux linux/generate-drbd2.sh --check  diff against a fresh
#                                                        run, exit 1 on drift
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SPEC="$HERE/drbd2.yaml"

: "${KDIR:?set KDIR to a Linux kernel source tree (tools/net/ynl is not part of kernel-devel packages)}"
GEN="$KDIR/tools/net/ynl/pyynl/ynl_gen_c.py"
for f in "$GEN" "$KDIR/Documentation/netlink/genetlink.yaml" "$KDIR/MAINTAINERS"; do
	[ -f "$f" ] || { echo "error: $f not found; KDIR must be a kernel source tree" >&2; exit 1; }
done

KSPEC="$KDIR/Documentation/netlink/specs/drbd2.yaml"
cleanup_kspec=0
if [ -e "$KSPEC" ]; then
	cmp -s "$SPEC" "$KSPEC" || {
		echo "error: $KSPEC exists and differs from $SPEC" >&2
		echo "       (kernel tree already carries a drbd2 spec; reconcile them first)" >&2
		exit 1
	}
else
	cp "$SPEC" "$KSPEC"
	cleanup_kspec=1
fi
tmp="$(mktemp -d)"
cleanup() { [ $cleanup_kspec -eq 1 ] && rm -f "$KSPEC"; rm -rf "$tmp"; }
trap cleanup EXIT

gen() {  # gen <outdir>
	mkdir -p "$1/uapi/linux" "$1/linux"
	python3 "$GEN" --mode uapi   --header --spec "$KSPEC" -o "$1/uapi/linux/drbd2.h"
	python3 "$GEN" --mode kernel --header --spec "$KSPEC" -o "$1/linux/drbd2_nl_gen.h"
	python3 "$GEN" --mode kernel --source --spec "$KSPEC" -o "$1/linux/drbd2_nl_gen.c"
}

if [ "${1:-}" = "--check" ]; then
	gen "$tmp"
	rc=0
	for f in uapi/linux/drbd2.h linux/drbd2_nl_gen.h linux/drbd2_nl_gen.c; do
		diff -u "$ROOT/$f" "$tmp/$f" || rc=1
	done
	[ $rc -eq 0 ] && echo "generated drbd2 files are up to date"
	exit $rc
fi

gen "$ROOT"
echo "generated: uapi/linux/drbd2.h linux/drbd2_nl_gen.h linux/drbd2_nl_gen.c"
