#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Generate C headers and source from the YNL spec.
# Run from the drbd-headers directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GEN="$SCRIPT_DIR/ynl/ynl_gen_c.py"
SPEC="$SCRIPT_DIR/drbd_genl_ynl.yaml"
SCHEMA="$SCRIPT_DIR/genetlink-legacy.yaml"
UAPI_DIR="$SCRIPT_DIR/../uapi/linux"

python3 "$GEN" --mode uapi --header \
    --schema "$SCHEMA" --spec "$SPEC" \
    -o "$UAPI_DIR/drbd_genl.h"

python3 "$GEN" --mode kernel --header \
    --schema "$SCHEMA" --spec "$SPEC" \
    --struct-header linux/drbd_nl_types.h \
    -o "$SCRIPT_DIR/drbd_nl_gen.h"

python3 "$GEN" --mode kernel --source \
    --schema "$SCHEMA" --spec "$SPEC" \
    -o "$SCRIPT_DIR/drbd_nl_gen.c"

# Userspace variant for drbd-utils (parsers built on libgenl.h)
python3 "$GEN" --mode userspace --header \
    --schema "$SCHEMA" --spec "$SPEC" \
    -o "$SCRIPT_DIR/drbd_genl_userspace.h"

python3 "$GEN" --mode userspace --source \
    --schema "$SCHEMA" --spec "$SPEC" \
    -o "$SCRIPT_DIR/drbd_genl_userspace.c"

# drbd2 (modern genetlink family): generated with the unmodified YNL tooling
# of a kernel source tree, which kernel-devel packages do not carry; skip
# without KDIR (CI has none), see generate-drbd2.sh.
if [ -n "${KDIR:-}" ]; then
	"$SCRIPT_DIR/generate-drbd2.sh"
else
	echo "KDIR not set; skipping drbd2 generation (see linux/generate-drbd2.sh)" >&2
fi
