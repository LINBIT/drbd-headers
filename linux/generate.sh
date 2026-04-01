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
    -o "$SCRIPT_DIR/drbd_nl_gen.h"

python3 "$GEN" --mode kernel --source \
    --schema "$SCHEMA" --spec "$SPEC" \
    -o "$SCRIPT_DIR/drbd_nl_gen.c"
