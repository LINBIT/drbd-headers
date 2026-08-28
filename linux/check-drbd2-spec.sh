#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Validate linux/drbd2.yaml with the unmodified YNL tooling of a Linux kernel
# source tree ($KDIR):
#   1. JSON-schema validation (pyynl cli --validate)
#   2. user-mode C generation compiles against tools/net/ynl/lib
#   3. RST documentation renders
#   4. every definition, enum entry, attribute set, attribute and operation
#      has a doc
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SPEC="$HERE/drbd2.yaml"

: "${KDIR:?set KDIR to a Linux kernel source tree}"
PYYNL="$KDIR/tools/net/ynl/pyynl"
SCHEMA="$KDIR/Documentation/netlink/genetlink.yaml"
for f in "$PYYNL/cli.py" "$PYYNL/ynl_gen_c.py" "$PYYNL/ynl_gen_rst.py" "$SCHEMA" "$KDIR/tools/net/ynl/lib/ynl.h"; do
	[ -f "$f" ] || { echo "error: $f not found; KDIR must be a kernel source tree" >&2; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "[1/4] schema validation"
python3 "$PYYNL/cli.py" --spec "$SPEC" --schema "$SCHEMA" --validate

echo "[2/4] user-mode generation + compile"
# ynl_gen_c.py needs the spec inside a kernel-like tree (see generate-drbd2.sh);
# use a throwaway one for the user-mode compile check.
mkdir -p "$tmp/k/Documentation/netlink/specs" "$tmp/linux"
touch "$tmp/k/MAINTAINERS"
ln -s "$SCHEMA" "$tmp/k/Documentation/netlink/genetlink.yaml"
cp "$SPEC" "$tmp/k/Documentation/netlink/specs/drbd2.yaml"
KSPEC="$tmp/k/Documentation/netlink/specs/drbd2.yaml"
python3 "$PYYNL/ynl_gen_c.py" --mode uapi --header --spec "$KSPEC" -o "$tmp/linux/drbd2.h"
python3 "$PYYNL/ynl_gen_c.py" --mode user --header --spec "$KSPEC" -o "$tmp/drbd2-user.h"
python3 "$PYYNL/ynl_gen_c.py" --mode user --source --spec "$KSPEC" -o "$tmp/drbd2-user.c"
gcc -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
	-I "$KDIR/tools/net/ynl/lib" -I "$tmp" -c "$tmp/drbd2-user.c" -o "$tmp/drbd2-user.o"

echo "[3/4] RST rendering"
python3 "$PYYNL/ynl_gen_rst.py" -i "$SPEC" -o "$tmp/drbd2.rst"

echo "[4/4] doc coverage"
python3 - "$SPEC" <<'PY'
import sys, yaml
s = yaml.safe_load(open(sys.argv[1]))
missing = []
for d in s.get('definitions', []):
    if 'doc' not in d: missing.append(f"definition {d['name']}")
    for e in d.get('entries', []):
        if not isinstance(e, dict) or 'doc' not in e:
            name = e if isinstance(e, str) else e.get('name')
            missing.append(f"enum entry {d['name']}.{name}")
for a in s['attribute-sets']:
    if 'doc' not in a: missing.append(f"attribute-set {a['name']}")
    for x in a['attributes']:
        if 'doc' not in x: missing.append(f"attribute {a['name']}.{x['name']}")
for o in s['operations']['list']:
    if 'doc' not in o: missing.append(f"operation {o['name']}")
if missing:
    print(f"{len(missing)} items without doc:"); print("\n".join("  " + m for m in missing))
    sys.exit(1)
print("all definitions, enum entries, attribute-sets, attributes and operations documented")
PY
echo "OK: $SPEC"
