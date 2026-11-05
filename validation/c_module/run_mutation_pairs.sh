#!/usr/bin/env bash
# Mutation: pairs of redundant barriers. Each single mutant survives (the other barrier still stops the
# bad output); the pair must be caught by the module tests. The edits are made in a copy of the generated benma tree
# under $C_BUILD/dm (default .work/c/build/dm), never in .work/c/benma itself.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd); cd "$ROOT"
SRCTREE=.work/c/benma
W=${C_BUILD:-$ROOT/.work/c/build}/dm
rm -rf "$W"; mkdir -p "$W"; cp -r "$SRCTREE" "$W/tree"
F=$W/tree/src/modules/anti_exfil/main_impl.h
cp "$SRCTREE/src/modules/anti_exfil/main_impl.h" "$W/main_impl.clean.h"
run() { # name, python edit snippet
    cp "$W/main_impl.clean.h" $F
    python3 - "$F" "$2" <<'PY'
import sys
f, spec = sys.argv[1], sys.argv[2]
s = open(f).read()
for old, new, nth in [x.split("@@") for x in spec.split("##")]:
    nth = int(nth); i = -1
    for _ in range(nth + 1):
        i = s.index(old, i + 1)
    s = s[:i] + new + s[i + len(old):]
open(f, "w").write(s)
PY
    TREE=$W/tree OUT=$W/benma-mutx c/build.sh benma tests-seam > /dev/null 2>&1
    if $W/benma-mutx/tests -t=anti_exfil -i=16 > $W/mutx.out 2>&1; then echo "$1: SURVIVED"; else echo "$1: KILLED ($(grep -m1 -E 'test condition failed|CHECK|failed' $W/mutx.out | cut -vectors-120))"; fi
}
K='secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);'
run "A1 schnorr_sign: no ret propagation from xonly_pub (|=) alone" "ret &= secp256k1_keypair_xonly_pub(ctx, &xonly_pk, NULL, keypair);@@ret |= secp256k1_keypair_xonly_pub(ctx, &xonly_pk, NULL, keypair);@@0"
run "A2 schnorr_sign: |= at xonly_pub AND k' fallback cmov removed" "ret &= secp256k1_keypair_xonly_pub(ctx, &xonly_pk, NULL, keypair);@@ret |= secp256k1_keypair_xonly_pub(ctx, &xonly_pk, NULL, keypair);@@0##$K@@;@@0"
run "B1 ecdsa_sign: |= at sig_sign alone" "ret &= secp256k1_ecdsa_sig_sign(@@ret |= secp256k1_ecdsa_sig_sign(@@0"
run "B2 ecdsa_sign: |= at sig_sign AND k' fallback cmov removed" "ret &= secp256k1_ecdsa_sig_sign(@@ret |= secp256k1_ecdsa_sig_sign(@@0##$K@@;@@1"
