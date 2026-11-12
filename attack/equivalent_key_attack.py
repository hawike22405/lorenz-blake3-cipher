#!/usr/bin/env python3
"""
Equivalent-key recovery against the fixed permutation-plus-XOR reference model.

Reproduces the Section 4.1 result from FIXED_PAPER.md against a *toy*
implementation of the reference schedule C_j = P_pi(j) XOR R_j.

Scope: this attacks the fixed permutation-plus-XOR reference schedule only.
It does NOT break the full Lorenz-BLAKE3 prototype (random IV per message).

Usage:
    python3 equivalent_key_attack.py --n 256 --seed 42
    python3 equivalent_key_attack.py --n 65536 --seed 42   # 3 queries total
"""

import argparse
import math
import random
import sys
from typing import List, Tuple


class FixedScheduleCipher:
    """Toy reference schedule: C_j = P_pi(j) XOR R_j."""

    def __init__(self, n: int, seed: int):
        self.n = n
        rng = random.Random(seed)
        self.pi: List[int] = list(range(n))
        for i in range(n - 1, 0, -1):
            j = rng.randrange(i + 1)
            self.pi[i], self.pi[j] = self.pi[j], self.pi[i]
        self.R: bytes = bytes(rng.randrange(256) for _ in range(n))

    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(plaintext) == self.n
        out = bytearray(self.n)
        for j in range(self.n):
            out[j] = plaintext[self.pi[j]] ^ self.R[j]
        return bytes(out)


def recover_equivalent_key(cipher: FixedScheduleCipher) -> Tuple[List[int], bytes, int]:
    """
    Equivalent-key recovery. Cost = 1 zero-query + d label queries,
    where d = ceil(log_256 n). For n=65536, d=2 => 3 queries total.
    """
    n = cipher.n
    d = max(1, math.ceil(math.log(n, 256)))

    # Query 1: all-zero plaintext -> recovers R directly.
    zero = bytes(n)
    c_zero = cipher.encrypt(zero)
    R = c_zero

    # Queries 2..d+1: encrypt d label images once each.
    # Label image t: plaintext[i] = digit_t(i) (base-256 digit at position t).
    label_ciphertexts = []
    for t in range(d):
        label = bytes(((i >> (8 * t)) & 0xFF) for i in range(n))
        label_ciphertexts.append(cipher.encrypt(label))

    # For each output position j, reconstruct the input index that maps to it.
    # recovered_pi[out_pos] = input index i such that pi(i) = out_pos.
    recovered_pi = [0] * n
    for out_pos in range(n):
        idx = 0
        for t in range(d):
            digit = label_ciphertexts[t][out_pos] ^ R[out_pos]
            idx |= digit << (8 * t)
        recovered_pi[out_pos] = idx

    # Convert to forward permutation: pi[in_pos] = out_pos.
    pi_forward = [0] * n
    for out_pos, in_pos in enumerate(recovered_pi):
        pi_forward[in_pos] = out_pos

    # recovered_pi is out->in, matching cipher.pi. Return it directly.
    return recovered_pi, R, 1 + d


def verify(cipher: FixedScheduleCipher, pi: List[int], R: bytes, trials: int = 10) -> bool:
    rng = random.Random(12345)
    for _ in range(trials):
        pt = bytes(rng.randrange(256) for _ in range(cipher.n))
        c_orig = cipher.encrypt(pt)
        c_rec = bytes(pt[pi[j]] ^ R[j] for j in range(cipher.n))
        if c_orig != c_rec:
            return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Equivalent-key recovery demo (reference model only)."
    )
    parser.add_argument("--n", type=int, default=256, help="Number of byte positions.")
    parser.add_argument("--seed", type=int, default=42, help="PRNG seed for the toy cipher.")
    args = parser.parse_args()

    cipher = FixedScheduleCipher(args.n, args.seed)
    pi_rec, R_rec, queries = recover_equivalent_key(cipher)

    ok = verify(cipher, pi_rec, R_rec)

    d = max(1, math.ceil(math.log(args.n, 256)))
    print(f"n = {args.n}, d = {d}")
    print(f"Queries used: 1 zero + {d} label = {queries} total")
    print(f"Permutation recovered: {pi_rec == cipher.pi}")
    print(f"Mask recovered:        {R_rec == cipher.R}")
    print(f"Verification on random plaintexts: {'PASS' if ok else 'FAIL'}")
    print()
    print("Scope: this attacks the fixed permutation-plus-XOR reference model only.")
    print("It does NOT break the full Lorenz-BLAKE3 prototype (random IV per message).")


if __name__ == "__main__":
    main()
