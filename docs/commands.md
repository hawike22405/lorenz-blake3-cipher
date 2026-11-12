# Linux Commands — Lorenz–BLAKE3 Cipher Fix & Evaluation

Work from `/home/sp/Projects/FIX/`. All commands assume a standard Linux shell
with `cargo`, `rustc`, `python3`, `pip`, and `git` available.

---

## 0. Prerequisites

```bash
# Python deps for analysis
pip install --user numpy pillow

# Verify Rust toolchain (record the real version; 1.99.1 does not exist)
rustc --version
cargo --version
```

---

## 1. Build the reference implementation

```bash
cd /home/sp/Projects/FIX/code

# Generate a locked dependency tree (reproducible builds)
cargo generate-lockfile

# Build release
cargo build --release --locked

# Run the test suite (none yet; add unit tests for round-trip correctness)
cargo test --release --locked

# Record versions for the paper
rustc --version > ../docs/build.log 2>&1
cargo --version >> ../docs/build.log 2>&1
cat Cargo.lock >> ../docs/build.log
```

Expected binary: `code/target/release/lrz`

---

## 2. Generate a 32-byte key and test encrypt/decrypt round-trip

```bash
cd /home/sp/Projects/FIX

# Create a 32-byte random key
head -c 32 /dev/urandom > code/key.bin

# Create a small test plaintext (e.g. 256 bytes of interleaved RGBA)
head -c 256 /dev/urandom > code/test_plain.raw

# Encrypt (256 bytes = 8x8 RGBA)
./code/target/release/lrz encrypt \
  --key code/key.bin \
  --input code/test_plain.raw \
  --output code/test.lrz \
  --width 8 --height 8 --channels 4 \
  --seed 42

# Decrypt
./code/target/release/lrz decrypt \
  --key code/key.bin \
  --input code/test.lrz \
  --output code/test_dec.raw

# Verify exact recovery
cmp code/test_plain.raw code/test_dec.raw && echo "ROUND-TRIP OK"

# Verify authentication tag independently
./code/target/release/lrz verify --key code/key.bin --input code/test.lrz
```

Tamper test (tag should fail):

```bash
# Flip one payload byte
cp code/test.lrz code/test_tampered.lrz
printf '\xff' | dd of=code/test_tampered.lrz bs=1 seek=100 conv=notrunc status=none
./code/target/release/lrz verify --key code/key.bin --input code/test_tampered.lrz
# expect: INVALID + exit 1
```

---

## 3. Run statistical analysis on ciphertexts

If you have saved ciphertext images (PNG):

```bash
cd /home/sp/Projects/FIX

# Entropy + correlation of a single ciphertext
python3 analysis/stats.py --single path/to/cipher.png --mode RGBA

# NPCR/UACI between two ciphertexts (same plaintext, different nonce/IV)
python3 analysis/stats.py --cipher path/to/c1.png path/to/c2.png --channel 0 --mode RGB
```

For per-trial NPCR/UACI (500 runs), wrap the encrypt CLI in a loop and collect
means/SDs/confidence intervals (see `analysis/stats.py` `ci_mean_sd`).

---

## 4. Run the equivalent-key attack (reference model only)

```bash
cd /home/sp/Projects/FIX

# Small demo (n = 256 positions, d = 1 label query -> 2 queries total)
python3 attack/equivalent_key_attack.py --n 256 --seed 42

# Larger demo (n = 65536 = 256x256 8-bit plane, d = 2 -> 3 queries total)
python3 attack/equivalent_key_attack.py --n 65536 --seed 42
```

Expected output:
```
n = 65536, d = 2
Queries used: 1 zero + 2 label = 3 total
Permutation recovered: True
Mask recovered:        True
Verification on random plaintexts: PASS

Scope: this attacks the fixed permutation-plus-XOR reference model only.
It does NOT break the full Lorenz-BLAKE3 prototype (random IV per message).
```

**Scope reminder:** This attacks the *fixed permutation-plus-XOR reference schedule*
(`C_j = P_pi(j) XOR R_j`), not the full prototype. The prototype uses a random
IV per message, so the permutation and mask are not fixed across queries.

---

## 5. NIST SP 800-22 randomness testing (planned, not yet run)

Install the NIST STS suite or use the `sts` Python package, then:

```bash
# Convert ciphertext payload to a bitstream file
# (extract bytes from .lrz container, skip 81-byte header and 32-byte tag)
python3 - <<'EOF'
import sys
buf = open("test.lrz", "rb").read()
payload = buf[81:-32]
open("bitstream.bin", "wb").write(payload)
EOF

# Run NIST SP 800-22 on bitstream.bin (suite-specific command)
# e.g., ./assess 10000  (depending on STS build)
```

Byte entropy and Pearson correlation (Section 6 of the paper) are **not**
substitutes for NIST SP 800-22 / TestU01.

---

## 6. Reproducibility checklist (before any submission)

```bash
cd /home/sp/Projects/FIX/code

# 1. Source present?
ls -la src/

# 2. Lockfile present?
ls -la Cargo.lock

# 3. Build transcript?
cat ../docs/build.log

# 4. Commit hash (if using git)?
git -C /home/sp/Projects/FIX rev-parse HEAD 2>/dev/null || echo "init git repo"

# 5. Round-trip on two test images?
# 6. Per-trial NPCR/UACI with CIs?
# 7. NIST SP 800-22 results?
# 8. Matched baseline: AES-GCM / ChaCha20-Poly1305 on same host?
```

---

## 7. Files in this FIX folder

| Path | Purpose |
|------|---------|
| `FIXED_PAPER.md` | Corrected research paper |
| `code/Cargo.toml` | Rust manifest (pinned deps) |
| `code/src/lib.rs` | Crate root |
| `code/src/cipher.rs` | Fixed reference implementation (random IV, key separation, S-box, fixed-point Lorenz, BLAKE3 tag) |
| `code/src/main.rs` | CLI (encrypt/decrypt/verify) |
| `attack/equivalent_key_attack.py` | 3-query equivalent-key recovery (reference model only) |
| `analysis/stats.py` | Entropy, correlation, NPCR, UACI, CIs |
| `docs/build.log` | Toolchain + dependency versions (generated by build) |
