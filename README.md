# Lorenz-BLAKE3 Image Cipher

A reproducible research prototype of a hybrid image cipher combining a fixed-point Lorenz chaotic map with keyed BLAKE3 scheduling, S-box substitution, Fisher–Yates permutation, and two-pass nonlinear feedback diffusion.

> **⚠️ Research Prototype** — This cipher has **no security proof**. Do not use for sensitive real-world data. Use AES-GCM or ChaCha20-Poly1305 instead.

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Security Analysis](#security-analysis)
- [Results](#results)
- [Limitations](#limitations)
- [Citation](#citation)
- [License](#license)

## Overview

This repository contains a reproducible reference implementation of a Lorenz–BLAKE3 hybrid image cipher, along with structural analysis scripts, an equivalent-key recovery demonstration, and statistical evaluation tools.

### Key Features

- **32-byte master key** with fresh random nonce and IV per message
- **Key separation**: independent encryption, authentication, and S-box keys
- **Fixed-point Lorenz map** (Q32.32) — avoids Float64 portability issues
- **Keyed non-linear S-box** substitution (replaces vulnerable linear XOR mixing)
- **Fisher–Yates permutation** with explicit inverse for decryption
- **Two-pass nonlinear feedback diffusion** (forward and backward)
- **BLAKE3 keyed-hash authentication tag** (~2⁻²⁵⁶ forgery bound)
- **Fail-fast decryption** — tag verified before any transformation
- **Container format**: `LRZIMG01` (81-byte header + payload + 32-byte tag)

### What This Is NOT

- Not an IND-CPA secure cipher
- Not an INT-CTXT authenticated encryption scheme with a formal proof
- Not 256-bit secure despite the 2²⁵⁶ nominal key space
- Not suitable for production use

## Project Structure

```
lorenz-blake3-cipher/
├── README.md                 # This file
├── ARCHITECTURE.md           # Detailed system architecture
├── CONTRIBUTING.md           # Contribution guidelines
├── LICENSE                   # MIT License
├── .gitignore                # Git ignore rules
├── FIXED_PAPER.md            # Research paper (Markdown)
├── FIXED_PAPER.pdf           # Research paper (PDF)
├── code/                     # Rust reference implementation
│   ├── Cargo.toml            # Rust manifest (pinned dependencies)
│   ├── Cargo.lock            # Locked dependency tree
│   ├── src/
│   │   ├── lib.rs            # Crate root
│   │   ├── cipher.rs         # Core cipher implementation
│   │   └── main.rs           # CLI (encrypt/decrypt/verify)
│   └── target/               # Build artifacts (gitignored)
├── attack/                   # Cryptanalytic demonstration
│   └── equivalent_key_attack.py   # 3-query equivalent-key recovery (reference model)
├── analysis/                 # Statistical evaluation
│   └── stats.py              # Entropy, correlation, NPCR, UACI
└── docs/                     # Documentation
    ├── build.log             # Toolchain + dependency versions
    ├── commands.md           # Linux command reference
    └── commands.pdf          # Linux command reference (PDF)
```

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the complete system architecture, including the encryption pipeline, container format, key schedule, and threat model.

## Installation

### Prerequisites

- Rust toolchain (1.99.1 or later)
- Python 3.10+ (for analysis and attack scripts)
- `numpy` and `pillow` Python packages

### Build the Rust Implementation

```bash
cd code
cargo generate-lockfile
cargo build --release --locked
```

This produces the `lrz` binary at `code/target/release/lrz`.

### Install Python Dependencies

```bash
pip install --user numpy pillow
```

## Usage

### Generate a Key

```bash
head -c 32 /dev/urandom > key.bin
```

### Encrypt

```bash
./code/target/release/lrz encrypt \
  --key key.bin \
  --input plaintext.raw \
  --output cipher.lrz \
  --width 256 \
  --height 256 \
  --channels 4 \
  --seed 42
```

### Decrypt

```bash
./code/target/release/lrz decrypt \
  --key key.bin \
  --input cipher.lrz \
  --output recovered.raw
```

### Verify Authentication Tag

```bash
./code/target/release/lrz verify \
  --key key.bin \
  --input cipher.lrz
```

### Run Unit Tests

```bash
cd code
cargo test --release --locked
```

### Statistical Analysis

```bash
# Entropy and correlation of a single ciphertext
python analysis/stats.py --single cipher.png --mode RGBA

# NPCR/UACI between two ciphertexts
python analysis/stats.py --cipher c1.png c2.png --channel 0 --mode RGB
```

### Equivalent-Key Recovery (Reference Model Only)

```bash
# Small demo (2 queries)
python attack/equivalent_key_attack.py --n 256 --seed 42

# Larger demo (3 queries, 256×256 8-bit plane)
python attack/equivalent_key_attack.py --n 65536 --seed 42
```

> **Scope**: This attack targets the fixed permutation-plus-XOR reference model [1], **not** the full Lorenz–BLAKE3 prototype (which uses a random IV per message).

## Security Analysis

### Threat Model

| Adversary Capability | Status |
|---------------------|--------|
| Ciphertext-only | Tag verification provides integrity |
| Known-plaintext | No confidentiality claim |
| Chosen-plaintext | No IND-CPA claim |
| Nonce/IV misuse | Tag verification fails on reuse detection |

### Security Goals (Explicitly Scoped)

**Provided:**
- Correctness: exact plaintext recovery on valid tag
- Authentication: forgery bounded at ~2⁻²⁵⁶ (BLAKE3 keyed hash)

**Not Claimed:**
- IND-CPA confidentiality
- Resistance to key recovery beyond the equivalent-key result
- 256-bit security

### Known Limitations

1. No security proof (IND-CPA/INT-CTXT reduction)
2. Fixed-point Lorenz cryptographic strength unanalyzed
3. Two test images only, non-standard sizes
4. No matched baseline (AES-GCM, ChaCha20-Poly1305)
5. No NIST SP 800-22 results reported
6. Equivalent-key attack targets reference model, not the full prototype

## Results

### Correctness

All saved recovered images match originals pixel-for-pixel (verified via SHA-256).

### Statistical Diagnostics (saved payloads)

| Image/Channel | Cipher Entropy (bits/byte) | Max \|r\| |
|---------------|---------------------------|-----------|
| Lena R | 7.99724 | 0.006995 |
| Lena G | 7.99662 | 0.009743 |
| Lena B | 7.99721 | 0.006571 |
| Lena A | 7.99719 | 0.006645 |
| Graphic R | 7.99987 | 0.001465 |
| Graphic G | 7.99988 | 0.001280 |
| Graphic B | 7.99986 | 0.001483 |

### IV Ablation

Disabling the random IV collapses differential diffusion:
- NPCR SD rises to ~2.18 points (Lena)
- Balanced-change NPCR falls to ~63.45% (vs ~99.6% with random IV)

This confirms the IV/BLAKE3 layer carries the avalanche property.

### Performance (AMD Ryzen 5 7235HS, 16 GB RAM)

| Resolution | Encrypt (ms) | Decrypt (ms) | Throughput (MP/s) |
|------------|-------------|-------------|-------------------|
| 256×256 | 2.671 ± 0.142 | 2.613 ± 0.387 | 24.54 |
| 1920×1080 | 87.273 ± 4.168 | 70.404 ± 2.926 | 23.76 |
| 3840×2160 | 465.365 ± 11.698 | 422.263 ± 13.521 | 17.82 |

## Citation

If you use this work, please cite the accompanying research paper:

```
[Authors] (2026) Reproducible Evaluation of a Lorenz–BLAKE3 Hybrid Image Cipher.
FIXED_PAPER.md / FIXED_PAPER.pdf
```

## License

MIT License. See [LICENSE](./LICENSE) for details.

## Disclaimer

This is a **research prototype** with **no security proof**. It is intended for academic evaluation and structural analysis only. **Do not use for sensitive real-world data.** For production use, use AES-GCM (NIST SP 800-38D) or ChaCha20-Poly1305 (RFC 8439).

## References

1. Podder D, Deb S (2024) A Fast and Secure Image Cryptosystem Based on New Row_Column Index Manipulator and Split_Join Algorithm. LNNS 918, pp 445–456.
2. Lorenz EN (1963) Deterministic Nonperiodic Flow. J Atmos Sci 20(2):130–141.
3. O'Connor J, Aumasson JP, Neves S, Wilcox-O'Hearn Z (2020) BLAKE3 One Function Fast Everywhere.
4. Alvarez G, Li S (2006) Some Basic Cryptographic Requirements for Chaos-Based Cryptosystems. Int J Bifurcation Chaos 16(8):2129–2151.
5. Wu Y, Noonan JP, Agaian S (2011) NPCR and UACI Randomness Tests for Image Encryption.
6. Rukhin A et al (2010) NIST SP 800-22 Rev 1a.
7. Dworkin M (2007) NIST SP 800-38D (GCM/GMAC).
8. Nir Y, Langley A (2018) RFC 8439 (ChaCha20-Poly1305).
