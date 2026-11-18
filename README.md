# Lorenz BLAKE3 cipher research and implementation audit

This repository contains an experimental image-byte cipher, a fixed-schedule model attack, and a **separate AES-256-GCM file tool** for practical cryptographic protection. The experimental cipher has no confidentiality or integrity proof. Its statistics do not establish security or superiority over Podder and Deb.

## Versions and compatibility

- Original repository commit: `69465bcdd7501913953c31a36816d7964440585f` (`LRZIMG01`). Its CLI seeded `StdRng` with 42 on every invocation. Different invocations repeated nonce/IV and ciphertext. It accepted trailing bytes and inconsistent geometry.
- Reviewed implementation: `LRZIMG02`, intentionally incompatible. It uses `OsRng`, checked geometry (1–4 channels, positive dimensions, at most 64 MiB), strict lengths, `subtle` tag comparison, continuous BLAKE3 XOF/rejection sampling, rescaled Q32.32 Euler arithmetic and corrected feedback. It permutes **bytes**, not complete pixels. There is no RGB mixing or plaintext-derived IV.
- The older Float64 RK4/plaintext-derived-IV experiments in the manuscript drafts are **another implementation**, not measurements of this repository. Do not attach their speed, memory or differential figures to either repository version.
- `FIXED_PAPER.md`, `FIXED_PAPER.pdf`, and `docs/commands.pdf` are historical drafts. The evaluator report, six-page IEEEtran manuscript and editable LaTeX source are supplied separately in the research package. Detailed evidence is not published in this repository. Running the evaluation creates local `review/` results.

## Install and run (Linux/macOS)

Install a Rust toolchain through [rustup](https://rustup.rs). The reviewed build used Rust 1.100.0 on Linux x86-64; CI also passed debug and release tests on Linux, Windows and macOS; the Bash demo and file wrappers were exercised locally on Linux. Python 3 is needed for scripts. Do not regenerate Cargo.lock during an ordinary build.

```bash
git clone https://github.com/hawike22405/lorenz-blake3-cipher.git
cd lorenz-blake3-cipher
bash scripts/run.sh setup
. .venv/bin/activate
bash scripts/run.sh test
bash scripts/run.sh demo
bash scripts/run.sh evaluate
```

`setup` creates `.venv`, installs Python requirements and builds the locked release crate. It requires Rust, Python 3 with venv support, and first-run network access. It does not install a compiler/toolchain for you. `build` builds Rust only.

`demo` generates synthetic 64×64 RGB raw data and a test key in a new temporary directory, encrypts, verifies, decrypts and compares bytes. `evaluate` writes all 500 ablation trial records and summaries to `review/`. Dependency downloads require network access on the first build.

If you skipped `setup`, install the Python analysis/image/AES dependencies separately:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Try your own image

After `setup` and activating `.venv`:

```bash
python scripts/image_demo.py --input photo.png --output-dir image-demo
```

Use a **new** output directory on each run. This creates a demo key, `cipher.lrz` and `recovered.png`, and asserts exact decoded-byte recovery. Keep the demo directory private; it contains a key and recovered plaintext. The script preserves L, LA, RGB and RGBA modes; for other modes select an explicit conversion, for example `--mode RGB`. It handles only the first frame of animated/multipage images. Source metadata and compressed file bytes are not preserved. Use the AES-GCM file wrapper below when complete-file recovery is required.

On Windows, use PowerShell with Rust and Python installed:

```powershell
git clone https://github.com/hawike22405/lorenz-blake3-cipher.git
cd lorenz-blake3-cipher
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cargo build --release --locked --manifest-path code/Cargo.toml
cargo test --locked --manifest-path code/Cargo.toml
.\.venv\Scripts\python.exe scripts/image_demo.py --input photo.png --output-dir image-demo
```

The Rust tests have CI coverage on Windows; these complete PowerShell/demo commands have only been exercised locally on Linux through the corresponding Python/Bash paths.

## Raw image workflow

`lrz` reads **raw interleaved bytes**, not PNG/JPEG. Preserve width, height and channel count when converting an image. L, LA, RGB and RGBA use 1, 2, 3 and 4 channels. Decoded pixel equality does not mean identical PNG metadata/compression.

```bash
# Generate an independent random key with owner-only permissions on POSIX.
python3 -c 'import os; f=os.open("key.bin",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,os.urandom(32)); os.close(f)'
./code/target/release/lrz encrypt --key key.bin --input image.raw --output image.lrz --width 256 --height 256 --channels 3
./code/target/release/lrz verify --key key.bin --input image.lrz
./code/target/release/lrz decrypt --key key.bin --input image.lrz --output recovered.raw
```

There is no CLI seed option. Output files are never overwritten. Errors return a nonzero status; invalid authentication never writes plaintext. Protect keys separately from ciphertext. No replay database or nonce-reuse detection is provided. The limit caps payload bytes, **not total process memory**; byte permutations and copies use considerably more memory.

## Separate reviewed primitive for practical file protection

```bash
python scripts/aead_file.py keygen --key aes.key
python scripts/aead_file.py encrypt --key aes.key --input photo.png --output photo.aes
python scripts/aead_file.py decrypt --key aes.key --input photo.aes --output recovered.png
```

This tool uses the `cryptography` implementation of AES-256-GCM, a fresh 96-bit random nonce and authenticated header, under its own `AESFILE1` format (36-byte overhead). It preserves the complete input file, does not use Lorenz, caps files at 64 MiB, and refuses overwrites. Reads are bounded and new output/key files request mode 0600 on POSIX; Windows permissions follow its OS access-control settings. It is a small wrapper, not an audited storage product: it has no password KDF, replay tracking, streaming, crash recovery or key-management system. It does not convert the research cipher into standardized AEAD.

## What was tested

The accompanying evaluator report contains the full review. Reproduce JSON records and test outputs with the commands below. The original 11 tests passed, despite the CLI problems. The reviewed implementation has 15 passing debug and release tests and a separately invoked 500-record ablation experiment. CLI regression checks verify changed nonces, exact round trips, extension rejection and geometry validation.

The matched 100-trial fixed-schedule ablation shows old feedback around 4.53% NPCR, corrected full feedback around 99.81%, and corrected feedback without Lorenz around 99.80%. The latter two are **above the independent random-pair expectation** of 99.609375%; they do not pass a claimed randomness/security certification. This experiment demonstrates the old feedback defect and no demonstrated advantage from Lorenz. It does not prove improved confidentiality.

The three-query script recovers a permutation and mask for a **toy fixed permutation-plus-XOR model** with 65,536 byte positions. It is not a faithful implementation or an experimentally demonstrated break of the Podder–Deb paper.

## Reproduce checks

```bash
python3 scripts/check_aead.py
python3 attack/equivalent_key_attack.py --n 65536 --seed 42
python3 scripts/check_cli.py --binary code/target/release/lrz --output review/revised_cli.json
python analysis/stats.py --single cipher.png --mode RGB
python analysis/stats.py --cipher c1.png c2.png --channel 0 --mode RGB
```

The frozen container digest passed the [Linux/Windows/macOS debug and release CI matrix](https://github.com/hawike22405/lorenz-blake3-cipher/actions/runs/44256257063); that validates the tested vector and configurations only.

No NIST SP 800-22 results, general CPA resistance, universal cross-platform interoperability, 256-bit security, construction-level forgery bound, matched reference speedup or publication acceptance is claimed. Nominal key length and a 32-byte tag do not establish those properties.

MIT License; see LICENSE. Add confirmed author metadata and dataset permissions before submitting the manuscript.

