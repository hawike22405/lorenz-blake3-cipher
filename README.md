# Lorenz–BLAKE3 Image Cipher. 

An experimental image-byte cipher built from a fixed-point Lorenz map and keyed BLAKE3, with a reproducible evaluation toolkit and a separate AES-256-GCM file tool.

> **Research prototype. Not for real data.**
> There is no security proof, no third-party cryptanalysis, and the statistics reported here do not establish confidentiality or integrity. For practical protection use `scripts/aead_file.py` (AES-256-GCM) or an audited encryption product.

## Contents

- [Project report and documentation](#project-report-and-documentation)
- [Flowchart](#flowchart)
- [Quick start](#quick-start)
- [Windows install](#windows)
- [Encrypt your own image](#encrypt-your-own-image)
- [Evaluate the cipher](#evaluate-the-cipher)
- [NIST SP 800-22 randomness tests](#nist-sp-800-22-randomness-tests)
- [AES-256-GCM file tool](#aes-256-gcm-file-tool)
- [Findings and limits](#findings-and-limits)
- [Versions and compatibility](#versions-and-compatibility)
- [Repository layout](#repository-layout)

## Project report and documentation

- [Adamas University project report (PDF)](docs/Lorenz_BLAKE3_Project_Report_Adamas_Format.pdf)
- [Repository documentation on DeepWiki](https://deepwiki.com/hawike22405/lorenz-blake3-cipher/)

## Flowchart

Step-by-step install and usage flowcharts with copy-paste commands. Click your operating system to open the full-size image:

- [Windows flowchart](https://raw.githubusercontent.com/hawike22405/lorenz-blake3-cipher/master/docs/flowcharts/flowchart-windows.png)
- [Linux flowchart](https://raw.githubusercontent.com/hawike22405/lorenz-blake3-cipher/master/docs/flowcharts/flowchart-linux.png)
- [macOS flowchart](https://raw.githubusercontent.com/hawike22405/lorenz-blake3-cipher/master/docs/flowcharts/flowchart-macos.png)

## Quick start

Linux and macOS. Requires `git`, `python3` with `venv`, and a C compiler (`build-essential` on Debian/Ubuntu, `xcode-select --install` on macOS). Rust is installed for you if missing. The first build needs network access.

```bash
git clone https://github.com/hawike22405/lorenz-blake3-cipher.git
cd lorenz-blake3-cipher
bash scripts/install_and_test.sh
```

The script builds the `lrz` binary, runs the Rust tests (debug and release), creates `.venv`, runs the demo round trip and all check scripts, then shows system info with `fastfetch` and asks for an image to test. It prints a PASS/FAIL summary and exits nonzero on any failure.

| Option | Effect |
| --- | --- |
| `--image PATH` | Test this image without prompting |
| `--no-image` | Skip the image step |
| `--trials N` | Differential trials for the image metrics (default 20) |
| `--no-metrics` | Skip the metrics table |
| `--no-fetch` | Skip the fastfetch system info |
| `--keep-going` | Continue after a failing check |

Prefer manual steps? Use the runner:

```bash
bash scripts/run.sh setup       # venv + Python deps + release build
bash scripts/run.sh test        # Rust tests
bash scripts/run.sh demo        # synthetic encrypt → verify → decrypt round trip
bash scripts/run.sh evaluate    # 500-trial ablation, writes review/
```

### Windows

Windows has no Rust or Docker requirement. Once a release exists, install the prebuilt `lrz.exe` from PowerShell:

```powershell
irm https://raw.githubusercontent.com/hawike22405/lorenz-blake3-cipher/master/install.ps1 | iex
```

This downloads `lrz-windows-x86_64.exe` from the [latest release](https://github.com/hawike22405/lorenz-blake3-cipher/releases/latest), saves it as `%LOCALAPPDATA%\lrz\lrz.exe` and adds that folder to your user `PATH`. Open a new terminal, then run `lrz --help`. You can also download the `.exe` from the Releases page yourself.

Release binaries for Windows, Linux (`lrz-linux-x86_64`) and macOS (`lrz-macos-aarch64`, Apple Silicon only) are built by GitHub Actions when a `v*` tag is pushed. They are generic x86-64 release builds with no `target-cpu=native` and no fast-math or FMA, so the float64 results match the frozen test vector. For timing numbers, build locally and record the CPU, Rust version and flags.

To build from source instead, with Rust installed: `cargo build --release --locked --manifest-path code/Cargo.toml`. The scripts above are only exercised on Linux; the Rust tests run in CI on Windows.

## Encrypt your own image

`lrz` works on **raw interleaved bytes**, not PNG or JPEG. The helper converts for you:

```bash
. .venv/bin/activate
python scripts/image_demo.py --input photo.png --output-dir image-demo
```

Use a new output directory each run. It creates a throwaway key, `cipher.lrz` and `recovered.png`, and checks that the decoded pixels match exactly. Modes L, LA, RGB and RGBA are preserved; for other modes pass `--mode RGB`. Only the first frame is used and file metadata is not preserved. Keep the output folder private, since it contains the key and the recovered image.

To use the CLI directly, create a key and pass the image geometry:

```bash
python3 -c 'import os; f=os.open("key.bin",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,os.urandom(32)); os.close(f)'
./code/target/release/lrz encrypt --key key.bin --input image.raw --output image.lrz --width 256 --height 256 --channels 3
./code/target/release/lrz verify  --key key.bin --input image.lrz
./code/target/release/lrz decrypt --key key.bin --input image.lrz --output recovered.raw
```

Channels are 1 (L), 2 (LA), 3 (RGB) or 4 (RGBA). Output files are never overwritten, and a failed authentication writes nothing. Keep keys separate from ciphertext. There is no replay or nonce-reuse detection. The 256 MiB limit caps payload bytes, not total memory, which is several times higher.

## Evaluate the cipher

| Goal | Command |
| --- | --- |
| Metrics for one image (entropy, correlation, chi-square, NPCR/UACI, recovery, timing) | `python scripts/image_metrics.py --binary code/target/release/lrz --raw input.raw --width W --height H --channels C --out-dir EXISTING_DIR --trials 20` |
| Fixed-schedule ablation (the meaningful differential test) | `bash scripts/run.sh evaluate` |
| CLI regression checks and timings | `mkdir -p review && python scripts/check_cli.py --binary code/target/release/lrz --output review/cli.json` |
| Toy equivalent-key attack | `python attack/equivalent_key_attack.py --n 65536 --seed 42` |
| Image statistics from PNGs | `python analysis/stats.py --single cipher.png --mode RGB` |

Results are written to the git-ignored `review/` folder.

**Read NPCR/UACI carefully.** The CLI draws a fresh random nonce for every encryption, so any two ciphertexts differ. NPCR/UACI from `image_metrics.py` therefore mostly reflect the nonce and land near the random-pair values (99.609 % and 33.464 %). They are not evidence of plaintext sensitivity. Use `bash scripts/run.sh evaluate` for that.

## NIST SP 800-22 randomness tests

1. **Make the bit file** from one or more `.lrz` files. It strips headers and tags and trims to whole 1,000,000-bit streams:

   ```bash
   python3 scripts/make_nist_bits.py image.lrz            # writes cipher_bits.bin
   ```

   It prints the number of bitstreams. A 3072×1728 RGB image gives 127. For a stricter test, encrypt an all-zero plaintext under many fresh keys and pass all the containers at once.

2. **Download** the NIST Statistical Test Suite from the [NIST Random Bit Generation page](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software), unpack it, and `cd` to the folder containing the `Makefile`.

3. **Build and run:**

   ```bash
   make
   ./assess 1000000
   ```

   | Prompt | Answer |
   | --- | --- |
   | Generator | `0` (input file), then the absolute path to `cipher_bits.bin` |
   | Apply all tests | `1` |
   | Parameter adjustments | `0` |
   | Number of bitstreams | the count printed in step 1 |
   | Input format | `1` (binary) |

4. **Read the report** at `experiments/AlgorithmTesting/finalAnalysisReport.txt`. Each test should pass in roughly 98–100 % of streams, and the uniformity column should be at least 0.0001. With about 188 sub-tests, one or two marginal failures are expected by chance; re-run on fresh data before drawing conclusions. A pass shows the output looks random, not that the cipher is secure.

## AES-256-GCM file tool

A separate, small wrapper around the `cryptography` library for protecting whole files:

```bash
python scripts/aead_file.py keygen  --key aes.key
python scripts/aead_file.py encrypt --key aes.key --input photo.png --output photo.aes
python scripts/aead_file.py decrypt --key aes.key --input photo.aes --output recovered.png
```

It uses a fresh 96-bit random nonce and an authenticated header (`AESFILE1`, 36 bytes of overhead), preserves the complete file, caps files at 64 MiB and refuses to overwrite. It is not an audited storage product: no password KDF, replay tracking, streaming, crash recovery or key management. Run `python scripts/check_aead.py` to exercise it.

## Findings and limits

- **Correctness:** round trips are exact, wrong keys and tampered containers are rejected, and the frozen test vector passes the Linux/Windows/macOS debug and release [CI matrix](https://github.com/hawike22405/lorenz-blake3-cipher/actions/runs/44256257063). That validates the tested vector and configurations only.
- **Ablation (100 matched trials):** the old feedback gave about 4.53 % NPCR. The corrected feedback gives about 99.81 %, and about 99.80 % with Lorenz removed. So the Lorenz map adds no measurable diffusion, and the avalanche comes from the feedback passes. Values above the random-pair expectation of 99.609 % are a structural property of the feedback, not evidence of improved confidentiality.
- **Toy attack:** the three-query script breaks a *toy* fixed permutation-plus-XOR model with 65,536 byte positions. It is not an implementation of, or a demonstrated break of, the Podder–Deb paper.
- **Not claimed:** NIST SP 800-22 results, CPA resistance, 256-bit security, a construction-level forgery bound, cross-platform interoperability beyond CI, a speed advantage over standard ciphers, or publication acceptance. A 256-bit key and a 32-byte tag do not establish any of these.
- **Throughput:** about 5 MB/s end to end for a 3072×1728 RGB image on a Ryzen 5 7235HS, including process start and file I/O.

### Maximum image size

The limit is on payload bytes, not pixels: `width × height × channels` must be at most 256 MiB (268,435,456 bytes). The largest image therefore depends on the channel count. The "K" column is the width in thousands of pixels for a 16:9 image.

| Image type | Channels | Max pixels | Max size at 16:9 | Max "K" |
| --- | --- | --- | --- | --- |
| RGB (colour) | 3 | 89,478,485 | about 12,600 × 7,090 | about 12.6K |
| RGBA (colour with transparency) | 4 | 67,108,864 | about 10,900 × 6,140 | about 10.9K |
| Grayscale + alpha (LA) | 2 | 134,217,728 | about 15,400 × 8,680 | about 15.4K |
| Grayscale (L) | 1 | 268,435,456 | about 21,800 × 12,280 | about 21.8K |

For a normal colour photo this is about 12K. Standard 8K UHD (7,680 × 4,320) and DCI 8K (8,192 × 4,320) fit even as RGBA, and 10K (10,240 × 4,320 or 10,240 × 5,760) fits as RGB or RGBA. 16K does not fit. Larger images are rejected before encryption. Memory use is several times the payload size, so the largest images need a lot of RAM. These limits come from the size cap in the code and were not benchmarked at the largest sizes.

## Versions and compatibility

- **`LRZIMG02` (this version):** `OsRng` nonce and IV, checked geometry (1–4 channels, positive dimensions, at most 256 MiB), strict lengths, constant-time tag comparison, BLAKE3 XOF with rejection sampling, rescaled Q32.32 Euler arithmetic and corrected feedback. It permutes bytes, not whole pixels. Container overhead is 113 bytes. See [ARCHITECTURE.md](ARCHITECTURE.md) for the exact specification.
- **`LRZIMG01` (commit `69465bc`):** intentionally incompatible. Its CLI seeded `StdRng` with 42 on every run, so nonce, IV and ciphertext repeated, and it accepted trailing bytes and inconsistent geometry.
- **Earlier Float64 RK4 implementation:** Its speed, memory and differential results apply to that implementation.

## Repository layout

| Path | Contents |
| --- | --- |
| `code/` | Rust crate (`lrz` binary, cipher library, tests) |
| `scripts/` | Installer, runner, image demo, metrics, CLI checks, AES-GCM tool, NIST helper |
| `docs/` | Project report, command reference and `flowcharts/` (install and usage flowcharts for Windows, Linux and macOS) |
| `analysis/` | Entropy, correlation, NPCR/UACI helpers |
| `attack/` | Toy equivalent-key attack |
| `ARCHITECTURE.md` | Normative `LRZIMG02` specification |
| `CONTRIBUTING.md` | Contribution guide |

Rust 1.100.0 on Linux x86-64 was used for the reviewed build. Do not regenerate `Cargo.lock` during an ordinary build.

## License

MIT, see [LICENSE](LICENSE). Add confirmed author metadata and dataset permissions before submitting a manuscript.
