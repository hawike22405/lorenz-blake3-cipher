#!/usr/bin/env bash
# Linux/macOS. Run from any working directory. No automatic toolchain download.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
command -v cargo >/dev/null || { echo 'Install Rust using https://rustup.rs then restart your shell.' >&2; exit 1; }
case "${1:-help}" in
 build) cargo build --release --locked --manifest-path "$root/code/Cargo.toml" ;;
 test) cargo test --locked --manifest-path "$root/code/Cargo.toml" ;;
 evaluate) mkdir -p "$root/review"; cargo test --release --locked --manifest-path "$root/code/Cargo.toml" -- --ignored --nocapture > "$root/review/ablation.log"; python3 "$root/scripts/summarize.py" ;;
 demo)
  cargo build --release --locked --manifest-path "$root/code/Cargo.toml"
  demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/lrz-demo.XXXXXXXX")"
  python3 - "$demo_dir" <<'PY'
import os,sys
from pathlib import Path
p=Path(sys.argv[1]);(p/'key.bin').write_bytes(os.urandom(32));(p/'key.bin').chmod(0o600)
(p/'input.raw').write_bytes(bytes(range(256))*48)
PY
  "$root/code/target/release/lrz" encrypt --key "$demo_dir/key.bin" --input "$demo_dir/input.raw" --output "$demo_dir/cipher.lrz" --width 64 --height 64 --channels 3
  "$root/code/target/release/lrz" verify --key "$demo_dir/key.bin" --input "$demo_dir/cipher.lrz"
  "$root/code/target/release/lrz" decrypt --key "$demo_dir/key.bin" --input "$demo_dir/cipher.lrz" --output "$demo_dir/recovered.raw"
  cmp "$demo_dir/input.raw" "$demo_dir/recovered.raw"
  echo "Exact round trip; files in $demo_dir (contains a test key)." ;;
 *) echo "Usage: bash scripts/run.sh {build|test|evaluate|demo}" ;;
esac
