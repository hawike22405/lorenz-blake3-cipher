#!/usr/bin/env bash
# One-command install + test for lorenz-blake3-cipher (Linux/macOS).
#
# Usage (from anywhere):
#   bash install_and_test.sh                 # clone (if needed), install, build, test
#   bash install_and_test.sh --keep-going    # don't stop at the first failing check
#   REPO_DIR=~/src/lrz bash install_and_test.sh
#
# What it does:
#   1. Installs Rust via rustup if `cargo` is missing
#   2. Clones the repo (skipped if you run it from inside a checkout)
#   3. Builds the `lrz` binary (release, --locked)
#   4. Runs the Rust test suite (debug + release)
#   5. Creates a Python venv and installs requirements.txt
#   6. Runs the demo round trip, CLI checks, AES-GCM checks and the toy attack script
set -uo pipefail

REPO_URL="${REPO_URL:-https://github.com/hawike22405/lorenz-blake3-cipher.git}"
REPO_DIR="${REPO_DIR:-lorenz-blake3-cipher}"
ORIG_PWD="$PWD"
KEEP_GOING=0
SKIP_IMAGE=0
SKIP_FETCH=0
SKIP_METRICS=0
TRIALS="${TRIALS:-20}"
IMAGE_PATH="${IMAGE_PATH:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-going) KEEP_GOING=1 ;;
    --image)      IMAGE_PATH="${2:-}"; shift ;;
    --no-image)   SKIP_IMAGE=1 ;;
    --no-fetch)   SKIP_FETCH=1 ;;
    --no-metrics) SKIP_METRICS=1 ;;
    --trials)     TRIALS="${2:-20}"; shift ;;
    -h|--help)    sed -n '2,12p' "${BASH_SOURCE[0]}"; echo "Options: --image PATH | --no-image | --no-metrics | --trials N | --no-fetch | --keep-going"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

bold=$'\033[1m'; green=$'\033[32m'; red=$'\033[31m'; reset=$'\033[0m'
step()  { printf '\n%s==> %s%s\n' "$bold" "$*" "$reset"; }
die()   { printf '%sERROR:%s %s\n' "$red" "$reset" "$*" >&2; exit 1; }

declare -a RESULTS=()
FAILED=0
run_check() {  # run_check "label" cmd args...
  local label="$1"; shift
  step "$label"
  if "$@"; then
    RESULTS+=("${green}PASS${reset}  $label")
  else
    RESULTS+=("${red}FAIL${reset}  $label")
    FAILED=1
    [[ $KEEP_GOING -eq 1 ]] || { summary; exit 1; }
  fi
}
summary() {
  printf '\n%s==== Summary ====%s\n' "$bold" "$reset"
  printf '%s\n' "${RESULTS[@]}"
}

# --- system metrics (fastfetch) -----------------------------------------------
# Shown right before the image-path prompt so the output records the machine. Best effort:
# uses fastfetch if present, tries a non-interactive install, and otherwise
# falls back to a basic summary. Skip with --no-fetch.
install_fastfetch() {
  local sudo_cmd=""
  if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null && sudo -n true 2>/dev/null && sudo_cmd="sudo -n" || sudo_cmd="none"
  fi
  if   command -v brew    >/dev/null; then brew install fastfetch >/dev/null 2>&1
  elif [[ "$sudo_cmd" == "none" ]]; then return 1
  elif command -v apt-get >/dev/null; then $sudo_cmd apt-get install -y fastfetch >/dev/null 2>&1
  elif command -v dnf     >/dev/null; then $sudo_cmd dnf install -y fastfetch >/dev/null 2>&1
  elif command -v pacman  >/dev/null; then $sudo_cmd pacman -S --noconfirm fastfetch >/dev/null 2>&1
  elif command -v zypper  >/dev/null; then $sudo_cmd zypper -n install fastfetch >/dev/null 2>&1
  else return 1; fi
}
basic_sysinfo() {
  echo "(fastfetch not available; basic system info)"
  echo "OS:      $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-}" || true) $(uname -srm)"
  echo "Host:    $(hostname)"
  if command -v lscpu >/dev/null; then echo "CPU:     $(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1) ($(nproc) threads)"
  else echo "CPU:     $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -p) ($(getconf _NPROCESSORS_ONLN 2>/dev/null) threads)"; fi
  if command -v free >/dev/null; then echo "Memory:  $(free -h | awk '/^Mem:/{print $3" used / "$2" total"}')"
  elif command -v sysctl >/dev/null; then echo "Memory:  $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 )) GiB total"; fi
  echo "Disk:    $(df -h . | awk 'NR==2{print $3" used / "$2" total ("$5")"}')"
  echo "Uptime:  $(uptime -p 2>/dev/null || uptime)"
}
show_system_info() {
  [[ $SKIP_FETCH -eq 1 ]] && return 0
  step "System metrics"
  if ! command -v fastfetch >/dev/null; then
    echo "fastfetch not found; trying to install it (skipped if this needs a password)..."
    install_fastfetch || true
  fi
  if command -v fastfetch >/dev/null; then
    fastfetch || basic_sysinfo
  else
    basic_sysinfo
  fi
}

# --- 0. prerequisites ---------------------------------------------------------
command -v git >/dev/null     || die "git is required."
command -v python3 >/dev/null || die "python3 is required."
python3 -c 'import venv, ensurepip' 2>/dev/null \
  || die "python3 venv support missing (Debian/Ubuntu: sudo apt install python3-venv)."

# --- 1. Rust ------------------------------------------------------------------
if ! command -v cargo >/dev/null; then
  [[ -f "$HOME/.cargo/env" ]] && . "$HOME/.cargo/env"
fi
if ! command -v cargo >/dev/null; then
  step "Installing Rust toolchain via rustup"
  command -v curl >/dev/null || die "curl is required to install rustup."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
    || die "rustup installation failed."
  . "$HOME/.cargo/env"
fi
echo "Using $(rustc --version) / $(cargo --version)"
# a C linker is needed to build Rust binaries
command -v cc >/dev/null || die "No C compiler/linker found (Debian/Ubuntu: sudo apt install build-essential; macOS: xcode-select --install)."

# --- 2. Get the source --------------------------------------------------------
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
if   [[ -f "$here/scripts/run.sh" && -f "$here/code/Cargo.toml" ]];       then ROOT="$here"
elif [[ -f "$here/../scripts/run.sh" && -f "$here/../code/Cargo.toml" ]]; then ROOT="$(cd "$here/.." && pwd)"
elif [[ -f "./scripts/run.sh" && -f "./code/Cargo.toml" ]];               then ROOT="$PWD"
else
  if [[ -d "$REPO_DIR/.git" ]]; then
    step "Updating existing clone in $REPO_DIR"
    git -C "$REPO_DIR" pull --ff-only || die "git pull failed."
  else
    step "Cloning $REPO_URL"
    git clone --depth 1 "$REPO_URL" "$REPO_DIR" || die "git clone failed."
  fi
  ROOT="$(cd "$REPO_DIR" && pwd)"
fi
cd "$ROOT" || die "cannot enter $ROOT"
echo "Project root: $ROOT"
BIN="$ROOT/code/target/release/lrz"
mkdir -p "$ROOT/review"

# --- 3. Build -----------------------------------------------------------------
run_check "Build (release, --locked)" bash scripts/run.sh build

# --- 4. Rust tests ------------------------------------------------------------
run_check "Rust tests (debug)"   cargo test --locked --manifest-path code/Cargo.toml
run_check "Rust tests (release)" cargo test --locked --release --manifest-path code/Cargo.toml

# --- 5. Python environment ----------------------------------------------------
step "Python virtual environment + dependencies"
if [[ ! -d .venv ]]; then python3 -m venv .venv || die "venv creation failed."; fi
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --quiet --upgrade pip \
  && python -m pip install --quiet -r requirements.txt \
  || die "pip install failed."
echo "Installed: $(python -m pip list 2>/dev/null | grep -Ei '^(numpy|pillow|cryptography) ' | tr -s ' ' | paste -sd, -)"

# --- 6. End-to-end checks -----------------------------------------------------
run_check "Demo: encrypt -> verify -> decrypt -> compare" bash scripts/run.sh demo
run_check "CLI checks (nonce uniqueness, round trip, tamper/geometry rejection)" \
  python scripts/check_cli.py --binary "$BIN" --output review/revised_cli.json
run_check "AES-256-GCM wrapper checks" python scripts/check_aead.py
run_check "Toy equivalent-key attack script" python attack/equivalent_key_attack.py --n 65536 --seed 42

# --- 7. Test with your own image ----------------------------------------------
# lrz works on RAW interleaved bytes, so this converts PNG/JPEG/etc. with Pillow,
# encrypts -> verifies -> decrypts, checks the pixels match exactly, and saves
# a PNG of the recovered image plus a PNG preview of the encrypted bytes.
test_image() {
  local img="$1"
  local out="$ROOT/review/image_test/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$out" && chmod 700 "$out"
  python - "$img" "$out" "$BIN" "$ROOT" "$SKIP_METRICS" "$TRIALS" <<'PY'
import subprocess, sys
from pathlib import Path
from PIL import Image

src, out, binary = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
LIMIT = 64 * 1024 * 1024

img = Image.open(src)
img.load()
if img.mode not in ("L", "LA", "RGB", "RGBA"):
    has_alpha = img.mode in ("P", "PA") and "transparency" in img.info
    img = img.convert("RGBA" if (has_alpha or "A" in img.mode) else "RGB")
channels = len(img.getbands())
w, h = img.size
raw = img.tobytes()
if len(raw) > LIMIT:
    sys.exit(f"Image is {len(raw)} bytes raw; the cipher limit is {LIMIT} (64 MiB). Use a smaller image.")

(out / "key.bin").write_bytes(__import__("os").urandom(32))
(out / "key.bin").chmod(0o600)
(out / "input.raw").write_bytes(raw)
print(f"Image: {src.name}  {w}x{h}, {channels} channel(s) ({img.mode}), {len(raw)} raw bytes")

def lrz(*a):
    r = subprocess.run([binary, *map(str, a)], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"lrz {a[0]} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout.strip()

lrz("encrypt", "--key", out/"key.bin", "--input", out/"input.raw", "--output", out/"image.lrz",
    "--width", w, "--height", h, "--channels", channels)
print("encrypt: ok ->", out/"image.lrz")
print("verify :", lrz("verify", "--key", out/"key.bin", "--input", out/"image.lrz") or "ok")
lrz("decrypt", "--key", out/"key.bin", "--input", out/"image.lrz", "--output", out/"recovered.raw")

if (out/"recovered.raw").read_bytes() != raw:
    sys.exit("FAIL: recovered bytes differ from the original.")
print("decrypt: ok, recovered pixels are identical to the original")

# Viewable outputs. Format: 81-byte header | payload (w*h*channels) | 32-byte tag.
img.save(out/"original.png")
Image.frombytes(img.mode, (w, h), (out/"recovered.raw").read_bytes()).save(out/"recovered.png")
blob = (out/"image.lrz").read_bytes()
payload = blob[81:81 + len(raw)]
Image.frombytes(img.mode, (w, h), payload).save(out/"encrypted_preview.png")
print("Saved original.png, recovered.png, encrypted_preview.png in", out)

if sys.argv[5] != "1":
    print("\n--- Research metrics (entropy, correlation, chi-square, NPCR/UACI, ...) ---")
    r = subprocess.run([sys.executable, str(Path(sys.argv[4]) / "scripts" / "image_metrics.py"),
                        "--binary", binary, "--raw", out/"input.raw", "--width", str(w), "--height", str(h),
                        "--channels", str(channels), "--out-dir", out, "--trials", sys.argv[6]])
    if r.returncode != 0:
        sys.exit("metrics step failed")
PY
}

resolve_path() {  # expand ~ and strip quotes/whitespace that come from drag-and-drop
  local p="$1"
  p="${p#"${p%%[![:space:]]*}"}"; p="${p%"${p##*[![:space:]]}"}"
  p="${p#\'}"; p="${p%\'}"; p="${p#\"}"; p="${p%\"}"
  p="${p//\\ / }"
  [[ "$p" == "~"* ]] && p="${HOME}${p:1}"
  [[ "$p" != /* ]] && p="$ORIG_PWD/$p"   # relative paths are relative to where you ran the script
  printf '%s' "$p"
}

if [[ $SKIP_IMAGE -eq 0 ]]; then
  # Show system metrics right before asking for the image path.
  show_system_info
  step "Test with your own image"
  img=""
  if [[ -n "$IMAGE_PATH" ]]; then
    img="$(resolve_path "$IMAGE_PATH")"
  elif [[ -r /dev/tty && -t 1 ]] || [[ -t 0 ]]; then
    while true; do
      printf 'Enter the path to an image to test (png/jpg/bmp/...), or press Enter to skip: '
      if [[ -t 0 ]]; then IFS= read -r reply; else IFS= read -r reply </dev/tty; fi
      [[ -z "${reply// /}" ]] && break
      img="$(resolve_path "$reply")"
      if [[ -f "$img" ]]; then break; fi
      echo "  Not a file: $img  (try again, or press Enter to skip)"; img=""
    done
  else
    echo "No terminal available to prompt; skipping. Re-run with --image /path/to/pic.png"
  fi

  if [[ -n "$img" ]]; then
    if [[ ! -f "$img" ]]; then
      RESULTS+=("${red}FAIL${reset}  Image test (file not found: $img)"); FAILED=1
    elif test_image "$img"; then
      RESULTS+=("${green}PASS${reset}  Image round trip: $(basename "$img")")
    else
      RESULTS+=("${red}FAIL${reset}  Image round trip: $(basename "$img")"); FAILED=1
    fi
  else
    echo "Image test skipped."
  fi
fi

# --- done ---------------------------------------------------------------------
summary
if [[ $FAILED -eq 0 ]]; then
  printf '\n%sAll checks passed.%s\n' "$green" "$reset"
  cat <<EOF

Use it:
  cd "$ROOT" && . .venv/bin/activate
  python3 -c 'import os; f=os.open("key.bin",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,os.urandom(32)); os.close(f)'
  $BIN encrypt --key key.bin --input image.raw --output image.lrz --width 256 --height 256 --channels 3
  $BIN decrypt --key key.bin --input image.lrz --output recovered.raw

Optional 500-trial ablation (slow):  bash scripts/run.sh evaluate
Note: this is a research prototype with no security proof; do not use it for real data.
EOF
else
  exit 1
fi
