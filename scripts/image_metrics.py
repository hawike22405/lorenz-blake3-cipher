#!/usr/bin/env python3
"""Research metrics for one image encrypted with `lrz`.

Reports, per channel and overall:
  * Shannon entropy, adjacent-pixel correlation (H/V/D) for plaintext and ciphertext
  * Histogram chi-square of the ciphertext (uniformity)
  * NPCR / UACI over N trials (one-byte plaintext change; mean, sd, 95% CI)
  * Baseline NPCR / UACI between two encryptions of the *same* plaintext
  * Exact-recovery check, MSE/PSNR, wrong-key rejection, timing, size overhead

Writes metrics.json, metrics.csv and metrics.md next to the other image-test files.

IMPORTANT: the CLI draws a fresh random nonce for every encryption, so two
ciphertexts always differ even for identical plaintexts. The NPCR/UACI numbers
here therefore mostly measure the nonce, not plaintext sensitivity. For the
fixed-schedule differential experiment use `bash scripts/run.sh evaluate`.
"""
import argparse, csv, json, math, os, subprocess, sys, tempfile, time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analysis"))
from stats import shannon_entropy, adjacent_correlation, npcr_uaci, ci_mean_sd  # noqa: E402

HEADER, TAG = 81, 32
CHI2_CRIT_255_5PCT = 293.2478  # chi-square critical value, 255 dof, alpha = 0.05
EXPECTED_NPCR = 100 * (1 - 1 / 256)   # random byte pair: 99.609375 %
EXPECTED_UACI = 100 * (256 ** 2 - 1) / (3 * 256 * 255)  # ~33.4635 %


def chi_square_uniform(ch):
    counts = np.bincount(ch.ravel(), minlength=256).astype(np.float64)
    e = ch.size / 256.0
    return float(((counts - e) ** 2 / e).sum())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--raw", type=Path, required=True)
    ap.add_argument("--width", type=int, required=True)
    ap.add_argument("--height", type=int, required=True)
    ap.add_argument("--channels", type=int, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--trials", type=int, default=20)
    a = ap.parse_args()

    w, h, c = a.width, a.height, a.channels
    plain = np.frombuffer(a.raw.read_bytes(), dtype=np.uint8).copy()
    assert plain.size == w * h * c
    trials = a.trials if plain.size <= 8 * 1024 * 1024 else min(a.trials, 5)
    names = {1: ["L"], 2: ["L", "A"], 3: ["R", "G", "B"], 4: ["R", "G", "B", "A"]}[c]
    rng = np.random.default_rng()

    def lrz(*args):
        r = subprocess.run([a.binary, *map(str, args)], capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"lrz {args[0]} failed: {r.stderr.strip() or r.stdout.strip()}")
        return r

    with tempfile.TemporaryDirectory(dir=a.out_dir) as t:
        t = Path(t)
        key = t / "key"; key.write_bytes(os.urandom(32))
        counter = [0]

        def encrypt(data, k=key):
            counter[0] += 1
            src, dst = t / f"p{counter[0]}", t / f"c{counter[0]}"
            src.write_bytes(data.tobytes())
            t0 = time.perf_counter()
            lrz("encrypt", "--key", k, "--input", src, "--output", dst,
                "--width", w, "--height", h, "--channels", c)
            dt = time.perf_counter() - t0
            blob = dst.read_bytes()
            return np.frombuffer(blob[HEADER:HEADER + plain.size], dtype=np.uint8).copy(), dst, dt, len(blob)

        cipher, cfile, t_enc, blob_len = encrypt(plain)

        # Decrypt, exact recovery, MSE/PSNR
        out = t / "rec"
        t0 = time.perf_counter()
        lrz("decrypt", "--key", key, "--input", cfile, "--output", out)
        t_dec = time.perf_counter() - t0
        rec = np.frombuffer(out.read_bytes(), dtype=np.uint8)
        exact = bool(np.array_equal(rec, plain))
        mse = float(np.mean((rec.astype(float) - plain.astype(float)) ** 2))
        psnr = "inf" if mse == 0 else 10 * math.log10(255 ** 2 / mse)

        # Wrong key (one flipped key bit) must be rejected, no plaintext written
        k2 = t / "key2"; kb = bytearray(key.read_bytes()); kb[0] ^= 1; k2.write_bytes(bytes(kb))
        wrong = subprocess.run([a.binary, "decrypt", "--key", k2, "--input", cfile, "--output", t / "wrongout"],
                               capture_output=True)
        wrong_key_rejected = wrong.returncode != 0 and not (t / "wrongout").exists()

        # Baseline: same plaintext encrypted twice
        cipher_b, *_ = encrypt(plain)
        base_np, base_ua = npcr_uaci(cipher, cipher_b)

        # One-byte plaintext change, N trials
        np_list, ua_list = [], []
        per_ch = {n: ([], []) for n in names}
        for _ in range(trials):
            p2 = plain.copy()
            i = int(rng.integers(plain.size))
            p2[i] ^= 1  # flip LSB of one pixel byte
            c1, *_ = encrypt(plain)
            c2, *_ = encrypt(p2)
            n_, u_ = npcr_uaci(c1, c2); np_list.append(n_); ua_list.append(u_)
            a1, a2 = c1.reshape(h, w, c), c2.reshape(h, w, c)
            for k, n in enumerate(names):
                x, y = npcr_uaci(a1[:, :, k], a2[:, :, k]); per_ch[n][0].append(x); per_ch[n][1].append(y)

    P, C = plain.reshape(h, w, c), cipher.reshape(h, w, c)
    rows = []
    for k, n in enumerate(names):
        row = {"channel": n}
        for label, arr in (("plain", P[:, :, k]), ("cipher", C[:, :, k])):
            row[f"entropy_{label}"] = shannon_entropy(arr)
            for d in ("horizontal", "vertical", "diagonal"):
                row[f"corr_{d[0]}_{label}"] = adjacent_correlation(arr, d)
        chi = chi_square_uniform(C[:, :, k])
        row["chi2_cipher"] = chi
        row["chi2_pass_5pct"] = chi < CHI2_CRIT_255_5PCT
        m, sd, lo, hi = ci_mean_sd(per_ch[n][0]); row["npcr_mean"], row["npcr_sd"] = m, sd
        m, sd, lo, hi = ci_mean_sd(per_ch[n][1]); row["uaci_mean"], row["uaci_sd"] = m, sd
        rows.append(row)

    nm, nsd, nlo, nhi = ci_mean_sd(np_list)
    um, usd, ulo, uhi = ci_mean_sd(ua_list)
    summary = {
        "image": {"width": w, "height": h, "channels": c, "raw_bytes": int(plain.size)},
        "entropy_plain_overall": shannon_entropy(plain), "entropy_cipher_overall": shannon_entropy(cipher),
        "chi2_cipher_overall": chi_square_uniform(cipher), "chi2_critical_5pct_255dof": CHI2_CRIT_255_5PCT,
        "differential": {"trials": trials, "npcr_mean": nm, "npcr_sd": nsd, "npcr_ci95": [nlo, nhi],
                         "uaci_mean": um, "uaci_sd": usd, "uaci_ci95": [ulo, uhi],
                         "expected_random_npcr": EXPECTED_NPCR, "expected_random_uaci": EXPECTED_UACI,
                         "baseline_same_plaintext_npcr": base_np, "baseline_same_plaintext_uaci": base_ua,
                         "note": "Fresh random nonce per encryption: values mostly reflect the nonce, not plaintext sensitivity."},
        "recovery": {"exact": exact, "mse": mse, "psnr_db": psnr, "wrong_key_rejected": wrong_key_rejected},
        "performance": {"encrypt_s": t_enc, "decrypt_s": t_dec, "mb_per_s_encrypt": plain.size / 1e6 / t_enc,
                        "ciphertext_bytes": blob_len, "overhead_bytes": blob_len - int(plain.size)},
        "per_channel": rows,
    }
    out_dir = a.out_dir
    (out_dir / "metrics.json").write_text(json.dumps(summary, indent=2, default=float) + "\n")
    with open(out_dir / "metrics.csv", "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(rows[0].keys())); wr.writeheader(); wr.writerows(rows)

    # ---- terminal / markdown report ----
    L = []
    L.append(f"Image {w}x{h}, {c} channel(s), {plain.size} bytes; {trials} differential trials")
    L.append("")
    L.append("Entropy (ideal 8) and adjacent-pixel correlation (ideal ~0 for cipher)")
    L.append(f"{'ch':<3}{'H plain':>9}{'H cipher':>10} | {'plain h':>8}{'v':>8}{'d':>8} | {'cipher h':>9}{'v':>8}{'d':>8} | {'chi2':>8}")
    for r in rows:
        L.append(f"{r['channel']:<3}{r['entropy_plain']:>9.4f}{r['entropy_cipher']:>10.4f} | "
                 f"{r['corr_h_plain']:>8.4f}{r['corr_v_plain']:>8.4f}{r['corr_d_plain']:>8.4f} | "
                 f"{r['corr_h_cipher']:>9.4f}{r['corr_v_cipher']:>8.4f}{r['corr_d_cipher']:>8.4f} | "
                 f"{r['chi2_cipher']:>8.1f}")
    L.append(f"Overall entropy: plain {summary['entropy_plain_overall']:.4f}, cipher {summary['entropy_cipher_overall']:.4f}; "
             f"chi2 {summary['chi2_cipher_overall']:.1f} (uniform if < {CHI2_CRIT_255_5PCT} at 5%, 255 dof)")
    L.append("")
    L.append("NPCR / UACI, one-byte plaintext change (mean ± sd [95% CI])")
    L.append(f"  NPCR {nm:.4f} ± {nsd:.4f} % [{nlo:.4f}, {nhi:.4f}]   (random-pair expectation {EXPECTED_NPCR:.4f} %)")
    L.append(f"  UACI {um:.4f} ± {usd:.4f} % [{ulo:.4f}, {uhi:.4f}]   (random-pair expectation {EXPECTED_UACI:.4f} %)")
    for n in names:
        L.append(f"    {n}: NPCR {np.mean(per_ch[n][0]):.4f} %  UACI {np.mean(per_ch[n][1]):.4f} %")
    L.append(f"  Baseline, SAME plaintext encrypted twice: NPCR {base_np:.4f} %  UACI {base_ua:.4f} %")
    L.append("  NOTE: a fresh random nonce is used per encryption, so these mostly reflect the nonce, not")
    L.append("        plaintext sensitivity. Use `bash scripts/run.sh evaluate` for the fixed-schedule experiment.")
    L.append("")
    L.append(f"Recovery: exact={exact}  MSE={mse:.4g}  PSNR={psnr if psnr == 'inf' else f'{psnr:.2f} dB'}  "
             f"1-bit-wrong-key rejected={wrong_key_rejected}")
    L.append(f"Speed: encrypt {t_enc*1000:.1f} ms ({summary['performance']['mb_per_s_encrypt']:.2f} MB/s, includes process start), "
             f"decrypt {t_dec*1000:.1f} ms; overhead {blob_len - plain.size} bytes")
    text = "\n".join(L)
    print(text)
    (out_dir / "metrics.md").write_text("```\n" + text + "\n```\n")
    print(f"\nSaved metrics.json, metrics.csv, metrics.md in {out_dir}")
    if not (exact and wrong_key_rejected):
        sys.exit(1)


if __name__ == "__main__":
    main()
