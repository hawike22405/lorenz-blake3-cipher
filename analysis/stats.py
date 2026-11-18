#!/usr/bin/env python3
"""
Statistical analysis for image-cipher ciphertexts.

Computes Shannon entropy, Pearson adjacent-pixel correlation, NPCR, and UACI
with per-trial statistics and 95% confidence intervals.

Usage:
    python3 stats.py --cipher c1.png --cipher c2.png   # NPCR/UACI between two ciphertexts
    python3 stats.py --single c.png                     # entropy + correlation of one file
"""

import argparse
import math
import sys
from typing import Tuple

import numpy as np
from PIL import Image


def shannon_entropy(data: np.ndarray) -> float:
    if data.size == 0: raise ValueError("nonempty byte array required")
    counts = np.bincount(data.ravel(), minlength=256)
    probs = counts[counts > 0] / len(data.ravel())
    return float(-np.sum(probs * np.log2(probs)))


def adjacent_correlation(channel: np.ndarray, direction: str = "horizontal") -> float:
    h, w = channel.shape
    if h == 0 or w == 0: return float("nan")
    channel = channel.astype(np.float64)
    if direction == "horizontal":
        x = channel[:, :-1].ravel()
        y = channel[:, 1:].ravel()
    elif direction == "vertical":
        x = channel[:-1, :].ravel()
        y = channel[1:, :].ravel()
    elif direction == "diagonal":
        x = channel[:-1, :-1].ravel()
        y = channel[1:, 1:].ravel()
    else:
        raise ValueError(direction)
    if len(x) < 2 or x.std() == 0 or y.std() == 0:
        return float("nan")
    return float(np.corrcoef(x, y)[0, 1])


def npcr_uaci(a: np.ndarray, b: np.ndarray) -> Tuple[float, float]:
    if a.shape != b.shape or a.size == 0:
        raise ValueError("equal nonempty shapes required")
    a = a.astype(np.int16).ravel()
    b = b.astype(np.int16).ravel()
    n = len(a)
    npcr = 100.0 * np.sum(a != b) / n
    uaci = 100.0 * np.sum(np.abs(a - b)) / (255.0 * n)
    return float(npcr), float(uaci)


def ci_mean_sd(values, confidence: float = 0.95):
    n = len(values)
    mean = float(np.mean(values))
    sd = float(np.std(values, ddof=1)) if n > 1 else 0.0
    # Approximate 95% CI (normal approximation; use t-distribution for small n).
    z = 1.96 if confidence == 0.95 else 2.576
    se = sd / math.sqrt(n) if n > 0 else 0.0
    return mean, sd, mean - z * se, mean + z * se


def load_channel(path: str, channel_idx: int, mode: str = "RGB"):
    img = np.array(Image.open(path).convert(mode))
    if img.ndim == 2:
        return img  # grayscale
    return img[:, :, channel_idx]


def main():
    parser = argparse.ArgumentParser(description="Image cipher statistics.")
    parser.add_argument("--single", help="Single ciphertext image: entropy + correlation.")
    parser.add_argument("--cipher", nargs="+", help="Two ciphertexts for NPCR/UACI.")
    parser.add_argument("--channel", type=int, default=0, help="Channel index (0=R,1=G,2=B,3=A).")
    parser.add_argument("--mode", default="RGB", help="PIL conversion mode.")
    args = parser.parse_args()

    if args.single:
        img = np.array(Image.open(args.single).convert(args.mode))
        if img.ndim == 2:
            channels = [("gray", img)]
        else:
            names = list(args.mode)
            channels = [(names[i], img[:, :, i]) for i in range(img.shape[2])]
        print(f"File: {args.single}")
        for name, ch in channels:
            print(f"  {name}: H={shannon_entropy(ch):.6f} "
                  f"r_h={adjacent_correlation(ch, 'horizontal'):.6f} "
                  f"r_v={adjacent_correlation(ch, 'vertical'):.6f} "
                  f"r_d={adjacent_correlation(ch, 'diagonal'):.6f}")
        return

    if args.cipher:
        if len(args.cipher) != 2:
            print("Provide exactly two ciphertext images for NPCR/UACI.", file=sys.stderr)
            sys.exit(1)
        a = load_channel(args.cipher[0], args.channel, args.mode)
        b = load_channel(args.cipher[1], args.channel, args.mode)
        if a.shape != b.shape:
            print("Shape mismatch.", file=sys.stderr)
            sys.exit(1)
        npcr, uaci = npcr_uaci(a, b)
        print(f"NPCR = {npcr:.6f}%")
        print(f"UACI = {uaci:.6f}%")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
