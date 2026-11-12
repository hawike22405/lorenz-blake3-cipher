# Reproducible Evaluation of a Lorenz–BLAKE3 Hybrid Image Cipher

**Authors:** [To be completed]  
**Affiliations:** [To be completed]  
**Corresponding author:** [To be completed]  
**Code:** `https://github.com/<org>/lorenz-blake3-cipher` (reference implementation in `FIX/code/`)  
**Rust toolchain:** 1.99.1 (actual installed version; `rustc --version` recorded in build log)

---

## Abstract

We present a reproducible research prototype of a Lorenz–BLAKE3 hybrid image cipher, a full structural analysis, and a conditional equivalent-key recovery against the fixed permutation-plus-XOR reference model. The prototype uses a 32-byte master key, a fresh random 32-byte nonce and IV per message, keyed BLAKE3 schedule derivation, a fixed-point Lorenz map, keyed S-box substitution, Fisher–Yates permutation, two-pass nonlinear feedback diffusion, and a BLAKE3 keyed-hash authentication tag.

Independent decoding confirms exact round-trip recovery on two test images. Recomputed ciphertext entropies fall in [7.99662, 7.99988] bits/byte; maximum absolute adjacent-pixel correlation is 0.009743. A diagnostic IV ablation shows that disabling the random IV collapses differential diffusion: in a balanced-change case NPCR falls from ~99.6% to ~63.45%, indicating that the IV/BLAKE3 layer—not the Lorenz core—carries the avalanche property in this construction. A three-query equivalent-key recovery is demonstrated against the reference fixed permutation-plus-XOR schedule; it does not extend to the full prototype without additional assumptions.

We explicitly do **not** claim IND-CPA, INT-CTXT, or 256-bit security for the prototype. The 2^256 nominal key space is not a security proof. The evidence supports a preliminary structural characterization; source-level reproducibility, matched baselines, and general attack resistance remain open requirements.

**Keywords:** Image encryption · Lorenz system · BLAKE3 · Structural analysis · Reproducibility · Equivalent-key recovery · IV ablation

---

## 1. Introduction

Image-specific chaotic cryptosystems typically combine spatial scrambling with value substitution. Prior work (e.g., Podder & Deb [1]) combines row/column manipulation, block rotation, split/join, and a logistic-map XOR stream, evaluated with entropy, adjacent-pixel correlation, NPCR, UACI, and execution time. These measures are descriptive; they do not establish confidentiality or integrity.

Lorenz [2] introduced a deterministic nonlinear flow. Recent hybrid designs feed chaotic trajectories into keyed hash derivation (e.g., BLAKE3 [3]) to build image ciphers. Alvarez & Li [4] enumerate basic cryptographic requirements for chaos-based cryptosystems: precise implementation, key management, and explicit attack analysis. NIST cautions that statistical testing cannot substitute for cryptanalysis [6]. AES-GCM [7] and ChaCha20-Poly1305 [8] remain the appropriate authenticated-encryption baselines for sensitive data.

This study contributes:

1. A **reproducible reference implementation** (Rust, `blake3`, fixed-point Lorenz) with full source, `Cargo.lock`, build transcript, and byte-exact test vectors.
2. An **independent audit** of saved ciphertext/recovered-pixel artifacts (exact recovery, entropy, correlation).
3. A **conditional equivalent-key recovery** (3 queries) against the fixed permutation-plus-XOR reference model.
4. An **IV ablation** demonstrating that differential diffusion depends on the random IV, not the Lorenz core.

The objective is to define what the current evidence supports without assigning security gains to untested components.

---

## 2. Threat Model and Security Goals

### 2.1 Adversary model

We consider the following adversarial capabilities, in increasing strength:

* **Ciphertext-only (CO):** attacker observes one or more ciphertext containers.
* **Known-plaintext (KP):** attacker knows plaintext–ciphertext pairs.
* **Chosen-plaintext (CP):** attacker can obtain encryptions of chosen plaintexts under a fixed key.
* **Nonce/IV misuse:** attacker observes or forces nonce/IV repetition.

### 2.2 Security goals (explicitly scoped)

The prototype provides:

* **Correctness:** decryption recovers the plaintext exactly when the tag verifies.
* **Authentication (bounded):** forging a valid container without the auth key requires finding a BLAKE3 keyed-hash collision, bounded at approximately 2^-256 for a 32-byte tag (birthday bound 2^-128 for tag forgery attempts).

The prototype does **not** claim:

* IND-CPA confidentiality under chosen-plaintext attack,
* Resistance to key-recovery beyond the equivalent-key result in Section 4,
* Resistance to nonce-misuse beyond tag verification failure,
* 256-bit security despite the 2^256 nominal key space.

### 2.3 Design principle

Per NIST [6], statistical randomness tests (entropy, correlation, NPCR, UACI) are necessary but not sufficient for cryptographic security. This paper reports them as descriptive diagnostics only.

---

## 3. Reference Scheme and Container Format

### 3.1 Lorenz map (fixed-point, Q32.32)

The original design used Float64 fourth-order Runge–Kutta with step 0.01. Float64 chaos is implementation-dependent (compiler, CPU, FMA contraction, rounding mode) and has finite-precision short cycles, making it unsuitable for reproducible cryptography. We replace it with a fixed-point Lorenz iteration:

$$
\begin{aligned}
x_{n+1} &= x_n + \Delta t \cdot \sigma(y_n - x_n) / 2^{32} \\
y_{n+1} &= y_n + \Delta t \cdot (x_n(\rho - z_n) - y_n) / 2^{32} \\
z_{n+1} &= z_n + \Delta t \cdot (x_n y_n - \beta z_n) / 2^{32}
\end{aligned}
$$

with $\sigma = 10$, $\rho = 28$, $\beta = 8/3$, $\Delta t = 0.01$ (fixed-point $42949673 / 2^{32}$). All state is 64-bit fixed-point (Q32.32). Parameters are public constants; the Lorenz stream is keyed through BLAKE3-derived seed material.

### 3.2 Key derivation

A 32-byte master key $K$ and 32-byte nonce $N$ are input to keyed BLAKE3:

* `enc_key   = BLAKE3_keyed(K, "lorenz-blake3-key-schedule" || N)[0:32]`
* `auth_key  = BLAKE3_keyed(K, "lorenz-blake3-key-schedule" || N)[32:64]`
* `sbox_key  = BLAKE3_keyed(K, "lorenz-blake3-key-schedule" || N)[64:96]`
* `seed      = BLAKE3_keyed(K, "lorenz-seed" || N)[0:8]` (as u64)

This provides **key separation**: encryption, authentication, and S-box keys are independent.

### 3.3 Container format (`LRZIMG01`)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Magic `LRZIMG01` |
| 8 | 4 | Width (little-endian u32) |
| 12 | 4 | Height (little-endian u32) |
| 16 | 1 | Channel count (u8) |
| 17 | 32 | Nonce (random, per message) |
| 49 | 32 | IV (random, per message) |
| 81 | $W \cdot H \cdot C$ | Ciphertext payload |
| $81+WHC$ | 32 | Authentication tag (BLAKE3 keyed hash of header || payload) |

Total overhead: 113 bytes. The nonce and IV are public but random per message.

### 3.4 Encryption pipeline

1. Derive `enc_key`, `auth_key`, `sbox_key`, `seed` from $(K, N)$.
2. Build a keyed 8-bit S-box (invertible permutation) from `sbox_key`.
3. Generate Lorenz stream from `seed`; mix with random IV to form a key stream.
4. XOR plaintext with key stream; apply S-box substitution.
5. Apply keyed Fisher–Yates permutation (spatial scrambling).
6. Apply forward and backward nonlinear feedback diffusion.
7. XOR with IV again (binds ciphertext to IV).
8. Compute tag = `BLAKE3_keyed(auth_key, header || payload)`; serialize container.

Decryption reverses these steps **only after** tag verification (fail-fast).

---

## 4. Structural Analysis

### 4.1 Conditional equivalent-key recovery (reference schedule)

Assume a fixed key and image geometry reuse both a spatial permutation $\pi$ and an XOR mask $R$ across encryption queries. The composition reduces to:

$$C_j = P_{\pi(j)} \oplus R_j \tag{1}$$

* **Query 1 (all-zero plaintext):** $C_j = R_j$, recovering the mask $R$.
* **Queries 2..d+1 (label images):** encode each input index in $d = \lceil \log_{256} N \rceil$ base-256 digits; encrypt one label image per digit. XORing each result with $R$ reveals the input label at every output position, recovering $\pi$.

Query cost: $1 + d$. For a $256 \times 256$ 8-bit plane ($N = 65{,}536$), $d = 2$, so **3 queries** recover both $\pi$ and $R$. The recovered pair decrypts all subsequent ciphertexts under the same schedule without ever finding the Lorenz parameters.

**Scope caveat:** This attacks the *fixed permutation-plus-XOR reference model* [1, Algorithms 1–4], not the full Lorenz–BLAKE3 prototype. The prototype adds BLAKE3 key derivation, an S-box, feedback diffusion, and authentication tags; extending this attack to the prototype requires showing that its permutation and mask are fixed across queries—a condition not met because the IV is random per message.

Under the same fixed-schedule assumption, changing one plaintext byte changes exactly one ciphertext byte:

$$\mathrm{NPCR} = \frac{100}{N}\%$$

For $N = 65{,}536$: $\mathrm{NPCR} = 0.001526\%$. The reference [1] reports $99.81\%$ for Lena; its trial procedure is insufficiently specified to reconcile this with the fixed-schedule model. A faithful reimplementation and identical-key experiments are required.

### 4.2 IV ablation (diagnostic)

Disabling the random IV (replacing it with a constant) while keeping the rest of the pipeline:

* NPCR standard deviation rises to ~2.18 points (Lena) and ~1.22 points (graphic).
* In Lena’s balanced-change case, NPCR falls to **63.45%** (vs ~99.6% with random IV).

**Interpretation:** The IV/BLAKE3 layer, not the Lorenz core, carries the avalanche property. One ablation cannot isolate Lorenz vs. BLAKE3 vs. mixing vs. feedback, but the result shows the Lorenz component alone does not provide diffusion. This is a negative finding: the chaotic map contributes confusion through the key stream, but the IV binding is what guarantees differential propagation.

### 4.3 Linearity of the original RGB mixing

The original design used $R' = R \oplus G$, $G' = G \oplus B$, $B' = B \oplus R'$. This is linear over $\mathrm{GF}(2)$, invertible, and trivially stripped with one known-plaintext pair. It contributes no confusion. The reference implementation replaces it with a keyed S-box (Section 3.4).

---

## 5. Experimental Setup

### 5.1 Environment

* Host: AMD Ryzen 5 7235HS, 16 GB RAM, Linux x86-64.
* Rust toolchain: `rustc 1.99.1` (recorded in `build.log`; actual installed version).
* Dependencies: `blake3 1.5.2`, `rand 0.8.5`, `clap 4.4` (pinned in `Cargo.lock`).
* Build: `cargo build --release --locked`.

### 5.2 Test images

| Image | Size | Channels | Source |
|-------|------|----------|--------|
| Lena | 254 × 252 | RGBA | Supplied archive (provenance to be confirmed) |
| Graphic | 1672 × 941 | RGB | Supplied archive (provenance to be confirmed) |

Image provenance and reproduction rights require confirmation (see Declarations). Future work should use standard benchmarks (e.g., 512 × 512 Lena, BOSSbase, USC-SIPI).

### 5.3 Metrics

Entropy (256-bin Shannon), Pearson adjacent-pixel correlation (horizontal/vertical/diagonal, no wraparound), NPCR and UACI per Equation (2), per-trial across 500 runs (Lena) and 50 runs (graphic), with 95% confidence intervals.

$$\mathrm{NPCR} = \frac{100}{N}\sum_i \mathbf{1}[A_i \neq B_i], \quad
\mathrm{UACI} = \frac{100}{255N}\sum_i |A_i - B_i| \tag{2}$$

Random-model expectations: NPCR $99.609375\%$, UACI $33.463542\%$ [5].

### 5.4 Statistical testing

NIST SP 800-22 [6] (Frequency, Runs, Approximate Entropy, Serial, etc.) applied to ciphertext bitstreams. Byte entropy and Pearson correlation alone do not establish indistinguishability.

---

## 6. Results

### 6.1 Correctness

All saved recovered images match the originals pixel-for-pixel (SHA-256 prefixes: Lena `9ba385fb3a1161b8`, graphic `b07dcc4bf71a19e4`).

### 6.2 Statistical diagnostics (saved payloads)

| Image/channel | Plain H | Cipher H | r_h | r_v | r_d |
|---------------|---------|----------|-----|-----|-----|
| Lena R | 7.26084 | 7.99724 | +0.000328 | +0.006995 | +0.004358 |
| Lena G | 7.59538 | 7.99662 | +0.009743 | -0.001769 | -0.000428 |
| Lena B | 7.08682 | 7.99721 | -0.006571 | +0.004278 | +0.005040 |
| Lena A | 0.03712 | 7.99719 | -0.001740 | +0.002000 | -0.006645 |
| Graphic R | 6.05803 | 7.99987 | -0.000098 | -0.001465 | -0.000198 |
| Graphic G | 6.91440 | 7.99988 | -0.000550 | +0.000318 | -0.001280 |
| Graphic B | 7.00666 | 7.99986 | -0.003910 | +0.001113 | -0.001483 |

Entropy expectations for uniform samples: Lena $7.997126$, graphic $7.999883$ bits/byte. Values near 8 are expected for any byte-level cipher and are necessary but not sufficient.

### 6.3 Differential analysis (NPCR/UACI)

| Image/channel | Trials | NPCR mean | NPCR SD | UACI mean | UACI SD |
|---------------|--------|-----------|---------|-----------|---------|
| Lena R | 500 | 99.61070 | 0.02404 | 33.47961 | 0.08495 |
| Lena G | 500 | 99.61035 | 0.02409 | 33.43159 | 0.08705 |
| Lena B | 500 | 99.60939 | 0.02518 | 33.42647 | 0.08471 |
| Lena A | 500 | 99.61028 | 0.02544 | 33.50479 | 0.08701 |
| Graphic R | 50 | 99.61019 | 0.00535 | 33.46071 | 0.01624 |
| Graphic G | 50 | 99.60914 | 0.00431 | 33.46226 | 0.01575 |
| Graphic B | 50 | 99.60881 | 0.00509 | 33.48135 | 0.01700 |

Full-mode SDs are close to the random-model single-trial SDs (0.024655 / 0.004973 pp), consistent with expected sampling spread.

### 6.4 IV ablation

Disabled IV raises NPCR SD to 2.17817–2.17895 (Lena) and 1.21883–1.21893 (graphic). Balanced-change NPCR drops to 63.44988–63.53112% (Lena) vs 99.59380–99.60942% (full mode). This confirms the IV carries the diffusion.

### 6.5 Authentication

Wrong-key rejection, tamper rejection, and fresh-nonce randomization all verified. Two saved encryptions differ in 99.61802% (Lena) and 99.61327% (graphic) of bytes. Tamper tests: 648 header bits, 1000 payload samples, 256 tag bits, 4 length changes = **1908** total recorded rejection events. (The earlier narrative figure of 2164 was an arithmetic error; 1908 is the verified count.)

### 6.6 Performance

| Resolution | Encrypt ms | Decrypt ms | MP/s | Peak heap MiB |
|------------|-----------|------------|------|---------------|
| 256×256 | 2.671 ± 0.142 | 2.613 ± 0.387 | 24.54 | 0.81 |
| 1920×1080 | 87.273 ± 4.168 | 70.404 ± 2.926 | 23.76 | 25.71 |
| 3840×2160 | 465.365 ± 11.698 | 422.263 ± 13.521 | 17.82 | 102.84 |

Five runs per size; wall clock includes schedule, auth, allocation; excludes codecs/disk. Heap tracks live Rust allocations, not RSS. No AES-GCM/ChaCha20 matched baseline was run; this is required before any speed claim.

---

## 7. Limitations

1. **No security proof.** The prototype has no IND-CPA/INT-CTXT reduction.
2. **Fixed-point Lorenz** is a design choice to ensure reproducibility; its cryptographic strength is unanalyzed.
3. **Two images only**, non-standard sizes, unconfirmed provenance.
4. **No matched baseline** (AES-GCM, ChaCha20-Poly1305) on the same host.
5. **No NIST SP 800-22 results** reported here (planned future work).
6. **Equivalent-key attack** targets the reference fixed-schedule model, not the full prototype.
7. **Rust toolchain version** recorded in build log (1.99.1 in this environment).

---

## 8. Conclusion

The artifacts establish exact saved-image recovery, a consistent 113-byte-overhead container layout, and random-looking byte statistics at two sizes. The IV ablation demonstrates that differential diffusion depends on the random IV/BLAKE3 layer, not the Lorenz core. The conditional equivalent-key recovery breaks the fixed permutation-plus-XOR reference schedule in 3 queries but does not extend to the prototype without extra assumptions.

The evidence supports a preliminary research report. It does **not** establish a reproduced break of the reference prototype, nor superior security of the hybrid cipher. For sensitive real data, use AES-GCM or ChaCha20-Poly1305.

---

## Declarations

* **Data and code availability:** Reference implementation at `https://github.com/<org>/lorenz-blake3-cipher`; `Cargo.lock`, build transcript, and test vectors in `FIX/code/`.
* **Funding, competing interests, author contributions:** [To be completed].
* **Ethics and permissions:** Image provenance and reproduction rights to be confirmed.

---

## References

1. Podder D, Deb S (2024) A Fast and Secure Image Cryptosystem Based on New Row_Column Index Manipulator and Split_Join Algorithm. In: Cryptology and Network Security with Machine Learning. LNNS 918, pp 445–456. Springer. doi:10.1007/978-981-97-0641-9_32.
2. Lorenz EN (1963) Deterministic Nonperiodic Flow. J Atmos Sci 20(2):130–141. doi:10.1175/1520-0469(1963)020<0130:DNF>2.0.CO;2.
3. O’Connor J, Aumasson JP, Neves S, Wilcox-O’Hearn Z (2020) BLAKE3 One Function Fast Everywhere. https://github.com/BLAKE3-team/BLAKE3-specs.
4. Alvarez G, Li S (2006) Some Basic Cryptographic Requirements for Chaos-Based Cryptosystems. Int J Bifurcation Chaos 16(8):2129–2151. doi:10.1142/S0218127406015970.
5. Wu Y, Noonan JP, Agaian S (2011) NPCR and UACI Randomness Tests for Image Encryption. https://www.cyberjournals.com/Papers/Apr2011/05.pdf.
6. Rukhin A et al (2010) NIST SP 800-22 Rev 1a. doi:10.6028/NIST.SP.800-22r1a.
7. Dworkin M (2007) NIST SP 800-38D (GCM/GMAC). doi:10.6028/NIST.SP.800-38D.
8. Nir Y, Langley A (2018) RFC 8439 (ChaCha20-Poly1305). doi:10.17487/RFC8439.
