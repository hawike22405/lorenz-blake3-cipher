# Lorenz–BLAKE3 Image Cipher — System Architecture

This document describes the complete system architecture of the Lorenz–BLAKE3 hybrid image cipher reference implementation.

## 1. Threat Model

### Adversary Capabilities

| Capability | Description |
|------------|-------------|
| Ciphertext-only (CO) | Attacker observes one or more ciphertext containers |
| Known-plaintext (KP) | Attacker knows plaintext–ciphertext pairs |
| Chosen-plaintext (CP) | Attacker can obtain encryptions of chosen plaintexts |
| Nonce/IV misuse | Attacker observes or forces nonce/IV repetition |

### Security Goals

**Provided:**
- **Correctness**: decryption recovers plaintext exactly when tag verifies
- **Authentication (bounded)**: forging a valid container without `auth_key` requires BLAKE3 keyed-hash collision (~2⁻²⁵⁶)

**Not Claimed:**
- IND-CPA confidentiality under chosen-plaintext
- Resistance to key recovery beyond equivalent-key result on reference model
- 256-bit security despite 2²⁵⁶ nominal key space

---

## 2. Container Format (`LRZIMG01`)

Total overhead: **113 bytes** (81 header + 32 tag)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | Magic | `LRZIMG01` |
| 8 | 4 | Width | Little-endian u32 |
| 12 | 4 | Height | Little-endian u32 |
| 16 | 1 | Channels | u8 (1=gray, 3=RGB, 4=RGBA) |
| 17 | 32 | Nonce | Random, per message |
| 49 | 32 | IV | Random, per message |
| 81 | $W \times H \times C$ | Payload | Encrypted ciphertext |
| $81+WHC$ | 32 | Tag | BLAKE3 keyed hash of header‖payload |

---

## 3. Key Schedule

A 32-byte master key $K$ and 32-byte nonce $N$ are input to keyed BLAKE3:

```
enc_key   = BLAKE3_keyed(K, "lorenz-blake3-key-schedule" || N)[0:32]
auth_key  = BLAKE3_keyed(K, "auth-key" || enc_key)[0:32]
sbox_key  = BLAKE3_keyed(K, "sbox-key" || auth_key)[0:32]
seed      = BLAKE3_keyed(K, "lorenz-seed" || N)[0:8]  (as u64)
```

**Key separation:** encryption, authentication, and S-box keys are independent.

---

## 4. Fixed-Point Lorenz Map (Q32.32)

Float64 RK4 is replaced with 64-bit fixed-point arithmetic for portability:

```
dx/dt = σ(y - x)
dy/dt = x(ρ - z) - y
dz/dt = xy - βz
```

Parameters: σ=10, ρ=28, β=8/3, Δt=0.01 (fixed-point 42949673/2³²)

State (x, y, z) is 64-bit fixed-point (Q32.32). The Lorenz stream is keyed through BLAKE3-derived seed material.

---

## 5. Encryption Pipeline

```
Input: plaintext P (W×H×C interleaved bytes), master key K

1. Generate random nonce N (32 bytes) and IV (32 bytes)
2. Derive enc_key, auth_key, sbox_key, seed from (K, N)
3. Build keyed 8-bit S-box from sbox_key
4. Generate Lorenz stream from seed; mix with IV → key stream
5. XOR plaintext with key stream              [Confusion]
6. Apply S-box substitution                    [Non-linearity]
7. Apply keyed Fisher–Yates permutation        [Spatial scrambling]
8. Apply forward nonlinear feedback diffusion  [Diffusion]
9. Apply backward nonlinear feedback diffusion [Diffusion]
10. XOR with IV again                          [IV binding]
11. Compute tag = BLAKE3_keyed(auth_key, header || payload)
12. Serialize: header || payload || tag
```

### Step Details

**Step 4 — Lorenz key stream:**
- `lorenz_stream(seed, steps)` produces 4 bytes per step (x-state)
- Cycled and XORed with IV to cover plaintext length

**Step 6 — S-box:**
- 256-entry invertible permutation built via Fisher–Yates shuffle keyed by BLAKE3
- Each byte: `out[i] = sbox[in[i]]`

**Step 7 — Fisher–Yates permutation:**
- `perm[out_pos]` = input position that moves to `out_pos`
- Applied to all interleaved pixel bytes

**Steps 8–9 — Feedback diffusion:**
- Forward: `out[i] = sbox[in[i] + carry] ^ carry`, carry = out[i]
- Backward: `out[i] = sbox[in[i] - carry] ^ carry`, carry = out[i]
- Reversed in decryption

**Step 10 — IV binding:**
- `out[i] ^= iv[i % 32]` ensures ciphertext depends on IV

---

## 6. Decryption Pipeline

1. Verify tag = BLAKE3_keyed(auth_key, header || payload) — **fail-fast**
2. XOR payload with IV (inverse of Step 10)
3. Undiffuse backward (inverse of Step 9)
4. Undiffuse forward (inverse of Step 8)
5. Apply Fisher–Yates inverse permutation (inverse of Step 7)
6. Apply inverse S-box substitution (inverse of Step 6)
7. XOR with Lorenz key stream (inverse of Step 5)

---

## 7. Authentication Tag

- **Algorithm**: BLAKE3 keyed hash with `auth_key`
- **Input**: header bytes (81) || ciphertext payload
- **Output**: 32-byte tag
- **Forgery bound**: ~2⁻²⁵⁶ (birthday bound 2⁻¹²⁸ for forgery attempts)
- **Comparison**: Byte-by-byte equality check

---

## 8. Module Boundaries

```
code/src/
├── lib.rs        # Crate root, declares cipher module
├── cipher.rs     # Core cipher (470+ lines):
│   ├── Constants (MAGIC, HEADER_SIZE, TAG_SIZE, Lorenz params)
│   ├── lorenz_stream()       # Fixed-point Lorenz iterator
│   ├── blake3_keyed()        # BLAKE3 helper with [u8;32] key
│   ├── build_sbox()          # Keyed S-box construction
│   ├── derive_keys()         # Key schedule (enc/auth/sbox/seed)
│   ├── fisher_yates_perm()   # Keyed permutation generator
│   ├── apply_perm() / apply_perm_inverse()
│   ├── diffuse_forward/backward()   # Nonlinear feedback
│   ├── undiffuse_forward/backward() # Inverse diffusion
│   ├── Header (serialize/deserialize)
│   ├── compute_tag() / verify_tag()
│   ├── CiphertextContainer (serialize/deserialize)
│   ├── encrypt()             # Full encryption pipeline
│   ├── decrypt()             # Full decryption pipeline
│   └── tests (11 unit tests)
└── main.rs                   # CLI:
    ├── encrypt subcommand
    ├── decrypt subcommand
    └── verify subcommand
```

**External crates:**
- `blake3` — cryptographic hashing
- `rand` — random number generation (nonce, IV)
- `clap` — CLI argument parsing

---

## 9. Data Flow Diagram

```
┌─────────┐     ┌─────────────────┐     ┌──────────────────┐
│ Plain   │────▶│ Key Schedule    │────▶│ Lorenz Stream    │
│ P (W×H×C│     │ (BLAKE3)        │     │ (fixed-point)    │
└─────────┘     └─────────────────┘     └────────┬─────────┘
                                                 │
┌─────────┐     ┌─────────────────┐     ┌────────▼─────────┐
│ Tag     │◀────│ Authentication  │◀────│ Step 10: IV XOR  │
│ (BLAKE3 │     │ Tag             │     │                  │
│ keyed   │     │                 │     ┌────────┴─────────┐
│ hash)   │     │                 │     │ Step 9: Backward │
└─────────┘     └─────────────────┘     │ Diffusion        │
                                         ┌────────┴─────────┐
                                         │ Step 8: Forward  │
                                         │ Diffusion        │
                                         ┌────────┴─────────┐
                                         │ Step 7: Permute  │
                                         │ (Fisher–Yates)   │
                                         ┌────────┴─────────┐
                                         │ Step 6: S-box    │
                                         │ Substitution     │
                                         ┌────────┴─────────┐
                                         │ Step 5: Lorenz   │
                                         │ + IV XOR         │
                                         ┌────────┴─────────┐
                                         │ Step 4: Key      │
                                         │ Stream Gen       │
                                         └──────────────────┘
```

---

## 10. Trust Boundaries

| Component | Trusted? | Reason |
|-----------|----------|--------|
| Master key | Yes | Only secret material |
| Nonce | No | Public, random per message |
| IV | No | Public, random per message |
| BLAKE3 | Yes | Standard cryptographic primitive |
| S-box | Yes | Keyed, invertible permutation |
| Lorenz map | No | Public parameters, keyed through seed |
| Authentication tag | Yes | Verified before decryption |

---

## 11. Failure Modes

| Failure | Detection | Consequence |
|---------|-----------|-------------|
| Wrong key | Tag mismatch | `decrypt()` returns `None` |
| Tampered payload | Tag mismatch | `decrypt()` returns `None` |
| Truncated container | Size check | `deserialize()` returns `None` |
| Bad magic bytes | Magic check | `deserialize()` returns `None` |
| Corrupted header | Parse failure | `deserialize()` returns `None` |

---

## 12. Comparison with Original Design

| Feature | Original | This Implementation |
|---------|----------|---------------------|
| Lorenz | Float64 RK4 | Fixed-point Q32.32 |
| IV | Plaintext-derived | Random per message |
| Key separation | None | enc/auth/sbox keys |
| RGB mixing | Linear XOR | Non-linear S-box |
| Authentication | None specified | BLAKE3 keyed hash |
| Permutation inverse | Ambiguous | Explicit `apply_perm_inverse` |
| Security proof | None | None (explicitly stated) |
