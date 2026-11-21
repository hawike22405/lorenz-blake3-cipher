# Reviewed LRZIMG02 specification

This document replaces the inaccurate original architecture description. The code is normative; this remains an experimental construction with no security proof.

## Container and parsing

Header: ASCII `LRZIMG02` (8 bytes), width u32-LE (4), height u32-LE (4), channel count (1), nonce (32), random IV (32). Payload is exactly width × height × channels bytes; tag is 32 bytes. Overhead: 113 bytes. Zero dimensions, channel counts outside 1–4, overflow, more than 256 MiB and trailing/truncated bytes are rejected. The raw API checks payload/geometry consistency. The CLI limits input reads, refuses existing outputs and never writes on authentication failure. Parser allocation still occurs before MAC verification but is explicitly bounded.

## Domains and keys

All keys are 32 bytes, with K the master and N the nonce:

- E = keyed BLAKE3(K, ASCII `lorenz-blake3-key-schedule` || N)
- A = keyed BLAKE3(K, ASCII `auth-key` || E)
- S = keyed BLAKE3(K, ASCII `sbox-key` || A)
- seed = first 8 bytes, interpreted u64-LE, of keyed BLAKE3(K, ASCII `lorenz-seed` || N).

These are domain-separated derived keys, not information-theoretically independent keys. Internal slice keys are always 32 bytes at current call sites. Nonce and IV are filled from OsRng in the CLI; generic encryption requires RngCore + CryptoRng.

## Integer trajectory

Let q=2^32. Initial states: x=q+(seed & 65535)q/65536, y=q+((seed>>16)&65535)q/65536, z=q+(seed>>32). Integer division truncates toward zero. All working arithmetic is i128. At each simultaneous Euler step:

```
dx = 10*(y-x)
dy = (x*(28*q-z) >> 32)-y
dz = (x*y >> 32)-(8*z/3)
x += (42949673*dx) >> 32
y += (42949673*dy) >> 32
z += (42949673*dz) >> 32
```

Signed shifts are arithmetic. A defensive bound requires absolute states below 1024q. Discard 1000 steps; retain 4096 x states, each serialized i64-LE (32768 bytes). The nominal seed is only 64 bits; no 256-bit Lorenz-strength claim is made. The frozen vector passed debug/release CI on Linux, Windows and macOS; broader interoperability remains unverified.

## Streams and permutation

Payload stream: keyed BLAKE3 XOF under E, absorbing ASCII `lrz02-payload`, IV, trajectory. Request exactly the payload length. This prevents raw chaotic bytes from being the payload keystream.

S-box stream seed: keyed BLAKE3(S, ASCII `lrz02-sbox`). Permutation stream seed: keyed BLAKE3(E, ASCII `lrz02-permutation`). Each seeds a keyed BLAKE3 XOF with empty message. Fisher–Yates uses u64-LE draws and rejection sampling: reject draws smaller than (-bound mod 2^64) mod bound; use draw mod bound otherwise. S-box shuffles 0…255; the final-position byte permutation shuffles 0…length-1. Both use descending indices. The permutation maps output index to input index and is inverted explicitly.

## Transformation and inverse

XOR plaintext with payload stream; substitute each byte through S-box; permute bytes. Forward recurrence c_i=S[p_i XOR c_(i-1)], boundary zero. Backward recurrence d_i=S[c_i XOR d_(i+1)], boundary zero. Finally XOR the public IV repeatedly (this step adds no secret entropy). Inversion removes this final IV XOR, inverts the backward and forward recurrences using inverse S-box lookup and saved original feedback bytes, inverts permutation and substitution, and XORs the payload stream.

Tag: keyed BLAKE3(A, complete 81-byte header || payload), verified with subtle::ConstantTimeEq before the inverse transforms. No automatic replay or nonce-reuse rejection exists. The S-box accesses are data-dependent; this is not a constant-time cipher implementation as a whole.

## Compatibility and practical use

LRZIMG01 inputs are rejected. The feedback, trajectory, stream expansion and shuffling changed; silently reusing the old version marker would be incorrect. Keep the original source/commit separately to study old files; never claim compatibility with the earlier Float64 RK4 archive merely because it used the same magic string.

For real file protection use scripts/aead_file.py (AES-GCM) or an established audited encryption product, not this experimental pipeline. The AES wrapper is a separate format and implementation path.
