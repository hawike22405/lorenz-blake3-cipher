/*!
 * Lorenz-BLAKE3 image cipher — research reference implementation.
 *
 * This is a reproducible reference skeleton that addresses the flaws
 * identified in the original audit:
 *   * random per-message IV (not plaintext-derived),
 *   * key separation (encryption key vs. authentication key),
 *   * non-linear S-box substitution (replaces linear RGB XOR mixing),
 *   * explicit Fisher–Yates permutation with invertible inverse,
 *   * BLAKE3 keyed-hash authentication tag without a construction-level forgery proof,
 *   * fixed-point Lorenz map (avoids Float64 RK4 portability problems).
 *
 * WARNING: This is a research prototype. It has NO security proof.
 * Do not use for sensitive real-world data. Use AES-GCM or
 * ChaCha20-Poly1305 instead.
 */

use blake3::Hasher;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
pub const MAX_PAYLOAD: usize = 64 * 1024 * 1024;

pub fn payload_len(width: u32, height: u32, channels: u8) -> Option<usize> {
    if width == 0 || height == 0 || !(1..=4).contains(&channels) {
        return None;
    }
    let n = (width as usize)
        .checked_mul(height as usize)?
        .checked_mul(channels as usize)?;
    (n <= MAX_PAYLOAD).then_some(n)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Container magic bytes.
const MAGIC: &[u8; 8] = b"LRZIMG02";
/// Header size: 8 (magic) + 4 (width) + 4 (height) + 1 (channels) + 32 (nonce) + 32 (iv).
pub const HEADER_SIZE: usize = 81;
/// Authentication tag size in bytes (BLAKE3 output).
const TAG_SIZE: usize = 32;
// Fixed Lorenz parameters (public, constant). These are NOT secret.
const LORENZ_SIGMA: i64 = 10;
const LORENZ_RHO: i64 = 28;
const LORENZ_BETA_NUM: i64 = 8;
const LORENZ_BETA_DEN: i64 = 3;

// ---------------------------------------------------------------------------
// Fixed-point Lorenz attractor (Q32.32)
// ---------------------------------------------------------------------------
// Using 64-bit fixed-point arithmetic avoids Float64/RK4 portability issues.
// The map is iterated with a simple explicit Euler step; dt is fixed.

/// Iterate the Lorenz system for `steps` using fixed-point arithmetic.
/// Eight x-state bytes per retained step after 1000 discarded steps.
fn lorenz_stream(seed: u64, steps: usize) -> Vec<u8> {
    // Bounded initial conditions; Q32.32, simultaneous explicit Euler updates.
    let q = 1i128 << 32;
    let mut x = q + ((seed & 0xffff) as i128 * q / 65536);
    let mut y = q + (((seed >> 16) & 0xffff) as i128 * q / 65536);
    let mut z = q + ((seed >> 32) as i128);
    let mut out = Vec::with_capacity(steps * 8);
    for i in 0..steps + 1000 {
        let dx = LORENZ_SIGMA as i128 * (y - x);
        let dy = (x * (LORENZ_RHO as i128 * q - z) >> 32) - y;
        let dz = (x * y >> 32) - (LORENZ_BETA_NUM as i128 * z / LORENZ_BETA_DEN as i128);
        x += (42949673i128 * dx) >> 32;
        y += (42949673i128 * dy) >> 32;
        z += (42949673i128 * dz) >> 32;
        // This bound is a defensive invariant, not a chaotic-security argument.
        assert!([x, y, z].iter().all(|v| v.abs() < 1024 * q));
        if i >= 1000 {
            out.extend_from_slice(&(x as i64).to_le_bytes());
        }
    }
    out
}

fn payload_stream(keys: &Keys, iv: &[u8; 32], n: usize) -> Vec<u8> {
    let trajectory = lorenz_stream(keys.schedule_seed, 4096);
    let mut h = Hasher::new_keyed(&keys.enc_key);
    h.update(b"lrz02-payload");
    h.update(iv);
    h.update(&trajectory);
    let mut out = vec![0; n];
    h.finalize_xof().fill(&mut out);
    out
}

fn bounded(reader: &mut blake3::OutputReader, bound: usize) -> usize {
    let bound = bound as u64;
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let mut b = [0; 8];
        reader.fill(&mut b);
        let x = u64::from_le_bytes(b);
        if x >= threshold {
            return (x % bound) as usize;
        }
    }
}

/// Derive a 64-bit Lorenz seed from BLAKE3 key material.
fn lorenz_seed(master_key: &[u8; 32], nonce: &[u8; 32]) -> u64 {
    let mut h = Hasher::new_keyed(master_key);
    h.update(b"lorenz-seed");
    h.update(nonce);
    let binding = h.finalize();
    let seed_bytes = binding.as_bytes();
    u64::from_le_bytes(seed_bytes[..8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Keyed BLAKE3 helper (takes a slice, internally copies to [u8;32])
// ---------------------------------------------------------------------------

fn blake3_keyed(key: &[u8; 32], context: &[u8], input: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_keyed(key);
    h.update(context);
    h.update(input);
    let binding = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(binding.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// S-box (non-linear, invertible)
// ---------------------------------------------------------------------------
// A simple 8-bit S-box built from key material via BLAKE3-driven Fisher-Yates.

fn build_sbox(key: &[u8; 32]) -> [u8; 256] {
    let mut sbox = core::array::from_fn(|i| i as u8);
    let seed = blake3_keyed(key, b"lrz02-sbox", &[]);
    let mut reader = Hasher::new_keyed(&seed).finalize_xof();
    for i in (1..256).rev() {
        let j = bounded(&mut reader, i + 1);
        sbox.swap(i, j);
    }
    sbox
}

fn sbox_sub(data: &mut [u8], sbox: &[u8; 256]) {
    for b in data.iter_mut() {
        *b = sbox[*b as usize];
    }
}

// ---------------------------------------------------------------------------
// Key schedule
// ---------------------------------------------------------------------------

/// Derived keys produced from the master 32-byte key and 32-byte nonce.
pub struct Keys {
    pub enc_key: [u8; 32],  // for permutation + diffusion
    pub auth_key: [u8; 32], // for authentication tag
    pub sbox_key: [u8; 32], // for S-box derivation
    pub schedule_seed: u64, // for Lorenz stream
}

pub fn derive_keys(master_key: &[u8; 32], nonce: &[u8; 32]) -> Keys {
    let enc_key = blake3_keyed(master_key, b"lorenz-blake3-key-schedule", nonce);
    let auth_key = blake3_keyed(master_key, b"auth-key", &enc_key);
    let sbox_key = blake3_keyed(master_key, b"sbox-key", &auth_key);
    let schedule_seed = lorenz_seed(master_key, nonce);

    Keys {
        enc_key,
        auth_key,
        sbox_key,
        schedule_seed,
    }
}

// ---------------------------------------------------------------------------
// Permutation (Fisher–Yates)
// ---------------------------------------------------------------------------

/// Produce a final-position permutation array of length n using a keyed stream.
fn fisher_yates_perm(n: usize, enc_key: &[u8; 32]) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..n).collect();
    let seed = blake3_keyed(enc_key, b"lrz02-permutation", &[]);
    let mut reader = Hasher::new_keyed(&seed).finalize_xof();
    for i in (1..n).rev() {
        let j = bounded(&mut reader, i + 1);
        perm.swap(i, j);
    }
    perm
}

/// Apply permutation to pixel bytes (interleaved channels).
/// `perm[out_pos]` = input position that moves to out_pos.
fn apply_perm(data: &mut [u8], perm: &[usize]) {
    let mut out = vec![0u8; data.len()];
    for (out_pos, &in_pos) in perm.iter().enumerate() {
        out[out_pos] = data[in_pos];
    }
    data.copy_from_slice(&out);
}

/// Invert the permutation.
fn apply_perm_inverse(data: &mut [u8], perm: &[usize]) {
    let mut out = vec![0u8; data.len()];
    for (out_pos, &in_pos) in perm.iter().enumerate() {
        out[in_pos] = data[out_pos];
    }
    data.copy_from_slice(&out);
}

// ---------------------------------------------------------------------------
// Diffusion (two-pass nonlinear feedback)
// ---------------------------------------------------------------------------

// Injective feedback in carry for a fixed input byte; still no security proof.
fn diffuse_forward(data: &mut [u8], sbox: &[u8; 256]) {
    let mut carry = 0;
    for b in data.iter_mut() {
        *b = sbox[(*b ^ carry) as usize];
        carry = *b;
    }
}
fn diffuse_backward(data: &mut [u8], sbox: &[u8; 256]) {
    let mut carry = 0;
    for b in data.iter_mut().rev() {
        *b = sbox[(*b ^ carry) as usize];
        carry = *b;
    }
}
fn undiffuse_backward(data: &mut [u8], sbox: &[u8; 256]) {
    let mut inv = [0; 256];
    for (i, &v) in sbox.iter().enumerate() {
        inv[v as usize] = i as u8;
    }
    let mut carry = 0;
    for b in data.iter_mut().rev() {
        let c = *b;
        *b = inv[c as usize] ^ carry;
        carry = c;
    }
}
fn undiffuse_forward(data: &mut [u8], sbox: &[u8; 256]) {
    let mut inv = [0; 256];
    for (i, &v) in sbox.iter().enumerate() {
        inv[v as usize] = i as u8;
    }
    let mut carry = 0;
    for b in data.iter_mut() {
        let c = *b;
        *b = inv[c as usize] ^ carry;
        carry = c;
    }
}

// ---------------------------------------------------------------------------
// Container format
// ---------------------------------------------------------------------------

pub struct Header {
    pub width: u32,
    pub height: u32,
    pub channels: u8,
    pub nonce: [u8; 32],
    pub iv: [u8; 32],
}

impl Header {
    pub fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(MAGIC);
        buf[8..12].copy_from_slice(&self.width.to_le_bytes());
        buf[12..16].copy_from_slice(&self.height.to_le_bytes());
        buf[16] = self.channels;
        buf[17..49].copy_from_slice(&self.nonce);
        buf[49..81].copy_from_slice(&self.iv);
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE || &buf[0..8] != MAGIC {
            return None;
        }
        let width = u32::from_le_bytes(buf[8..12].try_into().ok()?);
        let height = u32::from_le_bytes(buf[12..16].try_into().ok()?);
        let channels = buf[16];
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&buf[17..49]);
        let mut iv = [0u8; 32];
        iv.copy_from_slice(&buf[49..81]);
        Some(Header {
            width,
            height,
            channels,
            nonce,
            iv,
        })
    }
}

/// Authentication tag: BLAKE3 keyed hash over header || ciphertext.
pub fn compute_tag(auth_key: &[u8; 32], header: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_keyed(auth_key);
    h.update(header);
    h.update(ciphertext);
    let binding = h.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(binding.as_bytes());
    tag
}

pub fn verify_tag(auth_key: &[u8; 32], header: &[u8], ciphertext: &[u8], tag: &[u8; 32]) -> bool {
    let expected = compute_tag(auth_key, header, ciphertext);
    bool::from(tag.ct_eq(&expected))
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

pub struct CiphertextContainer {
    pub header: Header,
    pub payload: Vec<u8>,
    pub tag: [u8; 32],
}

impl CiphertextContainer {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.header.serialize().to_vec();
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.tag);
        out
    }

    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE + TAG_SIZE {
            return None;
        }
        let header = Header::deserialize(&buf[0..HEADER_SIZE])?;
        let total_payload = payload_len(header.width, header.height, header.channels)?;
        if buf.len()
            != HEADER_SIZE
                .checked_add(total_payload)?
                .checked_add(TAG_SIZE)?
        {
            return None;
        }
        let payload = buf[HEADER_SIZE..HEADER_SIZE + total_payload].to_vec();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(
            &buf[HEADER_SIZE + total_payload..HEADER_SIZE + total_payload + TAG_SIZE],
        );
        Some(CiphertextContainer {
            header,
            payload,
            tag,
        })
    }
}

/// Encrypt a raw interleaved byte buffer.
pub fn encrypt(
    master_key: &[u8; 32],
    plaintext: &[u8],
    width: u32,
    height: u32,
    channels: u8,
    rng: &mut (impl RngCore + CryptoRng + ?Sized),
) -> Result<CiphertextContainer, &'static str> {
    let expected = payload_len(width, height, channels).ok_or("invalid or oversized geometry")?;
    if expected != plaintext.len() {
        return Err("payload length does not match geometry");
    }
    // Random per-message nonce and IV.
    let mut nonce = [0u8; 32];
    let mut iv = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    rng.fill_bytes(&mut iv);

    let keys = derive_keys(master_key, &nonce);
    let sbox = build_sbox(&keys.sbox_key);

    let lorenz_key_stream = payload_stream(&keys, &iv, plaintext.len());

    let mut data = plaintext.to_vec();

    // Step 1: XOR with Lorenz + IV stream (confusion).
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= lorenz_key_stream[i];
    }

    // Step 2: Non-linear S-box substitution.
    sbox_sub(&mut data, &sbox);

    // Step 3: Fisher-Yates permutation (spatial scrambling).
    let perm = fisher_yates_perm(data.len(), &keys.enc_key);
    apply_perm(&mut data, &perm);

    // Step 4: Two-pass nonlinear feedback diffusion.
    diffuse_forward(&mut data, &sbox);
    diffuse_backward(&mut data, &sbox);

    // Step 5: XOR with IV again (binds ciphertext to IV).
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= iv[i % 32];
    }

    let header = Header {
        width,
        height,
        channels,
        nonce,
        iv,
    };

    let tag = compute_tag(&keys.auth_key, &header.serialize(), &data);

    Ok(CiphertextContainer {
        header,
        payload: data,
        tag,
    })
}

/// Decrypt and verify. Returns None on authentication failure.
pub fn decrypt(master_key: &[u8; 32], container: &CiphertextContainer) -> Option<Vec<u8>> {
    if payload_len(
        container.header.width,
        container.header.height,
        container.header.channels,
    )? != container.payload.len()
    {
        return None;
    }
    let keys = derive_keys(master_key, &container.header.nonce);
    let sbox = build_sbox(&keys.sbox_key);

    // Verify authentication tag BEFORE any transformation (fail-fast).
    if !verify_tag(
        &keys.auth_key,
        &container.header.serialize(),
        &container.payload,
        &container.tag,
    ) {
        return None;
    }

    let mut data = container.payload.clone();
    let iv = &container.header.iv;

    // Inverse of Step 5.
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= iv[i % 32];
    }

    // Inverse of Step 4 (reverse order of forward passes).
    undiffuse_backward(&mut data, &sbox);
    undiffuse_forward(&mut data, &sbox);

    // Inverse of Step 3.
    let perm = fisher_yates_perm(data.len(), &keys.enc_key);
    apply_perm_inverse(&mut data, &perm);

    // Inverse of Step 2 (inverse S-box).
    let inv_sbox = {
        let mut inv = [0u8; 256];
        for (i, &v) in sbox.iter().enumerate() {
            inv[v as usize] = i as u8;
        }
        inv
    };
    for b in data.iter_mut() {
        *b = inv_sbox[*b as usize];
    }

    // Inverse of Step 1.
    let n = data.len();
    let lorenz_bytes = payload_stream(&keys, iv, n);
    for (b, l) in data.iter_mut().zip(lorenz_bytes.iter().take(n)) {
        *b ^= *l;
    }

    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn round_trip_helper(plaintext: &[u8], width: u32, height: u32, channels: u8, seed: u64) {
        let key = [0x42u8; 32];
        let mut rng = StdRng::seed_from_u64(seed);
        let container = encrypt(&key, plaintext, width, height, channels, &mut rng).unwrap();
        let decrypted = decrypt(&key, &container).expect("decryption failed");
        assert_eq!(decrypted, plaintext, "round-trip failed");
    }

    #[test]
    fn test_round_trip_small() {
        let pt = [0x00u8; 256];
        round_trip_helper(&pt, 8, 8, 4, 42);
    }

    #[test]
    fn test_round_trip_random() {
        let mut rng = StdRng::seed_from_u64(12345);
        let mut pt = vec![0u8; 1024];
        rng.fill_bytes(&mut pt);
        round_trip_helper(&pt, 16, 16, 4, 7);
    }

    #[test]
    fn test_round_trip_rgba() {
        let pt: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect(); // 16x16 RGBA
        round_trip_helper(&pt, 16, 16, 4, 99);
    }

    #[test]
    fn test_round_trip_rgb() {
        let pt: Vec<u8> = (0..768).map(|i| ((i * 7) % 256) as u8).collect(); // 16x16 RGB
        round_trip_helper(&pt, 16, 16, 3, 31337);
    }

    #[test]
    fn test_round_trip_grayscale() {
        let pt: Vec<u8> = (0..256).map(|i| i as u8).collect(); // 16x16 grayscale
        round_trip_helper(&pt, 16, 16, 1, 2024);
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let pt = [0x00u8; 256];
        let mut rng = StdRng::seed_from_u64(42);
        let container = encrypt(&key1, &pt, 8, 8, 4, &mut rng).unwrap();
        let result = decrypt(&key2, &container);
        assert!(result.is_none(), "wrong key should be rejected");
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let key = [0x33u8; 32];
        let pt = [0x00u8; 256];
        let mut rng = StdRng::seed_from_u64(42);
        let mut container = encrypt(&key, &pt, 8, 8, 4, &mut rng).unwrap();
        // Flip one payload byte
        container.payload[10] ^= 0xFF;
        let result = decrypt(&key, &container);
        assert!(result.is_none(), "tampered payload should be rejected");
    }

    #[test]
    fn test_sbox_is_permutation() {
        let key = [0x55u8; 32];
        let sbox = build_sbox(&key);
        let mut seen = [false; 256];
        for &v in &sbox {
            assert!(!seen[v as usize], "S-box is not a permutation");
            seen[v as usize] = true;
        }
        assert!(
            seen.iter().all(|&x| x),
            "S-box does not cover all byte values"
        );
    }

    #[test]
    fn test_perm_is_permutation() {
        let key = [0x66u8; 32];
        let n = 1000;
        let perm = fisher_yates_perm(n, &key);
        let mut seen = vec![false; n];
        for &p in &perm {
            assert!(p < n, "permutation value out of range");
            assert!(!seen[p], "permutation has duplicate");
            seen[p] = true;
        }
        assert!(
            seen.iter().all(|&x| x),
            "permutation does not cover all indices"
        );
    }

    #[test]
    fn test_perm_inverse() {
        let key = [0x77u8; 32];
        let n = 500;
        let perm = fisher_yates_perm(n, &key);
        let mut data: Vec<u8> = (0..n as u8).cycle().take(n).collect();
        let original = data.clone();
        apply_perm(&mut data, &perm);
        apply_perm_inverse(&mut data, &perm);
        assert_eq!(data, original, "perm inverse failed");
    }

    #[test]
    fn test_lorenz_stream_deterministic() {
        let s1 = lorenz_stream(42, 100);
        let s2 = lorenz_stream(42, 100);
        assert_eq!(s1, s2, "Lorenz stream must be deterministic");
        let s3 = lorenz_stream(43, 100);
        assert_ne!(s1, s3, "different seeds should produce different streams");
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    #[test]
    fn rejects_bad_geometry_and_trailing_bytes() {
        let key = [7; 32];
        let mut rng = StdRng::seed_from_u64(9);
        assert!(encrypt(&key, &[0; 3], 1, 1, 4, &mut rng).is_err());
        assert!(payload_len(u32::MAX, u32::MAX, 4).is_none());
        assert!(payload_len(0, 1, 3).is_none());
        assert!(payload_len(1, 1, 5).is_none());
        let c = encrypt(&key, &[0; 4], 1, 1, 4, &mut rng).unwrap();
        let mut b = c.serialize();
        b.push(0);
        assert!(CiphertextContainer::deserialize(&b).is_none());
        b.pop();
        b.pop();
        assert!(CiphertextContainer::deserialize(&b).is_none());
    }
    #[test]
    fn every_header_and_tag_bit_is_rejected() {
        let key = [7; 32];
        let mut rng = StdRng::seed_from_u64(9);
        let c = encrypt(&key, &[0; 4], 1, 1, 4, &mut rng).unwrap();
        let b = c.serialize();
        for byte in (0..81).chain(85..117) {
            for bit in 0..8 {
                let mut changed = b.clone();
                changed[byte] ^= 1 << bit;
                if let Some(parsed) = CiphertextContainer::deserialize(&changed) {
                    assert!(decrypt(&key, &parsed).is_none());
                }
            }
        }
    }
    #[test]
    fn all_shapes_and_modes_serialize() {
        for (w, h) in [(1, 1), (1, 17), (19, 1), (17, 23), (64, 64)] {
            for ch in 1..=4 {
                let p = vec![127; (w * h * ch) as usize];
                let mut rng = StdRng::seed_from_u64(1);
                let c = encrypt(&[3; 32], &p, w, h, ch as u8, &mut rng).unwrap();
                let parsed = CiphertextContainer::deserialize(&c.serialize()).unwrap();
                assert_eq!(decrypt(&[3; 32], &parsed).unwrap(), p);
            }
        }
    }
    #[test]
    fn version_and_stream_vectors() {
        let mut rng = StdRng::seed_from_u64(9);
        let c = encrypt(&[7; 32], &[0; 4], 1, 1, 4, &mut rng).unwrap();
        assert_eq!(&c.serialize()[..8], b"LRZIMG02");
        assert_eq!(
            blake3::hash(&c.serialize()).to_hex().as_str(),
            "9fea7c94f8a354d120d798381d1f0f79c16b9075ea8b004d7b4f8132556cefd6"
        );
        let mut old = c.serialize();
        old[..8].copy_from_slice(b"LRZIMG01");
        assert!(CiphertextContainer::deserialize(&old).is_none());
    }
    #[test]
    #[ignore]
    fn evaluation() {
        let key = [42; 32];

        let p: Vec<u8> = (0..12288).map(|i| (i % 251) as u8).collect();
        println!("REVIEW_JSON_BEGIN");
        print!("[\n");
        for mode in 0..5 {
            // Modes: full; Lorenz replaced by zero trajectory; no diffusion; no permutation.
            for trial in 0..100 {
                let mut nonce = [0; 32];
                let mut paired_rng = StdRng::seed_from_u64(20261118 + trial as u64);
                paired_rng.fill_bytes(&mut nonce);
                let iv = [5; 32];
                let keys = derive_keys(&key, &nonce);
                let sbox = build_sbox(&keys.sbox_key);
                let perm = fisher_yates_perm(p.len(), &keys.enc_key);
                let stream = if mode == 1 {
                    let mut h = Hasher::new_keyed(&keys.enc_key);
                    h.update(b"lrz02-payload");
                    h.update(&iv);
                    h.update(&vec![0; 4096 * 8]);
                    let mut s = vec![0; p.len()];
                    h.finalize_xof().fill(&mut s);
                    s
                } else {
                    payload_stream(&keys, &iv, p.len())
                };
                let transform = |input: &[u8]| {
                    let mut d: Vec<u8> = input.iter().zip(&stream).map(|(a, b)| a ^ b).collect();
                    sbox_sub(&mut d, &sbox);
                    if mode != 3 {
                        apply_perm(&mut d, &perm);
                    }
                    if mode == 4 {
                        let mut carry = 0;
                        for b in d.iter_mut() {
                            *b = sbox[b.wrapping_add(carry) as usize] ^ carry;
                            carry = *b;
                        }
                        carry = 0;
                        for b in d.iter_mut().rev() {
                            *b = sbox[b.wrapping_sub(carry) as usize] ^ carry;
                            carry = *b;
                        }
                    } else if mode != 2 {
                        diffuse_forward(&mut d, &sbox);
                        diffuse_backward(&mut d, &sbox);
                    }
                    d
                };
                let mut changed = p.clone();
                changed[(trial * 127) % p.len()] ^= 1;
                let a = transform(&p);
                let b = transform(&changed);
                let n = a.iter().zip(&b).filter(|(x, y)| x != y).count() as f64 * 100.0
                    / p.len() as f64;
                let u = a
                    .iter()
                    .zip(&b)
                    .map(|(x, y)| (*x as i32 - *y as i32).unsigned_abs() as u64)
                    .sum::<u64>() as f64
                    * 100.0
                    / (255 * p.len()) as f64;
                println!(
                    "{{\"mode\":{},\"trial\":{},\"npcr\":{},\"uaci\":{}}}{}",
                    mode,
                    trial,
                    n,
                    u,
                    if mode == 4 && trial == 99 { "" } else { "," }
                );
            }
        }
        println!("]\nREVIEW_JSON_END");
    }
}
