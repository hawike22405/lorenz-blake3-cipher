/*!
 * Lorenz-BLAKE3 image cipher — research reference implementation.
 *
 * This is a reproducible reference skeleton that addresses the flaws
 * identified in the original audit:
 *   * random per-message IV (not plaintext-derived),
 *   * key separation (encryption key vs. authentication key),
 *   * non-linear S-box substitution (replaces linear RGB XOR mixing),
 *   * explicit Fisher–Yates permutation with invertible inverse,
 *   * BLAKE3 keyed-hash authentication tag with a forgery bound of 2^-256,
 *   * fixed-point Lorenz map (avoids Float64 RK4 portability problems).
 *
 * WARNING: This is a research prototype. It has NO security proof.
 * Do not use for sensitive real-world data. Use AES-GCM or
 * ChaCha20-Poly1305 instead.
 */

use blake3::Hasher;
use rand::RngCore;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Container magic bytes.
const MAGIC: &[u8; 8] = b"LRZIMG01";
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
/// Returns raw fixed-point x-state bytes after each step.
fn lorenz_stream(seed: u64, steps: usize) -> Vec<u8> {
    // Fixed-point state (Q32.32). Seed derives initial conditions from key material.
    let mut x: i64 = (seed as i64).wrapping_mul(2654435761) % (i64::MAX / 4);
    let mut y: i64 = ((seed as i64).wrapping_mul(40503) % 1000000) * 1000000;
    let mut z: i64 = 1000000000;

    // dt in fixed point: 0.01 * 2^32  (approx 42949673)
    let dt: i64 = 42949673;

    let mut out = Vec::with_capacity(steps * 4);

    for _ in 0..steps {
        // dx/dt = sigma * (y - x)
        let dx = LORENZ_SIGMA.wrapping_mul(y.wrapping_sub(x));
        // dy/dt = x * (rho - z) - y
        let dy = x.wrapping_mul(LORENZ_RHO.wrapping_sub(z)).wrapping_sub(y);
        // dz/dt = x * y - beta * z
        let dz = x.wrapping_mul(y).wrapping_sub(LORENZ_BETA_NUM.wrapping_mul(z) / LORENZ_BETA_DEN);

        // Euler step: state += dt * derivative / 2^32
        x = x.wrapping_add(dt.wrapping_mul(dx) >> 32);
        y = y.wrapping_add(dt.wrapping_mul(dy) >> 32);
        z = z.wrapping_add(dt.wrapping_mul(dz) >> 32);

        out.extend_from_slice(&x.to_le_bytes());
    }
    out
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

fn blake3_keyed(key: &[u8], context: &[u8], input: &[u8]) -> [u8; 32] {
    // blake3::Hasher::new_keyed requires &[u8; 32]. We pad/truncate the key to 32 bytes.
    let mut k = [0u8; 32];
    let len = key.len().min(32);
    k[..len].copy_from_slice(&key[..len]);
    let mut h = Hasher::new_keyed(&k);
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

fn build_sbox(key: &[u8]) -> [u8; 256] {
    let mut sbox: [u8; 256] = core::array::from_fn(|i| i as u8);
    // Deterministic key stream from BLAKE3 (unkeyed, context-separated).
    let mut stream: Vec<u8> = blake3_keyed(key, b"sbox-stream", &[]).to_vec();
    let mut pos: usize = 0;

    for i in (1..256).rev() {
        if pos + 4 > stream.len() {
            let ext = blake3_keyed(key, b"sbox-ext", &[pos as u8]);
            stream.extend_from_slice(&ext);
        }
        let j = u32::from_le_bytes(stream[pos..pos + 4].try_into().unwrap()) as usize % (i + 1);
        pos += 4;
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
    pub enc_key: [u8; 32],   // for permutation + diffusion
    pub auth_key: [u8; 32],  // for authentication tag
    pub sbox_key: [u8; 32],  // for S-box derivation
    pub schedule_seed: u64,  // for Lorenz stream
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
fn fisher_yates_perm(n: usize, enc_key: &[u8]) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..n).collect();
    let mut stream: Vec<u8> = blake3_keyed(enc_key, b"fisher-yates-stream", &[]).to_vec();
    let mut pos: usize = 0;

    for i in (1..n).rev() {
        if pos + 4 > stream.len() {
            let ext = blake3_keyed(enc_key, b"fy-ext", &[(pos % 256) as u8]);
            stream.extend_from_slice(&ext);
        }
        let j = u32::from_le_bytes(stream[pos..pos + 4].try_into().unwrap()) as usize % (i + 1);
        pos += 4;
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

fn diffuse_forward(data: &mut [u8], sbox: &[u8; 256]) {
    let mut carry: u8 = 0;
    for b in data.iter_mut() {
        let mixed = b.wrapping_add(carry);
        let subbed = sbox[mixed as usize];
        *b = subbed ^ carry;
        carry = *b;
    }
}

fn diffuse_backward(data: &mut [u8], sbox: &[u8; 256]) {
    let mut carry: u8 = 0;
    for b in data.iter_mut().rev() {
        let mixed = b.wrapping_sub(carry);
        let subbed = sbox[mixed as usize];
        *b = subbed ^ carry;
        carry = *b;
    }
}

fn undiffuse_backward(data: &mut [u8], sbox: &[u8; 256]) {
    // Inverse of diffuse_backward, which processed n-1..0.
    // Reverse order: process n-1 down to 0.
    // diffuse_backward: out[i] = sbox[in[i] - out[i+1]] ^ out[i+1], out[n] = 0
    // in[i] = sbox_inv[out[i] ^ out[i+1]] + out[i+1]
    let mut carry: u8 = 0; // out[i+1], starts as out[n] = 0
    for i in (0..data.len()).rev() {
        let out_i = data[i];
        let xored = out_i ^ carry;
        let mut pre = 0u8;
        for (j, &v) in sbox.iter().enumerate() {
            if v == xored {
                pre = j as u8;
                break;
            }
        }
        data[i] = pre.wrapping_add(carry);
        carry = out_i;
    }
}

fn undiffuse_forward(data: &mut [u8], sbox: &[u8; 256]) {
    // Inverse of diffuse_forward, which processed 0..n-1.
    // Forward order: process 0 to n-1.
    // diffuse_forward: out[i] = sbox[in[i] + out[i-1]] ^ out[i-1], out[-1] = 0
    // in[i] = sbox_inv[out[i] ^ out[i-1]] - out[i-1]
    let mut carry: u8 = 0; // out[i-1], starts as out[-1] = 0
    for b in data.iter_mut() {
        let out_i = *b;
        let xored = out_i ^ carry;
        let mut pre = 0u8;
        for (j, &v) in sbox.iter().enumerate() {
            if v == xored {
                pre = j as u8;
                break;
            }
        }
        *b = pre.wrapping_sub(carry);
        carry = out_i;
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
    tag.iter().zip(expected.iter()).all(|(a, b)| a == b)
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
        let total_payload = (header.width as usize)
            * (header.height as usize)
            * (header.channels as usize);
        if buf.len() < HEADER_SIZE + total_payload + TAG_SIZE {
            return None;
        }
        let payload = buf[HEADER_SIZE..HEADER_SIZE + total_payload].to_vec();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&buf[HEADER_SIZE + total_payload..HEADER_SIZE + total_payload + TAG_SIZE]);
        Some(CiphertextContainer { header, payload, tag })
    }
}

/// Encrypt a raw interleaved byte buffer.
pub fn encrypt(
    master_key: &[u8; 32],
    plaintext: &[u8],
    width: u32,
    height: u32,
    channels: u8,
    rng: &mut (impl RngCore + ?Sized),
) -> CiphertextContainer {
    // Random per-message nonce and IV.
    let mut nonce = [0u8; 32];
    let mut iv = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    rng.fill_bytes(&mut iv);

    let keys = derive_keys(master_key, &nonce);
    let sbox = build_sbox(&keys.sbox_key);

    // Lorenz stream mixes into the IV to form the initial key stream.
    // lorenz_stream yields 4 bytes per step; request enough steps to cover plaintext.len().
    let lorenz_steps = plaintext.len().div_ceil(4);
    let lorenz_bytes = lorenz_stream(keys.schedule_seed, lorenz_steps);
    let lorenz_key_stream: Vec<u8> = lorenz_bytes
        .iter()
        .cycle()
        .zip(iv.iter().cycle())
        .take(plaintext.len())
        .map(|(l, v)| *l ^ *v)
        .collect();

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

    CiphertextContainer {
        header,
        payload: data,
        tag,
    }
}

/// Decrypt and verify. Returns None on authentication failure.
pub fn decrypt(
    master_key: &[u8; 32],
    container: &CiphertextContainer,
) -> Option<Vec<u8>> {
    let keys = derive_keys(master_key, &container.header.nonce);
    let sbox = build_sbox(&keys.sbox_key);

    // Verify authentication tag BEFORE any transformation (fail-fast).
    if !verify_tag(&keys.auth_key, &container.header.serialize(), &container.payload, &container.tag)
    {
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
    let lorenz_steps = n.div_ceil(4);
    let lorenz_bytes = lorenz_stream(keys.schedule_seed, lorenz_steps);
    for (i, (b, l)) in data.iter_mut().zip(lorenz_bytes.iter().cycle().take(n)).enumerate() {
        *b ^= *l ^ iv[i % 32];
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
        let container = encrypt(&key, plaintext, width, height, channels, &mut rng);
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
        let pt: Vec<u8> = (0..768).map(|i| (i % 256) as u8).collect(); // 16x16 RGBA
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
        let container = encrypt(&key1, &pt, 8, 8, 4, &mut rng);
        let result = decrypt(&key2, &container);
        assert!(result.is_none(), "wrong key should be rejected");
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let key = [0x33u8; 32];
        let pt = [0x00u8; 256];
        let mut rng = StdRng::seed_from_u64(42);
        let mut container = encrypt(&key, &pt, 8, 8, 4, &mut rng);
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
        assert!(seen.iter().all(|&x| x), "S-box does not cover all byte values");
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
        assert!(seen.iter().all(|&x| x), "permutation does not cover all indices");
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
