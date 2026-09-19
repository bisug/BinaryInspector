//! Cryptographic hashing and entropy calculation routines in safe Rust.

/// Computes the SHA-256 hash of a byte slice and returns it as a lowercase hexadecimal string.
pub fn sha256_hex(data: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let hash = sha256_digest(data);
    let mut hex = String::with_capacity(64);
    for byte in hash {
        hex.push(HEX_LOWER[(byte >> 4) as usize] as char);
        hex.push(HEX_LOWER[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Computes the Shannon entropy of a byte slice, returning bits of entropy per byte (0.0 to 8.0).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0_usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Standard SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Computes a 32-byte raw SHA-256 digest.
fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);

    // Process complete 64-byte chunks
    let (chunks, remainder) = data.as_chunks::<64>();
    for chunk in chunks {
        process_block(&mut h, chunk);
    }

    // Process padding in the remainder
    let mut buffer = [0_u8; 128];
    buffer[..remainder.len()].copy_from_slice(remainder);
    buffer[remainder.len()] = 0x80;

    let pad_len = if remainder.len() < 56 { 64 } else { 128 };
    buffer[pad_len - 8..pad_len].copy_from_slice(&bit_len.to_be_bytes());

    let (pad_chunks, _) = buffer[..pad_len].as_chunks::<64>();
    for chunk in pad_chunks {
        process_block(&mut h, chunk);
    }

    let mut out = [0_u8; 32];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

fn process_block(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0_u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut h_val = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h_val
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h_val = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(h_val);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_vectors() {
        // NIST test vector: "" (empty)
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // NIST test vector: "abc"
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_entropy() {
        assert_eq!(calculate_entropy(b""), 0.0);
        assert_eq!(calculate_entropy(&[0_u8; 100]), 0.0);
        // 4 distinct bytes with equal frequency -> exactly log2(4) = 2.0
        let data = [0, 1, 2, 3];
        assert!((calculate_entropy(&data) - 2.0).abs() < 1e-6);
    }
}
