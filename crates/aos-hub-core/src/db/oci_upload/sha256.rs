//! Portable resumable SHA-256 state used by OCI chunk uploads.
//!
//! The representation uses SQL-portable integers and lowercase hexadecimal
//! tail bytes so native and Worker processes can resume the same stream.

use super::*;

/// Portable continuation state for a resumable SHA-256 computation.
///
/// `words` are the eight chaining words after all complete 64-byte blocks;
/// `total_bytes` includes both those blocks and `tail`. The tail is encoded as
/// lowercase hexadecimal so every SQL transport preserves it byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciSha256State {
    /// Encoding version, currently [`OCI_SHA256_STATE_VERSION`].
    pub version: u32,
    /// Eight SHA-256 chaining words.
    pub words: [u32; 8],
    /// Total bytes accepted by the upload.
    pub total_bytes: u64,
    /// Lowercase hexadecimal encoding of the pending 0..63-byte tail.
    pub tail_hex: String,
}

impl OciSha256State {
    /// Returns the initial SHA-256 state for an empty upload.
    #[must_use]
    pub fn initial() -> Self {
        Self {
            version: OCI_SHA256_STATE_VERSION,
            words: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            total_bytes: 0,
            tail_hex: String::new(),
        }
    }

    /// Validates the portable state representation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version, non-lowercase hexadecimal
    /// tail, a tail of 64 bytes or more, or a tail length inconsistent with
    /// `total_bytes`.
    pub fn validate(&self) -> Result<()> {
        if self.version != OCI_SHA256_STATE_VERSION {
            bail!("unsupported OCI SHA-256 state version {}", self.version);
        }
        if self.tail_hex.len() > 126
            || self.tail_hex.len() % 2 != 0
            || self
                .tail_hex
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            bail!("OCI SHA-256 tail must encode 0..63 bytes as lowercase hexadecimal");
        }
        let tail_bytes = u64::try_from(self.tail_hex.len() / 2)
            .context("OCI SHA-256 tail length exceeds u64")?;
        if self.total_bytes % 64 != tail_bytes {
            bail!("OCI SHA-256 tail length is inconsistent with total bytes");
        }
        Ok(())
    }

    /// Advances the resumable state with one contiguous byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error when the current state is malformed or the total byte
    /// count overflows the portable representation.
    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        let mut pending = decode_lower_hex(&self.tail_hex)?;
        pending.extend_from_slice(bytes);
        self.total_bytes = self
            .total_bytes
            .checked_add(u64::try_from(bytes.len()).context("OCI SHA-256 input is too large")?)
            .context("OCI SHA-256 total byte count overflow")?;

        let complete_len = pending.len() / 64 * 64;
        for block in pending[..complete_len].chunks_exact(64) {
            let block: &[u8; 64] = block
                .try_into()
                .context("OCI SHA-256 block has an invalid length")?;
            sha256_compress(&mut self.words, block);
        }
        self.tail_hex = encode_lower_hex(&pending[complete_len..]);
        self.validate()
    }

    /// Finalizes a copy of this continuation state into its OCI digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the state is malformed, the SHA-256 bit length
    /// overflows `u64`, or the resulting digest cannot be parsed.
    pub fn final_digest(&self) -> Result<Sha256Digest> {
        self.validate()?;
        let bit_length = self
            .total_bytes
            .checked_mul(8)
            .context("OCI SHA-256 bit length exceeds u64")?;
        let mut final_bytes = decode_lower_hex(&self.tail_hex)?;
        final_bytes.push(0x80);
        while final_bytes.len() % 64 != 56 {
            final_bytes.push(0);
        }
        final_bytes.extend_from_slice(&bit_length.to_be_bytes());

        let mut words = self.words;
        for block in final_bytes.chunks_exact(64) {
            let block: &[u8; 64] = block
                .try_into()
                .context("OCI SHA-256 final block has an invalid length")?;
            sha256_compress(&mut words, block);
        }
        let mut encoded = String::with_capacity(64);
        for word in words {
            use std::fmt::Write as _;
            write!(&mut encoded, "{word:08x}").context("formatting OCI SHA-256 digest")?;
        }
        Sha256Digest::parse(&format!("sha256:{encoded}")).map_err(Into::into)
    }
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("lowercase hexadecimal value has an odd length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = lower_hex_nibble(pair[0])?;
            let low = lower_hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn lower_hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => bail!("value is not lowercase hexadecimal"),
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[allow(clippy::many_single_char_names)]
fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut schedule = [0_u32; 64];
    for (index, bytes) in block.chunks_exact(4).enumerate() {
        schedule[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let upper_e = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ ((!e) & g);
        let first = h
            .wrapping_add(upper_e)
            .wrapping_add(choose)
            .wrapping_add(K[index])
            .wrapping_add(schedule[index]);
        let upper_a = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let second = upper_a.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}
