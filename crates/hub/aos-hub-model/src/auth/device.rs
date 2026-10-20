//! RFC 8628 device-authorization secrets.
//!
//! The CLI login flow (`apr login https://hub.example.com`) is the OAuth
//! device-code grant: the CLI starts a grant, prints a short **user code**,
//! the human approves it inside an authenticated browser session at
//! `/activate`, and the CLI polls with its long **device code** until the
//! approval mints a provisioning token owned by the approving user — its
//! scope and permissions clamped to that user's own grants.
//!
//! Two secrets per grant:
//!
//! ```text
//! device code  64 hex chars (32 random bytes)   polled by the CLI; hashed at rest
//! user code    "ABCD-1234"                       typed by the human; from an
//!                                                 unambiguous alphabet (no 0/O/1/I)
//! ```
//!
//! This module owns only the secret formats; the grant lifecycle (start,
//! approve with scope clamping, deny, poll) lives on
//! `Database`, and the poll outcome is
//! `DevicePollResult`.

use rand::Rng;

/// How long a device-authorization grant stays pollable, in seconds
/// (15 minutes — the RFC 8628 default neighbourhood).
pub const DEVICE_CODE_TTL_SECS: i64 = 15 * 60;

/// Unambiguous user-code alphabet: digits and uppercase letters with the
/// visually confusable `0`, `O`, `1`, and `I` removed.
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Generates a fresh device code (256 bits as lowercase hex).
///
/// This is the long secret the CLI polls with; only its SHA-256 hash is
/// persisted.
#[must_use]
pub fn new_device_code() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Generates a fresh 8-character user code in `XXXX-YYYY` form.
///
/// Each character is drawn from the `USER_CODE_ALPHABET`, which omits the
/// confusable `0`/`O`/`1`/`I` so the human can read and type it reliably.
#[must_use]
pub fn new_user_code() -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            out.push('-');
        }
        let idx = rng.random_range(0..USER_CODE_ALPHABET.len());
        out.push(USER_CODE_ALPHABET[idx] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_code_is_256_bits_hex() {
        let c = new_device_code();
        assert_eq!(c.len(), 64);
        assert!(c.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_ne!(c, new_device_code());
    }

    #[test]
    fn user_code_shape_and_alphabet() {
        let code = new_user_code();
        // "ABCD-1234" — 9 chars with a dash in the middle.
        assert_eq!(code.len(), 9);
        assert_eq!(code.as_bytes()[4], b'-');
        for (i, ch) in code.char_indices() {
            if i == 4 {
                continue;
            }
            assert!(
                USER_CODE_ALPHABET.contains(&(ch as u8)),
                "{ch} not in unambiguous alphabet"
            );
            assert!(!matches!(ch, '0' | 'O' | '1' | 'I'));
        }
    }

    #[test]
    fn user_codes_vary() {
        // Not a strong guarantee, but a sanity check against a constant.
        let a = new_user_code();
        let b = new_user_code();
        assert!(a != b || new_user_code() != a);
    }
}
