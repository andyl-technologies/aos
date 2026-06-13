//! Password credentials: Argon2id hashing and constant-time verification.
//!
//! RFC-0004 originally said the hub would have **no passwords** — magic links
//! and passkeys were the human-login baseline. That stance is reversed by
//! explicit operator request: a first-class email + password login is now
//! supported alongside magic links and passkeys. Passwords are stored only as
//! a one-way hash, never in plaintext, in the `users.password_hash` column
//! (migration v18; `NULL` = no password set).
//!
//! # Key derivation
//!
//! Hashes use **Argon2id** — the memory-hard winner of the Password Hashing
//! Competition and the algorithm OWASP recommends for password storage. Each
//! hash is salted with 16 fresh random bytes drawn from the OS CSPRNG and
//! encoded as a self-describing **PHC string** that carries the algorithm,
//! version, cost parameters, salt, and digest in one field:
//!
//! ```text
//! $argon2id$v=19$m=19456,t=2,p=1$<base64-salt>$<base64-hash>
//!  └ algo     └ ver  └ params      └ salt        └ digest
//! ```
//!
//! Because the parameters are embedded, [`verify_password`] re-derives with
//! exactly the params a hash was created under, so a future parameter bump
//! verifies old hashes transparently. Verification is constant-time over the
//! digest (argon2's own comparison), and [`verify_password`] returns `false`
//! for *any* failure — wrong password, malformed PHC string, unknown
//! algorithm — so it never panics and never distinguishes the failure mode to
//! a caller.

use anyhow::{Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// Hashes a plaintext password into a self-describing Argon2id PHC string.
///
/// A fresh 16-byte salt is drawn from the OS CSPRNG per call, so hashing the
/// same password twice yields two distinct strings. The returned value is the
/// complete PHC string to persist in `users.password_hash`; pass it back to
/// [`verify_password`] to check a login attempt.
///
/// # Errors
///
/// Returns an error only if the underlying Argon2 hasher fails (e.g. an
/// out-of-memory condition allocating the cost-parameter working set); a
/// correctly configured process does not hit this in practice.
pub fn hash_password(plaintext: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))
        .context("hashing password")?;
    Ok(hash.to_string())
}

/// Verifies a plaintext password against a stored Argon2id PHC string.
///
/// Returns `true` only when `plaintext` matches the password the PHC string
/// `phc` was derived from. Returns `false` for a wrong password, and — by
/// design — also for a malformed or unparseable `phc`, an unknown algorithm,
/// or any internal verification error: the function never panics and never
/// surfaces *why* it failed, so a caller cannot use it as an oracle. The
/// digest comparison is constant-time (performed by argon2 itself).
#[must_use]
pub fn verify_password(plaintext: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_round_trips() {
        let phc = hash_password("correct horse battery staple").unwrap();
        assert!(phc.starts_with("$argon2id$"), "PHC string, got {phc}");
        assert!(verify_password("correct horse battery staple", &phc));
    }

    #[test]
    fn wrong_password_does_not_verify() {
        let phc = hash_password("hunter2").unwrap();
        assert!(!verify_password("hunter3", &phc));
        assert!(!verify_password("", &phc));
    }

    #[test]
    fn salt_makes_each_hash_unique() {
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b, "fresh salt per call");
        // Both still verify the same plaintext.
        assert!(verify_password("same", &a));
        assert!(verify_password("same", &b));
    }

    #[test]
    fn tampered_or_malformed_hash_returns_false_not_panic() {
        let phc = hash_password("secret").unwrap();
        // Flip the last character of the digest.
        let mut bytes: Vec<char> = phc.chars().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = bytes.into_iter().collect();
        assert!(!verify_password("secret", &tampered));

        // Outright garbage must be rejected without panicking.
        assert!(!verify_password("secret", "not-a-phc-string"));
        assert!(!verify_password("secret", ""));
        assert!(!verify_password("secret", "$argon2id$broken"));
    }
}
