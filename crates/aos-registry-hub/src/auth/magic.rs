//! Single-use email magic links.
//!
//! Magic links are RFC-0004's v1 human-login baseline and the recovery
//! path (there are no passwords). The hub mints a high-entropy link secret,
//! emails the human a URL embedding it, and consumes the secret exactly
//! once on click — proving control of the mailbox. Only the SHA-256 hash is
//! stored; the link expires in [`MAGIC_LINK_TTL_SECS`].
//!
//! ```text
//! https://hub.example.com/login/magic?token=<64 hex chars>
//!                                            └ 32 random bytes; hashed at rest,
//!                                              single-use, 15-minute expiry
//! ```
//!
//! Actual delivery is abstracted behind the [`Mailer`] trait. This module
//! ships [`LogMailer`], which logs the link instead of sending it — useful
//! for dev and tests. Real transports (SMTP via `lettre` natively, an HTTP
//! mail API on Workers) implement [`Mailer`] in a later phase. The link
//! lifecycle (create, consume-once) lives on [`crate::db::Database`].

use rand::Rng;

/// How long a magic link stays valid, in seconds (15 minutes).
pub const MAGIC_LINK_TTL_SECS: i64 = 15 * 60;

/// Generates a fresh magic-link secret (256 bits as lowercase hex).
///
/// Only its SHA-256 hash is persisted; the plaintext is embedded in the
/// emailed URL.
#[must_use]
pub fn new_magic_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Delivers a login magic link to an email address.
///
/// Implementations send the URL however their runtime allows; the hub
/// holds a `dyn Mailer` and calls [`Mailer::send_magic_link`] after
/// [`crate::db::Database::create_magic_link`] returns the secret.
pub trait Mailer: Send + Sync {
    /// Sends `link_url` (a fully-formed magic-link URL) to `email`.
    ///
    /// # Errors
    ///
    /// Returns an error if delivery fails; the hub surfaces this as a
    /// transient failure to the caller without leaking whether the address
    /// is known.
    fn send_magic_link(&self, email: &str, link_url: &str) -> anyhow::Result<()>;
}

/// A [`Mailer`] that logs the link instead of sending it.
///
/// Intended for dev mode and tests: the link is emitted at `info` level so
/// an operator can follow it manually. **Do not** use it where real
/// delivery is expected — the link is visible to anyone reading the logs.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogMailer;

impl Mailer for LogMailer {
    fn send_magic_link(&self, email: &str, link_url: &str) -> anyhow::Result<()> {
        tracing::info!(%email, %link_url, "magic link issued (LogMailer: not actually emailed)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_256_bits_hex() {
        let s = new_magic_secret();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(s, new_magic_secret());
    }

    #[test]
    fn log_mailer_is_infallible() {
        let mailer = LogMailer;
        assert!(mailer
            .send_magic_link("a@b.com", "https://h/login/magic?token=x")
            .is_ok());
    }
}
