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
//! Actual delivery is abstracted behind the [`Mailer`] trait, whose single
//! required method ([`Mailer::send_email`]) takes a fully-rendered
//! [`EmailContent`](crate::email::EmailContent); the message bodies are rendered
//! once in [`crate::email`] so every transport sends identical copy. This module
//! ships [`LogMailer`], which logs the message instead of sending it — useful
//! for dev and tests. Real transports (SMTP via `lettre` natively, the
//! Cloudflare Email Service binding on Workers) implement [`Mailer`]. The link
//! lifecycle (create, consume-once) lives on `Database`.

use rand::Rng;

use crate::backend::BackendBounds;

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

/// Delivers a rendered transactional email to an address.
///
/// Implementations send the message however their runtime allows; the hub
/// holds a `dyn Mailer` and calls [`Mailer::send_email`] with content rendered
/// by [`crate::email`]. [`send_magic_link`](Mailer::send_magic_link) is a
/// convenience that renders the (brand-less) magic-link email and forwards to
/// [`send_email`](Mailer::send_email).
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait Mailer: BackendBounds {
    /// Sends a fully-rendered [`EmailContent`](crate::email::EmailContent) to
    /// `to`.
    ///
    /// This is the single required method: callers render a message with the
    /// shared [`crate::email`] helpers and hand it here, so the transport never
    /// owns the copy. `async` so a deployment can deliver over the network (the
    /// Cloudflare Worker calls the Email Service binding or an HTTP relay; a
    /// native impl may call SMTP/HTTP). The bound is [`BackendBounds`]:
    /// `Send + Sync` natively, unbounded on the single-threaded Worker.
    ///
    /// # Errors
    ///
    /// Returns an error if delivery fails; the hub surfaces this as a
    /// transient failure to the caller without leaking whether the address
    /// is known.
    async fn send_email(
        &self,
        to: &str,
        content: &crate::email::EmailContent,
    ) -> anyhow::Result<()>;

    /// Renders and sends the brand-less magic-link sign-in email to `email`.
    ///
    /// A convenience over [`send_email`](Mailer::send_email): it renders
    /// [`crate::email::magic_link_email`] with an empty brand (callers with a
    /// configured brand should render the email themselves and call
    /// [`send_email`](Mailer::send_email) directly) and forwards `link_url`.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`send_email`](Mailer::send_email).
    async fn send_magic_link(&self, email: &str, link_url: &str) -> anyhow::Result<()> {
        let content = crate::email::magic_link_email("", link_url);
        self.send_email(email, &content).await
    }
}

/// A [`Mailer`] that logs the message instead of sending it.
///
/// Intended for dev mode and tests: the subject, recipient, and a short body
/// snippet are emitted at `info` level so an operator can follow a magic link
/// manually. **Do not** use it where real delivery is expected — the message is
/// visible to anyone reading the logs. It implements only the required
/// [`Mailer::send_email`] and inherits the default
/// [`send_magic_link`](Mailer::send_magic_link).
#[derive(Debug, Default, Clone, Copy)]
pub struct LogMailer;

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Mailer for LogMailer {
    async fn send_email(
        &self,
        to: &str,
        content: &crate::email::EmailContent,
    ) -> anyhow::Result<()> {
        // Log a bounded body snippet so a magic link is still followable from
        // the logs without dumping the entire HTML body.
        let snippet: String = content.text.chars().take(200).collect();
        tracing::info!(
            %to,
            subject = %content.subject,
            %snippet,
            "email issued (LogMailer: not actually sent)"
        );
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

    #[tokio::test]
    async fn log_mailer_is_infallible() {
        let mailer = LogMailer;
        assert!(mailer
            .send_magic_link("a@b.com", "https://h/login/magic?token=x")
            .await
            .is_ok());
    }
}
