//! Narinfo signing support.
//!
//! Re-exports the ed25519 [`NarInfoSigner`] from `aos-core` so that server
//! modules ([`crate::narinfo`], [`crate::routes`]) can sign `.narinfo`
//! responses without depending on `aos_core::nar::cache` directly. The
//! signing key is loaded from the `[signing] secret_key_file` configured in
//! [`crate::config::SigningConfig`].

pub use aos_core::nar::cache::NarInfoSigner;
