//! Signing reads in the releases capability.

use super::*;

impl Database {
    /// Load (or, on first use, generate and persist) the per-instance
    /// draft-signing key.
    ///
    /// Web edits to git-backed config are committed as change requests to
    /// `refs/hub/changes/<change_id>`, signed by this key (RFC-0004
    /// "Configuration management", git-backed path). The key is deliberately
    /// **not** in any registry's roster — a draft never verifies for consumers
    /// until a maintainer re-signs it with a roster key (`apr change merge`) —
    /// so it carries no consumption trust; it exists only to produce a
    /// well-formed signed commit object the hub and `apr` can fetch and diff.
    ///
    /// The seed is hex-encoded, sealed with the instance
    /// [`SecretSealer`](aos_hub_model::auth::seal::SecretSealer), then stored as the
    /// `draft_signing_key` instance-config value. Returns the usable key with its
    /// public trusted-key line (named `aos-hub-draft`), for surfacing in the UI
    /// and for round-trip verification in tests. This isolated instance secret
    /// is not a signing-key generation and cannot be bound to a live consumer.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, or when an existing sealed value
    /// cannot be unsealed or decoded into a 32-byte seed (tampering or a key
    /// mismatch).
    pub async fn get_or_create_draft_signing_key(
        &self,
        sealer: &dyn aos_hub_model::auth::seal::SecretSealer,
    ) -> Result<(ed25519_dalek::SigningKey, String)> {
        let seed: [u8; 32] = match self.instance_config_get(Self::DRAFT_SIGNING_KEY).await? {
            Some(sealed) => {
                let seed_hex = sealer
                    .unseal(&sealed)
                    .context("unsealing the draft-signing key")?;
                hex::decode(seed_hex.trim())
                    .context("decoding the draft-signing key seed")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("draft-signing key seed is not 32 bytes"))?
            }
            None => {
                use rand::Rng as _;
                let seed: [u8; 32] = rand::rng().random();
                let sealed = sealer.seal(&hex::encode(seed))?;
                self.instance_config_set(Self::DRAFT_SIGNING_KEY, &sealed)
                    .await?;
                seed
            }
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_line = aos_registry_format::sshsig::trusted_key_line(
            "aos-hub-draft",
            &signing_key.verifying_key(),
        );
        Ok((signing_key, public_line))
    }
}
