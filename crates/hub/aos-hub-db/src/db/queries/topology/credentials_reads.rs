//! Credentials reads in the topology capability.

use super::*;

impl Database {
    /// Look up a WebAuthn credential by its base64url credential id.
    ///
    /// Returns `Ok(None)` when no credential with that id is registered (the
    /// assertion is for an unknown or de-registered passkey).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn webauthn_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredentialRecord>> {
        self.backend
            .query_opt(
                "SELECT id, user_id, credential_id, public_key, sign_count, transports,
                        label, created_at, last_used_at
                 FROM webauthn_credentials WHERE credential_id = ?1",
                &vals![credential_id],
            )
            .await
            .context("loading webauthn credential by id")?
            .map(|row| row_to_webauthn_credential(&row))
            .transpose()
    }

    /// Returns the current credential generation for one purpose.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn current_binding_credential(
        &self,
        binding_id: i64,
        purpose: &str,
    ) -> Result<Option<BindingCredentialRevisionRecord>> {
        let generation: Option<i64> = self
            .backend
            .query_opt(
                "SELECT current_generation FROM binding_credential_heads
                 WHERE binding_id = ?1 AND purpose = ?2",
                &vals![binding_id, purpose],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()?;
        match generation {
            Some(generation) => {
                self.binding_credential_revision(binding_id, purpose, generation)
                    .await
            }
            None => Ok(None),
        }
    }
}
