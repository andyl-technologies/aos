//! Rechecks original accepted identity against the genuine fixed TLS registry.
//!
//! This owner reuses the public session credential reader and closed registry.
//! It authenticates no new transport: original TLS DER and exporter custody are
//! not retained, and no `PublicApiPeer` is reconstructed from historical data.

use aos_sandbox_core::{ChannelBinding, PrincipalId, ProjectId};
use sha2::{Digest as _, Sha256};

use super::{KEY_BINDING_DOMAIN, PublicApiSessionError, credentials, registration};

/// Keeps the current fixed credential snapshot alive through original consume.
pub(crate) struct CurrentOriginalPublicRegistrationV3 {
    credentials: credentials::Credentials,
    key_binding: ChannelBinding,
}

impl CurrentOriginalPublicRegistrationV3 {
    /// Resolves the original leaf, principal, project, and stable certificate key.
    ///
    /// # Errors
    /// Rejects changed fixed trust, a missing/rebound registration, or unsafe
    /// credential custody. A fresh leaf cannot substitute for the original one.
    pub(crate) fn load(
        original_trust: [[u8; 32]; 4],
        principal: PrincipalId,
        project: ProjectId,
        original_binding: ChannelBinding,
    ) -> Result<Self, PublicApiSessionError> {
        let (credentials, bytes) = credentials::Credentials::load()?;
        let registrations = registration::decode(&bytes[3])?;
        let key_binding = require_original_registration(
            credentials.public_trust_digests(),
            &registrations,
            original_trust,
            principal,
            project,
            original_binding,
        )?;
        credentials.recheck()?;
        Ok(Self {
            credentials,
            key_binding,
        })
    }

    /// Returns the exact original certificate-derived stable holder binding.
    pub(crate) const fn key_binding(&self) -> ChannelBinding {
        self.key_binding
    }

    /// Rechecks the same retained fixed credential snapshot before consume.
    ///
    /// # Errors
    /// Rejects changed files, unsafe paths, or changed owner custody.
    pub(crate) fn recheck(&self) -> Result<(), PublicApiSessionError> {
        self.credentials.recheck()
    }
}

fn require_original_registration(
    current_trust: [[u8; 32]; 3],
    registrations: &std::collections::BTreeMap<[u8; 32], registration::Registration>,
    original_trust: [[u8; 32]; 4],
    principal: PrincipalId,
    project: ProjectId,
    original_binding: ChannelBinding,
) -> Result<ChannelBinding, PublicApiSessionError> {
    if current_trust != original_trust[..3]
        || original_trust.iter().any(|digest| digest == &[0; 32])
    {
        return Err(PublicApiSessionError::Stale);
    }
    let registered = registrations
        .get(&original_trust[3])
        .ok_or(PublicApiSessionError::Stale)?;
    let key_binding = ChannelBinding::new(
        Sha256::new()
            .chain_update(KEY_BINDING_DOMAIN)
            .chain_update(registered.certificate_sha256)
            .finalize()
            .into(),
    );
    if registered.principal != principal
        || registered.project != project
        || key_binding != original_binding
    {
        return Err(PublicApiSessionError::Stale);
    }
    Ok(key_binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_leaf_registration_and_stable_key_cannot_be_rebound() {
        let principal = PrincipalId::from_bytes([1; 16]);
        let project = ProjectId::from_bytes([2; 16]);
        let trust = [[3; 32], [4; 32], [5; 32], [6; 32]];
        let binding = ChannelBinding::new(
            Sha256::new()
                .chain_update(KEY_BINDING_DOMAIN)
                .chain_update(trust[3])
                .finalize()
                .into(),
        );
        let registrations = std::collections::BTreeMap::from([(
            trust[3],
            registration::Registration {
                certificate_sha256: trust[3],
                principal,
                project,
            },
        )]);
        let current = [trust[0], trust[1], trust[2]];
        assert!(
            require_original_registration(
                current,
                &registrations,
                trust,
                principal,
                project,
                binding
            )
            .is_ok()
        );
        assert!(
            require_original_registration(
                current,
                &registrations,
                trust,
                PrincipalId::from_bytes([7; 16]),
                project,
                binding
            )
            .is_err()
        );
        assert!(
            require_original_registration(
                current,
                &registrations,
                trust,
                principal,
                ProjectId::from_bytes([7; 16]),
                binding
            )
            .is_err()
        );
        assert!(
            require_original_registration(
                current,
                &registrations,
                trust,
                principal,
                project,
                ChannelBinding::new([7; 32])
            )
            .is_err()
        );
        for index in 0..4 {
            let mut changed = trust;
            changed[index] = [7; 32];
            assert!(
                require_original_registration(
                    current,
                    &registrations,
                    changed,
                    principal,
                    project,
                    binding
                )
                .is_err()
            );
        }
        assert!(
            require_original_registration(
                current,
                &Default::default(),
                trust,
                principal,
                project,
                binding
            )
            .is_err()
        );
    }
}
