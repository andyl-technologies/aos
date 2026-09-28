//! Protected delivery of the existing two-role Source genesis packet pair.
//!
//! ```text
//! CREDENTIALS_DIRECTORY/controller-source-tree-seed-v1 = AOSCSE01[224]
//! CREDENTIALS_DIRECTORY/project-authorization-source-v2 = AOSPSC02[224]
//! fixed issuer names = existing independent AOSCSK01[80] and AOSPAK02[80]
//! ```
//!
//! Delivery checks signatures and matching administrative claims, not current
//! publisher heads, a spent epoch, Source append permission or a Root floor.
//! The real coordinator must retain this input and the sole Controller writer
//! before entering the existing held admission producer. Delivery alone never
//! admits or abandons a durable pending genesis as a ready Controller.

use aos_sandbox_core::ProjectId;

use super::controller_genesis::{
    HeldControllerSourceGenesisV1, hold_controller_source_genesis_v1, require_controller,
};
use super::genesis_profile::SourceGenesisErrorV1;
use super::source_seed::{
    CONTROLLER_SOURCE_TREE_SEED_BYTES_V1, ControllerSourceTreeSeedErrorV1,
    PinnedControllerSourceTreeSeedIssuerV1, verify_signed_controller_source_tree_seed_v1,
};
use crate::Journal;
use crate::public_api_session::PinnedSystemdCredential;
use crate::publisher_policy::{
    CurrentSourceTreeSeedPreflightErrorV1, PROJECT_AUTHORIZATION_SOURCE_BYTES_V2,
    PinnedPublisherProjectAuthorizationIssuerV2, ProjectAuthorizationSourceErrorV2,
    PublisherPolicyLimits, PublisherPolicyStore, verify_signed_project_authorization_claims_v2,
};

/// Reports invalid protected delivery or unavailable actual Controller custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerSourceGenesisInputErrorV1 {
    /// A pair or issuer credential is absent, partial, unsafe or replaced.
    #[error("protected Source genesis input credentials are unavailable or changed")]
    Credential,
    /// The two separately signed packets disagree or reuse one signing key.
    #[error("Source genesis administrative packet pair does not match")]
    Pair,
    /// The seed is malformed or not signed by its independent fixed issuer.
    #[error(transparent)]
    Seed(#[from] ControllerSourceTreeSeedErrorV1),
    /// The authorization is malformed or not signed by its fixed issuer.
    #[error(transparent)]
    Authorization(#[from] ProjectAuthorizationSourceErrorV2),
    /// No actual authenticated AOSPAUH2 authorization head is retained yet.
    #[error("Source genesis awaits an actual retained current project authorization")]
    MissingCurrentAuthorization,
    /// The existing protected genesis owner rejected admission or custody.
    #[error(transparent)]
    Owner(#[from] SourceGenesisErrorV1),
}

/// Retains one genuinely provisioned packet pair and both independent issuer files.
///
/// Its only production constructor uses fixed protected systemd names. It is
/// neither cloneable nor serializable and supplies no signing key, caller path,
/// expected epoch, Root proof or read grant. The project is only a signed input
/// selector until the actual Controller owner validates its current heads.
pub struct ProvisionedControllerSourceGenesisInputV1 {
    packets: [PinnedSystemdCredential; 2],
    issuers: [PinnedSystemdCredential; 2],
    project: ProjectId,
}

impl ProvisionedControllerSourceGenesisInputV1 {
    /// Retains an optional exact packet pair from PID1's protected delivery.
    ///
    /// Both absent leaves ordinary startup unchanged. Any partial, oversized,
    /// legacy AOSPSC01, malformed or substituted pair is rejected. No journal
    /// mutation, administrative issuance or replay-floor assumption occurs.
    ///
    /// # Errors
    ///
    /// Rejects unsafe or changing credential custody, missing independent role
    /// pins, wrong signatures, shared role keys or mismatched packet claims.
    pub fn from_systemd_credentials_optional()
    -> Result<Option<Self>, ControllerSourceGenesisInputErrorV1> {
        let Some(packets) = PinnedSystemdCredential::load_source_genesis_packets_optional()
            .map_err(|_| ControllerSourceGenesisInputErrorV1::Credential)?
        else {
            return Ok(None);
        };
        let issuers = [
            PinnedSystemdCredential::load_controller_source_tree_seed_issuer_v1()
                .map_err(|_| ControllerSourceGenesisInputErrorV1::Credential)?,
            PinnedSystemdCredential::load_project_authorization_issuer_v2()
                .map_err(|_| ControllerSourceGenesisInputErrorV1::Credential)?,
        ];
        let project = validate_pair(
            packets[0].bytes(),
            packets[1].bytes(),
            issuers[0].bytes(),
            issuers[1].bytes(),
        )?;
        let input = Self {
            packets,
            issuers,
            project,
        };
        input.recheck()?;
        Ok(Some(input))
    }

    /// Returns only the administrative signatures' matched project selector.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Rechecks original protected names, inode identities, bytes and role joins.
    ///
    /// # Errors
    ///
    /// Rejects any missing, replaced or altered packet/pin, signature or pair.
    pub fn recheck(&self) -> Result<(), ControllerSourceGenesisInputErrorV1> {
        for credential in self.packets.iter().chain(&self.issuers) {
            credential
                .recheck()
                .map_err(|_| ControllerSourceGenesisInputErrorV1::Credential)?;
        }
        if validate_pair(
            self.packets[0].bytes(),
            self.packets[1].bytes(),
            self.issuers[0].bytes(),
            self.issuers[1].bytes(),
        )? != self.project
        {
            return Err(ControllerSourceGenesisInputErrorV1::Pair);
        }
        Ok(())
    }

    // This DATA-only route selector permits exact historical recovery before
    // unrelated bootstrap policy installation (whose credential may expire).
    // The actual coordinator still verifies original Root and both real owners.
    pub(crate) fn has_retained_attempt(
        &self,
        journal: &mut Journal,
    ) -> Result<bool, ControllerSourceGenesisInputErrorV1> {
        self.recheck()?;
        let uid = journal
            .protected_owner_uid()
            .map_err(SourceGenesisErrorV1::from)?;
        require_controller(journal, uid)?;
        let retained = crate::journal::controller_source_genesis::rows(journal, self.project)?;
        if crate::journal::controller_source_genesis::pending(journal)?
            .is_some_and(|pending| pending.project() != self.project)
        {
            return Err(SourceGenesisErrorV1::Conflict.into());
        }
        if retained.as_ref().is_some_and(|row| {
            row.acceptance.seed_packet().as_slice() != self.packets[0].bytes()
                || row.acceptance.auth_packet().as_slice() != self.packets[1].bytes()
        }) {
            return Err(SourceGenesisErrorV1::Conflict.into());
        }
        self.recheck()?;
        require_controller(journal, uid)?;
        Ok(retained.is_some())
    }

    /// Inspects actual current heads through the fixed NodeController writer funnel.
    ///
    /// # Errors
    ///
    /// Rejects changed delivery or owner custody, absent authorization, stale
    /// heads and the existing store's invalid signature or graph conditions.
    pub(crate) fn inspect_current(
        &self,
        journal: &mut Journal,
    ) -> Result<(), ControllerSourceGenesisInputErrorV1> {
        self.recheck()?;
        let uid = journal
            .protected_owner_uid()
            .map_err(SourceGenesisErrorV1::from)?;
        require_controller(journal, uid)?;
        {
            let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
                .map_err(SourceGenesisErrorV1::from)?;
            store
                .inspect_current_source_genesis_pair_from_fixed_issuers_v1(
                    self.project,
                    self.seed_packet()?,
                    self.authorization_packet()?,
                )
                .map_err(|error| match error {
                    CurrentSourceTreeSeedPreflightErrorV1::MissingAuthorization => {
                        ControllerSourceGenesisInputErrorV1::MissingCurrentAuthorization
                    }
                    CurrentSourceTreeSeedPreflightErrorV1::Authorization(error) => error.into(),
                    CurrentSourceTreeSeedPreflightErrorV1::Seed(error) => error.into(),
                    CurrentSourceTreeSeedPreflightErrorV1::Acceptance(error) => error.into(),
                })?;
        }
        self.recheck()?;
        require_controller(journal, uid)?;
        Ok(())
    }

    /// Retains genuine administrative admission through the fixed writer funnel.
    ///
    /// # Errors
    ///
    /// Rejects changed delivery and the existing held producer's ownership,
    /// replay, epoch, graph or capacity failures.
    pub(crate) fn hold<'held>(
        &'held self,
        journal: &'held mut Journal,
    ) -> Result<HeldControllerSourceGenesisV1<'held>, ControllerSourceGenesisInputErrorV1> {
        self.recheck()?;
        let held = hold_controller_source_genesis_v1(
            journal,
            self.project,
            self.seed_packet()?,
            self.authorization_packet()?,
        )?;
        self.recheck()?;
        held.recheck()?;
        Ok(held)
    }

    fn seed_packet(
        &self,
    ) -> Result<[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1], ControllerSourceGenesisInputErrorV1>
    {
        self.packets[0]
            .bytes()
            .try_into()
            .map_err(|_| ControllerSourceGenesisInputErrorV1::Pair)
    }

    fn authorization_packet(
        &self,
    ) -> Result<[u8; PROJECT_AUTHORIZATION_SOURCE_BYTES_V2], ControllerSourceGenesisInputErrorV1>
    {
        self.packets[1]
            .bytes()
            .try_into()
            .map_err(|_| ControllerSourceGenesisInputErrorV1::Pair)
    }
}

// Signature-only delivery validation deliberately has no expected-current
// scalar, Journal argument, epoch mutation or owner-token return value.
fn validate_pair(
    seed: &[u8],
    authorization: &[u8],
    seed_issuer: &[u8],
    authorization_issuer: &[u8],
) -> Result<ProjectId, ControllerSourceGenesisInputErrorV1> {
    let seed_pin = PinnedControllerSourceTreeSeedIssuerV1::decode(seed_issuer)?;
    let authorization_pin =
        PinnedPublisherProjectAuthorizationIssuerV2::decode(authorization_issuer)?;
    if seed_pin.verifying_key() == authorization_pin.verifying_key() {
        return Err(ControllerSourceGenesisInputErrorV1::Pair);
    }
    let seed = verify_signed_controller_source_tree_seed_v1(seed, &seed_pin)?.seed();
    let authorization =
        verify_signed_project_authorization_claims_v2(authorization, &authorization_pin)?;
    if seed.project() != authorization.project
        || seed.request_id() != authorization.request_id
        || seed.epoch() != authorization.epoch
        || seed.limits() != authorization.limits
        || seed.publisher_generation() != authorization.publisher_generation
        || seed.publisher_head() != authorization.publisher_head_digest
    {
        return Err(ControllerSourceGenesisInputErrorV1::Pair);
    }
    Ok(seed.project())
}

#[cfg(test)]
mod tests;
