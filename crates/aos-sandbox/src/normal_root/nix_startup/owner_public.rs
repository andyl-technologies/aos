//! Retains fixed independent public credentials beside genuine Nix059 startup.
//!
//! This move-only loan borrows an externally retained root control startup and
//! owns twelve public credential originals plus a separate exact node original.
//! The fixed owner directory is not selected by an environment variable or a
//! caller. Shared canonical validation is DATA processing; original startup and
//! protected file checks remain necessary at every observation. The loan grants
//! no Session, currentness, journal, NV, build, population-drain or effect proof.

use std::path::Path;

use aos_sandbox_core::NodeId;
use aos_sandbox_linux::pidfd::PidFd;

use crate::production_operation_compiler::{
    ControllerNixStartRecipeSelectorV2, NixFixedDomainPinsDataV2, NixStartAdmissionErrorV2,
};
use crate::public_api_session::PinnedSystemdCredential;

use super::ProductionNixOwnerStartupV1;
use super::floor_origin::OriginFailureLatchV2;

/// Borrows genuine root control startup and retains its independent public pins.
///
/// The four configured identities describe the Controller and later builders;
/// actual Nix control credentials remain root UID/GID0 with bounding0xc0.
/// This cannot be cloned or constructed from public DATA, a File, FD, path,
/// profile, predicate or startup-only receipt. Later Security composition must
/// keep the external startup alive rather than consume it into a self-borrow.
#[must_use = "retain and recheck this original startup/public-credential loan"]
pub struct NixOwnerPublicSessionFloorOriginV2<'origin> {
    startup: &'origin ProductionNixOwnerStartupV1,
    credentials: [PinnedSystemdCredential; 12],
    node: PinnedSystemdCredential,
    pins: NixFixedDomainPinsDataV2,
    health: OriginFailureLatchV2,
}

impl ProductionNixOwnerStartupV1 {
    /// Retains the fixed owner's public credentials under this original startup.
    ///
    /// Public credentials come only from the fixed owner directory
    /// `/run/credentials/aos-sandbox-nixd.service`, through the existing reader.
    /// The separate nonzero16-byte node is excluded from the unchanged
    /// twelve-public ordering and pin-set hash.
    /// No secret, assignment, operation, clock, Session or physical floor opens.
    ///
    /// # Errors
    ///
    /// Preserves actual startup, credential, canonical encoding and signed
    /// catalog errors. Rejects mismatched original node/profile/domain/manifest,
    /// issuer/session key reuse or invalid independent ownership/plan policies.
    pub fn borrow_public_session_floor_origin_v2(
        &self,
    ) -> Result<NixOwnerPublicSessionFloorOriginV2<'_>, NixStartAdmissionErrorV2> {
        self.recheck()?;

        let credentials = PinnedSystemdCredential::load_nix_owner_publics()?;
        let node = PinnedSystemdCredential::load_nix_owner_node_id()?;
        let pins = ControllerNixStartRecipeSelectorV2::validate_owner_floor_publics(
            &credentials,
            original_node_id(&node)?,
            self.retained.profile.identities,
        )?;

        let mut origin = NixOwnerPublicSessionFloorOriginV2 {
            startup: self,
            credentials,
            node,
            pins,
            health: OriginFailureLatchV2::default(),
        };
        origin.recheck()?;
        Ok(origin)
    }
}

impl NixOwnerPublicSessionFloorOriginV2<'_> {
    /// Rechecks original startup, all twelve publics, node, then startup again.
    ///
    /// # Errors
    ///
    /// Preserves the first actual typed failure. A failed or interrupted
    /// observation permanently fences this loan; later calls return `Invalid`.
    /// This is per-instance fencing, not a resident original-cause archive.
    pub fn recheck(&mut self) -> Result<(), NixStartAdmissionErrorV2> {
        let observation = self
            .health
            .begin()
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let result = Self::recheck_originals(self.startup, &self.credentials, &self.node);
        observation.finish(result)
    }

    fn recheck_originals(
        startup: &ProductionNixOwnerStartupV1,
        credentials: &[PinnedSystemdCredential; 12],
        node: &PinnedSystemdCredential,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        startup.recheck()?;
        for credential in credentials {
            credential.recheck()?;
        }
        node.recheck()?;
        startup.recheck()?;
        Ok(())
    }

    /// Requires both current Nix service-barrier flights to match the originals.
    ///
    /// This observes PID1 policy, not population drain, current manager image
    /// after reexec, cross-flight bus-owner identity, or a physical TPM value.
    ///
    /// # Errors
    ///
    /// Preserves actual startup/credential failures and fences the loan on
    /// failure or interruption; a previously closed loan returns `Invalid`.
    pub fn require_physical_service_barrier(
        &mut self,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        self.recheck()?;
        let observation = self
            .health
            .begin()
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let result = self
            .startup
            .require_physical_service_barrier()
            .map_err(NixStartAdmissionErrorV2::from);
        observation.finish(result)?;
        self.recheck()
    }

    /// Compares the actual child under the original executed-helper checks.
    ///
    /// Root helper UID/GID0, zero effective/permitted/inheritable caps,
    /// bounding0xc0, NNP, parent, cgroup and MAC remain required. This does not
    /// prove complete loader mappings, a measured phase, or physical TPM custody.
    /// The old executed-helper API is unchanged and is a pre-HELLO check.
    ///
    /// # Errors
    ///
    /// Preserves original startup/credential/helper errors and fences this loan
    /// on failure or interruption; a previously closed loan returns `Invalid`.
    pub fn require_floor_helper(
        &mut self,
        process: &PidFd,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        self.recheck()?;
        let observation = self
            .health
            .begin()
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let result = self
            .startup
            .require_floor_helper(process)
            .map_err(NixStartAdmissionErrorV2::from);
        observation.finish(result)?;
        self.recheck()
    }

    /// Returns the original measured helper path as nonauthorizing launch DATA.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/public/node custody.
    pub fn helper_path(&mut self) -> Result<&Path, NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.startup.retained.helper.path())
    }

    /// Returns the independently measured helper-loader path as comparison DATA.
    ///
    /// This does not establish executed-loader mappings or physical custody.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/public/node custody.
    pub fn helper_loader_path(&mut self) -> Result<&Path, NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(Path::new(&self.startup.retained.profile.helper_loader.path))
    }

    /// Returns the original immutable startup profile path as comparison DATA.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/public/node custody.
    pub fn profile_path(&mut self) -> Result<&Path, NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.startup.profile_path())
    }

    /// Returns the original selected invocation identifier as comparison DATA.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/public/node custody.
    pub fn invocation_id(&mut self) -> Result<[u8; 16], NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.startup.invocation())
    }

    /// Borrows the decoded original domain pins as nonauthorizing DATA.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/public/node custody.
    pub fn fixed_domain_pins(
        &mut self,
    ) -> Result<&NixFixedDomainPinsDataV2, NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(&self.pins)
    }

    /// Borrows all twelve original public preimages in the existing pin order.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/public/node custody.
    pub fn public_preimages(&mut self) -> Result<[&[u8]; 12], NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.credentials
            .each_ref()
            .map(|credential| credential.bytes()))
    }

    /// Borrows the separate exact original node bytes outside the twelve-pin set.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/public/node custody.
    pub fn node_preimage(&mut self) -> Result<&[u8], NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.node.bytes())
    }
}

/// Decodes only the separately retained original protected node bytes.
///
/// # Errors
///
/// Rejects nonexact or zero original node data without constructing authority.
pub(super) fn original_node_id(
    credential: &PinnedSystemdCredential,
) -> Result<NodeId, NixStartAdmissionErrorV2> {
    decode_node_id(credential.bytes())
}

fn decode_node_id(bytes: &[u8]) -> Result<NodeId, NixStartAdmissionErrorV2> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
    if bytes == [0; 16] {
        return Err(NixStartAdmissionErrorV2::Invalid);
    }
    Ok(NodeId::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure node bytes cannot construct startup, credential custody or a loan.
    #[test]
    fn a_nonzero_sixteen_byte_node_is_data_only() {
        assert_eq!(
            decode_node_id(&[7; 16]).unwrap(),
            NodeId::from_bytes([7; 16]),
        );
    }

    #[test]
    fn zero_short_long_and_empty_node_bytes_are_refused() {
        for bytes in [
            Vec::new(),
            vec![1; 15],
            vec![1; 17],
            vec![0; 16],
        ] {
            assert!(matches!(
                decode_node_id(&bytes),
                Err(NixStartAdmissionErrorV2::Invalid),
            ));
        }
    }
}
