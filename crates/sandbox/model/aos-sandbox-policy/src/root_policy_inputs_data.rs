//! Shares retained signed-input DATA without owning a current Root interval.
//!
//! The container borrows raw installed packets. Verification compares the full
//! supplied historical rows and delegates the canonical held-signed recipe;
//! no supplied DATA becomes a protected pin, financial admission, or native
//! completion. Every native caller retains its own actual owner and posts.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as MechanicalError;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

use crate::signed_inputs::PolicyDeploymentInputsV1;

pub use crate::root_signed_sources_data::{
    RootSignedProjectSourcesDataV1, RootSignedSourcesDataErrorV1,
    verify_root_signed_project_sources_data_v1,
};

/// Borrows untrusted input DATA already retained by the actual Root daemon.
///
/// This type owns no journal, verifying key, receiving original or authority.
/// Only verification against the actual held Root heads can authenticate its
/// bytes. Construction performs no IO, allocation or typed policy decoding.
pub struct RootCurrentPolicyInputDataV1<'input> {
    deployment_packet: &'input [u8],
    deployment: PolicyDeploymentInputsV1<'input>,
    project_packet: Option<&'input [u8]>,
    project_input: Option<&'input [u8]>,
}

impl<'input> RootCurrentPolicyInputDataV1<'input> {
    /// Borrows installed signed heads and their retained deployment/project inputs.
    #[must_use]
    pub fn new(
        deployment_packet: &'input [u8],
        deployment: &PolicyDeploymentInputsV1<'input>,
        project: Option<(&'input [u8], &'input [u8])>,
    ) -> Self {
        Self {
            deployment_packet,
            deployment: PolicyDeploymentInputsV1 {
                node: deployment.node,
                site: deployment.site,
                backend: deployment.backend,
                catalogs: deployment.catalogs,
            },
            project_packet: project.map(|(packet, _)| packet),
            project_input: project.map(|(_, input)| input),
        }
    }

    /// Borrows raw installed signed inputs without authenticating their cut.
    ///
    /// The actual read-only Root purpose separately verifies these same bytes
    /// against its held current policy Journal and pins before encoding them.
    /// No native owner or signing capability crosses this DATA boundary.
    pub fn raw_signed_input_envelopes_v2(&self) -> Option<(
        aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::
            SignedDeploymentInputsDataV2<'_>,
        aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::
            SignedProjectInputsDataV2<'_>,
    )>{
        use aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::{
            SignedDeploymentInputsDataV2, SignedProjectInputsDataV2,
        };

        Some((
            SignedDeploymentInputsDataV2 {
                signed_packet: self.deployment_packet,
                node: self.deployment.node,
                site: self.deployment.site,
                backend: self.deployment.backend,
                catalogs: self.deployment.catalogs,
            },
            SignedProjectInputsDataV2 {
                signed_packet: self.project_packet?,
                input: self.project_input?,
            },
        ))
    }

    /// Totals the same retained raw input widths without decoding.
    ///
    /// # Errors
    /// Refuses a width that cannot be represented as a checked u64 sum.
    pub fn encoded_width_v1(&self) -> Result<u64, MechanicalError> {
        [
            self.deployment_packet,
            self.deployment.node,
            self.deployment.site,
            self.deployment.backend,
            self.deployment.catalogs,
            self.project_packet.unwrap_or(&[]),
            self.project_input.unwrap_or(&[]),
        ]
        .into_iter()
        .try_fold(0_u64, |total, bytes| {
            total
                .checked_add(
                    u64::try_from(bytes.len()).map_err(|_| MechanicalError::JournalTooLarge)?,
                )
                .ok_or(MechanicalError::JournalTooLarge)
        })
    }

    /// Compares the preview's complete signed-input fields with retained bytes.
    ///
    /// # Errors
    /// Refuses any changed deployment envelope/input or project envelope/input.
    pub fn require_preview_data_v1(
        &self,
        fields: &[&[u8]; 9],
    ) -> Result<(), RootPolicyInputErrorV1> {
        if fields[2] != self.deployment_packet
            || fields[3..7]
                != [
                    self.deployment.node,
                    self.deployment.site,
                    self.deployment.backend,
                    self.deployment.catalogs,
                ]
            || self.project_packet != Some(fields[7])
            || self.project_input != Some(fields[8])
        {
            return Err(RootPolicyInputErrorV1::ChangedHead);
        }
        Ok(())
    }

    /// Verifies retained inputs against supplied complete historical rows.
    ///
    /// # Errors
    /// Refuses bounded shape, head, pin, signature, expiry, generation, or
    /// prerequisite mismatch. Success does not authenticate native provenance.
    pub fn verify_current_sources_v1(
        &self,
        policy: HistoricalLedgerReadViewV1<'_>,
        now: i64,
    ) -> Result<RootSignedProjectSourcesDataV1, RootSignedSourcesDataErrorV1> {
        let input = self
            .require_shape()
            .map_err(|_| RootSignedSourcesDataErrorV1::ChangedCut)?;
        self.require_current_heads_data_v1(policy)
            .map_err(|_| RootSignedSourcesDataErrorV1::ChangedCut)?;
        verify_root_signed_project_sources_data_v1(policy, input, &self.deployment, now)
    }

    /// Compares supplied signed envelopes with the same complete historical rows.
    ///
    /// # Errors
    /// Refuses a substituted deployment or project signed-head packet. The view
    /// supplies comparison DATA, never current native custody or role authority.
    pub fn require_current_heads_data_v1(
        &self,
        policy: HistoricalLedgerReadViewV1<'_>,
    ) -> Result<(), RootPolicyInputErrorV1> {
        if policy.get(RecordNamespace::DesiredState, crate::journal_keys::HEAD_KEY)
            != Some(self.deployment_packet)
            || policy.get(
                RecordNamespace::DesiredState,
                crate::journal_keys::PROJECT_HEAD_KEY_V2,
            ) != self.project_packet
        {
            return Err(RootPolicyInputErrorV1::ChangedHead);
        }
        Ok(())
    }

    /// Borrows the untrusted deployment envelope without authenticating it.
    pub fn deployment_packet_data_v1(&self) -> &'input [u8] {
        self.deployment_packet
    }

    /// Borrows the untrusted bounded deployment input fields.
    pub fn deployment_inputs_data_v1(&self) -> &PolicyDeploymentInputsV1<'input> {
        &self.deployment
    }

    /// Borrows the optional untrusted project envelope.
    pub fn project_packet_data_v1(&self) -> Option<&'input [u8]> {
        self.project_packet
    }

    /// Borrows the optional untrusted project input bytes.
    pub fn project_input_data_v1(&self) -> Option<&'input [u8]> {
        self.project_input
    }

    /// Checks the existing closed raw input and envelope bounds.
    ///
    /// # Errors
    /// Refuses an absent project or any input/envelope outside its old bound.
    pub fn require_shape(&self) -> Result<&[u8], RootPolicyInputErrorV1> {
        if [
            self.deployment.node,
            self.deployment.site,
            self.deployment.backend,
            self.deployment.catalogs,
        ]
        .iter()
        .any(|input| input.len() > 64 * 1024)
        {
            return Err(RootPolicyInputErrorV1::Bounds);
        }
        let project = self
            .project_input
            .ok_or(RootPolicyInputErrorV1::MissingProject)?;
        if self.deployment_packet.len() != 224
            || self.project_packet.map(|packet| packet.len()) != Some(328)
            || project.len() > 3 * 1024
        {
            return Err(RootPolicyInputErrorV1::Bounds);
        }
        Ok(project)
    }
}

/// Describes a passive raw-input shape or exact-head comparison refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootPolicyInputErrorV1 {
    /// A raw input or envelope exceeds its existing closed bound.
    #[error("actual Root policy input exceeds its closed credential bound")]
    Bounds,
    /// The retained container has no explicit project input.
    #[error("actual Root has no retained explicit project policy input")]
    MissingProject,
    /// A held signed head differs from the retained envelope bytes.
    #[error("actual Root held heads differ from its retained daemon credentials")]
    ChangedHead,
}

/// Measures the new historical-view and typed verification return bridges.
///
/// The two actual verification frames each carry one canonical tuple Result
/// and one supplied historical view. Two shape/head Results cover the nested
/// passive comparison and its caller projection. Existing decoder/model and
/// retained upper native/error owners remain separately priced by the caller.
#[must_use]
pub fn verification_return_control_bytes_v1() -> Option<usize> {
    std::mem::size_of::<Result<RootSignedProjectSourcesDataV1, RootSignedSourcesDataErrorV1>>()
        .checked_mul(2)?
        .checked_add(std::mem::size_of::<HistoricalLedgerReadViewV1<'_>>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<Result<(), RootPolicyInputErrorV1>>().checked_mul(2)?)
}

/// Measures the new width-result return and exact upper projection lane.
#[must_use]
pub fn width_return_control_bytes_v1() -> Option<usize> {
    std::mem::size_of::<Result<u64, MechanicalError>>().checked_mul(2)
}
