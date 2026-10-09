//! Retains the authenticated fixed workflow input under its original decoder.
//!
//! The input file, raw bytes and descriptor custody close before their loans.
//! The service-policy projection contains no owning model data or bank getter.
//! Actual scenario/schedule import, Source admission and native initialization
//! qualification follow this read; an authenticated descriptor is not a VM
//! launch permission.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use crucible::owned_decode::{DecodeAdmissionError, DecodeDescriptorLoan, DecodeScratch};
use crucible_qemu::{OriginalActorDecodeOwner, OriginalActorServicePolicy};

use super::MeasurementRuntimeAdmissionError;
use super::actor_roles::OriginalActorRoleIssuer;

const WORKFLOW_PATH: &str = "/etc/crucible/measurement-workflow.json";

/// Keeps the descriptor and its original authority through subsequent use.
pub(super) struct OriginalResidentWorkflowOwner {
    policy: Option<OriginalActorServicePolicy>,
    input: Option<Vec<u8>>,
    file: Option<File>,
    descriptors: Option<DecodeDescriptorLoan>,
    input_credit: Option<DecodeScratch>,
    decoder: Option<OriginalActorDecodeOwner>,
}

/// Preserves an actual read refusal before its independent original boundary.
#[derive(Debug, thiserror::Error)]
#[error("original workflow input refused: {source}; original: {original_after:?}")]
pub struct OriginalWorkflowReadError {
    /// First actual kernel read, file identity or allocation refusal.
    #[source]
    pub source: OriginalWorkflowInputError,
    /// The same decoder's original post-effect refusal, when present.
    pub original_after: Option<DecodeAdmissionError>,
}

/// Classifies input failures without flattening their typed original causes.
#[derive(Debug, thiserror::Error)]
pub enum OriginalWorkflowInputError {
    /// The same closed actor's original custody refused without a new wrapper.
    #[error("workflow actor custody refused: {0}")]
    Actor(#[from] crucible_qemu::OriginalActorAccountError),
    /// The actual fixed-path kernel operation failed.
    #[error("workflow kernel operation refused: {0}")]
    Io(#[from] std::io::Error),
    /// A buffer allocation failed after original admission.
    #[error("workflow buffer allocation refused: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    /// The original decoder refused credit before an effect.
    #[error("workflow original credit refused: {0}")]
    Admission(#[from] DecodeAdmissionError),
    /// The installed input is mutable, unowned, empty or cannot fit this target.
    #[error("workflow file identity or extent is inadmissible")]
    Identity,
}

impl OriginalResidentWorkflowOwner {
    pub(super) fn load(
        actor: &OriginalActorRoleIssuer,
    ) -> Result<Self, MeasurementRuntimeAdmissionError> {
        let decoder = actor.prepare_workflow_decode_owner()?;
        let mut owner = Self {
            policy: None,
            input: None,
            file: None,
            descriptors: None,
            input_credit: None,
            decoder: Some(decoder),
        };
        owner.read_fixed_input()?;
        let decoder =
            owner
                .decoder
                .as_ref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained workflow decoder",
                ))?;
        let input =
            owner
                .input
                .as_deref()
                .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                    "retained workflow input",
                ))?;
        owner.policy = Some(actor.admit_workflow_service(decoder, input)?);
        actor.require_original()?;
        Ok(owner)
    }

    fn read_fixed_input(&mut self) -> Result<(), OriginalWorkflowReadError> {
        let decoder = self
            .decoder
            .as_ref()
            .ok_or_else(|| OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Identity,
                original_after: None,
            })?;
        let budget = decoder
            .budget()
            .map_err(|source| OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Actor(source),
                original_after: None,
            })?;
        let result: Result<(), OriginalWorkflowInputError> = (|| {
            self.descriptors = Some(budget.reserve_descriptors(1)?);
            budget.verify_live()?;
            // The trusted rootfs installs a symlink to its immutable store
            // object. Pin the actual opened file before the fallible original
            // postcut; matching its contents is authenticated separately.
            self.file = Some(File::open(WORKFLOW_PATH)?);
            budget.verify_live()?;
            let file = self
                .file
                .as_mut()
                .ok_or(OriginalWorkflowInputError::Identity)?;
            let metadata = file.metadata()?;
            budget.verify_live()?;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o222 != 0 {
                return Err(OriginalWorkflowInputError::Identity);
            }
            let length = usize::try_from(metadata.len())
                .ok()
                .filter(|length| *length != 0)
                .ok_or(OriginalWorkflowInputError::Identity)?;
            self.input_credit = Some(budget.reserve_scratch_bytes(metadata.len())?);
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length)?;
            bytes.resize(length, 0);
            self.input = Some(bytes);
            budget.verify_live()?;
            let bytes = self
                .input
                .as_mut()
                .ok_or(OriginalWorkflowInputError::Identity)?;
            file.read_exact(bytes)?;
            budget.verify_live()?;
            // A fixed one-byte stack probe refuses a changed length. It owns
            // no extra retained buffer or independently inferred descriptor.
            let mut trailing = [0];
            if file.read(&mut trailing)? != 0 {
                return Err(OriginalWorkflowInputError::Identity);
            }
            Ok(())
        })();
        let after = budget.verify_live();
        match (result, after) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(source), after) => Err(OriginalWorkflowReadError {
                source,
                original_after: after.err(),
            }),
            (Ok(()), Err(source)) => Err(OriginalWorkflowReadError {
                source: OriginalWorkflowInputError::Admission(source),
                original_after: None,
            }),
        }
    }

    pub(super) fn take_service_policy(
        &mut self,
    ) -> Result<OriginalActorServicePolicy, MeasurementRuntimeAdmissionError> {
        self.policy
            .take()
            .ok_or(MeasurementRuntimeAdmissionError::MissingPurpose(
                "unconsumed original workflow service policy",
            ))
    }
}

impl Drop for OriginalResidentWorkflowOwner {
    fn drop(&mut self) {
        drop(self.policy.take());
        drop(self.input.take());
        drop(self.file.take());
        drop(self.descriptors.take());
        drop(self.input_credit.take());
        if let Some(decoder) = self.decoder.take() {
            // A refused close returns the same fail-sticky owner. Its Drop
            // retains opaque errors and original credit until actor teardown.
            let _closed = decoder.try_close();
        }
    }
}
