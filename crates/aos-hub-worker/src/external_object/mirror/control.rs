//! Closed physical relays of an unchanged Native mirror control.
//!
//! The application MAC covers the complete Native plan. A separate physical
//! role covers the selected item and the closed internal action. Internal
//! selection never supplies a new provider grant or replaces the original.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    mirror_work::{MirrorOriginal, MirrorProgress, MirrorStep, digest},
    storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan},
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub(super) const PHYSICAL_PATH: &str = "/mirror-turn";
pub(super) const SIGNATURE_HEADER: &str = "x-aos-external-mirror-physical-signature";
pub(super) const RECEIPT_HEADER: &str = "x-aos-external-mirror-physical-receipt";
pub(super) const MAX_CONTROL_BYTES: usize = 384 * 1024;
const DOMAIN: &[u8] = b"aos.external-mirror-physical-control.v1\0";
const REPLY_DOMAIN: &[u8] = b"aos.external-mirror-physical-reply.v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Action {
    Execute,
    SourceProgress,
    SourceRange { part_number: u32 },
    StageAcknowledgement { progress: Box<MirrorProgress> },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Control {
    pub version: u8,
    pub native_body: String,
    pub native_signature: String,
    pub item_index: Option<usize>,
    pub action: Action,
}

impl Control {
    pub(super) fn new(
        body: &[u8],
        signature: &str,
        index: Option<usize>,
        action: Action,
    ) -> Result<Self> {
        ensure!(
            body.len() <= 256 * 1024,
            "mirror Native control exceeds bound"
        );
        Ok(Self {
            version: 1,
            native_body: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body),
            native_signature: signature.into(),
            item_index: index,
            action,
        })
    }

    pub(super) fn authenticate(
        &self,
        application: &StorageWorkKey,
        deployment: &str,
        latest: i64,
    ) -> Result<StorageWorkPlan> {
        ensure!(
            self.version == 1
                && self.native_body.len() <= (256_usize * 1024 * 4).div_ceil(3)
                && self.native_signature.len() <= 256,
            "mirror physical envelope exceeds bounds"
        );
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.native_body)?;
        ensure!(
            body.len() <= 256 * 1024,
            "mirror decoded Native control exceeds bound"
        );
        let plan = application.verify_plan(&self.native_signature, &body, deployment, latest)?;
        let (original, step) = self.selected(&plan)?;
        ensure!(
            original.external_destination.is_some(),
            "External mirror relay received Managed original"
        );
        original.validate_plan(&plan)?;
        match &self.action {
            Action::Execute => {}
            Action::SourceProgress => ensure!(
                matches!(
                    step,
                    MirrorStep::BeginPromotion
                        | MirrorStep::CopyParts { .. }
                        | MirrorStep::CompletePromotion
                ),
                "mirror source observation is unrelated to Native promotion"
            ),
            Action::SourceRange { part_number } => {
                let MirrorStep::CopyParts {
                    first_part,
                    maximum_parts,
                } = step
                else {
                    anyhow::bail!("mirror source range is unrelated to Native copy");
                };
                ensure!(
                    (*first_part..first_part + maximum_parts).contains(part_number)
                        && *part_number > 0
                        && u64::from(*part_number - 1)
                            * aos_hub_core::mirror_work::MIRROR_PART_BYTES
                            < original.verification.size(),
                    "mirror range escapes its signed part group"
                );
            }
            Action::StageAcknowledgement { progress } => {
                let MirrorStep::Acknowledge { commit_digest } = step else {
                    anyhow::bail!("private mirror acknowledgement lacks Native commit");
                };
                ensure!(
                    progress.commit_digest(original)? == *commit_digest,
                    "private mirror acknowledgement changed exact final evidence"
                );
            }
        }
        Ok(plan)
    }

    pub(super) fn selected<'a>(
        &self,
        plan: &'a StorageWorkPlan,
    ) -> Result<(&'a MirrorOriginal, &'a MirrorStep)> {
        match (&plan.operation, self.item_index) {
            (StorageWorkOperation::MirrorTransfer { original, step }, None) => Ok((original, step)),
            (StorageWorkOperation::MirrorTransferBatch { items }, Some(index)) => {
                let item = items
                    .get(index)
                    .context("mirror selected batch item absent")?;
                Ok((&item.original, &item.step))
            }
            _ => anyhow::bail!("mirror physical selection differs from Native plan"),
        }
    }

    pub(super) fn destination(&self, step: &MirrorStep) -> bool {
        self.action == Action::Execute
            && matches!(
                step,
                MirrorStep::Status { destination: true }
                    | MirrorStep::BeginPromotion
                    | MirrorStep::CopyParts { .. }
                    | MirrorStep::CompletePromotion
                    | MirrorStep::Acknowledge { .. }
            )
    }

    pub(super) fn sign(&self, role: &StorageWorkKey) -> Result<(Vec<u8>, String)> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_CONTROL_BYTES,
            "mirror physical control exceeds bound"
        );
        let signature = role.sign_body(&[DOMAIN, &bytes].concat())?;
        Ok((bytes, signature))
    }

    pub(super) fn verify(role: &StorageWorkKey, bytes: &[u8], signature: &str) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_CONTROL_BYTES,
            "mirror physical control exceeds bound"
        );
        role.verify_body(signature, &[DOMAIN, bytes].concat())?;
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reply {
    pub request_digest: String,
    pub progress: MirrorProgress,
    pub source_bytes: u64,
}

impl Reply {
    pub(super) fn sign(
        &self,
        control: &Control,
        role: &StorageWorkKey,
    ) -> Result<(Vec<u8>, String)> {
        ensure!(
            self.request_digest == digest(control)?,
            "mirror physical reply changed request"
        );
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= 256 * 1024,
            "mirror physical reply exceeds bound"
        );
        Ok((
            bytes.clone(),
            role.sign_body(&[REPLY_DOMAIN, &bytes].concat())?,
        ))
    }

    pub(super) fn verify(
        control: &Control,
        role: &StorageWorkKey,
        bytes: &[u8],
        signature: &str,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= 256 * 1024,
            "mirror physical reply exceeds bound"
        );
        role.verify_body(signature, &[REPLY_DOMAIN, bytes].concat())?;
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            value.request_digest == digest(control)?,
            "mirror physical response substituted its control"
        );
        Ok(value)
    }
}
