//! Durable stage-entry admission of one image-sealed source template.
//!
//! The admission record keeps the exact native root exchanges and the plan
//! reconstructed from them. A restart re-observes roots and replays the
//! retained constructor transcript; it never replaces an owned transaction
//! with a plan built for a different provider assignment.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::EnvironmentDocument;
use aos_ability_plan::{
    CheckedSourceStageAdmission, SOURCE_STAGE_BUNDLE_MAX_BYTES, SourceStageAdmission,
    SourceStageBundle,
};
use aos_contract::Sha256Digest;
use aos_provider_protocol::{RootObservationRequest, RootObservationResult};
use serde::{Deserialize, Serialize};

use super::source_root_inventory::{observe_source_roots, verify_recorded_source_roots};
use super::stage_handoff::read_trusted_file;
use super::transaction_store::publish_named_immutable_bounded;
use crate::package_contract::VerifiedPackageContractSet;

const ADMISSION_RECORD_SCHEMA: &str = "aos.ability.source-stage-admission-evidence/v1";
pub(crate) const ADMISSION_RECORD_FILE: &str = "source-admission.json";
const ROOT_MAX_AGE_MILLIS: u64 = 30_000;
const ROOT_INVOCATION_BUDGET_MILLIS: u64 = 5_000;
pub(crate) const ADMISSION_RECORD_MAX_BYTES: u64 = (SOURCE_STAGE_BUNDLE_MAX_BYTES as u64) * 2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceStageAdmissionRecord {
    schema: String,
    template: Sha256Digest,
    admission: SourceStageAdmission,
    requests: Vec<RootObservationRequest>,
    responses: Vec<RootObservationResult>,
}

/// Carries the exact executable plan and retained stage-entry commitment.
pub(crate) struct AdmittedSourceStage {
    pub(crate) template: SourceStageBundle,
    pub(crate) checked: CheckedSourceStageAdmission,
    pub(crate) record_digest: Sha256Digest,
    pub(crate) environment: EnvironmentDocument,
}

/// Admits or replays the source template under a fresh native root inventory.
///
/// A previously retained record is authoritative. New pure evaluation occurs
/// only before that record exists and before the stage journal begins.
///
/// # Errors
///
/// Returns an error when the template, package set, native roots, evaluator,
/// retained record, or provider assignment differs from the selected image.
pub(crate) fn load_or_admit_source_stage(
    template_bytes: &[u8],
    packages: &VerifiedPackageContractSet,
    static_contract_identity: &str,
    boot_id: &str,
    transaction_dir: &Path,
) -> Result<AdmittedSourceStage> {
    let template = super::source_stage::decode_source_stage(template_bytes)?;
    let record_path = transaction_dir.join(ADMISSION_RECORD_FILE);
    let existing = match fs::symlink_metadata(&record_path) {
        Ok(_) => Some(read_trusted_file(
            &record_path,
            ADMISSION_RECORD_MAX_BYTES,
            "retained source-stage admission",
        )?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspecting source-stage admission record"),
    };

    let first = observe_source_roots(
        &template,
        packages,
        boot_id,
        ROOT_MAX_AGE_MILLIS,
        ROOT_INVOCATION_BUDGET_MILLIS,
    )?;
    let (record, current_roots) = if let Some(bytes) = existing {
        (decode_record(&bytes)?, first)
    } else {
        let mut evaluator = super::native_activation::production_evaluator()?
            .with_source_fixed_point(
                PathBuf::from(template.bundle().evaluation_base_lib()),
                static_contract_identity.to_string(),
            )?;
        let admission = template
            .bundle()
            .admit_from_trusted_environment(first.environment.clone(), &mut evaluator)?;

        // Pure evaluation can outlast a root observation. Reprobe before
        // retaining the plan, and reject any intervening assignment change.
        let current = observe_source_roots(
            &template,
            packages,
            boot_id,
            ROOT_MAX_AGE_MILLIS,
            ROOT_INVOCATION_BUDGET_MILLIS,
        )?;
        current.ensure_fresh()?;
        ensure!(
            current.environment == first.environment,
            "source-stage root assignments changed during pure evaluation"
        );
        let record = SourceStageAdmissionRecord {
            schema: ADMISSION_RECORD_SCHEMA.to_string(),
            template: template.digest(),
            admission,
            requests: current.requests.clone(),
            responses: current.responses.clone(),
        };
        let bytes = aos_contract::canonical::to_vec(&record)?;
        ensure!(
            bytes.len() as u64 <= ADMISSION_RECORD_MAX_BYTES,
            "source-stage admission record exceeds its size bound"
        );
        publish_named_immutable_bounded(&record_path, &bytes, ADMISSION_RECORD_MAX_BYTES as usize)
            .context("retaining exact source-stage admission before journaling")?;
        (record, current)
    };

    let retained_bytes = read_trusted_file(
        &record_path,
        ADMISSION_RECORD_MAX_BYTES,
        "retained source-stage admission",
    )?;
    ensure!(
        aos_contract::canonical::to_vec(&record)? == retained_bytes,
        "retained source-stage admission changed during admission"
    );
    let historical =
        verify_recorded_source_roots(&template, &record.requests, &record.responses, boot_id)?;
    ensure!(
        record.template == template.digest()
            && historical == *record.admission.observed_environment(),
        "retained source-stage root evidence differs from its admitted inventory"
    );
    current_roots.ensure_fresh()?;
    let checked =
        record
            .admission
            .check(template.bundle(), current_roots.environment.clone(), None)?;
    Ok(AdmittedSourceStage {
        template: template.bundle().clone(),
        checked,
        record_digest: Sha256Digest::of_bytes(&retained_bytes),
        environment: current_roots.environment,
    })
}

/// Replays a retained source admission for handoff validation.
///
/// This checks the historical root exchanges and effect graph without
/// claiming that those roots remain live in the receiving stage.
///
/// # Errors
///
/// Returns an error when the record, template, root evidence, or admitted
/// plan differs from its independently retained commitment.
pub(crate) fn validate_retained_source_stage(
    template_bytes: &[u8],
    boot_id: &str,
    record_path: &Path,
    expected_digest: Sha256Digest,
) -> Result<CheckedSourceStageAdmission> {
    let template = super::source_stage::decode_source_stage(template_bytes)?;
    let bytes = read_trusted_file(
        record_path,
        ADMISSION_RECORD_MAX_BYTES,
        "retained source-stage admission",
    )?;
    ensure!(
        Sha256Digest::of_bytes(&bytes) == expected_digest,
        "retained source-stage admission differs from its journal commitment"
    );
    let record = decode_record(&bytes)?;
    ensure!(
        record.template == template.digest(),
        "retained source-stage admission names another image template"
    );
    let historical =
        verify_recorded_source_roots(&template, &record.requests, &record.responses, boot_id)?;
    ensure!(
        historical == *record.admission.observed_environment(),
        "retained root exchanges differ from the admitted inventory"
    );
    record
        .admission
        .check(template.bundle(), historical, None)
        .map_err(Into::into)
}

fn decode_record(bytes: &[u8]) -> Result<SourceStageAdmissionRecord> {
    let record: SourceStageAdmissionRecord =
        aos_contract::canonical::from_slice(bytes, ADMISSION_RECORD_SCHEMA)?;
    ensure!(
        record.schema == ADMISSION_RECORD_SCHEMA
            && aos_contract::canonical::to_vec(&record)? == bytes,
        "retained source-stage admission is not canonical"
    );
    Ok(record)
}
