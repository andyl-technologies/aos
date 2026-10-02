//! Native generation evidence bound to original admission and measured image pins.
//!
//! A record describes an already committed native profile generation and its
//! immutable pre-evaluation descriptor. Admission receipts remain evidence of
//! the original image or signed release; they never become independent trust
//! anchors merely because their names appear in a quoted record.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::native_deployment::EvaluationInput;
use crate::registry::ReleaseTrustReceipt;

/// Identifies an original receipt bound to the verified bootstrap image.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageAdmission {
    /// Locates the immutable admission document.
    pub path: PathBuf,
    /// Binds its bytes to the original authenticated image authority.
    pub digest: Sha256Digest,
}

/// Records the exact NAR identity and original authority admitted for one root.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputEvidence {
    /// Identifies the canonical immutable store root.
    pub store_path: String,
    /// Identifies the complete uncompressed NAR bytes.
    pub nar_hash: Sha256Digest,
    /// Bounds the exact complete NAR byte count.
    pub nar_size: u64,
    /// Lists sorted direct reference component hashes.
    pub references: Vec<String>,
    /// Preserves the signed release that authenticated this root.
    pub release: Option<ReleaseTrustReceipt>,
    /// Preserves the image authority when this root came from bootstrap.
    pub image: Option<ImageAdmission>,
    /// Preserves a caller-authenticated domain proof for supplementary sources.
    #[serde(default)]
    pub source_authority: Option<crate::native_deployment::SourceAuthorization>,
}

/// Carries physical image expectations supplied by an authenticated boot contract.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredImageEvidence {
    /// Identifies the immutable selected sysroot image.
    pub toplevel: String,
    /// Identifies its authenticated boot artifact contract.
    pub boot_artifact_contract: String,
    /// Pins the published ready-phase PCR 11; an observed value is not a pin.
    pub expected_pcr11: Option<Sha256Digest>,
    /// Pins the published dm-verity root hash as lowercase hexadecimal.
    pub root_verity_roothash: Option<String>,
    /// Pins the verity superblock UUID when the boot contract supplies it.
    pub root_verity_uuid: Option<String>,
}

/// Binds a committed native package generation to immutable authenticated inputs.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationEvidence {
    /// Identifies the native generation attestation contract.
    pub schema: String,
    /// Names this quote transaction independently from earlier activations.
    pub activation_id: Sha256Digest,
    /// Names the committed profile generation.
    pub profile_generation: u32,
    /// Names its authoritative native journal sequence.
    pub sequence: u64,
    /// Names the exact checked desired deployment content.
    pub content: String,
    /// Locates the immutable pre-evaluation descriptor.
    pub evaluation_input: PathBuf,
    /// Commits to the exact descriptor bytes, including source ordering.
    pub evaluation_sha256: Sha256Digest,
    /// Records the native source roles and exact resolved package context.
    pub evaluation: EvaluationInput,
    /// Preserves the exact supplemental root set of the committed deployment.
    pub deployment_inputs: Vec<String>,
    /// Records original admission for all retained generation roots.
    pub inputs: BTreeMap<String, InputEvidence>,
    /// Records the exact checked runtime results committed by this generation.
    pub outputs: BTreeMap<String, serde_json::Value>,
    /// Records independently authenticated physical image expectations.
    pub image: MeasuredImageEvidence,
    /// Distinguishes a TPM quote from explicitly unavailable evidence.
    pub quote_status: String,
    /// Encodes the embedded TPM quote evidence as hexadecimal.
    pub quote: String,
}

/// Identifies the native generation evidence format.
pub const GENERATION_SCHEMA: &str = "aos.package.generation-attestation";

/// Canonicalizes native evidence without its quote and returns its measured digest.
///
/// # Errors
/// Returns an error for serialization or canonical JSON limits.
pub fn record_hash(record: &GenerationEvidence) -> Result<Sha256Digest> {
    Ok(Sha256Digest::of_bytes(bare_record_bytes(record)?))
}

fn bare_record_bytes(record: &GenerationEvidence) -> Result<Vec<u8>> {
    let mut bare = record.clone();
    bare.quote.clear();
    aos_contract::canonical::canonical_json(&serde_json::to_value(bare)?)
}

/// Publishes native evidence for a committed generation and optionally quotes it.
///
/// A durable transaction fixes the activation identity before PCR extension.
/// Recovery reuses that identity and rejects changed inputs. Image expectations
/// are supplied by the authenticated boot backend, never inferred from live PCRs.
///
/// # Errors
/// Returns an error for inconsistent admission or retained transactions, missing
/// mandatory hardware evidence, a physical image mismatch, or failed publication.
pub fn persist(
    profile: &Path,
    generation: u32,
    image: MeasuredImageEvidence,
    require_quote: bool,
    detect_tpm: bool,
) -> Result<GenerationEvidence> {
    let directory = profile.join(format!("gen-{generation}"));
    let transaction_path = directory.join(".native-attestation.pending.json");
    let record_path = directory.join("gen-attestation.json");
    let mut record = collect(profile, generation, image)?;
    let retained: Option<GenerationEvidence> = match std::fs::read(&transaction_path) {
        Ok(bytes) => Some(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("reading native quote transaction"),
    };
    if let Some(previous) = &retained {
        record.activation_id = previous.activation_id;
    }

    let has_tpm = detect_tpm && crate::package_attestation::tpm_available()?;
    let has_physical_pins = record.image.expected_pcr11.is_some()
        && record
            .image
            .root_verity_roothash
            .as_deref()
            .is_some_and(super::is_verity_roothash);
    if super::generation_quote_status(require_quote, has_tpm, has_physical_pins)?.is_some() {
        ensure!(
            retained.is_none(),
            "cannot recover a pending quoted activation without its authenticated physical pins and TPM"
        );
        super::write_canonical_json_atomic(&record_path, &record)?;
        return Ok(record);
    }

    let expected_pcr11 = record
        .image
        .expected_pcr11
        .context("missing authenticated PCR 11 pin")?;
    ensure!(
        super::ct_eq(
            &crate::package_attestation::current_pcr11()?,
            &expected_pcr11.hex()
        ),
        "running image PCR 11 differs from its authenticated measurement"
    );
    record.quote_status = super::QUOTE_STATUS_QUOTED.into();
    if let Some(previous) = &retained {
        ensure!(
            previous == &record,
            "pending native attestation disagrees with committed inputs"
        );
    } else {
        super::write_canonical_json_atomic(&transaction_path, &record)?;
    }

    let quote_directory = directory.join("gen-attestation-quote");
    let stage = directory.join(".gen-attestation-quote.pending");
    super::remove_private_quote_dir_if_exists(&stage)?;
    let digest = record_hash(&record)?;
    let generation_id = format!("{}:{}", record.sequence, record.content);
    ensure!(
        crate::package_attestation::measure_generation_attestation(
            Path::new("/"),
            &generation_id,
            &record.activation_id.to_string(),
            &bare_record_bytes(&record)?,
        )?,
        "TPM disappeared before native generation measurement"
    );
    let nonce = digest.hex();
    let artifacts = crate::package_attestation::produce_package_quote(&nonce, &stage)?;
    let quote = super::EmbeddedQuote {
        schema: "aos.gen-attestation-quote/v1".into(),
        nonce,
        pcr_selection: artifacts.pcr_selection.to_string(),
        quoted_pcr15: artifacts.quoted_pcr15,
        ak_public: super::read_hex(&stage.join("ak.pub"))?,
        quote_message: super::read_hex(&stage.join("quote.msg"))?,
        quote_signature: super::read_hex(&stage.join("quote.sig"))?,
        quote_pcrs: super::read_hex(&stage.join("quote.pcrs"))?,
    };
    record.quote = hex::encode(serde_json::to_vec(&quote)?);
    super::remove_private_quote_dir_if_exists(&quote_directory)?;
    std::fs::rename(&stage, &quote_directory)?;
    std::fs::File::open(&directory)?.sync_all()?;
    super::write_canonical_json_atomic(&record_path, &record)?;
    super::remove_file_durable_if_exists(&transaction_path)?;
    Ok(record)
}

/// Collects checked generation state and re-verifies its original admission.
///
/// This read boundary rejects pending activation. Physical image expectations
/// must come from the caller's authenticated boot contract; missing values
/// remain explicitly unavailable until a quote-capable caller supplies them.
///
/// # Errors
/// Returns an error for inconsistent committed state or descriptors, missing
/// admission, changed NARs, or failed source identity checks.
pub fn collect(
    profile: &Path,
    generation: u32,
    image: MeasuredImageEvidence,
) -> Result<GenerationEvidence> {
    let committed = crate::profile::deployment::committed_generation(profile, generation)?;
    let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
    let (descriptor, bytes) = crate::native_deployment::read_descriptor_in(
        &profile.join(format!("gen-{generation}/evaluation.json")),
        &executable,
        &aos_ability_runtime::adapter::CancellationToken::default(),
    )?;
    let evaluation = EvaluationInput::read(&descriptor)?;
    ensure!(
        evaluation.scope == committed.deployment.scope()
            && evaluation.packages == committed.deployment.resolved(),
        "attested input descriptor differs from the committed deployment"
    );
    let (descriptor_root, _) = crate::deployment::nix::store_root_and_suffix(&descriptor)?;
    ensure!(
        committed
            .deployment
            .inputs()
            .iter()
            .any(|root| Path::new(root) == descriptor_root),
        "committed generation does not retain its evaluation descriptor"
    );
    let executable = PathBuf::from(
        std::env::var_os("AOS_NIX_STORE")
            .context("native attestation requires its packaged Nix store executable")?,
    );
    let mut admission = crate::native_registry::RegistryAdmission::new(
        executable,
        &profile.join("deployment/registry-admissions"),
    )?;
    let mut inputs = BTreeMap::new();
    for root in committed.deployment.inputs().iter().chain(
        committed
            .deployment
            .artifacts()
            .iter()
            .map(|artifact| &artifact.path),
    ) {
        if !inputs.contains_key(root) {
            inputs.insert(root.clone(), admission.evidence(root)?);
        }
    }
    let (library_root, _) = crate::deployment::nix::store_root_and_suffix(&evaluation.library)?;
    ensure!(
        inputs
            .get(library_root.to_str().context("library root is not UTF-8")?)
            .is_some_and(|evidence| evidence.nar_hash == evaluation.library_nar_hash),
        "library identity differs from its original admission"
    );
    Ok(GenerationEvidence {
        schema: GENERATION_SCHEMA.into(),
        activation_id: Sha256Digest::of_bytes(rand::random::<[u8; 32]>()),
        profile_generation: generation,
        sequence: committed.sequence,
        content: committed.content,
        evaluation_input: descriptor,
        evaluation_sha256: Sha256Digest::of_bytes(bytes),
        evaluation,
        deployment_inputs: committed.deployment.inputs().to_vec(),
        inputs,
        outputs: committed.outputs,
        image,
        quote_status: super::QUOTE_STATUS_UNQUOTED.into(),
        quote: String::new(),
    })
}

/// Describes a signed release whose tag and catalog the verifier authenticated.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiedRelease {
    /// Carries the independently verified name-bound tag and signer identity.
    pub receipt: ReleaseTrustReceipt,
    /// Carries exact NAR identities recovered from the authenticated store graph.
    pub roots: BTreeMap<String, InputEvidence>,
}

/// Describes source roots authenticated independently under a domain proof.
///
/// The verifier's caller checks the domain authority and recovers this exact NAR
/// map from that authority. A proof pin by itself does not authorize any root.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSourceAuthorization {
    /// Pins the original independently verified domain proof.
    pub authority: crate::native_deployment::SourceAuthorization,
    /// Maps authorized roots to their exact NAR identities and direct references.
    pub roots: BTreeMap<String, InputEvidence>,
}

/// Replays the exact immutable native evaluation and validates retained results.
///
/// Original input authority must be checked independently before this function.
///
/// # Errors
/// Returns an error for changed descriptor bytes/NARs, failed pure evaluation,
/// unknown or malformed retained results, or an incomplete result set.
pub fn rederive(record: &GenerationEvidence) -> Result<String> {
    let descriptor = EvaluationInput::read(&record.evaluation_input)?;
    ensure!(
        descriptor == record.evaluation,
        "attested descriptor roles changed"
    );
    ensure!(
        Sha256Digest::of_bytes(crate::native_deployment::read_regular_document(
            &record.evaluation_input
        )?) == record.evaluation_sha256,
        "attested descriptor bytes changed"
    );
    let executable = PathBuf::from(
        std::env::var_os("AOS_NIX_STORE")
            .context("native attestation replay requires its packaged Nix store")?,
    );
    for evidence in record.inputs.values() {
        crate::store::verification::verify_store_object_in(
            &evidence.store_path,
            evidence.nar_hash,
            evidence.nar_size,
            &evidence.references,
            Some(&executable),
        )?;
    }
    let declarations = crate::native_deployment::retained_declarations(
        &descriptor.package_envelopes,
        descriptor.os_release.as_ref(),
        &executable,
    )?;
    let evaluation = crate::deployment::evaluation::Evaluation {
        os_release: descriptor.os_release.clone(),
        os_requirements: declarations.os_requirements,
        package_releases: declarations.package_releases,
        module_requirements: descriptor
            .resolution_lock
            .as_ref()
            .map_or_else(Vec::new, |lock| lock.module_requirements()),
        nix_store: executable.clone(),
        library: descriptor.library,
        scope: descriptor.scope,
        packages: descriptor.packages,
        configuration: descriptor
            .configuration
            .into_iter()
            .chain(descriptor.runtime_configuration)
            .collect(),
        retained_inputs: record.deployment_inputs.iter().map(PathBuf::from).collect(),
        evaluation_input: Some(record.evaluation_input.clone()),
    };
    let staging = tempfile::tempdir()?;
    let deployment = evaluation.evaluate(
        staging.path(),
        90_000,
        &aos_ability_runtime::adapter::CancellationToken::default(),
    )?;
    let graph = deployment.graph().graph();
    ensure!(
        record.outputs.len() == graph.nodes.len(),
        "native quote omitted checked runtime results"
    );
    for (key, result) in &record.outputs {
        graph
            .nodes
            .get(key)
            .context("native quote contains an unknown effect result")?
            .check_results(result)?;
    }
    deployment.id()
}

/// Supplies independent boot pins and source authorities for native verification.
pub struct VerifierPolicy {
    /// Pins the selected authenticated image and its physical expectations.
    pub image: MeasuredImageEvidence,
    /// Pins Secure Boot state PCR 7.
    pub expected_pcr7: String,
    /// Pins the verifier-authorized boot-input state PCR 12.
    pub expected_pcr12: String,
    /// Pins the generic module library admitted by the image/runtime authority.
    pub library_nar_hash: Sha256Digest,
    /// Supplies the validated PCR 15 value preceding the replayed CEL prefix.
    pub pcr15_baseline: Option<String>,
    /// Supplies the ordered validated CEL prefix preceding this record.
    pub prior_pcr15_event_digests: Vec<String>,
    /// Names active registry tag signers in the authenticated roster.
    pub roster_fingerprints: Vec<String>,
    /// Names revoked roster signers, which always override active membership.
    pub revoked_roster_fingerprints: Vec<String>,
    /// Supplies independently authenticated signed release catalogs.
    pub releases: Vec<VerifiedRelease>,
    /// Supplies original image receipt identities and their authenticated roots.
    pub image_roots: Vec<(ImageAdmission, BTreeMap<String, InputEvidence>)>,
    /// Explicitly accepts local root as authority for operator module snapshots.
    pub allow_local_root_runtime_modules: bool,
    /// Supplies independently authenticated domain proof pins; quote claims cannot supply these.
    pub source_authorities: Vec<VerifiedSourceAuthorization>,
}

fn same_nar(left: &InputEvidence, right: &InputEvidence) -> bool {
    left.store_path == right.store_path
        && left.nar_hash == right.nar_hash
        && left.nar_size == right.nar_size
        && left.references == right.references
}

/// Verifies the native record's TPM, image, signer, source, and re-derivation bindings.
///
/// `rederive` must authenticate the exact descriptor bytes/NAR and its sources,
/// replay the native evaluation, validate the checked runtime result contracts,
/// and return the resulting deployment content ID. It must not take trust
/// anchors from the record being verified.
///
/// # Errors
/// Returns an error for missing physical pins, invalid TPM evidence or CEL
/// replay, source identity or signer mismatches, disallowed operator authority,
/// or a native re-derivation that differs from the committed deployment.
pub fn verify(
    record: &GenerationEvidence,
    checker: &dyn super::QuoteChecker,
    policy: &VerifierPolicy,
    nonce: &[u8],
    rederive: &dyn Fn(&GenerationEvidence) -> Result<String>,
) -> Result<()> {
    ensure!(
        record.schema == GENERATION_SCHEMA
            && record.sequence > 0
            && record.quote_status == super::QUOTE_STATUS_QUOTED
            && !record.quote.is_empty(),
        "native generation has no valid quoted identity"
    );
    ensure!(
        record.image == policy.image,
        "native quote names another authenticated image"
    );
    let expected_pcr11 = policy
        .image
        .expected_pcr11
        .context("authenticated image has no PCR 11 expectation")?;
    let expected_root = policy
        .image
        .root_verity_roothash
        .as_ref()
        .context("authenticated image has no root verity expectation")?;
    ensure!(
        super::is_verity_roothash(expected_root),
        "invalid authenticated root verity hash"
    );
    let quote = hex::decode(&record.quote)?;
    let pcrs = checker.check(&quote, nonce)?;
    ensure!(
        super::ct_eq(&pcrs.pcr7, super::strip_sha256(&policy.expected_pcr7)),
        "Secure Boot PCR 7 binding failed"
    );
    ensure!(
        super::ct_eq(&pcrs.pcr11, &expected_pcr11.hex()),
        "published PCR 11 binding failed"
    );
    ensure!(
        super::ct_eq(&pcrs.pcr12, super::strip_sha256(&policy.expected_pcr12)),
        "authorized PCR 12 binding failed"
    );
    let digest = record_hash(record)?;
    let expected_pcr15 = super::expected_app_pcr_after(
        policy.pcr15_baseline.as_deref(),
        &policy.prior_pcr15_event_digests,
        digest.as_bytes(),
    )?;
    ensure!(
        super::ct_eq(&pcrs.pcr15, &expected_pcr15),
        "native record PCR 15 binding failed"
    );
    ensure!(
        record.evaluation.library_nar_hash == policy.library_nar_hash,
        "native library differs from its authorized identity"
    );
    let (descriptor_root, _) =
        crate::deployment::nix::store_root_and_suffix(&record.evaluation_input)?;
    let (library_root, _) =
        crate::deployment::nix::store_root_and_suffix(&record.evaluation.library)?;
    let runtime_roots = record
        .evaluation
        .runtime_configuration
        .iter()
        .map(|source| crate::deployment::nix::store_root_and_suffix(source).map(|(root, _)| root))
        .collect::<Result<Vec<_>>>()?;
    for (root, evidence) in &record.inputs {
        let (canonical, suffix) = crate::deployment::nix::store_root_and_suffix(Path::new(root))?;
        ensure!(
            canonical == Path::new(root) && suffix.as_os_str().is_empty(),
            "native input is not a canonical store root"
        );
        ensure!(
            root == &evidence.store_path && evidence.nar_size > 0,
            "native input identity is malformed"
        );
        let mut references = evidence.references.clone();
        references.sort();
        references.dedup();
        ensure!(
            references == evidence.references,
            "native input references are not canonical"
        );
        let registry_trusted = evidence.release.as_ref().is_some_and(|release| {
            release.schema == "aos.registry-release-trust/v1"
                && policy.roster_fingerprints.contains(&release.tag_signer_key)
                && !policy
                    .revoked_roster_fingerprints
                    .contains(&release.tag_signer_key)
                && policy.releases.iter().any(|verified| {
                    &verified.receipt == release
                        && verified
                            .roots
                            .get(root)
                            .is_some_and(|expected| same_nar(expected, evidence))
                })
        });
        let image_trusted = evidence.image.as_ref().is_some_and(|receipt| {
            policy.image_roots.iter().any(|(expected_receipt, roots)| {
                expected_receipt == receipt
                    && roots
                        .get(root)
                        .is_some_and(|expected| same_nar(expected, evidence))
            })
        });
        let receipt_trusted = trusted_receipt_root(root, evidence, policy)?;
        let generated_descriptor = evidence.release.is_none()
            && evidence.image.is_none()
            && Path::new(root) == descriptor_root;
        let pinned_library =
            Path::new(root) == library_root && evidence.nar_hash == policy.library_nar_hash;
        let source_trusted = if let Some(authority) = &evidence.source_authority {
            ensure!(
                policy.source_authorities.iter().any(|verified| {
                    &verified.authority == authority
                        && verified
                            .roots
                            .get(root)
                            .is_some_and(|expected| same_nar(expected, evidence))
                }),
                "native source authority is unpinned or unknown"
            );
            authority.verify_integrity()?;
            let (proof_root, _) = crate::deployment::nix::store_root_and_suffix(&authority.proof)?;
            ensure!(
                record
                    .deployment_inputs
                    .iter()
                    .any(|input| Path::new(input) == proof_root),
                "native source omitted its original authority proof"
            );
            true
        } else {
            false
        };
        let authorized_operator = policy.allow_local_root_runtime_modules
            && evidence.release.is_none()
            && evidence.image.is_none()
            && runtime_roots
                .iter()
                .any(|expected| Path::new(root) == expected);
        ensure!(
            registry_trusted
                || image_trusted
                || receipt_trusted
                || generated_descriptor
                || pinned_library
                || authorized_operator
                || source_trusted,
            "native input lacks independent authority: {root}"
        );
    }
    for source in std::iter::once(&record.evaluation.library)
        .chain(&record.evaluation.configuration)
        .chain(&record.evaluation.runtime_configuration)
        .chain(&record.evaluation.supplemental_inputs)
        .chain(record.evaluation.module_envelopes.values())
    {
        let (root, _) = crate::deployment::nix::store_root_and_suffix(source)?;
        ensure!(
            record
                .inputs
                .contains_key(root.to_str().context("source root is not UTF-8")?),
            "native source omitted its original admission"
        );
    }
    ensure!(
        record.inputs.contains_key(
            descriptor_root
                .to_str()
                .context("descriptor root is not UTF-8")?
        ),
        "native descriptor omitted its NAR identity"
    );
    ensure!(
        rederive(record)? == record.content,
        "native source re-derivation differs from committed content"
    );
    Ok(())
}

// A catalog cannot contain its own NAR identity. Its sole document is instead
// authenticated by the verifier's original image digest; live NAR replay still
// checks the evidence for this root before evaluating the retained sources.
fn trusted_receipt_root(
    root: &str,
    evidence: &InputEvidence,
    policy: &VerifierPolicy,
) -> Result<bool> {
    let Some(receipt) = evidence.image.as_ref() else {
        return Ok(false);
    };
    if !policy
        .image_roots
        .iter()
        .any(|(expected, _)| expected == receipt)
    {
        return Ok(false);
    }
    let (receipt_root, suffix) = crate::deployment::nix::store_root_and_suffix(&receipt.path)?;
    if receipt_root != Path::new(root) {
        return Ok(false);
    }
    ensure!(
        suffix.as_os_str().is_empty(),
        "authenticated receipt must be a regular store-root file"
    );
    let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
    let bytes = crate::native_deployment::read_regular_store_document_in(
        &receipt.path,
        &executable,
        &aos_ability_runtime::adapter::CancellationToken::default(),
    )?;
    crate::native_deployment::AdmissionCatalog::decode(&bytes, receipt.digest)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CheckedQuote(super::super::QuotedPcrs);

    impl super::super::QuoteChecker for CheckedQuote {
        fn check(&self, _quote: &[u8], _nonce: &[u8]) -> Result<super::super::QuotedPcrs> {
            Ok(self.0.clone())
        }
    }

    fn fixture() -> (GenerationEvidence, VerifierPolicy, CheckedQuote) {
        let library = format!("/nix/store/{}-library", "a".repeat(32));
        let descriptor = format!("/nix/store/{}-evaluation.json", "b".repeat(32));
        let baseline = format!("/nix/store/{}-baseline", "c".repeat(32));
        let image = MeasuredImageEvidence {
            toplevel: format!("/nix/store/{}-image", "d".repeat(32)),
            boot_artifact_contract: "signed-uki-contract".into(),
            expected_pcr11: Some(Sha256Digest::of_bytes(b"signed image measurement")),
            root_verity_roothash: Some("e".repeat(64)),
            root_verity_uuid: None,
        };
        let receipt = ImageAdmission {
            path: PathBuf::from(format!("/nix/store/{}-receipt.json", "f".repeat(32))),
            digest: Sha256Digest::of_bytes(b"authenticated image receipt"),
        };
        let library_hash = Sha256Digest::of_bytes(b"library NAR");
        let evidence = |path: &str, hash, image| InputEvidence {
            store_path: path.into(),
            nar_hash: hash,
            nar_size: 128,
            references: Vec::new(),
            release: None,
            image,
            source_authority: None,
        };
        let baseline_evidence = evidence(
            &baseline,
            Sha256Digest::of_bytes(b"baseline NAR"),
            Some(receipt.clone()),
        );
        let inputs = BTreeMap::from([
            (library.clone(), evidence(&library, library_hash, None)),
            (
                descriptor.clone(),
                evidence(&descriptor, Sha256Digest::of_bytes(b"descriptor NAR"), None),
            ),
            (baseline.clone(), baseline_evidence.clone()),
        ]);
        let record = GenerationEvidence {
            schema: GENERATION_SCHEMA.into(),
            activation_id: Sha256Digest::of_bytes(b"activation"),
            profile_generation: 3,
            sequence: 2,
            content: "committed-content".into(),
            evaluation_input: PathBuf::from(&descriptor),
            evaluation_sha256: Sha256Digest::of_bytes(b"descriptor bytes"),
            evaluation: EvaluationInput {
                os_release: None,
                package_envelopes: Default::default(),
                schema: "aos.package.evaluation-input".into(),
                library: PathBuf::from(format!("{library}/default.nix")),
                library_nar_hash: library_hash,
                scope: vec!["profile".into(), "system".into()],
                packages: crate::deployment::model::ResolvedPackages {
                    system: "x86_64-linux".into(),
                    artifacts: Vec::new(),
                    modules: Vec::new(),
                },
                configuration: vec![PathBuf::from(format!("{baseline}/host.nix"))],
                module_envelopes: Default::default(),
                resolution_lock: None,
                runtime_configuration: Vec::new(),
                supplemental_inputs: Vec::new(),
            },
            deployment_inputs: vec![library, descriptor, baseline.clone()],
            inputs,
            outputs: BTreeMap::new(),
            image: image.clone(),
            quote_status: super::super::QUOTE_STATUS_QUOTED.into(),
            quote: "ab".into(),
        };
        let digest = record_hash(&record).unwrap();
        let checker = CheckedQuote(super::super::QuotedPcrs {
            pcr7: "1".repeat(64),
            pcr11: image.expected_pcr11.unwrap().hex(),
            pcr12: "2".repeat(64),
            pcr15: super::super::expected_app_pcr_after(None, &[], digest.as_bytes()).unwrap(),
        });
        let policy = VerifierPolicy {
            image,
            expected_pcr7: "1".repeat(64),
            expected_pcr12: "2".repeat(64),
            library_nar_hash: library_hash,
            pcr15_baseline: None,
            prior_pcr15_event_digests: Vec::new(),
            roster_fingerprints: Vec::new(),
            revoked_roster_fingerprints: Vec::new(),
            releases: Vec::new(),
            image_roots: vec![(receipt, BTreeMap::from([(baseline, baseline_evidence)]))],
            allow_local_root_runtime_modules: false,
            source_authorities: Vec::new(),
        };
        (record, policy, checker)
    }

    #[test]
    fn domain_proof_pin_cannot_authorize_foreign_roots_or_changed_nars() {
        let (mut record, mut policy, _) = fixture();
        let baseline = record.evaluation.configuration[0]
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let authority = crate::native_deployment::SourceAuthorization {
            kind: "aos.boot.authenticated-source".into(),
            proof: PathBuf::from(format!("/nix/store/{}-proof.json", "g".repeat(32))),
            digest: Sha256Digest::of_bytes(b"independently checked proof"),
        };
        record.inputs.get_mut(&baseline).unwrap().source_authority = Some(authority.clone());
        let digest = record_hash(&record).unwrap();
        let checker = CheckedQuote(super::super::QuotedPcrs {
            pcr7: policy.expected_pcr7.clone(),
            pcr11: policy.image.expected_pcr11.unwrap().hex(),
            pcr12: policy.expected_pcr12.clone(),
            pcr15: super::super::expected_app_pcr_after(None, &[], digest.as_bytes()).unwrap(),
        });
        // Existing image/operator trust cannot bypass explicit source-authority checks.
        policy.allow_local_root_runtime_modules = true;
        let rejected = |policy: &VerifierPolicy| {
            let error = verify(&record, &checker, policy, b"nonce", &|record| {
                Ok(record.content.clone())
            })
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("source authority is unpinned or unknown"),
                "{error:#}"
            );
        };
        rejected(&policy);

        policy.source_authorities.push(VerifiedSourceAuthorization {
            authority,
            roots: BTreeMap::from([("foreign-root".into(), record.inputs[&baseline].clone())]),
        });
        rejected(&policy);

        let mut expected = record.inputs[&baseline].clone();
        expected.nar_hash = Sha256Digest::of_bytes(b"another NAR");
        policy.source_authorities[0].roots = BTreeMap::from([(baseline.clone(), expected)]);
        rejected(&policy);

        let mut expected = record.inputs[&baseline].clone();
        expected.references.push("foreign-reference".into());
        policy.source_authorities[0].roots = BTreeMap::from([(baseline, expected)]);
        rejected(&policy);
    }

    #[test]
    fn receipt_root_exception_requires_original_pin_and_exact_root_file() {
        let (_, mut policy, _) = fixture();
        let receipt = policy.image_roots[0].0.clone();
        let (root, _) = crate::deployment::nix::store_root_and_suffix(&receipt.path).unwrap();
        let root = root.to_str().unwrap();
        let mut evidence = InputEvidence {
            store_path: root.into(),
            nar_hash: Sha256Digest::of_bytes(b"receipt NAR"),
            nar_size: 128,
            references: Vec::new(),
            release: None,
            image: Some(receipt.clone()),
            source_authority: None,
        };

        policy.image_roots.clear();
        assert!(!trusted_receipt_root(root, &evidence, &policy).unwrap());

        let invalid = ImageAdmission {
            path: Path::new(root).join("other.json"),
            ..receipt
        };
        evidence.image = Some(invalid.clone());
        policy.image_roots.push((invalid, BTreeMap::new()));
        assert!(trusted_receipt_root(root, &evidence, &policy).is_err());
    }

    #[test]
    fn native_quote_requires_original_image_authority_and_source_replay() {
        let (record, mut policy, checker) = fixture();
        verify(&record, &checker, &policy, b"nonce", &|record| {
            Ok(record.content.clone())
        })
        .unwrap();
        assert!(
            verify(&record, &checker, &policy, b"nonce", &|_| Ok(
                "different-content".into()
            ))
            .is_err()
        );

        policy.image_roots.clear();
        assert!(
            verify(&record, &checker, &policy, b"nonce", &|record| Ok(record
                .content
                .clone()))
            .is_err()
        );
    }

    #[test]
    fn native_quote_rejects_changed_physical_pins_and_pcr_binding() {
        let (record, mut policy, mut checker) = fixture();
        checker.0.pcr15 = "0".repeat(64);
        assert!(
            verify(&record, &checker, &policy, b"nonce", &|record| Ok(record
                .content
                .clone()))
            .is_err()
        );

        policy.image.root_verity_roothash = None;
        assert!(
            verify(&record, &checker, &policy, b"nonce", &|record| Ok(record
                .content
                .clone()))
            .is_err()
        );
    }

    #[test]
    fn native_quote_rejects_revoked_release_signer_even_with_matching_catalog() {
        let (mut record, mut policy, _) = fixture();
        let baseline = record.evaluation.configuration[0]
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let release = ReleaseTrustReceipt {
            schema: "aos.registry-release-trust/v1".into(),
            registry: "test".into(),
            release_tag: "1.0.0".into(),
            commit: "a".repeat(40),
            tag_signer_key: "signer".into(),
        };
        let evidence = record.inputs.get_mut(&baseline).unwrap();
        evidence.image = None;
        evidence.release = Some(release.clone());
        policy.image_roots.clear();
        policy.roster_fingerprints.push("signer".into());
        policy.releases.push(VerifiedRelease {
            receipt: release,
            roots: BTreeMap::from([(baseline, evidence.clone())]),
        });
        let digest = record_hash(&record).unwrap();
        let checker = CheckedQuote(super::super::QuotedPcrs {
            pcr7: policy.expected_pcr7.clone(),
            pcr11: policy.image.expected_pcr11.unwrap().hex(),
            pcr12: policy.expected_pcr12.clone(),
            pcr15: super::super::expected_app_pcr_after(None, &[], digest.as_bytes()).unwrap(),
        });
        verify(&record, &checker, &policy, b"nonce", &|record| {
            Ok(record.content.clone())
        })
        .unwrap();

        policy.revoked_roster_fingerprints.push("signer".into());
        assert!(
            verify(&record, &checker, &policy, b"nonce", &|record| Ok(record
                .content
                .clone()))
            .is_err()
        );
    }
}
