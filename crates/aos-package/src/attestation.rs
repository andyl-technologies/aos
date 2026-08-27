//! The `aos.gen-attestation/v1` generation-attestation record.
//!
//! The locally-computed config manifest needs **no signature**: it is
//! `f(inputs)` under `--pure-eval`, so reproducibility from policy-authorized,
//! content-bound inputs is strictly stronger than a signature on the output.
//! What a remote verifier still cannot see
//! from a bare PCR-11 quote is *which* config-module inputs and `host.nix` the
//! evaluator consumed. This record closes that gap: it binds the five
//! content-addressed eval inputs (base lib, evaluator, config modules,
//! `host.nix`, instance facts) plus the F1 dm-verity roothash into a TPM2 quote
//! over PCR 7, 11, and the application PCR 15, turning attestation into full
//! re-derivation.
//!
//! # On-disk format
//!
//! Serialized to **canonical JSON** (the same canonicalization as the manifest
//! hash; see [`crate::graph_compile::reproject::hash_cjson`]) and persisted
//! alongside `gen-N/manifest.json`. Each successful activation, including a
//! same-generation rollback, receives a fresh random `activation_id`; crash
//! recovery retains that identity only while completing the same transaction.
//!
//! ```text
//! aos.gen-attestation/v1
//!   schema          : "aos.gen-attestation/v1"
//!   activation_id   : "sha256:<64 lowercase hex>"
//!   generation_id   : "<hex>"
//!   manifest_hash   : "sha256:<hex>"
//!   inputs:
//!     base_lib:        { pcr11_expected, abi_hash, module_abi,
//!                        root_verity_roothash, root_verity_uuid? }
//!     evaluator:       { store_path, store_hash }
//!     config_modules:  { registry, release_tag, tag_signer_key, realization,
//!                        closure_hash, store_paths, nar_hashes, package_names,
//!                        provenance }
//!     host_nix:        { content_hash, store_path, trust_mode,
//!                        platform?, signer_key? }
//!     instance_facts:  { facts_hash, store_path, platform }
//!   eval_mode       : "pure-eval"
//!   quote_status    : "quoted" | "unquoted-tpm-unavailable"
//!   quote           : "<hex of the embedded TPM quote evidence>"
//! ```
//!
//! # Quoting (build-spec §1.4)
//!
//! The record is bound to the TPM by extending its hash into application PCR 15,
//! then quoting PCR {7, 11, 12, 15}:
//!
//! 1. canonicalize the record **without** `quote` -> `record_bytes`;
//! 2. `record_hash = sha256(record_bytes)`;
//! 3. `TPM2_PCR_Extend(15, record_hash)`;
//! 4. `quote = TPM2_Quote(PCR{7,11,12,15}, nonce)`.
//!
//! The seal mechanism is unchanged: `/var` stays sealed to PCR 7 + 11; PCR 15
//! carries only attestation evidence, never the seal. The TPM operations are
//! isolated behind [`TpmQuoter`] / [`QuoteChecker`] so the record logic is
//! unit-testable off-host with a mock TPM.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config_eval::{PackageAuthorization, materialize::ConfigManifest};
use crate::graph_compile::reproject::hash_cjson;
use crate::types::{ImageGeneration, ModuleAbiCompat};

/// Schema discriminator for the generation-attestation record.
pub const GEN_ATTESTATION_SCHEMA: &str = "aos.gen-attestation/v1";

/// Literal `eval_mode`, asserting the determinism precondition (build-spec §1.3).
pub const EVAL_MODE_PURE: &str = "pure-eval";

/// The application PCR the record hash is extended into (build-spec §1.4).
pub const APP_PCR_INDEX: u8 = 15;

/// A record whose complete TPM and immutable-image binding is unavailable.
///
/// The historical wire literal is retained for v1 compatibility. It also
/// covers an available TPM on an image without authenticated dm-verity state.
pub const QUOTE_STATUS_UNQUOTED: &str = "unquoted-tpm-unavailable";

/// A record whose hash was extended into PCR 15 and covered by a TPM quote.
pub const QUOTE_STATUS_QUOTED: &str = "quoted";

const GEN_ATTESTATION_TRANSACTION_SCHEMA: &str = "aos.gen-attestation-transaction/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenAttestationTransaction {
    schema: String,
    activation_id: String,
    generation_id: String,
    manifest_hash: String,
    record_hash: String,
}

/// The `aos.gen-attestation/v1` evidence bundle (build-spec §1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenAttestation {
    /// Always [`GEN_ATTESTATION_SCHEMA`]; rejected otherwise.
    pub schema: String,
    /// Unique identity of this activation attempt, including rollback
    /// reactivations of an otherwise unchanged generation.
    #[serde(default)]
    pub activation_id: String,
    /// Content hash APM assigned the materialized config-generation directory.
    /// Read from the generation record, not recomputed.
    pub generation_id: String,
    /// `sha256:<hex>` of the canonicalized manifest (build-spec §1.3).
    pub manifest_hash: String,
    /// The five content-addressed eval inputs.
    pub inputs: AttestationInputs,
    /// Literal [`EVAL_MODE_PURE`].
    pub eval_mode: String,
    /// Whether `quote` contains TPM evidence or why this record was retained
    /// without a hardware binding.
    pub quote_status: String,
    /// Hex of the TPM2 quote blob over PCR {7, 11, 12, 15} + this record's hash.
    /// Empty in a freshly-built, not-yet-quoted record.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub quote: String,
}

/// The five content-addressed inputs that fully determine the generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationInputs {
    /// Base-lib + evaluator measured-boot binding (incl. F1 roothash).
    pub base_lib: BaseLibAttInput,
    /// The eval binary that produced the manifest.
    pub evaluator: EvaluatorAttInput,
    /// The signed-tag-blessed config-module set consumed.
    pub config_modules: ConfigModulesAttInput,
    /// The policy-authorized `host.nix`.
    pub host_nix: HostNixAttInput,
    /// Separately authorized runtime operator module set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_modules: Option<RuntimeModulesAttInput>,
    /// The platform-supplied instance facts (recorded, not signed).
    pub instance_facts: InstanceFactsAttInput,
}

/// Runtime module set identity recorded independently from platform host trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeModulesAttInput {
    /// Descriptor schema covered by this identity.
    pub schema: String,
    /// Recursive source root.
    pub store_path: String,
    /// NAR hash of the complete source root.
    pub nar_hash: String,
    /// Ordered direct entrypoints.
    pub entrypoints: Vec<String>,
    /// `local-root` or `signed`.
    pub trust_mode: String,
    /// Trusted signer fingerprint in signed mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<String>,
}

/// Base-lib measured-boot binding plus the F1 dm-verity roothash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseLibAttInput {
    /// Exact base-library store path consumed by evaluation.
    pub store_path: String,
    /// `sha256:<hex>` predicted ready-phase PCR-11 of the booted UKI
    /// (ties to measured boot). Read from the registry catalog's recorded
    /// `expected_pcr11`, not recomputed (build-spec §1.3).
    pub pcr11_expected: Option<String>,
    /// `sha256:<hex>` over the base-lib module API schema concatenated with
    /// `module_abi`.
    pub abi_hash: String,
    /// `AOS_MODULE_ABI` parsed from the running image's `/etc/os-release`.
    pub module_abi: u32,
    /// F1: Merkle root of the erofs root, read from `/proc/cmdline`'s
    /// `roothash=<hex>` token (which sd-stub measured into PCR 11). Validated
    /// `^[0-9a-f]{64}$`.
    pub root_verity_roothash: Option<String>,
    /// F1 (optional): the verity superblock UUID from `veritysetup status root`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_verity_uuid: Option<String>,
}

/// The eval binary consumed by `aos-eval.service`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorAttInput {
    /// Resolved store path of the `aos-eval` binary; recorded for re-derivation.
    pub store_path: String,
    /// Authenticated identity of the evaluator store path.
    pub store_hash: String,
}

/// The measured-image and/or signed-release config-module set consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigModulesAttInput {
    /// Registry whose signed release selected the registry-origin subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Semver release tag whose verified tag chain authenticates the set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_tag: Option<String>,
    /// Fingerprint of the roster key that signed `release_tag`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_signer_key: Option<String>,
    /// `sha256:<hex>` identity of the consumed signed `store/` subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realization: Option<String>,
    /// Set hash over every authenticated module path and NAR hash.
    pub closure_hash: String,
    /// Number of authenticated config-only outputs.
    pub count: usize,
    /// Exact evaluator order of config-only output store paths.
    pub store_paths: Vec<String>,
    /// Authenticated NAR hashes corresponding to `store_paths`.
    pub nar_hashes: Vec<String>,
    /// Authenticated package identities corresponding to `store_paths`.
    pub package_names: Vec<String>,
    /// Authenticated origins, ABI bands, and root-write grants retained from
    /// the manifest so a verifier can reconstruct the complete eval input.
    pub provenance: Value,
}

/// The policy-authorized `host.nix` provenance (mirrors the manifest's
/// `inputs.host_nix`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostNixAttInput {
    /// `sha256:<hex>` of the exact `host.nix` bytes fed to the evaluator.
    pub content_hash: String,
    /// Content-addressed store copy of the exact host module.
    pub store_path: String,
    /// Image-selected authorization policy: `platform`, `signed`, or the
    /// narrowly-defined `image` fallback for the image-authored empty module.
    pub trust_mode: String,
    /// Detected control-plane identity in platform mode, or literal `image`
    /// for the image-authored empty-module fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Trusted configuration-key fingerprint in signed mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<String>,
}

/// Platform-supplied instance facts (the second host-varying input).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceFactsAttInput {
    /// `sha256:<hex>` of the canonical `host.facts.*` tree.
    pub facts_hash: String,
    /// Content-addressed store copy of the exact normalized fact document.
    pub store_path: String,
    /// The IMDS platform tag (`aws`, `gcp`, …). Recorded, not signed.
    pub platform: String,
}

// ---------------------------------------------------------------------------
// TPM seams (mockable)
// ---------------------------------------------------------------------------

/// Produces a TPM2 quote binding a record hash to PCR {7, 11, 12, 15}.
///
/// The production implementation extends `record_hash` into PCR 15 and runs
/// `tpm2_quote` (reusing the
/// [`crate::package_attestation`] machinery); tests inject a deterministic
/// mock so the record/compute logic is exercised off-host.
pub trait TpmQuoter {
    /// Extend PCR 15 with `record_hash`, then quote PCR {7, 11, 12, 15} with
    /// `nonce`. Returns the opaque quote blob.
    ///
    /// # Errors
    ///
    /// Returns an error when the TPM cannot be driven (no device, tool failure).
    fn quote(&self, record_hash: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The PCR values a verifier recovered from a checked quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotedPcrs {
    /// SB-state PCR 7, lowercase hex.
    pub pcr7: String,
    /// Measured-boot PCR 11, lowercase hex.
    pub pcr11: String,
    /// Boot-input PCR 12, lowercase hex.
    pub pcr12: String,
    /// Application PCR 15 (record binding), lowercase hex.
    pub pcr15: String,
}

/// Verifies a quote signature under an attestation key and recovers its PCRs.
///
/// The production implementation checks the TPM2B_ATTEST + signature under the
/// AK public key over `(PCR{7,11,12,15}, nonce)`; tests inject a mock that returns
/// scripted PCRs (or an error to model a bad signature).
pub trait QuoteChecker {
    /// Verify `quote` over `nonce` and return the quoted PCR values.
    ///
    /// # Errors
    ///
    /// Returns an error when the quote signature is invalid under the verifier's
    /// pinned AK, the nonce does not match, or the blob cannot be parsed.
    fn check(&self, quote: &[u8], nonce: &[u8]) -> anyhow::Result<QuotedPcrs>;
}

// ---------------------------------------------------------------------------
// Compute
// ---------------------------------------------------------------------------

/// Canonicalize a record **without** its `quote` field and return the
/// `sha256(record_bytes)` digest bytes (build-spec §1.4 steps 1-2).
///
/// The `quote` field is cleared before canonicalization so the digest is the
/// pre-quote record identity — the value extended into PCR 15.
///
/// # Errors
///
/// Returns an error if canonical serialization or digest decoding fails.
pub fn record_hash(record: &GenAttestation) -> Result<[u8; 32]> {
    let mut bare = record.clone();
    bare.quote = String::new();
    // `hash_cjson` is the single canonicalization used everywhere (build-spec
    // §0): it returns "sha256:<hex>" over the canonical JSON bytes. The quoter
    // extends the 32 raw digest bytes into PCR 15, so decode the hex back to
    // bytes here rather than re-canonicalizing independently.
    let value = serde_json::to_value(&bare).context("serializing generation attestation")?;
    let digest_hex = hash_cjson(&value);
    let hex_part = digest_hex
        .strip_prefix("sha256:")
        .context("canonical generation attestation hash has no sha256 prefix")?;
    let bytes = hex::decode(hex_part).context("decoding generation attestation hash")?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "generation attestation hash decoded to {} bytes, expected 32",
            bytes.len()
        )
    })
}

/// Returns the canonical bytes measured into PCR 15, excluding the quote.
///
/// # Errors
///
/// Returns an error if the record cannot be serialized as JSON.
pub(crate) fn bare_record_bytes(record: &GenAttestation) -> Result<Vec<u8>> {
    let mut bare = record.clone();
    bare.quote = String::new();
    let value = serde_json::to_value(&bare).context("serializing generation attestation")?;
    Ok(crate::graph_compile::reproject::canonical_json(&value).into_bytes())
}

/// Compute the canonical-JSON hash of the full record (incl. `quote`), the
/// `"sha256:<hex>"` content-address used to reference an emitted record.
///
/// # Errors
///
/// Returns an error if the record cannot be serialized to JSON.
pub fn attestation_content_hash(record: &GenAttestation) -> anyhow::Result<String> {
    let value = serde_json::to_value(record)?;
    Ok(hash_cjson(&value))
}

/// Build and quote a [`GenAttestation`] from its inputs (build-spec §1.4).
///
/// Assembles the record with an empty `quote`, computes [`record_hash`], drives
/// `quoter` to extend PCR 15 and quote PCR {7, 11, 15} with `nonce`, then stores
/// the hex-encoded quote blob. The host input must carry complete authorization
/// evidence for its named policy.
///
/// # Errors
///
/// Returns an error when host-input authorization evidence is incomplete, when
/// `base_lib.root_verity_roothash` is not 64 lowercase hex digits, or when the
/// `quoter` fails to produce a quote.
pub fn compute_gen_attestation(
    generation_id: impl Into<String>,
    manifest_hash: impl Into<String>,
    inputs: AttestationInputs,
    quoter: &dyn TpmQuoter,
    nonce: &[u8],
) -> anyhow::Result<GenAttestation> {
    validate_host_evidence(&inputs.host_nix)?;
    if !inputs
        .base_lib
        .root_verity_roothash
        .as_deref()
        .is_some_and(is_verity_roothash)
        || inputs.base_lib.pcr11_expected.is_none()
    {
        bail!(
            "base_lib.root_verity_roothash must be 64 lowercase hex digits, got '{}'",
            inputs
                .base_lib
                .root_verity_roothash
                .as_deref()
                .unwrap_or("<missing>")
        );
    }

    let mut record = build_unquoted_gen_attestation(
        generation_id.into(),
        manifest_hash.into(),
        new_activation_id(),
        inputs,
    )?;
    record.quote_status = QUOTE_STATUS_QUOTED.to_string();

    let digest = record_hash(&record)?;
    let quote = quoter.quote(&digest, nonce)?;
    record.quote = hex::encode(quote);
    Ok(record)
}

/// Builds an explicit TPM-less generation record without fabricating a quote.
///
/// # Errors
///
/// Returns an error when host authorization evidence is incomplete.
pub fn compute_unquoted_gen_attestation(
    generation_id: impl Into<String>,
    manifest_hash: impl Into<String>,
    inputs: AttestationInputs,
) -> Result<GenAttestation> {
    build_unquoted_gen_attestation(
        generation_id.into(),
        manifest_hash.into(),
        new_activation_id(),
        inputs,
    )
}

fn build_unquoted_gen_attestation(
    generation_id: String,
    manifest_hash: String,
    activation_id: String,
    inputs: AttestationInputs,
) -> Result<GenAttestation> {
    validate_host_evidence(&inputs.host_nix)?;
    Ok(GenAttestation {
        schema: GEN_ATTESTATION_SCHEMA.to_string(),
        activation_id,
        generation_id,
        manifest_hash,
        inputs,
        eval_mode: EVAL_MODE_PURE.to_string(),
        quote_status: QUOTE_STATUS_UNQUOTED.to_string(),
        quote: String::new(),
    })
}

fn generation_quote_status(
    quote_required: bool,
    has_tpm: bool,
    has_root_verity: bool,
) -> Result<Option<&'static str>> {
    if !has_tpm {
        if quote_required {
            bail!("measured boot requires a TPM-backed generation attestation quote");
        }
        return Ok(Some(QUOTE_STATUS_UNQUOTED));
    }
    if !has_root_verity {
        if quote_required {
            bail!("TPM-backed generation attestation requires image root verity metadata");
        }
        return Ok(Some(QUOTE_STATUS_UNQUOTED));
    }
    Ok(None)
}

fn new_activation_id() -> String {
    format!("sha256:{}", hex::encode(rand::random::<[u8; 32]>()))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddedQuote {
    schema: String,
    nonce: String,
    pcr_selection: String,
    quoted_pcr15: String,
    ak_public: String,
    quote_message: String,
    quote_signature: String,
    quote_pcrs: String,
}

/// Produces and durably persists the attestation for one committed generation.
///
/// The record is derived only from the validated manifest and authenticated
/// running-image index. With a TPM, its canonical bare bytes are appended to
/// the AOS CEL, extended into PCR 15, and quoted with PCR 7/11/12/15 using the
/// existing package-attestation machinery. Without a TPM, or when the running
/// image has no immutable root measurement to bind, an explicit unquoted
/// record is retained unless `require_quote` makes hardware evidence mandatory.
/// `detect_tpm` is kept explicit so hermetic tests do not inherit ambient host
/// devices; the production activation path always enables detection.
///
/// # Errors
///
/// Returns an error if the input binding is incomplete, an existing record
/// disagrees, durable publication fails, or mandatory measurement/quote
/// production fails.
pub(crate) fn persist_generation_attestation(
    generation_dir: &Path,
    generation_id: &str,
    manifest_hash: &str,
    manifest: &ConfigManifest,
    running_image: &ImageGeneration,
    require_quote: bool,
    detect_tpm: bool,
) -> Result<GenAttestation> {
    let record_path = generation_dir.join("gen-attestation.json");
    let transaction_path = generation_dir.join(".gen-attestation-transaction.json");
    let mut inputs = inputs_from_manifest(manifest, running_image)?;
    let retained_transaction = read_attestation_transaction(&transaction_path)?;
    let activation_id = retained_transaction
        .as_ref()
        .map(|transaction| transaction.activation_id.clone())
        .unwrap_or_else(new_activation_id);

    let quote_required = require_quote || image_requires_generation_quote(running_image);
    let has_tpm = detect_tpm && crate::package_attestation::tpm_available()?;
    let quote_dir = generation_dir.join("gen-attestation-quote");
    let stage = generation_dir.join(".gen-attestation-quote.pending");
    if let Some(quote_status) = generation_quote_status(
        quote_required,
        has_tpm,
        running_image.root_verity_roothash.is_some(),
    )? {
        if retained_transaction.is_some() {
            bail!(
                "cannot recover the retained TPM-backed generation attestation transaction without quote-capable running-image state"
            );
        }
        let mut record = build_unquoted_gen_attestation(
            generation_id.to_string(),
            manifest_hash.to_string(),
            activation_id,
            inputs,
        )?;
        record.quote_status = quote_status.to_string();
        // All validation is complete before replacing evidence from the prior
        // activation. In particular, a corrupt retained transaction must never
        // delete an otherwise usable quote bundle.
        remove_private_quote_dir_if_exists(&stage)?;
        remove_private_quote_dir_if_exists(&quote_dir)?;
        write_record_atomic(&record_path, &record)?;
        remove_file_durable_if_exists(&transaction_path)?;
        return Ok(record);
    }

    // `aos-eval.service` hard-requires systemd-pcrphase.service on measured
    // images, so this is the stable ready-phase value. A catalog-published
    // value is immutable policy and must match; it is never replaced by a
    // self-reported live reading. Directly booted seed images have no external
    // catalog record yet, so they bind the record to the ready value and rely
    // on remote policy to supply the independent image expectation.
    let live_pcr11 = crate::package_attestation::current_pcr11()?;
    inputs.base_lib.pcr11_expected = Some(ready_pcr11_value(
        running_image.expected_pcr11.as_deref(),
        &live_pcr11,
    )?);
    let mut record = build_unquoted_gen_attestation(
        generation_id.to_string(),
        manifest_hash.to_string(),
        activation_id.clone(),
        inputs,
    )?;
    record.quote_status = QUOTE_STATUS_QUOTED.to_string();
    let digest = record_hash(&record)?;
    let canonical = bare_record_bytes(&record)?;
    let transaction = GenAttestationTransaction {
        schema: GEN_ATTESTATION_TRANSACTION_SCHEMA.to_string(),
        activation_id: activation_id.clone(),
        generation_id: generation_id.to_string(),
        manifest_hash: manifest_hash.to_string(),
        record_hash: format!("sha256:{}", hex::encode(digest)),
    };
    prepare_attestation_transaction(
        &transaction_path,
        retained_transaction.as_ref(),
        &transaction,
    )?;
    // Validate the retained transaction before mutating the prior activation's
    // published quote evidence.
    remove_private_quote_dir_if_exists(&stage)?;
    remove_private_quote_dir_if_exists(&quote_dir)?;
    if !crate::package_attestation::measure_generation_attestation(
        Path::new("/"),
        generation_id,
        &activation_id,
        &canonical,
    )? {
        bail!("TPM disappeared before generation attestation measurement");
    }

    let nonce = hex::encode(digest);
    let artifacts = crate::package_attestation::produce_package_quote(&nonce, &stage)?;
    let embedded = EmbeddedQuote {
        schema: "aos.gen-attestation-quote/v1".to_string(),
        nonce,
        pcr_selection: artifacts.pcr_selection.to_string(),
        quoted_pcr15: artifacts.quoted_pcr15,
        ak_public: read_hex(&stage.join("ak.pub"))?,
        quote_message: read_hex(&stage.join("quote.msg"))?,
        quote_signature: read_hex(&stage.join("quote.sig"))?,
        quote_pcrs: read_hex(&stage.join("quote.pcrs"))?,
    };
    record.quote = hex::encode(serde_json::to_vec(&embedded)?);
    std::fs::rename(&stage, &quote_dir)
        .with_context(|| format!("publishing {}", quote_dir.display()))?;
    write_record_atomic(&record_path, &record)?;
    remove_file_durable_if_exists(&transaction_path)?;
    Ok(record)
}

/// Returns whether authenticated running-image metadata requires quoted
/// generation evidence.
///
/// An expected PCR 11 exists only for images published with measured boot. A
/// seed image can instead carry the initrd's observed PCR value, but that is a
/// measured-image policy signal only when authenticated dm-verity metadata
/// binds the immutable root. This distinction lets an otherwise unmeasured
/// machine expose a TPM without making ordinary host activation unbootable.
pub(crate) fn image_requires_generation_quote(image: &ImageGeneration) -> bool {
    image.expected_pcr11.is_some()
        || (image.initrd_pcr11.is_some() && image.root_verity_roothash.is_some())
}

fn read_attestation_transaction(path: &Path) -> Result<Option<GenAttestationTransaction>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let transaction: GenAttestationTransaction = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display()))?;
            if transaction.schema != GEN_ATTESTATION_TRANSACTION_SCHEMA
                || !is_sha256_identity(&transaction.activation_id)
            {
                bail!("invalid retained generation-attestation transaction identity");
            }
            Ok(Some(transaction))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn prepare_attestation_transaction(
    path: &Path,
    retained: Option<&GenAttestationTransaction>,
    expected: &GenAttestationTransaction,
) -> Result<()> {
    if let Some(retained) = retained {
        if *retained != *expected {
            bail!("retained generation-attestation transaction disagrees with activation inputs");
        }
        return Ok(());
    }
    write_canonical_json_atomic(path, expected)
}

fn remove_private_quote_dir_if_exists(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "generation attestation quote path is not a private directory: {}",
            path.display()
        );
    }
    std::fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))
}

fn remove_file_durable_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("removing {}", path.display())),
    }
    let parent = path
        .parent()
        .with_context(|| format!("path has no parent: {}", path.display()))?;
    File::open(parent)
        .with_context(|| format!("opening {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", parent.display()))
}

fn inputs_from_manifest(
    manifest: &ConfigManifest,
    image: &ImageGeneration,
) -> Result<AttestationInputs> {
    let config = &manifest.inputs.config_modules;
    let has_registry_modules =
        config.origins.is_empty() || config.origins.iter().any(|origin| origin == "registry");
    if config.count > 0
        && has_registry_modules
        && (config.registry.is_none()
            || config.release_tag.is_none()
            || config.tag_signer_key.is_none()
            || config.realization.is_none())
    {
        bail!("cannot attest config modules without signed-release provenance");
    }
    let mut provenance = serde_json::json!({
        "module_abi_compat": config.module_abi_compat,
        "authorizations": config.authorizations,
    });
    if !config.origins.is_empty() {
        provenance["origins"] = serde_json::json!(config.origins);
    }
    let host = &manifest.inputs.host_nix;
    let (platform, signer_key) = match host.trust_mode.as_str() {
        "platform" => (Some(host.platform.clone()), None),
        "signed" => (None, host.signer_key.clone()),
        "image" if host.platform == "image" && host.signer_key.is_none() => {
            (Some(host.platform.clone()), None)
        }
        mode => bail!("cannot attest unsupported host.nix trust mode {mode:?}"),
    };
    Ok(AttestationInputs {
        base_lib: BaseLibAttInput {
            store_path: manifest.inputs.base_lib.store_path.clone(),
            pcr11_expected: image.expected_pcr11.clone(),
            abi_hash: manifest.inputs.base_lib.abi_hash.clone(),
            module_abi: manifest.inputs.base_lib.module_abi,
            root_verity_roothash: image.root_verity_roothash.clone(),
            root_verity_uuid: None,
        },
        evaluator: EvaluatorAttInput {
            store_path: manifest.inputs.evaluator.store_path.clone(),
            store_hash: manifest.inputs.evaluator.store_hash.clone(),
        },
        config_modules: ConfigModulesAttInput {
            registry: config.registry.clone(),
            release_tag: config.release_tag.clone(),
            tag_signer_key: config.tag_signer_key.clone(),
            realization: config.realization.clone(),
            closure_hash: config.closure_hash.clone(),
            count: config.count,
            store_paths: config.store_paths.clone(),
            nar_hashes: config.nar_hashes.clone(),
            package_names: config.package_names.clone(),
            provenance,
        },
        host_nix: HostNixAttInput {
            content_hash: host.content_hash.clone(),
            store_path: host.store_path.clone(),
            trust_mode: host.trust_mode.clone(),
            platform,
            signer_key,
        },
        runtime_modules: manifest.inputs.runtime_modules.as_ref().map(|runtime| {
            RuntimeModulesAttInput {
                schema: runtime.schema.clone(),
                store_path: runtime.store_path.clone(),
                nar_hash: runtime.nar_hash.clone(),
                entrypoints: runtime.entrypoints.clone(),
                trust_mode: runtime.trust_mode.clone(),
                signer_key: runtime.signer_key.clone(),
            }
        }),
        instance_facts: InstanceFactsAttInput {
            facts_hash: manifest.inputs.instance_facts.facts_hash.clone(),
            store_path: manifest.inputs.instance_facts.store_path.clone(),
            platform: manifest.inputs.instance_facts.platform.clone(),
        },
    })
}

fn read_hex(path: &Path) -> Result<String> {
    std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))
        .map(hex::encode)
}

fn write_record_atomic(path: &Path, record: &GenAttestation) -> Result<()> {
    write_canonical_json_atomic(path, record)
}

fn write_canonical_json_atomic<T: Serialize>(path: &Path, record: &T) -> Result<()> {
    let value = serde_json::to_value(record).context("serializing generation attestation")?;
    let bytes = crate::graph_compile::reproject::canonical_json(&value);
    let parent = path
        .parent()
        .context("generation attestation path has no parent")?;
    let temporary = parent.join(format!(".gen-attestation.json.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    file.write_all(bytes.as_bytes())
        .with_context(|| format!("writing {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("publishing {}", path.display()))?;
    File::open(parent)
        .with_context(|| format!("opening {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", parent.display()))
}

fn validate_host_evidence(host: &HostNixAttInput) -> Result<()> {
    match host.trust_mode.as_str() {
        "platform" if host.platform.is_some() && host.signer_key.is_none() => Ok(()),
        "signed" if host.signer_key.is_some() && host.platform.is_none() => Ok(()),
        "image" if host.platform.as_deref() == Some("image") && host.signer_key.is_none() => Ok(()),
        mode => bail!("host.nix authorization evidence is incomplete for trust mode '{mode}'"),
    }
}

/// Whether `s` is a 64-character lowercase-hex string (a dm-verity roothash).
pub fn is_verity_roothash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// Verify (build-spec §1.5)
// ---------------------------------------------------------------------------

/// The data a verifier checks a record against: the registry catalog's pinned
/// PCRs, the trusted operator/roster key sets, and the published image's root
/// roothash (build-spec §1.5).
#[derive(Debug, Clone)]
pub struct VerifierPolicy {
    /// Catalog `expected_pcr7` (SB-state pin), lowercase hex.
    pub expected_pcr7: String,
    /// Catalog `expected_pcr11` for the booted UKI, `sha256:<hex>`.
    pub expected_pcr11: String,
    /// Authorized PCR 12 boot-input state, lowercase hex.
    pub expected_pcr12: String,
    /// The published image's `root.roothash` (UKI `.cmdline` token), 64 hex.
    pub expected_root_roothash: String,
    /// Optional verifier-known canonical instance-facts hash.
    pub expected_facts_hash: Option<String>,
    /// Validated PCR 15 value preceding the first AOS CEL event. When absent,
    /// replay begins at the all-zero reset value.
    pub pcr15_baseline: Option<String>,
    /// Ordered SHA-256 event digests already extended into the shared AOS
    /// application PCR before this generation record. A verifier obtains this
    /// history by validating and replaying the CEL prefix.
    pub prior_pcr15_event_digests: Vec<String>,
    /// Operator config-key fingerprints in `trusted-config-keys.d`.
    pub trusted_config_keys: Vec<String>,
    /// Deployment platform identities accepted as control-plane authorities.
    pub trusted_platforms: Vec<String>,
    /// Whether verifier policy explicitly accepts local root as runtime-module authority.
    pub allow_local_root_runtime_modules: bool,
    /// Registry roster fingerprints that may sign release tags.
    pub roster_fingerprints: Vec<String>,
    /// Registry roster fingerprints explicitly revoked by the authenticated
    /// catalog. A key appearing in both lists is rejected.
    pub revoked_roster_fingerprints: Vec<String>,
    /// Release/tag/module evidence accepted after `verify_tag_chain` and
    /// signed-catalog validation.
    pub valid_release_tags: Vec<VerifiedConfigModuleRelease>,
    /// Config-module members independently recovered from the immutable,
    /// dm-verity-covered image package catalog.
    pub image_config_modules: Vec<VerifiedConfigModuleMember>,
}

/// A config-module member authenticated by one signed registry release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedConfigModuleMember {
    /// Authenticated package identity.
    pub package_name: String,
    /// Exact config-output store path selected for evaluation.
    pub store_path: String,
    /// Canonical NAR hash blessed for `store_path` by the signed graph.
    pub nar_hash: String,
    /// Base-library ABI band authenticated by the signed package catalog.
    pub module_abi_compat: ModuleAbiCompat,
    /// Shared-root write authority authenticated by the signed package catalog.
    pub authorization: PackageAuthorization,
}

/// Verifier-side evidence recovered from a successfully verified release tag.
///
/// Callers populate this only after validating the signed tag chain and the
/// catalog/store graph it targets. Verification below binds the quoted record
/// to this authenticated evidence; a bare tag name is never sufficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedConfigModuleRelease {
    /// Registry name bound into the signing key and authenticated catalog.
    pub registry: String,
    /// Name-bound semver release tag accepted by `verify_tag_chain`.
    pub release_tag: String,
    /// Fingerprints of keys whose signatures validated on the release tag.
    pub signer_fingerprints: Vec<String>,
    /// `sha256:<hex>` identity of the authenticated `store/` subset.
    pub realization: String,
    /// Exact config-module membership authenticated by that release.
    pub config_modules: Vec<VerifiedConfigModuleMember>,
}

/// Why a [`GenAttestation`] failed verification (build-spec §1.5 FAIL points).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenAttestationFailure {
    /// `schema` is not [`GEN_ATTESTATION_SCHEMA`].
    Schema,
    /// The quote signature did not validate under the verifier's AK.
    Quote,
    /// PCR 15 did not equal the validated CEL prefix extended with this record.
    RecordBinding,
    /// PCR 7 did not match the catalog SB-state pin.
    SbState,
    /// PCR 11 did not match `pcr11_expected` and/or the catalog value.
    Pcr11,
    /// PCR 12 did not match the verifier-authorized boot-input state.
    Pcr12,
    /// The F1 root-verity binding did not hold across record/catalog.
    RootVerity,
    /// Recorded instance facts disagree with verifier-known facts.
    Facts,
    /// The release tag is unsigned/revoked, or `tag_signer_key` is off-roster.
    Tag,
    /// Host-input authorization evidence does not satisfy verifier policy.
    HostNixTrust,
    /// Runtime-module authorization evidence does not satisfy verifier policy.
    RuntimeModulesTrust,
    /// Runtime-module identity is malformed or internally inconsistent.
    RuntimeModulesIdentity,
    /// `eval_mode` is not `pure-eval`.
    EvalMode,
    /// Optional re-derivation produced a different `manifest_hash`.
    Rederive,
}

impl std::fmt::Display for GenAttestationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GenAttestationFailure::Schema => "unrecognized attestation schema",
            GenAttestationFailure::Quote => "TPM quote signature invalid under the pinned AK",
            GenAttestationFailure::RecordBinding => {
                "PCR 15 does not bind this record (record-binding check failed)"
            }
            GenAttestationFailure::SbState => "PCR 7 does not match the catalog SB-state pin",
            GenAttestationFailure::Pcr11 => {
                "PCR 11 does not match the expected measured-boot value"
            }
            GenAttestationFailure::Pcr12 => "PCR 12 does not match the authorized boot-input state",
            GenAttestationFailure::RootVerity => "F1 root-verity roothash binding failed",
            GenAttestationFailure::Facts => "instance-facts binding failed",
            GenAttestationFailure::Tag => "release tag is unsigned, revoked, or off-roster",
            GenAttestationFailure::HostNixTrust => "host.nix authorization evidence is untrusted",
            GenAttestationFailure::RuntimeModulesTrust => {
                "runtime module authorization evidence is untrusted"
            }
            GenAttestationFailure::RuntimeModulesIdentity => {
                "runtime module identity is malformed or inconsistent"
            }
            GenAttestationFailure::EvalMode => "eval_mode is not 'pure-eval'",
            GenAttestationFailure::Rederive => "re-derived manifest hash does not match the record",
        };
        f.write_str(s)
    }
}

impl std::error::Error for GenAttestationFailure {}

/// Verify a generation-attestation record (build-spec §1.5 steps 1-9, with the
/// optional step-10 re-derivation supplied by `rederive`).
///
/// `checker` recovers the quoted PCR values (mock or real TPM); `policy` carries
/// the catalog pins and trusted key sets; `nonce` is the challenge the quote was
/// taken over. When `rederive` is `Some`, it is called with the record and must
/// return the re-computed `manifest_hash`; a mismatch is
/// [`GenAttestationFailure::Rederive`]. Pass `None` to stop at step 9.
/// Image-default records are the exception: their authorization proof depends
/// on re-deriving the exact empty-module evaluation, so `None` rejects them.
///
/// # Errors
///
/// Returns the first [`GenAttestationFailure`] encountered, in build-spec order
/// (schema, quote, record-binding, SB-state, PCR 11, root-verity, tag,
/// host-nix-key, eval-mode, rederive). The checks are fail-closed: any error
/// means the box did **not** demonstrably derive its generation only from
/// trusted inputs.
pub fn verify_gen_attestation(
    record: &GenAttestation,
    checker: &dyn QuoteChecker,
    policy: &VerifierPolicy,
    nonce: &[u8],
    rederive: Option<&dyn Fn(&GenAttestation) -> String>,
) -> Result<(), GenAttestationFailure> {
    // 1. schema
    if record.schema != GEN_ATTESTATION_SCHEMA {
        return Err(GenAttestationFailure::Schema);
    }
    if !is_sha256_identity(&record.activation_id)
        || record.quote_status != QUOTE_STATUS_QUOTED
        || record.quote.is_empty()
    {
        return Err(GenAttestationFailure::Schema);
    }

    // 2. quote signature valid -> recover PCRs.
    let quote_bytes = hex::decode(&record.quote).map_err(|_| GenAttestationFailure::Quote)?;
    let pcrs = checker
        .check(&quote_bytes, nonce)
        .map_err(|_| GenAttestationFailure::Quote)?;

    // 3. PCR15 == replay(validated CEL prefix) then extend(record\quote).
    let record_digest = record_hash(record).map_err(|_| GenAttestationFailure::RecordBinding)?;
    let expected_pcr15 = expected_app_pcr_after(
        policy.pcr15_baseline.as_deref(),
        &policy.prior_pcr15_event_digests,
        &record_digest,
    )
    .map_err(|_| GenAttestationFailure::RecordBinding)?;
    if !ct_eq(&pcrs.pcr15, &expected_pcr15) {
        return Err(GenAttestationFailure::RecordBinding);
    }

    // 4. PCR7 == catalog.expected_pcr7
    if !ct_eq(&pcrs.pcr7, &policy.expected_pcr7) {
        return Err(GenAttestationFailure::SbState);
    }

    // 5. PCR11 == record.base_lib.pcr11_expected AND == catalog.expected_pcr11
    let pcr11_expected = record
        .inputs
        .base_lib
        .pcr11_expected
        .as_deref()
        .ok_or(GenAttestationFailure::Pcr11)?;
    let pcr11_hex = strip_sha256(pcr11_expected);
    let catalog_pcr11 = strip_sha256(&policy.expected_pcr11);
    if !ct_eq(&pcrs.pcr11, pcr11_hex) || !ct_eq(pcr11_hex, catalog_pcr11) {
        return Err(GenAttestationFailure::Pcr11);
    }

    // 6. PCR12 == verifier-authorized boot-input state.
    if !ct_eq(&pcrs.pcr12, &policy.expected_pcr12) {
        return Err(GenAttestationFailure::Pcr12);
    }

    // 7. F1 root binding: record roothash == catalog/published roothash.
    if !ct_eq(
        record
            .inputs
            .base_lib
            .root_verity_roothash
            .as_deref()
            .ok_or(GenAttestationFailure::RootVerity)?,
        &policy.expected_root_roothash,
    ) {
        return Err(GenAttestationFailure::RootVerity);
    }
    if policy
        .expected_facts_hash
        .as_ref()
        .is_some_and(|expected| !ct_eq(expected, &record.inputs.instance_facts.facts_hash))
    {
        return Err(GenAttestationFailure::Facts);
    }

    // 7. Bind the quoted module input to one name-bound, signed release tag,
    // an active roster signer, the authenticated store-graph realization,
    // and the release's exact module membership. Merely observing that the
    // vectors have equal lengths is not trust evidence.
    if !config_module_release_is_trusted(&record.inputs.config_modules, policy) {
        return Err(GenAttestationFailure::Tag);
    }

    // 8. Host-input evidence satisfies the named image policy.
    let host = &record.inputs.host_nix;
    let host_trusted = match host.trust_mode.as_str() {
        "platform" => {
            host.signer_key.is_none()
                && host
                    .platform
                    .as_ref()
                    .is_some_and(|platform| policy.trusted_platforms.contains(platform))
        }
        "signed" => {
            host.platform.is_none()
                && host
                    .signer_key
                    .as_ref()
                    .is_some_and(|key| policy.trusted_config_keys.contains(key))
        }
        // `image` is not operator input. The evaluator admits this arm only
        // for its exact image-authored empty module, while steps 4-6 bind that
        // evaluator and immutable base library to the verified boot. A remote
        // verifier still re-runs evaluation in step 10 before accepting the
        // resulting manifest.
        "image" => host.platform.as_deref() == Some("image") && host.signer_key.is_none(),
        _ => false,
    };
    if !host_trusted {
        return Err(GenAttestationFailure::HostNixTrust);
    }
    if let Some(runtime) = &record.inputs.runtime_modules {
        let identity = crate::config_eval::materialize::RuntimeModulesInput {
            schema: runtime.schema.clone(),
            trust_mode: runtime.trust_mode.clone(),
            store_path: runtime.store_path.clone(),
            nar_hash: runtime.nar_hash.clone(),
            entrypoints: runtime.entrypoints.clone(),
            signer_key: runtime.signer_key.clone(),
        };
        if identity.validate().is_err() {
            return Err(GenAttestationFailure::RuntimeModulesIdentity);
        }

        let trusted = match runtime.trust_mode.as_str() {
            "local-root" => runtime.signer_key.is_none() && policy.allow_local_root_runtime_modules,
            "signed" => runtime
                .signer_key
                .as_ref()
                .is_some_and(|key| policy.trusted_config_keys.contains(key)),
            _ => false,
        };
        if !trusted {
            return Err(GenAttestationFailure::RuntimeModulesTrust);
        }
    }

    // 9. eval_mode == "pure-eval".
    if record.eval_mode != EVAL_MODE_PURE {
        return Err(GenAttestationFailure::EvalMode);
    }

    // 10. Full re-derivation is mandatory for the image-default arm: that is
    // what demonstrates the measured evaluator admitted only its exact empty
    // module rather than operator-controlled bytes. Other trust modes retain
    // the API's optional step-10 behavior.
    if host.trust_mode == "image" && rederive.is_none() {
        return Err(GenAttestationFailure::Rederive);
    }
    if let Some(rederive) = rederive {
        if rederive(record) != record.manifest_hash {
            return Err(GenAttestationFailure::Rederive);
        }
    }

    Ok(())
}

fn config_module_release_is_trusted(
    modules: &ConfigModulesAttInput,
    policy: &VerifierPolicy,
) -> bool {
    let Some((abi_compat, authorizations, mut origins)) = provenance_entries(&modules.provenance)
    else {
        return false;
    };
    if modules.count == 0 {
        return modules.registry.is_none()
            && modules.release_tag.is_none()
            && modules.tag_signer_key.is_none()
            && modules.realization.is_none()
            && modules.store_paths.is_empty()
            && modules.nar_hashes.is_empty()
            && modules.package_names.is_empty()
            && abi_compat.is_empty()
            && authorizations.is_empty()
            && origins.is_empty()
            && ct_eq(
                &modules.closure_hash,
                &hash_cjson(&Value::Array(Vec::new())),
            );
    }
    let count = modules.count;
    if count != modules.store_paths.len()
        || count != modules.nar_hashes.len()
        || count != modules.package_names.len()
        || count != abi_compat.len()
        || count != authorizations.len()
    {
        return false;
    }
    if origins.is_empty() {
        origins = vec!["registry".to_string(); count];
    }
    if origins.len() != count
        || origins
            .iter()
            .any(|origin| origin != "registry" && origin != "image")
    {
        return false;
    }

    let mut quoted_members = BTreeSet::new();
    let mut closure_members = Vec::with_capacity(count);
    for ((path, nar_hash), package_name) in modules
        .store_paths
        .iter()
        .zip(&modules.nar_hashes)
        .zip(&modules.package_names)
    {
        if !is_canonical_store_path(path)
            || crate::types::validate_package_name(package_name).is_err()
            || crate::registry::store::NarBytes::from_hash(nar_hash, 0)
                .map(|nar| nar.nar_hash() != *nar_hash)
                .unwrap_or(true)
            || !quoted_members.insert((package_name, path, nar_hash))
        {
            return false;
        }
        closure_members.push(serde_json::json!([path, nar_hash]));
    }
    closure_members.sort_by(|left, right| {
        left[0]
            .as_str()
            .unwrap_or_default()
            .cmp(right[0].as_str().unwrap_or_default())
    });
    let expected_closure = hash_cjson(&Value::Array(closure_members));
    if !ct_eq(&modules.closure_hash, &expected_closure) {
        return false;
    }

    let registry_indexes = origins
        .iter()
        .enumerate()
        .filter_map(|(index, origin)| (origin == "registry").then_some(index))
        .collect::<Vec<_>>();
    let image_indexes = origins
        .iter()
        .enumerate()
        .filter_map(|(index, origin)| (origin == "image").then_some(index))
        .collect::<Vec<_>>();
    let mut image_catalog = BTreeMap::new();
    for member in &policy.image_config_modules {
        if !is_canonical_store_path(&member.store_path)
            || crate::types::validate_package_name(&member.package_name).is_err()
            || crate::registry::store::NarBytes::from_hash(&member.nar_hash, 0)
                .map(|nar| nar.nar_hash() != member.nar_hash)
                .unwrap_or(true)
            || image_catalog
                .insert(
                    (&member.package_name, &member.store_path, &member.nar_hash),
                    member,
                )
                .is_some()
        {
            return false;
        }
    }
    if !image_indexes.into_iter().all(|index| {
        let key = (
            &modules.package_names[index],
            &modules.store_paths[index],
            &modules.nar_hashes[index],
        );
        image_catalog.get(&key).is_some_and(|member| {
            member.module_abi_compat == abi_compat[index]
                && member.authorization == authorizations[index]
        })
    }) {
        return false;
    }
    if registry_indexes.is_empty() {
        return modules.registry.is_none()
            && modules.release_tag.is_none()
            && modules.tag_signer_key.is_none()
            && modules.realization.is_none();
    }

    let (Some(registry), Some(release_tag), Some(signer), Some(realization)) = (
        modules.registry.as_deref(),
        modules.release_tag.as_deref(),
        modules.tag_signer_key.as_deref(),
        modules.realization.as_deref(),
    ) else {
        return false;
    };
    if crate::types::validate_registry_name(registry).is_err()
        || semver::Version::parse(release_tag).is_err()
        || !is_short_fingerprint(signer)
        || !is_sha256_identity(realization)
        || !policy
            .roster_fingerprints
            .iter()
            .any(|fingerprint| is_short_fingerprint(fingerprint) && fingerprint == signer)
        || policy
            .revoked_roster_fingerprints
            .iter()
            .any(|fingerprint| fingerprint.eq_ignore_ascii_case(signer))
    {
        return false;
    }
    let matching_releases = policy
        .valid_release_tags
        .iter()
        .filter(|release| release.registry == registry && release.release_tag == release_tag)
        .collect::<Vec<_>>();
    let [release] = matching_releases.as_slice() else {
        return false;
    };
    let catalog_signers = release
        .signer_fingerprints
        .iter()
        .filter(|fingerprint| is_short_fingerprint(fingerprint))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if catalog_signers.len() != release.signer_fingerprints.len()
        || !catalog_signers.contains(signer)
        || !ct_eq(&release.realization, realization)
        || !is_sha256_identity(&release.realization)
        || release.config_modules.len() != registry_indexes.len()
    {
        return false;
    }

    let mut catalog_members = BTreeMap::new();
    for member in &release.config_modules {
        if !is_canonical_store_path(&member.store_path)
            || crate::types::validate_package_name(&member.package_name).is_err()
            || crate::registry::store::NarBytes::from_hash(&member.nar_hash, 0)
                .map(|nar| nar.nar_hash() != member.nar_hash)
                .unwrap_or(true)
            || catalog_members
                .insert(
                    (&member.package_name, &member.store_path, &member.nar_hash),
                    member,
                )
                .is_some()
        {
            return false;
        }
    }

    registry_indexes.into_iter().all(|index| {
        let key = (
            &modules.package_names[index],
            &modules.store_paths[index],
            &modules.nar_hashes[index],
        );
        catalog_members.get(&key).is_some_and(|member| {
            member.module_abi_compat == abi_compat[index]
                && member.authorization == authorizations[index]
        })
    })
}

fn provenance_entries(
    provenance: &Value,
) -> Option<(Vec<ModuleAbiCompat>, Vec<PackageAuthorization>, Vec<String>)> {
    let Some(object) = provenance.as_object() else {
        return None;
    };
    if object.len() < 2 || object.len() > 3 {
        return None;
    }
    let compat = serde_json::from_value(object.get("module_abi_compat")?.clone()).ok()?;
    let authorization = serde_json::from_value(object.get("authorizations")?.clone()).ok()?;
    let origins = object
        .get("origins")
        .map(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_else(|| Some(Vec::new()))?;
    Some((compat, authorization, origins))
}

fn is_short_fingerprint(value: &str) -> bool {
    value.len() == 8
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256_identity(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_store_path(value: &str) -> bool {
    let Some(name) = value.strip_prefix("/nix/store/") else {
        return false;
    };
    if name.contains('/') {
        return false;
    }
    let Some((hash, suffix)) = name.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && !suffix.is_empty()
        && hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
}

/// Returns the PCR value after replaying `prior` and extending `digest`.
fn expected_app_pcr_after(
    baseline: Option<&str>,
    prior: &[String],
    digest: &[u8; 32],
) -> Result<String> {
    let mut pcr = match baseline {
        Some(value) => hex::decode(strip_sha256(value))
            .with_context(|| format!("decoding PCR 15 baseline {value:?}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("PCR 15 baseline is not SHA-256"))?,
        None => [0_u8; 32],
    };
    for event in prior {
        let decoded = hex::decode(strip_sha256(event))
            .with_context(|| format!("decoding prior PCR 15 event digest {event:?}"))?;
        let event: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("prior PCR 15 event digest is not SHA-256"))?;
        pcr = extend_app_pcr(&pcr, &event);
    }
    Ok(hex::encode(extend_app_pcr(&pcr, digest)))
}

fn extend_app_pcr(pcr: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(*pcr);
    hasher.update(digest);
    hasher.finalize().into()
}

/// `extend(0, digest)` convenience used by the isolated mock TPM.
#[cfg(test)]
fn expected_app_pcr(digest: &[u8; 32]) -> String {
    hex::encode(extend_app_pcr(&[0_u8; 32], digest))
}

/// Strip an optional `sha256:`/`sha256-` prefix, returning the bare hex.
fn strip_sha256(s: &str) -> &str {
    s.strip_prefix("sha256:")
        .or_else(|| s.strip_prefix("sha256-"))
        .unwrap_or(s)
}

/// Binds a generation record to the independently published ready-phase PCR
/// value, or to the live canonical value when booting an uncataloged seed.
fn ready_pcr11_value(expected: Option<&str>, live: &str) -> Result<String> {
    if let Some(expected) = expected {
        if !ct_eq(strip_sha256(expected), strip_sha256(live)) {
            bail!(
                "live ready-phase PCR 11 does not match the published image expectation (expected {}, live {})",
                strip_sha256(expected),
                strip_sha256(live)
            );
        }
    }
    Ok(expected.unwrap_or(live).to_string())
}

/// Constant-time-ish case-insensitive hex equality. Compares lengths first, then
/// bytes; used for PCR/digest comparison so a mismatch is total, not prefix.
fn ct_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock TPM that "extends" PCR 15 itself and returns a structured quote
    /// the matching [`MockChecker`] decodes — exercising the full
    /// compute->verify round trip with no real TPM.
    struct MockTpm {
        pcr7: String,
        pcr11: String,
    }

    impl TpmQuoter for MockTpm {
        fn quote(&self, record_hash: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>> {
            // The mock quote is just the three PCR values + nonce, JSON-encoded.
            let pcr15 = expected_app_pcr(&to_array(record_hash));
            let blob = serde_json::json!({
                "pcr7": self.pcr7,
                "pcr11": self.pcr11,
                "pcr12": PCR12_HEX,
                "pcr15": pcr15,
                "nonce": hex::encode(nonce),
            });
            Ok(serde_json::to_vec(&blob)?)
        }
    }

    /// The verifier-side counterpart: decodes the mock quote and checks the
    /// nonce, returning the embedded PCRs.
    struct MockChecker;

    impl QuoteChecker for MockChecker {
        fn check(&self, quote: &[u8], nonce: &[u8]) -> anyhow::Result<QuotedPcrs> {
            let v: serde_json::Value = serde_json::from_slice(quote)?;
            let got_nonce = v["nonce"].as_str().unwrap_or_default();
            if got_nonce != hex::encode(nonce) {
                anyhow::bail!("nonce mismatch");
            }
            Ok(QuotedPcrs {
                pcr7: v["pcr7"].as_str().unwrap_or_default().to_string(),
                pcr11: v["pcr11"].as_str().unwrap_or_default().to_string(),
                pcr12: v["pcr12"].as_str().unwrap_or_default().to_string(),
                pcr15: v["pcr15"].as_str().unwrap_or_default().to_string(),
            })
        }
    }

    struct HistoryChecker {
        pcr15: String,
    }

    impl QuoteChecker for HistoryChecker {
        fn check(&self, quote: &[u8], nonce: &[u8]) -> anyhow::Result<QuotedPcrs> {
            let mut quoted = MockChecker.check(quote, nonce)?;
            quoted.pcr15 = self.pcr15.clone();
            Ok(quoted)
        }
    }

    fn to_array(b: &[u8]) -> [u8; 32] {
        let mut a = [0_u8; 32];
        a.copy_from_slice(b);
        a
    }

    const ROOTHASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const PCR11_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const PCR12_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const PCR7_HEX: &str = "7777777777777777777777777777777777777777777777777777777777777777";

    #[test]
    fn ready_pcr11_seed_value_keeps_one_hash_prefix() {
        let live = format!("sha256:{PCR11_HEX}");
        assert_eq!(ready_pcr11_value(None, &live).unwrap(), live);
    }

    #[test]
    fn ready_pcr11_accepts_equivalent_prefixed_and_bare_values() {
        let live = format!("sha256:{PCR11_HEX}");
        assert_eq!(
            ready_pcr11_value(Some(PCR11_HEX), &live).unwrap(),
            PCR11_HEX
        );
        let error = ready_pcr11_value(Some(&format!("sha256:{}", "aa".repeat(32))), &live)
            .unwrap_err()
            .to_string();
        assert!(error.contains(&"aa".repeat(32)), "{error}");
        assert!(error.contains(PCR11_HEX), "{error}");
    }

    fn sample_inputs() -> AttestationInputs {
        let module_path = "/nix/store/cccccccccccccccccccccccccccccccc-web-config".to_string();
        let module_nar_hash =
            crate::registry::store::NarBytes::from_hash(&format!("sha256:{}", "dd".repeat(32)), 0)
                .unwrap()
                .nar_hash();
        let closure_hash = hash_cjson(&serde_json::json!([[&module_path, &module_nar_hash]]));
        AttestationInputs {
            base_lib: BaseLibAttInput {
                store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-base-lib".to_string(),
                pcr11_expected: Some(format!("sha256:{PCR11_HEX}")),
                abi_hash: "sha256:aa".to_string(),
                module_abi: 1,
                root_verity_roothash: Some(ROOTHASH.to_string()),
                root_verity_uuid: Some("11111111-2222-3333-4444-555555555555".to_string()),
            },
            evaluator: EvaluatorAttInput {
                store_path: "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-aos-eval-1".to_string(),
                store_hash: "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh".to_string(),
            },
            config_modules: ConfigModulesAttInput {
                registry: Some("aos-core".to_string()),
                release_tag: Some("1.4.0".to_string()),
                tag_signer_key: Some("deadbeef".to_string()),
                realization: Some(format!("sha256:{}", "aa".repeat(32))),
                closure_hash,
                count: 1,
                store_paths: vec![module_path],
                nar_hashes: vec![module_nar_hash],
                package_names: vec!["web".to_string()],
                provenance: serde_json::json!({"module_abi_compat":[{"min":1,"max":1}],"authorizations":[{"owns":[],"contributes":{}}]}),
            },
            host_nix: HostNixAttInput {
                content_hash: "sha256:dd".to_string(),
                store_path: "/nix/store/dddddddddddddddddddddddddddddddd-host-nix".to_string(),
                trust_mode: "signed".to_string(),
                platform: None,
                signer_key: Some("0badf00d".to_string()),
            },
            runtime_modules: None,
            instance_facts: InstanceFactsAttInput {
                facts_hash: "sha256:ee".to_string(),
                store_path: "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-facts".to_string(),
                platform: "aws".to_string(),
            },
        }
    }

    fn sample_policy() -> VerifierPolicy {
        VerifierPolicy {
            expected_pcr7: PCR7_HEX.to_string(),
            expected_pcr11: format!("sha256:{PCR11_HEX}"),
            expected_pcr12: PCR12_HEX.to_string(),
            expected_root_roothash: ROOTHASH.to_string(),
            expected_facts_hash: None,
            pcr15_baseline: None,
            prior_pcr15_event_digests: Vec::new(),
            trusted_config_keys: vec!["0badf00d".to_string()],
            trusted_platforms: vec!["aws".to_string()],
            allow_local_root_runtime_modules: false,
            roster_fingerprints: vec!["deadbeef".to_string()],
            revoked_roster_fingerprints: Vec::new(),
            valid_release_tags: vec![VerifiedConfigModuleRelease {
                registry: "aos-core".to_string(),
                release_tag: "1.4.0".to_string(),
                signer_fingerprints: vec!["deadbeef".to_string()],
                realization: format!("sha256:{}", "aa".repeat(32)),
                config_modules: vec![VerifiedConfigModuleMember {
                    package_name: "web".to_string(),
                    store_path: "/nix/store/cccccccccccccccccccccccccccccccc-web-config"
                        .to_string(),
                    nar_hash: crate::registry::store::NarBytes::from_hash(
                        &format!("sha256:{}", "dd".repeat(32)),
                        0,
                    )
                    .unwrap()
                    .nar_hash(),
                    module_abi_compat: ModuleAbiCompat { min: 1, max: 1 },
                    authorization: PackageAuthorization::default(),
                }],
            }],
            image_config_modules: Vec::new(),
        }
    }

    fn computed() -> GenAttestation {
        computed_with_inputs(sample_inputs())
    }

    fn computed_with_inputs(inputs: AttestationInputs) -> GenAttestation {
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        compute_gen_attestation("gen-7-cafe", "sha256:abc", inputs, &tpm, b"nonce-xyz")
            .expect("compute")
    }

    #[test]
    fn round_trips_through_canonical_json() {
        let record = computed();
        let json = serde_json::to_string(&record).unwrap();
        let back: GenAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
        assert_eq!(record.schema, GEN_ATTESTATION_SCHEMA);
        assert!(!record.quote.is_empty());
    }

    #[test]
    fn repeated_same_generation_attestations_have_activation_bound_identity() {
        let first = computed();
        let mut newer_image_inputs = first.inputs.clone();
        // Module ABI and every config input remain identical; only the
        // authenticated running-image measurements change.
        newer_image_inputs.base_lib.pcr11_expected = Some(format!("sha256:{}", "ab".repeat(32)));
        newer_image_inputs.base_lib.root_verity_roothash = Some("cd".repeat(32));
        let second = computed_with_inputs(newer_image_inputs);
        assert_eq!(first.generation_id, second.generation_id);
        assert_ne!(first.activation_id, second.activation_id);
        assert_ne!(record_hash(&first).unwrap(), record_hash(&second).unwrap());
    }

    #[test]
    fn authenticated_measured_image_metadata_requires_generation_quotes() {
        let mut image = ImageGeneration {
            number: 1,
            slot: crate::types::ImageSlot::A,
            uki_path: "EFI/Linux/aos.efi".to_string(),
            uki_source_path: None,
            toplevel: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos".to_string(),
            package_name: "aos".to_string(),
            version: "1".to_string(),
            registry: "aos-core".to_string(),
            kernel_path: None,
            evaluator_ref: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-base-lib".to_string(),
            module_abi: 1,
            baselib_digest: format!("sha256:{}", "11".repeat(32)),
            root_verity_roothash: Some("22".repeat(32)),
            expected_pcr11: None,
            initrd_pcr11: None,
            recovery: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        assert!(!image_requires_generation_quote(&image));
        image.initrd_pcr11 = Some(format!("sha256:{}", "44".repeat(32)));
        assert!(image_requires_generation_quote(&image));
        image.root_verity_roothash = None;
        assert!(!image_requires_generation_quote(&image));
        image.initrd_pcr11 = None;
        image.expected_pcr11 = Some(format!("sha256:{}", "33".repeat(32)));
        assert!(image_requires_generation_quote(&image));
    }

    #[test]
    fn quote_status_matches_available_image_binding() {
        let cases = [
            (false, false, false, Some(QUOTE_STATUS_UNQUOTED), None),
            (false, false, true, Some(QUOTE_STATUS_UNQUOTED), None),
            (false, true, false, Some(QUOTE_STATUS_UNQUOTED), None),
            (false, true, true, None, None),
            (true, false, false, None, Some("requires a TPM-backed")),
            (true, false, true, None, Some("requires a TPM-backed")),
            (
                true,
                true,
                false,
                None,
                Some("requires image root verity metadata"),
            ),
            (true, true, true, None, None),
        ];
        for (required, tpm, verity, expected, error_fragment) in cases {
            let result = generation_quote_status(required, tpm, verity);
            match error_fragment {
                Some(fragment) => {
                    let error = result.unwrap_err();
                    assert!(format!("{error}").contains(fragment));
                }
                None => assert_eq!(result.unwrap(), expected),
            }
        }
    }

    #[test]
    fn compute_refuses_incomplete_host_nix_evidence() {
        let mut inputs = sample_inputs();
        inputs.host_nix.signer_key = None;
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        let err = compute_gen_attestation("g", "h", inputs, &tpm, b"n").unwrap_err();
        assert!(format!("{err}").contains("authorization evidence is incomplete"));
    }

    #[test]
    fn compute_rejects_bad_roothash() {
        let mut inputs = sample_inputs();
        inputs.base_lib.root_verity_roothash = Some("tooshort".to_string());
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        assert!(compute_gen_attestation("g", "h", inputs, &tpm, b"n").is_err());
    }

    #[test]
    fn verifies_a_well_formed_record() {
        let record = computed();
        let res =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None);
        assert!(res.is_ok(), "got {res:?}");
    }

    #[test]
    fn local_root_runtime_modules_require_explicit_policy_and_bind_order() {
        let mut inputs = sample_inputs();
        inputs.runtime_modules = Some(RuntimeModulesAttInput {
            schema: "aos.runtime-module-set/v1".to_string(),
            store_path: "/nix/store/99999999999999999999999999999999-runtime-modules".to_string(),
            nar_hash: format!("sha256:{}", "ab".repeat(32)),
            entrypoints: vec!["10-packages.nix".to_string(), "20-services.nix".to_string()],
            trust_mode: "local-root".to_string(),
            signer_key: None,
        });
        let record = computed_with_inputs(inputs);
        let mut policy = sample_policy();
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::RuntimeModulesTrust
        );

        policy.allow_local_root_runtime_modules = true;
        assert!(verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).is_ok());

        let mut reordered = record;
        reordered
            .inputs
            .runtime_modules
            .as_mut()
            .unwrap()
            .entrypoints
            .reverse();
        assert!(
            verify_gen_attestation(&reordered, &MockChecker, &policy, b"nonce-xyz", None).is_err()
        );

        let mut malformed_inputs = sample_inputs();
        malformed_inputs.runtime_modules = Some(RuntimeModulesAttInput {
            schema: "aos.runtime-module-set/v2".to_string(),
            store_path: "/nix/store/99999999999999999999999999999999-runtime-modules".to_string(),
            nar_hash: format!("sha256:{}", "ab".repeat(32)),
            entrypoints: vec!["10-packages.nix".to_string()],
            trust_mode: "local-root".to_string(),
            signer_key: None,
        });
        let malformed = computed_with_inputs(malformed_inputs);
        assert_eq!(
            verify_gen_attestation(&malformed, &MockChecker, &policy, b"nonce-xyz", None)
                .unwrap_err(),
            GenAttestationFailure::RuntimeModulesIdentity
        );
    }

    #[test]
    fn rejects_unexpected_boot_input_pcr() {
        let record = computed();
        let mut policy = sample_policy();
        policy.expected_pcr12 = "12".repeat(32);
        let err =
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::Pcr12);
    }

    #[test]
    fn verifier_accepts_measured_image_config_module_origin() {
        let mut inputs = sample_inputs();
        let modules = &mut inputs.config_modules;
        modules.registry = None;
        modules.release_tag = None;
        modules.tag_signer_key = None;
        modules.realization = None;
        modules.provenance["origins"] = serde_json::json!(["image"]);
        let image_member = VerifiedConfigModuleMember {
            package_name: modules.package_names[0].clone(),
            store_path: modules.store_paths[0].clone(),
            nar_hash: modules.nar_hashes[0].clone(),
            module_abi_compat: serde_json::from_value(
                modules.provenance["module_abi_compat"][0].clone(),
            )
            .unwrap(),
            authorization: serde_json::from_value(modules.provenance["authorizations"][0].clone())
                .unwrap(),
        };
        let record = computed_with_inputs(inputs);
        let mut policy = sample_policy();
        policy.image_config_modules.push(image_member);
        let result = verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None);
        assert!(result.is_ok(), "got {result:?}");
    }

    #[test]
    fn verifier_rejects_uncataloged_image_config_module_origin() {
        let mut inputs = sample_inputs();
        let modules = &mut inputs.config_modules;
        modules.registry = None;
        modules.release_tag = None;
        modules.tag_signer_key = None;
        modules.realization = None;
        modules.provenance["origins"] = serde_json::json!(["image"]);
        let record = computed_with_inputs(inputs);
        let error =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err();
        assert_eq!(error, GenAttestationFailure::Tag);
    }

    #[test]
    fn verifier_rejects_unknown_config_module_origin() {
        let mut inputs = sample_inputs();
        inputs.config_modules.provenance["origins"] = serde_json::json!(["unsigned-local"]);
        let record = computed_with_inputs(inputs);
        let error =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err();
        assert_eq!(error, GenAttestationFailure::Tag);
    }

    #[test]
    fn verifier_rejects_missing_release_identity() {
        let mut inputs = sample_inputs();
        inputs.config_modules.registry = None;
        let record = computed_with_inputs(inputs);
        let error =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err();
        assert_eq!(error, GenAttestationFailure::Tag);
    }

    #[test]
    fn verifier_accepts_only_canonical_empty_config_module_evidence() {
        let mut inputs = sample_inputs();
        inputs.config_modules = ConfigModulesAttInput {
            registry: None,
            release_tag: None,
            tag_signer_key: None,
            realization: None,
            closure_hash: hash_cjson(&Value::Array(Vec::new())),
            count: 0,
            store_paths: Vec::new(),
            nar_hashes: Vec::new(),
            package_names: Vec::new(),
            provenance: serde_json::json!({
                "module_abi_compat": [],
                "authorizations": []
            }),
        };
        let record = computed_with_inputs(inputs.clone());
        let result =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None);
        assert!(result.is_ok(), "got {result:?}");

        inputs.config_modules.registry = Some("aos-core".to_string());
        let record = computed_with_inputs(inputs);
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None,)
                .unwrap_err(),
            GenAttestationFailure::Tag
        );
    }

    #[test]
    fn verifier_rejects_unverified_or_cross_registry_release_tag() {
        let record = computed();
        let mut policy = sample_policy();
        policy.valid_release_tags[0].registry = "mirror".to_string();
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );

        let mut policy = sample_policy();
        policy.valid_release_tags[0].release_tag = "1.4.1".to_string();
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );
    }

    #[test]
    fn verifier_rejects_off_roster_revoked_or_non_signing_key() {
        let record = computed();

        let mut policy = sample_policy();
        policy.roster_fingerprints.clear();
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );

        let mut policy = sample_policy();
        policy
            .revoked_roster_fingerprints
            .push("deadbeef".to_string());
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );

        let mut policy = sample_policy();
        policy.valid_release_tags[0].signer_fingerprints = vec!["cafebabe".to_string()];
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );

        let mut policy = sample_policy();
        policy.valid_release_tags[0]
            .signer_fingerprints
            .push("deadbeef".to_string());
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );
    }

    #[test]
    fn verifier_rejects_realization_or_module_catalog_mismatch() {
        let record = computed();

        let mut policy = sample_policy();
        policy.valid_release_tags[0].realization = format!("sha256:{}", "bb".repeat(32));
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );

        let mut policy = sample_policy();
        policy.valid_release_tags[0].config_modules[0].package_name = "database".to_string();
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );

        let mut policy = sample_policy();
        policy.valid_release_tags[0].config_modules[0].nar_hash =
            crate::registry::store::NarBytes::from_hash(&format!("sha256:{}", "cc".repeat(32)), 0)
                .unwrap()
                .nar_hash();
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );

        let mut inputs = sample_inputs();
        inputs.config_modules.provenance["module_abi_compat"][0]["max"] = serde_json::json!(2);
        let record = computed_with_inputs(inputs);
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err(),
            GenAttestationFailure::Tag
        );

        let mut inputs = sample_inputs();
        inputs.config_modules.provenance["authorizations"][0]["owns"] =
            serde_json::json!(["firewall"]);
        let record = computed_with_inputs(inputs);
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err(),
            GenAttestationFailure::Tag
        );
    }

    #[test]
    fn verifier_recomputes_module_closure_and_rejects_duplicates() {
        let mut inputs = sample_inputs();
        inputs.config_modules.closure_hash = format!("sha256:{}", "ff".repeat(32));
        let record = computed_with_inputs(inputs);
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err(),
            GenAttestationFailure::Tag
        );

        let mut inputs = sample_inputs();
        inputs.config_modules.count = 2;
        inputs
            .config_modules
            .store_paths
            .push(inputs.config_modules.store_paths[0].clone());
        inputs
            .config_modules
            .nar_hashes
            .push(inputs.config_modules.nar_hashes[0].clone());
        inputs
            .config_modules
            .package_names
            .push(inputs.config_modules.package_names[0].clone());
        inputs.config_modules.provenance = serde_json::json!({
            "module_abi_compat": [{"min":1,"max":1}, {"min":1,"max":1}],
            "authorizations": [{"owns":[],"contributes":{}}, {"owns":[],"contributes":{}}]
        });
        let record = computed_with_inputs(inputs);
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err(),
            GenAttestationFailure::Tag
        );
    }

    #[test]
    fn verifier_rejects_ambiguous_release_catalog_entries() {
        let record = computed();
        let mut policy = sample_policy();
        policy
            .valid_release_tags
            .push(policy.valid_release_tags[0].clone());
        assert_eq!(
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err(),
            GenAttestationFailure::Tag
        );
    }

    #[test]
    fn verifies_record_after_replaying_cumulative_pcr15_history() {
        let record = computed();
        let prior = format!("sha256:{}", "22".repeat(32));
        let digest = record_hash(&record).expect("record hashes");
        let expected = expected_app_pcr_after(None, std::slice::from_ref(&prior), &digest)
            .expect("history replays");
        let checker = HistoryChecker { pcr15: expected };
        let mut policy = sample_policy();
        policy.prior_pcr15_event_digests.push(prior);
        let result = verify_gen_attestation(&record, &checker, &policy, b"nonce-xyz", None);
        assert!(result.is_ok(), "got {result:?}");

        policy.prior_pcr15_event_digests[0] = format!("sha256:{}", "33".repeat(32));
        assert_eq!(
            verify_gen_attestation(&record, &checker, &policy, b"nonce-xyz", None)
                .expect_err("wrong CEL prefix must fail"),
            GenAttestationFailure::RecordBinding
        );
    }

    #[test]
    fn verifies_record_after_replaying_from_validated_pcr15_baseline() {
        let record = computed();
        let baseline = format!("sha256:{}", "44".repeat(32));
        let prior = format!("sha256:{}", "22".repeat(32));
        let digest = record_hash(&record).expect("record hashes");
        let expected =
            expected_app_pcr_after(Some(&baseline), std::slice::from_ref(&prior), &digest)
                .expect("baseline history replays");
        let checker = HistoryChecker { pcr15: expected };
        let mut policy = sample_policy();
        policy.pcr15_baseline = Some(baseline);
        policy.prior_pcr15_event_digests.push(prior);

        let result = verify_gen_attestation(&record, &checker, &policy, b"nonce-xyz", None);
        assert!(result.is_ok(), "got {result:?}");

        policy.pcr15_baseline = Some(format!("sha256:{}", "55".repeat(32)));
        assert_eq!(
            verify_gen_attestation(&record, &checker, &policy, b"nonce-xyz", None)
                .expect_err("wrong PCR baseline must fail"),
            GenAttestationFailure::RecordBinding
        );
    }

    #[test]
    fn rejects_wrong_schema() {
        let mut record = computed();
        record.schema = "aos.gen-attestation/v2".to_string();
        let err =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err();
        assert_eq!(err, GenAttestationFailure::Schema);
    }

    #[test]
    fn rejects_wrong_nonce() {
        let record = computed();
        // A different nonce makes the mock checker reject the quote (step 2).
        let err = verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"WRONG", None)
            .unwrap_err();
        assert_eq!(err, GenAttestationFailure::Quote);
    }

    #[test]
    fn rejects_tampered_record_binding() {
        let mut record = computed();
        // Tampering any covered field changes record_hash, so the quoted PCR15
        // (taken over the original) no longer binds it.
        record.manifest_hash = "sha256:tampered".to_string();
        let err =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err();
        assert_eq!(err, GenAttestationFailure::RecordBinding);
    }

    #[test]
    fn rejects_pcr7_mismatch() {
        let record = computed();
        let mut policy = sample_policy();
        policy.expected_pcr7 = "00".repeat(32);
        let err =
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::SbState);
    }

    #[test]
    fn rejects_pcr11_catalog_mismatch() {
        let record = computed();
        let mut policy = sample_policy();
        policy.expected_pcr11 = format!("sha256:{}", "22".repeat(32));
        let err =
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::Pcr11);
    }

    #[test]
    fn rejects_root_verity_mismatch() {
        let record = computed();
        let mut policy = sample_policy();
        policy.expected_root_roothash = "00".repeat(32);
        let err =
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::RootVerity);
    }

    #[test]
    fn rejects_incomplete_config_module_provenance() {
        let mut inputs = sample_inputs();
        inputs.config_modules.nar_hashes.clear();
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        let record =
            compute_gen_attestation("gen-abc", "sha256:manifest", inputs, &tpm, b"nonce-xyz")
                .expect("compute malformed provenance fixture");
        let err =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
                .unwrap_err();
        assert_eq!(err, GenAttestationFailure::Tag);
    }

    #[test]
    fn rejects_untrusted_operator_key() {
        let record = computed();
        let mut policy = sample_policy();
        policy.trusted_config_keys = vec!["abadcafe".to_string()];
        let err =
            verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::HostNixTrust);
    }

    #[test]
    fn accepts_trusted_platform_evidence() {
        let mut inputs = sample_inputs();
        inputs.host_nix.trust_mode = "platform".to_string();
        inputs.host_nix.platform = Some("aws".to_string());
        inputs.host_nix.signer_key = None;
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        let record =
            compute_gen_attestation("gen-platform", "sha256:abc", inputs, &tpm, b"nonce-xyz")
                .expect("compute platform-mode record");
        let result =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None);
        assert!(result.is_ok(), "got {result:?}");
    }

    #[test]
    fn accepts_the_image_authored_empty_host_evidence() {
        let mut inputs = sample_inputs();
        inputs.host_nix.trust_mode = "image".to_string();
        inputs.host_nix.platform = Some("image".to_string());
        inputs.host_nix.signer_key = None;
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        let record = compute_gen_attestation(
            "gen-image-default",
            "sha256:abc",
            inputs,
            &tpm,
            b"nonce-xyz",
        )
        .expect("compute image-default record");
        let without_rederivation =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None);
        assert_eq!(
            without_rederivation.unwrap_err(),
            GenAttestationFailure::Rederive
        );
        let result = verify_gen_attestation(
            &record,
            &MockChecker,
            &sample_policy(),
            b"nonce-xyz",
            Some(&|record| record.manifest_hash.clone()),
        );
        assert!(result.is_ok(), "got {result:?}");
    }

    #[test]
    fn optional_rederivation_gate() {
        let record = computed();
        // A re-derivation that disagrees fails; one that agrees passes.
        let bad = verify_gen_attestation(
            &record,
            &MockChecker,
            &sample_policy(),
            b"nonce-xyz",
            Some(&|_r| "sha256:other".to_string()),
        );
        assert_eq!(bad.unwrap_err(), GenAttestationFailure::Rederive);

        let good = verify_gen_attestation(
            &record,
            &MockChecker,
            &sample_policy(),
            b"nonce-xyz",
            Some(&|r| r.manifest_hash.clone()),
        );
        assert!(good.is_ok());
    }
}
