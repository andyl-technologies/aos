//! Portable assessment exports with verified closure and explicit source custody.
//!
//! Bundles carry closed JSON objects, never executable scripts or extraction
//! paths. Reproducing an assessment establishes semantic agreement only; imports
//! require separate current authority before advancing Hub heads or release gates.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::evaluator::evaluate;
use crate::input::{EvaluationData, ScanInputV1};
use crate::observation::SourceEvidenceRef;
use crate::result::PackageAssessmentV1;

/// Identifies the closed assessment bundle transport.
pub const ASSESSMENT_BUNDLE_V1: &str = "aos.assessment-bundle/v1";

/// Identifies the canonical content-addressed bundle manifest.
pub const BUNDLE_MANIFEST_V1: &str = "aos.assessment-bundle-manifest/v1";

/// Distinguishes full retained-source exports from explicit external custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleProfile {
    /// Includes every required normalized and raw source object.
    SelfContained,
    /// Includes normalized inputs with explicit omitted raw evidence references.
    Reference,
}

/// Binds one canonical object to its domain, identity and exact encoded length.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectReference {
    /// Domain-separated content identity, or exact-byte identity for raw evidence.
    pub digest: Sha256Digest,
    /// Closed semantic schema/type; no extraction path or executable content.
    pub schema: String,
    /// Exact canonical or raw encoded length.
    pub byte_length: u64,
}

/// Carries raw evidence as bounded canonical base64 without filesystem paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawEvidenceMember {
    /// Exact raw bytes, independent of semantic normalized-object identities.
    pub digest: Sha256Digest,
    /// Exact decoded length, checked before allocation.
    pub byte_length: u64,
    /// Canonical standard padded base64 encoding.
    pub data: String,
}

impl RawEvidenceMember {
    /// Encodes a bounded raw evidence object.
    ///
    /// # Errors
    ///
    /// Returns an error when source bytes exceed the admitted per-response limit.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8 * 1024 * 1024 {
            bail!("bundle raw member exceeds byte budget");
        }
        Ok(Self {
            digest: Sha256Digest::of_bytes(bytes),
            byte_length: bytes.len() as u64,
            data: STANDARD.encode(bytes),
        })
    }

    /// Verifies bounded canonical encoding, size and exact-byte identity.
    ///
    /// # Errors
    ///
    /// Returns an error for excessive size, invalid/noncanonical base64, a size
    /// mismatch or a digest mismatch. No source URLs or paths are followed.
    pub fn decode(&self) -> Result<Vec<u8>> {
        if self.byte_length > 8 * 1024 * 1024 || self.data.len() > 12 * 1024 * 1024 {
            bail!("bundle raw member exceeds byte budget");
        }
        let expected_encoded = self
            .byte_length
            .div_ceil(3)
            .checked_mul(4)
            .ok_or_else(|| anyhow::anyhow!("bundle size overflow"))?;
        if self.data.len() as u64 != expected_encoded {
            bail!("raw evidence encoding differs from declared size");
        }
        let bytes = STANDARD.decode(&self.data)?;
        if bytes.len() as u64 != self.byte_length
            || STANDARD.encode(&bytes) != self.data
            || Sha256Digest::of_bytes(&bytes) != self.digest
        {
            bail!("raw evidence bytes differ from declared content identity");
        }
        Ok(bytes)
    }
}

/// Binds one complete normalized closure and explicit external raw references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BundleManifestV1 {
    /// Exact manifest schema discriminator.
    pub schema: String,
    /// Required source-custody profile.
    pub profile: BundleProfile,
    /// Exact normalized inventory identity.
    pub inventory_digest: Sha256Digest,
    /// Exact frozen semantic input identity.
    pub scan_input_digest: Sha256Digest,
    /// Claimed result identity, recomputed by import verification.
    pub assessment_digest: Sha256Digest,
    /// Required semantic engine/profile identity.
    pub engine_digest: Sha256Digest,
    /// Sorted unique included canonical and raw members.
    pub objects: Vec<ObjectReference>,
    /// Sorted required raw members omitted from this export; no arbitrary URLs.
    pub external_references: Vec<SourceEvidenceRef>,
    /// Sorted admitted package publication identities; signatures remain separate.
    pub provenance: Vec<String>,
}

/// Carries a complete frozen normalized closure and its claimed canonical result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssessmentBundleV1 {
    /// Exact transport schema discriminator.
    pub schema: String,
    /// Exact digest-bound member inventory and custody profile.
    pub manifest: BundleManifestV1,
    /// Frozen semantic input; operation metadata is intentionally separate.
    pub input: ScanInputV1,
    /// Complete normalized semantic closure.
    pub data: EvaluationData,
    /// Claimed result, recomputed before accepting a reproduction receipt.
    pub assessment: PackageAssessmentV1,
    /// Optional raw members strictly sorted by exact-byte digest.
    pub raw_members: Vec<RawEvidenceMember>,
}

impl AssessmentBundleV1 {
    /// Constructs a verified export and explicit omitted-source custody list.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid inputs, result disagreement, missing raw
    /// evidence in a self-contained export, conflicting members or byte budgets.
    pub fn export(
        input: ScanInputV1,
        data: EvaluationData,
        profile: BundleProfile,
        mut raw_members: Vec<RawEvidenceMember>,
    ) -> Result<Self> {
        let assessment = evaluate(&input, &data)?;
        raw_members.sort_by_key(|member| member.digest);
        let manifest = manifest(&input, &data, &assessment, profile, &raw_members)?;
        let bundle = Self {
            schema: ASSESSMENT_BUNDLE_V1.into(),
            manifest,
            input,
            data,
            assessment,
            raw_members,
        };
        bundle.verify()?;
        bundle.encoded()?;
        Ok(bundle)
    }

    /// Verifies closure, source custody and deterministic agreement.
    ///
    /// The resulting identity confers no publication, provider, disposition or
    /// release authority. An admitting service must independently check those.
    ///
    /// # Errors
    ///
    /// Returns an error for changed/duplicate/missing members, incompatible
    /// engines, forged sizes/digests, ambiguous data or result disagreement.
    pub fn verify(&self) -> Result<Sha256Digest> {
        if self.schema != ASSESSMENT_BUNDLE_V1 {
            bail!("unsupported assessment bundle schema");
        }
        let expected = manifest(
            &self.input,
            &self.data,
            &self.assessment,
            self.manifest.profile,
            &self.raw_members,
        )?;
        if self.manifest != expected {
            bail!("assessment bundle manifest differs from its member closure");
        }
        if evaluate(&self.input, &self.data)? != self.assessment {
            bail!("assessment bundle result does not reproduce");
        }
        Sha256Digest::of_canonical(BUNDLE_MANIFEST_V1, &self.manifest)
    }

    /// Encodes one bounded closed transport document.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding or the complete export byte budget fails.
    pub fn encoded(&self) -> Result<Vec<u8>> {
        let mut budget = aos_contract::limits::BoundedWriter::new(
            16 * 1024 * 1024,
            "assessment bundle exceeds total byte budget",
        );
        serde_json::to_writer(&mut budget, self)?;
        Ok(serde_json::to_vec(self)?)
    }

    /// Decodes and verifies a bounded transport without extracting any files.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible/ambiguous JSON, excessive sizes/depth,
    /// missing/mismatched members or a result that does not reproduce.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let limits = JsonLimits {
            max_bytes: 16 * 1024 * 1024,
            max_depth: 32,
            max_items: 250_000,
            max_string_bytes: 12 * 1024 * 1024,
        };
        let bundle: Self =
            crate::validation::decode_with_limits(bytes, "assessment bundle", limits)?;
        bundle.verify()?;
        Ok(bundle)
    }
}

fn manifest(
    input: &ScanInputV1,
    data: &EvaluationData,
    assessment: &PackageAssessmentV1,
    profile: BundleProfile,
    raw: &[RawEvidenceMember],
) -> Result<BundleManifestV1> {
    if raw.len() > 4096 || raw.windows(2).any(|pair| pair[0].digest >= pair[1].digest) {
        bail!("bundle raw objects must be bounded, sorted and unique");
    }
    let mut objects = BTreeMap::<Sha256Digest, ObjectReference>::new();
    let mut add = |schema: &str, identity: Sha256Digest, bytes: usize| -> Result<()> {
        let reference = ObjectReference {
            digest: identity,
            schema: schema.into(),
            byte_length: bytes as u64,
        };
        if objects
            .insert(identity, reference.clone())
            .is_some_and(|previous| previous != reference)
        {
            bail!("bundle contains conflicting semantic object identities");
        }
        Ok(())
    };
    macro_rules! member {
        ($domain:expr, $object:expr, $identity:expr) => {
            add(
                $domain,
                $identity,
                aos_contract::canonical::to_vec($object)?.len(),
            )?;
        };
    }
    member!(crate::input::SCAN_INPUT_V1, input, input.digest()?);
    member!(
        crate::scan_inventory::SCAN_INVENTORY_V1,
        &data.inventory,
        data.inventory.digest()?
    );
    member!(
        crate::input::ASSESSMENT_POLICY_V1,
        &data.policy,
        data.policy.digest()?
    );
    member!(
        crate::result::PACKAGE_ASSESSMENT_V1,
        assessment,
        assessment.digest()?
    );
    member!(
        "aos.candidate-history/v1",
        &data.history,
        input.history_digest
    );
    for definition in &data.definitions {
        member!(
            crate::definition::PACKAGE_SCAN_DEFINITION_V1,
            definition,
            definition.digest()?
        );
    }
    for binding in &data.upstream {
        member!(
            "aos.component-upstream-observation/v1",
            binding,
            Sha256Digest::of_canonical("aos.component-upstream-observation/v1", binding)?
        );
        member!(
            crate::UPSTREAM_OBSERVATION_V1,
            &binding.observation,
            Sha256Digest::of_canonical(crate::UPSTREAM_OBSERVATION_V1, &binding.observation)?
        );
    }
    for record in &data.advisories {
        member!(
            crate::advisory::ADVISORY_RECORD_V1,
            record,
            record.digest()?
        );
    }
    for disposition in &data.dispositions {
        member!(
            crate::disposition::SECURITY_DISPOSITION_V1,
            disposition,
            disposition.digest()?
        );
    }
    let disposition_refs = data
        .dispositions
        .iter()
        .map(|disposition| disposition.digest())
        .collect::<Result<BTreeSet<_>>>()?;
    member!(
        "aos.disposition-set/v1",
        &disposition_refs,
        input.disposition_set_digest
    );
    let mut source_refs = BTreeMap::<Sha256Digest, SourceEvidenceRef>::new();
    if let Some(snapshot) = &data.advisory_snapshot {
        member!(
            crate::advisory::ADVISORY_SNAPSHOT_V1,
            snapshot,
            snapshot.digest()?
        );
        let observations = snapshot
            .sources
            .iter()
            .map(|source| &source.observation)
            .chain(
                snapshot
                    .exploit_catalog
                    .iter()
                    .map(|catalog| &catalog.observation),
            );
        for observation in observations {
            member!(
                crate::observation::PROVIDER_OBSERVATION_V1,
                observation,
                observation.digest()?
            );
            for source in &observation.source_refs {
                if let Some(previous) = source_refs.insert(source.digest, source.clone())
                    && previous.byte_length != source.byte_length
                {
                    bail!("source custody references disagree about exact byte length");
                }
            }
        }
    }
    for binding in &data.upstream {
        for source in &binding.source_refs {
            if source_refs.insert(source.digest, source.clone())
                .is_some_and(|previous| previous.byte_length != source.byte_length)
            {
                bail!("upstream chain source custody references disagree about exact byte length");
            }
        }
        source_refs
            .entry(binding.observation.response_digest)
            .or_insert(SourceEvidenceRef {
                digest: binding.observation.response_digest,
                byte_length: binding.response_byte_length,
                origin: binding.observation.provider.clone(),
            });
    }
    for member in raw {
        let bytes = member.decode()?;
        let Some(source) = source_refs.remove(&member.digest) else {
            bail!("bundle contains unlisted raw evidence");
        };
        if source.byte_length != bytes.len() as u64 {
            bail!("retained source length differs from bundled raw evidence");
        }
        add("aos.raw-evidence/v1", member.digest, bytes.len())?;
    }
    if profile == BundleProfile::SelfContained && !source_refs.is_empty() {
        bail!("self-contained bundle lacks required retained source evidence");
    }
    let provenance = data
        .definitions
        .iter()
        .flat_map(|definition| definition.metadata_origins.iter().cloned())
        .collect::<BTreeSet<_>>();
    if objects.len() > 100_000 {
        bail!("bundle semantic object count exceeds budget");
    }
    Ok(BundleManifestV1 {
        schema: BUNDLE_MANIFEST_V1.into(),
        profile,
        inventory_digest: input.inventory_digest,
        scan_input_digest: input.digest()?,
        assessment_digest: assessment.digest()?,
        engine_digest: input.engine_digest,
        objects: objects.into_values().collect(),
        external_references: source_refs.into_values().collect(),
        provenance: provenance.into_iter().collect(),
    })
}
