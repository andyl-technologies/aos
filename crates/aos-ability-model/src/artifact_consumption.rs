//! Realized artifact-consumption evidence produced by build gates.
//!
//! Version 1 proves one ELF executable's startup linkage to one exact shared
//! library artifact. It does not describe plugins, explicit runtime loads,
//! helper execution, build-tool execution, or immutable data inputs. Those
//! mechanisms require distinct evidence because `DT_NEEDED` and startup-loader
//! facts cannot establish them.
//!
//! ```json
//! {"consumer":{"artifact":{"closure":"sha256:<digest>","content":"sha256:<digest>","nar_hash":"sha256:<digest>","store_path":"/nix/store/<hash>-consumer"},"path":"/bin/consumer","sha256":"sha256:<digest>"},"contract":{"loader":"/nix/store/<hash>-glibc/lib/ld-linux-x86-64.so.2","needed":["libexample.so.1"],"search_path":["/nix/store/<hash>-provider/lib"],"search_path_kind":"runpath","soname":"libexample.so.1","symbols":[{"name":"example","version":"EXAMPLE_1"}]},"id":"example-linkage","mechanism":"elf-startup-linkage","observation":{"abi_version":"0","data_encoding":"2's complement, little endian","elf_class":"ELF64","loader":"/nix/store/<hash>-glibc/lib/ld-linux-x86-64.so.2","loader_elf_compatible":true,"machine":"Advanced Micro Devices X86-64","needed":["libexample.so.1"],"os_abi":"UNIX - System V","provider_elf_compatible":true,"provider_retained_by_consumer":true,"search_path":["/nix/store/<hash>-provider/lib"],"search_path_kind":"runpath","search_resolves_exact_provider":true,"soname":"libexample.so.1","symbols":[{"name":"example","version":"EXAMPLE_1"}]},"platforms":{"build":{"architecture":"x86_64","system":"linux"},"host":{"architecture":"x86_64","system":"linux"},"target":{"architecture":"x86_64","system":"linux"}},"provider":{"artifact":{"closure":"sha256:<digest>","content":"sha256:<digest>","nar_hash":"sha256:<digest>","store_path":"/nix/store/<hash>-provider"},"path":"/lib/libexample.so.1","sha256":"sha256:<digest>"},"required_features":["elf-startup-linkage-v1"],"schema":"aos.artifact-consumption.evidence/v1"}
//! ```

use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::document::{PlatformIdentity, RequiredFeature, VersionedDocument};
use crate::identity::LocalKey;
use crate::value::ArtifactReference;

/// Exact schema discriminator for realized artifact-consumption evidence.
pub const ARTIFACT_CONSUMPTION_EVIDENCE_SCHEMA: &str = "aos.artifact-consumption.evidence/v1";

/// Required semantic feature for version-1 ELF startup-linkage evidence.
pub const ELF_STARTUP_LINKAGE_FEATURE: &str = "elf-startup-linkage-v1";

/// Selects the concrete mechanism established by an evidence document.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactConsumptionMechanism {
    /// A dynamic executable names the provider through `DT_NEEDED` at startup.
    ElfStartupLinkage,
}

/// Identifies the platforms involved in constructing and consuming an artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConsumptionPlatforms {
    /// Identifies the platform on which the build action executed.
    pub build: PlatformIdentity,
    /// Identifies the platform on which the consumer executable will run.
    pub host: PlatformIdentity,
    /// Identifies the code platform of the consumer and provider ELF objects.
    pub target: PlatformIdentity,
}

/// Identifies one exact file within an immutable artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFileEvidence {
    /// Pins the exact artifact and its retained closure.
    pub artifact: ArtifactReference,
    /// Gives an absolute artifact-relative path such as `/bin/tool`.
    pub path: String,
    /// Identifies the exact bytes of this file within the artifact.
    pub sha256: Sha256Digest,
}

/// Names one versioned symbol required from the provider.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ElfSymbolVersion {
    /// Names the dynamic symbol.
    pub name: String,
    /// Names the ELF symbol version required by the consumer.
    pub version: String,
}

/// States the complete expected ELF startup-linkage relationship.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ElfStartupLinkageContract {
    /// Names the provider's exact `DT_SONAME`.
    pub soname: String,
    /// Lists the consumer's complete sorted `DT_NEEDED` set.
    pub needed: Vec<String>,
    /// Lists the consumer's ordered `DT_RUNPATH` or `DT_RPATH` entries.
    pub search_path: Vec<String>,
    /// Identifies whether the recorded search list is `DT_RUNPATH` or `DT_RPATH`.
    pub search_path_kind: ElfSearchPathKind,
    /// Names the consumer's program interpreter.
    pub loader: String,
    /// Lists exact provider symbol versions required by the consumer.
    pub symbols: Vec<ElfSymbolVersion>,
}

/// Records ELF facts read from the realized consumer and provider files.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ElfStartupLinkageObservation {
    /// Records the shared consumer/provider/loader ELF class.
    pub elf_class: String,
    /// Records the shared consumer/provider/loader ELF byte order.
    pub data_encoding: String,
    /// Records the consumer's ELF machine description.
    pub machine: String,
    /// Records the consumer's ELF OS/ABI label.
    pub os_abi: String,
    /// Records the consumer's ELF ABI version.
    pub abi_version: String,
    /// Records the provider's observed `DT_SONAME`.
    pub soname: String,
    /// Records the consumer's complete sorted `DT_NEEDED` set.
    pub needed: Vec<String>,
    /// Records the consumer's ordered `DT_RUNPATH` or `DT_RPATH` entries.
    pub search_path: Vec<String>,
    /// Records whether the inspected search list was `DT_RUNPATH` or `DT_RPATH`.
    pub search_path_kind: ElfSearchPathKind,
    /// Records the consumer's program interpreter.
    pub loader: String,
    /// Records symbol versions observed in both provider and consumer tables.
    pub symbols: Vec<ElfSymbolVersion>,
    /// States that the provider's class, byte order, machine, and ABI match.
    pub provider_elf_compatible: bool,
    /// States that the program interpreter's class, byte order, machine, and ABI match.
    pub loader_elf_compatible: bool,
    /// States that the embedded search order selects this exact provider first.
    pub search_resolves_exact_provider: bool,
    /// States that the consumer's realized Nix closure contains the provider.
    pub provider_retained_by_consumer: bool,
}

/// Distinguishes the dynamic linker's two non-equivalent embedded search tags.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ElfSearchPathKind {
    /// The consumer carries modern `DT_RUNPATH` semantics.
    Runpath,
    /// The consumer carries legacy transitive `DT_RPATH` semantics.
    Rpath,
}

/// Carries canonical evidence for one exact realized artifact-consumption edge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConsumptionEvidenceDocument {
    /// Carries [`ARTIFACT_CONSUMPTION_EVIDENCE_SCHEMA`].
    pub schema: String,
    /// Names required evidence semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Gives this evidence edge a stable local identity.
    pub id: LocalKey,
    /// Selects the mechanism that the producer actually inspected.
    pub mechanism: ArtifactConsumptionMechanism,
    /// Identifies the build, host, and code-target platforms.
    pub platforms: ArtifactConsumptionPlatforms,
    /// Pins the exact consuming ELF executable.
    pub consumer: ArtifactFileEvidence,
    /// Pins the exact shared-library provider.
    pub provider: ArtifactFileEvidence,
    /// States the linkage contract supplied to the build gate.
    pub contract: ElfStartupLinkageContract,
    /// Records facts inspected from realized outputs and their closure.
    pub observation: ElfStartupLinkageObservation,
}

impl VersionedDocument for ArtifactConsumptionEvidenceDocument {
    const SCHEMA: &'static str = ARTIFACT_CONSUMPTION_EVIDENCE_SCHEMA;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }
}
