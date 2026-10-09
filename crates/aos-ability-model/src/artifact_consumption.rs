//! Realized artifact-consumption evidence produced by build gates.
//!
//! Version 1 distinguishes startup linkage, runtime plugin loading, helper
//! execution, build-tool execution, and immutable data reads. Each mechanism
//! carries observations from an actual hermetic invocation; metadata alone is
//! not evidence that the provider was consumed.
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

/// Required semantic feature for a directly observed runtime plugin load.
pub const RUNTIME_PLUGIN_LOAD_FEATURE: &str = "runtime-plugin-load-v1";

/// Required semantic feature for a directly observed helper execution.
pub const HELPER_EXECUTION_FEATURE: &str = "helper-execution-v1";

/// Required semantic feature for a directly observed build-tool execution.
pub const BUILD_TOOL_EXECUTION_FEATURE: &str = "build-tool-execution-v1";

/// Required semantic feature for a directly observed immutable data read.
pub const IMMUTABLE_DATA_INPUT_FEATURE: &str = "immutable-data-input-v1";

/// Selects the concrete mechanism established by an evidence document.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactConsumptionMechanism {
    /// A dynamic executable names the provider through `DT_NEEDED` at startup.
    ElfStartupLinkage,
    /// A host process loads one exact shared object during an observed invocation.
    RuntimePluginLoad,
    /// A host process executes one exact helper during an observed invocation.
    HelperExecution,
    /// A build action executes one exact tool to produce the consumer artifact.
    BuildToolExecution,
    /// A host process reads one exact immutable data file during an observed invocation.
    ImmutableDataInput,
}

/// States whether the realized consumer closure must retain the provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRetentionRequirement {
    /// The provider must be reachable from the consumer's runtime closure.
    Required,
    /// The provider must stay outside the consumer's runtime closure.
    Forbidden,
}

/// Identifies the platforms involved in constructing and consuming an artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConsumptionPlatforms {
    /// Identifies the platform on which the build action executed.
    pub build: PlatformIdentity,
    /// Identifies the platform on which the consumer runs or is consumed.
    pub host: PlatformIdentity,
    /// Identifies the target platform of the consumer artifact.
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

/// States the expected result of one hermetic path-consumption invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedPathConsumptionContract {
    /// Lists the exact arguments after the invoked executable's path.
    pub arguments: Vec<String>,
    /// Pins the SHA-256 of standard output from the successful invocation.
    pub output_sha256: Sha256Digest,
    /// States the required runtime-closure relationship for this mechanism.
    pub retention: ArtifactRetentionRequirement,
}

/// Records facts captured while invoking one path-consumption relationship.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedPathConsumptionObservation {
    /// Records the exact arguments supplied to the invoked executable.
    pub arguments: Vec<String>,
    /// Records the invocation's successful exit status.
    pub exit_code: i32,
    /// Pins the SHA-256 of the captured standard output.
    pub output_sha256: Sha256Digest,
    /// Confirms that syscall evidence observed the mechanism-specific provider access.
    pub provider_access_observed: bool,
    /// States whether the realized consumer closure contains the provider.
    pub provider_retained_by_consumer: bool,
}

/// Carries the mechanism-specific authored consumption contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ArtifactConsumptionContract {
    /// Describes startup ELF linkage.
    ElfStartupLinkage(ElfStartupLinkageContract),
    /// Describes an invocation whose provider access is observed through syscalls.
    ObservedPath(ObservedPathConsumptionContract),
}

/// Carries mechanism-specific observations from realized artifacts or execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ArtifactConsumptionObservation {
    /// Records startup ELF facts.
    ElfStartupLinkage(ElfStartupLinkageObservation),
    /// Records one actual path-consumption invocation.
    ObservedPath(ObservedPathConsumptionObservation),
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
    /// Pins the exact consuming executable or produced file.
    pub consumer: ArtifactFileEvidence,
    /// Pins the exact library, executable, or data provider.
    pub provider: ArtifactFileEvidence,
    /// States the mechanism-specific contract supplied to the build gate.
    pub contract: ArtifactConsumptionContract,
    /// Records mechanism-specific facts inspected from execution and realized outputs.
    pub observation: ArtifactConsumptionObservation,
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
