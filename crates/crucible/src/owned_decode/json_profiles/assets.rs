//! Owns the closed assets JSON DTOs and their diagnostic label roster.
//!
//! Validation and runtime effects stay in the consuming service. Field names,
//! borrowing and Serde type names retain the existing wire contract.

use serde::Deserialize;
use serde::de::IgnoredAny;

/// Deserializes the closed Projection wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Projection {
    /// Declares the schema.
    pub schema: String,
    /// Declares the family.
    pub family: String,
    /// Declares the native count.
    pub native_count: usize,
    /// Declares the hot fork.
    pub hot_fork: Option<IgnoredAny>,
    /// Declares the world memory mib.
    pub world_memory_mib: u64,
    /// Declares the execution quanta.
    pub execution_quanta: u64,
    /// Declares the service profile.
    #[serde(rename = "serviceProfile")]
    pub _service_profile: IgnoredAny,
    /// Declares the guest assets.
    pub guest_assets: GuestAssets,
    /// Declares the emulator executable artifact.
    #[serde(rename = "qemu")]
    pub executable: Artifact,
    /// Declares the plugin.
    pub plugin: Artifact,
    /// Declares the rows.
    pub rows: Vec<Row>,
}

/// Deserializes the closed GuestAssets wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestAssets {
    /// Declares the architecture.
    pub architecture: String,
    /// Declares the boot mode.
    pub boot_mode: String,
    /// Declares the kernel.
    pub kernel: Artifact,
    /// Declares the root image.
    pub root_image: Artifact,
    /// Declares the initrd.
    pub initrd: Option<Artifact>,
    /// Declares the root image format.
    pub root_image_format: RootImageFormat,
    /// Declares the kernel cmdline.
    pub kernel_cmdline: String,
}

/// Deserializes the closed RootImageFormat wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RootImageFormat {
    /// Selects the raw representation.
    Raw,
    /// Selects the qcow2 representation.
    Qcow2,
}

/// Deserializes the closed Artifact wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    /// Declares the path.
    pub path: String,
    /// Declares the bytes.
    pub bytes: u64,
    /// Declares the blake3.
    pub blake3: String,
}

/// Deserializes the closed Row wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Row {
    /// Declares the target divisor.
    pub target_divisor: u64,
    /// Declares the repeat.
    pub repeat: usize,
    /// Declares the attempts.
    pub attempts: Vec<Attempt>,
}

/// Deserializes the closed Attempt wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Attempt {
    /// Declares the seed.
    pub seed: u64,
    /// Declares the campaign.
    pub campaign: String,
    /// Declares the scenario file.
    pub scenario_file: String,
    /// Declares the schedule file.
    pub schedule_file: String,
    /// Declares the scenario id.
    pub scenario_id: crucible_campaign::ScenarioDefId,
    /// Declares the configuration artifact id.
    pub configuration_artifact_id: crucible_campaign::ConfigurationArtifactId,
    /// Declares the scenario blake3.
    pub scenario_blake3: String,
    /// Declares the schedule blake3.
    pub schedule_blake3: String,
    /// Declares the campaign creation.
    pub campaign_creation: CampaignCreation,
}

/// Deserializes the closed CampaignCreation wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CampaignCreation {
    /// Declares the schema.
    pub schema: String,
    /// Declares the request file.
    pub request_file: String,
    /// Declares the request bytes.
    pub request_bytes: u64,
    /// Declares the request blake3.
    pub request_blake3: String,
    /// Declares the request digest.
    pub request_digest: crucible_campaign::CampaignHash,
    /// Declares the lineage id.
    pub lineage_id: crucible_campaign::CampaignLineageId,
    /// Declares the policy id.
    pub policy_id: crucible_campaign::CampaignPolicyId,
    /// Declares the generators.
    pub generators: Vec<Generator>,
}

/// Deserializes the closed Generator wire object.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Generator {
    /// Declares the file.
    pub file: String,
    /// Declares the bytes.
    pub bytes: u64,
    /// Declares the blake3.
    pub blake3: String,
    /// Declares the id.
    pub id: crucible_campaign::CandidateGeneratorSpecId,
}

impl super::sealed::Sealed for Projection {}

impl<'input> super::ClosedJsonProfile<'input> for Projection {
    const DIAGNOSTIC_LABELS: &'static [&'static str] = &[
        "struct Projection",
        "schema",
        "family",
        "nativeCount",
        "hotFork",
        "worldMemoryMib",
        "executionQuanta",
        "serviceProfile",
        "guestAssets",
        "qemu",
        "plugin",
        "rows",
        "struct GuestAssets",
        "architecture",
        "bootMode",
        "kernel",
        "rootImage",
        "initrd",
        "rootImageFormat",
        "kernelCmdline",
        "enum RootImageFormat",
        "raw",
        "qcow2",
        "struct Artifact",
        "path",
        "bytes",
        "blake3",
        "struct Row",
        "targetDivisor",
        "repeat",
        "attempts",
        "struct Attempt",
        "seed",
        "campaign",
        "scenarioFile",
        "scheduleFile",
        "scenarioId",
        "configurationArtifactId",
        "scenarioBlake3",
        "scheduleBlake3",
        "campaignCreation",
        "struct CampaignCreation",
        "schema",
        "requestFile",
        "requestBytes",
        "requestBlake3",
        "requestDigest",
        "lineageId",
        "policyId",
        "generators",
        "struct Generator",
        "file",
        "bytes",
        "blake3",
        "id",
    ];
}
