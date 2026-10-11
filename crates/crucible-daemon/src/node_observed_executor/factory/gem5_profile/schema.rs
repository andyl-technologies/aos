//! Closed metadata and complete installed recipe/model/witness provenance.

use std::path::{Component, Path, PathBuf};

use super::{Artifact, BTreeMap, Deserialize, NodeObservedError, U64, refused};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    schema: String,
    edition: u16,
    policy_id: String,
    policy_version: U64,
    pub(super) artifacts: BTreeMap<String, Artifact>,
    pub(super) guests: BTreeMap<String, Guest>,
    source: Source,
    source_artifacts: BTreeMap<String, Artifact>,
    dmtcp_patches: Vec<SourcePatch>,
    pub(super) clock: Clock,
    model: Model,
    witnesses: BTreeMap<String, Witness>,
    modeled_diagnostics_complete: bool,
    full_system_device_parity_qualified: bool,
}

impl Manifest {
    pub(super) fn validate(&self) -> Result<(), NodeObservedError> {
        let expected_artifacts = [
            "auditor",
            "auditor_source",
            "controller",
            "dmtcp_launch",
            "dmtcp_restart",
            "image_guard",
            "model",
            "mtcp_restart",
            "native_executable",
            "python",
            "witness",
        ];
        if self.schema != super::SCHEMA
            || self.edition != 1
            || self.policy_id != super::POLICY
            || self.policy_version != U64::new(1)
            || self.modeled_diagnostics_complete
            || self.full_system_device_parity_qualified
            || self
                .artifacts
                .keys()
                .map(String::as_str)
                .ne(expected_artifacts)
            || self
                .guests
                .keys()
                .map(String::as_str)
                .ne(["aarch64", "x86_64"])
            || self
                .witnesses
                .keys()
                .map(String::as_str)
                .ne(["aarch64", "x86_64"])
            || self.clock.native_tick_ps != U64::new(1)
            || self.clock.mapping_id != super::MAPPING
            || self.clock.maximum_microsteps != U64::new(1_000_000)
        {
            return Err(refused("unsupported source-built gem5 closed profile"));
        }
        self.model.validate()?;
        self.source.validate()?;
        if self.source_artifacts.keys().map(String::as_str).ne([
            "dmtcp-upstream.tar.gz",
            "dmtcp.nix",
            "gem5-upstream.tar.gz",
        ]) || self.dmtcp_patches.is_empty()
        {
            return Err(refused("source-built gem5 implementation closure differs"));
        }
        for (isa, guest) in &self.guests {
            if guest.name != "crucible-o3-workload" || guest.syscalls != ["write_fd1", "exit"] {
                return Err(refused("source-built gem5 guest syscall scope differs"));
            }
            self.witnesses[isa].validate(isa, &self.artifacts["native_executable"].sha256)?;
        }
        Ok(())
    }

    pub(super) fn measure_provenance(&self, package_root: &Path) -> Result<(), NodeObservedError> {
        for artifact in self.source_artifacts.values() {
            artifact.measure()?;
        }
        measure_recipe(
            package_root.join("sources/gem5.nix"),
            &self.source.recipe_sha256,
        )?;
        for patch in &self.source.patches {
            require_filename(&patch.file)?;
            measure_recipe(
                package_root.join("sources/gem5-patches").join(&patch.file),
                &patch.sha256,
            )?;
        }
        for patch in &self.dmtcp_patches {
            require_filename(&patch.file)?;
            if patch.path != package_root.join("sources/dmtcp-patches").join(&patch.file) {
                return Err(refused("source-built gem5 patch path differs"));
            }
            Artifact {
                path: patch.path.clone(),
                sha256: patch.sha256.clone(),
                length: patch.length,
            }
            .measure()?;
        }
        for witness in self.witnesses.values() {
            witness.realized_configuration.measure()?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Guest {
    pub(super) artifact: Artifact,
    name: String,
    syscalls: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Clock {
    native_tick_ps: U64,
    mapping_id: String,
    pub(super) maximum_microsteps: U64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Model {
    cpu: String,
    cpu_clock: String,
    memory_bytes: U64,
    cache_hierarchy: String,
    memory_controller: String,
    configuration_scope: String,
    full_system: bool,
    ingress: Vec<String>,
    host_derived_guest_inputs: bool,
    native_listeners: bool,
}

impl Model {
    fn validate(&self) -> Result<(), NodeObservedError> {
        if self.cpu != "O3"
            || self.cpu_clock != "1GHz"
            || self.memory_bytes != U64::new(536_870_912)
            || self.cache_hierarchy != "classic-two-level"
            || self.memory_controller != "DDR3_1600_8x8"
            || self.configuration_scope != "exact-owned-controller-and-model-with-fixed-known-guest"
            || self.full_system
            || !self.ingress.is_empty()
            || self.host_derived_guest_inputs
            || self.native_listeners
        {
            return Err(refused("source-built gem5 model scope differs"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    schema: String,
    revision: String,
    upstream: String,
    version: String,
    build_configuration: String,
    recipe_sha256: String,
    patches: Vec<RecipePatch>,
    crucible_node_protocol: bool,
    qualified_exact_capture: bool,
    qualified_live_branch: bool,
}

impl Source {
    fn validate(&self) -> Result<(), NodeObservedError> {
        if self.schema != "crucible.gem5.source-foundation.v1"
            || self.revision != "f5c5a6e390f55dd5984977815bf9d0bd05da6945"
            || self.upstream != "https://github.com/gem5/gem5"
            || self.version != "25.1.0.1"
            || self.build_configuration != "ALL"
            || self.patches.is_empty()
            || self.crucible_node_protocol
            || self.qualified_exact_capture
            || self.qualified_live_branch
            || !valid_digest(&self.recipe_sha256)
        {
            return Err(refused("source-built gem5 implementation closure differs"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipePatch {
    file: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePatch {
    file: String,
    path: PathBuf,
    sha256: String,
    length: U64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    guest_isa: String,
    native_artifact_sha256: String,
    opaque_capture_complete: bool,
    modeled_diagnostics_complete: bool,
    unchanged_capture_cut: bool,
    source_dead_before_restore: bool,
    original_owned_root_absent: bool,
    original_image_namespace_absent: bool,
    authenticated_saved_copy_relocation: bool,
    private_launch_artifact_modes_preserved: bool,
    private_concurrent_reconstructions: U64,
    full_position_exclusive_stop: bool,
    full_position_single_callback_at_budget_ceiling: bool,
    actual_native_publication_birth: bool,
    original_receipt_retry: bool,
    output_matches_native_checksum: bool,
    group_reclaimed: bool,
    fresh_reconstruction_capture_closure: bool,
    image_sha256: String,
    image_length: U64,
    closure_receipt_sha256: String,
    boundary_sha256: String,
    host_abi: HostAbi,
    realized_configuration: Artifact,
}

impl Witness {
    fn validate(&self, isa: &str, native_sha256: &str) -> Result<(), NodeObservedError> {
        if self.guest_isa != isa
            || self.native_artifact_sha256 != native_sha256
            || self.modeled_diagnostics_complete
            || self.private_concurrent_reconstructions != U64::new(2)
            || !self.opaque_capture_complete
            || !self.unchanged_capture_cut
            || !self.source_dead_before_restore
            || !self.original_owned_root_absent
            || !self.original_image_namespace_absent
            || !self.authenticated_saved_copy_relocation
            || !self.private_launch_artifact_modes_preserved
            || !self.full_position_exclusive_stop
            || !self.full_position_single_callback_at_budget_ceiling
            || !self.actual_native_publication_birth
            || !self.original_receipt_retry
            || !self.output_matches_native_checksum
            || !self.group_reclaimed
            || !self.fresh_reconstruction_capture_closure
            || !valid_digest(&self.image_sha256)
            || !valid_digest(&self.closure_receipt_sha256)
            || !valid_digest(&self.boundary_sha256)
            || self.image_length.get() == 0
            || self.image_length.get() > super::MAX_ARTIFACT_BYTES
            || self.host_abi.byte_order != "little"
            || self.host_abi.kernel_release.is_empty()
            || !matches!(self.host_abi.machine.as_str(), "x86_64" | "aarch64")
            || self.host_abi.page_bytes.get() == 0
            || !self.host_abi.page_bytes.get().is_power_of_two()
        {
            return Err(refused(
                "source-built gem5 native qualification is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAbi {
    byte_order: String,
    kernel_release: String,
    machine: String,
    page_bytes: U64,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_filename(value: &str) -> Result<(), NodeObservedError> {
    let mut components = Path::new(value).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(refused(
            "source-built gem5 patch filename is not a safe leaf",
        ));
    }
    Ok(())
}

fn measure_recipe(path: PathBuf, sha256: &str) -> Result<(), NodeObservedError> {
    let length = std::fs::symlink_metadata(&path)
        .map_err(super::io_error)?
        .len();
    Artifact {
        path,
        sha256: sha256.into(),
        length: U64::new(length),
    }
    .measure()?;
    Ok(())
}
