//! Materializes an authenticated Root image beneath an already owned capsule.
//!
//! Signed role/name/content rows determine new private paths. Historical source
//! routes remain inert data and are never opened. Imported image seals grant no
//! live authority; reconstructed owners must capture and audit their own peers.

use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use crucible::{
    node_adapters::arm_root::{
        AuthenticatedArmRootContinuation, authenticate_arm_root_continuation,
    },
    node_admission::AdmittedGraph,
    node_contract::NativeCaptureArtifact,
    node_state::{AuthenticatedNativeSource, StateError, StateErrorCode},
};
use crucible_node_contract::Id;
use crucible_node_provider::{
    ProviderError,
    gem5::{
        ArmRootArchiveImport, ArmRootArchiveSourceVerifier, ArmRootCapturedImage,
        Gem5ArchiveArtifact, Gem5CapturedArtifactRole, Gem5LaunchArtifact,
        InstalledArmRootMechanism,
    },
};

use super::super::native_state::archive::{
    check_empty_private_root, check_geometry, copy_original, create_parents, native_relative,
};
use super::profile::RootWorldProfile;

pub(super) struct MaterializedRootArchive {
    pub(super) image: ArmRootCapturedImage,
    pub(super) continuation: Option<AuthenticatedArmRootContinuation>,
    pub(super) artifacts: Vec<NativeCaptureArtifact>,
    pub(super) root: PathBuf,
}

impl MaterializedRootArchive {
    pub(super) fn prepare(
        graph: &AdmittedGraph,
        source: &AuthenticatedNativeSource<'_>,
        node: &Id,
        profile: Rc<RootWorldProfile>,
        artifacts: Vec<NativeCaptureArtifact>,
        root: &Path,
    ) -> Result<Self, StateError> {
        let continuation = authenticate_arm_root_continuation(source, node)
            .map_err(|failure| refusal(failure.reason))?;
        check_selection(graph, &continuation, &profile)?;
        check_geometry(source)?;
        check_empty_private_root(root)?;
        let image_root = root.join("images");
        let resource_root = root.join("resources");
        for path in [&image_root, &resource_root] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(refusal)?;
        }
        if artifacts.len() != source.owner().artifacts.len()
            || artifacts
                .iter()
                .zip(&source.owner().artifacts)
                .any(|(held, signed)| {
                    held.role() != &signed.role
                        || held.name() != signed.name
                        || held.reference() != &signed.content
                })
        {
            return Err(refusal(
                "Root pinned descriptors differ from signed complete roster",
            ));
        }
        let mut copied = Vec::new();
        copied.try_reserve_exact(artifacts.len()).map_err(refusal)?;
        for artifact in &artifacts {
            let (role, directory) = match artifact.role().as_str() {
                "image" => (Gem5CapturedArtifactRole::Image, &image_root),
                "resource" => (Gem5CapturedArtifactRole::Resource, &resource_root),
                _ => return Err(refusal("Root original artifact uses an unsupported role")),
            };
            let relative = native_relative(artifact.role().as_str(), artifact.name())?;
            let path = directory.join(&relative);
            create_parents(directory, &relative)?;
            copy_original(artifact, &path)?;
            copied.push(Gem5ArchiveArtifact {
                role,
                relative,
                artifact: Gem5LaunchArtifact {
                    path,
                    content: artifact.reference().clone(),
                },
            });
        }
        let record = ArmRootArchiveImport {
            capture: continuation.capture().clone(),
            source: continuation.native_source().clone(),
            source_supplementary_files_root: PathBuf::from(continuation.supplementary_files_root()),
            boundary: continuation.native_boundary().clone(),
            original_outcomes: continuation
                .original_outcomes()
                .map_err(|failure| refusal(failure.reason))?,
            control_history: continuation.control_history().clone(),
            pending: continuation.pending().cloned(),
            last_acknowledged: continuation.last_acknowledged().cloned(),
            artifacts: copied,
        };
        let verifier = SignedRootVerifier {
            graph,
            continuation: &continuation,
            profile: &profile,
        };
        let image = ArmRootCapturedImage::import_authenticated_arm_archive(record, &verifier)
            .map_err(refusal)?;
        Ok(Self {
            image,
            continuation: Some(continuation),
            artifacts,
            root: root.to_owned(),
        })
    }
}

struct SignedRootVerifier<'a> {
    graph: &'a AdmittedGraph,
    continuation: &'a AuthenticatedArmRootContinuation,
    profile: &'a RootWorldProfile,
}

impl ArmRootArchiveSourceVerifier for SignedRootVerifier<'_> {
    fn verify_archive(&self, record: &ArmRootArchiveImport) -> Result<(), ProviderError> {
        check_selection(self.graph, self.continuation, self.profile).map_err(|_| {
            ProviderError::Correlation("Root signed source installed selection differs")
        })?;
        self.continuation
            .verify_imported_record(record)
            .map_err(|_| {
                ProviderError::Correlation(
                    "Root import differs from complete signed preparation/control ancestry",
                )
            })
    }
}

pub(super) fn check_selection(
    graph: &AdmittedGraph,
    source: &AuthenticatedArmRootContinuation,
    profile: &RootWorldProfile,
) -> Result<(), StateError> {
    let installed = InstalledArmRootMechanism::load().map_err(refusal)?;
    let native = source.native_source();
    if graph.world() != &profile.scenario.world
        || graph.node_ids().count() != 2
        || !graph.selected_extensions().is_empty()
        || native.owner.as_str() != "owner/root"
        || native.profile != profile.installed
        || native.bindings != profile.bindings
        || native.model_id != crucible::node_adapters::arm_root::ARM_ROOT_MODEL
        || native.native_dialect != crucible::node_adapters::arm_root::ARM_ROOT_DIALECT
        || source.maximum_events_per_poll().get() != 262_144
        || installed.document()["policy_id"] != native.model_id
    {
        return Err(refusal(
            "Root signed continuation differs from the fixed installed model and complete world",
        ));
    }
    for descriptor in &profile.scenario.descriptors {
        let selected = profile
            .scenario
            .compatibility
            .iter()
            .find(|binding| binding.node_id == descriptor.id)
            .ok_or_else(|| refusal("Root selected compatibility is absent"))?;
        if graph.descriptor(&descriptor.id) != Some(descriptor)
            || graph
                .binding(&descriptor.id)
                .is_none_or(|binding| &binding.compatibility != selected)
        {
            return Err(refusal(
                "Root source descriptor or full compatibility differs",
            ));
        }
    }
    Ok(())
}

fn refusal(error: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed Root source",
        error.to_string(),
    )
}
