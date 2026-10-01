//! Complete OCI graph capture and resumable candidate upload.
//!
//! Candidate records retain repository membership and every exact descriptor.
//! Transfers use the existing Distribution client and its durable upload-offset
//! checkpoints; manifests and indexes are uploaded by digest. Public version
//! and channel tags belong to the later verified Hub publication transaction.

use std::fs::{self, File};
use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aos_oci::RegistryReference;
use aos_oci::registry::{
    PushOptions, RegistryClient, ReleaseGraphPushResult, verified_release_graph,
};
use aos_oci_types::{ContainerRelease, ImageIndex, RepositoryName, to_canonical_json};
use aos_registry_surface::staging::{StageContainerGraph, StageObject, StageRevision};
use sha2::{Digest as _, Sha256};

/// Validates the complete source graph and binds it to an OCI repository.
///
/// # Errors
///
/// Returns an error for malformed repository names, missing graph members,
/// incorrect descriptor bytes, or a layout inconsistent with the release.
pub fn prepare_container_stage(
    layout: &Path,
    repository: &str,
    release: &ContainerRelease,
) -> Result<StageContainerGraph> {
    Ok(StageContainerGraph {
        repository: RepositoryName::parse(repository)?,
        release: release.clone(),
        descriptors: verified_release_graph(layout, release)?,
    })
}

/// Projects the graph into exact physical OCI digest storage keys.
pub fn graph_objects(graph: &StageContainerGraph) -> Vec<StageObject> {
    graph
        .descriptors
        .iter()
        .map(|descriptor| StageObject {
            path: format!("oci/blobs/sha256/{}", descriptor.digest.encoded()),
            sha256: descriptor.digest.to_string(),
            byte_size: descriptor.size,
            kind: if descriptor.media_type.is_image_index()
                || descriptor.media_type.is_image_manifest()
            {
                "oci_manifest".into()
            } else {
                "oci_blob".into()
            },
            media_type: descriptor.media_type.to_string(),
        })
        .collect()
}

/// Captures exact graph bytes in the candidate's private content-addressed store.
///
/// # Errors
///
/// Returns an error for changed source bytes, missing descriptors, collisions,
/// or filesystem failures. Complete graph validation precedes any capture.
pub fn capture_layout_objects(
    layout: &Path,
    graph: &StageContainerGraph,
    object_directory: &Path,
) -> Result<()> {
    ensure!(
        verified_release_graph(layout, &graph.release)? == graph.descriptors,
        "container source graph changed since candidate preparation"
    );
    fs::create_dir_all(object_directory)?;
    for descriptor in &graph.descriptors {
        let source = layout
            .join("blobs/sha256")
            .join(descriptor.digest.encoded());
        let destination = object_directory.join(descriptor.digest.encoded());
        if destination.exists() {
            verify_object(&destination, descriptor)?;
            continue;
        }
        let mut input = File::open(&source)?;
        let mut temporary = tempfile::NamedTempFile::new_in(object_directory)?;
        std::io::copy(&mut input, &mut temporary)?;
        temporary.as_file().sync_all()?;
        verify_object(temporary.path(), descriptor)?;
        match temporary.persist_noclobber(&destination) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_object(&destination, descriptor)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Resolves durable upload checkpoints for an exact OCI origin and repository.
///
/// # Errors
///
/// Returns an error when the origin is invalid or the user cache is unavailable.
pub fn container_upload_state_directory(
    origin: &str,
    repository: &RepositoryName,
) -> Result<std::path::PathBuf> {
    let parsed = url::Url::parse(origin)?;
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cache"))
        })
        .context("HOME or XDG_CACHE_HOME is required for resumable container upload state")?;
    let mut digest = Sha256::new();
    digest.update(parsed.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(repository.as_str().as_bytes());
    Ok(cache
        .join("aos/oci/staged-uploads")
        .join(hex::encode(digest.finalize())))
}

/// Uploads retained candidate bytes into their real Distribution repository.
///
/// The candidate must already exist before transfer begins. Its checkpoint
/// directory persists upload locations and server-confirmed offsets, making
/// an interrupted transfer resumable without changing the candidate revision.
///
/// # Errors
///
/// Returns an error for corrupt local inventory, invalid registry origins,
/// incomplete graphs, authentication failures, or Distribution transfer errors.
pub async fn upload_container_stage(
    candidate: &StageRevision,
    object_directory: &Path,
    origin: &str,
    token: Option<String>,
    state_directory: &Path,
) -> Result<ReleaseGraphPushResult> {
    let options = PushOptions::native(
        object_directory.to_path_buf(),
        state_directory.to_path_buf(),
    );
    upload_container_stage_with_options(candidate, object_directory, origin, token, &options, &[])
        .await
}

/// Uploads retained OCI bytes with the caller's cancellation and progress hooks.
///
/// # Errors
///
/// Returns an error for corrupt inventory, invalid origins, incomplete graphs,
/// authentication, cancellation, or Distribution transfer failures.
pub async fn upload_container_stage_with_options(
    candidate: &StageRevision,
    object_directory: &Path,
    origin: &str,
    token: Option<String>,
    options: &PushOptions,
    mount_sources: &[RepositoryName],
) -> Result<ReleaseGraphPushResult> {
    candidate.validate()?;
    let graph = candidate
        .container
        .as_ref()
        .context("candidate has no container graph")?;
    graph.validate(&candidate.inventory, &candidate.release_id)?;
    let origin = url::Url::parse(origin)?;
    ensure!(
        matches!(origin.scheme(), "http" | "https")
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "OCI candidate origin must be an HTTP(S) Distribution root"
    );
    let authority = origin[url::Position::BeforeHost..url::Position::AfterPort].to_string();
    ensure!(
        !authority.is_empty(),
        "OCI candidate origin lacks a registry authority"
    );
    let reference = RegistryReference::parse(&format!(
        "{}/{}@{}",
        authority, graph.repository, graph.release.oci.index.digest,
    ))?;
    let client = RegistryClient::new(&reference, Some(origin.as_str()), token)?;
    let layout = retained_container_layout(graph, object_directory)?;
    let mut options = options.clone();
    options.source = layout.path().to_path_buf();
    client
        .push_release_graph(&reference, &options, &graph.release, mount_sources)
        .await
}

/// Verifies the retained bytes form the exact declared closed OCI graph.
///
/// Static origins use this same verifier before transferring canonical digest
/// keys. Signed Git release metadata remains their version authority.
///
/// # Errors
///
/// Returns an error for missing or corrupt bytes, changed graph membership,
/// invalid signed roots, or filesystem failures.
pub fn verify_container_stage_objects(
    graph: &StageContainerGraph,
    object_directory: &Path,
) -> Result<()> {
    graph.validate(&graph_objects(graph), &graph.release.identity.release)?;
    let layout = retained_container_layout(graph, object_directory)?;
    ensure!(
        verified_release_graph(layout.path(), &graph.release)? == graph.descriptors,
        "retained container bytes differ from the prepared closed graph"
    );
    Ok(())
}

fn retained_container_layout(
    graph: &StageContainerGraph,
    object_directory: &Path,
) -> Result<tempfile::TempDir> {
    let layout = tempfile::TempDir::new_in(object_directory)?;
    fs::create_dir_all(layout.path().join("blobs/sha256"))?;
    for descriptor in &graph.descriptors {
        let source = object_directory.join(descriptor.digest.encoded());
        verify_object(&source, descriptor)?;
        let destination = layout
            .path()
            .join("blobs/sha256")
            .join(descriptor.digest.encoded());
        // Both paths share the private candidate filesystem. Hard links keep
        // multi-gigabyte retries cheap; neither verifier nor upload mutates them.
        if let Err(error) = fs::hard_link(&source, &destination) {
            if error.kind() == std::io::ErrorKind::CrossesDevices {
                fs::copy(&source, &destination)?;
            } else {
                return Err(error).context("linking retained OCI candidate object");
            }
        }
    }
    let index = ImageIndex::from_json(&serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [graph.release.oci.index],
    }))?)?;
    fs::write(layout.path().join("index.json"), to_canonical_json(&index)?)?;
    fs::write(
        layout.path().join("oci-layout"),
        b"{\"imageLayoutVersion\":\"1.0.0\"}",
    )?;
    Ok(layout)
}

fn verify_object(path: &Path, descriptor: &aos_oci_types::Descriptor) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() == descriptor.size,
        "container stage object has unexpected type or size: {}",
        path.display()
    );
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ensure!(
        hex::encode(hash.finalize()) == descriptor.digest.encoded(),
        "container stage object differs from its signed digest: {}",
        path.display()
    );
    Ok(())
}
