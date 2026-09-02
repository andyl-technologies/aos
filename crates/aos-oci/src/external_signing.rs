//! Private-key-free finalization of externally signed container publications.
//!
//! A hermetic Nix build emits an unsigned `publicationInputs` directory. This
//! module derives the exact DSSE pre-authentication bytes for an external
//! signer, then verifies the returned SSHSIG against an explicit AOS trust
//! identity before assembling the signed OCI graph. Private key material is
//! never accepted by this API.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_oci_types::limits::MAX_JSON_BYTES;
use aos_oci_types::{
    Annotations, CONTAINER_DSSE_SIGNATURE_NAMESPACE, CONTAINER_RELEASE_SCHEMA_VERSION,
    CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE, ContainerDsseEnvelope, ContainerDsseSignature,
    ContainerRelease, ContainerReleaseEvidence, ContainerSignatureInput, Descriptor, ImageIndex,
    ImageManifest, MediaType, Sha256Digest, to_canonical_json,
};
use base64::Engine as _;
use serde_json::Value;
use tar::{Builder, EntryType, Header};

use crate::layout::{open_verified_blob, read_root_file, read_verified_blob};

const OCI_LAYOUT_MARKER: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;
const MAX_GRAPH_OBJECTS: usize = 100_000;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

/// Exact paths and signed release identity installed by external finalization.
#[derive(Clone, Debug)]
pub struct FinalizedContainerPublication {
    /// Atomically installed bundle directory.
    pub bundle: PathBuf,
    /// Complete OCI image-layout directory within [`Self::bundle`].
    pub layout: PathBuf,
    /// Deterministic uncompressed OCI archive within [`Self::bundle`].
    pub archive: PathBuf,
    /// Canonical signed container-release sidecar within [`Self::bundle`].
    pub release: PathBuf,
    /// Canonical unsigned input copied into [`Self::bundle`].
    pub signature_input: PathBuf,
    /// Exact signed release declaration.
    pub declaration: ContainerRelease,
}

/// Returns the exact DSSE PAE bytes authorized by an external signer.
///
/// `inputs` must name a complete `publicationInputs` directory. The canonical
/// signature input, signing request, publication roots, image layout, and
/// evidence graph are checked before bytes are returned.
///
/// # Errors
///
/// Returns an error when the input bundle is malformed, unqualified, changed,
/// non-canonical, or missing any exact descriptor in its bounded OCI graph.
pub fn container_signature_pae(inputs: &Path) -> Result<Vec<u8>> {
    let validated = validate_publication_inputs(inputs)?;
    Ok(dsse_pae(&validated.signature_input_bytes))
}

/// Writes exact external-signing bytes without overwriting an existing path.
///
/// The destination is created through a same-directory temporary file and a
/// no-clobber persist after the complete publication input has been validated.
///
/// # Errors
///
/// Returns an error under the same conditions as [`container_signature_pae`],
/// when the output parent is absent, when the destination already exists, or
/// when the durable no-clobber write fails.
pub fn write_container_signature_pae(inputs: &Path, output: &Path) -> Result<Vec<u8>> {
    let pae = container_signature_pae(inputs)?;
    let parent = output_parent(output);
    ensure!(parent.is_dir(), "signature output parent does not exist");
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .context("creating external-signing PAE temporary file")?;
    temporary
        .write_all(&pae)
        .context("writing external-signing PAE bytes")?;
    temporary
        .as_file_mut()
        .sync_all()
        .context("syncing external-signing PAE bytes")?;
    temporary
        .persist_noclobber(output)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "installing PAE output {} without overwrite",
                output.display()
            )
        })?;
    sync_directory(parent)?;
    Ok(pae)
}

/// Verifies an external SSHSIG and atomically installs a complete signed bundle.
///
/// `signer` is the exact `name:Ed25519:<base64 SSH public-key blob>` identity
/// printed by AOS key tooling. `signature` is armored SSHSIG output from an
/// external signer using namespace [`CONTAINER_DSSE_SIGNATURE_NAMESPACE`]. The
/// output bundle must not exist and contains fixed `layout/`, `image.oci.tar`,
/// `container-release.json`, and `signature-input.json` children.
///
/// All input and signature validation completes before the staging directory
/// is created. Installation is one same-directory `RENAME_NOREPLACE`, so a
/// failed operation cannot expose a partial or overwritten final bundle.
///
/// # Errors
///
/// Returns an error for malformed or unqualified inputs, a malformed signer,
/// an invalid/wrong-key/wrong-namespace signature, graph corruption, an
/// existing output, an unsafe output path, or any staging, sync, or atomic
/// installation failure.
pub fn finalize_container_publication(
    inputs: &Path,
    signer: &str,
    signature: &Path,
    output: &Path,
) -> Result<FinalizedContainerPublication> {
    let validated = validate_publication_inputs(inputs)?;
    let signer_key = exact_signer_key(signer)?;
    let signature_bytes = read_regular_bounded(signature, "armored SSHSIG", MAX_SIGNATURE_BYTES)?;
    let armored = std::str::from_utf8(&signature_bytes).context("armored SSHSIG is not UTF-8")?;
    let pae = dsse_pae(&validated.signature_input_bytes);
    let verified_key = aos_registry_surface::sshsig::verify_armored_namespace(
        armored,
        &pae,
        &[signer.to_string()],
        CONTAINER_DSSE_SIGNATURE_NAMESPACE,
    )
    .context("verifying external container SSHSIG")?;
    ensure!(
        verified_key == signer_key,
        "verified SSHSIG key differs from the exact supplied signer identity"
    );

    let envelope = ContainerDsseEnvelope {
        payload_type: CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE.to_string(),
        payload: base64::engine::general_purpose::STANDARD.encode(&validated.signature_input_bytes),
        signatures: vec![ContainerDsseSignature {
            keyid: signer_key,
            sig: base64::engine::general_purpose::STANDARD.encode(&signature_bytes),
        }],
    };
    let envelope_bytes =
        to_canonical_json(&envelope).context("encoding canonical DSSE envelope")?;
    ensure!(
        envelope.pae()? == pae,
        "DSSE envelope changed the exact externally signed PAE bytes"
    );
    let (release, generated) = signed_release(&validated.signature_input, &envelope_bytes)?;
    validated
        .signature_input
        .validate_final_release(&release)
        .context("binding final sidecar to the externally signed input")?;

    let parent = fs::canonicalize(output_parent(output))
        .context("resolving finalized bundle output parent")?;
    ensure!(
        parent.is_dir(),
        "finalized bundle output parent is not a directory"
    );
    let output_name = output
        .file_name()
        .context("finalized bundle output must have one file name")?;
    ensure!(
        output
            .parent()
            .map_or(true, |candidate| candidate == output_parent(output)),
        "finalized bundle output path is malformed"
    );
    ensure!(
        fs::symlink_metadata(output)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "finalized bundle output already exists"
    );

    let staging = tempfile::Builder::new()
        .prefix(".aos-container-finalize-")
        .tempdir_in(&parent)
        .context("creating finalized publication staging directory")?;
    let layout = staging.path().join("layout");
    fs::create_dir(&layout).context("creating finalized OCI layout")?;
    write_complete_layout(&validated, &generated, &layout)?;
    validate_finalized_graph(&layout, &release)?;

    let release_bytes = to_canonical_json(&release).context("encoding final container release")?;
    write_new_file(
        &staging.path().join("container-release.json"),
        &release_bytes,
    )?;
    write_new_file(
        &staging.path().join("signature-input.json"),
        &validated.signature_input_bytes,
    )?;
    write_complete_archive(&layout, &staging.path().join("image.oci.tar"))?;
    sync_directory(&layout.join("blobs/sha256"))?;
    sync_directory(&layout.join("blobs"))?;
    sync_directory(&layout)?;
    sync_directory(staging.path())?;

    let staging_path = staging.keep();
    let staging_name = staging_path
        .file_name()
        .context("publication staging path lost its file name")?;
    let parent_handle = File::open(&parent).context("opening finalized bundle output parent")?;
    rustix::fs::renameat_with(
        &parent_handle,
        staging_name,
        &parent_handle,
        output_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .context("atomically installing finalized publication bundle without overwrite")?;
    rustix::fs::fsync(&parent_handle).context("syncing finalized bundle output parent")?;

    let bundle = parent.join(output_name);
    Ok(FinalizedContainerPublication {
        layout: bundle.join("layout"),
        archive: bundle.join("image.oci.tar"),
        release: bundle.join("container-release.json"),
        signature_input: bundle.join("signature-input.json"),
        bundle,
        declaration: release,
    })
}

struct ValidatedInputs {
    signature_input: ContainerSignatureInput,
    signature_input_bytes: Vec<u8>,
    evidence_layout: PathBuf,
    objects: BTreeMap<Sha256Digest, Descriptor>,
}

fn validate_publication_inputs(inputs: &Path) -> Result<ValidatedInputs> {
    let metadata = fs::metadata(inputs)
        .with_context(|| format!("reading publication inputs metadata {}", inputs.display()))?;
    ensure!(metadata.is_dir(), "publication inputs must be a directory");

    let signature_input_path = inputs.join("signature-input.json");
    let signature_input_bytes = read_regular_bounded(
        &signature_input_path,
        "canonical container signature input",
        MAX_JSON_BYTES,
    )?;
    let signature_input = ContainerSignatureInput::from_canonical_json(&signature_input_bytes)
        .context("validating canonical container signature input")?;
    ensure!(
        signature_input.qualification.ready_for_verified_publication,
        "container signature input is not ready for verified publication"
    );
    validate_signing_request(inputs, &signature_input, &signature_input_bytes)?;
    validate_publication_roots(inputs, &signature_input)?;

    let image_layout = inputs.join("oci-layout");
    let evidence_layout = inputs.join("evidence-layout");
    let image_index =
        read_root_file(&image_layout, "index.json").context("reading publication image index")?;
    let evidence_index = read_root_file(&evidence_layout, "index.json")
        .context("reading publication evidence index")?;
    ensure!(
        image_index == evidence_index,
        "publication image and evidence layouts contain different root indexes"
    );
    ensure!(
        read_root_file(&image_layout, "oci-layout")? == OCI_LAYOUT_MARKER,
        "publication image layout marker is not canonical OCI 1.0"
    );
    ensure!(
        read_root_file(&evidence_layout, "oci-layout")? == OCI_LAYOUT_MARKER,
        "publication evidence layout marker is not canonical OCI 1.0"
    );

    let layout_index =
        ImageIndex::from_json(&image_index).context("validating publication layout index")?;
    ensure!(
        layout_index.manifests == vec![signature_input.oci.index.clone()],
        "publication layout index does not contain the exact signed root descriptor"
    );
    let root_index_bytes = read_verified_blob(&evidence_layout, &signature_input.oci.index)
        .context("binding publication layouts to the signed root index")?;
    let root_index = ImageIndex::from_json(&root_index_bytes)
        .context("validating signed publication root index")?;
    ensure!(
        root_index.manifests == signature_input.oci.platform_manifests,
        "publication root index platform manifests differ from signature input"
    );
    let roots = unsigned_roots(&signature_input);
    let objects = validate_graph(&evidence_layout, &roots, &signature_input.oci.index)?;
    Ok(ValidatedInputs {
        signature_input,
        signature_input_bytes,
        evidence_layout,
        objects,
    })
}

fn validate_signing_request(
    inputs: &Path,
    input: &ContainerSignatureInput,
    input_bytes: &[u8],
) -> Result<()> {
    let bytes = read_regular_bounded(
        &inputs.join("signing-request.json"),
        "container signing request",
        MAX_JSON_BYTES,
    )?;
    let request: Value =
        serde_json::from_slice(&bytes).context("decoding container signing request")?;
    ensure!(
        request["schema"] == "aos.container.signing-request/v1",
        "unexpected container signing request schema"
    );
    ensure!(
        request["qualified"] == true,
        "container signing request is not qualified"
    );
    ensure!(
        request["input"]["mediaType"] == CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE
            && request["input"]["digest"] == Sha256Digest::digest(input_bytes).to_string()
            && request["input"]["size"] == input_bytes.len(),
        "container signing request does not bind the exact signature input"
    );
    let mut unsigned = serde_json::to_value(input).context("encoding unsigned release identity")?;
    unsigned
        .as_object_mut()
        .context("container signature input did not encode as an object")?
        .remove("schema");
    ensure!(
        request["unsignedRelease"] == unsigned,
        "container signing request unsigned release differs from signature input"
    );
    for constraint in [
        "exactInputBytesRequired",
        "privateMaterialPermittedInNixBuild",
        "finalizerMustRejectUnqualifiedInput",
        "finalizerMustVerifyEnvelope",
        "finalizerMustAddSignatureReferrerDescriptor",
        "releaseSurfaceMustSignFinalSidecar",
    ] {
        let expected = constraint != "privateMaterialPermittedInNixBuild";
        ensure!(
            request["constraints"][constraint] == expected,
            "container signing request constraint {constraint} drifted"
        );
    }
    Ok(())
}

fn validate_publication_roots(inputs: &Path, input: &ContainerSignatureInput) -> Result<()> {
    let bytes = read_regular_bounded(
        &inputs.join("publication-roots.json"),
        "container publication roots",
        MAX_JSON_BYTES,
    )?;
    let roots: Value =
        serde_json::from_slice(&bytes).context("decoding container publication roots")?;
    ensure!(
        roots["schema"] == "aos.container.publication-roots/v1",
        "unexpected container publication roots schema"
    );
    ensure!(
        roots["image"] == serde_json::to_value(&input.oci.index)?,
        "container publication root index differs from signature input"
    );
    let mut expected = unsigned_evidence(input)
        .into_iter()
        .map(|descriptor| serde_json::to_value(descriptor))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    expected.sort_by_key(Value::to_string);
    let mut observed = roots["referrers"]
        .as_array()
        .context("container publication referrers must be an array")?
        .clone();
    observed.sort_by_key(Value::to_string);
    ensure!(
        observed == expected,
        "container publication referrer roots differ from signature input"
    );
    Ok(())
}

fn unsigned_evidence(input: &ContainerSignatureInput) -> Vec<&Descriptor> {
    vec![
        &input.nix.closure,
        &input.evidence.sbom,
        &input.evidence.source,
        &input.evidence.license,
        &input.evidence.provenance,
    ]
}

fn unsigned_roots(input: &ContainerSignatureInput) -> Vec<Descriptor> {
    let mut roots = vec![input.oci.index.clone()];
    roots.extend(unsigned_evidence(input).into_iter().cloned());
    roots
}

fn validate_graph(
    layout: &Path,
    roots: &[Descriptor],
    subject: &Descriptor,
) -> Result<BTreeMap<Sha256Digest, Descriptor>> {
    let mut objects = BTreeMap::new();
    let evidence = roots
        .iter()
        .skip(1)
        .map(|root| root.digest)
        .collect::<BTreeSet<_>>();
    for root in roots {
        visit_descriptor(layout, root, subject, &evidence, &mut objects)?;
    }
    ensure!(
        objects.len() <= MAX_GRAPH_OBJECTS,
        "container publication graph exceeds object bound"
    );
    Ok(objects)
}

fn visit_descriptor(
    layout: &Path,
    descriptor: &Descriptor,
    subject: &Descriptor,
    evidence_roots: &BTreeSet<Sha256Digest>,
    objects: &mut BTreeMap<Sha256Digest, Descriptor>,
) -> Result<()> {
    if let Some(previous) = objects.get(&descriptor.digest) {
        ensure!(
            previous.size == descriptor.size && previous.media_type == descriptor.media_type,
            "one OCI digest was declared with conflicting descriptor identity"
        );
        return Ok(());
    }
    ensure!(
        objects.len() < MAX_GRAPH_OBJECTS,
        "container publication graph exceeds object bound"
    );
    objects.insert(descriptor.digest, descriptor.clone());

    if descriptor.media_type.is_image_index() {
        let bytes = read_verified_blob(layout, descriptor)?;
        let index = ImageIndex::from_json(&bytes).context("validating publication graph index")?;
        for child in &index.manifests {
            visit_descriptor(layout, child, subject, evidence_roots, objects)?;
        }
    } else if descriptor.media_type.is_image_manifest() {
        let bytes = read_verified_blob(layout, descriptor)?;
        let manifest =
            ImageManifest::from_json(&bytes).context("validating publication graph manifest")?;
        if evidence_roots.contains(&descriptor.digest) {
            ensure!(
                manifest.subject.as_ref() == Some(subject),
                "evidence manifest subject differs from signed root index"
            );
            ensure!(
                manifest.artifact_type == descriptor.artifact_type,
                "evidence manifest artifact type differs from its root descriptor"
            );
        }
        visit_descriptor(layout, &manifest.config, subject, evidence_roots, objects)?;
        for child in &manifest.layers {
            visit_descriptor(layout, child, subject, evidence_roots, objects)?;
        }
    } else {
        open_verified_blob(layout, descriptor)
            .with_context(|| format!("verifying publication graph object {}", descriptor.digest))?;
    }
    Ok(())
}

fn signed_release(
    input: &ContainerSignatureInput,
    envelope: &[u8],
) -> Result<(ContainerRelease, BTreeMap<Sha256Digest, Vec<u8>>)> {
    let envelope_descriptor = descriptor(MediaType::DsseEnvelope, envelope, None);
    let empty = b"{}".to_vec();
    let empty_descriptor = descriptor(MediaType::OciEmptyJson, &empty, None);
    let signature_manifest = ImageManifest {
        schema_version: 2,
        media_type: Some(MediaType::OciImageManifest),
        artifact_type: Some(MediaType::DsseEnvelope),
        config: empty_descriptor.clone(),
        layers: vec![envelope_descriptor],
        subject: Some(input.oci.index.clone()),
        annotations: Annotations::new(),
    };
    signature_manifest.validate()?;
    let signature_manifest = to_canonical_json(&signature_manifest)?;
    let mut signature_descriptor = descriptor(
        MediaType::OciImageManifest,
        &signature_manifest,
        Some(MediaType::DsseEnvelope),
    );
    signature_descriptor.artifact_type = Some(MediaType::DsseEnvelope);

    let release = ContainerRelease {
        schema_version: CONTAINER_RELEASE_SCHEMA_VERSION,
        media_type: MediaType::AosContainerRelease,
        identity: input.identity.clone(),
        oci: input.oci.clone(),
        nix: input.nix.clone(),
        qualification: input.qualification.clone(),
        evidence: ContainerReleaseEvidence {
            sbom: input.evidence.sbom.clone(),
            source: input.evidence.source.clone(),
            license: input.evidence.license.clone(),
            provenance: input.evidence.provenance.clone(),
            signature: signature_descriptor,
        },
    };
    release.validate()?;

    let mut generated = BTreeMap::new();
    for bytes in [empty, envelope.to_vec(), signature_manifest] {
        generated.insert(Sha256Digest::digest(&bytes), bytes);
    }
    Ok((release, generated))
}

fn descriptor(media_type: MediaType, bytes: &[u8], artifact_type: Option<MediaType>) -> Descriptor {
    Descriptor {
        media_type,
        digest: Sha256Digest::digest(bytes),
        size: bytes.len() as u64,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type,
        platform: None,
    }
}

fn write_complete_layout(
    validated: &ValidatedInputs,
    generated: &BTreeMap<Sha256Digest, Vec<u8>>,
    output: &Path,
) -> Result<()> {
    let blobs = output.join("blobs/sha256");
    fs::create_dir_all(&blobs).context("creating finalized OCI blob directory")?;
    write_new_file(&output.join("oci-layout"), OCI_LAYOUT_MARKER)?;
    let index = read_root_file(&validated.evidence_layout, "index.json")?;
    write_new_file(&output.join("index.json"), &index)?;

    for (digest, descriptor) in &validated.objects {
        let path = blobs.join(digest.encoded());
        if let Some(bytes) = generated.get(digest) {
            ensure!(
                descriptor.size == bytes.len() as u64,
                "generated OCI object size drifted"
            );
            write_new_file(&path, bytes)?;
            continue;
        }
        let mut source = open_verified_blob(&validated.evidence_layout, descriptor)?;
        let mut destination = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating finalized OCI blob {}", path.display()))?;
        let copied = std::io::copy(&mut source, &mut destination)?;
        ensure!(
            copied == descriptor.size,
            "OCI object changed while finalizing"
        );
        destination.sync_all()?;
    }
    for (digest, bytes) in generated {
        let path = blobs.join(digest.encoded());
        if !path.exists() {
            write_new_file(&path, bytes)?;
        }
    }
    Ok(())
}

fn validate_finalized_graph(layout: &Path, release: &ContainerRelease) -> Result<()> {
    let roots = vec![
        release.oci.index.clone(),
        release.nix.closure.clone(),
        release.evidence.sbom.clone(),
        release.evidence.source.clone(),
        release.evidence.license.clone(),
        release.evidence.provenance.clone(),
        release.evidence.signature.clone(),
    ];
    let objects = validate_graph(layout, &roots, &release.oci.index)?;
    ensure!(
        objects.len() >= roots.len(),
        "finalized OCI graph lost a release root"
    );
    Ok(())
}

fn write_complete_archive(layout: &Path, output: &Path) -> Result<()> {
    let index = read_root_file(layout, "index.json")?;
    let marker = read_root_file(layout, "oci-layout")?;
    let mut blobs = fs::read_dir(layout.join("blobs/sha256"))
        .context("reading finalized OCI blobs for archive")?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    blobs.sort();

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .with_context(|| format!("creating finalized OCI archive {}", output.display()))?;
    {
        let mut builder = Builder::new(&mut file);
        builder.mode(tar::HeaderMode::Deterministic);
        append_directory(&mut builder, Path::new("blobs"))?;
        append_directory(&mut builder, Path::new("blobs/sha256"))?;
        for blob in blobs {
            let metadata = fs::symlink_metadata(&blob)?;
            ensure!(
                metadata.is_file(),
                "finalized OCI archive encountered a non-file blob"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                ensure!(
                    metadata.nlink() == 1,
                    "finalized OCI blob must not be hard-linked"
                );
            }
            let mut source = File::open(&blob)?;
            let name = blob
                .file_name()
                .context("finalized OCI blob lost its name")?;
            append_reader(
                &mut builder,
                &Path::new("blobs/sha256").join(name),
                &mut source,
                metadata.len(),
            )?;
        }
        append_bytes(&mut builder, Path::new("index.json"), &index)?;
        append_bytes(&mut builder, Path::new("oci-layout"), &marker)?;
        builder
            .finish()
            .context("finishing finalized OCI archive")?;
    }
    file.sync_all().context("syncing finalized OCI archive")
}

fn append_directory(builder: &mut Builder<&mut File>, path: &Path) -> Result<()> {
    let mut header = normalized_header(0, 0o755, EntryType::Directory)?;
    builder.append_data(&mut header, path, std::io::empty())?;
    Ok(())
}

fn append_bytes(builder: &mut Builder<&mut File>, path: &Path, bytes: &[u8]) -> Result<()> {
    append_reader(builder, path, &mut &bytes[..], bytes.len() as u64)
}

fn append_reader(
    builder: &mut Builder<&mut File>,
    path: &Path,
    reader: &mut impl Read,
    size: u64,
) -> Result<()> {
    let mut header = normalized_header(size, 0o644, EntryType::Regular)?;
    builder.append_data(&mut header, path, reader)?;
    Ok(())
}

fn normalized_header(size: u64, mode: u32, entry_type: EntryType) -> Result<Header> {
    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1);
    header.set_entry_type(entry_type);
    header.set_username("")?;
    header.set_groupname("")?;
    header.set_cksum();
    Ok(header)
}

fn exact_signer_key(signer: &str) -> Result<String> {
    let (name, algorithm, key) = signer
        .split_once(':')
        .and_then(|(name, rest)| rest.split_once(':').map(|parts| (name, parts.0, parts.1)))
        .context("--signer must be name:Ed25519:<base64 SSH public-key blob>")?;
    ensure!(!name.is_empty(), "--signer name must not be empty");
    ensure!(algorithm == "Ed25519", "--signer algorithm must be Ed25519");
    ensure!(
        !key.is_empty() && !key.contains(':'),
        "--signer key blob is malformed"
    );
    let (parsed_name, _) = aos_registry_surface::sshsig::trusted_key_ed25519(signer)
        .context("decoding exact --signer identity")?;
    ensure!(
        parsed_name == name,
        "--signer identity changed while decoding"
    );
    Ok(key.to_string())
}

fn dsse_pae(payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::with_capacity(
        payload
            .len()
            .saturating_add(CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE.len())
            .saturating_add(64),
    );
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(
        CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE
            .len()
            .to_string()
            .as_bytes(),
    );
    pae.push(b' ');
    pae.extend_from_slice(CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

fn read_regular_bounded(path: &Path, label: &str, limit: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {label} metadata {}", path.display()))?;
    ensure!(metadata.is_file(), "{label} must be a regular file");
    ensure!(
        metadata.len() <= limit as u64,
        "{label} exceeds its byte limit"
    );
    let bytes = fs::read(path).with_context(|| format!("reading {label} {}", path.display()))?;
    ensure!(
        bytes.len() <= limit,
        "{label} changed or exceeds its byte limit"
    );
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory =
        File::open(path).with_context(|| format!("opening directory {}", path.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_dsse_v1_length_framing() {
        let payload = br#"{"schema":"aos.container.signature-input/v1"}"#;
        let expected = format!(
            "DSSEv1 {} {} {} ",
            CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE.len(),
            CONTAINER_SIGNATURE_INPUT_MEDIA_TYPE,
            payload.len(),
        )
        .into_bytes();
        let mut expected = expected;
        expected.extend_from_slice(payload);
        assert_eq!(dsse_pae(payload), expected);
    }

    #[test]
    fn exact_signer_rejects_bare_or_wrong_algorithm_identity() {
        assert!(exact_signer_key("AAAA").is_err());
        assert!(exact_signer_key("release:RSA:AAAA").is_err());
        assert!(exact_signer_key(":Ed25519:AAAA").is_err());
    }
}
