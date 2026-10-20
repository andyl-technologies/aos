//! Qualifies actual protected intent, owner journals and present or absent artifacts.

use super::*;

/// Fixes a neutral observation beneath a genuine current collection Frame.
pub(in super::super::super) struct ObservationRequest {
    root: PathBuf,
    control: PathBuf,
    key: String,
    bytes: Vec<u8>,
    journals: [Vec<u8>; 3],
    generation: u64,
    owner: u32,
    result: mpsc::Sender<NativeLocalDeletion>,
}

/// Receives only an actual completed native observation.
pub(in super::super::super) struct ObservationReceiver(mpsc::Receiver<NativeLocalDeletion>);

impl ObservationReceiver {
    /// Takes the native result once, refusing fabricated unit completion.
    ///
    /// # Errors
    /// Refuses an unexecuted, failed or no-op observation.
    pub(in super::super::super) fn take(self) -> Result<NativeLocalDeletion, NativeEffectFailure> {
        self.0
            .try_recv()
            .map_err(|_| invalid("owned observation acknowledgment absent").into())
    }
}

/// Fixes observation inputs derived only inside the retained current producer.
///
/// # Errors
/// Refuses malformed operation bytes or an unrelated registered operation key.
pub(in super::super::super) fn plan(
    root: &Path,
    control: &Path,
    key: &str,
    bytes: Vec<u8>,
    journals: [Vec<u8>; 3],
    generation: u64,
    owner: u32,
) -> Result<(Plan, ObservationReceiver), NativeEffectFailure> {
    DeleteOperation::decode(&bytes, key).map_err(io::Error::other)?;
    let (result, receiver) = mpsc::channel();
    Ok((
        Plan::ObserveLocalDeletion(Box::new(ObservationRequest {
            root: root.to_owned(),
            control: control.to_owned(),
            key: key.to_owned(),
            bytes,
            journals,
            generation,
            owner,
            result,
        })),
        ObservationReceiver(receiver),
    ))
}

fn protected(worker: &Worker, path: PathBuf, bytes: &[u8], owner: u32) -> io::Result<Protected> {
    let read = worker.projection.exact(&path, Some(bytes))?;
    if !matches!(read.policy, FencePolicy::ProtectedRecord { owner: actual } if actual == owner) {
        return Err(invalid("owned evidence lacks protected current preimage"));
    }
    let mut file = open_native(&path, false)?;
    let stamp = MetadataStamp::checked(&file.metadata()?)?;
    checked_protected(&mut file, &path, stamp, bytes, owner)?;
    Ok(Protected {
        path,
        file,
        stamp,
        bytes: bytes.to_vec(),
        owner,
    })
}

fn identity(stamp: MetadataStamp) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&stamp.identity.0.to_be_bytes());
    bytes[8..].copy_from_slice(&stamp.identity.1.to_be_bytes());
    bytes
}

// Deletion recovery verifies the binding without allocating a whole data pack.
// This is not marking or decoding chunk bodies; the domain is the fixed v1 profile.
fn verify_file(file: &mut File, binding: &ArtifactBinding) -> io::Result<()> {
    let (kind, digest, size) = match binding {
        ArtifactBinding::Pack { digest, size } => (IdentityKind::Pack, digest, *size),
        ArtifactBinding::Index { digest, size } => (IdentityKind::Index, digest, *size),
        ArtifactBinding::Trash(bytes) => {
            file.seek(SeekFrom::Start(0))?;
            let mut actual = vec![0; bytes.len()];
            file.read_exact(&mut actual)?;
            if &actual != bytes || file.metadata()?.len() != bytes.len() as u64 {
                return Err(invalid("owned Trash body changed"));
            }
            return Ok(());
        }
    };
    if file.metadata()?.len() != size {
        return Err(invalid("owned artifact length changed"));
    }
    let mut hash = blake3::Hasher::new();
    hash.update(
        TERRANE_V1
            .domain(kind)
            .map_err(io::Error::other)?
            .as_bytes(),
    );
    hash.update(&[0]);
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = size;
    let mut buffer = [0; 64 * 1024];
    while remaining != 0 {
        let amount =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(io::Error::other)?;
        file.read_exact(&mut buffer[..amount])?;
        hash.update(&buffer[..amount]);
        remaining -= amount as u64;
    }
    if hash.finalize().as_bytes() != digest {
        return Err(invalid("owned artifact binding changed"));
    }
    Ok(())
}

/// Completes the real protected and physical observation under current exclusions.
///
/// # Errors
/// Refuses unsafe roots, mismatched ownership, replacements or unknown absence.
pub(in super::super) fn execute(
    request: ObservationRequest,
    worker: Worker,
) -> Result<(), NativeEffectFailure> {
    worker
        .projection
        .root(&request.root, request.owner, false)?;
    worker
        .projection
        .root(&request.control, request.owner, true)?;
    worker.refresh(&[])?;
    let operation =
        DeleteOperation::decode(&request.bytes, &request.key).map_err(io::Error::other)?;
    let authorization = operation.authorization.digest().map_err(io::Error::other)?;
    let snapshot =
        PackIndexSnapshot::decode(&operation.authorization.index_witness, request.generation)
            .map_err(io::Error::other)?;
    let intent = protected(
        &worker,
        request.control.join(&request.key),
        &request.bytes,
        request.owner,
    )?;
    let mut artifacts = Vec::new();
    let mut journals = Vec::new();
    let mut committed_seen = false;
    let mut remaining_seen = false;
    for (index, version) in operation.authorization.artifacts.iter().enumerate() {
        worker.refresh(&[])?;
        let journal =
            CreationJournal::decode(&request.journals[index]).map_err(io::Error::other)?;
        if journal.key != version.key || journal.nonce != version.nonce {
            return Err(invalid("owned artifact nonce changed").into());
        }
        let owned = match &journal.state {
            JournalState::DeleteOwned {
                binding,
                file_identity,
                operation_key,
                authorization: digest,
            } if binding == &version.binding
                && file_identity == &version.file_identity
                && operation_key == &request.key
                && digest == &authorization
                && !committed_seen =>
            {
                true
            }
            JournalState::Committed {
                binding,
                file_identity,
            } if matches!(
                operation.phase,
                DeletePhase::Authorized | DeletePhase::Cancelled
            ) && binding == &version.binding
                && file_identity == &version.file_identity =>
            {
                committed_seen = true;
                false
            }
            JournalState::Invalidated
                if operation.phase == DeletePhase::Cancelled && !remaining_seen =>
            {
                true
            }
            _ => return Err(invalid("journal differs from exact local owner prefix").into()),
        };
        if !matches!(journal.state, JournalState::Invalidated) {
            remaining_seen = true;
        }
        let path = request.root.join(&version.key);
        let artifact = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let observation = ArtifactObservation::checked(&metadata)?;
                let stamp = observation.stamp;
                FencePolicy::Payload {
                    owner: request.owner,
                }
                .validate(stamp)?;
                if identity(stamp).as_slice() != version.file_identity.as_slice() {
                    return Err(invalid("owned artifact was replaced").into());
                }
                let mut file = open_native(&path, false)?;
                if !MetadataStamp::checked(&file.metadata()?)?.same_incarnation(stamp) {
                    return Err(invalid("owned artifact changed while opening").into());
                }
                verify_file(&mut file, &version.binding)?;
                let bounded_body = match &version.binding {
                    ArtifactBinding::Pack { .. } => None,
                    ArtifactBinding::Index { .. } => {
                        Some(operation.authorization.index_witness.clone())
                    }
                    ArtifactBinding::Trash(bytes) => Some(bytes.clone()),
                };
                Artifact {
                    path,
                    file: Some(file),
                    observation: Some(observation),
                    bounded_body,
                    owner: request.owner,
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && owned
                    && operation.phase != DeletePhase::Authorized =>
            {
                Artifact {
                    path,
                    file: None,
                    observation: None,
                    bounded_body: None,
                    owner: request.owner,
                }
            }
            Err(error) => return Err(error.into()),
        };
        let required_absent = match operation.phase {
            DeletePhase::PackAbsent => index == 0,
            DeletePhase::IndexAbsent | DeletePhase::ContainersConfirmed => index < 2,
            DeletePhase::Done => true,
            _ => false,
        };
        if required_absent && artifact.file.is_some() {
            return Err(invalid("durable absence phase has a present artifact").into());
        }
        artifacts.push(artifact);
        journals.push(protected(
            &worker,
            journal_path(&request.control, &version.key),
            &request.journals[index],
            request.owner,
        )?);
    }
    let observed = NativeLocalDeletion {
        root: request.root,
        control: request.control,
        operation,
        snapshot,
        artifacts: artifacts
            .try_into()
            .map_err(|_| invalid("incomplete owned triple"))?,
        journals: journals
            .try_into()
            .map_err(|_| invalid("incomplete owner journals"))?,
        intent,
    };
    observed.recheck()?;
    worker.refresh(&[])?;
    let _ = request.result.send(observed);
    Ok(())
}
