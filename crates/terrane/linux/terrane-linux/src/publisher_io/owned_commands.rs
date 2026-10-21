//! Owns domain-bound native command authority and retained body incarnations.

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;

use terrane_format::chunking::ChunkProfile;
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_sdk::host::publication::{PublicationClaim, PublicationRecipe};
use terrane_sdk::store::{LocalFs, TokioClock, TokioLocalFs};

use super::super::NativeManifestWitness;
use super::super::bodies::{BodyIo, EncodedUnit};
use super::{
    NativePublishedObject, NativePublisher, NativePublisherConfig, NativeRetirementPolicy,
    NativeSealProbe, WorkerState,
};
use std::path::PathBuf;
use std::sync::Arc;
use terrane_sdk::host::publication::Publisher;
use terrane_sdk::host::publication::{FsPublicationState, RetirementInode, RetirementLeaseRequest};

/// Selects a configured domain and one cache owner's current incarnation.
#[derive(Clone, Debug)]
pub struct NativeCommandContext {
    /// The configured disclosure-domain label, never a filesystem path.
    pub domain: String,
    /// The cache owner's random incarnation, authenticated by the transport.
    pub cache_incarnation: [u8; 16],
}

/// Names one existing body through registered identities and layout rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeBodyKey {
    /// A plaintext canonical backing inode.
    Sealed {
        /// Its inline chunk or manifest descriptor.
        descriptor: Descriptor,
    },
    /// A compressed individual chunk body.
    Chunk {
        /// The plaintext chunk descriptor.
        descriptor: Descriptor,
        /// Its registered decimal codec identifier.
        codec: u8,
    },
    /// A pack and its detached index, retired as one unit.
    Pack {
        /// Its existing 16-byte random pack identifier.
        pack_id: [u8; 16],
    },
}

impl NativeBodyKey {
    fn validate(&self) -> io::Result<()> {
        let descriptor = match self {
            Self::Sealed { descriptor } => descriptor,
            Self::Chunk { descriptor, codec } => {
                if *codec > 2 {
                    return Err(invalid("unregistered chunk codec"));
                }
                if descriptor.domain()
                    != TERRANE_V1
                        .domain(IdentityKind::Chunk)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
                {
                    return Err(invalid("chunk body has a non-chunk descriptor"));
                }
                descriptor
            }
            Self::Pack { .. } => return Ok(()),
        };
        Descriptor::decode(&TERRANE_V1, &descriptor.encode())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if matches!(self, Self::Sealed { .. })
            && !matches!(
                TERRANE_V1
                    .kind(descriptor.domain())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
                IdentityKind::Chunk | IdentityKind::Manifest
            )
        {
            return Err(invalid("sealed body has a non-content descriptor"));
        }
        Ok(())
    }
}

/// Supplies a fixed operation; token bytes remain untrusted until native lookup.
pub enum NativeOperation {
    /// Creates a non-serving seal-capability probe.
    Probe,
    /// Publishes copied and independently verified plaintext.
    Publish {
        /// The validated immutable witness in this domain.
        claim: PublicationClaim,
        /// An owned read-only regular source descriptor.
        source: File,
    },
    /// Independently adopts an existing canonical inode.
    Adopt {
        /// The immutable reconstruction witness.
        claim: PublicationClaim,
    },
    /// Publishes from an actual received metadata witness, without pin authority.
    ///
    /// The registered receiver remains closed until native cache composition
    /// establishes genuine durable retention before submitting this operation.
    PublishManifest {
        /// The verified actual metadata-pack descriptor and canonical claim.
        witness: NativeManifestWitness,
        /// The owned read-only plaintext source descriptor.
        source: File,
    },
    /// Adopts using an actual received reconstruction witness.
    AdoptManifest {
        /// The verified actual metadata-pack descriptor and canonical claim.
        witness: NativeManifestWitness,
    },
    /// Adopts and binds a sealed key using actual reconstruction metadata.
    InspectManifest {
        /// The registered sealed key, checked against the exact witness.
        key: NativeBodyKey,
        /// The verified received reconstruction witness.
        witness: NativeManifestWitness,
    },
    /// Retains an inode incarnation for a checked registered key.
    InspectBody {
        /// The requested registered body key.
        key: NativeBodyKey,
        /// Required only for sealed-body independent adoption.
        claim: Option<PublicationClaim>,
    },
    /// Retains pending namespace custody without content or serving authority.
    InspectPending {
        /// The registered body key whose pending entry is inspected.
        key: NativeBodyKey,
    },
    /// Opens an existing quarantined sealed-body inode without verifying its bytes.
    InspectQuarantine {
        /// A registered sealed key selecting only its scoped quarantine name.
        key: NativeBodyKey,
        /// An optional public name tag; this grants no lifecycle authority.
        incarnation: Option<[u8; 32]>,
    },
    /// Quarantines an exact retained canonical sealed inode without replacing another.
    Quarantine {
        /// The registered key of the retained original canonical inode.
        key: NativeBodyKey,
        /// Its existing publisher-issued canonical incarnation token.
        incarnation: [u8; 32],
    },
    /// Begins two-phase deletion of an exact retained incarnation.
    Retire {
        /// Its configured domain's body key.
        key: NativeBodyKey,
        /// Untrusted opaque bytes matched against the owner's retained table.
        incarnation: [u8; 32],
    },
    /// Restores an exact pending incarnation without replacement.
    Restore {
        /// Its configured domain's body key.
        key: NativeBodyKey,
        /// Untrusted opaque bytes matched against the owner's retained table.
        incarnation: [u8; 32],
    },
    /// Completes the configured wipe policy for an exact pending incarnation.
    FinishRetirement {
        /// Its configured domain's body key.
        key: NativeBodyKey,
        /// Untrusted opaque bytes matched against the owner's retained table.
        incarnation: [u8; 32],
    },
    /// Drains prior accepted effects and establishes recovery custody.
    Drain,
    /// Enumerates bounded key names without granting content authority.
    Inventory {
        /// An opaque owner-issued continuation for this incarnation.
        cursor: Option<Vec<u8>>,
    },
    /// Leaves recovery after the native cache owner has reconciled durable state.
    Resume,
}

/// Carries an incarnation issued only after retaining its actual native inode.
pub struct NativeBodyIncarnation([u8; 32]);

impl NativeBodyIncarnation {
    /// Borrows the issued token for transport encoding.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Retains an unverified body without claiming valid bytes or serving authority.
pub struct NativeBodyHandle(File);

impl NativeBodyHandle {
    /// Transfers the unverified descriptor for independent cache inspection.
    pub fn into_handle(self) -> File {
        self.0
    }
}

/// Contains only results completed by the fixed native command owner.
pub enum NativeCommandResult {
    /// An unnamed private capability probe, never a canonical backing object.
    Probe {
        /// Actual fresh probe evidence, independently checked by the cache.
        probe: NativeSealProbe,
    },
    /// A canonical backing object and its retained native incarnation.
    Published {
        /// A privately minted native publication/adoption result.
        object: NativePublishedObject,
        /// Its unguessable retained-inode token.
        incarnation: NativeBodyIncarnation,
    },
    /// An unsealed inode requiring independent content verification.
    Inspected {
        /// A namespace-bound descriptor with no verified-byte authority.
        body: NativeBodyHandle,
        /// Its retained-inode token.
        incarnation: NativeBodyIncarnation,
    },
    /// A pending lifecycle token with no descriptor or content-validity proof.
    Pending {
        /// The actual retained pending inode incarnation.
        incarnation: NativeBodyIncarnation,
    },
    /// An opaque quarantine observation with no seal, binding or lifecycle token.
    Quarantined {
        /// A read-only descriptor requiring independent custody and charge checks.
        body: NativeBodyHandle,
    },
    /// A completed fixed lifecycle or barrier operation.
    Complete,
    /// A bounded unverified key-name inventory page.
    Inventory {
        /// At most 64 keys, never backing handles or incarnation authority.
        keys: Vec<NativeBodyKey>,
        /// The owner-issued continuation, if more names remain.
        next_cursor: Option<Vec<u8>>,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Transition {
    Retire,
    Restore,
    FinishNone,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Location {
    Canonical,
    Pending,
}

struct RetainedBody {
    key: NativeBodyKey,
    claim: Option<Arc<PublicationClaim>>,
    token: [u8; 32],
    file: File,
    location: Location,
    encoded: Option<EncodedUnit>,
    manifest: Option<Arc<NativeManifestWitness>>,
}

pub(super) struct CommandOwner {
    // Accepted effects outlive a connection's waiter. Keep actual configured
    // quota observations, root descriptors and shared guards in this owner.
    _configured_custody: Option<std::sync::Arc<crate::configured::ConfiguredPublisherCustody>>,
    confinement: std::sync::Arc<crate::quota_confinement::Installed>,
    domain: String,
    publisher: Option<Publisher<NativePublisher, WorkerState>>,
    cache: Option<[u8; 16]>,
    recovery: bool,
    bodies: Vec<RetainedBody>,
    leases: FsPublicationState<TokioLocalFs>,
    retirement: NativeRetirementPolicy,
    body_io: BodyIo,
    profile: ChunkProfile,
    inventory: super::inventory::NativeInventory,
}

#[path = "manifest_commands.rs"]
mod manifest_commands;
#[path = "retention.rs"]
mod retention;

impl CommandOwner {
    pub(super) fn new(
        config: NativePublisherConfig,
        publisher: Publisher<NativePublisher, WorkerState>,
        state_directory: PathBuf,
        body_io: BodyIo,
        inventory: super::inventory::NativeInventory,
        confinement: std::sync::Arc<crate::quota_confinement::Installed>,
        configured_custody: Option<std::sync::Arc<crate::configured::ConfiguredPublisherCustody>>,
    ) -> Self {
        Self {
            _configured_custody: configured_custody,
            confinement,
            domain: config.domain,
            publisher: Some(publisher),
            cache: None,
            recovery: true,
            bodies: Vec::new(),
            leases: FsPublicationState::new(TokioLocalFs, state_directory),
            retirement: config.retirement,
            body_io,
            profile: config.profile,
            inventory,
        }
    }

    pub(super) fn publisher(&mut self) -> io::Result<&mut Publisher<NativePublisher, WorkerState>> {
        self.publisher
            .as_mut()
            .ok_or_else(|| io::Error::other("native publisher unavailable"))
    }

    pub(super) fn validate_claim(&self, claim: &PublicationClaim) -> io::Result<()> {
        self.confinement.check_current()?;
        if claim.domain() != self.domain {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "publisher claim domain mismatch",
            ));
        }
        let recipe = match claim.canonical_manifest() {
            Some(bytes) => PublicationRecipe::Manifest {
                object: claim.descriptor().clone(),
                canonical_manifest: bytes.to_owned(),
            },
            None => PublicationRecipe::Inline {
                chunk: claim.descriptor().clone(),
            },
        };
        PublicationClaim::new(self.domain.clone(), recipe, &self.profile)?;
        Ok(())
    }

    fn kernel<T>(
        &mut self,
        operation: impl FnOnce(&mut NativePublisher) -> io::Result<T>,
    ) -> io::Result<T> {
        let publisher = self
            .publisher
            .take()
            .ok_or_else(|| io::Error::other("native publisher unavailable"))?;
        let (mut native, state) = publisher.into_parts();
        let result = operation(&mut native);
        self.publisher = Some(Publisher::new(native, state));
        result
    }

    pub(super) async fn execute(
        &mut self,
        context: NativeCommandContext,
        operation: NativeOperation,
    ) -> io::Result<NativeCommandResult> {
        self.confinement.check_current()?;
        if context.domain != self.domain {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "publisher domain mismatch",
            ));
        }
        match &operation {
            NativeOperation::InspectBody { key, .. }
            | NativeOperation::InspectPending { key }
            | NativeOperation::InspectQuarantine { key, .. }
            | NativeOperation::Quarantine { key, .. }
            | NativeOperation::Retire { key, .. }
            | NativeOperation::Restore { key, .. }
            | NativeOperation::FinishRetirement { key, .. } => key.validate()?,
            _ => {}
        }
        if matches!(operation, NativeOperation::Drain) {
            // The single owner reaches this command only after earlier physical
            // effects, their state writes and cleanup have actually completed.
            self.cache = Some(context.cache_incarnation);
            self.recovery = true;
            self.bodies.clear();
            self.inventory.reset();
            return Ok(NativeCommandResult::Complete);
        }
        if self.cache != Some(context.cache_incarnation) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cache incarnation requires drain",
            ));
        }
        if self.recovery
            && matches!(
                operation,
                NativeOperation::Publish { .. }
                    | NativeOperation::PublishManifest { .. }
                    | NativeOperation::Retire { .. }
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "publisher is under recovery custody",
            ));
        }
        match operation {
            NativeOperation::Drain => unreachable_operation(),
            NativeOperation::Resume => {
                self.recovery = false;
                Ok(NativeCommandResult::Complete)
            }
            NativeOperation::Probe => self.kernel(|native| {
                let file = native.probe_seal()?;
                let binding = crate::verity::measure(&file)?;
                Ok(NativeCommandResult::Probe {
                    probe: NativeSealProbe { file, binding },
                })
            }),
            NativeOperation::Publish { claim, source } => {
                self.validate_claim(&claim)?;
                if claim.manifest().is_some() {
                    return Err(unsupported(
                        "manifest publication requires actual metadata retention custody",
                    ));
                }
                let claim = Arc::new(claim);
                let prepared = self.prepare_retention(Arc::clone(&claim)).await?;
                let object = self.publisher()?.publish_retained(&claim, source).await?;
                Ok(self.commit_retention(prepared, object, None))
            }
            NativeOperation::Adopt { claim } => self.adopt(claim).await,
            NativeOperation::PublishManifest { witness, source } => {
                self.consume_manifest(witness, Some(source), None).await
            }
            NativeOperation::AdoptManifest { witness } => {
                self.consume_manifest(witness, None, None).await
            }
            NativeOperation::InspectManifest { key, witness } => {
                self.consume_manifest(witness, None, Some(key)).await
            }
            NativeOperation::InspectBody {
                key: NativeBodyKey::Sealed { descriptor },
                claim: Some(claim),
            } => {
                if claim.descriptor() != &descriptor {
                    return Err(invalid("sealed inspection claim mismatch"));
                }
                self.adopt(claim).await
            }
            NativeOperation::InspectBody {
                key: NativeBodyKey::Sealed { .. },
                claim: None,
            } => Err(invalid("sealed inspection requires its content claim")),
            NativeOperation::InspectBody { claim: Some(_), .. } => {
                Err(invalid("unsealed inspection cannot carry a content claim"))
            }
            NativeOperation::InspectBody { key, .. } => self.inspect_encoded(key, false).await,
            NativeOperation::InspectPending { key } => self.inspect_pending(key).await,
            NativeOperation::InspectQuarantine {
                key: NativeBodyKey::Sealed { descriptor },
                incarnation,
            } => self.kernel(|native| {
                let file = native.inspect_quarantined_sealed(&descriptor, incarnation.as_ref())?;
                Ok(NativeCommandResult::Quarantined {
                    body: NativeBodyHandle(file),
                })
            }),
            NativeOperation::InspectQuarantine { .. } => {
                Err(invalid("quarantine inspection requires a sealed-body key"))
            }
            NativeOperation::Quarantine { key, incarnation } => self.quarantine(key, incarnation),
            NativeOperation::Retire { key, incarnation } => {
                self.transition(key, incarnation, Transition::Retire).await
            }
            NativeOperation::Restore { key, incarnation } => {
                self.transition(key, incarnation, Transition::Restore).await
            }
            NativeOperation::FinishRetirement { key, incarnation } => {
                self.transition(key, incarnation, Transition::FinishNone)
                    .await
            }
            NativeOperation::Inventory { cursor } if self.recovery => {
                self.inventory.page(cursor).await
            }
            NativeOperation::Inventory { .. } => {
                Err(invalid("inventory requires drained recovery custody"))
            }
        }
    }

    fn quarantine(
        &mut self,
        key: NativeBodyKey,
        token: [u8; 32],
    ) -> io::Result<NativeCommandResult> {
        let index = self
            .bodies
            .iter()
            .position(|body| body.key == key && body.token == token)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::PermissionDenied, "unknown body incarnation")
            })?;
        let body = &self.bodies[index];
        if !matches!(key, NativeBodyKey::Sealed { .. }) || body.location != Location::Canonical {
            return Err(invalid(
                "quarantine requires an original canonical sealed inode",
            ));
        }
        let claim = body
            .claim
            .clone()
            .ok_or_else(|| invalid("quarantine requires original adoption custody"))?;
        let original = body.file.try_clone()?;
        self.kernel(|native| native.quarantine_registered(&claim, &original, &token))?;
        // The name tag remains public routing data. The old lifecycle token is
        // removed only after the exact move and both directory syncs complete.
        self.bodies.remove(index);
        Ok(NativeCommandResult::Complete)
    }

    async fn inspect_pending(&mut self, key: NativeBodyKey) -> io::Result<NativeCommandResult> {
        let NativeBodyKey::Sealed { descriptor } = &key else {
            return self.inspect_encoded(key, true).await;
        };
        let file = self.kernel(|native| native.inspect_pending_sealed(descriptor))?;
        let metadata = file.metadata()?;
        self.leases
            .retirement_lease(
                &TokioClock,
                RetirementLeaseRequest {
                    domain: &self.domain,
                    key: &descriptor.encode(),
                    incarnation: retirement_inode(&metadata),
                    interval: self.retirement.interval(),
                },
            )
            .await?;
        for retained in &self.bodies {
            let previous = retained.file.metadata()?;
            if retained.key == key
                && retained.location == Location::Pending
                && previous.dev() == metadata.dev()
                && previous.ino() == metadata.ino()
            {
                return Ok(NativeCommandResult::Pending {
                    incarnation: NativeBodyIncarnation(retained.token),
                });
            }
        }
        if self.bodies.len() >= 4096 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "publisher incarnation budget exhausted",
            ));
        }
        let token = TokioLocalFs
            .random_bytes(32)
            .await?
            .try_into()
            .map_err(|_| io::Error::other("invalid native random length"))?;
        self.bodies.push(RetainedBody {
            key,
            claim: None,
            token,
            file,
            location: Location::Pending,
            encoded: None,
            manifest: None,
        });
        Ok(NativeCommandResult::Pending {
            incarnation: NativeBodyIncarnation(token),
        })
    }

    async fn inspect_encoded(
        &mut self,
        key: NativeBodyKey,
        pending: bool,
    ) -> io::Result<NativeCommandResult> {
        let unit = match &key {
            NativeBodyKey::Chunk { descriptor, codec } => {
                self.body_io.inspect_chunk(descriptor, *codec, pending)?
            }
            NativeBodyKey::Pack { pack_id } => self.body_io.inspect_pack(pack_id, pending)?,
            NativeBodyKey::Sealed { .. } => {
                return Err(invalid("sealed inspection requires adoption"));
            }
        };
        unit.sync_names(&self.body_io)?;
        if pending {
            for lease in unit.lease_inputs(&key)? {
                self.leases
                    .retirement_lease(
                        &TokioClock,
                        RetirementLeaseRequest {
                            domain: &self.domain,
                            key: &lease.key,
                            incarnation: lease.incarnation,
                            interval: self.retirement.interval(),
                        },
                    )
                    .await?;
            }
        }
        let handle = unit.handle()?;
        for body in &mut self.bodies {
            let same = match &body.encoded {
                Some(previous) if body.key == key => previous.same_inode(&unit)?,
                _ => false,
            };
            if same {
                let token = body.token;
                body.encoded = Some(unit);
                body.location = if pending {
                    Location::Pending
                } else {
                    Location::Canonical
                };
                return Ok(if pending {
                    NativeCommandResult::Pending {
                        incarnation: NativeBodyIncarnation(token),
                    }
                } else {
                    NativeCommandResult::Inspected {
                        body: NativeBodyHandle(handle),
                        incarnation: NativeBodyIncarnation(token),
                    }
                });
            }
        }
        if self.bodies.len() >= 4096 {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "publisher incarnation budget exhausted",
            ));
        }
        let token = TokioLocalFs
            .random_bytes(32)
            .await?
            .try_into()
            .map_err(|_| io::Error::other("invalid native random length"))?;
        self.bodies.push(RetainedBody {
            key,
            claim: None,
            token,
            file: handle.try_clone()?,
            location: if pending {
                Location::Pending
            } else {
                Location::Canonical
            },
            encoded: Some(unit),
            manifest: None,
        });
        Ok(if pending {
            NativeCommandResult::Pending {
                incarnation: NativeBodyIncarnation(token),
            }
        } else {
            NativeCommandResult::Inspected {
                body: NativeBodyHandle(handle),
                incarnation: NativeBodyIncarnation(token),
            }
        })
    }

    async fn adopt(&mut self, claim: PublicationClaim) -> io::Result<NativeCommandResult> {
        self.validate_claim(&claim)?;
        if claim.manifest().is_some() {
            return Err(unsupported(
                "manifest adoption requires actual metadata retention custody",
            ));
        }
        let claim = Arc::new(claim);
        let prepared = self.prepare_retention(Arc::clone(&claim)).await?;
        let object = self.publisher()?.adopt_retained(&claim).await?;
        Ok(self.commit_retention(prepared, object, None))
    }

    async fn transition_encoded(
        &mut self,
        index: usize,
        key: &NativeBodyKey,
        transition: Transition,
    ) -> io::Result<NativeCommandResult> {
        let location = self.bodies[index].location;
        if matches!(transition, Transition::Retire) && location != Location::Canonical
            || !matches!(transition, Transition::Retire) && location != Location::Pending
        {
            return Err(invalid("encoded body lifecycle state mismatch"));
        }
        let mut unit = self.bodies[index]
            .encoded
            .take()
            .ok_or_else(|| io::Error::other("encoded unit unavailable"))?;
        let result = async {
            match transition {
                Transition::Retire => {
                    unit.retire(&self.body_io)?;
                    for lease in unit.lease_inputs(key)? {
                        self.leases
                            .begin_retirement_lease(
                                &TokioClock,
                                RetirementLeaseRequest {
                                    domain: &self.domain,
                                    key: &lease.key,
                                    incarnation: lease.incarnation,
                                    interval: self.retirement.interval(),
                                },
                            )
                            .await?;
                    }
                }
                Transition::Restore => unit.restore(&self.body_io)?,
                Transition::FinishNone => {
                    for lease in unit.lease_inputs(key)? {
                        let deadline = self
                            .leases
                            .retirement_lease(
                                &TokioClock,
                                RetirementLeaseRequest {
                                    domain: &self.domain,
                                    key: &lease.key,
                                    incarnation: lease.incarnation,
                                    interval: self.retirement.interval(),
                                },
                            )
                            .await?;
                        if !deadline.expired(&TokioClock)? {
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "pending retirement lease has not expired",
                            ));
                        }
                    }
                    unit.finish(&self.body_io)?;
                }
            }
            Ok(NativeCommandResult::Complete)
        }
        .await;
        self.bodies[index].location = if unit.any_pending() {
            Location::Pending
        } else {
            Location::Canonical
        };
        self.bodies[index].encoded = Some(unit);
        if result.is_ok() && matches!(transition, Transition::FinishNone) {
            self.bodies.remove(index);
        }
        result
    }

    async fn transition(
        &mut self,
        key: NativeBodyKey,
        token: [u8; 32],
        transition: Transition,
    ) -> io::Result<NativeCommandResult> {
        let index = self
            .bodies
            .iter()
            .position(|body| body.key == key && body.token == token)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::PermissionDenied, "unknown body incarnation")
            })?;
        if self.bodies[index].encoded.is_some() {
            return self.transition_encoded(index, &key, transition).await;
        }
        let body = &self.bodies[index];
        let claim = body.claim.clone();
        let expected = body.file.try_clone()?;
        if matches!(transition, Transition::Restore | Transition::FinishNone) {
            if body.location != Location::Pending {
                return Err(invalid("body is not pending retirement"));
            }
        } else if body.location != Location::Canonical {
            return Err(invalid("body is not canonical"));
        }
        let NativeBodyKey::Sealed { descriptor } = &key else {
            return Err(unsupported(
                "encoded retirement awaits configured content custody",
            ));
        };
        let lease_key = descriptor.encode();
        let metadata = expected.metadata()?;
        if matches!(transition, Transition::FinishNone) {
            let lease = self
                .leases
                .retirement_lease(
                    &TokioClock,
                    RetirementLeaseRequest {
                        domain: &self.domain,
                        key: &lease_key,
                        incarnation: retirement_inode(&metadata),
                        interval: self.retirement.interval(),
                    },
                )
                .await?;
            if !lease.expired(&TokioClock)? {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "pending retirement lease has not expired",
                ));
            }
            self.kernel(|native| native.finish_pending_sealed(descriptor, &expected))?;
            self.bodies.remove(index);
        } else if matches!(transition, Transition::Restore) {
            self.kernel(|native| native.restore_pending_sealed(descriptor, &expected))?;
            // Namespace restoration is not adoption. A token obtained from
            // InspectPending still has no content claim or backing authority.
            self.bodies[index].location = Location::Canonical;
        } else {
            let claim = claim.ok_or_else(|| invalid("retirement requires canonical adoption"))?;
            self.kernel(|native| native.retire_checked(&claim, &expected))?;
            self.bodies[index].location = Location::Pending;
            let metadata = expected.metadata()?;
            self.leases
                .begin_retirement_lease(
                    &TokioClock,
                    RetirementLeaseRequest {
                        domain: &self.domain,
                        key: &lease_key,
                        incarnation: retirement_inode(&metadata),
                        interval: self.retirement.interval(),
                    },
                )
                .await?;
        }
        Ok(NativeCommandResult::Complete)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
fn unreachable_operation() -> io::Result<NativeCommandResult> {
    Err(invalid("drain dispatch state mismatch"))
}

fn retirement_inode(metadata: &std::fs::Metadata) -> RetirementInode {
    RetirementInode {
        device: metadata.dev(),
        inode: metadata.ino(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}
