//! Publishes verified inline or manifest bytes through the Running command owner.
//!
//! A synchronized reservation precedes the anonymous plaintext inode and the
//! publisher's copy. Original input, descriptors, replies and uncertain results
//! stay in the physical registry after cancellation. Successful read accessors
//! borrow immutable fields without consulting embedded policy state. After real
//! source closure and sealed-file synchronization, the final snapshot settles
//! future copy overlap. Its metadata allowance and durable pin remain retained.

mod completion;
pub(in crate::host_cache::owner) mod eviction;
pub(super) mod handoff;
mod io;
mod manifest;
mod producer_reads;
pub(super) mod residence;
pub(super) mod retirement;
mod settle;
mod state;

pub use eviction::NativeCacheEvictionReport;
pub use handoff::{NativeCacheHandoffError, NativeCacheHandoffReport};
pub use manifest::NativeManifestPublication;
pub(super) use manifest::run as run_manifest;
pub(in crate::host_cache::owner) use producer_reads::execute as close_producer_reads;
pub(super) use residence::RecoveredInlineJob;
pub(super) use residence::retain as retain_resident_chunk;
pub use residence::{NativeProducerReadClosure, NativeResidentChunkSource};
pub use retirement::NativeSourceCleanupReport;

use super::{
    admission::{AdmissionJob, NativeChunkAdmissionError, TransferSource},
    retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
};
use crate::publisher_local::{client::PeerPublishedObject, socket::ReceivedPacket};
use std::{
    fs::File,
    io as std_io,
    sync::{Arc, Mutex, mpsc},
};
use terrane_format::{
    codec::Codec,
    identity::{Descriptor, IdentityKind, TERRANE_V1},
};
use terrane_sdk::{
    host::{
        cache::HostDomainLocation,
        publication::{PublicationClaim, PublicationRecipe},
    },
    store::ChunkPosition,
};
use tokio::sync::oneshot;

/// Retains actual physical resources independently of an external response waiter.
pub(super) struct PublicationJob {
    /// Original physical admission order; zero only before executor registration.
    pub(super) order: u64,
    custody: Arc<Mutex<Custody>>,
    encoded: Vec<u8>,
    plaintext: Vec<u8>,
    claim: PublicationClaim,
    dictionary: Option<Arc<Mutex<AdmissionJob>>>,
    manifest: Option<manifest::ManifestInput>,
    transfer: Option<TransferSource>,
    transfer_observation:
        Option<Arc<crate::publisher_local::client::BodyIncarnationObservation<HostDomainLocation>>>,
    transfer_retired: bool,
    transfer_cleanup: Option<crate::publisher_local::client::AcknowledgedSourceRetirement>,
    token: String,
    hold: u64,
    generation: u64,
    pub(super) started: bool,
    complete: bool,
    cached: Option<handoff::CachedPublication>,
    // This deny-only latch prevents issuing new external producer views after
    // revocation. It grants no replacement pin, cache or retirement authority.
    producer_reads_closed: bool,
    synchronized: Option<completion::SynchronizedPublication>,
    writer: Option<File>,
    reader: Option<File>,
    reply: Option<ReceivedPacket>,
    body: Option<Arc<PeerPublishedObject<HostDomainLocation>>>,
}

/// Retains one actual executor job's synchronized publication funding.
pub(super) struct Funding {
    job: Arc<Mutex<PublicationJob>>,
    custody: Arc<Mutex<Custody>>,
    token: String,
    hash: String,
    descriptor: Descriptor,
    source: (u64, u64, u64),
    transfer: Option<TransferSource>,
    manifest: Option<Arc<super::RetainedManifest>>,
    sources: Vec<TransferSource>,
    hold: u64,
    generation: u64,
}

impl Funding {
    /// Checks the producer's exact verified claim without accepting another key.
    ///
    /// # Errors
    /// Refuses a domain, descriptor or length outside the actual funded job.
    pub(super) fn check_claim(&self, claim: &PublicationClaim) -> std_io::Result<()> {
        let owner = self
            .custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        if claim.domain() != owner.preparation.config.location.domain()
            || claim.descriptor() != &self.descriptor
            || claim.canonical_manifest()
                != self
                    .manifest
                    .as_ref()
                    .and_then(|retained| retained.claim().canonical_manifest())
        {
            return Err(invalid(
                "publication claim differs from actual funded input",
            ));
        }
        if let Some(retained) = &self.manifest {
            retained.check_registration(&owner)?;
        }
        Ok(())
    }

    /// Borrows only the actual manifest pin owned by this registered job.
    ///
    /// # Errors
    /// Refuses changed metadata, missing native registration or poisoned custody.
    pub(super) fn retained_manifest(&self) -> std_io::Result<Option<Arc<super::RetainedManifest>>> {
        let owner = self
            .custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        if let Some(retained) = &self.manifest {
            retained.check_registration(&owner)?;
        }
        Ok(self.manifest.as_ref().map(Arc::clone))
    }

    /// Checks the original anonymous source inode before passing its descriptor.
    ///
    /// # Errors
    /// Refuses another or changed physical source inode.
    pub(super) fn check_source(&self, source: &File) -> std_io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let metadata = source.metadata()?;
        if (metadata.dev(), metadata.ino(), metadata.len()) != self.source {
            return Err(invalid(
                "publication source differs from actual funded input",
            ));
        }
        Ok(())
    }

    /// Requires an actual verified sealed replacement before source retirement.
    ///
    /// # Errors
    /// Refuses another claim/root, missing kernel seal, changed native project,
    /// ownership or unlinked backing. A raw file cannot construct this receipt.
    pub(super) fn check_replacement(
        &self,
        body: &PeerPublishedObject<HostDomainLocation>,
    ) -> std_io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let owner = self
            .custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        let metadata = body.handle().metadata()?;
        if body.claim().descriptor() != &self.descriptor
            || body.claim().domain() != owner.preparation.config.location.domain()
            || !Arc::ptr_eq(body.layout(), owner.preparation.layout())
            || metadata.nlink() == 0
            || metadata.len() != body.claim().plaintext_size()
            || metadata.uid() != owner.preparation.config.publisher.identities.publish_uid
            || metadata.mode() & 0o7777 != 0o400
            || crate::host_quota::NativeProject::inspect(body.handle())?.project_id
                != owner.preparation.config.project_id
            || crate::verity::measure(body.handle())? != *body.binding()
        {
            return Err(invalid(
                "transfer lacks its actual verified sealed replacement",
            ));
        }
        body.layout().recheck()
    }

    /// Returns only the original admitted key after checking its canonical custody.
    ///
    /// # Errors
    /// Refuses absent transfer custody, altered source bytes or lost actual pins.
    pub(super) fn transfer_key(
        &self,
        index: usize,
    ) -> std_io::Result<crate::publisher_local::wire::BodyKey> {
        let owner = self
            .custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        let transfer = self
            .transfer_at(index)
            .ok_or_else(|| invalid("publication has no standalone transfer"))?;
        transfer.check_current(&owner)?;
        Ok(transfer.key().clone())
    }

    fn transfer_at(&self, index: usize) -> Option<&TransferSource> {
        if self.manifest.is_some() {
            self.sources.get(index)
        } else if index == 0 {
            self.transfer.as_ref()
        } else {
            None
        }
    }

    /// Checks the actual same-response descriptor before permitting retirement.
    ///
    /// # Errors
    /// Refuses another registered key, inode, bytes or native project custody.
    pub(super) fn check_transfer_reply(
        &self,
        key: &crate::publisher_local::wire::BodyKey,
        file: &File,
    ) -> std_io::Result<()> {
        let owner = self
            .custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        let transfer = self
            .sources
            .iter()
            .chain(self.transfer.iter())
            .find(|source| source.key() == key)
            .ok_or_else(|| invalid("publication has no standalone transfer"))?;
        if transfer.key() != key {
            return Err(invalid("transfer reply names another actual source"));
        }
        transfer.check_current(&owner)?;
        transfer.check_received(&owner, file)
    }

    /// Borrows the actual registered resource identity without locking it.
    pub(super) fn job(&self) -> &Arc<Mutex<PublicationJob>> {
        &self.job
    }

    /// Rechecks genuine synchronized funding and fresh quota before an RPC lock.
    ///
    /// # Errors
    /// Refuses another owner, changed policy/generation, unknown quota or capacity.
    pub(super) fn check(&self, custody: &Arc<Mutex<Custody>>) -> std_io::Result<()> {
        if !Arc::ptr_eq(custody, &self.custody) {
            return Err(invalid("publication funding belongs to another owner"));
        }
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        state::check_funding(&owner, &self.token, &self.hash, self.hold, self.generation)?;
        owner.preparation.recheck()?;
        state::check_charge(&owner).map(|_| ())
    }
}

/// Retains an actual completed publication independently of its public wrapper.
struct PublicationCompletion {
    body: Arc<PeerPublishedObject<HostDomainLocation>>,
    job: Arc<Mutex<PublicationJob>>,
    allocated: u64,
    charged: u64,
    future: u64,
    cleanup_not_before: std::time::Duration,
}

/// Owns a completed inline publication and its original physical funding.
///
/// The handle is independently verified, kernel-sealed and read-only. This
/// receipt grants neither a consumer lease nor bucket/Store readiness. The
/// physical owner retains its pin and future hold until actual retirement;
/// dropping a waiter or this receipt does not release them.
pub struct NativeInlinePublication {
    completion: PublicationCompletion,
}

impl NativeInlinePublication {
    /// Transfers the completed publication into cache ownership and release grace.
    ///
    /// Final standalone-source cleanup must have completed first. Producer read
    /// views close, while consumer pins and reconstruction metadata remain owned.
    /// A queue refusal returns this receipt for retry. Accepted commands consume
    /// it and retain physical resources on their original owner after failure or
    /// waiter cancellation. No producer descriptor is returned.
    ///
    /// # Errors
    /// Refuses a full/stopped queue, foreign or incomplete work, active producer
    /// reads, missing native cleanup acknowledgments, changed backing, failed
    /// snapshot synchronization or unavailable quota reconciliation.
    pub async fn into_cache(
        self,
        owner: &NativeMetadataOwner,
    ) -> Result<NativeCacheHandoffReport, NativeCacheHandoffError<Self>> {
        let job = Arc::clone(&self.completion.job);
        handoff::submit(owner, job, self).await
    }

    /// Closes this publication's externally issued producer read views.
    ///
    /// Later external producer-view acquisition is also refused permanently.
    /// Separately synchronized consumer leases and internal reassembly sources
    /// remain protected. A cancelled waiter does not cancel accepted closure.
    /// The result releases no durable protection or physical allocation and
    /// supplies no cache ownership or eviction authority.
    ///
    /// # Errors
    /// Refuses another physical owner, a stopped/full queue, stale publication
    /// funding, absent Running custody or an unavailable worker response.
    pub async fn close_resident_reads(
        &self,
        owner: &NativeMetadataOwner,
    ) -> std_io::Result<NativeProducerReadClosure> {
        producer_reads::submit(owner, &self.completion.job).await
    }

    /// Finishes the original standalone source retirements on their physical owner.
    ///
    /// Call after the configured publisher retirement grace. The result counts
    /// original sources whose final removal was acknowledged; repeated calls
    /// check retained actual acknowledgements without repeating those RPCs.
    /// The owner closes its original source descriptors only after their real
    /// final-removal acknowledgements. Original pins and holds remain retained;
    /// independently held descriptors may still retain physical allocation.
    ///
    /// # Errors
    /// Refuses another owner, queue limits, active native grace, stale backing,
    /// quota failures and uncertain exchanges. Accepted failures require actual
    /// recovery, retaining funding and resources after waiter cancellation.
    pub async fn finish_retired_sources(
        &self,
        owner: &NativeMetadataOwner,
    ) -> std_io::Result<NativeSourceCleanupReport> {
        retirement::submit(owner, &self.completion.job).await
    }

    /// Borrows verified read-only sealed bytes without an embedded-state lock.
    pub fn handle(&self) -> &File {
        self.completion.body.handle()
    }

    /// Borrows the independently verified content declaration.
    pub fn claim(&self) -> &PublicationClaim {
        self.completion.body.claim()
    }

    /// Returns synchronized allocation of this sealed inode alone.
    pub fn synchronized_sealed_inode_bytes(&self) -> u64 {
        self.completion.allocated
    }

    /// Returns separate fresh full-project kernel charged-and-reserved bytes.
    pub fn charged_reserved_bytes(&self) -> u64 {
        self.completion.charged
    }

    /// Returns distinct durable future policy holds at acknowledgment.
    pub fn future_hold_bytes(&self) -> u64 {
        self.completion.future
    }
}

impl NativeMetadataOwner {
    /// Publishes one verified encoded inline chunk after actual recovery and Resume.
    ///
    /// The owner derives domain/profile, checks original encoded bytes, and
    /// durably funds simultaneous plaintext-source and publisher-copy lifetimes.
    /// A standalone body may transfer only from this physical owner's actual
    /// completed admission. Its original descriptors, pins and holds survive
    /// publisher retirement into the pending namespace; actual cleanup is separate.
    /// No source path, raw file or validity assertion is accepted.
    ///
    /// # Errors
    /// Returns original encoded inputs with `ChunkPosition::Final` on local/queue
    /// refusal. Accepted failures retain physical resources and durable funding;
    /// no uncertain outcome is retried automatically or returned as a backing.
    pub async fn publish_inline(
        &self,
        descriptor: Descriptor,
        encoded: Vec<u8>,
    ) -> Result<NativeInlinePublication, NativeChunkAdmissionError> {
        let (response, receive) = oneshot::channel();
        let refusal = self
            .admission_bounds
            .check(encoded.len(), 0)
            .and_then(|()| self.admission_bounds.check(encoded.capacity(), 0))
            .err();
        let command = Command::PublishInline {
            descriptor,
            encoded,
            response,
        };
        let submitted = match (refusal, self.commands.as_ref()) {
            (Some(error), _) => Err((error, command)),
            (None, None) => Err((invalid("native publication owner stopped"), command)),
            (None, Some(commands)) => commands.try_send(command).map_err(|error| match error {
                mpsc::TrySendError::Full(command) => (
                    std_io::Error::new(std_io::ErrorKind::WouldBlock, "publication queue full"),
                    command,
                ),
                mpsc::TrySendError::Disconnected(command) => (
                    std_io::Error::new(std_io::ErrorKind::BrokenPipe, "publication owner stopped"),
                    command,
                ),
            }),
        };
        if let Err((
            error,
            Command::PublishInline {
                descriptor,
                encoded,
                ..
            },
        )) = submitted
        {
            return Err(NativeChunkAdmissionError::Unsubmitted {
                error,
                descriptor,
                encoded,
                position: ChunkPosition::Final,
            });
        }
        receive
            .await
            .map_err(|_| {
                NativeChunkAdmissionError::Accepted(invalid(
                    "publication owner terminated before completion",
                ))
            })?
            .map_err(NativeChunkAdmissionError::Accepted)
    }
}

/// Runs genuine funded publication on the actual physical executor.
///
/// # Errors
/// Refuses invalid input or running custody, native/transport/durability failure
/// and changed accounting. Started jobs remain registered and faulted on error.
pub(super) async fn run(
    executor: &mut NativeOwnerExecutor,
    descriptor: Descriptor,
    encoded: Vec<u8>,
) -> std_io::Result<NativeInlinePublication> {
    let context = executor.admission_context()?;
    context.check_current().map_err(std_io::Error::other)?;
    let custody = Arc::clone(executor.custody());
    let prepared = prepare(executor, &custody, descriptor, encoded)?;
    eviction::restore_publication(executor, prepared.claim.descriptor()).await?;
    let job = executor.register_publication(prepared)?;
    let outcome = execute(executor, &job, &context).await;
    if outcome.is_err() {
        executor.reclaim_publication(&job)?;
    }
    outcome.map(|completion| NativeInlinePublication { completion })
}

fn prepare(
    executor: &NativeOwnerExecutor,
    custody: &Arc<Mutex<Custody>>,
    descriptor: Descriptor,
    encoded: Vec<u8>,
) -> std_io::Result<PublicationJob> {
    let owner = custody
        .lock()
        .map_err(|_| invalid("publication custody poisoned"))?;
    owner.check_current()?;
    let config = &owner.preparation.config;
    let claim = PublicationClaim::new(
        config.location.domain().to_owned(),
        PublicationRecipe::Inline {
            chunk: descriptor.clone(),
        },
        config.location.chunk_profile(),
    )?;
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, descriptor.digest())
        .map_err(std_io::Error::other)?;
    let length = usize::try_from(claim.plaintext_size()).map_err(std_io::Error::other)?;
    let bounds = super::admission::AdmissionBounds::new(config)?;
    bounds.check(encoded.capacity(), length)?;
    let envelope = terrane_format::codec::parse_envelope(&encoded).map_err(std_io::Error::other)?;
    let (dictionary, dependency) = if let Codec::ZstdDictionary(digest) = envelope.codec {
        let (plaintext, actual) =
            super::admission::chunk::dictionary(executor, None, &owner, &digest)?;
        (Some(plaintext), Some(actual))
    } else {
        (None, None)
    };
    let verified = terrane_sdk::codec::decode_verified(
        &encoded,
        length,
        config.location.chunk_profile(),
        true,
        &identity,
        dictionary.as_deref(),
    )
    .map_err(std_io::Error::other)?;
    descriptor
        .verify_bytes(&TERRANE_V1, IdentityKind::Chunk, verified.plaintext())
        .map_err(std_io::Error::other)?;
    let plaintext = verified.plaintext().to_vec();
    bounds.check(encoded.capacity(), plaintext.capacity())?;
    let transfer = match io::refuse_standalone(&owner, descriptor.digest()) {
        Ok(()) => None,
        Err(error) if error.kind() == std_io::ErrorKind::AlreadyExists => {
            let actual = TransferSource::select(executor, &owner, &descriptor)?;
            io::refuse_other_standalone(&owner, descriptor.digest(), actual.key().codec)?;
            Some(actual)
        }
        Err(error) => return Err(error),
    };
    Ok(PublicationJob {
        order: 0,
        custody: Arc::clone(custody),
        encoded,
        plaintext,
        claim,
        dictionary: dependency,
        manifest: None,
        transfer,
        transfer_observation: None,
        transfer_retired: false,
        transfer_cleanup: None,
        token: String::new(),
        hold: 0,
        generation: 0,
        started: false,
        complete: false,
        cached: None,
        producer_reads_closed: false,
        synchronized: None,
        writer: None,
        reader: None,
        reply: None,
        body: None,
    })
}

async fn execute(
    executor: &mut NativeOwnerExecutor,
    job: &Arc<Mutex<PublicationJob>>,
    context: &crate::publisher_local::client::PublisherRunningContext,
) -> std_io::Result<PublicationCompletion> {
    let custody = Arc::clone(executor.custody());
    let ticket = {
        let mut physical = job
            .lock()
            .map_err(|_| invalid("publication job poisoned"))?;
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        if !Arc::ptr_eq(&physical.custody, &custody) {
            return Err(invalid("publication resource belongs to another owner"));
        }
        state::begin(executor, &mut owner, &mut physical)?
    };
    super::snapshot::persist(executor, ticket).await?;
    let funding = {
        let mut physical = job
            .lock()
            .map_err(|_| invalid("publication job poisoned"))?;
        let scope = {
            let mut owner = custody
                .lock()
                .map_err(|_| invalid("publication custody poisoned"))?;
            if let Some(input) = &physical.manifest {
                input.check(&owner)?;
            }
            io::SourceContext::funded(&mut owner, &physical)?
        };
        // Keep the actual registered job locked, but never hold embedded state
        // while copying existing sealed ranges or synchronizing native output.
        io::prepare_source(&scope, &mut physical)?;
        let owner = custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        state::check_funding(
            &owner,
            &physical.token,
            &state::hex(physical.claim.descriptor().digest()),
            physical.hold,
            physical.generation,
        )?;
        if let Some(input) = &physical.manifest {
            input.check(&owner)?;
        }
        use std::os::unix::fs::MetadataExt;
        let source = physical
            .reader
            .as_ref()
            .ok_or_else(|| invalid("publication source absent"))?
            .metadata()?;
        Funding {
            job: Arc::clone(job),
            custody: Arc::clone(&custody),
            token: physical.token.clone(),
            hash: state::hex(physical.claim.descriptor().digest()),
            descriptor: physical.claim.descriptor().clone(),
            source: (source.dev(), source.ino(), source.len()),
            transfer: physical.transfer.clone(),
            manifest: physical
                .manifest
                .as_ref()
                .map(|input| Arc::clone(&input.retained)),
            sources: physical
                .manifest
                .as_ref()
                .map_or_else(|| Ok(Vec::new()), |input| input.transfer_sources())?,
            hold: physical.hold,
            generation: physical.generation,
        }
    };
    let session = Arc::clone(context.publisher_session());
    {
        let mut turn = executor.publication_turn(funding)?;
        let mut physical = job
            .lock()
            .map_err(|_| invalid("publication job poisoned"))?;
        let claim = physical.claim.clone();
        let PublicationJob { reader, reply, .. } = &mut *physical;
        let source = reader
            .as_ref()
            .ok_or_else(|| invalid("publication source absent"))?;
        let body = session
            .publish_running(source, claim.clone(), context, &mut turn, reply)
            .map_err(std_io::Error::other)?;
        // The actual accepted result is retained before any later fallible
        // synchronization, state write or fresh quota reconciliation.
        physical.body = Some(Arc::new(body));
        drop(physical.reader.take());
        if physical.transfer.is_some() {
            let published = Arc::clone(
                physical
                    .body
                    .as_ref()
                    .ok_or_else(|| invalid("transfer replacement absent"))?,
            );
            let observation = session
                .inspect_source_transfer(&published, context, &mut turn, 0, &mut physical.reply)
                .map_err(std_io::Error::other)?;
            physical.transfer_observation = Some(Arc::new(observation));
            let observation = physical
                .transfer_observation
                .as_ref()
                .ok_or_else(|| invalid("transfer observation absent"))?;
            session
                .retire_source_transfer(&published, context, &mut turn, 0, observation)
                .map_err(std_io::Error::other)?;
            physical.transfer_retired = true;
        }
        let published = Arc::clone(
            physical
                .body
                .as_ref()
                .ok_or_else(|| invalid("publication replacement absent"))?,
        );
        if let Some(input) = &mut physical.manifest {
            input.retire_sources(&session, &published, context, &mut turn)?;
        }
    }
    completion::synchronize(executor, job)?;
    context.check_current().map_err(std_io::Error::other)?;
    let ticket = {
        let mut physical = job
            .lock()
            .map_err(|_| invalid("publication job poisoned"))?;
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        state::complete(executor, &mut owner, &mut physical)?
    };
    super::snapshot::persist(executor, ticket).await?;
    context.check_current().map_err(std_io::Error::other)?;
    let mut physical = job
        .lock()
        .map_err(|_| invalid("publication job poisoned"))?;
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("publication custody poisoned"))?;
    state::check_funding(
        &owner,
        &physical.token,
        &state::hex(physical.claim.descriptor().digest()),
        physical.hold,
        physical.generation,
    )?;
    let allocated = io::observe(&owner, &physical)?;
    owner.preparation.recheck()?;
    let future = state::check_charge(&owner)?;
    let body = Arc::clone(
        physical
            .body
            .as_ref()
            .ok_or_else(|| invalid("publication body absent"))?,
    );
    let charged = owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes;
    owner.faulted = false;
    let cleanup_not_before = settle::cleanup_schedule(
        owner.preparation.config.retirement_interval,
        physical.transfer.is_some()
            || physical
                .manifest
                .as_ref()
                .is_some_and(|input| !input.transfers.is_empty()),
    )?;
    physical.complete = true;
    physical.plaintext.clear();
    physical.plaintext.shrink_to_fit();
    Ok(PublicationCompletion {
        body,
        job: Arc::clone(job),
        allocated,
        charged,
        future,
        cleanup_not_before,
    })
}

/// Counts retained manifest headers and actual per-source ownership slots.
pub(super) fn manifest_source_header_bytes() -> usize {
    // Handoff additionally retains one closed admission scope (token plus
    // chunk/dictionary hashes) and temporary/stored backing-hash sets per input.
    std::mem::size_of::<manifest::ManifestInput>()
        + std::mem::size_of::<io::SourceContext>()
        + residence::header_bytes()
        + std::mem::size_of::<super::admission::TransferredFunding>()
        + 32
        + 2 * (std::mem::size_of::<String>() + 64)
        + 2 * (std::mem::size_of::<String>() + 64 + 6 * std::mem::size_of::<usize>())
        + std::mem::size_of::<manifest::SourceTransfer>()
        + retirement_observation_bytes()
        + 2 * std::mem::size_of::<crate::host_cache::NativeChunkSource>()
        + 4 * std::mem::size_of::<TransferSource>()
        + std::mem::size_of::<crate::host_cache::NativeManifestSource>()
        + std::mem::size_of::<super::RetainedManifest>()
}

/// Counts the shared observation payload and both Arc ownership counters.
pub(super) fn retirement_observation_bytes() -> usize {
    std::mem::size_of::<
        crate::publisher_local::client::BodyIncarnationObservation<HostDomainLocation>,
    >() + 2 * std::mem::size_of::<std::sync::atomic::AtomicUsize>()
}

fn invalid(message: &'static str) -> std_io::Error {
    std_io::Error::other(message)
}
