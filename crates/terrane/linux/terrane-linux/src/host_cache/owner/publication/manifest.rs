//! Reassembles genuinely retained metadata and admitted sources under Running custody.
//!
//! The physical job retains the metadata pin, ordered source descriptors,
//! original admissions and actual retirement replies independently of waiters.
//! Ordinary cached metadata never becomes embedded policy or serving authority.

use super::{
    super::{
        admission::{TransferSource, pack_reads::AdmittedPackRead},
        retention::{Command, Custody, NativeMetadataOwner, NativeOwnerExecutor},
    },
    PublicationCompletion, PublicationJob, invalid,
};
use crate::{
    host_cache::{NativeChunkSource, NativeReassemblyPlan, RetainedManifest},
    publisher_local::{
        client::{
            BodyIncarnationObservation, Client, PeerPublishedObject, PublisherRunningContext,
        },
        socket::ReceivedPacket,
    },
};
use std::{
    fs::File,
    io,
    sync::{Arc, mpsc},
};
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::host::{cache::HostDomainLocation, publication::PublicationClaim};
use tokio::sync::oneshot;

/// Owns a completed manifest publication and its original native resources.
///
/// Immutable accessors take no embedded-state locks. The physical owner keeps
/// the actual metadata pin and future holds after waiter or receipt destruction.
/// Source handles remain owned through acknowledged cleanup. This grants no
/// consumer lease or Store readiness.
pub struct NativeManifestPublication {
    pub(super) completion: PublicationCompletion,
}

impl NativeManifestPublication {
    /// Transfers the completed publication into cache ownership and release grace.
    ///
    /// Final standalone-source cleanup must have completed first. Producer views
    /// close; independently pinned consumers and reconstruction metadata remain
    /// owned. Queue refusals return this receipt for retry. Accepted commands
    /// consume it; failed or cancelled operations stay on their physical owner.
    ///
    /// # Errors
    /// Refuses stopped/full queues, foreign or incomplete work, active producer
    /// reads, missing cleanup acknowledgments, changed backing or failed durable
    /// policy and quota reconciliation. No producer descriptor is returned.
    pub async fn into_cache(
        self,
        owner: &NativeMetadataOwner,
    ) -> Result<super::NativeCacheHandoffReport, super::NativeCacheHandoffError<Self>> {
        let job = Arc::clone(&self.completion.job);
        super::handoff::submit(owner, job, self).await
    }

    /// Closes this publication's externally issued producer read views.
    ///
    /// Later external producer-view acquisition is also refused permanently.
    /// Internal reassembly sources and separately synchronized consumer leases
    /// retain their own protection. The operation releases no durable pin,
    /// lease or reservation and grants no cache ownership or eviction authority.
    /// Accepted closure continues after waiter cancellation.
    ///
    /// # Errors
    /// Refuses another physical owner, a stopped/full queue, stale publication
    /// funding, absent Running custody or an unavailable worker response.
    pub async fn close_resident_reads(
        &self,
        owner: &NativeMetadataOwner,
    ) -> io::Result<super::NativeProducerReadClosure> {
        super::producer_reads::submit(owner, &self.completion.job).await
    }

    /// Finishes the original standalone source retirements on their physical owner.
    ///
    /// Call after the configured publisher retirement grace. The result counts
    /// only actual original standalone transfers; reused sealed ranges do not
    /// retire again. Repeated calls check retained native acknowledgements.
    /// The owner closes its original source descriptions and completed reassembly
    /// plan only after real final-removal acknowledgements. Reconstruction
    /// metadata, pins and holds remain retained; independently held descriptions
    /// may still retain physical charge after pending names are removed.
    ///
    /// # Errors
    /// Refuses another owner, queue limits, active native grace, stale backing,
    /// quota failures and uncertain exchanges. Accepted failures require actual
    /// recovery, retaining funding and resources after waiter cancellation.
    pub async fn finish_retired_sources(
        &self,
        owner: &NativeMetadataOwner,
    ) -> io::Result<super::NativeSourceCleanupReport> {
        super::retirement::submit(owner, &self.completion.job).await
    }

    /// Borrows independently verified read-only sealed bytes.
    pub fn handle(&self) -> &File {
        self.completion.body.handle()
    }

    /// Borrows the verified canonical manifest and complete content declaration.
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
    /// Reassembles and publishes one genuinely retained manifest after actual Resume.
    ///
    /// The physical owner looks up canonical metadata and original admitted
    /// chunks itself. It synchronizes metadata retention and allocation funding
    /// before creating output, streams ordered bytes through content verification,
    /// and retires actual standalone sources before recording their sealed ranges.
    /// Existing sealed ranges retain their original completed job and residence.
    /// Packed inputs retain their actual admitted pair with synchronized source
    /// pins and handoff grace; only standalone sources retire into this object.
    /// This never guesses source bytes or reconstructs metadata from plaintext.
    /// View-policy selection belongs to the caller's trusted tier composition,
    /// before this explicit physical operation.
    ///
    /// # Errors
    /// Refuses a full/stopped queue, absent Resume, invalid or missing metadata,
    /// unavailable genuine sources, exhausted operator resources, failed native
    /// publication/retirement or changed durability and quota custody. Accepted
    /// work remains physically owned after cancellation; errors return no backing.
    pub async fn publish_manifest(
        &self,
        identity: Identity,
    ) -> io::Result<NativeManifestPublication> {
        let (response, receive) = oneshot::channel();
        let commands = self
            .commands
            .as_ref()
            .ok_or_else(|| invalid("publication owner stopped"))?;
        commands
            .try_send(Command::PublishManifest { identity, response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "publication queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "publication owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| invalid("publication owner terminated before manifest completion"))?
    }
}

/// Retains one unique original source and all accepted retirement resources.
pub(super) struct SourceTransfer {
    /// Original registered admission retained through native cleanup.
    pub(super) source: TransferSource,
    /// Actual inspected source reply retained before verification.
    pub(super) reply: Option<ReceivedPacket>,
    /// Original connection-bound inode observation used for retirement.
    pub(super) observation: Option<Arc<BodyIncarnationObservation<HostDomainLocation>>>,
    /// Actual acknowledged rename into the pending namespace.
    pub(super) retired: bool,
    /// Actual correlated final-removal acknowledgement, never an asserted flag.
    pub(super) cleanup: Option<crate::publisher_local::client::AcknowledgedSourceRetirement>,
}

/// Retains verified ordered reads and the actual pin closure that funds them.
pub(super) struct ManifestInput {
    pub(super) retained: Arc<RetainedManifest>,
    pub(super) plan: Option<NativeReassemblyPlan>,
    pub(super) transfers: Vec<SourceTransfer>,
    dependencies: Vec<TransferSource>,
    residents: Vec<Arc<crate::host_cache::NativeResidentChunkSource>>,
    packs: Vec<Arc<AdmittedPackRead>>,
}

impl ManifestInput {
    /// Relinquishes private copy inputs after cache handoff has retained their grace.
    ///
    /// The completed plan has already closed its reads. Durable release pins
    /// protect the original bodies independently; keeping these descriptions
    /// would retain their quota after those pins expire and final unlink succeeds.
    pub(super) fn take_copy_inputs(
        &mut self,
    ) -> (
        Vec<Arc<crate::host_cache::NativeResidentChunkSource>>,
        Vec<Arc<AdmittedPackRead>>,
    ) {
        (
            std::mem::take(&mut self.residents),
            std::mem::take(&mut self.packs),
        )
    }

    /// Derives backing protection from original sealed sources and admitted pairs.
    ///
    /// # Errors
    /// Refuses changed original source protection.
    pub(super) fn backing_hashes(&self, owner: &Custody) -> io::Result<Vec<String>> {
        let mut hashes = std::collections::BTreeSet::new();
        for source in &self.residents {
            source.check_protected(owner)?;
            hashes.insert(super::state::hex(source.protected_object_digest()));
        }
        for source in &self.packs {
            source.check_protected(owner)?;
            hashes.extend(source.digests().map(super::state::hex));
        }
        Ok(hashes.into_iter().collect())
    }

    fn prepare(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        retained: RetainedManifest,
    ) -> io::Result<Self> {
        retained.check_registration(owner)?;
        let claim = retained.claim();
        let declaration = claim
            .manifest()
            .ok_or_else(|| invalid("publication metadata is not a manifest"))?;
        let limit = owner.preparation.config.inventory_entries;
        if declaration.chunks.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "ordered source inventory exceeds operator budget",
            ));
        }
        let mut sources = Vec::new();
        let mut residents: Vec<Arc<crate::host_cache::NativeResidentChunkSource>> = Vec::new();
        residents
            .try_reserve_exact(declaration.chunks.len())
            .map_err(io::Error::other)?;
        let mut packs: Vec<Arc<AdmittedPackRead>> = Vec::new();
        packs
            .try_reserve_exact(declaration.chunks.len())
            .map_err(io::Error::other)?;
        let mut transfers: Vec<SourceTransfer> = Vec::new();
        let mut dependencies: Vec<TransferSource> = Vec::new();
        sources
            .try_reserve_exact(declaration.chunks.len())
            .map_err(io::Error::other)?;
        transfers
            .try_reserve_exact(declaration.chunks.len())
            .map_err(io::Error::other)?;
        dependencies
            .try_reserve_exact(owner.preparation.config.state.records)
            .map_err(io::Error::other)?;
        for (index, chunk) in declaration.chunks.iter().enumerate() {
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &chunk.digest)
                .map_err(io::Error::other)?;
            let chunk_hash = super::state::hex(identity.digest());
            if owner
                .state
                .residences
                .iter()
                .any(|row| row.chunk == chunk_hash)
            {
                super::io::refuse_standalone(owner, identity.digest())?;
                let source = match residents
                    .iter()
                    .find(|source| source.identity() == &identity)
                {
                    Some(source) => Arc::clone(source),
                    None => {
                        let source = Arc::new(super::residence::retain_registered(
                            executor,
                            owner,
                            identity.clone(),
                        )?);
                        residents.push(Arc::clone(&source));
                        source
                    }
                };
                if u64::try_from(source.span().length).map_err(io::Error::other)? != chunk.length {
                    return Err(invalid("resident chunk length differs from new manifest"));
                }
                sources.push(NativeChunkSource::from_resident(
                    source,
                    index + 1 == declaration.chunks.len(),
                )?);
                continue;
            }
            let Some(actual) =
                TransferSource::select_chunk_optional(executor, owner, &identity, chunk.length)?
            else {
                // Whole-pack cache custody remains independent of this object.
                // Retain and pin the genuine pair; never synthesize a standalone
                // extraction or retire other members to assemble one object.
                super::io::refuse_standalone(owner, &chunk.digest)?;
                let source = match packs.iter().find(|source| source.identity() == &identity) {
                    Some(source) => Arc::clone(source),
                    None => {
                        let source = Arc::new(AdmittedPackRead::prepare_publication(
                            executor, owner, identity,
                        )?);
                        packs.push(Arc::clone(&source));
                        source
                    }
                };
                sources.push(NativeChunkSource::from_pack(
                    source,
                    index + 1 == declaration.chunks.len(),
                )?);
                continue;
            };
            actual.check_retirement(executor, owner)?;
            super::io::refuse_other_standalone(owner, &chunk.digest, actual.key().codec)?;
            let source = NativeChunkSource::open_bounded(
                owner.preparation.layout(),
                identity,
                usize::try_from(chunk.length).map_err(io::Error::other)?,
                index + 1 == declaration.chunks.len(),
                owner.preparation.config.reads.max_allocation_bytes,
                owner.preparation.config.state.records,
            )?;
            // Match every actual readable inode, including dictionaries, to a
            // completed native admission with its original durable pin and hold.
            for (identity, length, file) in source.handles() {
                let dependency = TransferSource::select_chunk(
                    executor,
                    owner,
                    identity,
                    u64::try_from(length).map_err(io::Error::other)?,
                )?;
                dependency.check_received(owner, file)?;
                if !dependencies.iter().any(|old| old.key() == dependency.key()) {
                    if dependencies.len() >= owner.preparation.config.state.records {
                        return Err(invalid("source dependencies exceed owner registry bound"));
                    }
                    dependencies.push(dependency);
                }
            }
            if !transfers.iter().any(|old| old.source.key() == actual.key()) {
                transfers.push(SourceTransfer {
                    source: actual,
                    reply: None,
                    observation: None,
                    cleanup: None,
                    retired: false,
                });
            }
            sources.push(source);
        }
        let plan = NativeReassemblyPlan::new(owner.preparation.layout(), claim.clone(), sources)?;
        Ok(Self {
            retained: Arc::new(retained),
            plan: Some(plan),
            transfers,
            dependencies,
            residents,
            packs,
        })
    }

    /// Checks the original source closure before copying and after native effects.
    ///
    /// # Errors
    /// Refuses missing metadata pins, altered actual admissions or changed bytes.
    pub(super) fn check(&self, owner: &Custody) -> io::Result<()> {
        self.retained.check_registration(owner)?;
        for source in &self.residents {
            source.check_protected(owner)?;
        }
        for source in &self.packs {
            source.check_protected(owner)?;
        }
        for dependency in &self.dependencies {
            if self
                .transfers
                .iter()
                .any(|entry| entry.retired && entry.source.key() == dependency.key())
            {
                dependency.check_retired(owner)?;
            } else {
                dependency.check_current(owner)?;
            }
        }
        Ok(())
    }

    /// Recognizes an original range retained from its genuine completed job.
    pub(super) fn retains_residence(
        &self,
        row: &terrane_sdk::host::cache::ResidenceRecord,
    ) -> bool {
        self.residents
            .iter()
            .any(|source| source.matches_record(row))
    }

    /// Clones actual admissions for the exclusive turn without duplicating payloads.
    ///
    /// # Errors
    /// Refuses allocation failure before publisher submission.
    pub(super) fn transfer_sources(&self) -> io::Result<Vec<TransferSource>> {
        let mut sources = Vec::new();
        sources
            .try_reserve_exact(self.transfers.len())
            .map_err(io::Error::other)?;
        sources.extend(self.transfers.iter().map(|entry| entry.source.clone()));
        Ok(sources)
    }

    /// Retains each actual inspected reply and acknowledgment under this job.
    ///
    /// # Errors
    /// Refuses any native or transport uncertainty without discarding prior work.
    pub(super) fn retire_sources(
        &mut self,
        session: &Client<HostDomainLocation>,
        body: &PeerPublishedObject<HostDomainLocation>,
        context: &PublisherRunningContext,
        turn: &mut crate::host_cache::PublisherRunningTurn<'_>,
    ) -> io::Result<()> {
        for (index, entry) in self.transfers.iter_mut().enumerate() {
            let observation = session
                .inspect_source_transfer(body, context, turn, index, &mut entry.reply)
                .map_err(io::Error::other)?;
            entry.observation = Some(Arc::new(observation));
            session
                .retire_source_transfer(
                    body,
                    context,
                    turn,
                    index,
                    entry
                        .observation
                        .as_ref()
                        .ok_or_else(|| invalid("manifest source observation absent"))?,
                )
                .map_err(io::Error::other)?;
            entry.retired = true;
        }
        Ok(())
    }

    /// Requires every source's actual retirement before installing sealed ranges.
    ///
    /// # Errors
    /// Refuses unacknowledged retirement, lost observed custody or canonical copies.
    pub(super) fn check_retired(&self, owner: &Custody) -> io::Result<()> {
        self.check(owner)?;
        for entry in &self.transfers {
            if !entry.retired || entry.observation.is_none() || entry.reply.is_none() {
                return Err(invalid(
                    "manifest source lacks actual retirement acknowledgment",
                ));
            }
            let descriptor = Descriptor::decode(&TERRANE_V1, &entry.source.key().descriptor)
                .map_err(io::Error::other)?;
            super::io::refuse_standalone(owner, descriptor.digest())?;
        }
        Ok(())
    }
}

/// Runs actual manifest publication under the same registered physical job owner.
///
/// # Errors
/// Refuses absent Running custody or genuine sources, native/transport failures,
/// and unavailable synchronized accounting while retaining accepted resources.
pub(in crate::host_cache::owner) async fn run(
    executor: &mut NativeOwnerExecutor,
    identity: Identity,
) -> io::Result<NativeManifestPublication> {
    let context = executor.admission_context()?;
    context.check_current().map_err(io::Error::other)?;
    let retained = executor.retain_metadata(identity).await?;
    super::eviction::restore_publication(executor, retained.claim().descriptor()).await?;
    let (layout, limit) = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        (
            Arc::clone(owner.preparation.layout()),
            owner.preparation.config.inventory_entries,
        )
    };
    let residences = crate::host_cache::NativeResidencePlan::new(&layout, retained.claim(), limit)?;
    for identity in residences.identities()? {
        super::eviction::restore_for(executor, &identity).await?;
        super::residence::prepare_recovered_inline(executor, &identity).await?;
    }
    let custody = Arc::clone(executor.custody());
    context.check_current().map_err(io::Error::other)?;
    let input = {
        let owner = custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        owner.check_current()?;
        ManifestInput::prepare(executor, &owner, retained)?
    };
    context.check_current().map_err(io::Error::other)?;
    let claim = input.retained.claim().clone();
    let job = executor.register_publication(PublicationJob {
        order: 0,
        custody,
        encoded: Vec::new(),
        plaintext: Vec::new(),
        claim,
        dictionary: None,
        manifest: Some(input),
        transfer: None,
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
    })?;
    let outcome = super::execute(executor, &job, &context).await;
    if outcome.is_err() {
        executor.reclaim_publication(&job)?;
    }
    outcome.map(|completion| NativeManifestPublication { completion })
}
