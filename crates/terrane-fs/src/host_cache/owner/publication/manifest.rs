//! Reassembles genuinely retained metadata and admitted sources under Running custody.
//!
//! The physical job retains the metadata pin, ordered source descriptors,
//! original admissions and actual retirement replies independently of waiters.
//! Ordinary cached metadata never becomes embedded policy or serving authority.

use super::{
    super::{
        admission::TransferSource,
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
use terrane::host::{cache::HostDomainLocation, publication::PublicationClaim};
use terrane_core::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use tokio::sync::oneshot;

/// Owns a completed manifest publication and its original native resources.
///
/// Immutable accessors take no embedded-state locks. The physical owner keeps
/// the actual metadata pin, source handles and future holds after waiter or
/// receipt destruction. This grants no consumer lease or Store readiness.
pub struct NativeManifestPublication {
    completion: PublicationCompletion,
}

impl NativeManifestPublication {
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
    /// Existing sealed-range sources require the separately retained native read
    /// path; this operation never guesses their bytes or reconstructs metadata
    /// from assembled plaintext. View-policy selection belongs to the caller's
    /// trusted tier composition, before this explicit physical operation.
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
    source: TransferSource,
    reply: Option<ReceivedPacket>,
    observation: Option<BodyIncarnationObservation<HostDomainLocation>>,
    retired: bool,
}

/// Retains verified ordered reads and the actual pin closure that funds them.
pub(super) struct ManifestInput {
    pub(super) retained: Arc<RetainedManifest>,
    pub(super) plan: NativeReassemblyPlan,
    transfers: Vec<SourceTransfer>,
    dependencies: Vec<TransferSource>,
}

impl ManifestInput {
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
        let mut transfers: Vec<SourceTransfer> = Vec::new();
        let mut dependencies: Vec<TransferSource> = Vec::new();
        sources
            .try_reserve_exact(declaration.chunks.len())
            .map_err(io::Error::other)?;
        transfers
            .try_reserve_exact(declaration.chunks.len())
            .map_err(io::Error::other)?;
        dependencies
            .try_reserve_exact(
                declaration
                    .chunks
                    .len()
                    .checked_mul(2)
                    .ok_or_else(|| invalid("source inventory overflow"))?,
            )
            .map_err(io::Error::other)?;
        for (index, chunk) in declaration.chunks.iter().enumerate() {
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &chunk.digest)
                .map_err(io::Error::other)?;
            let actual = TransferSource::select_chunk(executor, owner, &identity, chunk.length)?;
            super::io::refuse_other_standalone(owner, &chunk.digest, actual.key().codec)?;
            let source = NativeChunkSource::open_bounded(
                owner.preparation.layout(),
                identity,
                usize::try_from(chunk.length).map_err(io::Error::other)?,
                index + 1 == declaration.chunks.len(),
                owner.preparation.config.reads.max_allocation_bytes,
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
                    dependencies.push(dependency);
                }
            }
            if !transfers.iter().any(|old| old.source.key() == actual.key()) {
                transfers.push(SourceTransfer {
                    source: actual,
                    reply: None,
                    observation: None,
                    retired: false,
                });
            }
            sources.push(source);
        }
        let plan = NativeReassemblyPlan::new(owner.preparation.layout(), claim.clone(), sources)?;
        Ok(Self {
            retained: Arc::new(retained),
            plan,
            transfers,
            dependencies,
        })
    }

    /// Checks the original source closure before copying and after native effects.
    ///
    /// # Errors
    /// Refuses missing metadata pins, altered actual admissions or changed bytes.
    pub(super) fn check(&self, owner: &Custody) -> io::Result<()> {
        self.retained.check_registration(owner)?;
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
            entry.observation = Some(observation);
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
    let custody = Arc::clone(executor.custody());
    let input = {
        let owner = custody
            .lock()
            .map_err(|_| invalid("publication custody poisoned"))?;
        owner.check_current()?;
        ManifestInput::prepare(executor, &owner, retained)?
    };
    let claim = input.retained.claim().clone();
    let job = executor.register_publication(PublicationJob {
        custody,
        encoded: Vec::new(),
        plaintext: Vec::new(),
        claim,
        dictionary: None,
        manifest: Some(input),
        transfer: None,
        transfer_observation: None,
        transfer_retired: false,
        token: String::new(),
        hold: 0,
        generation: 0,
        started: false,
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
