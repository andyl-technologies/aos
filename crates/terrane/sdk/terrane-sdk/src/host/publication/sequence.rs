//! Orders descriptor publication and verified recovery without filesystem guesses.

use std::io::{self, Read, Seek, SeekFrom};

use super::PublicationClaim;

/// Classifies adoption failures without losing their underlying I/O cause.
#[derive(Debug)]
pub enum AdoptionFailure {
    /// The recorded measurement contradicts an independently verified inode.
    RecordedBindingMismatch,
    /// The retained canonical inode could not supply its kernel seal.
    KernelSeal(io::Error),
    /// The sealed inode failed independent plaintext verification.
    Plaintext(io::Error),
    /// Durable quarantine succeeded but exact stale-state removal failed.
    BindingRepair(io::Error),
    /// A rejected binding could not be moved into owned quarantine.
    Quarantine {
        /// The independently classified verification failure.
        cause: Box<AdoptionFailure>,
        /// The actual quarantine namespace or synchronization failure.
        failure: io::Error,
    },
}

impl std::fmt::Display for AdoptionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecordedBindingMismatch => {
                formatter.write_str("recorded verity binding mismatch")
            }
            Self::BindingRepair(error) => write!(formatter, "quarantined binding repair: {error}"),
            Self::KernelSeal(error) => write!(formatter, "canonical kernel seal: {error}"),
            Self::Plaintext(error) => write!(formatter, "canonical plaintext: {error}"),
            Self::Quarantine { cause, failure } => {
                write!(formatter, "{cause}; quarantine failed: {failure}")
            }
        }
    }
}

impl std::error::Error for AdoptionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RecordedBindingMismatch => None,
            Self::KernelSeal(error) | Self::Plaintext(error) | Self::BindingRepair(error) => {
                Some(error)
            }
            Self::Quarantine { failure, .. } => Some(failure),
        }
    }
}

/// Records the kernel measurement independently of the content identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerityBinding {
    /// The Linux fs-verity digest algorithm identifier.
    pub algorithm: u16,
    /// The measured fs-verity digest, including its distinct digest domain.
    pub digest: Vec<u8>,
}

/// Persists only verified bindings; reconstruction witnesses remain metadata.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait PublicationState {
    /// Looks up an existing binding for this exact domain and identity.
    ///
    /// # Errors
    /// Returns state read failures; absence must not hide corruption.
    async fn binding(&self, claim: &PublicationClaim) -> io::Result<Option<VerityBinding>>;

    /// Durably records a verified binding before publication is acknowledged.
    ///
    /// # Errors
    /// Returns write or synchronization failures without acknowledging success.
    async fn record(&mut self, claim: &PublicationClaim, binding: &VerityBinding)
    -> io::Result<()>;

    /// Removes only the exact stale record retained before durable quarantine.
    ///
    /// The caller invokes this only after inode-checked quarantine and both
    /// namespace-parent synchronizations succeed. Implementations retain actual
    /// record identity and must refuse replacement or unrelated state removal.
    ///
    /// # Errors
    /// Returns unsupported repair, changed record or physical durability errors.
    fn forget_quarantined(&mut self, _claim: &PublicationClaim) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "retained binding repair unavailable",
        ))
    }
}

/// Supplies inode-retaining operations unavailable through portable path I/O.
///
/// Adapters must not expose staged handles to consumers. The staged reader retains the exact private inode; `close_writers`
/// consumes every writer before the kernel seal may be enabled.
/// Ordinary metadata persistence belongs to the caller's existing `LocalFs`.
pub trait PublicationKernel {
    /// The incoming owned content descriptor.
    type Source;
    /// A private inode retained throughout verification and writer closure.
    type Staged: Read;
    /// A retained read-only canonical inode descriptor.
    type Handle: Read + Seek;

    /// Copies descriptor content into a fresh publisher-private inode.
    ///
    /// # Errors
    /// Returns invalid source, copy or private inode creation failures.
    fn stage(&mut self, claim: &PublicationClaim, source: Self::Source)
    -> io::Result<Self::Staged>;

    /// Closes every private-inode writer, reporting deferred close errors.
    ///
    /// # Errors
    /// Returns close failures; callers must not proceed to sealing.
    fn close_writers(&mut self, staged: &mut Self::Staged) -> io::Result<()>;

    /// Enables and independently measures the private inode's kernel seal.
    ///
    /// # Errors
    /// Returns unsupported sealing, outstanding writer or measurement failures.
    fn seal(&mut self, staged: &Self::Staged) -> io::Result<VerityBinding>;

    /// Synchronizes the retained inode after seal verification.
    ///
    /// # Errors
    /// Returns inode synchronization failures.
    fn sync_staged(&mut self, staged: &Self::Staged) -> io::Result<()>;

    /// Inserts the canonical link without replacing an existing inode.
    ///
    /// Returns false when a canonical entry already exists.
    ///
    /// # Errors
    /// Returns directory mutation failures other than an existing name.
    fn insert(&mut self, claim: &PublicationClaim, staged: &Self::Staged) -> io::Result<bool>;

    /// Synchronizes the canonical parent directory.
    ///
    /// # Errors
    /// Returns directory synchronization failures.
    fn sync_parent(&mut self, claim: &PublicationClaim) -> io::Result<()>;

    /// Removes a failed insertion only if it still names the staged inode.
    ///
    /// # Errors
    /// Returns failed or uncertain cleanup, including a replaced entry.
    fn rollback(&mut self, claim: &PublicationClaim, staged: &Self::Staged) -> io::Result<()>;

    /// Opens the canonical entry read-only without following symlinks.
    ///
    /// # Errors
    /// Returns missing, unsafe or unreadable canonical inode failures.
    fn open(&mut self, claim: &PublicationClaim) -> io::Result<Self::Handle>;

    /// Measures an existing inode's genuine kernel seal.
    ///
    /// # Errors
    /// Returns missing seal, invalid measurement or kernel failures.
    fn measure(&mut self, handle: &Self::Handle) -> io::Result<VerityBinding>;

    /// Retains a read-only private inode before canonical publication begins.
    ///
    /// # Errors
    /// Returns unsupported retention or actual descriptor-duplication errors.
    fn retain_staged(&mut self, _staged: &Self::Staged) -> io::Result<Self::Handle> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "staged descriptor retention unavailable",
        ))
    }

    /// Duplicates an actual read-only canonical handle before adoption effects.
    ///
    /// # Errors
    /// Returns unsupported retention or actual descriptor-duplication errors.
    fn duplicate_handle(&mut self, _handle: &Self::Handle) -> io::Result<Self::Handle> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "canonical descriptor retention unavailable",
        ))
    }

    /// Synchronizes the retained canonical inode during adoption.
    ///
    /// # Errors
    /// Returns inode synchronization failures.
    fn sync_handle(&mut self, handle: &Self::Handle) -> io::Result<()>;

    /// Moves the exact retained rejected canonical inode into owned quarantine.
    ///
    /// The adapter compares the current entry with `rejected` before mutation
    /// and synchronizes both namespace parents before reporting success.
    ///
    /// # Errors
    /// Returns unsupported quarantine or actual namespace/durability failures.
    fn quarantine_adoption_failure(
        &mut self,
        _claim: &PublicationClaim,
        _rejected: &Self::Handle,
        _cause: &AdoptionFailure,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "owned publication quarantine unavailable",
        ))
    }
}

/// Contains a backing handle only after complete publication or adoption.
pub struct PublishedObject<H> {
    handle: H,
    binding: VerityBinding,
}

impl<H> PublishedObject<H> {
    /// Borrows the verified canonical handle without changing its ownership.
    pub fn handle(&self) -> &H {
        &self.handle
    }

    /// Returns the independently measured kernel binding.
    pub fn binding(&self) -> &VerityBinding {
        &self.binding
    }

    /// Transfers the read-only canonical handle to its consumer.
    pub fn into_handle(self) -> H {
        self.handle
    }
}

/// Owns a verified result and its descriptor retained before publication effects.
pub struct RetainedPublishedObject<H> {
    object: PublishedObject<H>,
    retained: H,
}

impl<H> RetainedPublishedObject<H> {
    /// Transfers both actual handles without further allocation or native I/O.
    pub fn into_parts(self) -> (PublishedObject<H>, H) {
        (self.object, self.retained)
    }
}

// Completion policies are private fixed operations, never caller callbacks.
// Their only fallible work precedes canonical insertion or adoption state writes.
trait Completion<K: PublicationKernel> {
    type Prepared;
    type Output;
    fn staged(kernel: &mut K, staged: &K::Staged) -> io::Result<Self::Prepared>;
    fn existing(kernel: &mut K, handle: &K::Handle) -> io::Result<Self::Prepared>;
    fn finish(object: PublishedObject<K::Handle>, prepared: Self::Prepared) -> Self::Output;
}

struct Direct;
struct Retained;

impl<K: PublicationKernel> Completion<K> for Direct {
    type Prepared = ();
    type Output = PublishedObject<K::Handle>;
    fn staged(_: &mut K, _: &K::Staged) -> io::Result<()> {
        Ok(())
    }
    fn existing(_: &mut K, _: &K::Handle) -> io::Result<()> {
        Ok(())
    }
    fn finish(object: PublishedObject<K::Handle>, _: ()) -> Self::Output {
        object
    }
}

impl<K: PublicationKernel> Completion<K> for Retained {
    type Prepared = K::Handle;
    type Output = RetainedPublishedObject<K::Handle>;
    fn staged(kernel: &mut K, staged: &K::Staged) -> io::Result<Self::Prepared> {
        kernel.retain_staged(staged)
    }
    fn existing(kernel: &mut K, handle: &K::Handle) -> io::Result<Self::Prepared> {
        kernel.duplicate_handle(handle)
    }
    fn finish(object: PublishedObject<K::Handle>, retained: Self::Prepared) -> Self::Output {
        RetainedPublishedObject { object, retained }
    }
}

/// Coordinates a sole-writer adapter and durable binding state.
pub struct Publisher<K, S> {
    kernel: K,
    state: S,
}

impl<K: PublicationKernel, S: PublicationState> Publisher<K, S> {
    /// Constructs a publisher from already authorized adapters.
    pub fn new(kernel: K, state: S) -> Self {
        Self { kernel, state }
    }

    /// Verifies, seals and durably publishes content from an owned descriptor.
    ///
    /// The caller must durably retain reconstruction metadata before calling.
    /// Any late failure withholds the backing handle and attempts inode-checked
    /// cleanup. A surviving canonical entry must pass independent adoption.
    ///
    /// # Errors
    /// Returns claim, sealing, publication or durable-state failures.
    pub async fn publish(
        &mut self,
        claim: &PublicationClaim,
        source: K::Source,
    ) -> io::Result<PublishedObject<K::Handle>> {
        self.publish_as::<Direct>(claim, source).await
    }

    /// Publishes while retaining actual read-only custody before canonical insertion.
    ///
    /// # Errors
    /// Returns verification, retention, publication or durability failures. Failed
    /// prepublication retention cannot create a canonical name.
    pub async fn publish_retained(
        &mut self,
        claim: &PublicationClaim,
        source: K::Source,
    ) -> io::Result<RetainedPublishedObject<K::Handle>> {
        self.publish_as::<Retained>(claim, source).await
    }

    async fn publish_as<C: Completion<K>>(
        &mut self,
        claim: &PublicationClaim,
        source: K::Source,
    ) -> io::Result<C::Output> {
        let mut staged = self.kernel.stage(claim, source)?;
        claim.verify_reader(&mut staged)?;

        self.kernel.close_writers(&mut staged)?;
        let binding = self.kernel.seal(&staged)?;
        self.kernel.sync_staged(&staged)?;
        let prepared = C::staged(&mut self.kernel, &staged)?;

        if !self.kernel.insert(claim, &staged)? {
            return self.adopt_as::<C>(claim).await;
        }

        let finish = async {
            self.kernel.sync_parent(claim)?;
            self.state.record(claim, &binding).await?;

            let handle = self.kernel.open(claim)?;
            if self.kernel.measure(&handle)? != binding {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "canonical seal changed before publication acknowledgment",
                ));
            }

            Ok(C::finish(PublishedObject { handle, binding }, prepared))
        }
        .await;

        if finish.is_err() {
            // Cleanup is best effort: its failure cannot turn an unacknowledged
            // publication into a servable object. Recovery verifies independently.
            let _cleanup = self.kernel.rollback(claim, &staged);
        }

        finish
    }

    /// Independently verifies an existing canonical inode before adoption.
    ///
    /// A conflicting recorded measurement is corruption, never missing state.
    ///
    /// # Errors
    /// Returns unsafe inode, seal, plaintext, binding or synchronization failures.
    pub async fn adopt(
        &mut self,
        claim: &PublicationClaim,
    ) -> io::Result<PublishedObject<K::Handle>> {
        self.adopt_as::<Direct>(claim).await
    }

    /// Adopts while retaining actual read-only custody before durable-state effects.
    ///
    /// # Errors
    /// Returns unsafe inode, verification, retention or durability failures.
    pub async fn adopt_retained(
        &mut self,
        claim: &PublicationClaim,
    ) -> io::Result<RetainedPublishedObject<K::Handle>> {
        self.adopt_as::<Retained>(claim).await
    }

    async fn adopt_as<C: Completion<K>>(
        &mut self,
        claim: &PublicationClaim,
    ) -> io::Result<C::Output> {
        let mut handle = self.kernel.open(claim)?;
        let binding = match self.kernel.measure(&handle) {
            Ok(binding) => binding,
            Err(error) => {
                return self.reject_adoption(claim, &handle, AdoptionFailure::KernelSeal(error));
            }
        };
        if let Err(error) = claim.verify_reader(&mut handle) {
            return self.reject_adoption(claim, &handle, AdoptionFailure::Plaintext(error));
        }

        if self
            .state
            .binding(claim)
            .await?
            .is_some_and(|existing| existing != binding)
        {
            return self.reject_adoption(claim, &handle, AdoptionFailure::RecordedBindingMismatch);
        }

        handle.seek(SeekFrom::Start(0))?;
        let prepared = C::existing(&mut self.kernel, &handle)?;
        self.kernel.sync_handle(&handle)?;
        self.kernel.sync_parent(claim)?;
        self.state.record(claim, &binding).await?;

        Ok(C::finish(PublishedObject { handle, binding }, prepared))
    }

    fn reject_adoption<T>(
        &mut self,
        claim: &PublicationClaim,
        rejected: &K::Handle,
        cause: AdoptionFailure,
    ) -> io::Result<T> {
        if let Err(failure) = self
            .kernel
            .quarantine_adoption_failure(claim, rejected, &cause)
        {
            return Err(io::Error::new(
                failure.kind(),
                AdoptionFailure::Quarantine {
                    cause: Box::new(cause),
                    failure,
                },
            ));
        }
        if matches!(&cause, AdoptionFailure::RecordedBindingMismatch)
            && let Err(error) = self.state.forget_quarantined(claim)
        {
            return Err(io::Error::new(
                error.kind(),
                AdoptionFailure::BindingRepair(error),
            ));
        }
        let kind = match &cause {
            AdoptionFailure::KernelSeal(error) | AdoptionFailure::Plaintext(error) => error.kind(),
            _ => io::ErrorKind::InvalidData,
        };
        Err(io::Error::new(kind, cause))
    }

    /// Returns the owned adapters for shutdown or administrative maintenance.
    pub fn into_parts(self) -> (K, S) {
        (self.kernel, self.state)
    }
}
