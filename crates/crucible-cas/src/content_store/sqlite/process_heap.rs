//! Owns one genuinely prepaid SQLite heap and its managed native connections.
//!
//! Installation and terminal cleanup share a process fence. Healthy database
//! operations retain their individual connection locks and run concurrently.
//! A refused or uncertain native close retains the original heap and actor.

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

use crate::owned_decode::ResourceLoan;

mod connection;
use connection::ConnectionOwner;
pub use connection::SqliteConnection;
pub(super) use connection::SqliteConnectionGuard;

/// Issues memory from the original process service that owns SQLite.
///
/// The native heap and retained Rust controls are distinct purposes. An issuer
/// keeps its original actor alive until every returned credit has closed.
pub trait SqliteHeapAuthority: Send + Sync {
    /// Checks the retained original service without issuing another credit.
    ///
    /// # Errors
    /// Refuses closed, expired, canceled or unavailable original ownership.
    fn verify_live(&self) -> Result<(), super::StoreError>;

    /// Reserves the one process-native heap before SQLite initialization.
    ///
    /// # Errors
    /// Refuses insufficient original resident capacity or unavailable custody.
    fn reserve_heap(&self, bytes: u64) -> Result<ResourceLoan, super::StoreError>;

    /// Prepays retained Rust storage and its credit controls.
    ///
    /// # Errors
    /// Refuses insufficient original metadata or resident capacity.
    fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, super::StoreError>;
}

/// Retains a prepaid issuer control outside its shared allocation.
///
/// The original control credit closes after the issuer allocation. Its credit
/// also retains the original actor through its final refund. Issuance is a
/// caller responsibility; neither this value nor its extent supplies authority.
pub struct SqliteHeapIssuer {
    authority: Option<Arc<dyn SqliteHeapAuthority>>,
    _control: ResourceLoan,
}

impl SqliteHeapIssuer {
    /// Publishes one original issuer under its already retained control credit.
    #[must_use]
    pub fn new<T: SqliteHeapAuthority + 'static>(authority: T, credit: ResourceLoan) -> Self {
        Self {
            authority: Some(Arc::new(authority)),
            _control: credit,
        }
    }

    /// Returns the concrete issuer control extent before allocation.
    #[must_use]
    pub const fn control_bytes<T: SqliteHeapAuthority>() -> u64 {
        ResourceLoan::allocation_bytes::<T>()
    }

    fn authority(&self) -> Result<&dyn SqliteHeapAuthority, SqliteHeapError> {
        self.authority
            .as_deref()
            .ok_or_else(|| refusal("SQLite issuer has closed"))
    }
}

impl Drop for SqliteHeapIssuer {
    fn drop(&mut self) {
        drop(self.authority.take());
        // The sole dynamic Arc has now closed. The separate credit field and
        // its original actor remain live until automatic field destruction.
    }
}

/// Issues the permanent process purpose before SQLite's first native entry.
///
/// Implementations retain the original process bootstrap actor and prepay the
/// linked library's fixed native state and initialization peak, plus the actual
/// Rust lifecycle storage supplied below. A campaign's reclaimable heap issuer
/// cannot substitute for this process-lifetime ownership.
pub trait SqliteProcessBootstrapAuthority {
    /// Checks the original process issuer before creating permanent custody.
    ///
    /// # Errors
    /// Refuses unavailable, expired or unauthenticated process ownership.
    fn verify_live(&self) -> Result<(), super::StoreError>;

    /// Prepays the native bootstrap purpose and actual Rust lifecycle storage.
    ///
    /// The argument covers Rust storage only. The implementation includes its
    /// source-qualified native globals, initialization peak and credit controls.
    /// Returned credit retains that original process actor for process lifetime.
    ///
    /// # Errors
    /// Refuses insufficient original capacity or an unqualified native purpose.
    fn reserve_bootstrap(
        &self,
        rust_metadata_bytes: u64,
    ) -> Result<ResourceLoan, super::StoreError>;
}

#[derive(Debug, thiserror::Error)]
pub(super) enum HeapFailure {
    #[error("SQLite allocator setup failed")]
    Native(#[from] crucible_sqlite_heap::NativeHeapError),
    #[error("SQLite connection close failed")]
    Connection(#[from] rusqlite::Error),
    #[error("SQLite connection ownership is poisoned")]
    PoisonedConnection,
}

/// Preserves a heap lifecycle refusal and its first native cleanup cause.
#[derive(Clone)]
pub struct SqliteHeapError {
    reason: &'static str,
    owner: Option<Arc<HeapOwner>>,
}

impl fmt::Debug for SqliteHeapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteHeapError")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SqliteHeapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl Error for SqliteHeapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.owner
            .as_ref()?
            .failure
            .get()
            .map(|error| error as &dyn Error)
    }
}

fn refusal(reason: &'static str) -> SqliteHeapError {
    SqliteHeapError {
        reason,
        owner: None,
    }
}

struct HeapOwner {
    generation: u64,
    maximum: i64,
    failure: OnceLock<HeapFailure>,
    // These loans close after the shared allocation has been extracted.
    _metadata: ResourceLoan,
    _heap: ResourceLoan,
    // Original actor custody outlives both original credits.
    issuer: SqliteHeapIssuer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Active,
    Closing,
    Quarantined,
}

struct Installed {
    owner: Arc<HeapOwner>,
    connections: Box<[Option<Arc<ConnectionOwner>>]>,
    phase: Phase,
}

struct Process {
    next_generation: u64,
    installing: Option<u64>,
    installed: Option<Installed>,
    // The process fence remains allocated between installations. Its original
    // fixed-purpose credit is therefore retained for the process lifetime.
    bootstrap: Option<ResourceLoan>,
}

static PROCESS: Mutex<Process> = Mutex::new(Process {
    next_generation: 1,
    installing: None,
    installed: None,
    bootstrap: None,
});

fn process() -> Result<std::sync::MutexGuard<'static, Process>, SqliteHeapError> {
    PROCESS
        .lock()
        .map_err(|_| refusal("SQLite process ownership is poisoned"))
}

impl Installed {
    fn error(&self, reason: &'static str) -> SqliteHeapError {
        SqliteHeapError {
            reason,
            owner: Some(self.owner.clone()),
        }
    }
}

/// Borrows one installed process heap under the same original service.
///
/// Clones retain the same finite heap. A different issuer cannot install while
/// this scope or any managed connection remains live. No raw connection or
/// native heap-limit setter escapes this owner.
pub struct SqliteProcessHeap {
    owner: Option<Arc<HeapOwner>>,
}

impl Clone for SqliteProcessHeap {
    fn clone(&self) -> Self {
        Self {
            owner: self.owner.clone(),
        }
    }
}

impl SqliteProcessHeap {
    /// Publishes the permanent original process credit before native entry.
    ///
    /// This admits no database and supplies no reclaimable heap credit. The
    /// returned permanent loan belongs to the original bootstrap issuer rather
    /// than whichever campaign first requests a connection.
    ///
    /// # Errors
    /// Refuses an occupied bootstrap, concurrent installation, unavailable
    /// original issuer or insufficient source-qualified permanent capacity.
    pub fn prepare_bootstrap(
        authority: &dyn SqliteProcessBootstrapAuthority,
    ) -> Result<(), super::StoreError> {
        authority.verify_live()?;
        let mut state = process()?;
        if state.bootstrap.is_some() || state.installing.is_some() || state.installed.is_some() {
            return Err(refusal("SQLite process bootstrap is already owned").into());
        }
        // Issuance creates no SQLite effect. The fixed process fence excludes
        // competing bootstrap publication until this exact original loan exists.
        let credit = authority.reserve_bootstrap(std::mem::size_of::<Mutex<Process>>() as u64)?;
        authority.verify_live()?;
        state.bootstrap = Some(credit);
        Ok(())
    }

    /// Installs one finite original heap before opening any database.
    ///
    /// The issuer reserves H once, separately from fixed metadata. The bounded
    /// connection table is published before native effects. Initialization's
    /// actual pre-limit peak still requires qualification against the original
    /// grant; the hard limit itself is installed after native initialization.
    ///
    /// # Errors
    /// Refuses invalid limits, occupied or uncertain process ownership, original
    /// admission failure, native initialization failure or unowned native state.
    pub fn install(
        issuer: SqliteHeapIssuer,
        maximum_heap_bytes: u64,
        maximum_connections: usize,
    ) -> Result<Self, super::StoreError> {
        Self::install_inner::<false>(issuer, maximum_heap_bytes, maximum_connections)
    }

    /// Exercises the actual late installation generation refusal after table allocation.
    ///
    /// This fixed test control performs no native initialization or open. It
    /// shares the ordinary staging and refusal path under the supplied original.
    ///
    /// # Errors
    /// Returns the original admission error or the deliberate generation refusal.
    #[cfg(feature = "test-support")]
    pub fn refuse_installation_after_table_for_test(
        issuer: SqliteHeapIssuer,
        maximum_heap_bytes: u64,
        maximum_connections: usize,
    ) -> Result<Self, super::StoreError> {
        Self::install_inner::<true>(issuer, maximum_heap_bytes, maximum_connections)
    }

    fn install_inner<const REFUSE_GENERATION: bool>(
        issuer: SqliteHeapIssuer,
        maximum_heap_bytes: u64,
        maximum_connections: usize,
    ) -> Result<Self, super::StoreError> {
        let authority = issuer.authority()?;
        authority.verify_live()?;
        let maximum = i64::try_from(maximum_heap_bytes)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| refusal("SQLite heap must be positive and representable"))?;
        if maximum_connections == 0 {
            return Err(refusal("SQLite connection roster is empty").into());
        }
        let generation = {
            let mut state = process()?;
            if state.bootstrap.is_none() {
                return Err(refusal("SQLite requires its original process bootstrap").into());
            }
            if state.installing.is_some() || state.installed.is_some() {
                return Err(refusal("a different SQLite process scope is retained").into());
            }
            if crucible_sqlite_heap::memory_used() != 0 {
                return Err(refusal("SQLite native memory has no managed original owner").into());
            }
            let generation = state.next_generation;
            state.next_generation = generation
                .checked_add(1)
                .ok_or_else(|| refusal("SQLite scope generations are exhausted"))?;
            state.installing = Some(generation);
            generation
        };
        let mut installation = Installation {
            generation,
            published: false,
        };
        let heap_credit = authority.reserve_heap(maximum_heap_bytes)?;
        let metadata = authority.reserve_metadata(Self::metadata_bytes(maximum_connections)?)?;
        authority.verify_live()?;
        let handle = Self {
            owner: Some(Arc::new(HeapOwner {
                generation,
                maximum,
                failure: OnceLock::new(),
                _metadata: metadata,
                _heap: heap_credit,
                issuer,
            })),
        };
        // The consuming handle owns the sole control immediately. Refusal or
        // unwind before publication still frees that allocation before loans.
        // Declare the table after its owner so unpublished teardown closes
        // this allocation before the owner's shared metadata credit refunds.
        let connections = std::iter::repeat_with(|| None)
            .take(maximum_connections)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        if REFUSE_GENERATION {
            process()?.installing = None;
        }
        let owner = handle.identity()?;
        let mut state = process()?;
        if state.installing != Some(generation) {
            return Err(refusal("SQLite installation lost its original generation").into());
        }
        state.installed = Some(Installed {
            owner: owner.clone(),
            connections,
            phase: Phase::Quarantined,
        });
        state.installing = None;
        installation.published = true;
        // The original owner is already published. The integer boundary does
        // not supply authority or turn this current sample into a peak bound.
        let positive = std::num::NonZeroU64::new(maximum_heap_bytes)
            .ok_or_else(|| refusal("SQLite heap must be positive"))?;
        let used = match crucible_sqlite_heap::install_limit(positive) {
            Ok(used) => used,
            Err(source) => {
                let _ = owner.failure.set(source.into());
                return Err(state
                    .installed
                    .as_ref()
                    .ok_or_else(|| refusal("SQLite owner disappeared"))?
                    .error("SQLite allocator setup failed under retained ownership")
                    .into());
            }
        };
        if used < 0 || used > maximum {
            return Err(state
                .installed
                .as_ref()
                .ok_or_else(|| refusal("SQLite owner disappeared"))?
                .error("SQLite initialization exceeds the original heap")
                .into());
        }
        state
            .installed
            .as_mut()
            .ok_or_else(|| refusal("SQLite owner disappeared"))?
            .phase = Phase::Active;
        drop(state);
        Ok(handle)
    }

    /// Returns retained process-owner and fixed connection-table metadata bytes.
    ///
    /// This excludes the separately reserved native H, each managed connection
    /// control, issuer credit controls and the permanent process fence credit.
    ///
    /// # Errors
    /// Refuses overflow in the authored finite table size.
    pub fn metadata_bytes(maximum_connections: usize) -> Result<u64, SqliteHeapError> {
        let bytes = std::mem::size_of::<HeapOwner>() + 2 * std::mem::size_of::<usize>();
        maximum_connections
            .checked_mul(std::mem::size_of::<Option<Arc<ConnectionOwner>>>())
            .and_then(|slots| slots.checked_add(bytes))
            .map(|bytes| bytes as u64)
            .ok_or_else(|| refusal("SQLite connection metadata size overflow"))
    }

    fn identity(&self) -> Result<&Arc<HeapOwner>, SqliteHeapError> {
        self.owner
            .as_ref()
            .ok_or_else(|| refusal("SQLite heap handle has closed"))
    }

    /// Checks the same original scope before a native operation.
    ///
    /// # Errors
    /// Refuses original liveness failure, stale generations or closing scopes.
    pub fn verify_live(&self) -> Result<(), super::StoreError> {
        let owner = self.identity()?;
        owner.issuer.authority()?.verify_live()?;
        let state = process()?;
        let installed = state
            .installed
            .as_ref()
            .filter(|installed| Arc::ptr_eq(&installed.owner, owner))
            .ok_or_else(|| refusal("SQLite heap generation is stale"))?;
        if installed.phase != Phase::Active {
            return Err(installed
                .error("SQLite process admission has closed")
                .into());
        }
        Ok(())
    }

    /// Returns this scope's finite process-native ceiling.
    #[must_use]
    pub fn maximum_heap_bytes(&self) -> u64 {
        self.owner.as_ref().map_or(0, |owner| owner.maximum as u64)
    }

    /// Stops admission and attempts terminal cleanup under this original scope.
    ///
    /// # Errors
    /// Retains ownership on live borrowers, native close refusal, uncertainty,
    /// residual native allocator memory or uncertain native ownership.
    pub fn finish(&self) -> Result<(), SqliteHeapError> {
        let owner = self.identity()?;
        let mut state = process()?;
        let installed = state
            .installed
            .as_mut()
            .filter(|installed| Arc::ptr_eq(&installed.owner, owner))
            .ok_or_else(|| refusal("SQLite heap generation is stale"))?;
        if installed.phase == Phase::Quarantined {
            return Err(installed.error("SQLite heap cleanup is uncertain"));
        }
        installed.phase = Phase::Closing;
        close(&mut state, 2)
    }
}

struct Installation {
    generation: u64,
    published: bool,
}

impl Drop for Installation {
    fn drop(&mut self) {
        if !self.published
            && let Ok(mut state) = PROCESS.lock()
            && state.installing == Some(self.generation)
        {
            state.installing = None;
        }
    }
}

fn close(state: &mut Process, permitted_owners: usize) -> Result<(), SqliteHeapError> {
    let installed = state
        .installed
        .as_mut()
        .ok_or_else(|| refusal("SQLite scope is absent"))?;
    if installed.phase == Phase::Quarantined {
        return Err(installed.error("SQLite heap cleanup is uncertain"));
    }
    if Arc::strong_count(&installed.owner) != permitted_owners {
        return Err(installed.error("SQLite scope still has live borrowers"));
    }
    for connection in installed.connections.iter().flatten() {
        if Arc::strong_count(connection) != 1 {
            return Err(installed.error("SQLite connection still has live borrowers"));
        }
    }
    installed.phase = Phase::Quarantined;
    for connection in installed.connections.iter().flatten() {
        close_connection(installed, connection)?;
    }
    // The pinned library may make cache release a no-op. Native usage zero
    // supplements the managed closure proof; it never replaces that proof.
    let _released = crucible_sqlite_heap::release_memory();
    if crucible_sqlite_heap::memory_used() != 0 {
        return Err(installed.error("SQLite allocator memory remains after connection close"));
    }
    let installed = state
        .installed
        .take()
        .ok_or_else(|| refusal("SQLite owner disappeared"))?;
    for connection in installed.connections.into_vec().into_iter().flatten() {
        drop(Arc::into_inner(connection));
    }
    drop(Arc::into_inner(installed.owner));
    Ok(())
}

impl Drop for SqliteProcessHeap {
    fn drop(&mut self) {
        let Some(owner) = self.owner.take() else {
            return;
        };
        let Ok(mut state) = PROCESS.lock() else {
            drop(Arc::into_inner(owner));
            return;
        };
        let generation = owner.generation;
        drop(Arc::into_inner(owner));
        if let Some(installed) = state.installed.as_mut()
            && installed.owner.generation == generation
            && Arc::strong_count(&installed.owner) == 1
            && installed.phase != Phase::Quarantined
        {
            installed.phase = Phase::Closing;
            // A failed terminal result stays in the same retained installation.
            if let Err(mut error) = close(&mut state, 1) {
                // Remove this temporary observer while retaining the published
                // installation; its Drop must not reacquire the held fence.
                if let Some(owner) = error.owner.take() {
                    drop(Arc::into_inner(owner));
                }
            }
        }
    }
}

fn close_connection(
    installed: &Installed,
    connection: &ConnectionOwner,
) -> Result<(), SqliteHeapError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| connection.close())) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(source)) => {
            let _ = installed.owner.failure.set(source);
            Err(installed.error("SQLite native connection refused terminal close"))
        }
        Err(_) => Err(installed.error("SQLite native close panicked under retained ownership")),
    }
}

impl Drop for SqliteHeapError {
    fn drop(&mut self) {
        let Some(owner) = self.owner.take() else {
            return;
        };
        // An error can be destroyed while its parent already holds PROCESS.
        // Contention keeps published custody; no cleanup is inferred from it.
        let Ok(mut state) = PROCESS.try_lock() else {
            drop(Arc::into_inner(owner));
            return;
        };
        let generation = owner.generation;
        drop(Arc::into_inner(owner));
        if let Some(installed) = state.installed.as_mut()
            && installed.owner.generation == generation
            && Arc::strong_count(&installed.owner) == 1
            && installed.phase != Phase::Quarantined
        {
            installed.phase = Phase::Closing;
            if let Err(mut error) = close(&mut state, 1)
                && let Some(owner) = error.owner.take()
            {
                drop(Arc::into_inner(owner));
            }
        }
    }
}
