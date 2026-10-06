//! Original resource ownership for fallible, retained artifact decoding.
//!
//! The host supplies real resource authority; this module owns no clocks or
//! platform resources. Each charge precedes its corresponding allocation and
//! remains live in [`DecodeCustody`] until the decoded owner closes. Scoped
//! routing lets compact codecs and nested JSON leaves share one account.

use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Provides actual original-owner memory credits for one artifact decoder.
pub trait DecodeResourceAuthority: Send + Sync {
    /// Reserves owned memory before allocation, retaining original custody.
    ///
    /// # Errors
    /// Refuses expired, unavailable or exhausted original resource authority.
    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError>;
}

/// Retains a typed operational or decoder-accounting refusal.
#[derive(Clone, Debug)]
pub struct DecodeAdmissionError {
    source: Arc<dyn Error + Send + Sync>,
}

impl DecodeAdmissionError {
    /// Preserves an original typed resource refusal without string conversion.
    pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            source: Arc::new(source),
        }
    }
}

impl fmt::Display for DecodeAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.source.as_ref(), formatter)
    }
}

impl Error for DecodeAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl PartialEq for DecodeAdmissionError {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.source, &other.source)
    }
}

impl Eq for DecodeAdmissionError {}

#[derive(Debug)]
struct AccountingRefusal(&'static str);

impl fmt::Display for AccountingRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for AccountingRefusal {}

struct State {
    used: u64,
    receipts: Vec<Arc<dyn Send + Sync>>,
    failure: Option<DecodeAdmissionError>,
}

struct Account {
    state: Mutex<State>,
    authority: Arc<dyn DecodeResourceAuthority>,
    maximum: u64,
    _initial: Arc<dyn Send + Sync>,
}

/// Shares one finite independently authored account across a complete decode.
#[derive(Clone)]
pub struct DecodeBudget(Arc<Account>);

thread_local! {
    static CURRENT: RefCell<Option<DecodeBudget>> = const { RefCell::new(None) };
}

impl DecodeBudget {
    /// Admits the account's retained metadata before creating it.
    ///
    /// # Errors
    /// Refuses an empty, exhausted or unavailable original allowance.
    pub fn new(
        authority: Arc<dyn DecodeResourceAuthority>,
        maximum: u64,
    ) -> Result<Self, DecodeAdmissionError> {
        let initial_bytes =
            (std::mem::size_of::<Account>() + 2 * std::mem::size_of::<usize>()) as u64;
        if initial_bytes > maximum {
            return Err(refusal("decoded metadata allowance is too small"));
        }
        let initial = authority.reserve(initial_bytes)?;
        Ok(Self(Arc::new(Account {
            state: Mutex::new(State {
                used: initial_bytes,
                receipts: Vec::new(),
                failure: None,
            }),
            authority,
            maximum,
            _initial: initial,
        })))
    }

    /// Creates an independently retained copy account under the same authority.
    ///
    /// The original allocator enforces the aggregate live peak across parent
    /// and child accounts. A child receives the same authored limit, and never
    /// retains its receipts in the parent's monotone decode ledger.
    ///
    /// # Errors
    /// Refuses an earlier parent failure or exhausted original authority.
    pub fn child(&self) -> Result<Self, DecodeAdmissionError> {
        self.check()?;
        Self::new(Arc::clone(&self.0.authority), self.0.maximum)
    }

    /// Admits owned bytes and the bounded receipt-vector growth before allocation.
    ///
    /// Charges are conservative and monotone during one decode. Released
    /// temporaries do not create new entitlement for later attacker input.
    ///
    /// # Errors
    /// Refuses overflow, account poisoning or original resource exhaustion.
    pub fn charge_bytes(&self, bytes: u64) -> Result<(), DecodeAdmissionError> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| refusal("decoded metadata account is poisoned"))?;
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let receipt_growth = (4 * std::mem::size_of::<Arc<dyn Send + Sync>>()) as u64;
        let result = bytes
            .checked_add(receipt_growth)
            .and_then(|bytes| state.used.checked_add(bytes).map(|used| (bytes, used)))
            .filter(|(_, used)| *used <= self.0.maximum)
            .ok_or_else(|| refusal("decoded metadata allowance exhausted"))
            .and_then(|(bytes, used)| {
                self.0
                    .authority
                    .reserve(bytes)
                    .map(|receipt| (receipt, used))
            });
        match result {
            Ok((receipt, used)) => {
                // At most four pointer slots per appended receipt cover Vec's
                // minimum capacity and old/new geometric growth overlap.
                if let Err(error) = state.receipts.try_reserve(1) {
                    let error = DecodeAdmissionError::new(error);
                    state.failure = Some(error.clone());
                    return Err(error);
                }
                state.receipts.push(receipt);
                state.used = used;
                Ok(())
            }
            Err(error) => {
                state.failure = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Admits one exact typed array before reserving its element storage.
    ///
    /// # Errors
    /// Refuses multiplication overflow or unavailable original resources.
    pub fn charge_array<T>(&self, count: usize) -> Result<(), DecodeAdmissionError> {
        let bytes = (std::mem::size_of::<T>() as u64)
            .checked_mul(count as u64)
            .ok_or_else(|| refusal("decoded array size overflow"))?;
        self.charge_bytes(bytes)
    }

    /// Routes nested codec reservations to this account on the current thread.
    #[must_use]
    pub fn enter(&self) -> DecodeScope {
        let previous = CURRENT.with(|current| current.replace(Some(self.clone())));
        DecodeScope {
            previous,
            _thread: std::marker::PhantomData,
        }
    }

    /// Returns retained custody for the owning decoded input or execution.
    #[must_use]
    pub fn custody(&self) -> DecodeCustody {
        DecodeCustody {
            _account: Some(self.clone()),
        }
    }

    /// Records a typed allocation refusal for an infallible canonical helper.
    ///
    /// The owning fallible artifact boundary must call [`Self::check`] before
    /// using the resulting identity or releasing a guest.
    pub fn record_failure(&self, error: DecodeAdmissionError) {
        if let Ok(mut state) = self.0.state.lock()
            && state.failure.is_none()
        {
            state.failure = Some(error);
        }
    }

    /// Refuses a result after any nested infallible codec recorded exhaustion.
    ///
    /// # Errors
    /// Returns the original typed refusal or a poisoned account lock.
    pub fn check(&self) -> Result<(), DecodeAdmissionError> {
        match self.failure()? {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Returns the original typed refusal recorded by a nested serde codec.
    ///
    /// # Errors
    /// Refuses a poisoned accounting lock.
    pub fn failure(&self) -> Result<Option<DecodeAdmissionError>, DecodeAdmissionError> {
        Ok(self
            .0
            .state
            .lock()
            .map_err(|_| refusal("decoded metadata account is poisoned"))?
            .failure
            .clone())
    }
}

/// Retains one temporary allocation's original credit until its storage closes.
///
/// Parser objects and their buffers must be dropped before this guard. The
/// credit comes from the same account as retained decoded fields; dropping the
/// guard releases only this temporary extent, never a retained field charge.
#[must_use]
pub struct DecodeScratch {
    receipt: Option<Arc<dyn Send + Sync>>,
    budget: DecodeBudget,
    bytes: u64,
}

impl Drop for DecodeScratch {
    fn drop(&mut self) {
        drop(self.receipt.take());
        if let Ok(mut state) = self.budget.0.state.lock() {
            // Reservation and Drop are paired linearly; poisoning leaves the
            // accounting total conservative rather than admitting more work.
            if let Some(remaining) = state.used.checked_sub(self.bytes) {
                state.used = remaining;
            } else if state.failure.is_none() {
                state.failure = Some(refusal("decoded scratch accounting invariant failed"));
            }
        }
    }
}

impl DecodeBudget {
    /// Admits temporary owned storage under the same original live allowance.
    ///
    /// The returned guard must outlive the corresponding buffer or compiler
    /// object. Retained decoded fields use [`Self::charge_bytes`] instead.
    ///
    /// # Errors
    /// Refuses overflow, poisoning, earlier failure or original exhaustion.
    pub fn reserve_scratch_bytes(&self, bytes: u64) -> Result<DecodeScratch, DecodeAdmissionError> {
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| refusal("decoded metadata account is poisoned"))?;
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let result = state
            .used
            .checked_add(bytes)
            .filter(|used| *used <= self.0.maximum)
            .ok_or_else(|| refusal("decoded metadata allowance exhausted"))
            .and_then(|used| {
                self.0
                    .authority
                    .reserve(bytes)
                    .map(|receipt| (used, receipt))
            });
        match result {
            Ok((used, receipt)) => {
                state.used = used;
                Ok(DecodeScratch {
                    receipt: Some(receipt),
                    budget: self.clone(),
                    bytes,
                })
            }
            Err(error) => {
                state.failure = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Admits an exact temporary array before allocating its element storage.
    ///
    /// # Errors
    /// Refuses size overflow or the same failures as [`Self::reserve_scratch_bytes`].
    pub fn reserve_scratch_array<T>(
        &self,
        count: usize,
    ) -> Result<DecodeScratch, DecodeAdmissionError> {
        let bytes = (std::mem::size_of::<T>() as u64)
            .checked_mul(count as u64)
            .ok_or_else(|| refusal("decoded scratch array size overflow"))?;
        self.reserve_scratch_bytes(bytes)
    }
}

/// Retains the original resource receipts after successful decoding.
#[derive(Clone, Default)]
pub struct DecodeCustody {
    _account: Option<DecodeBudget>,
}

impl fmt::Debug for DecodeCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodeCustody")
            .finish_non_exhaustive()
    }
}

// Operational custody does not change modeled input equality. Cloning this
// owner shares credits; a deep clone must admit its allocations separately.
impl PartialEq for DecodeCustody {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}
impl Eq for DecodeCustody {}

impl std::hash::Hash for DecodeCustody {
    fn hash<H: std::hash::Hasher>(&self, _state: &mut H) {}
}

/// Restores the previous thread-local decode account when a codec returns.
pub struct DecodeScope {
    previous: Option<DecodeBudget>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for DecodeScope {
    fn drop(&mut self) {
        CURRENT.with(|current| current.replace(self.previous.take()));
    }
}

/// Charges owned bytes to an explicitly installed compact-codec account.
///
/// Unscoped component codecs retain their existing behavior. Production owners
/// must install a budget before reading or allocating any artifact content.
///
/// # Errors
/// Returns the original active account refusal when admission fails.
pub fn charge_bytes(bytes: u64) -> Result<(), DecodeAdmissionError> {
    CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .map_or(Ok(()), |budget| budget.charge_bytes(bytes))
    })
}

/// Charges an exact typed compact-codec array before allocation.
///
/// # Errors
/// Returns overflow or the original active account refusal.
pub fn charge_array<T>(count: usize) -> Result<(), DecodeAdmissionError> {
    CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .map_or(Ok(()), |budget| budget.charge_array::<T>(count))
    })
}

fn refusal(message: &'static str) -> DecodeAdmissionError {
    DecodeAdmissionError::new(AccountingRefusal(message))
}

/// Returns the explicitly installed account for the current decoder thread.
///
/// `None` grants no resources and denotes an unscoped component codec.
#[must_use]
pub fn current_budget() -> Option<DecodeBudget> {
    CURRENT.with(|current| current.borrow().clone())
}

/// Returns current original custody for a successfully decoded owning value.
///
/// `None` denotes an unscoped component decoder and grants no resource credits.
/// A production artifact entry must establish a budget before decoding.
#[must_use]
pub fn current_custody() -> Option<DecodeCustody> {
    current_budget().map(|budget| budget.custody())
}

/// Creates a copy account from the explicitly installed original authority.
///
/// `None` denotes an unscoped component call and grants no resource credit.
/// The returned account must be retained by the resulting copied owner.
///
/// # Errors
/// Refuses original exhaustion or an earlier current-account failure.
pub fn current_child_budget() -> Result<Option<DecodeBudget>, DecodeAdmissionError> {
    current_budget().map(|budget| budget.child()).transpose()
}

/// Admits cumulative B-tree node storage before an insertion can allocate.
///
/// The pinned standard library uses eleven key/value slots in a leaf and
/// twelve pointers in an internal node. Two complete internal-node bounds per
/// inserted entry cover cumulative node creation and split overlap. Padding is
/// bounded for every leaf field, allowing Rust field reordering and zero-sized
/// entries with large alignments.
///
/// # Errors
/// Refuses layout overflow or original resource exhaustion.
pub fn charge_btree_entry<K, V>() -> Result<(), DecodeAdmissionError> {
    match current_budget() {
        Some(budget) => budget.charge_btree_entry::<K, V>(),
        None => Ok(()),
    }
}

impl DecodeBudget {
    /// Admits the audited B-tree node bound under this original account.
    ///
    /// # Errors
    /// Refuses layout overflow or exhausted original resource authority.
    pub fn charge_btree_entry<K, V>(&self) -> Result<(), DecodeAdmissionError> {
        let result = btree_entry_bytes::<K, V>().and_then(|bytes| self.charge_bytes(bytes));
        if let Err(error) = &result {
            self.record_failure(error.clone());
        }
        result
    }
}

fn btree_entry_bytes<K, V>() -> Result<u64, DecodeAdmissionError> {
    use std::alloc::Layout;

    // alloc::collections::btree::node in the pinned toolchain: LeafNode has
    // parent, parent_idx, len, keys[11], vals[11]; InternalNode adds edges[12].
    // Five leaf fields and two internal fields require at most seven padding
    // extents, each smaller than the maximum alignment, independent of order.
    let keys = Layout::array::<K>(11).map_err(DecodeAdmissionError::new)?;
    let values = Layout::array::<V>(11).map_err(DecodeAdmissionError::new)?;
    let pointers = Layout::array::<usize>(13).map_err(DecodeAdmissionError::new)?;
    let alignment = keys.align().max(values.align()).max(pointers.align());
    let bytes = keys
        .size()
        .checked_add(values.size())
        .and_then(|bytes| bytes.checked_add(pointers.size()))
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<u16>()))
        .and_then(|bytes| {
            alignment
                .checked_sub(1)
                .and_then(|padding| padding.checked_mul(7))
                .and_then(|padding| bytes.checked_add(padding))
        })
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(|| refusal("decoded tree node size overflow"))?;
    u64::try_from(bytes).map_err(DecodeAdmissionError::new)
}

/// Admits one complete B-tree set node before an insertion can allocate.
///
/// # Errors
/// Returns the same overflow and resource refusals as
/// [`charge_btree_entry`].
pub fn charge_btree_set_entry<T>() -> Result<(), DecodeAdmissionError> {
    charge_btree_entry::<T, ()>()
}

struct StoreAuthority {
    guard: Arc<dyn crate::content_store::StorePhysicalQuotaGuard>,
    _resources: Arc<dyn Send + Sync>,
}

impl DecodeResourceAuthority for StoreAuthority {
    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.guard
            .reserve_resources(0, bytes)
            .map_err(DecodeAdmissionError::new)
    }
}

impl DecodeBudget {
    /// Opens one finite decode account from its original admitted storage owner.
    ///
    /// The limit is the explicitly authored Rust metadata subset. Existing
    /// catalogue and reader loans consume that same allocator; this method
    /// creates no independent entitlement.
    ///
    /// # Errors
    /// Refuses missing, expired or exhausted storage metadata authority.
    pub fn for_store(
        guard: Arc<dyn crate::content_store::StorePhysicalQuotaGuard>,
    ) -> Result<Self, DecodeAdmissionError> {
        let maximum = guard
            .decoded_metadata_limit()
            .map_err(DecodeAdmissionError::new)?;
        let resources = guard
            .reserve_resources(
                0,
                (std::mem::size_of::<StoreAuthority>() + 2 * std::mem::size_of::<usize>()) as u64,
            )
            .map_err(DecodeAdmissionError::new)?;
        Self::new(
            Arc::new(StoreAuthority {
                guard,
                _resources: resources,
            }),
            maximum,
        )
    }
}

impl DecodeCustody {
    /// Reinstalls the original account while decoding another owned component.
    ///
    /// Empty component custody grants no authority and returns `None`.
    #[must_use]
    pub fn enter(&self) -> Option<DecodeScope> {
        self._account.as_ref().map(DecodeBudget::enter)
    }
}

/// Reserves exact additional vector storage before its next insertion.
///
/// The previous allocation remains charged until the enclosing decoded owner
/// drops; a growth reservation therefore covers the simultaneous old/new peak.
///
/// # Errors
/// Refuses capacity overflow, allocation failure or original resource exhaustion.
pub fn reserve_vec<T>(values: &mut Vec<T>, additional: usize) -> Result<(), DecodeAdmissionError> {
    let required = values
        .len()
        .checked_add(additional)
        .ok_or_else(|| refusal("decoded vector size overflow"))?;
    if required > values.capacity() {
        charge_array::<T>(required)?;
        values
            .try_reserve_exact(additional)
            .map_err(DecodeAdmissionError::new)?;
    }
    Ok(())
}
