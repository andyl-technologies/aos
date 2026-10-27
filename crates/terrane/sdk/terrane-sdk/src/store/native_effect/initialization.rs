//! Owns opaque requests and genuine native root or portable-copy activation receipts.
//!
//! A request fixes configuration and, for an explicit copy, verified ordinary
//! data under an existing actual exclusion. The native factory retains actual
//! opened directories and performs a genuine administrative create-new event
//! before staging Pending and genesis. Decoded records and an existing root
//! cannot construct that receipt. D-108 fixes the copied proposal's exact
//! nonauthoritative staging locator independently of its selected slot.
//!
//! ```text
//! configured request -> native creator -> durable Pending + exact staged genesis
//! retained receipt -> checked activation -> durable selected genesis + Active
//! ```

use crate::store::{StoreErrorKind, StoreFailure};
use std::path::{Component, Path, PathBuf};
use terrane_format::bucket::StoreProfile;

#[cfg(unix)]
use super::super::{ExactRead, NamedFence, NativeExclusion, NativeOpenedDirectory};
#[cfg(unix)]
use super::{corrupt, digest};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use terrane_format::gc::publication::{BackendBinding, PublicationTransaction};

// The programs are descendants of both the opaque carriers and the native
// mechanics. Other crate modules can submit requests but cannot fabricate the
// successful creator event, descriptors, or exact physical staging transcript.
/// Creates absent roots or registers explicit copies and activates retained genesis.
#[path = "../../bucket/publication/activation/fresh.rs"]
pub(crate) mod fresh;
/// Recovers the same exact existing Pending registration under retained exclusion.
#[path = "../../bucket/publication/activation/pending.rs"]
pub(crate) mod pending;

/// Fixes configured inputs for one native root or portable-copy initialization.
///
/// Possessing this request grants no freshness or registration authority. It
/// has no public constructor; the file-bucket opener or explicit administrative
/// copy initializer fixes its canonical inputs before native factory dispatch.
pub struct NativePublicationInitialization {
    // Keep unsupported configurations opaque too; the unit is no authority.
    _private: (),
    #[cfg(unix)]
    root: PathBuf,
    #[cfg(unix)]
    control: PathBuf,
    #[cfg(unix)]
    operator_uid: u32,
    #[cfg(unix)]
    profile: StoreProfile,
    #[cfg(unix)]
    timestamp: u64,
    #[cfg(unix)]
    copy: Option<CopyInputs>,
    #[cfg(unix)]
    creator: Option<NativeFreshCreator>,
}

/// Retains the original root from the successful absent-root creation event.
#[cfg(unix)]
struct NativeFreshCreator {
    root: Arc<std::fs::File>,
    stamp: super::super::MetadataStamp,
}

/// Retains verified copy data and actual exclusion, without registration authority.
#[cfg(unix)]
struct CopyInputs {
    payload: crate::bucket::publication::copy_payload::CopyPayload,
    exclusion: NativeExclusion,
}

/// Reports existing-root observation or an actual retained native creator event.
pub enum NativePublicationInitializationOutcome {
    /// Requires complete existing registration and selected-chain verification.
    Existing,
    /// Retains the actual native factory's directories, exclusion and staging.
    Fresh(Box<NativePendingRoot>),
}

/// Retains genuine native activation inputs through physical worker completion.
///
/// The receipt has no public constructor, descriptor accessor or cloning
/// operation. Its exact preimages name the original durably staged leaves;
/// activation must reject replacement even when replacement bytes are equal.
/// Opened directories establish incarnation observations independently of the
/// genuinely acquired coordination exclusion.
pub struct NativePendingRoot {
    // Privacy must not disappear when the native fields are compiled out.
    _private: (),
    #[cfg(unix)]
    request: NativePublicationInitialization,
    #[cfg(unix)]
    directories: Arc<[NativeOpenedDirectory]>,
    #[cfg(unix)]
    exclusions: Arc<[NativeExclusion]>,
    #[cfg(unix)]
    binding: BackendBinding,
    #[cfg(unix)]
    pending: Vec<u8>,
    #[cfg(unix)]
    staged: NativeGenesisStage,
    #[cfg(unix)]
    names: Vec<NamedFence>,
    #[cfg(unix)]
    reads: Vec<ExactRead>,
}

/// Keeps the exact full genesis proposal as data under the creator's receipt.
#[cfg(unix)]
struct NativeGenesisStage {
    snapshot_bytes: Vec<u8>,
    transaction: PublicationTransaction,
}

fn normalized(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}

/// Fixes canonical configuration without observing or creating filesystem nodes.
///
/// # Errors
/// Refuses noncanonical or overlapping locations, unsupported profiles, and
/// platforms without the native retained initialization program.
pub(crate) fn request_for_open(
    root: &Path,
    control: &Path,
    operator_uid: u32,
    profile: StoreProfile,
    timestamp: u64,
) -> Result<NativePublicationInitialization, StoreFailure> {
    if !normalized(root)
        || !normalized(control)
        || root.parent().is_none()
        || control.parent().is_none()
        || root.starts_with(control)
        || control.starts_with(root)
        || profile.identity != "terrane-v1"
        || profile.algorithm != "blake3"
        || profile.chunk != "cdc-1m"
    {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported));
    }

    #[cfg(unix)]
    {
        Ok(NativePublicationInitialization {
            _private: (),
            root: root.to_owned(),
            control: control.to_owned(),
            operator_uid,
            profile,
            timestamp,
            copy: None,
            creator: None,
        })
    }

    #[cfg(not(unix))]
    {
        let _ = (operator_uid, profile, timestamp);
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

/// Fixes verified portable data under the independently acquired existing lock.
///
/// # Errors
/// Rejects unsupported configuration. Data and exclusion alone do not authorize
/// registration; the native worker must perform the administrative create event.
#[cfg(unix)]
pub(crate) fn request_for_copy(
    mut request: NativePublicationInitialization,
    payload: crate::bucket::publication::copy_payload::CopyPayload,
    exclusion: NativeExclusion,
) -> Result<NativePublicationInitialization, StoreFailure> {
    if request.copy.is_some() {
        return Err(corrupt());
    }
    request.copy = Some(CopyInputs { payload, exclusion });
    Ok(request)
}

#[cfg(unix)]
impl NativePublicationInitialization {
    /// Completes the sealed native creator synchronously through durable staging.
    ///
    /// A [`crate::store::LocalFs`] adapter calls this method on its owned
    /// physical worker. The call blocks through fixed creator completion and
    /// required staging durability. Tokio adapters submit the same program to
    /// their blocking worker; an asynchronous adapter must retain that worker
    /// after waiter cancellation. This method accepts no replacement inputs
    /// and cannot construct a creator receipt from decoded records or an
    /// existing root.
    ///
    /// # Examples
    ///
    /// A binding's physical worker consumes its fixed initialization request:
    ///
    /// ```no_run
    /// # fn initialize(request: terrane_sdk::store::NativePublicationInitialization)
    /// #     -> Result<terrane_sdk::store::NativePublicationInitializationOutcome,
    /// #         terrane_sdk::store::StoreFailure> {
    /// request.execute_inline()
    /// # }
    /// ```
    ///
    /// # Errors
    /// Preserves rejected physical inputs and genuine staging or durability
    /// failures. Returns `Unsupported` if the fixed inline creator cannot
    /// complete synchronously.
    pub fn execute_inline(self) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        fresh::initialize(self)
    }

    /// Owns the fixed creator program inside one submitted physical worker.
    ///
    /// # Errors
    /// Preserves creator rejection or durability failure and reports unavailable
    /// runtime or worker completion. Dropping the waiter does not cancel a
    /// submitted worker or release its actual retained descriptors early.
    #[cfg(feature = "tokio")]
    pub(in crate::store) async fn execute_tokio(
        self,
    ) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
        let unavailable = || StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None });
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| unavailable())?;
        runtime
            .spawn_blocking(move || self.execute_inline())
            .await
            .map_err(|_| unavailable())?
    }
}
