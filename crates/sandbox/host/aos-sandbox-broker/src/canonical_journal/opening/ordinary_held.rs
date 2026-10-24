//! Keeps the actual ordinary acquisition, parser and index in one transfer.
//!
//! This composition contains the existing native opening and indexed cursor.
//! Its private bundle can be formed only from those same completed originals;
//! no map, replay-success DATA or native state can be supplied to its constructor.
//! Role semantic checks, funding, native posts and authority remain external.

mod acquisition;
mod append;
#[cfg(target_os = "linux")]
mod nix_offline;
#[cfg(target_os = "linux")]
pub use nix_offline::{
    CanonicalOrdinaryNixOfflineOpeningV1, CanonicalNixOfflineAcquisitionErrorV1,
    CanonicalNixOfflineDirectoryOperationsV1, CanonicalNixOfflineFileOperationsV1,
};

mod readonly;
mod reread;
pub use reread::{CanonicalOrdinaryRereadDataV1, CanonicalOrdinaryRereadOriginalV1};
pub use readonly::{CanonicalOrdinaryReadonlyOpeningV1, CanonicalOrdinaryReadonlyReplayDataV1};

mod replacement;
mod observations;

pub use append::CanonicalOrdinaryAppendStageV1;
pub use replacement::{
    CanonicalOrdinaryReplacementInstalledV1, CanonicalOrdinaryReplacementReadyV1,
    CanonicalOrdinaryReplacementV1,
};

use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Weak};

use aos_sandbox_journal::protected_storage::{FileIdentity, ProtectedJournalLocation};
use aos_sandbox_journal::recovery::RecoveryTailMode;
use aos_sandbox_protocol::domain_ledger::readonly::{
    IdempotencyDecisionV1, IdempotencyRecordDataErrorV1,
};

use super::{AcquisitionAccess, CompletedNativeOpening, CanonicalWriterOpeningOriginalsV1};
use crate::canonical_journal::coordinator::CanonicalWriterReadViewV1;
use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1,
};
use crate::canonical_journal::{
    CanonicalNativeJournalV1, CanonicalReplayExtentDataV1, JournalLimits, NativeJournalDataErrorV1,
    RecoveryReport,
};
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

type Index = BTreeMap<Vec<u8>, IdempotencyDecisionV1>;

/// Identifies one original allocation for intrinsic comparison only.
///
/// This DATA carries no namespace, role, sequence, health or permission. Actual
/// role snapshots still retain and compare their own private purpose and cut.
/// Cloning retains the same allocation; it never creates another identity.
pub struct CanonicalJournalInstanceDataV1<I = ()>(Arc<I>);

/// Retains a non-owning comparison with the same original allocation.
///
/// This DATA cannot keep a writer alive or be converted into native custody.
pub struct CanonicalJournalInstanceWeakDataV1<I = ()>(Weak<I>);

impl<I> Clone for CanonicalJournalInstanceDataV1<I> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<I> Clone for CanonicalJournalInstanceWeakDataV1<I> {
    fn clone(&self) -> Self {
        Self(Weak::clone(&self.0))
    }
}

impl CanonicalJournalInstanceDataV1<()> {
    #[cfg(test)]
    fn new() -> Self {
        Self::from_payload(())
    }

    /// Bounds the existing unit-payload allocation and construction carriers.
    ///
    /// This passive supplier provides no funding or namespace entries. Returns
    /// `None` on checked representation overflow.
    #[must_use]
    pub fn allocation_receiving_bytes_v1() -> Option<usize> {
        Self::payload_allocation_receiving_bytes_v1()
    }
}

impl<I> CanonicalJournalInstanceDataV1<I> {
    fn from_payload(payload: I) -> Self {
        Self(Arc::new(payload))
    }

    /// Compares actual allocation identity without authenticating a role.
    #[must_use]
    pub fn same_original_v1(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Lends the SAME allocation as comparison DATA without adopting an Arc.
    ///
    /// An upper owner's existing typed snapshot or old Drop-position alias may
    /// clone this Arc without allocating another identity. The payload supplies
    /// no canonical native, index, purpose, currentness or financial authority.
    /// No method installs a supplied Arc into this owner.
    #[must_use]
    pub fn comparison_arc_v1(&self) -> &Arc<I> {
        &self.0
    }

    /// Retains a weak comparison without allocating another identity.
    #[must_use]
    pub fn comparison_stamp_v1(&self) -> CanonicalJournalInstanceWeakDataV1<I> {
        CanonicalJournalInstanceWeakDataV1(Arc::downgrade(&self.0))
    }

    /// Compares the original weak identity without upgrading or extending it.
    #[must_use]
    pub fn matches_stamp_v1(&self, stamp: &CanonicalJournalInstanceWeakDataV1<I>) -> bool {
        Weak::ptr_eq(&Arc::downgrade(&self.0), &stamp.0)
    }

    /// Bounds the actual payload allocation and its construction carriers.
    ///
    /// Payload residence and two caller/constructor staging lanes, Arc counters,
    /// alignment, returned handles and Layout are MemoryBytes only. Genuine
    /// callers admit this passive amount before the allocating entry, using the
    /// actual private payload type. Returns `None` on checked overflow.
    #[must_use]
    pub fn payload_allocation_receiving_bytes_v1() -> Option<usize> {
        let alignment = std::mem::align_of::<I>().max(std::mem::align_of::<usize>());
        std::mem::size_of::<I>()
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<usize>().checked_mul(2)?)?
            .checked_add(alignment.checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<std::alloc::Layout>())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OpeningMode {
    Ordinary,
    Retained,
}

// Only this module can construct the bundle, and only after the internal cursor
// and native tail complete. Neither the index nor its native half is supplied.
struct OpenedIndexBundle {
    opened: CompletedNativeOpening,
    index: Index,
}

/// Retains the same native acquisition and its privately created replay index.
///
/// The inert constructor allocates nothing. Genuine callers separately pay
/// acquisition, captured-prefix replay/index growth, semantic destinations and
/// independently owed posts before entering those existing engines. Completion
/// here certifies only mechanical native/index DATA, never role semantics.
#[must_use]
pub struct CanonicalOrdinaryOpeningOriginalsV1<C = ()> {
    // Before transfer, retained native originals precede the index. Once that
    // same native prefix is parked for traversal retirement, the old fixed
    // Network layout keeps index/identity before its moved native destination.
    // Ordinary destruction explicitly retires index locals before native.
    native: CanonicalWriterOpeningOriginalsV1,
    index: Index,
    index_originals: CanonicalReplayIndexOriginalsV1,
    instance: Option<CanonicalJournalInstanceDataV1<C>>,
    pending: Option<CompletedNativeOpening>,
    mode: Option<OpeningMode>,
    retirement: Option<Result<(), NativeJournalDataErrorV1>>,
    replay_started: bool,
    taken: bool,
    ordinary_disposition: u8,
    closed: Option<NativeJournalDataErrorV1>,
}

impl CanonicalOrdinaryOpeningOriginalsV1<()> {
    /// Bounds the existing fixed physical opening recipe around resident `T`.
    ///
    /// The concrete caller supplies its actual retained construction type. The
    /// recipe includes the held hierarchy and both failed or owed name bookends;
    /// semantic backing and other construction planes remain separate. This
    /// passive bound creates no opening, receiving permit or native authority.
    ///
    /// # Errors
    /// Reports checked memory arithmetic overflow in the original fixed recipe.
    pub fn fixed_preparation_demand_v1<T>(
        directory_descriptors: u16,
        path_name_bytes: u16,
    ) -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError> {
        use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};

        let overflow = || AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let directories = u64::from(directory_descriptors);
        let paths = u64::from(path_name_bytes);
        let memory = u64::try_from(std::mem::size_of::<T>())
            .ok()
            .and_then(|bytes| {
                bytes.checked_add(
                    directories
                        .checked_mul(3)?
                        .checked_mul(u64::try_from(std::mem::size_of::<std::fs::File>()).ok()?)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(paths.checked_add(32)?.checked_mul(16)?))
            .and_then(|bytes| bytes.checked_add(32 * 256))
            .ok_or_else(overflow)?;
        // Same already-admitted physical recipe: held hierarchy plus two
        // failed/owed name bookends. No semantic backing or heap metadata fee.
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OpenFiles, directories * 3 + 6)
            .with(D::MetadataEntries, directories * 3 + 14))
    }

    /// Returns zero namespace entries for these composition-only carriers.
    ///
    /// Actual resident keys retain their existing native/index suppliers.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        0
    }

    /// Creates unit-capture originals without IO, allocation or a payload.
    #[must_use]
    pub const fn new() -> Self {
        Self::new_for_capture_payload_v1()
    }

    /// Bounds the existing unit-capture and unit-held transfer carriers.
    ///
    /// Replaces the old enclosing header terms rather than adding both. Native,
    /// dynamic replay/index, role backing and optional allocation stay separate.
    /// Returns `None` on checked representation overflow.
    #[must_use]
    pub fn receiving_construction_bytes_v1<P>() -> Option<usize> {
        Self::receiving_payload_construction_bytes_v1::<P, ()>()
    }

    /// Captures the existing unit instance before native acquisition.
    ///
    /// # Errors
    /// Refuses reentry, attempted acquisition or prior refusal before allocation.
    pub fn capture_instance_once_v1(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        self.capture_instance_payload_once_v1(())
    }

    /// Transfers the bundle and allocates its unit identity at the late frontier.
    ///
    /// The actual caller prepays that allocation. Returns `None` before complete
    /// native/index transfer, after refusal, or when a captured instance exists.
    #[must_use]
    pub fn take_held_with_late_instance_once_v1<P>(
        &mut self,
        selection: P,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P>, RecoveryReport)> {
        self.take_held_with_late_payload_once_v1(selection, ())
    }
}

impl<C> CanonicalOrdinaryOpeningOriginalsV1<C> {
    /// Creates explicitly typed vacant originals without constructing a payload.
    ///
    /// This inert entry has no Default bound, allocation, native work or payer.
    /// The payload is supplied only at its actual paid allocation frontier.
    #[must_use]
    pub const fn new_for_capture_payload_v1() -> Self {
        Self {
            native: CanonicalWriterOpeningOriginalsV1::new(),
            index: BTreeMap::new(),
            index_originals: CanonicalReplayIndexOriginalsV1::new(),
            instance: None,
            pending: None,
            mode: None,
            retirement: None,
            replay_started: false,
            taken: false,
            ordinary_disposition: 0,
            closed: None,
        }
    }

    /// Bounds complete fixed composition and transfer carriers as bytes.
    ///
    /// This replaces the enclosing ordinary opening/held header terms when a
    /// real caller migrates; it is not an add-on to those same header terms.
    /// The existing additional native preparation supplier, actual-prefix
    /// replay/index suppliers, role semantic backing and optional instance
    /// allocation remain separate. No dynamic map or native file is copied.
    /// Returns `None` on checked representation overflow.
    #[must_use]
    pub fn receiving_payload_construction_bytes_v1<P, I>() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<OpenedIndexBundle>())?
            .checked_add(
                std::mem::size_of::<CanonicalOrdinaryHeldJournalV1<P, I>>().checked_mul(2)?,
            )?
            .checked_add(std::mem::size_of::<
                Option<(CanonicalOrdinaryHeldJournalV1<P, I>, RecoveryReport)>,
            >())?
            .checked_add(std::mem::size_of::<(
                CanonicalNativeJournalV1,
                Option<ProtectedJournalLocation<P>>,
                RecoveryReport,
            )>())?
            .checked_add(std::mem::size_of::<P>())
    }

    /// Captures the optional original instance before native acquisition.
    ///
    /// A genuine captured caller prepays the allocation at its existing fixed
    /// frontier. The allocation remains in this opening through later posts;
    /// positive transfer clones the same handle. Ordinary noncaptured callers
    /// omit this entry and allocate no identity.
    ///
    /// # Errors
    /// Refuses reentry, any already attempted native acquisition or prior refusal.
    pub fn capture_instance_payload_once_v1(
        &mut self,
        payload: C,
    ) -> Result<(), NativeJournalDataErrorV1> {
        if self.mode.is_some() || self.instance.is_some() || self.closed.is_some() {
            return Err(self.refuse_order());
        }
        self.instance = Some(CanonicalJournalInstanceDataV1::from_payload(payload));
        Ok(())
    }

    /// Borrows the actual pre-acquisition identity without creating another.
    #[must_use]
    pub fn captured_instance_data_v1(&self) -> Option<&CanonicalJournalInstanceDataV1<C>> {
        self.instance.as_ref()
    }

    /// Enters the same immediate ordinary native acquisition once.
    ///
    /// # Errors
    /// Retains the existing native cause; reentry refuses before additional IO.
    pub fn prepare_ordinary_once_v1(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.begin_mode(OpeningMode::Ordinary)?;
        self.native
            .prepare_ordinary_once(path, name, limits, uid, allow_create)
    }

    /// Acquires the same native empty-history profile without role admission.
    ///
    /// # Errors
    /// Preserves the first physical refusal; reentry performs no further IO.
    pub fn prepare_empty_ordinary_once_v1(
        &mut self, path: &Path, name: &str, limits: JournalLimits, uid: u32,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.begin_mode(OpeningMode::Ordinary)?;
        self.native.prepare_empty_ordinary_once(path, name, limits, uid)
    }

    /// Enters the same retained native acquisition for an ordinary held writer.
    ///
    /// Actual selected Controller, Root and Source constructors remain distinct;
    /// this mechanical entry supplies none of their private role brands.
    ///
    /// # Errors
    /// Retains the existing native cause; reentry refuses before additional IO.
    pub fn prepare_retaining_once_v1(
        &mut self,
        path: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
    ) -> Result<(), NativeJournalDataErrorV1> {
        self.begin_mode(OpeningMode::Retained)?;
        self.native
            .prepare_once(path, name, limits, uid, allow_create)
    }

    fn begin_mode(&mut self, mode: OpeningMode) -> Result<(), NativeJournalDataErrorV1> {
        if self.mode.is_some() || self.closed.is_some() {
            return Err(self.refuse_order());
        }
        self.mode = Some(mode);
        Ok(())
    }

    /// Returns this actual acquisition's bounded extent before parser growth.
    ///
    /// # Errors
    /// Preserves the native owner's failed, missing or already moved refusal.
    pub fn prepared_extent_v1(
        &self,
    ) -> Result<CanonicalReplayExtentDataV1, NativeJournalDataErrorV1> {
        self.native.prepared_extent()
    }

    /// Captures the same file identity at the caller's original parser frontier.
    ///
    /// # Errors
    /// Retains the existing ordinary seek/identity or retained identity cause;
    /// a vacant, failed or repeated observation refuses without another probe.
    pub fn prepare_parser_identity_once_v1(
        &mut self,
    ) -> Result<FileIdentity, NativeJournalDataErrorV1> {
        if self.closed.is_some() {
            return Err(self.refuse_order());
        }
        match self.mode {
            Some(OpeningMode::Ordinary) => self.native.prepare_ordinary_parser_once(),
            Some(OpeningMode::Retained) => self.native.prepare_selected_parser_identity_once(),
            None => Err(self.refuse_order()),
        }
    }

    /// Reports the actual indexed cursor's completed EOF as comparison DATA.
    ///
    /// This passive observation supplies no semantic completion or authority.
    /// Fixed callers retain their existing early guard before final name IO.
    #[must_use]
    pub fn indexed_replay_complete_data_v1(&self) -> bool {
        self.index_originals.is_complete()
    }

    /// Borrows the already sampled parser identity without another native probe.
    #[must_use]
    pub fn parser_identity_data_v1(&self) -> Option<FileIdentity> {
        match self.mode {
            Some(OpeningMode::Ordinary) => self.native.ordinary_parser_file_identity(),
            Some(OpeningMode::Retained) => self.native.selected_parser_identity_data_v1(),
            None => None,
        }
    }

    /// Observes the same held names through the caller's prepaid native sink.
    ///
    /// This delegate adds no healthy-entry check, so an independently owed post
    /// still reaches the existing sampler after a parser or semantic refusal.
    ///
    /// # Errors
    /// Preserves the actual rooted traversal, binding or name failure in the
    /// supplied original without opening a new writer or issuing role custody.
    pub fn observe_names_retaining_v1<E>(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        originals: &mut WriterCurrentnessOriginalsV1<E>,
    ) -> Result<(), E>
    where
        E: aos_sandbox_journal::protected_storage::ProtectedFailure
            + From<aos_sandbox_journal::framing::FrameError>
            + Error + 'static,
    {
        self.native
            .observe_names_retaining_v1(directory, name, uid, originals)
    }

    /// Observes the same held directory at the caller's existing native frontier.
    ///
    /// # Errors
    /// Retains the original traversal/binding refusal in the supplied sink.
    pub fn observe_directory_retaining_v1<E>(
        &self,
        directory: &Path,
        uid: u32,
        originals: &mut WriterCurrentnessOriginalsV1<E>,
    ) -> Result<(), E>
    where
        E: aos_sandbox_journal::protected_storage::ProtectedFailure
            + From<aos_sandbox_journal::framing::FrameError>
            + Error + 'static,
    {
        self.native
            .observe_directory_retaining_v1(directory, uid, originals)
    }

    /// Borrows the actual first metadata without any replacement observation.
    #[must_use]
    pub fn initial_metadata_data_v1(&self) -> Option<&std::fs::Metadata> {
        self.native.initial_metadata_data_v1()
    }

    /// Runs the same independently owed captured-prefix post into its real slot.
    ///
    /// # Errors
    /// Preserves repeated/missing-original refusal without a fresh observation.
    pub fn observe_captured_prefix_post_once_v1<E>(
        &self,
        slot: &mut Option<aos_sandbox_journal::protected_storage::CapturedReplayPrefixPostV1<E>>,
    ) -> Result<(), E>
    where
        E: aos_sandbox_journal::protected_storage::ProtectedFailure,
    {
        self.native.observe_captured_prefix_post_once_v1(slot)
    }

    /// Lends retained replay using its already sampled parser metadata once.
    ///
    /// The actual upper owner runs paid full semantics and its owed prefix post.
    /// This route adds no metadata probe or selected role/financial original.
    ///
    /// # Errors
    /// Refuses nonretained/repeated entry or the same native parser original.
    pub fn begin_captured_replay_with_parser_metadata_once_v1(
        &mut self,
    ) -> Result<CanonicalIndexedReplayV1<'_, '_>, NativeJournalDataErrorV1> {
        if self.mode != Some(OpeningMode::Retained) || self.replay_started || self.closed.is_some() {
            return Err(self.refuse_order());
        }
        self.replay_started = true;
        let cursor = self.native.begin_captured_replay_with_parser_metadata_once_v1()?;
        Ok(CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, &mut self.index, &mut self.index_originals,
        ))
    }

    /// Lends the existing staged cursor with this same private resident index.
    ///
    /// The role keeps its semantic scratch separate and runs its checks between
    /// native COMMIT stages. The index never escapes as a writable projection.
    ///
    /// # Errors
    /// Preserves the original native parser refusal and denies repeat entry.
    pub fn begin_indexed_replay_once_v1(
        &mut self,
    ) -> Result<CanonicalIndexedReplayV1<'_, '_>, NativeJournalDataErrorV1> {
        if self.mode.is_none() || self.replay_started || self.closed.is_some() {
            return Err(self.refuse_order());
        }
        self.replay_started = true;

        let cursor = match self.mode {
            Some(OpeningMode::Ordinary) => self.native.begin_ordinary_semantic_replay_once()?,
            Some(OpeningMode::Retained) => self.native.begin_semantic_replay_once()?,
            None => return Err(NativeJournalDataErrorV1::ProtectedBoundary),
        };
        Ok(CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor,
            &mut self.index,
            &mut self.index_originals,
        ))
    }

    /// Finalizes the same file only after its private indexed replay completes.
    ///
    /// The role invokes this after its actual final semantic checks. It grants
    /// no tail-repair permission beyond the caller's original selected mode.
    ///
    /// # Errors
    /// Retains the existing native tail Result or incomplete-index refusal.
    pub fn finish_replayed_tail_once_v1(
        &mut self,
        mode: RecoveryTailMode,
    ) -> Result<(), NativeJournalDataErrorV1> {
        if !self.index_originals.is_complete() || self.closed.is_some() {
            return Err(self.refuse_order());
        }
        self.native.finish_replayed_tail_once(mode)
    }

    /// Transfers the completed same-opening bundle without allocating an identity.
    ///
    /// Returns `None` after refusal, before complete replay/tail, on reentry or
    /// when a captured instance requires the explicit same-instance route.
    #[must_use]
    pub fn take_held_without_instance_once_v1<P>(
        &mut self,
        selection: P,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P, C>, RecoveryReport)> {
        if self.instance.is_some() {
            return None;
        }
        let bundle = self.take_bundle()?;
        Some(CanonicalOrdinaryHeldJournalV1::from_bundle(
            bundle, selection, None,
        ))
    }

    /// Transfers the bundle while retaining its original pre-acquisition identity.
    ///
    /// Clones the actual captured allocation only after the native/index move.
    /// The opening keeps its original alias through the caller's existing posts.
    /// Returns `None` if no captured identity or completed bundle exists.
    #[must_use]
    pub fn take_held_with_captured_instance_once_v1<P>(
        &mut self,
        selection: P,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P, C>, RecoveryReport)> {
        self.instance.as_ref()?;
        let bundle = self.take_bundle()?;
        let instance = self.instance.clone();
        Some(CanonicalOrdinaryHeldJournalV1::from_bundle(
            bundle, selection, instance,
        ))
    }

    /// Transfers the bundle and allocates its supplied late comparison payload.
    ///
    /// The actual caller prepays the I allocation before entry. The payload is
    /// inert DATA, not a supplied Arc, native owner, index or role success. Native
    /// or index refusal allocates nothing. An upper alias clones the SAME Arc<I>.
    /// Returns `None` before complete transfer or when a capture already exists.
    #[must_use]
    pub fn take_held_with_late_payload_once_v1<P, I>(
        &mut self,
        selection: P,
        payload: I,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P, I>, RecoveryReport)> {
        if self.instance.is_some() {
            return None;
        }
        let bundle = self.take_bundle()?;
        let instance = CanonicalJournalInstanceDataV1::from_payload(payload);
        Some(CanonicalOrdinaryHeldJournalV1::from_bundle(
            bundle,
            selection,
            Some(instance),
        ))
    }

    /// Transfers the bundle with a distinct late payload and keeps its capture.
    ///
    /// This explicit dual-origin route preserves the existing Session shape:
    /// one pre-native C allocation remains in the original opening/receiver,
    /// while one distinct late I allocation is shared by the held and upper
    /// Journal aliases. Actual fixed Session posts, conversion and loan gates
    /// remain with the caller; this mechanical factory certifies none of them.
    /// Both real allocation recipes are prepaid at their original frontiers.
    /// Returns `None` without allocating I when no capture or completed bundle
    /// exists. It neither merges the identities nor creates a third allocation.
    #[must_use]
    pub fn take_held_with_independent_late_payload_once_v1<P, I>(
        &mut self,
        selection: P,
        payload: I,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P, I>, RecoveryReport)> {
        self.instance.as_ref()?;
        let bundle = self.take_bundle()?;
        let instance = CanonicalJournalInstanceDataV1::from_payload(payload);
        Some(CanonicalOrdinaryHeldJournalV1::from_bundle(
            bundle,
            selection,
            Some(instance),
        ))
    }

    /// Parks the complete retained bundle before its traversal is retired.
    ///
    /// The actual role first completes its semantic and independent native posts.
    /// This entry parks the native prefix in this owner's private pending slot
    /// while retaining its SAME index in its original field. A later traversal
    /// refusal therefore retains both halves in their original Drop order;
    /// no generic role-specific held value must be built or dropped prematurely.
    ///
    /// # Errors
    /// Refuses ordinary mode, reentry, incomplete replay/tail or prior failure.
    pub fn prepare_completed_transfer_once_v1(
        &mut self,
    ) -> Result<(), NativeJournalDataErrorV1> {
        if self.mode != Some(OpeningMode::Retained)
            || self.pending.is_some()
            || self.taken
            || self.closed.is_some()
            || self.retirement.is_some()
            || !self.index_originals.is_complete()
        {
            return Err(self.refuse_order());
        }
        let Some(opened) = self.native.take_completed_native_parts_once() else {
            return Err(self.refuse_order());
        };
        self.pending = Some(opened);
        Ok(())
    }

    fn take_bundle(&mut self) -> Option<OpenedIndexBundle> {
        if self.taken || self.closed.is_some() || !self.index_originals.is_complete() {
            return None;
        }
        if matches!(self.retirement, Some(Err(_)))
            || (self.pending.is_some() && !matches!(self.retirement, Some(Ok(()))))
        {
            return None;
        }
        let opened = match self.pending.take() {
            Some(opened) => opened,
            None => self.native.take_completed_native_parts_once()?,
        };
        let bundle = OpenedIndexBundle {
            opened,
            index: std::mem::take(&mut self.index),
        };
        self.taken = true;
        Some(bundle)
    }

    /// Retires the actual retained traversal after its native bundle moved.
    ///
    /// The role invokes this only after its own completed semantic/native posts.
    /// Ordinary disposal retains its existing lexical route instead.
    ///
    /// # Errors
    /// Preserves the existing incomplete, ordinary or repeated-retirement refusal.
    pub fn retire_completed_traversal_once_v1(&mut self) -> Result<(), NativeJournalDataErrorV1> {
        if self.retirement.is_some() {
            return Err(self.refuse_order());
        }
        self.retirement = Some(self.native.retire_completed_traversal_once_v1());
        if matches!(self.retirement, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NativeJournalDataErrorV1::ProtectedBoundary)
        }
    }

    /// Disposes current ordinary parser locals before the role's older scratch.
    ///
    /// # Errors
    /// Refuses retained or repeated disposition without resetting any original.
    pub fn dispose_ordinary_current_once_v1(&mut self) -> Result<bool, NativeJournalDataErrorV1> {
        if self.mode != Some(OpeningMode::Ordinary) || self.ordinary_disposition != 0 {
            return Err(self.refuse_order());
        }
        self.ordinary_disposition = 1;
        Ok(self.native.dispose_ordinary_current_once())
    }

    /// Disposes pending ordinary parser locals after the actual role scratch.
    ///
    /// # Errors
    /// Refuses an out-of-order or repeated disposition without another effect.
    pub fn dispose_ordinary_pending_once_v1(&mut self) -> Result<bool, NativeJournalDataErrorV1> {
        if self.mode != Some(OpeningMode::Ordinary) || self.ordinary_disposition != 1 {
            return Err(self.refuse_order());
        }
        self.ordinary_disposition = 2;
        Ok(self.native.dispose_ordinary_pending_once())
    }

    /// Moves actual ordinary index and native causes in their old disposal order.
    ///
    /// The caller first disposes current parser locals, its own semantic scratch
    /// and pending locals. Index originals and index retire next, followed by
    /// the existing native error extractor's exact physical disposal. Both typed
    /// causes are returned separately so role chronology is never flattened.
    ///
    /// # Errors
    /// Returns the whole unchanged owner for retained or incomplete disposition.
    #[allow(clippy::result_large_err)]
    pub fn into_ordinary_errors_v1(
        mut self,
    ) -> Result<
        (
            Option<IdempotencyRecordDataErrorV1>,
            Option<NativeJournalDataErrorV1>,
        ),
        Self,
    > {
        if self.mode != Some(OpeningMode::Ordinary) || self.ordinary_disposition != 2 {
            return Err(self);
        }
        let originals = std::mem::replace(
            &mut self.index_originals,
            CanonicalReplayIndexOriginalsV1::new(),
        );
        let index_cause = originals.into_ordinary_error();
        drop(std::mem::take(&mut self.index));
        self.ordinary_disposition = 3;

        let native = std::mem::replace(&mut self.native, CanonicalWriterOpeningOriginalsV1::new());
        let native_cause = native.into_ordinary_error().or_else(|| self.closed.take());
        Ok((index_cause, native_cause))
    }

    /// Checks only the existing fixture's retained ancestor count and handles.
    ///
    /// This test-only observation performs the same metadata probes as the old
    /// real ancestor-lifetime regression. It returns no descriptor or authority.
    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    #[must_use]
    pub fn retained_ancestors_for_fixture_v1(&self) -> (usize, bool) {
        (
            self.native.ancestors.len(),
            self.native.ancestors.iter().all(|file| file.metadata().is_ok()),
        )
    }

    /// Borrows the actual native cause independently from the role's selector.
    #[must_use]
    pub fn native_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.native
            .failure()
            .or_else(|| {
                self.retirement.as_ref()?.as_ref().err().map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Borrows the actual index cause without changing its failure chronology.
    #[must_use]
    pub fn index_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.index_originals.failure()
    }

    fn refuse_order(&mut self) -> NativeJournalDataErrorV1 {
        self.closed
            .get_or_insert(NativeJournalDataErrorV1::ProtectedBoundary);
        NativeJournalDataErrorV1::ProtectedBoundary
    }
}

impl Default for CanonicalOrdinaryOpeningOriginalsV1<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> Drop for CanonicalOrdinaryOpeningOriginalsV1<C> {
    fn drop(&mut self) {
        if self.mode == Some(OpeningMode::Ordinary) {
            // These were lexical index locals in the ordinary adapter. Retained
            // opening fields deliberately keep their native-before-index order.
            drop(std::mem::replace(
                &mut self.index_originals,
                CanonicalReplayIndexOriginalsV1::new(),
            ));
            drop(std::mem::take(&mut self.index));
        }
    }
}

/// Keeps the actual ordinary native, same replay index and location together.
///
/// Its constructor accepts only this module's private acquisition bundle. Read
/// views expose no mutable map, descriptor, role brand or native adopter. Fields
/// retain native, index, location and optional instance in that destruction order.
///
/// The private index cannot be replaced by caller-supplied DATA:
///
/// ```compile_fail
/// use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryHeldJournalV1;
/// fn replace_index(writer: &mut CanonicalOrdinaryHeldJournalV1<()>) {
///     writer.index = Default::default();
/// }
/// ```
pub struct CanonicalOrdinaryHeldJournalV1<P, I = ()> {
    native: CanonicalNativeJournalV1,
    index: Index,
    location: Option<ProtectedJournalLocation<P>>,
    instance: Option<CanonicalJournalInstanceDataV1<I>>,
    access: AcquisitionAccess,
}

impl<P, I> CanonicalOrdinaryHeldJournalV1<P, I> {
    /// Returns the actual next sequence without issuing a snapshot authority.
    #[must_use]
    pub const fn next_sequence_data_v1(&self) -> u64 {
        self.native.native().next_sequence()
    }

    /// Returns the actual opened limits as passive configuration DATA.
    #[must_use]
    pub const fn limits_data_v1(&self) -> JournalLimits {
        self.native.native().limits()
    }


    fn from_bundle(
        bundle: OpenedIndexBundle,
        selection: P,
        instance: Option<CanonicalJournalInstanceDataV1<I>>,
    ) -> (Self, RecoveryReport) {
        let CompletedNativeOpening {
            configuration,
            directory,
            file,
            lock,
            prefix,
            report,
            access,
        } = bundle.opened;
        let native = CanonicalNativeJournalV1::from_owned_parts(
            configuration.path,
            file,
            lock,
            configuration.limits,
            prefix,
        );
        let location = directory.map(|directory| {
            ProtectedJournalLocation::from_original_parts((
                directory,
                configuration.name,
                configuration.uid,
                selection,
            ))
        });
        (
            Self {
                native,
                index: bundle.index,
                location,
                instance,
                access,
            },
            report,
        )
    }

    /// Borrows immutable DATA from these same held native/index/location objects.
    #[must_use]
    pub fn read_view_v1(&self) -> CanonicalWriterReadViewV1<'_, P> {
        CanonicalWriterReadViewV1::from_parts(
            self.native.native(),
            &self.index,
            self.location.as_ref(),
        )
    }

    /// Borrows the intrinsic instance without adopting a role or current cut.
    #[must_use]
    pub fn instance_data_v1(&self) -> Option<&CanonicalJournalInstanceDataV1<I>> {
        self.instance.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    use aos_sandbox_model::RecordNamespace;
    use aos_sandbox_protocol::domain_ledger::transaction::{
        self as data, JournalRecord, JournalTransaction,
    };

    pub(super) fn protected_directory() -> tempfile::TempDir {
        // Shared /tmp ancestry deliberately refuses protected traversal. This
        // is the same private executable-adjacent fixture as native opening.
        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new()
            .prefix("ordinary-bundle-")
            .tempdir_in(executable.parent().unwrap())
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn write_decisions(directory: &Path, decisions: &[(u8, u8)]) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("history"))
            .unwrap();
        let mut sequence = 1;
        for &(transaction, decision) in decisions {
            let mut value = vec![decision; 32];
            value.extend_from_slice(&[7; 16]);
            let transaction = JournalTransaction::new(
                [transaction; 16],
                vec![JournalRecord::put(
                    RecordNamespace::Idempotency,
                    vec![1, 2],
                    value,
                )],
            )
            .unwrap();
            for frame in data::encode_transaction(&transaction, sequence).unwrap() {
                file.write_all(&frame).unwrap();
            }
            sequence += 3;
        }
        file.sync_all().unwrap();
    }

    pub(super) fn finish_replay<C>(opening: &mut CanonicalOrdinaryOpeningOriginalsV1<C>) {
        let mut cursor = opening.begin_indexed_replay_once_v1().unwrap();
        while cursor.advance_once().unwrap() {
            cursor.validate_compaction_once().unwrap();
            cursor.register_and_compare_index_once().unwrap();
            cursor.prepare_change_once().unwrap();
            while cursor.apply_next_record_once().unwrap() {}
            cursor.finish_commit_accounting_once().unwrap();
            // The actual caller's final semantic window remains here.
            cursor.finish_commit_once().unwrap();
        }
        assert!(cursor.completed_prefix().is_some());
    }

    #[test]
    fn pending_transfer_keeps_the_same_native_index_and_capture_through_retirement() {
        let directory = protected_directory();
        write_decisions(directory.path(), &[(1, 4)]);
        // Existing-only acquisition requires its genuinely provisioned lock.
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.path().join("history.lock"))
                .unwrap(),
        );
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening.capture_instance_once_v1().unwrap();
        let captured = opening.captured_instance_data_v1().unwrap().clone();
        opening
            .prepare_retaining_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::getuid().as_raw(),
                false,
            )
            .unwrap();
        opening.prepare_parser_identity_once_v1().unwrap();
        let original_identity = opening.parser_identity_data_v1().unwrap();
        finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();

        opening.prepare_completed_transfer_once_v1().unwrap();
        assert!(opening.pending.is_some());
        assert!(opening.native.file.is_none());
        assert!(opening.native.directory.is_none());
        let pending_file = opening.pending.as_ref().unwrap().file.as_raw_fd();
        let pending_index = opening.index.keys().next().unwrap().as_ptr();
        assert!(
            opening
                .take_held_with_captured_instance_once_v1(())
                .is_none()
        );
        let pending = opening.pending.as_ref().unwrap();
        assert_eq!(pending.file.as_raw_fd(), pending_file);
        assert_eq!(opening.index.keys().next().unwrap().as_ptr(), pending_index);
        assert!(
            opening
                .captured_instance_data_v1()
                .unwrap()
                .same_original_v1(&captured)
        );

        opening.retire_completed_traversal_once_v1().unwrap();
        let (held, _) = opening
            .take_held_with_captured_instance_once_v1(())
            .unwrap();

        assert!(held.instance_data_v1().unwrap().same_original_v1(&captured));
        assert!(
            held.read_view_v1()
                .file_identity::<NativeJournalDataErrorV1>()
                .unwrap()
                == original_identity
        );
        assert_eq!(held.read_view_v1().state().len(), 1);
        assert!(opening.pending.is_none());
        assert!(
            opening
                .take_held_with_captured_instance_once_v1(())
                .is_none()
        );
    }

    #[test]
    fn premature_retirement_cannot_be_repaired_by_a_later_bundle_move() {
        let directory = protected_directory();
        write_decisions(directory.path(), &[(1, 4)]);
        // Existing-only acquisition requires its genuinely provisioned lock.
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.path().join("history.lock"))
                .unwrap(),
        );
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_retaining_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::getuid().as_raw(),
                false,
            )
            .unwrap();
        opening.prepare_parser_identity_once_v1().unwrap();
        finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();

        assert!(opening.retire_completed_traversal_once_v1().is_err());
        let first = opening.native_failure_v1().unwrap() as *const dyn Error;
        assert!(opening.prepare_completed_transfer_once_v1().is_err());
        assert!(opening.take_held_without_instance_once_v1(()).is_none());

        assert!(opening.native.file.is_some());
        assert!(opening.native.directory.is_some());
        assert!(opening.pending.is_none());
        assert!(std::ptr::eq(opening.native_failure_v1().unwrap(), first));
    }

    #[test]
    fn vacant_and_incomplete_openings_cannot_transfer_or_create_late_identity() {
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        assert!(opening.take_held_without_instance_once_v1(()).is_none());
        assert!(opening.take_held_with_late_instance_once_v1(()).is_none());
        assert!(opening.instance.is_none());
        assert!(opening.index.is_empty());
        assert!(!opening.index_originals.is_complete());

        let directory = protected_directory();
        write_decisions(directory.path(), &[(1, 3)]);
        opening
            .prepare_ordinary_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        {
            let mut cursor = opening.begin_indexed_replay_once_v1().unwrap();
            assert!(cursor.advance_once().unwrap());
        }

        // A real current COMMIT is still resident, not a completed parser/index.
        assert!(opening.take_held_without_instance_once_v1(()).is_none());
        assert!(opening.take_held_with_late_instance_once_v1(()).is_none());
        assert!(opening.instance.is_none());
        assert!(
            opening
                .native
                .replay
                .work
                .as_ref()
                .unwrap()
                .transaction
                .is_some()
        );
    }

    #[test]
    fn actual_bundle_moves_same_native_file_and_index_without_an_instance() {
        let directory = protected_directory();
        write_decisions(directory.path(), &[(1, 3)]);
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_ordinary_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        let file = opening.native.file.as_ref().unwrap().as_raw_fd();
        finish_replay(&mut opening);
        let index_key = opening.index.keys().next().unwrap().as_ptr();

        // Even completed replay cannot transfer before the actual tail stage.
        assert!(opening.take_held_without_instance_once_v1(()).is_none());
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (held, report) = opening.take_held_without_instance_once_v1(()).unwrap();

        assert_eq!(held.native.native().file().as_raw_fd(), file);
        assert_eq!(held.index.keys().next().unwrap().as_ptr(), index_key);
        assert_eq!(report.committed_transactions, 1);
        assert_eq!(report.committed_records, 1);
        assert_eq!(
            held.read_view_v1()
                .idempotency_index()
                .get([1, 2].as_slice())
                .unwrap()
                .request_digest,
            [3; 32]
        );
        assert!(
            held.read_view_v1()
                .state()
                .contains_key(&(RecordNamespace::Idempotency, vec![1, 2]))
        );
        assert!(held.instance_data_v1().is_none());
        assert!(opening.instance.is_none());
        assert!(opening.take_held_without_instance_once_v1(()).is_none());
    }

    #[test]
    fn captured_identity_moves_by_alias_and_weak_stamp_does_not_extend_custody() {
        let directory = protected_directory();
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening.capture_instance_once_v1().unwrap();
        let stamp = opening
            .captured_instance_data_v1()
            .unwrap()
            .comparison_stamp_v1();
        opening
            .prepare_retaining_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        assert!(opening.take_held_without_instance_once_v1(()).is_none());
        assert!(opening.take_held_with_late_instance_once_v1(()).is_none());
        let (held, _) = opening
            .take_held_with_captured_instance_once_v1(())
            .unwrap();

        let captured = opening.captured_instance_data_v1().unwrap();
        assert!(captured.same_original_v1(held.instance_data_v1().unwrap()));
        assert!(held.instance_data_v1().unwrap().matches_stamp_v1(&stamp));
        let foreign = CanonicalJournalInstanceDataV1::new();
        assert!(!foreign.matches_stamp_v1(&stamp));
        assert!(!foreign.same_original_v1(captured));
        opening.retire_completed_traversal_once_v1().unwrap();
        drop(held);
        assert!(stamp.0.upgrade().is_some());
        drop(opening);
        assert!(stamp.0.upgrade().is_none());
        assert!(!foreign.matches_stamp_v1(&stamp));
    }

    #[test]
    fn late_identity_appears_only_after_the_actual_completed_transfer() {
        let directory = protected_directory();
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_ordinary_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        finish_replay(&mut opening);
        assert!(opening.take_held_with_late_instance_once_v1(()).is_none());
        assert!(opening.instance.is_none());
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (held, _) = opening.take_held_with_late_instance_once_v1(()).unwrap();

        assert!(opening.instance.is_none());
        let original = held.instance_data_v1().unwrap();
        let alias = original.clone();
        assert!(original.same_original_v1(&alias));
        assert_eq!(Arc::strong_count(&alias.0), 2);
    }

    #[test]
    fn native_refusal_retains_original_cause_and_never_allocates_a_late_identity() {
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        let absent = std::path::PathBuf::from(format!(
            "/aos-ordinary-bundle-{}-absent",
            std::process::id()
        ));
        let uid = std::fs::File::open("/").unwrap().metadata().unwrap();
        use std::os::unix::fs::MetadataExt as _;
        assert!(
            opening
                .prepare_retaining_once_v1(
                    &absent,
                    "history",
                    JournalLimits::default(),
                    uid.uid(),
                    false
                )
                .is_err()
        );
        let first = opening.native_failure_v1().unwrap() as *const dyn Error as *const ();

        assert!(opening.take_held_with_late_instance_once_v1(()).is_none());
        assert!(opening.instance.is_none());
        assert!(
            opening
                .prepare_retaining_once_v1(
                    &absent,
                    "history",
                    JournalLimits::default(),
                    uid.uid(),
                    false
                )
                .is_err()
        );
        assert_eq!(
            opening.native_failure_v1().unwrap() as *const dyn Error as *const (),
            first
        );
        // A retained diagnostic extraction cannot consume its native prefix.
        assert!(opening.into_ordinary_errors_v1().is_err());
    }

    #[test]
    fn actual_index_conflict_survives_ordered_ordinary_disposition_as_typed_cause() {
        let directory = protected_directory();
        write_decisions(directory.path(), &[(1, 3), (2, 4)]);
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_ordinary_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        {
            let mut cursor = opening.begin_indexed_replay_once_v1().unwrap();
            assert!(cursor.advance_once().unwrap());
            cursor.validate_compaction_once().unwrap();
            cursor.register_and_compare_index_once().unwrap();
            cursor.prepare_change_once().unwrap();
            while cursor.apply_next_record_once().unwrap() {}
            cursor.finish_commit_accounting_once().unwrap();
            cursor.finish_commit_once().unwrap();
            assert!(cursor.advance_once().unwrap());
            cursor.validate_compaction_once().unwrap();
            assert!(cursor.register_and_compare_index_once().is_err());
        }
        assert!(opening.index_failure_v1().is_some());
        let mut opening = match opening.into_ordinary_errors_v1() {
            Err(held) => held,
            Ok(_) => panic!("unordered diagnostic extraction consumed the owner"),
        };
        let _ = opening.dispose_ordinary_current_once_v1().unwrap();
        // The real caller disposes its independent role scratch at this gap.
        let _ = opening.dispose_ordinary_pending_once_v1().unwrap();
        let (index, native) = match opening.into_ordinary_errors_v1() {
            Ok(causes) => causes,
            Err(_) => panic!("ordered ordinary disposition refused"),
        };
        assert!(matches!(
            index,
            Some(IdempotencyRecordDataErrorV1::Conflict)
        ));
        assert!(native.is_none());
    }

    struct NonClonePayload {
        dropped: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for NonClonePayload {
        fn drop(&mut self) {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct OtherNonClonePayload {
        dropped: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for OtherNonClonePayload {
        fn drop(&mut self) {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn typed_capture_preserves_non_clone_payload_same_arc_and_outer_drop_alias() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = protected_directory();
        write_decisions(directory.path(), &[(1, 3)]);
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut opening =
            CanonicalOrdinaryOpeningOriginalsV1::<NonClonePayload>::new_for_capture_payload_v1();
        assert!(opening.captured_instance_data_v1().is_none());
        opening
            .capture_instance_payload_once_v1(NonClonePayload {
                dropped: Arc::clone(&dropped),
            })
            .unwrap();
        let captured = opening.captured_instance_data_v1().unwrap().clone();
        let stamp = captured.comparison_stamp_v1();
        let weak_alias = stamp.clone();
        // These compile with no Clone or Default implementation on the payload.
        let outer_alias: Arc<NonClonePayload> = Arc::clone(captured.comparison_arc_v1());

        opening
            .prepare_retaining_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        let native_fd = opening.native.file.as_ref().unwrap().as_raw_fd();
        finish_replay(&mut opening);
        let index_key = opening.index.keys().next().unwrap().as_ptr();
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (held, _) = opening
            .take_held_with_captured_instance_once_v1(())
            .unwrap();
        assert_eq!(held.native.native().file().as_raw_fd(), native_fd);
        assert_eq!(held.index.keys().next().unwrap().as_ptr(), index_key);
        assert!(held.instance_data_v1().unwrap().same_original_v1(&captured));
        assert!(Arc::ptr_eq(
            held.instance_data_v1().unwrap().comparison_arc_v1(),
            &outer_alias
        ));
        assert!(
            held.instance_data_v1()
                .unwrap()
                .matches_stamp_v1(&weak_alias)
        );

        opening.retire_completed_traversal_once_v1().unwrap();
        drop(opening);
        drop(captured);
        drop(held);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(outer_alias);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(stamp.0.upgrade().is_none());
        assert!(weak_alias.0.upgrade().is_none());
    }

    #[test]
    fn late_non_clone_payload_keeps_typed_arc_through_actual_borrowed_append() {
        use crate::canonical_journal::coordinator::{
            CanonicalCoordinatorAppendDataV1 as _, CanonicalCoordinatorAppendV1 as _,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = protected_directory();
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut opening = CanonicalOrdinaryOpeningOriginalsV1::new();
        opening
            .prepare_ordinary_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        finish_replay(&mut opening);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (mut held, _) = opening
            .take_held_with_late_payload_once_v1(
                (),
                NonClonePayload {
                    dropped: Arc::clone(&dropped),
                },
            )
            .unwrap();
        let outer_alias: Arc<NonClonePayload> =
            Arc::clone(held.instance_data_v1().unwrap().comparison_arc_v1());
        let original_weak: Weak<NonClonePayload> = Arc::downgrade(&outer_alias);
        assert!(opening.captured_instance_data_v1().is_none());

        // The generic held payload adds no bound to the existing staged engine.
        // This is ordinary mechanical DATA, not a fake selected role original.
        let transaction = JournalTransaction::new(
            [9; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![42],
                vec![9, 8],
            )],
        )
        .unwrap();
        let mut stage = held.prepare_append_once(&transaction).unwrap();
        assert!(std::ptr::eq(stage.transaction().unwrap(), &transaction));
        held.append_coordinates_once(&mut stage).unwrap();
        held.expected_append_length_once(&mut stage).unwrap();
        assert!(held.append_prepared_once(&mut stage).unwrap() > 0);
        while held.apply_next_record_once(&mut stage).unwrap() {}
        held.publish_append_once(&mut stage).unwrap();
        held.finish_append_after_posts_once(&mut stage).unwrap();
        assert_eq!(
            held.read_view_v1()
                .state()
                .get(&(RecordNamespace::DesiredState, vec![42])),
            Some(&vec![9, 8])
        );
        assert!(Arc::ptr_eq(
            held.instance_data_v1().unwrap().comparison_arc_v1(),
            &outer_alias
        ));

        drop(stage);
        drop(opening);
        drop(held);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(outer_alias);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(original_weak.upgrade().is_none());
    }

    #[test]
    fn independent_late_payload_preserves_two_origins_and_refuses_before_tail() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = protected_directory();
        write_decisions(directory.path(), &[(1, 3)]);
        let captured_drops = Arc::new(AtomicUsize::new(0));
        let late_drops = Arc::new(AtomicUsize::new(0));
        let mut opening =
            CanonicalOrdinaryOpeningOriginalsV1::<NonClonePayload>::new_for_capture_payload_v1();
        opening
            .capture_instance_payload_once_v1(NonClonePayload {
                dropped: Arc::clone(&captured_drops),
            })
            .unwrap();
        let receiver_alias: Arc<NonClonePayload> = Arc::clone(
            opening
                .captured_instance_data_v1()
                .unwrap()
                .comparison_arc_v1(),
        );
        let capture_weak = Arc::downgrade(&receiver_alias);
        opening
            .prepare_retaining_once_v1(
                directory.path(),
                "history",
                JournalLimits::default(),
                rustix::process::geteuid().as_raw(),
                true,
            )
            .unwrap();
        finish_replay(&mut opening);
        let native_fd = opening.native.file.as_ref().unwrap().as_raw_fd();
        let index_key = opening.index.keys().next().unwrap().as_ptr();

        assert!(
            opening
                .take_held_with_independent_late_payload_once_v1(
                    (),
                    OtherNonClonePayload {
                        dropped: Arc::clone(&late_drops),
                    }
                )
                .is_none()
        );
        // The rejected by-value argument retires without taking native/index or
        // retaining a late identity. The original capture stays exactly live.
        assert_eq!(late_drops.load(Ordering::SeqCst), 1);
        assert_eq!(captured_drops.load(Ordering::SeqCst), 0);
        assert!(!opening.taken);
        assert_eq!(opening.native.file.as_ref().unwrap().as_raw_fd(), native_fd);
        assert_eq!(opening.index.keys().next().unwrap().as_ptr(), index_key);
        opening
            .finish_replayed_tail_once_v1(RecoveryTailMode::RejectIncomplete)
            .unwrap();
        let (held, _) = opening
            .take_held_with_independent_late_payload_once_v1(
                (),
                OtherNonClonePayload {
                    dropped: Arc::clone(&late_drops),
                },
            )
            .unwrap();
        let outer_alias: Arc<OtherNonClonePayload> =
            Arc::clone(held.instance_data_v1().unwrap().comparison_arc_v1());
        let late_weak = Arc::downgrade(&outer_alias);
        assert_eq!(held.native.native().file().as_raw_fd(), native_fd);
        assert_eq!(held.index.keys().next().unwrap().as_ptr(), index_key);
        assert_ne!(
            Arc::as_ptr(&receiver_alias) as *const (),
            Arc::as_ptr(&outer_alias) as *const ()
        );
        assert!(Arc::ptr_eq(
            opening
                .captured_instance_data_v1()
                .unwrap()
                .comparison_arc_v1(),
            &receiver_alias
        ));
        assert!(
            opening
                .take_held_with_independent_late_payload_once_v1(
                    (),
                    OtherNonClonePayload {
                        dropped: Arc::clone(&late_drops),
                    }
                )
                .is_none()
        );
        assert_eq!(late_drops.load(Ordering::SeqCst), 2);

        opening.retire_completed_traversal_once_v1().unwrap();
        drop(opening);
        drop(held);
        assert_eq!(captured_drops.load(Ordering::SeqCst), 0);
        assert_eq!(late_drops.load(Ordering::SeqCst), 2);
        drop(outer_alias);
        assert_eq!(late_drops.load(Ordering::SeqCst), 3);
        assert!(late_weak.upgrade().is_none());
        assert!(capture_weak.upgrade().is_some());
        drop(receiver_alias);
        assert_eq!(captured_drops.load(Ordering::SeqCst), 1);
        assert!(capture_weak.upgrade().is_none());
    }
}
