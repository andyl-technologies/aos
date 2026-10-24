//! Keeps actual typed floor models beside their reached native read prefixes.
//!
//! Ordinary and selected reads expand one ordered recipe. Selected ownership
//! is installed before each real call, while its genuine caller separately
//! prepays the captured sidecar extent and retains the whole operation/post.

use std::error::Error;
use std::mem::size_of;
use std::path::Path;

use aos_sandbox_controller_domain::{JournalError, JournalLimits, JournalTransaction,
    ProtectedJournalCurrentnessOriginalsV1, ProtectedJournalSnapshot};
use aos_sandbox_model::ResourceDimension as D;
use aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityReadCaptureV1;
use aos_sandbox_protocol::domain_ledger::transaction::PreparedTransactionDecodeCaptureV1;

use super::{BrokerSidecarStoreV1, FloorCheckpointDataV1, FloorErrorV1, FloorIntentDataV1,
    FloorProfileDataV1, StoredFloorDataV1, CHECKPOINT_KEY, INTENT_KEY, TRANSACTION_KEY,
    RecordNamespace, sidecar_sequence};

#[derive(Clone, Copy)]
enum FirstV1 {
    Before, Claim, Snapshot, Records, Checkpoint, Intent, Prepared, Presence,
    Profile, Predecessor, Transaction, Sequence, SequenceBinding, Effect, After, Returned, Reentry,
}

/// Retains one typed sidecar read without authorizing a floor or another writer.
///
/// Construction is inert. This value keeps both real rooted/name observations,
/// full canonical claim scans, the opaque snapshot, actual prepared transaction
/// partials and decoded models through every later comparison/post refusal.
#[must_use = "retain failed typed floor reads and their independently owed posts"]
pub(crate) struct BrokerFloorReadOriginalV1 {
    before_originals: ProtectedJournalCurrentnessOriginalsV1,
    before: Option<Result<(), JournalError>>,
    capacity: [CanonicalCapacityReadCaptureV1; 2],
    claim: Option<Result<(), JournalError>>,
    snapshot: Option<Result<ProtectedJournalSnapshot, JournalError>>,
    records: Option<Result<(), JournalError>>,
    checkpoint: Option<Result<FloorCheckpointDataV1, FloorErrorV1>>,
    intent: Option<Result<FloorIntentDataV1, FloorErrorV1>>,
    prepared: PreparedTransactionDecodeCaptureV1,
    transaction_digest: super::super::digest::FloorTransactionDigestOriginalV1,
    transaction: Option<JournalTransaction>,
    presence: Option<Result<(), FloorErrorV1>>,
    profile: Option<Result<(), FloorErrorV1>>,
    predecessor: Option<Result<(), FloorErrorV1>>,
    transaction_binding: Option<Result<(), FloorErrorV1>>,
    sequence: Option<Result<u64, FloorErrorV1>>,
    sequence_binding: Option<Result<(), FloorErrorV1>>,
    effect: Option<Result<(), JournalError>>,
    stored: Option<StoredFloorDataV1>,
    after_originals: ProtectedJournalCurrentnessOriginalsV1,
    after: Option<Result<(), JournalError>>,
    returned: Option<Result<StoredFloorDataV1, FloorErrorV1>>,
    entered: bool,
    reentry: Option<FloorErrorV1>,
    first: Option<FirstV1>,
}

// A field-split borrow keeps the actual selected read owner resident on its
// store while this same recipe observes the store's original custody.
struct BorrowedBrokerSidecarReadV2<'held> {
    custody: &'held mut crate::recovery::BrokerSidecarCustodyV1,
    main_limits: JournalLimits,
}

// These steps change destinations only. Both modes below share one complete
// row/semantic recipe; ordinary native error projection and drop stay local.
macro_rules! read_step {
    (Ordinary, native $original:ident, $field:ident, $site:ident, $result:expr) => {
        $result.map_err(|_| FloorErrorV1::Unavailable)?
    };
    (Retained, native $original:ident, $field:ident, $site:ident, $result:expr) => {{
        match $result {
            Ok(value) => { $original.$field = Some(Ok(())); value }
            Err(cause) => {
                $original.$field = Some(Err(cause));
                $original.first.get_or_insert(FirstV1::$site);
                return Err(FloorErrorV1::Unavailable);
            }
        }
    }};
    (Ordinary, scalar $original:ident, $field:ident, $site:ident, $result:expr) => { $result? };
    (Retained, scalar $original:ident, $field:ident, $site:ident, $result:expr) => {{
        $original.$field = Some($result);
        match $original.$field.as_ref() {
            Some(Ok(value)) => *value,
            Some(Err(cause)) => {
                $original.first.get_or_insert(FirstV1::$site);
                return Err(*cause);
            }
            None => return Err(FloorErrorV1::Unavailable),
        }
    }};
    (Ordinary, before $store:ident, $original:ident) => { $store.validate_held()?; };
    (Retained, before $store:ident, $original:ident) => {
        read_step!(Retained, native $original, before, Before,
            $store.custody.validate_held_retaining_v1(&mut $original.before_originals));
    };
    (Ordinary, claim $store:ident, $original:ident) => {
        $store.custody.journal_mut().claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
            .map_err(|_| FloorErrorV1::Unavailable)?
    };
    (Retained, claim $store:ident, $original:ident) => {
        read_step!(Retained, native $original, claim, Claim,
            $store.custody.journal_mut().claim_protected_authority_retaining_v1(
                RecordNamespace::BrokerSessionTraffic, &mut $original.capacity))
    };
    (Ordinary, snapshot $authority:ident, $original:ident) => {
        $authority.snapshot().map_err(|_| FloorErrorV1::Unavailable)?
    };
    (Retained, snapshot $authority:ident, $original:ident) => {{
        $original.snapshot = Some($authority.snapshot());
        match $original.snapshot.as_ref() {
            Some(Ok(snapshot)) => snapshot,
            _ => {
                $original.first.get_or_insert(FirstV1::Snapshot);
                return Err(FloorErrorV1::Unavailable);
            }
        }
    }};
    (Ordinary, presence $original:ident, $checkpoint:ident) => {
        $checkpoint.ok_or(FloorErrorV1::Unavailable)?
    };
    (Retained, presence $original:ident, $checkpoint:ident) => {{
        $original.presence = Some($checkpoint.as_ref().map(|_| ()).ok_or(FloorErrorV1::Unavailable));
        match $checkpoint {
            Some(checkpoint) => checkpoint,
            None => {
                $original.first.get_or_insert(FirstV1::Presence);
                return Err(FloorErrorV1::Unavailable);
            }
        }
    }};
    (Ordinary, bind_transaction $original:ident, $intent:ident, $transaction:ident) => {
        $intent.require_transaction($transaction)?
    };
    (Retained, bind_transaction $original:ident, $intent:ident, $transaction:ident) => {
        read_step!(Retained, scalar $original, transaction_binding, Transaction,
            $intent.require_transaction_retaining_v1($transaction, &mut $original.transaction_digest))
    };
    (Ordinary, transaction_init $local:ident) => {
        let mut $local: Option<JournalTransaction> = None;
    };
    (Retained, transaction_init $local:ident) => {};
    (Ordinary, transaction_slot $original:ident, $local:ident) => { &mut $local };
    (Retained, transaction_slot $original:ident, $local:ident) => { &mut $original.transaction };
    (Ordinary, prepared $original:ident, $value:ident, $limits:expr) => {
        JournalTransaction::decode_prepared_v1($value, $limits).map_err(|_| FloorErrorV1::Encoding)?
    };
    (Retained, prepared $original:ident, $value:ident, $limits:expr) => {{
        if $original.prepared.decode_once_v1($value, $limits).is_err() {
            $original.first.get_or_insert(FirstV1::Prepared);
            return Err(FloorErrorV1::Encoding);
        }
        $original.prepared.take_completed_v1().ok_or(FloorErrorV1::Encoding)?
    }};
    (Ordinary, store $original:ident, $stored:ident) => {};
    (Retained, store $original:ident, $stored:ident) => { $original.stored = Some($stored); };
    (Ordinary, after $store:ident, $original:ident) => { $store.validate_held()?; };
    (Retained, after $store:ident, $original:ident) => {
        read_step!(Retained, native $original, after, After,
            $store.custody.validate_held_retaining_v1(&mut $original.after_originals));
    };
    (Ordinary, finish $original:ident, $stored:ident) => { Ok($stored) };
    (Retained, finish $original:ident, $stored:ident) => {
        $original.stored.take().ok_or(FloorErrorV1::Unavailable)
    };
}

macro_rules! read_recipe {
    ($mode:ident, $store:ident, $original:ident, $profile:ident) => {{
        (|| {
            read_step!($mode, before $store, $original);
            let authority = read_step!($mode, claim $store, $original);
            let snapshot = read_step!($mode, snapshot authority, $original);
            let mut checkpoint = None;
            let mut intent = None;
            read_step!($mode, transaction_init ordinary_transaction);
            let transaction = read_step!($mode, transaction_slot $original, ordinary_transaction);
            for (key, value) in read_step!($mode, native $original, records, Records, authority.records()) {
                match key {
                    CHECKPOINT_KEY => {
                        checkpoint = Some(read_step!($mode, scalar $original, checkpoint, Checkpoint,
                            FloorCheckpointDataV1::decode($profile, value)));
                    }
                    INTENT_KEY => {
                        intent = Some(read_step!($mode, scalar $original, intent, Intent,
                            FloorIntentDataV1::decode($profile, value)));
                    }
                    TRANSACTION_KEY => {
                        *transaction = Some(read_step!($mode, prepared $original, value, $store.main_limits));
                    }
                    _ => return Err(FloorErrorV1::Encoding),
                }
            }
            let checkpoint = read_step!($mode, presence $original, checkpoint);
            read_step!($mode, scalar $original, profile, Profile, checkpoint.require_profile($profile));
            let prepared = match (intent, transaction.as_ref()) {
                (None, None) => None,
                (Some(intent), Some(transaction)) => {
                    read_step!($mode, scalar $original, predecessor, Predecessor,
                        intent.require_predecessor($profile, checkpoint));
                    read_step!($mode, bind_transaction $original, intent, transaction);
                    Some(intent)
                }
                _ => return Err(FloorErrorV1::Encoding),
            };
            let expected_sequence = read_step!($mode, scalar $original, sequence, Sequence,
                sidecar_sequence(checkpoint.ordinal(), prepared.is_some()));
            read_step!($mode, scalar $original, sequence_binding, SequenceBinding,
                if snapshot.sequence() == expected_sequence { Ok(()) } else { Err(FloorErrorV1::Diverged) });
            read_step!($mode, native $original, effect, Effect,
                authority.validate_snapshot_for_effect(&snapshot));
            let prepared = prepared.map(|intent| transaction.take()
                .map(|transaction| (intent, transaction)).ok_or(FloorErrorV1::Unavailable)).transpose()?;
            let stored = StoredFloorDataV1 { checkpoint, prepared, sequence: snapshot.sequence() };
            read_step!($mode, store $original, stored);
            read_step!($mode, after $store, $original);
            read_step!($mode, finish $original, stored)
        })()
    }};
}

pub(super) fn read_ordinary(store: &mut BrokerSidecarStoreV1, profile: FloorProfileDataV1)
    -> Result<StoredFloorDataV1, FloorErrorV1>
{
    read_recipe!(Ordinary, store, original, profile)
}

impl BrokerFloorReadOriginalV1 {
    /// Creates empty parser/native destinations without IO or allocation.
    pub(crate) fn new() -> Self {
        Self {
            before_originals: ProtectedJournalCurrentnessOriginalsV1::new(), before: None,
            capacity: std::array::from_fn(|_| CanonicalCapacityReadCaptureV1::new()),
            claim: None, snapshot: None, records: None, checkpoint: None, intent: None,
            prepared: PreparedTransactionDecodeCaptureV1::new(),
            transaction_digest: super::super::digest::FloorTransactionDigestOriginalV1::new(), transaction: None,
            presence: None, profile: None, predecessor: None, transaction_binding: None,
            sequence: None, sequence_binding: None, effect: None, stored: None,
            after_originals: ProtectedJournalCurrentnessOriginalsV1::new(), after: None,
            returned: None, entered: false, reentry: None, first: None,
        }
    }

    /// Reads the actual store once and retains every reached result/model.
    ///
    /// # Errors
    /// Preserves the existing native, schema, predecessor and snapshot refusal;
    /// reentry keeps the original failed owner and its first cause unchanged.
    pub(crate) fn observe_once(&mut self, store: &mut BrokerSidecarStoreV1,
        profile: super::super::FloorProfileV1) -> Result<(), FloorErrorV1>
    {
        self.observe_parts_once_v2(&mut store.custody, store.main_limits, profile)
    }

    pub(super) fn observe_parts_once_v2(&mut self,
        custody: &mut crate::recovery::BrokerSidecarCustodyV1,
        main_limits: JournalLimits, profile: super::super::FloorProfileV1)
        -> Result<(), FloorErrorV1>
    {
        let mut store = BorrowedBrokerSidecarReadV2 { custody, main_limits };
        let profile = FloorProfileDataV1::Broker(profile);
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Unavailable);
            self.first.get_or_insert(FirstV1::Reentry);
            return Err(FloorErrorV1::Unavailable);
        }
        self.entered = true;
        self.returned = Some(read_recipe!(Retained, store, self, profile));
        if matches!(self.returned, Some(Err(_))) {
            self.first.get_or_insert(FirstV1::Returned);
        }

        // Early parser/native refusal still owes the independently prepaid
        // rooted/name after. Use its original destination directly after poison;
        // the successful recipe already filled it and must never sample twice.
        if self.after.is_none() {
            self.after = Some(store.custody.validate_held_retaining_v1(
                &mut self.after_originals,
            ));
            if matches!(self.after, Some(Err(_))) {
                self.first.get_or_insert(FirstV1::After);
            }
        }

        match self.returned.as_ref() {
            Some(Ok(_)) if self.first.is_none() => Ok(()),
            Some(Err(cause)) => Err(*cause),
            _ => Err(FloorErrorV1::Unavailable),
        }
    }

    /// Disposes fresh probes only after the complete actual typed read succeeds.
    ///
    /// Positive read completion proves both native comparisons and the full
    /// typed/snapshot recipe. It does not settle an outer TPM/effect body.
    pub(crate) fn retire_positive_native_probes_once_v1(&mut self) {
        if self.completed().is_none() { return; }
        self.before_originals.settle_positive_once_v1();
        self.after_originals.settle_positive_once_v1();
    }

    pub(super) fn take_positive_model_and_retire_raw_v2(&mut self) -> Option<StoredFloorDataV1> {
        self.completed()?;
        self.retire_positive_native_probes_once_v1();
        let stored = self.take_completed()?;
        // The exact canonical model has moved to the enclosing retained read
        // owner. These completed parser/capacity/snapshot intermediates have no
        // remaining native or mutation debt; failed readers never reach here.
        self.capacity = std::array::from_fn(|_| CanonicalCapacityReadCaptureV1::new());
        self.snapshot = None;
        self.prepared = PreparedTransactionDecodeCaptureV1::new();
        self.transaction_digest = super::super::digest::FloorTransactionDigestOriginalV1::new();
        self.transaction = None;
        Some(stored)
    }

    /// Measures two actual failed/owed readers against this captured prefix.
    ///
    /// Returns `None` on mismatched sole limits or checked overflow. The genuine
    /// original must compare its saved facade/main/sidecar links before using
    /// these passive widths; the shape creates no account or reading authority.
    pub(crate) fn receiving_shape_v1(
        main_limits: JournalLimits,
        extent: &aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1,
    ) -> Option<aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::FloorSidecarDecodeShapeV1> {
        use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::{
            FloorSidecarDecodeShapeV1, SIDECAR_DECODE_OBSERVATIONS_V1, sidecar_limits_v1,
        };
        let sidecar_limits = sidecar_limits_v1(main_limits).ok()?;
        if extent.limits != sidecar_limits || extent.native_bytes > sidecar_limits.maximum_journal_bytes {
            return None;
        }
        let physical = usize::try_from(extent.native_bytes).ok()?;
        // The preparation decoder checks its complete maximum before growing.
        // An oversized malformed value therefore has no prepared Vec backing.
        let encoded = physical.min(JournalTransaction::maximum_prepared_bytes_v1(main_limits).ok()?);
        let rows = (physical / aos_sandbox_journal::framing::HEADER_BYTES)
            .min(sidecar_limits.maximum_materialized_records);
        let (prepared_bytes, _) =
            PreparedTransactionDecodeCaptureV1::receiving_obligations_v1(encoded, main_limits)?;
        let (digest_bytes, _) = super::super::digest::FloorTransactionDigestOriginalV1::
            receiving_obligations_v1(encoded, main_limits)?;
        let (capacity_bytes, _) = CanonicalCapacityReadCaptureV1::receiving_obligations_v1(rows)?;
        let rooted = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            Path::new("/var/lib/aos/sandboxd/broker-session/storage"),
            aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::SIDECAR_NAME_V1,
        ).ok()?;
        let rooted_bytes = usize::try_from(rooted.get(D::MemoryBytes)).ok()?;
        let rooted_files = usize::try_from(rooted.get(D::OpenFiles)).ok()?;
        let observations = SIDECAR_DECODE_OBSERVATIONS_V1;
        // Each actual owner and its construction temporary are explicit.
        // Nested supplier inline terms stay conservatively additive.
        let inline_bytes = size_of::<Self>().checked_mul(2)?.checked_mul(observations)?;
        let models = size_of::<FloorCheckpointDataV1>()
            .checked_add(size_of::<FloorIntentDataV1>())?
            .checked_add(size_of::<StoredFloorDataV1>())?
            .checked_add(size_of::<FloorProfileDataV1>())?.checked_mul(3)?;
        // The digest borrows value bytes and owns only its separately priced
        // key index. Checkpoint/intent codecs and nested scope/NV hashes use
        // exact fixed arrays/states; there is no absent encoded payload copy.
        let fixed_codec_scratch = super::super::CHECKPOINT_BYTES
            .checked_add(super::super::INTENT_BYTES.checked_mul(2)?)?
            .checked_add(size_of::<sha2::Sha256>().checked_mul(2)?)?;
        let heap_bytes = prepared_bytes.checked_add(digest_bytes)?
            .checked_add(capacity_bytes.checked_mul(2)?)?
            .checked_add(rooted_bytes.checked_mul(2)?)?.checked_add(models)?
            .checked_add(fixed_codec_scratch)?.checked_mul(observations)?;
        let prepared_entries = PreparedTransactionDecodeCaptureV1::receiving_named_entries_v2(
            encoded, main_limits,
        )?;
        let digest_entries = super::super::digest::FloorTransactionDigestOriginalV1::
            receiving_named_entries_v2(encoded, main_limits);
        let capacity_entries = CanonicalCapacityReadCaptureV1::receiving_named_entries_v2(rows)?;
        // One read retains its real snapshot map, the prepared ordered records
        // and validation index, the digest's key index and two capacity scans.
        // Both failed/owed reads can coexist. Rooted file names are the SAME
        // fixed namespace already charged by the native sidecar preparation;
        // duplicate traversals, path backing and control fields add only bytes
        // and descriptors, never another copy of that namespace.
        let named_entries = rows.checked_add(prepared_entries)?
            .checked_add(digest_entries)?
            .checked_add(capacity_entries.checked_mul(2)?)?
            .checked_mul(observations)?;
        Some(FloorSidecarDecodeShapeV1 {
            main_limits, sidecar_limits, native_bytes: extent.native_bytes,
            inline_bytes, heap_bytes,
            open_files: rooted_files.checked_mul(2)?.checked_mul(observations)?,
            named_entries,
        })
    }

    /// Borrows the same completed typed DATA without a currentness grant.
    pub(crate) fn completed(&self) -> Option<&StoredFloorDataV1> {
        if self.failure().is_some() { return None; }
        self.returned.as_ref()?.as_ref().ok()
    }

    /// Moves completed DATA once while leaving the original one-shot fence.
    pub(crate) fn take_completed(&mut self) -> Option<StoredFloorDataV1> {
        self.completed()?;
        match self.returned.take() {
            Some(Ok(stored)) => Some(stored),
            returned => { self.returned = returned; None }
        }
    }

    /// Borrows the earliest reached raw native, decoder or semantic cause.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
        }
        match self.first {
            Some(FirstV1::Before) => self.before_originals.failure().or_else(|| cause(&self.before)),
            Some(FirstV1::Claim) => cause(&self.claim),
            Some(FirstV1::Snapshot) => cause(&self.snapshot),
            Some(FirstV1::Records) => cause(&self.records),
            Some(FirstV1::Checkpoint) => cause(&self.checkpoint),
            Some(FirstV1::Intent) => cause(&self.intent),
            Some(FirstV1::Prepared) => self.prepared.failure(),
            Some(FirstV1::Presence) => cause(&self.presence),
            Some(FirstV1::Profile) => cause(&self.profile),
            Some(FirstV1::Predecessor) => cause(&self.predecessor),
            Some(FirstV1::Transaction) => self.transaction_digest.failure()
                .map(|cause| cause as &(dyn Error + 'static)).or_else(|| cause(&self.transaction_binding)),
            Some(FirstV1::Sequence) => cause(&self.sequence),
            Some(FirstV1::SequenceBinding) => cause(&self.sequence_binding),
            Some(FirstV1::Effect) => cause(&self.effect),
            Some(FirstV1::After) => self.after_originals.failure().or_else(|| cause(&self.after)),
            Some(FirstV1::Returned) => cause(&self.returned),
            Some(FirstV1::Reentry) => self.reentry.as_ref().map(|cause| cause as _),
            None => None,
        }.or_else(|| cause(&self.returned))
    }
}


#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use aos_sandbox_controller_domain::Journal;

    use super::*;
    use crate::recovery::BrokerSidecarCustodyV1;
    use crate::tpm_nv_custody::floor::format::FloorEndpointV1;
    use crate::tpm_nv_custody::floor::FloorProfileV1;

    fn empty_sidecar() -> (tempfile::TempDir, BrokerSidecarStoreV1, FloorProfileV1) {
        let directory = tempfile::Builder::new().prefix("aos-floor-read-after-")
            .tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let limits = JournalLimits::default();
        let sidecar_limits = aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::
            sidecar_limits_v1(limits).unwrap();
        let (journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::SIDECAR_NAME_V1,
            sidecar_limits,
            uid,
        ).unwrap();
        drop(journal);
        let custody = BrokerSidecarCustodyV1::open_fixture(directory.path(), limits, uid).unwrap();
        let profile = FloorProfileV1::new(
            FloorEndpointV1::ControllerStorageClient, [1; 16], [2; 16], [3; 32], [4; 32],
        ).unwrap();
        (directory, BrokerSidecarStoreV1::from_broker(custody), profile)
    }

    #[test]
    fn missing_checkpoint_keeps_positive_native_after_and_first_schema_cause() {
        let (_directory, mut store, profile) = empty_sidecar();
        let mut read = BrokerFloorReadOriginalV1::new();

        assert!(read.observe_once(&mut store, profile).is_err());

        assert!(matches!(read.before, Some(Ok(()))));
        assert!(matches!(read.presence, Some(Err(_))));
        assert!(matches!(read.after, Some(Ok(()))));
        assert!(read.completed().is_none());
        let primary = read.failure().unwrap() as *const dyn Error;
        let after = read.after.as_ref().unwrap() as *const Result<(), JournalError>;

        assert!(read.observe_once(&mut store, profile).is_err());

        assert!(std::ptr::eq(primary, read.failure().unwrap() as *const dyn Error));
        assert!(std::ptr::eq(after, read.after.as_ref().unwrap()));
    }

    #[test]
    fn replaced_name_keeps_both_native_refusals_without_replacing_primary() {
        let (directory, mut store, profile) = empty_sidecar();
        let name = aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::SIDECAR_NAME_V1;
        let path = directory.path().join(name);
        fs::rename(&path, directory.path().join("held-original")).unwrap();
        fs::write(&path, []).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut read = BrokerFloorReadOriginalV1::new();

        assert!(read.observe_once(&mut store, profile).is_err());

        assert!(matches!(read.before, Some(Err(_))));
        assert!(matches!(read.after, Some(Err(_))));
        assert!(read.claim.is_none());
        let primary = read.failure().unwrap() as *const dyn Error;
        let after = read.after.as_ref().unwrap() as *const Result<(), JournalError>;

        assert!(read.observe_once(&mut store, profile).is_err());

        assert!(std::ptr::eq(primary, read.failure().unwrap() as *const dyn Error));
        assert!(std::ptr::eq(after, read.after.as_ref().unwrap()));
    }
}
