//! Retains one actual independently admitted Capture17 upload transaction.
//!
//! The private receive scope supplies Source/once/same-Boot/index/Rc authority;
//! this owner preserves immutable quote, complete row, real Blob partials and
//! actual publication history. Historical DATA cannot construct this owner.

use crate::{
    ProviderError,
    blob::{
        BlobReceiver, NativeCapture17UploadAttempt, NativeCapture17UploadInput,
        NativeCapture17UploadStorageData, VerifiedTransfer,
    },
    reference_packet::service::{
        ack_emitter::OriginalNativeCapture17Read, native_startup::PacketNativeStartupAllocationRow,
    },
    retained_metadata::MetadataObserver,
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Map, Value};
use std::mem::size_of;

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Installed,
    EffectFailed,
    ReplyFailed,
    ReplyComplete,
    Publishing,
    Published,
    Failed,
}

/// Preserves one actual quotation and every initialized upload/publication field.
pub(crate) struct NativeCapture17UploadActionAttempt {
    storage: NativeCapture17UploadStorageData,
    effect: Option<NativeCapture17UploadAttempt>,
    admitted: PacketNativeStartupAllocationRow,
    publication_record: Option<usize>,
    phase: Phase,
}

fn refused() -> ProviderError {
    ProviderError::Correlation("Capture17 upload transaction phase or row differs")
}

impl NativeCapture17UploadActionAttempt {
    /// Installs immutable DATA before any fallible row check or actual effect.
    ///
    /// The genuine scope independently debits its full Blob/transport/parent
    /// row first. This installation itself issues no native permission. A short
    /// row stays retained in Failed state rather than disappearing on refusal.
    ///
    /// # Errors
    /// Refuses an existing once destination, invalid complete sum or any axis
    /// below the defining Blob demand, preserving the newly installed owner.
    pub(crate) fn install_into_data(
        storage: NativeCapture17UploadStorageData,
        admitted: PacketNativeStartupAllocationRow,
        destination: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if destination.is_some() {
            return Err(refused());
        }
        *destination = Some(Self {
            storage,
            effect: None,
            admitted,
            publication_record: None,
            phase: Phase::Failed,
        });
        let actual = destination.as_mut().ok_or_else(refused)?;
        actual.admitted.requested_peak_data()?;
        let required = actual.storage.row_data();
        for (have, need) in [
            (
                actual.admitted.retained_requested_bytes,
                required.retained_requested_bytes,
            ),
            (
                actual.admitted.maximum_simultaneous_transient_bytes,
                required.maximum_simultaneous_transient_bytes,
            ),
            (
                actual.admitted.declared_counter_scratch_bytes,
                required.declared_counter_scratch_bytes,
            ),
        ] {
            if have < need {
                return Err(refused());
            }
        }
        actual.phase = Phase::Installed;
        Ok(())
    }

    /// Borrows the real immutable quote for correspondence without issuing a grant.
    pub(crate) fn storage_data(&self) -> &NativeCapture17UploadStorageData {
        &self.storage
    }

    /// Returns the full independently admitted row as retained DATA.
    pub(crate) fn admitted_row_data(&self) -> PacketNativeStartupAllocationRow {
        self.admitted
    }

    /// Executes and encodes through the genuine scope under disjoint field loans.
    ///
    /// The scope lends its private spent action only after Source/once/native
    /// debit and exact quotation checks. The real Blob result/reply destination
    /// is the same retained Option throughout. Every fallible phase is sticky;
    /// a scope after-fence failure closes the owner even if a reply was encoded.
    ///
    /// # Errors
    /// Refuses a reused/failed transaction or conflicting native custody, and
    /// preserves every actual primitive, poststate or reply failure/partial.
    pub(crate) fn execute_and_produce_reply_data(
        &mut self,
        receiver: &mut BlobReceiver,
        scope: &OriginalNativeCapture17Read,
        input: NativeCapture17UploadInput<'_>,
    ) -> Result<(), ProviderError> {
        if self.phase != Phase::Installed
            || self.effect.is_some()
            || self.publication_record.is_some()
        {
            return Err(refused());
        }
        let Self {
            storage,
            effect,
            admitted: _,
            publication_record: _,
            phase,
        } = self;
        *phase = Phase::Failed;
        let result = scope.with_spent_upload_action17_data(storage, |token| {
            *phase = Phase::EffectFailed;
            receiver.execute_capture17_upload_into_data(token, storage, input, effect)?;
            *phase = Phase::ReplyFailed;
            receiver.produce_capture17_upload_reply_into_data(
                token,
                storage,
                input,
                effect.as_mut().ok_or_else(refused)?,
            )?;
            *phase = Phase::ReplyComplete;
            Ok(())
        });
        if result.is_err() {
            *phase = Phase::Failed;
        }
        result
    }

    fn authenticate_reply_phase_data(&self) -> Result<(), ProviderError> {
        if !matches!(
            self.phase,
            Phase::ReplyComplete | Phase::Publishing | Phase::Published
        ) {
            return Err(refused());
        }
        self.effect.as_ref().ok_or_else(refused)?.reply_data()?;
        Ok(())
    }

    /// Borrows only an actual normal reply after the scope's successful fences.
    ///
    /// # Errors
    /// Refuses failed/partial transactions and absent or incomplete Blob replies.
    pub(crate) fn reply_data(&self) -> Result<&Map<String, Value>, ProviderError> {
        self.authenticate_reply_phase_data()?;
        self.effect.as_ref().ok_or_else(refused)?.reply_data()
    }

    /// Borrows real verified possession after normal reply completion.
    ///
    /// This is inert possession DATA. Any Control installation remains its own
    /// independently admitted Source/native phase; it grants no schema access.
    ///
    /// # Errors
    /// Refuses a failed/partial transaction or absent real Blob result.
    pub(crate) fn verified_data(&self) -> Result<Option<&VerifiedTransfer>, ProviderError> {
        self.authenticate_reply_phase_data()?;
        Ok(self.effect.as_ref().ok_or_else(refused)?.verified_data())
    }

    /// Marks the single real publication attempt before parent transport work.
    ///
    /// # Errors
    /// Refuses a reused publication, failed transaction or incomplete reply.
    pub(crate) fn begin_publication_data(&mut self) -> Result<(), ProviderError> {
        if self.phase != Phase::ReplyComplete || self.publication_record.is_some() {
            return Err(refused());
        }
        self.authenticate_reply_phase_data()?;
        self.phase = Phase::Publishing;
        Ok(())
    }

    /// Saves the occurrence only after the defining scope's real publication proof.
    ///
    /// The private native scope is the only publication caller. It authenticates
    /// actual same-Boot/index/Rc transport records and all required completion
    /// before this bookkeeping method. A numeric record alone grants no rights.
    ///
    /// # Errors
    /// Refuses an absent/reused publication or incomplete real reply.
    pub(crate) fn complete_publication_data(&mut self, record: usize) -> Result<(), ProviderError> {
        if self.phase != Phase::Publishing || self.publication_record.is_some() {
            return Err(refused());
        }
        self.authenticate_reply_phase_data()?;
        self.publication_record = Some(record);
        self.phase = Phase::Published;
        Ok(())
    }

    /// Borrows the actual completed occurrence as DATA, without currentness rights.
    ///
    /// # Errors
    /// Refuses failed, unstarted or incomplete publications.
    pub(crate) fn publication_record_data(&self) -> Result<usize, ProviderError> {
        if self.phase != Phase::Published {
            return Err(refused());
        }
        self.authenticate_reply_phase_data()?;
        self.publication_record.ok_or_else(refused)
    }

    /// Closes the transaction while retaining all initialized proof/custody fields.
    pub(crate) fn interrupt_data(&mut self) {
        self.phase = Phase::Failed;
    }

    /// Observes actual quote/result backing and the real shared alias edges.
    ///
    /// # Errors
    /// Refuses observer overflow or exhausted metadata/alias banks.
    pub(crate) fn observe_current17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            storage,
            effect,
            admitted,
            publication_record,
            phase: _,
        } = self;
        storage.observe_current17_metadata_data(observer)?;
        if let Some(effect) = effect {
            effect.observe_current17_metadata_data(observer)?;
        }
        observer.observe(&admitted.retained_requested_bytes)?;
        observer.observe(&admitted.maximum_simultaneous_transient_bytes)?;
        observer.observe(&admitted.declared_counter_scratch_bytes)?;
        observer.observe(publication_record)
    }
}

struct Effect<'a>(&'a NativeCapture17UploadAttempt);

impl Serialize for Effect<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .borrowed_current17_fields_data()
            .serialize(serializer)
    }
}

impl Serialize for NativeCapture17UploadActionAttempt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            storage,
            effect,
            admitted,
            publication_record,
            phase,
        } = self;
        let mut fields = serializer.serialize_struct("NativeCapture17UploadAction", 6)?;
        fields.serialize_field("schema", "source-private.native-capture-upload-action/17")?;
        fields.serialize_field("storage", &storage.borrowed_current17_fields_data())?;
        fields.serialize_field("effect", &effect.as_ref().map(Effect))?;
        fields.serialize_field("admitted", admitted)?;
        fields.serialize_field("publication_record", publication_record)?;
        fields.serialize_field("phase", phase)?;
        fields.end()
    }
}

/// Names the actual transaction, disjoint loans, serializers and row-check views.
pub(crate) fn native_capture17_upload_action_counter_scratch_data() -> usize {
    size_of::<NativeCapture17UploadActionAttempt>()
        + size_of::<Option<NativeCapture17UploadActionAttempt>>()
        + size_of::<&OriginalNativeCapture17Read>()
        + size_of::<&mut BlobReceiver>()
        + size_of::<NativeCapture17UploadInput<'static>>()
        + size_of::<(
            &NativeCapture17UploadStorageData,
            &mut Option<NativeCapture17UploadAttempt>,
            &mut Phase,
        )>()
        + size_of::<[(crucible_node_contract::U64, crucible_node_contract::U64); 3]>()
        + size_of::<
            std::array::IntoIter<(crucible_node_contract::U64, crucible_node_contract::U64), 3>,
        >()
        + size_of::<Effect<'static>>()
        + size_of::<Option<Effect<'static>>>()
        + size_of::<&mut MetadataObserver<'static>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<Option<&VerifiedTransfer>, ProviderError>>()
        + size_of::<Result<&Map<String, Value>, ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob::{BlobLimits, BlobQuarantine, BlobSupervisor, NativeCapture17UploadKey},
        envelope::RequestOrigin,
        retained_metadata::{aliases::MetadataAliasBank, records::MetadataRecordBank},
    };
    use crucible_node_contract::{Id, U64, canonical};
    use std::{cell::RefCell, rc::Rc};

    #[derive(Default)]
    struct Supervisor(RefCell<Vec<BlobQuarantine>>);

    impl BlobSupervisor for Supervisor {
        fn quarantine(&self, custody: BlobQuarantine) {
            self.0.borrow_mut().push(custody);
        }
    }

    fn quotation() -> Result<NativeCapture17UploadStorageData, ProviderError> {
        let session = Id::new("session")?;
        let incarnation = Id::new("incarnation")?;
        let transfer = Id::new("transfer")?;
        let receiver = BlobReceiver::new(
            session.clone(),
            incarnation.clone(),
            BlobLimits {
                reserved_bytes: 65536,
                content_bytes: 65536,
                chunk_bytes: 64,
                transfers_per_origin: 16,
                tombstones_per_origin: 16,
                chunks_per_transfer: 64,
                operation_pins: 16,
            },
            Rc::new(Supervisor::default()),
        )?;
        receiver.quote_capture17_upload_storage_data(
            NativeCapture17UploadInput::Begin {
                key: NativeCapture17UploadKey {
                    origin: RequestOrigin::Controller,
                    session: &session,
                    incarnation: &incarnation,
                    transfer: &transfer,
                },
                content: &canonical::content_ref(b"actual", "application/octet-stream")?,
            },
            usize::MAX,
        )
    }

    #[test]
    fn inert_install_preserves_actual_quote_row_once_and_real_shared_metadata()
    -> Result<(), ProviderError> {
        let storage = quotation()?;
        let original = storage.duplicate_correspondence_data();
        let admitted = storage.row_data();
        let mut destination = None;

        NativeCapture17UploadActionAttempt::install_into_data(storage, admitted, &mut destination)?;

        let actual = destination.as_ref().ok_or_else(refused)?;
        actual
            .storage_data()
            .authenticate_same_quotation_data(&original)?;
        assert_eq!(actual.admitted_row_data(), admitted);
        assert!(actual.phase == Phase::Installed);
        assert!(actual.effect.is_none());
        assert!(actual.publication_record.is_none());
        assert!(actual.reply_data().is_err());
        assert!(actual.verified_data().is_err());
        assert!(actual.publication_record_data().is_err());
        let value =
            serde_json::to_value(actual).map_err(crucible_node_contract::ContractError::from)?;
        assert_eq!(value.as_object().ok_or_else(refused)?.len(), 6);
        assert!(value.get("effect").ok_or_else(refused)?.is_null());
        assert_eq!(
            value.get("phase").and_then(Value::as_str),
            Some("installed")
        );
        let mut rows = MetadataRecordBank::reserve(16)?;
        let mut aliases = MetadataAliasBank::reserve(8)?;
        let mut observer = MetadataObserver::recording_with_aliases(&mut rows, &mut aliases);
        actual.observe_current17_metadata_data(&mut observer)?;
        assert_eq!(observer.finish().shared_backing_views, 2);
        assert_eq!(aliases.retained_rows(), 2);

        assert!(
            NativeCapture17UploadActionAttempt::install_into_data(
                original,
                admitted,
                &mut destination,
            )
            .is_err()
        );
        assert!(destination.as_ref().ok_or_else(refused)?.phase == Phase::Installed);
        Ok(())
    }

    #[test]
    fn each_short_axis_retains_sticky_failed_owner_and_original_quote() -> Result<(), ProviderError>
    {
        for axis in 0..3 {
            let storage = quotation()?;
            let original = storage.duplicate_correspondence_data();
            let mut admitted = storage.row_data();
            let field = match axis {
                0 => &mut admitted.retained_requested_bytes,
                1 => &mut admitted.maximum_simultaneous_transient_bytes,
                _ => &mut admitted.declared_counter_scratch_bytes,
            };
            assert!(field.get() > 1);
            *field = U64::new(field.get() - 1);
            let mut destination = None;

            assert!(
                NativeCapture17UploadActionAttempt::install_into_data(
                    storage,
                    admitted,
                    &mut destination,
                )
                .is_err()
            );

            let actual = destination.as_ref().ok_or_else(refused)?;
            actual
                .storage_data()
                .authenticate_same_quotation_data(&original)?;
            assert!(actual.phase == Phase::Failed);
            assert_eq!(actual.admitted_row_data(), admitted);
            assert!(actual.effect.is_none());
            assert!(actual.reply_data().is_err());
            assert!(actual.publication_record_data().is_err());
            assert!(
                NativeCapture17UploadActionAttempt::install_into_data(
                    original,
                    admitted,
                    &mut destination,
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn interruption_keeps_once_owner_and_refuses_publication_without_real_reply()
    -> Result<(), ProviderError> {
        let storage = quotation()?;
        let admitted = storage.row_data();
        let mut destination = None;
        NativeCapture17UploadActionAttempt::install_into_data(storage, admitted, &mut destination)?;
        let actual = destination.as_mut().ok_or_else(refused)?;
        assert!(actual.begin_publication_data().is_err());
        assert!(actual.complete_publication_data(3).is_err());

        actual.interrupt_data();

        assert!(actual.phase == Phase::Failed);
        assert_eq!(actual.admitted_row_data(), admitted);
        assert!(actual.effect.is_none());
        assert!(actual.reply_data().is_err());
        assert!(actual.verified_data().is_err());
        assert!(actual.begin_publication_data().is_err());
        assert!(actual.complete_publication_data(3).is_err());
        assert!(actual.publication_record_data().is_err());
        Ok(())
    }
}

#[cfg(test)]
#[path = "upload17/reader_tests.rs"]
mod reader_tests;

#[path = "upload17/published.rs"]
mod published;
