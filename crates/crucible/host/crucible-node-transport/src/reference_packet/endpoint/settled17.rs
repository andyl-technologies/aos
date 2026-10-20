//! Borrows the actual settled native Endpoint without manufacturing live state.
//!
//! The new17 whole graph defines Connection, Boot, Policy and Control payloads
//! once. This component names those real edges and preserves every independently
//! retained Endpoint field. Unsupported active legacy Capture or transport
//! branches refuse before writing; their original owners remain untouched.

use super::*;
use crate::client::DeadlineStream;
use crate::reference_packet::Native5Policy;
use crate::reference_packet::service::ack_emitter::NativeAckBoot;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::cell::RefCell;

struct CurrentEndpoint17<'a> {
    endpoint: &'a PacketEndpoint<DeadlineStream>,
    boot: &'a Rc<RefCell<NativeAckBoot>>,
    policy: &'a Rc<Native5Policy>,
    rooted: bool,
}

impl PacketEndpoint<DeadlineStream> {
    /// Borrows complete actual Endpoint fields at an eligible selected17 cut.
    ///
    /// # Errors
    /// Refuses another live Boot/Policy/registration, borrowed child, absent
    /// complete service, or an active legacy transport/Capture flight. Refusal
    /// never normalizes that state or releases its original custody.
    pub(in crate::reference_packet) fn borrowed_settled17_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_settled17_endpoint_data()
    }

    /// Borrows the distinct rooted17 view with one enclosing full receiver.
    ///
    /// # Errors
    /// Refuses the same changed real parents or unsupported active slots.
    pub(in crate::reference_packet) fn borrowed_rooted_settled17_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        let mut view = self.authenticate_settled17_endpoint_data()?;
        view.rooted = true;
        Ok(view)
    }

    fn authenticate_settled17_endpoint_data(&self) -> Result<CurrentEndpoint17<'_>, ProviderError> {
        self.ensure_complete_origin()?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        // These are separate legacy transactions, not omissions from the new
        // graph. New17 Capture keeps its current occurrence in the actual Boot
        // reserve, including the literal raw/typed/in-flight state at each cut.
        if self.capture.is_some()
            || self.capture_allocation_attempt.is_some()
            || self.pending_capture.is_some()
            || self.after_confirmation.is_some()
        {
            return Err(refused());
        }
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        if !Rc::ptr_eq(boot, &admission.boot)
            || !self.authority.same_registration(&admission.authority)
            || !std::ptr::addr_eq(Rc::as_ptr(&self.policy), Rc::as_ptr(&admission.policy))
        {
            return Err(refused());
        }
        boot.try_borrow()
            .map_err(|_| borrowed())?
            .authenticate_settled_current_parent_data(boot)?;
        // Check real nested eligibility without consuming a bank or exposing a
        // native token. Each serialization checks those same children again.
        self.complete
            .as_ref()
            .ok_or_else(refused)?
            .borrowed_settled17_data()?;
        self.native.borrowed_restored_settled_history_data()?;
        if let Some(attempt) = &self.fresh_restore_attempt {
            attempt
                .try_borrow()
                .map_err(|_| borrowed())?
                .borrowed_settled17_data(boot, &admission.policy)?;
        }
        if let Some(flight) = &self.restore_commit {
            flight.borrowed_settled17_data(boot, &admission.policy)?;
        }
        Ok(CurrentEndpoint17 {
            endpoint: self,
            boot,
            policy: &admission.policy,
            rooted: false,
        })
    }

    /// Records actual Endpoint children in the one enclosing native17 walk.
    ///
    /// The whole graph records full Boot/Policy/Connection payloads first and
    /// retains both banks until encoding completes. Repeated references keep
    /// their actual Shared rows and aliases; they create no discount or credit.
    ///
    /// # Errors
    /// Refuses a changed parent, unsupported current branch, busy child or any
    /// finite record/alias/backing limit. Partial banks remain owned by caller.
    pub(in crate::reference_packet) fn observe_settled17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let view = self.authenticate_settled17_endpoint_data()?;
        let Self {
            transport: _,
            native: _,
            authority,
            policy: _,
            uploads,
            pins,
            records,
            next_sequence,
            transport_credit,
            held,
            complete,
            capture: _,
            capture_allocation_attempt: _,
            fresh_restore_attempt,
            pending_capture: _,
            after_confirmation: _,
            canonical_ack_boot: _,
            canonical_ack_admission,
            restore_commit,
            restore_protocol_attempted,
            restore_prepare_admission,
        } = self;
        authority.observe_retained_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativePolicy, view.policy.as_ref())?;
        uploads
            .borrowed_owned11_protocol_view(authority)?
            .observe_owned11_metadata(observer)?;
        observer.vector::<OperationContentPin>(pins.capacity())?;
        for pin in pins {
            pin.observe_original_owned11_metadata(uploads, observer)?;
        }
        observer.vector::<ExchangeRecord>(records.capacity())?;
        for record in records {
            record.observe_settled17_metadata_data(observer)?;
        }
        observer.observe(next_sequence)?;
        observer.observe(transport_credit)?;
        observer.observe(held)?;
        if let Some(complete) = complete {
            complete.observe_settled17_metadata_data(observer)?;
        }
        if let Some(attempt) = fresh_restore_attempt {
            observer.shared_original(
                MetadataSharedKind::NativeFreshReportAttempt,
                attempt.as_ref(),
            )?;
            attempt
                .try_borrow()
                .map_err(|_| borrowed())?
                .observe_settled17_metadata(view.boot, view.policy, observer)?;
        }
        observer.shared_original(MetadataSharedKind::NativeBoot, view.boot.as_ref())?;
        if let Some(admission) = canonical_ack_admission {
            admission.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(flight) = restore_commit {
            flight.observe_settled17_metadata_data(view.boot, view.policy, observer)?;
        }
        observer.observe(restore_protocol_attempted)?;
        if let Some(prepare) = restore_prepare_admission {
            prepare.observe_settled_history_metadata_data(observer)?;
        }
        Ok(())
    }
}

struct Pins17<'a>(&'a [OperationContentPin], &'a BlobReceiver);

impl Serialize for Pins17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for pin in self.0 {
            rows.serialize_element(
                &pin.original_protocol_view(self.1)
                    .map_err(serde::ser::Error::custom)?,
            )?;
        }
        rows.end()
    }
}

struct Records17<'a>(&'a [ExchangeRecord]);

impl Serialize for Records17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
        for record in self.0 {
            rows.serialize_element(&record.original_protocol_view())?;
        }
        rows.end()
    }
}

impl Serialize for CurrentEndpoint17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.endpoint
            .authenticate_settled17_endpoint_data()
            .map_err(serde::ser::Error::custom)?;
        let PacketEndpoint {
            transport: _,
            native: _,
            authority,
            policy: _,
            uploads,
            pins,
            records,
            next_sequence,
            transport_credit,
            held,
            complete,
            capture,
            capture_allocation_attempt,
            fresh_restore_attempt,
            pending_capture,
            after_confirmation,
            canonical_ack_boot: _,
            canonical_ack_admission,
            restore_commit,
            restore_protocol_attempted,
            restore_prepare_admission,
        } = self.endpoint;
        let mut fields = serializer.serialize_struct("NativeCurrentEndpoint17", 24)?;
        fields.serialize_field(
            "schema",
            if self.rooted {
                "source-private.native-rooted-endpoint/17"
            } else {
                "source-private.native-current-endpoint/17"
            },
        )?;
        fields.serialize_field("transport", &("connected", "current-native-connection"))?;
        fields.serialize_field("native_role", "current-native-control")?;
        fields.serialize_field("authority", &authority.borrowed_settled_history_data())?;
        fields.serialize_field("policy_role", "native-policy")?;
        if self.rooted {
            fields.serialize_field("uploads", "native-blob-receiver")?;
        } else {
            fields.serialize_field(
                "uploads",
                &uploads
                    .borrowed_owned11_protocol_view(authority)
                    .map_err(serde::ser::Error::custom)?,
            )?;
        }
        fields.serialize_field("pins", &Pins17(pins, uploads))?;
        fields.serialize_field("pins_capacity", &pins.capacity())?;
        fields.serialize_field("records", &Records17(records))?;
        fields.serialize_field("records_capacity", &records.capacity())?;
        fields.serialize_field("next_sequence", next_sequence)?;
        fields.serialize_field("transport_credit", transport_credit)?;
        fields.serialize_field("held", held)?;
        fields.serialize_field(
            "complete",
            &complete
                .as_ref()
                .map(|owner| owner.borrowed_settled17_data())
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        // Authentication proved these actual slots absent. Recording explicit
        // nulls preserves that fact; no Some branch is rewritten or discarded.
        fields.serialize_field("capture", &capture.as_ref().map(|_| ()))?;
        fields.serialize_field(
            "capture_allocation_attempt",
            &capture_allocation_attempt.as_ref().map(|_| ()),
        )?;
        if let Some(attempt) = fresh_restore_attempt {
            let owner = attempt.try_borrow().map_err(serde::ser::Error::custom)?;
            fields.serialize_field(
                "fresh_restore_attempt",
                &Some(
                    owner
                        .borrowed_settled17_data(self.boot, self.policy)
                        .map_err(serde::ser::Error::custom)?,
                ),
            )?;
        } else {
            fields.serialize_field("fresh_restore_attempt", &Option::<()>::None)?;
        }
        fields.serialize_field("pending_capture", &pending_capture.as_ref().map(|_| ()))?;
        fields.serialize_field(
            "after_confirmation",
            &after_confirmation.as_ref().map(|_| ()),
        )?;
        fields.serialize_field("canonical_ack_boot_role", "native-boot")?;
        fields.serialize_field(
            "canonical_ack_admission",
            &canonical_ack_admission
                .as_ref()
                .map(|token| token.borrowed_settled_history_data())
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "restore_commit",
            &restore_commit
                .as_ref()
                .map(|flight| flight.borrowed_settled17_data(self.boot, self.policy))
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("restore_protocol_attempted", restore_protocol_attempted)?;
        fields.serialize_field(
            "restore_prepare_admission",
            &restore_prepare_admission
                .as_ref()
                .map(|token| token.borrowed_settled_history_data())
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.end()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native17 actual settled Endpoint differs")
}

fn borrowed() -> ProviderError {
    ProviderError::Conflict("native17 settled Endpoint child borrowed")
}

mod reader;
pub(crate) use reader::{
    CurrentEndpoint17Data, CurrentEndpoint17GroupIds, read_endpoint17_data,
    read_endpoint17_fields_data, read_rooted_endpoint17_fields_data,
};

mod logical17;
pub(crate) use logical17::{
    BorrowedCommitFlight17Lineage, BorrowedHello17Lineage, BorrowedNativeEndpoint17LogicalData,
    BorrowedSpentFresh17, borrow_native17_endpoint_logical_data,
};

pub(crate) use logical17::{BorrowedTerminal17, BorrowedTerminal17Location};

pub(crate) use logical17::authenticate_native17_retained_terminal_data;
