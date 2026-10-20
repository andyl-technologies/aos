//! Borrows the complete current Prepare attempt and independently retained banks.
//!
//! This component defines the actual shared custody below Prepare and retains
//! every independent typed/raw/partial field. It does not create a Prepare,
//! import map, token or current registrar.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct PrepareHistory<'a> {
    attempt: &'a NativeCompleteRestorePrepareAttempt,
    policy: &'a Rc<crate::reference_packet::Native5Policy>,
    boot: &'a Rc<RefCell<NativeAckBoot>>,
}

impl NativeCompleteRestorePrepareAttempt {
    pub(in crate::reference_packet::service) fn borrowed_restored_settled_history_data<'a>(
        &'a self,
        policy: &'a Rc<crate::reference_packet::Native5Policy>,
        boot: &'a Rc<RefCell<NativeAckBoot>>,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.ensure_origin()?;
        Ok(PrepareHistory {
            attempt: self,
            policy,
            boot,
        })
    }
}

impl Serialize for PrepareHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.attempt
            .ensure_origin()
            .map_err(serde::ser::Error::custom)?;
        let NativeCompleteRestorePrepareAttempt {
            creator,
            thread: _,
            original,
            service_quote,
            control_quote,
            realize,
            receipt_started,
            input_segment_issued,
            input_segment_started,
            receipt_result,
            receipt_body,
            request,
            proof,
            context,
            context_body,
            kernel,
            policy,
            transfer_token,
            custody,
            reactive,
            verified,
        } = self.attempt;
        let mut fields = serializer.serialize_struct("NativeCurrentPrepare17", 23)?;
        fields.serialize_field("schema", "source-private.native-current-restore-prepare/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field("original", original)?;
        if let Some(quote) = service_quote {
            fields.serialize_field(
                "service_quote",
                &Some(
                    quote
                        .borrowed_settled_history_data(self.policy, self.boot)
                        .map_err(serde::ser::Error::custom)?,
                ),
            )?;
        } else {
            fields.serialize_field("service_quote", &Option::<()>::None)?;
        }
        if let Some(quote) = control_quote {
            fields.serialize_field(
                "control_quote",
                &Some(
                    quote
                        .borrowed_settled_history_data(self.policy)
                        .map_err(serde::ser::Error::custom)?,
                ),
            )?;
        } else {
            fields.serialize_field("control_quote", &Option::<()>::None)?;
        }
        fields.serialize_field("realize", realize)?;
        fields.serialize_field("receipt_started", receipt_started)?;
        fields.serialize_field("input_segment_issued", input_segment_issued)?;
        fields.serialize_field("input_segment_started", input_segment_started)?;
        fields.serialize_field("receipt_result", receipt_result)?;
        fields.serialize_field(
            "receipt_body",
            &(
                BorrowedCompactBytes::new(receipt_body),
                receipt_body.capacity(),
            ),
        )?;
        fields.serialize_field("request", request)?;
        fields.serialize_field("proof", proof)?;
        fields.serialize_field("context", context)?;
        fields.serialize_field(
            "context_body",
            &(
                BorrowedCompactBytes::new(context_body),
                context_body.capacity(),
            ),
        )?;
        fields.serialize_field("kernel", kernel)?;
        fields.serialize_field("policy", policy)?;
        fields.serialize_field("transfer_token", transfer_token)?;
        if let Some(custody) = custody {
            let custody = custody.try_borrow().map_err(serde::ser::Error::custom)?;
            let history = custody
                .borrowed_current17_data()
                .map_err(serde::ser::Error::custom)?;
            fields.serialize_field("custody", &Some(history))?;
        } else {
            fields.serialize_field("custody", &Option::<()>::None)?;
        }
        fields.serialize_field("reactive", reactive)?;
        fields.serialize_field("verified", verified)?;
        // The separate payload lender has the actual same Rc checked by the
        // outer Boot/Connection graph; no copied value establishes that edge.
        fields.serialize_field("owner_role", "native-complete-restore-prepare")?;
        fields.end()
    }
}

impl NativeCompleteRestorePrepareAttempt {
    /// Appends every actual retained field without clearing the aggregate banks.
    ///
    /// # Errors
    /// Refuses a foreign owner, borrowed custody, exhausted banks or layout overflow.
    pub(in crate::reference_packet::service) fn observe_current_settled17_metadata_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        use crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17;
        self.ensure_origin()?;
        let Self {
            creator,
            thread: _,
            original,
            service_quote,
            control_quote,
            realize,
            receipt_started,
            input_segment_issued,
            input_segment_started,
            receipt_result,
            receipt_body,
            request,
            proof,
            context,
            context_body,
            kernel,
            policy,
            transfer_token,
            custody,
            reactive,
            verified,
        } = self;
        observer.observe(creator)?;
        observer.observe(original)?;
        if let Some(value) = service_quote {
            value.observe_settled_history_metadata_data(boot, observer)?;
        }
        if let Some(value) = control_quote {
            value.observe_settled_history_metadata_data(observer)?;
        }
        observer.observe(realize)?;
        observer.observe(receipt_started)?;
        observer.observe(input_segment_issued)?;
        observer.observe(input_segment_started)?;
        if let Some(value) = receipt_result {
            value.observe_current(observer)?;
        }
        observer.observe(receipt_body)?;
        if let Some(value) = request {
            value.observe_current(observer)?;
        }
        if let Some(value) = proof {
            value.observe_current(observer)?;
        }
        if let Some(value) = context {
            value.observe_current(observer)?;
        }
        observer.observe(context_body)?;
        observer.observe(kernel)?;
        observer.observe(policy)?;
        observer.observe(transfer_token)?;
        if let Some(custody) = custody {
            observer.shared_original(
                crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoreInputCustody,
                custody.as_ref(),
            )?;
            custody
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("current17 custody borrowed"))?
                .observe_current17_metadata_data(observer)?;
        }
        observer.observe(reactive)?;
        observer.observe(verified)
    }
}
