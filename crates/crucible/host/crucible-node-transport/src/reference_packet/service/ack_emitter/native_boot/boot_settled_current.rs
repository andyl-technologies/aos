//! Borrows the complete current native boot graph under its genuine owner.
//!
//! Process-local identities are checked against the actual enclosing Boot and
//! emitted as closed historical edges. No decoded role or serialized private
//! material constructs an admission, current connection, Capture permit or key
//! issuer. Current Prepare, Commit, failed attempts and spent reserves remain
//! live; writing this view neither retires nor normalizes them.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use crate::reference_packet::service::native_startup::{
    NativeCaptureOutputCut17, NativeRestoredSettledActionCurrent17,
};
use crate::retained_metadata::{aliases::MetadataAliasBank, records::MetadataRecordBank};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

struct CurrentBootHistory17<'a> {
    owner: &'a NativeAckBoot,
    boot: &'a Rc<RefCell<NativeAckBoot>>,
    action_cut: Option<(
        &'a NativeRestoredSettledActionCurrent17<'a>,
        &'a NativeCaptureOutputCut17<'a>,
    )>,
}

impl NativeAckBoot {
    /// Borrows the actual complete current boot and independently recorded stages.
    ///
    /// The caller admits and retains both recording banks before this loan. The
    /// returned view borrows them until serialization ends. The enclosing graph
    /// still authenticates its real Connection, Policy, Hold and mapping edges.
    ///
    /// # Errors
    /// Refuses another Boot, foreign process/thread, absent genuine selected17
    /// reserve, borrowed child owners or insufficient admitted recording banks.
    pub(in crate::reference_packet::service) fn borrowed_restored_settled_current_data<'a>(
        &'a self,
        boot: &'a Rc<RefCell<Self>>,
        records: &'a mut MetadataRecordBank,
        aliases: &'a mut MetadataAliasBank,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.authenticate_settled_current_parent_data(boot)?;
        let _ = (records, aliases);
        Ok(CurrentBootHistory17 {
            owner: self,
            boot,
            action_cut: None,
        })
    }

    pub(in crate::reference_packet) fn authenticate_settled_current_parent_data(
        &self,
        boot: &Rc<RefCell<Self>>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if !std::ptr::eq(self as *const Self, boot.as_ptr().cast_const()) {
            return Err(ProviderError::Correlation("current17 actual Boot differs"));
        }
        self.restored_settled
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "current17 private reserve absent",
            ))?
            .borrowed_settled_history_data(boot)?;
        Ok(())
    }
}

struct ByteBank<'a>(&'a Vec<u8>);

impl Serialize for ByteBank<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.0.capacity(), BorrowedCompactBytes::new(self.0)).serialize(serializer)
    }
}

struct Banks<'a>(&'a [Vec<u8>; 5]);

impl Serialize for Banks<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut banks = serializer.serialize_seq(Some(5))?;
        for bank in self.0 {
            banks.serialize_element(&ByteBank(bank))?;
        }
        banks.end()
    }
}

struct BootDataHistory<'a>(&'a BootData);

impl Serialize for BootDataHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let BootData {
            schema,
            private_key,
            birth_id,
            source_birth,
            expected_host_registration,
            private_launch,
            host_executable,
        } = self.0;
        let mut fields = serializer.serialize_struct("NativeCurrentBootData17", 7)?;
        fields.serialize_field("schema", schema)?;
        fields.serialize_field("private_key", private_key)?;
        fields.serialize_field("birth_id", birth_id)?;
        fields.serialize_field("source_birth", source_birth)?;
        fields.serialize_field("expected_host_registration", expected_host_registration)?;
        fields.serialize_field("private_launch", private_launch)?;
        fields.serialize_field("host_executable", host_executable)?;
        fields.end()
    }
}

struct StartupHistory<'a> {
    owner: &'a native_startup::OriginalNativeStartupBoot,
    first: &'a Option<Rc<RefCell<NativeRestorationObservationAttempt>>>,
}

impl Serialize for StartupHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let native_startup::OriginalNativeStartupBoot {
            restored_suffix,
            allocation,
            source_digest,
            launch_digest,
            birth_id,
            native_birth_issued,
            baseline_complete,
            prepare_startup_issued,
        } = self.owner;
        let mut fields = serializer.serialize_struct("NativeCurrentStartup17", 8)?;
        fields.serialize_field("allocation", allocation)?;
        fields.serialize_field("source_digest", source_digest)?;
        fields.serialize_field("launch_digest", launch_digest)?;
        fields.serialize_field("birth_id", birth_id)?;
        fields.serialize_field("native_birth_issued", native_birth_issued)?;
        fields.serialize_field("baseline_complete", baseline_complete)?;
        fields.serialize_field("prepare_startup_issued", prepare_startup_issued)?;
        if let Some(suffix) = restored_suffix {
            let history = suffix
                .borrowed_current_settled17_data(self.first)
                .map_err(serde::ser::Error::custom)?;
            fields.serialize_field("restored_suffix", &Some(history))?;
        } else {
            fields.serialize_field("restored_suffix", &Option::<()>::None)?;
        }
        fields.end()
    }
}

impl Serialize for CurrentBootHistory17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.owner
            .authenticate_settled_current_parent_data(self.boot)
            .map_err(serde::ser::Error::custom)?;
        let NativeAckBoot {
            creator,
            thread: _,
            data,
            launch_body,
            policy,
            source_body,
            host_body,
            normalized,
            banks,
            context,
            proof,
            original,
            ready,
            attempted,
            verified,
            restoration,
            transfer,
            startup,
            restoration_activation: _,
            restoration_uploads: _,
            restoration_observation,
            restored_settled,
        } = self.owner;
        let policy = policy
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("current17 Policy absent"))?;
        let mut fields = serializer.serialize_struct("NativeCurrentBoot17", 21)?;
        fields.serialize_field("schema", "source-private.native-current-boot/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field("data", &BootDataHistory(data))?;
        fields.serialize_field("launch", &ByteBank(launch_body))?;
        fields.serialize_field("policy_role", "native-policy")?;
        fields.serialize_field("source", &ByteBank(source_body))?;
        fields.serialize_field("host", &ByteBank(host_body))?;
        fields.serialize_field("normalized", normalized)?;
        fields.serialize_field("banks", &Banks(banks))?;
        fields.serialize_field("context", context)?;
        fields.serialize_field("proof", proof)?;
        fields.serialize_field("original", original)?;
        fields.serialize_field("ready", ready)?;
        fields.serialize_field("attempted", attempted)?;
        fields.serialize_field("verified", verified)?;
        if let Some(commit) = restoration {
            let commit = commit.try_borrow().map_err(serde::ser::Error::custom)?;
            let history = commit
                .borrowed_restored_settled_history_data()
                .map_err(serde::ser::Error::custom)?;
            fields.serialize_field("commit", &Some(history))?;
        } else {
            fields.serialize_field("commit", &Option::<()>::None)?;
        }
        if let Some(prepare) = transfer {
            let prepare = prepare.try_borrow().map_err(serde::ser::Error::custom)?;
            let history = prepare
                .borrowed_restored_settled_history_data(policy, self.boot)
                .map_err(serde::ser::Error::custom)?;
            fields.serialize_field("prepare", &Some(history))?;
        } else {
            fields.serialize_field("prepare", &Option::<()>::None)?;
        }
        fields.serialize_field(
            "startup",
            &startup.as_ref().map(|owner| StartupHistory {
                owner,
                first: restoration_observation,
            }),
        )?;
        let stages = self
            .owner
            .borrowed_current_restoration_stages17_data()
            .map_err(serde::ser::Error::custom)?;
        fields.serialize_field("restoration_stages", &stages)?;
        let reserve = restored_settled
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("current17 reserve absent"))?;
        if let Some((view, cut)) = self.action_cut {
            fields.serialize_field(
                "settled_reserve",
                &reserve
                    .borrowed_settled_history_with_action_cut17_data(self.boot, view, cut)
                    .map_err(serde::ser::Error::custom)?,
            )?;
        } else {
            fields.serialize_field(
                "settled_reserve",
                &reserve
                    .borrowed_settled_history_data(self.boot)
                    .map_err(serde::ser::Error::custom)?,
            )?;
        }
        fields.end()
    }
}

impl NativeAckBoot {
    /// Verifies this actual spent Capture/BlobBegin using this Boot's birth key.
    ///
    /// The common receive consumer already holds the real installed admission
    /// and exact incoming literal. This narrowly checks the same retained slot
    /// and Source proof; it cannot debit an action, publish a terminal, disarm
    /// receive custody or manufacture a Capture from a serialized key/row.
    ///
    /// # Errors
    /// Refuses another Boot/index/shared slot, unsealed reserve, wrong family or
    /// method, repeated context, invalid assigned scope, short key or failed MAC.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_restored_settled_capture_source_data(
        &self,
        boot: &Rc<RefCell<Self>>,
        index: usize,
        attempt: &Rc<RefCell<crate::reference_packet::service::native_startup::NativeRestoredSettledActionAttempt>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_current_parent_data(boot)?;
        let state = self
            .restored_settled
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "current17 private reserve absent",
            ))?;
        state.authenticate_retained_attempt_data(boot, index, attempt)?;
        let maximum_frame = state.sealed_storage_data(boot)?.maximum_frame_bytes_data();
        let key: &[u8; 32] = self
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| ProviderError::Correlation("current17 original birth key differs"))?;
        let mut owner = attempt
            .try_borrow_mut()
            .map_err(|_| ProviderError::Conflict("current17 Capture child borrowed"))?;
        let capture = owner.capture_data_mut()?;
        match capture.original_data()?.method {
            crate::envelope::Method::Begin => {
                capture.authenticate_capture_source_data(key, maximum_frame)
            }
            crate::envelope::Method::BlobBegin => {
                capture.authenticate_upload_source_data(key, maximum_frame)
            }
            _ => Err(ProviderError::Correlation(
                "current17 Source proof method differs",
            )),
        }
    }
}

impl NativeAckBoot {
    /// Names this actual native Boot shared payload, separate from inert DTOs.
    pub(crate) const fn current_boot_shared_layout17_data() -> (usize, usize) {
        (
            std::mem::size_of::<RefCell<Self>>(),
            std::mem::align_of::<RefCell<Self>>(),
        )
    }

    /// Names the actual current Commit shared payload without exposing its type.
    pub(crate) const fn current_commit_shared_layout17_data() -> (usize, usize) {
        (
            std::mem::size_of::<RefCell<restore::NativeCompleteRestoreAttempt>>(),
            std::mem::align_of::<RefCell<restore::NativeCompleteRestoreAttempt>>(),
        )
    }

    /// Names the actual current Prepare shared payload without exposing its type.
    pub(crate) const fn current_prepare_shared_layout17_data() -> (usize, usize) {
        (
            std::mem::size_of::<RefCell<restore_prepare::NativeCompleteRestorePrepareAttempt>>(),
            std::mem::align_of::<RefCell<restore_prepare::NativeCompleteRestorePrepareAttempt>>(),
        )
    }
}

impl NativeAckBoot {
    /// Borrows the full current graph beneath its actual same Boot allocation.
    ///
    /// # Errors
    /// Refuses a foreign Boot or absent genuine selected17 private reserve.
    pub(in crate::reference_packet) fn borrowed_current17_data<'a>(
        &'a self,
        boot: &'a Rc<RefCell<Self>>,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.authenticate_settled_current_parent_data(boot)?;
        Ok(CurrentBootHistory17 {
            owner: self,
            boot,
            action_cut: None,
        })
    }

    /// Appends this real full Boot root and every child in one aggregate pass.
    ///
    /// Stage definitions precede suffix weak references. Complete Commit and
    /// Prepare roots precede later Connection token references. This consumes
    /// caller-owned banks without ever clearing or replacing their cursors.
    ///
    /// # Errors
    /// Refuses foreign or borrowed owners, mismatched real roots, or exhausted banks.
    pub(crate) fn observe_current17_metadata_data(
        boot: &Rc<RefCell<Self>>,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        use crate::retained_metadata::aliases::MetadataSharedKind;
        observer.shared_original(MetadataSharedKind::NativeBoot, boot.as_ref())?;
        let owner = boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("current17 Boot borrowed"))?;
        owner.observe_current17_payload_metadata_data(boot, None, observer)
    }

    fn observe_current17_payload_metadata_data(
        &self,
        boot: &Rc<RefCell<Self>>,
        action_cut: Option<(
            &NativeRestoredSettledActionCurrent17<'_>,
            &NativeCaptureOutputCut17<'_>,
        )>,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        use crate::protocol_snapshot::restored_settled17::current_contracts::CurrentContract17;
        use crate::retained_metadata::aliases::MetadataSharedKind;
        self.authenticate_settled_current_parent_data(boot)?;
        let Self {
            creator,
            thread: _,
            data,
            launch_body,
            policy,
            source_body,
            host_body,
            normalized,
            banks,
            context,
            proof,
            original,
            ready,
            attempted,
            verified,
            restoration,
            transfer,
            startup,
            restoration_activation: _,
            restoration_uploads: _,
            restoration_observation: _,
            restored_settled,
        } = self;
        observer.observe(creator)?;
        let BootData {
            schema,
            private_key,
            birth_id,
            source_birth,
            expected_host_registration,
            private_launch,
            host_executable,
        } = data;
        observer.observe(schema)?;
        observer.observe(private_key)?;
        observer.observe(birth_id)?;
        observer.observe(source_birth)?;
        observer.observe(expected_host_registration)?;
        observer.observe(private_launch)?;
        observer.observe(host_executable)?;
        observer.observe(launch_body)?;
        let policy = policy
            .as_ref()
            .ok_or(ProviderError::Correlation("current17 Policy absent"))?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        observer.observe(source_body)?;
        observer.observe(host_body)?;
        observer.observe(normalized)?;
        for bank in banks {
            observer.observe(bank)?;
        }
        if let Some(value) = context {
            value.observe_current(observer)?;
        }
        if let Some(value) = proof {
            value.observe_current(observer)?;
        }
        observer.observe(original)?;
        observer.observe(ready)?;
        observer.observe(attempted)?;
        observer.observe(verified)?;
        if let Some(commit) = restoration {
            observer.shared_original(
                MetadataSharedKind::NativeRestoreCommitAttempt,
                commit.as_ref(),
            )?;
            commit
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("current17 Commit borrowed"))?
                .observe_current_settled17_metadata_data(observer)?;
        }
        if let Some(prepare) = transfer {
            observer.shared_original(
                MetadataSharedKind::NativeRestorePrepareAttempt,
                prepare.as_ref(),
            )?;
            prepare
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("current17 Prepare borrowed"))?
                .observe_current_settled17_metadata_data(boot, observer)?;
        }
        self.observe_restoration_activation_metadata_data(observer)?;
        self.observe_restoration_upload_metadata_data(observer)?;
        self.observe_restoration_observation_metadata_data(observer)?;
        if let Some(startup) = startup {
            let native_startup::OriginalNativeStartupBoot {
                restored_suffix,
                allocation,
                source_digest: _,
                launch_digest: _,
                birth_id: _,
                native_birth_issued,
                baseline_complete,
                prepare_startup_issued,
            } = startup;
            let crate::reference_packet::service::native_startup::PacketNativeStartupAllocation {
                schema,
                private_bootstrap: _,
                native_birth: _,
                restore_prepare: _,
            } = allocation;
            observer.observe(schema)?;
            observer.observe(native_birth_issued)?;
            observer.observe(baseline_complete)?;
            observer.observe(prepare_startup_issued)?;
            if let Some(suffix) = restored_suffix {
                suffix.observe_current_settled17_metadata_data(observer)?;
            }
        }
        let reserve = restored_settled
            .as_ref()
            .ok_or(ProviderError::Correlation("current17 reserve absent"))?;
        if let Some((view, cut)) = action_cut {
            reserve
                .observe_current_settled17_with_action_cut_metadata_data(boot, view, cut, observer)
        } else {
            reserve.observe_current_settled17_metadata_data(boot, observer)
        }
    }

    /// Returns the defining ACK normalization bank bounds for historical DATA checks.
    pub(crate) const fn historical_ack_context_limits17_data() -> [usize; 5] {
        ORIGINAL_ACK_CONTEXT_BANK_BYTES
    }

    /// Names the actual new writer, ledger, borrow, reader and fixed result headers.
    pub(crate) fn current17_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<CurrentBootHistory17<'static>>()
            +size_of::<BootDataHistory<'static>>()
            +size_of::<StartupHistory<'static>>()
            +size_of::<ByteBank<'static>>()
            +size_of::<Banks<'static>>()
            +size_of::<crate::retained_metadata::MetadataObserver<'static>>()
            +size_of::<Result<std::cell::Ref<'static,Self>,std::cell::BorrowError>>()
            +size_of::<Result<(),ProviderError>>()
            +Self::current_stages17_writer_header_data()
            +crate::protocol_snapshot::restored_settled17::current_boot::current_boot17_counter_scratch_data()
            +crate::protocol_snapshot::restored_settled17::current_boot::current_boot17_inline_layouts_data().into_iter().sum::<usize>()
            +crate::protocol_snapshot::restored_settled17::current_contracts::current_contracts17_inline_layouts_data().into_iter().sum::<usize>()
    }
}

impl NativeAckBoot {
    /// Borrows the same complete graph through its exact currently mutable action.
    pub(in crate::reference_packet) fn borrowed_current17_with_action_cut_data<'a>(
        &'a self,
        boot: &'a Rc<RefCell<Self>>,
        view: &'a NativeRestoredSettledActionCurrent17<'a>,
        cut: &'a NativeCaptureOutputCut17<'a>,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.authenticate_settled_current_parent_data(boot)?;
        self.restored_settled
            .as_ref()
            .ok_or(ProviderError::Correlation("current17 reserve absent"))?
            .borrowed_settled_history_with_action_cut17_data(boot, view, cut)?;
        Ok(CurrentBootHistory17 {
            owner: self,
            boot,
            action_cut: Some((view, cut)),
        })
    }

    /// Appends the full graph while using that same action's active recorder cut.
    pub(crate) fn observe_current17_with_action_cut_metadata_data(
        boot: &Rc<RefCell<Self>>,
        view: &NativeRestoredSettledActionCurrent17<'_>,
        cut: &NativeCaptureOutputCut17<'_>,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativeBoot,
            boot.as_ref(),
        )?;
        let owner = boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("current17 Boot borrowed"))?;
        owner.observe_current17_payload_metadata_data(boot, Some((view, cut)), observer)
    }
}
