//! Serializes the genuine original-invocation boot under new class15 leaves.
//!
//! ```text
//! ["source-private.native-ack-boot-invocation/15", boot15, startup_owner15,
//!  ["source-private.native-invocation-phase/15", "original_never_queried",
//!   compact_birth32, false, false, false]]
//! ```
//!
//! The raw literal history is checked by the actual Connection before using
//! this view. A historical reader must independently establish that same
//! no-Query/no-PrepareBinding fact. This component alone grants no capture.

use super::*;

impl NativeAckBoot {
    pub(crate) fn authenticate_invocation_capture_data(&self) -> Result<(), ProviderError> {
        self.authenticate_invocation_owned_data()?;
        if self.restoration_activation.iter().any(Option::is_some)
            || self.restoration_uploads.iter().any(Option::is_some)
            || self.restoration_observation.is_some()
            || !self.permits_original_invocation_without_fresh_query_data()?
            || self
                .startup
                .as_ref()
                .is_none_or(|owner| owner.prepare_startup_issued)
        {
            return Err(ProviderError::Correlation(
                "invocation Capture requires original unspent purpose",
            ));
        }
        Ok(())
    }

    pub(crate) fn borrowed_invocation_protocol_view(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_invocation_capture_data()?;
        Ok(InvocationBootView(self))
    }

    pub(crate) fn invocation_wire_counter_scratch_data() -> usize {
        [
            Self::invocation_protocol_counter_scratch_data(),
            std::mem::size_of::<InvocationBootView<'static>>(),
            std::mem::size_of::<InvocationBaseView<'static>>(),
            std::mem::size_of::<InvocationDataView<'static>>(),
            std::mem::size_of::<InvocationOwnerView<'static>>(),
            std::mem::size_of::<InvocationPhaseView<'static>>(),
            std::mem::size_of::<InvocationTokenView<'static>>(),
            // These new temporary tuple values coexist with their borrowed
            // wrapper headers. Encoded/event counts do not pay for Rust views.
            std::mem::size_of::<(
                &'static str,
                InvocationBaseView<'static>,
                InvocationOwnerView<'static>,
                InvocationPhaseView<'static>,
            )>(),
            std::mem::size_of::<(
                &'static str,
                &'static str,
                BorrowedCompactBytes<'static>,
                bool,
                bool,
                bool,
            )>(),
            std::mem::size_of::<Result<InvocationBootView<'static>, ProviderError>>(),
            std::mem::size_of::<Result<InvocationTokenView<'static>, ProviderError>>(),
            crate::connection::original_native_invocation_history_counter_scratch_data(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .unwrap_or(usize::MAX)
    }
}

struct InvocationBootView<'a>(&'a NativeAckBoot);

impl Serialize for InvocationBootView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_invocation_capture_data()
            .map_err(serde::ser::Error::custom)?;
        let startup = self
            .0
            .startup
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("invocation startup absent"))?;
        (
            "source-private.native-ack-boot-invocation/15",
            InvocationBaseView(self.0),
            InvocationOwnerView(startup),
            InvocationPhaseView(self.0),
        )
            .serialize(serializer)
    }
}

struct InvocationDataView<'a>(&'a BootData);

impl Serialize for InvocationDataView<'_> {
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
        (
            "source-private.native-ack-boot-data/15",
            schema,
            DigestBank(private_key),
            DigestBank(birth_id),
            source_birth,
            expected_host_registration,
            private_launch,
            host_executable,
        )
            .serialize(serializer)
    }
}

struct InvocationBaseView<'a>(&'a NativeAckBoot);

impl Serialize for InvocationBaseView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_invocation_capture_data()
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
            restoration: _,
            restoration_activation: _,
            restoration_uploads: _,
            restoration_observation: _,
            restored_settled: _,
            transfer: _,
            startup: _,
        } = self.0;
        let policy = policy
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("invocation policy absent"))?;
        let mut tuple = serializer.serialize_tuple(16)?;
        tuple.serialize_element("source-private.native-ack-boot/15")?;
        tuple.serialize_element(creator)?;
        tuple.serialize_element("same-original-thread")?;
        tuple.serialize_element(&InvocationDataView(data))?;
        tuple.serialize_element(&ByteBank(launch_body))?;
        tuple.serialize_element(&policy.borrowed_owned11_protocol_view())?;
        tuple.serialize_element(&ByteBank(source_body))?;
        tuple.serialize_element(&ByteBank(host_body))?;
        tuple.serialize_element(normalized)?;
        tuple.serialize_element(&BanksView(banks))?;
        tuple.serialize_element(&context.as_ref().map(ContextView))?;
        tuple.serialize_element(&proof.as_ref().map(ProofView))?;
        tuple.serialize_element(original)?;
        tuple.serialize_element(ready)?;
        tuple.serialize_element(attempted)?;
        tuple.serialize_element(verified)?;
        tuple.end()
    }
}

struct InvocationOwnerView<'a>(&'a super::super::native_startup::OriginalNativeStartupBoot);

impl Serialize for InvocationOwnerView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.restored_suffix.is_some() {
            return Err(serde::ser::Error::custom(
                "suffix ledger requires paired continuation codec",
            ));
        }
        let super::super::native_startup::OriginalNativeStartupBoot {
            restored_suffix: _,
            allocation,
            source_digest,
            launch_digest,
            birth_id,
            native_birth_issued,
            baseline_complete,
            prepare_startup_issued,
        } = self.0;
        (
            "source-private.native-startup-owner/15",
            allocation,
            BorrowedCompactBytes::new(source_digest),
            BorrowedCompactBytes::new(launch_digest),
            BorrowedCompactBytes::new(birth_id),
            native_birth_issued,
            baseline_complete,
            prepare_startup_issued,
        )
            .serialize(serializer)
    }
}

struct InvocationPhaseView<'a>(&'a NativeAckBoot);

impl Serialize for InvocationPhaseView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_invocation_capture_data()
            .map_err(serde::ser::Error::custom)?;
        let startup = self
            .0
            .startup
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("invocation startup absent"))?;
        (
            "source-private.native-invocation-phase/15",
            "original_never_queried",
            BorrowedCompactBytes::new(&startup.birth_id),
            startup.prepare_startup_issued,
            self.0.transfer.is_some(),
            self.0.restoration.is_some(),
        )
            .serialize(serializer)
    }
}

struct InvocationTokenView<'a> {
    token: &'a VerifiedCanonicalAckAdmission,
    boot: std::cell::Ref<'a, NativeAckBoot>,
}

impl Serialize for InvocationTokenView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.token
            .authority
            .ensure_live()
            .map_err(serde::ser::Error::custom)?;
        self.boot
            .authenticate_invocation_capture_data()
            .map_err(serde::ser::Error::custom)?;
        (
            "source-private.native-ack-token/15",
            self.token.identity.borrowed_owned11_protocol_view(),
            InvocationBootView(&self.boot),
            self.token.policy.borrowed_owned11_protocol_view(),
            self.token.authority.historical_owned_view(),
            &self.token.original,
        )
            .serialize(serializer)
    }
}

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn borrowed_invocation_protocol_view<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_current(connection)?;
        let boot = self
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("invocation boot borrowed"))?;
        boot.authenticate_invocation_capture_data()?;
        Ok(InvocationTokenView { token: self, boot })
    }
}
