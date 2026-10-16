//! Encodes complete boot6 startup owners as explicit inert archive data.
//!
//! ```text
//! ["source-private.native-ack-boot-startup/14", full_boot14,
//!  ["source-private.native-startup-owner/14", full_allocation14,
//!   compact_source_digest32, compact_launch_digest32, compact_birth_id32,
//!   native_birth_issued, baseline_complete, prepare_startup_issued]]
//! ```
//!
//! Only the actual completed private boot can lend this view. Historical data
//! cannot recreate its issuer, original thread, startup occurrence or MAC key.

use super::super::native_startup::OriginalNativeStartupBoot;
use super::*;
use crate::reference_packet::service::native_startup::{
    PacketNativeStartupAllocation, PacketNativeStartupAllocationRow,
};

fn quoted_u64_data_matches(value: Option<&serde_json::Value>, expected: u64) -> bool {
    let Some(raw) = value.and_then(serde_json::Value::as_str) else {
        return false;
    };
    !raw.is_empty()
        && (raw == "0" || !raw.starts_with('0'))
        && raw.bytes().all(|byte| byte.is_ascii_digit())
        && raw.parse::<u64>() == Ok(expected)
}

pub(super) fn observe_row(
    row: &PacketNativeStartupAllocationRow,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let PacketNativeStartupAllocationRow {
        retained_requested_bytes,
        maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes,
    } = row;
    observer.observe(retained_requested_bytes)?;
    observer.observe(maximum_simultaneous_transient_bytes)?;
    observer.observe(declared_counter_scratch_bytes)
}

pub(super) fn observe_owner(
    owner: &OriginalNativeStartupBoot,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let OriginalNativeStartupBoot {
        restored_suffix,
        allocation,
        source_digest,
        launch_digest,
        birth_id,
        native_birth_issued,
        baseline_complete,
        prepare_startup_issued,
    } = owner;
    let PacketNativeStartupAllocation {
        schema,
        private_bootstrap,
        native_birth,
        restore_prepare,
    } = allocation;
    observer.observe(schema)?;
    observe_row(private_bootstrap, observer)?;
    observe_row(native_birth, observer)?;
    observer.observe(&restore_prepare.is_some())?;
    if let Some(row) = restore_prepare {
        observe_row(row, observer)?;
    }
    // These fixed primitive banks have no nested heap. Complete byte/hash work
    // remains in the serializer and closed decoder under their byte limits.
    observer.observe(&source_digest.len())?;
    observer.observe(&launch_digest.len())?;
    observer.observe(&birth_id.len())?;
    observer.observe(native_birth_issued)?;
    observer.observe(baseline_complete)?;
    observer.observe(prepare_startup_issued)?;
    if let Some(suffix) = restored_suffix {
        suffix.observe_retained_data(observer)?;
    }
    Ok(())
}

struct StartupOwnerView<'a>(&'a OriginalNativeStartupBoot);

impl Serialize for StartupOwnerView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.restored_suffix.is_some() {
            return Err(serde::ser::Error::custom(
                "suffix ledger requires its separately paired continuation codec",
            ));
        }
        let OriginalNativeStartupBoot {
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
            "source-private.native-startup-owner/14",
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

struct StartupBootView<'a>(&'a NativeAckBoot);

impl Serialize for StartupBootView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_startup_owned_state()
            .map_err(serde::ser::Error::custom)?;
        let owner = self
            .0
            .startup
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native startup owner absent"))?;
        (
            "source-private.native-ack-boot-startup/14",
            BootView {
                boot: self.0,
                startup: true,
            },
            StartupOwnerView(owner),
        )
            .serialize(serializer)
    }
}

impl NativeAckBoot {
    pub(crate) fn startup_protocol_counter_scratch_data() -> usize {
        [
            std::mem::size_of::<StartupTokenView<'static>>(),
            std::mem::size_of::<StartupBootView<'static>>(),
            std::mem::size_of::<StartupOwnerView<'static>>(),
            std::mem::size_of::<BootView<'static>>(),
            std::mem::size_of::<BootDataView<'static>>(),
            std::mem::size_of::<
                crate::reference_packet::service::native_startup::PacketNativeStartupPreambleData,
            >(),
            std::mem::size_of::<blake3::Hasher>(),
            BorrowedCompactBytes::requested_serialization_scratch_bytes(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .unwrap_or(usize::MAX)
    }

    pub(crate) fn requires_startup_codec_data(&self) -> Result<bool, ProviderError> {
        self.ensure_origin()?;
        Ok(self.startup.is_some())
    }

    fn authenticate_startup_admitted_state(&self) -> Result<(), ProviderError> {
        self.authenticate_base_admitted_boot_state()?;
        self.authenticate_original_native_baseline_data()?;
        let owner = self
            .startup
            .as_ref()
            .ok_or(ProviderError::Correlation("native startup owner absent"))?;
        owner
            .allocation
            .authenticate_owned_codec_source_data(&self.data.source_birth)
    }

    pub(super) fn authenticate_startup_owned_state(&self) -> Result<(), ProviderError> {
        self.authenticate_base_owned_state()?;
        self.authenticate_startup_admitted_state()
    }

    pub(crate) fn authenticate_startup_bootstrap_preamble_data(
        &self,
        preamble: &[u8],
        facts: &crate::reference_packet::service::native_startup::PacketNativeStartupPreambleData,
    ) -> Result<(), ProviderError> {
        self.authenticate_startup_owned_state()?;
        crate::reference_packet::service::native_startup::authenticate_original_native_startup_preamble_data(preamble, self.data.private_key.as_slice())?;
        let owner = self
            .startup
            .as_ref()
            .ok_or(ProviderError::Correlation("native startup owner absent"))?;
        if facts.private_bootstrap != owner.allocation.private_bootstrap
            || facts.native_birth != owner.allocation.native_birth
            || facts.restore_prepare != owner.allocation.restore_prepare
            || facts.birth_id != owner.birth_id
            || facts.launch_digest != owner.launch_digest
            || facts.source_digest != owner.source_digest
            || blake3::hash(&self.host_body).as_bytes() != &facts.registration_digest
            || blake3::hash(self.data.private_launch.as_str().as_bytes()).as_bytes()
                != &facts.private_launch_digest
        {
            return Err(ProviderError::Correlation(
                "native startup private bootstrap association differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate_startup_controller_data(
        &self,
        launch: &serde_json::Map<String, serde_json::Value>,
        pid: u64,
        uid: u64,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if !quoted_u64_data_matches(launch.get("controller_pid"), pid)
            || !quoted_u64_data_matches(launch.get("controller_uid"), uid)
        {
            return Err(ProviderError::Correlation(
                "native startup controller association differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn borrowed_startup_protocol_view(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_startup_owned_state()?;
        Ok(StartupBootView(self))
    }

    pub(crate) fn observe_startup_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_startup_owned_state()?;
        self.observe_admitted_startup_metadata(observer)
    }

    pub(crate) fn observe_admitted_startup_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_startup_admitted_state()?;
        self.observe_base_admitted_boot_metadata(observer)?;
        observe_owner(
            self.startup
                .as_ref()
                .ok_or(ProviderError::Correlation("native startup owner absent"))?,
            observer,
        )
    }
}

struct StartupTokenView<'a> {
    token: &'a VerifiedCanonicalAckAdmission,
    boot: std::cell::Ref<'a, NativeAckBoot>,
}

impl Serialize for StartupTokenView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.token
            .authority
            .ensure_live()
            .map_err(serde::ser::Error::custom)?;
        self.boot
            .authenticate_startup_owned_state()
            .map_err(serde::ser::Error::custom)?;
        (
            "source-private.native-ack-token/14",
            self.token.identity.borrowed_owned11_protocol_view(),
            StartupBootView(&self.boot),
            self.token.policy.borrowed_owned11_protocol_view(),
            self.token.authority.historical_owned_view(),
            &self.token.original,
        )
            .serialize(serializer)
    }
}

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn borrowed_startup_protocol_view<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_current(connection)?;
        let boot = self
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native startup boot borrowed"))?;
        boot.authenticate_startup_owned_state()?;
        Ok(StartupTokenView { token: self, boot })
    }

    pub(crate) fn observe_startup_metadata<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        observer.observe(&self.identity)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, self.boot.as_ref())?;
        self.boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native startup boot borrowed"))?
            .observe_startup_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativePolicy, self.policy.as_ref())?;
        self.policy.observe_owned11_metadata(observer)?;
        self.authority.observe_retained_metadata(observer)?;
        observer.observe(&self.original)
    }
}

impl PacketNativeStartupAllocation {
    /// Checks the exact separately retained allocation against the Source value.
    ///
    /// This borrowed comparison creates no parsed value or construction right.
    ///
    /// # Errors
    /// Refuses a changed schema, field roster, nullable phase or scalar term.
    pub(crate) fn authenticate_owned_codec_source_data(
        &self,
        source: &serde_json::Value,
    ) -> Result<(), ProviderError> {
        let invalid = || ProviderError::Correlation("native startup Source selection differs");
        self.authenticate_owned_codec_source_value_data(
            source
                .get("native_startup_allocation")
                .ok_or_else(invalid)?,
        )?;
        let prepare_selected = match source
            .get("complete_restore_selection")
            .ok_or_else(invalid)?
        {
            serde_json::Value::Null => false,
            serde_json::Value::String(value) if value == "SourceSignedOwned11" => false,
            serde_json::Value::String(value) if value == "SourceSignedTransfer12" => true,
            _ => return Err(invalid()),
        };
        self.validate_data(prepare_selected)
    }

    pub(crate) fn authenticate_owned_codec_source_value_data(
        &self,
        source: &serde_json::Value,
    ) -> Result<(), ProviderError> {
        fn invalid() -> ProviderError {
            ProviderError::Correlation("native startup codec source allocation differs")
        }
        fn read(value: &serde_json::Value) -> Result<u64, ProviderError> {
            let raw = value.as_str().ok_or_else(invalid)?;
            if raw.is_empty()
                || raw.len() > 20
                || !raw.bytes().all(|byte| byte.is_ascii_digit())
                || raw.len() > 1 && raw.starts_with('0')
            {
                return Err(invalid());
            }
            raw.parse().map_err(|_| invalid())
        }
        fn row(
            actual: &PacketNativeStartupAllocationRow,
            value: &serde_json::Value,
        ) -> Result<(), ProviderError> {
            let value = value.as_object().ok_or_else(invalid)?;
            if value.len() != 3 {
                return Err(invalid());
            }
            for (name, expected) in [
                ("retained_requested_bytes", actual.retained_requested_bytes),
                (
                    "maximum_simultaneous_transient_bytes",
                    actual.maximum_simultaneous_transient_bytes,
                ),
                (
                    "declared_counter_scratch_bytes",
                    actual.declared_counter_scratch_bytes,
                ),
            ] {
                if read(value.get(name).ok_or_else(invalid)?)? != expected.get() {
                    return Err(invalid());
                }
            }
            Ok(())
        }
        self.requested_peak_data()?;
        let source = source.as_object().ok_or_else(invalid)?;
        if source.len() != 4
            || source.get("schema").and_then(serde_json::Value::as_str)
                != Some(self.schema.as_str())
        {
            return Err(invalid());
        }
        row(
            &self.private_bootstrap,
            source.get("private_bootstrap").ok_or_else(invalid)?,
        )?;
        row(
            &self.native_birth,
            source.get("native_birth").ok_or_else(invalid)?,
        )?;
        let prepare = source.get("restore_prepare").ok_or_else(invalid)?;
        match &self.restore_prepare {
            Some(actual) => row(actual, prepare),
            None if prepare.is_null() => Ok(()),
            None => Err(invalid()),
        }
    }
}
