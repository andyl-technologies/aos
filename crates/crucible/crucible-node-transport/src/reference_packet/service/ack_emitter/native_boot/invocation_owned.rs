//! Borrows every genuine boot7 child for data-only current-owner censuses.
//!
//! Invocation provenance stays in the actual immutable Source15 and launch6
//! owners. These loans grant no Query, transfer, snapshot-class or Arm right.
//! Existing boot11 and startup14 wire views remain intrinsically closed to7.

use super::*;
use crate::reference_packet::service::native_startup::{
    PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA, PacketNativeInvocationPreambleData,
    authenticate_original_native_invocation_preamble_data,
};

impl NativeAckBoot {
    /// Selects a data adapter from the actual private boot, never caller DATA.
    pub(crate) fn requires_invocation_codec_data(&self) -> Result<bool, ProviderError> {
        self.ensure_origin()?;
        Ok(self.data.schema == PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA)
    }

    pub(crate) fn authenticate_invocation_owned_data(&self) -> Result<(), ProviderError> {
        self.authenticate_base_owned_state()?;
        self.authenticate_original_invocation_baseline_data()?;
        self.startup
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "invocation startup owner absent",
            ))?
            .allocation
            .authenticate_owned_codec_source_data(&self.data.source_birth)
    }

    pub(crate) fn observe_invocation_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_invocation_owned_data()?;
        self.observe_base_admitted_boot_metadata_at_encoding(true, observer)?;
        startup_codec::observe_owner(
            self.startup.as_ref().ok_or(ProviderError::Correlation(
                "invocation startup owner absent",
            ))?,
            observer,
        )?;
        self.observe_invocation_phase_metadata(observer)
    }

    pub(super) fn observe_invocation_phase_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        let startup = self.startup.as_ref().ok_or(ProviderError::Correlation(
            "invocation startup owner absent",
        ))?;
        observer.observe(&startup.birth_id.len())?;
        observer.observe(&startup.prepare_startup_issued)?;
        observer.observe(&self.transfer.is_some())?;
        observer.observe(&self.restoration.is_some())
    }

    pub(crate) fn authenticate_invocation_bootstrap_preamble_data(
        &self,
        preamble: &[u8],
        facts: &PacketNativeInvocationPreambleData,
    ) -> Result<(), ProviderError> {
        self.authenticate_invocation_owned_data()?;
        authenticate_original_native_invocation_preamble_data(
            preamble,
            self.data.private_key.as_slice(),
        )?;
        let owner = self.startup.as_ref().ok_or(ProviderError::Correlation(
            "invocation startup owner absent",
        ))?;
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
                "invocation bootstrap association differs",
            ));
        }
        Ok(())
    }

    /// Names actual additional fixed views before a boot7 census loan.
    pub(crate) fn invocation_protocol_counter_scratch_data() -> usize {
        [
            Self::startup_protocol_counter_scratch_data(),
            std::mem::size_of::<PacketNativeInvocationPreambleData>(),
            2 * std::mem::size_of::<std::cell::Ref<'static, NativeAckBoot>>(),
            2 * std::mem::size_of::<&serde_json::Map<String, serde_json::Value>>(),
            4 * std::mem::size_of::<Option<&serde_json::Value>>(),
            std::mem::size_of::<Result<(), ProviderError>>(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .unwrap_or(usize::MAX)
    }
}

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn observe_invocation_metadata<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        observer.observe(&self.identity)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, self.boot.as_ref())?;
        self.boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("invocation boot borrowed"))?
            .observe_invocation_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativePolicy, self.policy.as_ref())?;
        self.policy.observe_owned11_metadata(observer)?;
        self.authority.observe_retained_metadata(observer)?;
        observer.observe(&self.original)?;
        self.authenticate_current(connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfinished_retained_boot_cannot_observe_invocation_children_or_become_startup14() {
        for schema in [
            PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA,
            "source-owned.packet-canonical-ack-private-boot/6",
            "unknown-private-boot",
        ] {
            let data = BootData {
                schema: schema.into(),
                private_key: Bytes::new(vec![0; 32]),
                birth_id: Bytes::new(vec![1; 32]),
                source_birth: serde_json::json!({"retained":"actual source payload"}),
                expected_host_registration: serde_json::json!({"retained":"actual host payload"}),
                private_launch: Id::new("private-launch").unwrap(),
                host_executable: canonical::content_ref(b"inert", "application/test").unwrap(),
            };
            let payload = data.source_birth["retained"].as_str().unwrap().as_ptr();
            let mut output = None;
            let original = NativeAckBoot::retain_boot_data_into(
                data,
                b"retained raw launch".to_vec(),
                None,
                &mut output,
            );
            let owner = original.borrow();
            let mut observer = MetadataObserver::new();
            assert!(owner.observe_invocation_metadata(&mut observer).is_err());
            assert!(owner.borrowed_invocation_protocol_view().is_err());
            assert!(owner.borrowed_startup_protocol_view().is_err());
            assert!(owner.borrowed_owned11_protocol_view().is_err());
            assert_eq!(observer.finish().observed_nodes, 0);
            assert_eq!(
                owner.data.source_birth["retained"]
                    .as_str()
                    .unwrap()
                    .as_ptr(),
                payload
            );
            assert_eq!(owner.launch_body, b"retained raw launch");
            assert!(Rc::ptr_eq(&original, output.as_ref().unwrap()));
            assert!(!owner.ready);
            assert!(!owner.verified);
            assert!(owner.startup.is_none());
        }
    }
}
