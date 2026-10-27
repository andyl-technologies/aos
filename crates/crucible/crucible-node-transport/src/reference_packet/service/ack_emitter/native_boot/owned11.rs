//! Borrows successful native boot originals without reconstructing authority.
//!
//! These source-private leaves preserve actual retained fields. Their encoded
//! identities are historical labels; a decoder cannot recreate a key issuer,
//! registrar, original thread, connection, socket or admission marker.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeTuple},
};

impl NativeAckBoot {
    fn authenticate_owned11_state(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.startup.is_some() {
            return Err(ProviderError::Correlation(
                "boot6 requires native startup class",
            ));
        }
        self.authenticate_base_owned_state()
    }

    fn authenticate_base_owned_state(&self) -> Result<(), ProviderError> {
        if self.transfer.is_some() || self.restoration.is_some() {
            return Err(ProviderError::Correlation("native whole11 boot unresolved"));
        }
        self.authenticate_base_admitted_boot_state()
    }

    fn authenticate_admitted_boot_state(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.startup.is_some() {
            return Err(ProviderError::Correlation(
                "boot6 requires admitted startup codec",
            ));
        }
        self.authenticate_base_admitted_boot_state()
    }

    fn authenticate_base_admitted_boot_state(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if !self.ready
            || !self.attempted
            || !self.verified
            || self.policy.is_none()
            || self.context.is_none()
            || self.proof.is_none()
            || self.original.is_none()
            || self.normalized.iter().any(Option::is_none)
        {
            return Err(ProviderError::Correlation("native whole11 boot unresolved"));
        }
        self.context
            .as_ref()
            .ok_or(ProviderError::Correlation("native context absent"))?
            .validate_data()?;
        self.proof
            .as_ref()
            .ok_or(ProviderError::Correlation("native proof absent"))?
            .validate_data()
    }

    pub(crate) fn borrowed_owned11_protocol_view(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_owned11_state()?;
        Ok(BootView {
            boot: self,
            startup: false,
        })
    }

    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_owned11_state()?;
        self.observe_admitted_boot_metadata(observer)
    }

    pub(super) fn observe_admitted_boot_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.startup.is_some() {
            return Err(ProviderError::Correlation(
                "boot6 requires admitted startup observer",
            ));
        }
        self.observe_base_admitted_boot_metadata(observer)
    }

    fn observe_base_admitted_boot_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.observe_base_admitted_boot_metadata_at_encoding(false, observer)
    }

    // The new invocation class explicitly represents canonical byte banks by
    // capacity and initialized length. Old11/14 visit/row behavior stays exact.
    fn observe_base_admitted_boot_metadata_at_encoding(
        &self,
        compact_byte_banks: bool,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_base_admitted_boot_state()?;
        // The legacy codec cannot account for the selected17 reserve. Its full
        // custody is walked by the defining current17 observer instead.
        if self.restored_settled.is_some() {
            return Err(ProviderError::Correlation("native whole11 boot unresolved"));
        }

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
            restoration: _,
            restoration_activation: _,
            restoration_uploads: _,
            restoration_observation: _,
            transfer: _,
            startup: _,
            restored_settled: _,
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
        observe_unique_boot_byte_bank(launch_body, compact_byte_banks, observer)?;
        let policy = policy
            .as_ref()
            .ok_or(ProviderError::Correlation("native policy absent"))?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        policy.observe_owned11_metadata(observer)?;
        observe_unique_boot_byte_bank(source_body, compact_byte_banks, observer)?;
        observe_unique_boot_byte_bank(host_body, compact_byte_banks, observer)?;
        for value in normalized {
            observer.observe(value)?;
        }
        for bank in banks {
            observe_unique_boot_byte_bank(bank, compact_byte_banks, observer)?;
        }
        let PacketCanonicalAckAdmissionContext {
            schema,
            algorithm,
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_admit,
        } = context
            .as_ref()
            .ok_or(ProviderError::Correlation("native context absent"))?;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        for digest in [
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_admit,
        ] {
            observer.observe(digest)?;
        }
        let PacketCanonicalAckAdmissionProof {
            schema,
            algorithm,
            context_digest,
            mac,
        } = proof
            .as_ref()
            .ok_or(ProviderError::Correlation("native proof absent"))?;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        observer.observe(context_digest)?;
        observer.observe(mac)?;
        observer.observe(original)?;
        observer.observe(ready)?;
        observer.observe(attempted)?;
        observer.observe(verified)?;
        self.observe_restoration_activation_metadata_data(observer)?;
        self.observe_restoration_observation_metadata_data(observer)?;
        self.observe_restoration_upload_metadata_data(observer)
    }
}

struct ByteBank<'a>(&'a Vec<u8>);

impl Serialize for ByteBank<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.0.capacity(), BorrowedCompactBytes::new(self.0)).serialize(serializer)
    }
}

struct BootDataView<'a> {
    data: &'a BootData,
    startup: bool,
}

impl Serialize for BootDataView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let BootData {
            schema,
            private_key,
            birth_id,
            source_birth,
            expected_host_registration,
            private_launch,
            host_executable,
        } = self.data;
        (
            if self.startup {
                "source-private.native-ack-boot-data/14"
            } else {
                "source-private.native-ack-boot-data/11"
            },
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

struct BanksView<'a>(&'a [Vec<u8>; 5]);

impl Serialize for BanksView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(5))?;
        for bank in self.0 {
            sequence.serialize_element(&ByteBank(bank))?;
        }
        sequence.end()
    }
}

struct BootView<'a> {
    boot: &'a NativeAckBoot,
    startup: bool,
}

impl Serialize for BootView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.startup {
            self.boot.authenticate_startup_owned_state()
        } else {
            self.boot.authenticate_owned11_state()
        }
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
        } = self.boot;
        let policy = policy
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native policy absent"))?;
        let mut tuple = serializer.serialize_tuple(16)?;
        tuple.serialize_element(if self.startup {
            "source-private.native-ack-boot/14"
        } else {
            "source-private.native-ack-boot/11"
        })?;
        tuple.serialize_element(creator)?;
        tuple.serialize_element("same-original-thread")?;
        tuple.serialize_element(&BootDataView {
            data,
            startup: self.startup,
        })?;
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

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn borrowed_owned11_protocol_view<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_current(connection)?;
        let boot = self
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native whole11 boot borrowed"))?;
        boot.authenticate_owned11_state()?;
        Ok(TokenView { token: self, boot })
    }

    pub(crate) fn observe_owned11_metadata<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let Self {
            identity,
            boot,
            policy,
            authority,
            original,
        } = self;
        observer.observe(identity)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, boot.as_ref())?;
        boot.try_borrow()
            .map_err(|_| ProviderError::Conflict("native whole11 boot borrowed"))?
            .observe_owned11_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        policy.observe_owned11_metadata(observer)?;
        authority.observe_retained_metadata(observer)?;
        observer.observe(original)
    }
}

struct TokenView<'a> {
    token: &'a VerifiedCanonicalAckAdmission,
    boot: std::cell::Ref<'a, NativeAckBoot>,
}

impl Serialize for TokenView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.boot
            .ensure_origin()
            .map_err(serde::ser::Error::custom)?;
        self.token
            .authority
            .ensure_live()
            .map_err(serde::ser::Error::custom)?;
        let VerifiedCanonicalAckAdmission {
            identity,
            boot: _,
            policy,
            authority,
            original,
        } = self.token;
        (
            "source-private.native-ack-token/11",
            identity.borrowed_owned11_protocol_view(),
            BootView {
                boot: &self.boot,
                startup: false,
            },
            policy.borrowed_owned11_protocol_view(),
            authority.historical_owned_view(),
            original,
        )
            .serialize(serializer)
    }
}

// The new historical edition streams fixed digests through the bounded compact
// adapter. The shared wire-five Bytes serializer and proof grammar stay exact.
struct DigestBank<'a>(&'a Bytes);

impl Serialize for DigestBank<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            self.0.allocation_capacity(),
            BorrowedCompactBytes::new(self.0.as_slice()),
        )
            .serialize(serializer)
    }
}

struct ContextView<'a>(&'a PacketCanonicalAckAdmissionContext);

impl Serialize for ContextView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketCanonicalAckAdmissionContext {
            schema,
            algorithm,
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_admit,
        } = self.0;
        (
            "source-private.native-ack-context/11",
            schema,
            algorithm,
            DigestBank(source_birth),
            DigestBank(kernel_binding),
            DigestBank(policy_binding),
            DigestBank(host_registration),
            DigestBank(native_registration),
            DigestBank(hello_request),
            DigestBank(hello_response),
            DigestBank(assigned_admit),
        )
            .serialize(serializer)
    }
}

struct ProofView<'a>(&'a PacketCanonicalAckAdmissionProof);

impl Serialize for ProofView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketCanonicalAckAdmissionProof {
            schema,
            algorithm,
            context_digest,
            mac,
        } = self.0;
        (
            "source-private.native-ack-proof/11",
            schema,
            algorithm,
            DigestBank(context_digest),
            DigestBank(mac),
        )
            .serialize(serializer)
    }
}

// The enclosing actual RefCell<NativeAckBoot> strong edge is recorded by the
// caller. A first visit walks all boot-owned children with the shared roster.
// Primitive canonical byte banks own only their Vec allocation. The selected
// startup walk records actual capacity and initialized length in constant work;
// ordinary wire/cold byte serialization and complete hashing remain unchanged.
fn observe_unique_boot_byte_bank(
    bytes: &Vec<u8>,
    startup: bool,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    if startup {
        observer.vector::<u8>(bytes.capacity())?;
        observer.observe(&bytes.len())
    } else {
        observer.observe(bytes)
    }
}

impl NativeAckBoot {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        if self.requires_invocation_codec_data()? {
            self.authenticate_invocation_owned_data()?;
        } else if self.startup.is_some() {
            self.authenticate_startup_owned_state()?;
        } else {
            self.authenticate_owned11_state()?;
        }
        self.observe_unique_boot_children(roots, observer)
    }

    // Child-only: the caller records this actual RefCell<NativeAckBoot> edge.
    // The unique caller must separately record/walk every admitted transfer.
    fn observe_unique_boot_children(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        // A selected17 reserve is never omitted from a successful legacy walk.
        // Its complete current graph uses the separate aggregate observer.
        if self.restored_settled.is_some() {
            return Err(ProviderError::Correlation("native whole11 boot unresolved"));
        }

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
            restoration: _,
            restoration_activation: _,
            restoration_uploads: _,
            restoration_observation: _,
            transfer: _,
            startup: _,
            restored_settled: _,
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
        observe_unique_boot_byte_bank(launch_body, self.startup.is_some(), observer)?;
        let policy = policy
            .as_ref()
            .ok_or(ProviderError::Correlation("native policy absent"))?;
        if roots.observe_shared(observer, MetadataSharedKind::NativePolicy, policy.as_ref())? {
            policy.observe_unique_capture_metadata(roots, observer)?;
        }
        observe_unique_boot_byte_bank(source_body, self.startup.is_some(), observer)?;
        observe_unique_boot_byte_bank(host_body, self.startup.is_some(), observer)?;
        for value in normalized {
            observer.observe(value)?;
        }
        for bank in banks {
            observe_unique_boot_byte_bank(bank, self.startup.is_some(), observer)?;
        }
        let PacketCanonicalAckAdmissionContext {
            schema,
            algorithm,
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_admit,
        } = context
            .as_ref()
            .ok_or(ProviderError::Correlation("native context absent"))?;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        for digest in [
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_admit,
        ] {
            observer.observe(digest)?;
        }
        let PacketCanonicalAckAdmissionProof {
            schema,
            algorithm,
            context_digest,
            mac,
        } = proof
            .as_ref()
            .ok_or(ProviderError::Correlation("native proof absent"))?;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        observer.observe(context_digest)?;
        observer.observe(mac)?;
        observer.observe(original)?;
        observer.observe(ready)?;
        observer.observe(attempted)?;
        observer.observe(verified)?;
        self.observe_restoration_activation_metadata_data(observer)?;
        self.observe_restoration_observation_metadata_data(observer)?;
        self.observe_restoration_upload_metadata_data(observer)?;
        if let Some(startup) = &self.startup {
            startup_codec::observe_owner(startup, observer)?;
            if self.requires_invocation_codec_data()? {
                self.observe_invocation_phase_metadata(observer)?;
            }
        }
        Ok(())
    }
}

impl NativeAckBoot {
    /// Walks only this genuine admitted boot's children during verified Prepare.
    /// The caller owns and walks the same actual transfer Rc once; its second
    /// edge from boot is recorded here. No transferSome or numeric data alone
    /// satisfies the full current baseline, source allocation and verified Rc.
    pub(super) fn observe_verified_startup_prepare_metadata(
        &self,
        expected: &Rc<RefCell<restore_prepare::NativeCompleteRestorePrepareAttempt>>,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_base_admitted_boot_state()?;
        if self.requires_invocation_codec_data()? {
            self.authenticate_original_invocation_prepare_target_data()?;
        } else {
            self.authenticate_original_native_baseline_data()?;
        }
        let startup = self.startup.as_ref().ok_or(ProviderError::Correlation(
            "startup Prepare boot owner absent",
        ))?;
        startup
            .allocation
            .authenticate_owned_codec_source_data(&self.data.source_birth)?;
        let transfer = self.transfer.as_ref().ok_or(ProviderError::Correlation(
            "startup Prepare transfer absent",
        ))?;
        if self.restoration.is_some() || !Rc::ptr_eq(transfer, expected)
            || self.policy.as_ref().is_none_or(|policy| policy.complete_restore_selection()
                != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12))
        { return Err(ProviderError::Correlation("startup Prepare actual transfer differs")); }
        let flight = transfer
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("startup Prepare transfer borrowed"))?;
        flight.authenticate_verified_metadata_data()?;
        roots.observe_shared_edge(
            observer,
            MetadataSharedKind::NativeRestorePrepareAttempt,
            transfer.as_ref(),
        )?;
        self.observe_unique_boot_children(roots, observer)
    }
}

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn observe_unique_capture_metadata<S: crate::connection::ProviderStream>(
        &self,
        connection: &crate::connection::Connection<S>,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let Self {
            identity,
            boot,
            policy,
            authority,
            original,
        } = self;
        identity.observe_unique_capture_metadata(roots, observer)?;
        if roots.observe_shared(observer, MetadataSharedKind::NativeBoot, boot.as_ref())? {
            boot.try_borrow()
                .map_err(|_| ProviderError::Conflict("native Capture boot borrowed"))?
                .observe_unique_capture_metadata(roots, observer)?;
        }
        if roots.observe_shared(observer, MetadataSharedKind::NativePolicy, policy.as_ref())? {
            policy.observe_unique_capture_metadata(roots, observer)?;
        }
        authority.observe_unique_capture_metadata(roots, observer)?;
        observer.observe(original)?;
        self.authenticate_current(connection)
    }
}

#[path = "startup_owned.rs"]
mod startup_codec;

#[cfg(test)]
mod startup_byte_bank_tests {
    use super::*;
    use crate::retained_metadata::records::{MetadataRecordBank, MetadataRecordKind};

    #[test]
    fn startup_unique_byte_bank_preserves_spare_capacity_without_per_byte_owned_visits() {
        let mut bytes = Vec::with_capacity(200_003);
        bytes.resize(180_000, 0x5a);
        let mut records = MetadataRecordBank::reserve(8).unwrap();
        let mut observer = MetadataObserver::recording(&mut records);
        observe_unique_boot_byte_bank(&bytes, true, &mut observer).unwrap();
        let facts = observer.finish();

        assert_eq!(facts.vector_banks, 1);
        assert_eq!(facts.vector_capacity_bytes, bytes.capacity());
        assert_eq!(facts.observed_nodes, 1);
        assert_eq!(records.rows().len(), 1);
        assert_eq!(records.rows()[0].kind, MetadataRecordKind::Vector);
        assert_eq!(records.rows()[0].extent, bytes.capacity());
        assert_eq!(records.rows()[0].element_bytes, std::mem::size_of::<u8>());
        assert_eq!(bytes.len(), 180_000);
        assert!(bytes.iter().all(|byte| *byte == 0x5a));
    }

    #[test]
    fn startup_none_unique_byte_bank_keeps_ordinary_nodes_and_capacity_rows_exact() {
        let mut bytes = Vec::with_capacity(23);
        bytes.extend_from_slice(b"original");
        let mut expected_rows = MetadataRecordBank::reserve(8).unwrap();
        let mut expected = MetadataObserver::recording(&mut expected_rows);
        expected.observe(&bytes).unwrap();
        let expected = expected.finish();
        let mut actual_rows = MetadataRecordBank::reserve(8).unwrap();
        let mut actual = MetadataObserver::recording(&mut actual_rows);
        observe_unique_boot_byte_bank(&bytes, false, &mut actual).unwrap();
        let actual = actual.finish();

        assert_eq!(actual, expected);
        assert_eq!(actual_rows.rows(), expected_rows.rows());
        assert_eq!(actual.observed_nodes, bytes.len() + 1);
    }
}

#[path = "invocation_owned.rs"]
mod invocation_data;

#[path = "invocation_protocol.rs"]
mod invocation_protocol;
