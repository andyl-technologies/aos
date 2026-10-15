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
        if self.transfer.is_some() || self.restoration.is_some() {
            return Err(ProviderError::Correlation("native whole11 boot unresolved"));
        }
        self.authenticate_admitted_boot_state()
    }

    fn authenticate_admitted_boot_state(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        // The old tuple/observer has no startup owner leaf. Refuse before
        // traversing any children; an absent constructor is not a new codec.
        if self.startup.is_some() {
            return Err(ProviderError::Correlation(
                "native old11 startup owner unsupported",
            ));
        }
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
        Ok(BootView(self))
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
        self.authenticate_admitted_boot_state()?;
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
            transfer: _,
            startup: _,
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
            .ok_or(ProviderError::Correlation("native policy absent"))?;
        observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
        policy.observe_owned11_metadata(observer)?;
        observer.observe(source_body)?;
        observer.observe(host_body)?;
        for value in normalized {
            observer.observe(value)?;
        }
        for bank in banks {
            observer.observe(bank)?;
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
        observer.observe(verified)
    }
}

struct ByteBank<'a>(&'a Vec<u8>);

impl Serialize for ByteBank<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.0.capacity(), BorrowedCompactBytes::new(self.0)).serialize(serializer)
    }
}

struct BootDataView<'a>(&'a BootData);

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
        } = self.0;
        (
            "source-private.native-ack-boot-data/11",
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

struct BootView<'a>(&'a NativeAckBoot);

impl Serialize for BootView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_owned11_state()
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
            transfer: _,
            startup: _,
        } = self.0;
        let policy = policy
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native policy absent"))?;
        let mut tuple = serializer.serialize_tuple(16)?;
        tuple.serialize_element("source-private.native-ack-boot/11")?;
        tuple.serialize_element(creator)?;
        tuple.serialize_element("same-original-thread")?;
        tuple.serialize_element(&BootDataView(data))?;
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
            BootView(&self.boot),
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
