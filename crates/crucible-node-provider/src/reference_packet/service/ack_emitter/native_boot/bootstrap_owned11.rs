//! Borrows the actual closed successful private bootstrap for native history.
//!
//! Unknown Any values and unresolved births have no data fallback. This loan
//! keeps the original boot and literal banks borrowed, creates no new owner,
//! and never reconstructs a stream, registrar, key issuer or admission marker.

use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer};

pub(crate) struct OriginalNativeBootstrapOwned11<'a> {
    original: &'a Bootstrap<std::io::Stdin>,
    startup: bool,
    invocation: bool,
    reader: crate::transport::OriginalFrameReaderFacts,
    literals: std::cell::Ref<'a, OriginalFrameReservation>,
    boot: std::cell::Ref<'a, super::super::boot::NativeAckBoot>,
}

impl<'a> OriginalNativeBootstrapOwned11<'a> {
    // Only the genuine service supplies its retained Any slot. The completed
    // native token authenticates the exact boot/policy before any bank borrow.
    pub(in crate::reference_packet::service) fn borrow_original<
        S: crate::connection::ProviderStream,
    >(
        retained: &'a dyn std::any::Any,
        token: &super::super::boot::VerifiedCanonicalAckAdmission,
        connection: &crate::connection::Connection<S>,
    ) -> Result<Self, ProviderError> {
        Self::borrow_with_startup(retained, token, connection, false, false)
    }

    pub(in crate::reference_packet::service) fn borrow_original_startup<
        S: crate::connection::ProviderStream,
    >(
        retained: &'a dyn std::any::Any,
        token: &super::super::boot::VerifiedCanonicalAckAdmission,
        connection: &crate::connection::Connection<S>,
    ) -> Result<Self, ProviderError> {
        Self::borrow_with_startup(retained, token, connection, true, false)
    }

    pub(in crate::reference_packet::service) fn borrow_original_invocation<
        S: crate::connection::ProviderStream,
    >(
        retained: &'a dyn std::any::Any,
        token: &super::super::boot::VerifiedCanonicalAckAdmission,
        connection: &crate::connection::Connection<S>,
    ) -> Result<Self, ProviderError> {
        Self::borrow_with_startup(retained, token, connection, true, true)
    }

    fn borrow_with_startup<S: crate::connection::ProviderStream>(
        retained: &'a dyn std::any::Any,
        token: &super::super::boot::VerifiedCanonicalAckAdmission,
        connection: &crate::connection::Connection<S>,
        startup: bool,
        invocation: bool,
    ) -> Result<Self, ProviderError> {
        token.authenticate_current(connection)?;
        let original = retained.downcast_ref::<Bootstrap<std::io::Stdin>>().ok_or(
            ProviderError::Correlation("native whole11 bootstrap type unresolved"),
        )?;
        let boot_owner = original.boot.as_ref().ok_or(ProviderError::Correlation(
            "native whole11 bootstrap boot absent",
        ))?;
        if !Rc::ptr_eq(boot_owner, &token.boot) {
            return Err(ProviderError::Correlation(
                "native whole11 bootstrap issuer differs",
            ));
        }
        let boot = boot_owner
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native whole11 bootstrap boot borrowed"))?;
        boot.ensure_origin()?;
        if original.startup.is_some() != startup || boot.requires_startup_codec_data()? != startup {
            return Err(ProviderError::Correlation(
                "private bootstrap codec edition differs",
            ));
        }
        if boot.requires_invocation_codec_data()? != invocation {
            return Err(ProviderError::Correlation(
                "private invocation edition differs",
            ));
        }
        if invocation {
            boot.authenticate_invocation_owned_data()?;
        } else if startup {
            boot.borrowed_startup_protocol_view()?;
        } else {
            boot.borrowed_owned11_protocol_view()?;
        }
        if invocation {
            invocation_data::authenticate_original(original, &boot)?;
        } else {
            startup_codec::authenticate_original(original, &boot, startup)?;
        }
        if boot
            .policy
            .as_ref()
            .is_none_or(|policy| !Rc::ptr_eq(policy, &token.policy))
            || original.launch.is_some()
            || original.launch_value.is_none()
            || original.boot_value.is_none()
            || original.reader.stream_ref().cut.is_some()
        {
            return Err(ProviderError::Correlation(
                "native whole11 bootstrap transfer unresolved",
            ));
        }
        let reader = original.reader.original_owned11_facts(&original.literals)?;
        if reader.failed || reader.last_original_slot != Some(1) {
            return Err(ProviderError::Correlation(
                "native whole11 private reader unresolved",
            ));
        }
        ensure_closed_original(original)?;
        let literals = original
            .literals
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native whole11 private literal bank borrowed"))?;
        if literals.frames().count() != 2
            || literals.frames().any(|frame| {
                frame.direction != crate::transport::original_frames::FrameDirection::Incoming
                    || !frame.complete
                    || frame.transferred != frame.bytes.len()
            })
        {
            return Err(ProviderError::Correlation(
                "native whole11 private literal suffix unresolved",
            ));
        }
        Ok(Self {
            original,
            startup,
            invocation,
            reader,
            literals,
            boot,
        })
    }

    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        if self.startup {
            return Err(ProviderError::Correlation(
                "bootstrap14 requires startup observer",
            ));
        }
        self.observe_metadata_at_edition(observer)
    }

    pub(crate) fn observe_startup_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        if !self.startup || self.invocation {
            return Err(ProviderError::Correlation(
                "bootstrap startup edition absent",
            ));
        }
        self.observe_metadata_at_edition(observer)
    }

    pub(crate) fn observe_invocation_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        if !self.invocation {
            return Err(ProviderError::Correlation(
                "bootstrap invocation edition absent",
            ));
        }
        self.observe_metadata_at_edition(observer)
    }

    fn authenticate_data_edition(&self) -> Result<(), ProviderError> {
        if self.invocation {
            invocation_data::authenticate_original(self.original, &self.boot)
        } else {
            startup_codec::authenticate_original(self.original, &self.boot, self.startup)
        }
    }

    fn observe_metadata_at_edition(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.boot.ensure_origin()?;
        ensure_closed_original(self.original)?;
        self.authenticate_data_edition()?;
        let Bootstrap {
            reader: _,
            literals,
            launch_value,
            launch_bytes,
            launch,
            boot_value,
            boot,
            startup: _,
        } = self.original;
        observer.boxed_value(self.original)?;
        // Both retained strong owners are real: the reader's original bank and
        // Bootstrap.literals. The SDK correspondence check proves this alias.
        self.original.reader.original_owned11_facts(literals)?;
        observer.shared_original(MetadataSharedKind::PrivateBootstrapBank, literals.as_ref())?;
        self.literals.observe_owned11_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::PrivateBootstrapBank, literals.as_ref())?;
        self.literals.observe_owned11_metadata(observer)?;
        observer.observe(launch_value)?;
        if self.invocation {
            invocation_data::observe_launch_bytes(launch_bytes, observer)?;
        } else {
            observer.observe(launch_bytes)?;
        }
        // Success transferred the actual typed launch into the endpoint owner;
        // its historical slot remains exactly None and allocates no new value.
        if launch.is_some() {
            return Err(ProviderError::Correlation(
                "native private launch not transferred",
            ));
        }
        observer.observe(boot_value)?;
        let boot = boot
            .as_ref()
            .ok_or(ProviderError::Correlation("native private boot absent"))?;
        observer.shared_original(MetadataSharedKind::NativeBoot, boot.as_ref())?;
        if self.invocation {
            self.boot.observe_invocation_metadata(observer)?;
        } else if self.startup {
            self.boot.observe_startup_metadata(observer)?;
        } else {
            self.boot.observe_owned11_metadata(observer)?;
        }
        observer.observe(&self.reader.maximum_bytes)?;
        observer.observe(&self.reader.maximum_nesting)?;
        observer.observe(&self.reader.failed)?;
        observer.observe(&self.reader.last_original_slot)?;
        if let Some(startup) = &self.original.startup {
            startup_codec::observe_startup(startup, observer)?;
        }
        Ok(())
    }
}

fn ensure_closed_original(original: &Bootstrap<std::io::Stdin>) -> Result<(), ProviderError> {
    let mut probe = [0u8; 1];
    match rustix::net::recv(
        &original.reader.stream_ref().original,
        &mut probe,
        rustix::net::RecvFlags::DONTWAIT | rustix::net::RecvFlags::PEEK,
    ) {
        Ok((_, 0)) => Ok(()),
        Ok(_) => Err(ProviderError::Correlation(
            "native private channel has an unrecorded suffix",
        )),
        Err(error) if error == rustix::io::Errno::AGAIN => Err(ProviderError::Correlation(
            "native private channel remains live",
        )),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}

impl Serialize for OriginalNativeBootstrapOwned11<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.boot
            .ensure_origin()
            .map_err(serde::ser::Error::custom)?;
        ensure_closed_original(self.original).map_err(serde::ser::Error::custom)?;
        let Bootstrap {
            reader: _,
            literals: _,
            launch_value,
            launch_bytes,
            launch,
            boot_value,
            boot: _,
            startup: _,
        } = self.original;
        if self.invocation {
            return invocation_data::serialize_original(self, serializer);
        }
        if self.startup {
            return startup_codec::serialize_original(self, serializer);
        }
        if self.original.startup.is_some() {
            return Err(serde::ser::Error::custom(
                "bootstrap14 requires explicit startup view",
            ));
        }
        let boot_view = self
            .boot
            .borrowed_owned11_protocol_view()
            .map_err(serde::ser::Error::custom)?;
        (
            "source-private.native-private-bootstrap/11",
            "closed-original-private-stream",
            "original-cut-transferred",
            &self.reader,
            self.literals.protocol_view_with_encoding(true),
            launch_value,
            (
                launch_bytes.capacity(),
                crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(launch_bytes),
            ),
            launch.is_none(),
            boot_value,
            boot_view,
        )
            .serialize(serializer)
    }
}

impl OriginalNativeBootstrapOwned11<'_> {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.boot.ensure_origin()?;
        self.authenticate_data_edition()?;
        ensure_closed_original(self.original)?;
        let Bootstrap {
            reader: _,
            literals,
            launch_value,
            launch_bytes,
            launch,
            boot_value,
            boot,
            startup: _,
        } = self.original;
        // The successful Any slot owns this concrete Box independently of every
        // Rc. Its real payload is counted, not only the fat Box pointer header.
        observer.boxed_value(self.original)?;
        self.original.reader.original_owned11_facts(literals)?;
        if roots.observe_shared(
            observer,
            MetadataSharedKind::PrivateBootstrapBank,
            literals.as_ref(),
        )? {
            self.literals.observe_owned11_metadata(observer)?;
        }
        // Reader and Bootstrap each retain one actual strong owner of this bank.
        if roots.observe_shared(
            observer,
            MetadataSharedKind::PrivateBootstrapBank,
            literals.as_ref(),
        )? {
            self.literals.observe_owned11_metadata(observer)?;
        }
        observer.observe(launch_value)?;
        if self.invocation {
            invocation_data::observe_launch_bytes(launch_bytes, observer)?;
        } else {
            observer.observe(launch_bytes)?;
        }
        if launch.is_some() {
            return Err(ProviderError::Correlation(
                "native private launch not transferred",
            ));
        }
        observer.observe(boot_value)?;
        let boot = boot
            .as_ref()
            .ok_or(ProviderError::Correlation("native private boot absent"))?;
        if roots.observe_shared(observer, MetadataSharedKind::NativeBoot, boot.as_ref())? {
            self.boot.observe_unique_capture_metadata(roots, observer)?;
        }
        observer.observe(&self.reader.maximum_bytes)?;
        observer.observe(&self.reader.maximum_nesting)?;
        observer.observe(&self.reader.failed)?;
        observer.observe(&self.reader.last_original_slot)?;
        self.boot.ensure_origin()?;
        ensure_closed_original(self.original)
    }
}

#[path = "bootstrap_startup_owned.rs"]
mod startup_codec;

#[path = "bootstrap_invocation_owned.rs"]
mod invocation_data;

impl OriginalNativeBootstrapOwned11<'_> {
    pub(in crate::reference_packet::service) fn invocation_wire_counter_scratch_data() -> usize {
        invocation_data::wire_counter_scratch_data()
    }
}
