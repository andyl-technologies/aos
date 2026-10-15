//! Lends complete boot6 connection data under an explicit startup edition.
//!
//! The old connection11 adapter still refuses a startup token. This adapter
//! preserves every same Connection/reader/codec/blob/guard owner and uses the
//! original startup-aware token; historical data creates no live constructor.

use super::native_owned11::{NativeCodecView, NativeConnectionView};
use super::*;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use serde::{Serialize, Serializer};

pub(super) struct NativeStartupConnectionView<'a>(
    pub(super) &'a Connection<crate::client::DeadlineStream>,
);

impl Serialize for NativeStartupConnectionView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let connection = self.0;
        let codec = connection
            .native5_codec
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native codec absent"))?;
        let frames = connection
            .original_frames
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native literal owner absent"))?;
        let bank = frames
            .try_borrow()
            .map_err(|_| serde::ser::Error::custom("native literal bank borrowed"))?;
        let blobs = connection
            .native5_blobs
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native blob owner absent"))?
            .borrowed_owned11_protocol_view()
            .map_err(serde::ser::Error::custom)?;
        let admission = connection
            .original_native_owned11_admission()
            .map_err(serde::ser::Error::custom)?;
        let token = admission
            .borrowed_startup_protocol_view(connection)
            .map_err(serde::ser::Error::custom)?;
        // The reader and Connection each own the same bank. Both strong edges
        // are walked; historical reconstruction allocates the shared bank once.
        (
            "source-private.native-connection-complete-startup/14",
            "historical-source-owner",
            connection.authority.historical_owned_view(),
            connection.guard.protocol_view(),
            NativeCodecView(codec),
            NativeCodecView(codec),
            bank.protocol_view_with_encoding(true),
            connection
                .reader
                .original_owned11_facts(frames)
                .map_err(serde::ser::Error::custom)?,
            blobs,
            "source-private.native-supervisor-owner/11",
            connection.packet_schema,
            connection.connected_packet_schema,
            connection.fenced,
            "provider",
            token,
        )
            .serialize(serializer)
    }
}

impl NativeStartupConnectionView<'_> {
    pub(super) fn observe(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        let connection = self.0;
        observer.shared_original(
            MetadataSharedKind::ProtocolOwner,
            connection.protocol_owner.as_ref(),
        )?;
        connection.authority.observe_retained_metadata(observer)?;
        connection.guard.observe_owned_metadata(observer)?;
        let codec = connection
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("native codec absent"))?;
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(ProviderError::Correlation(
                "native complete codec role changed",
            ));
        };
        // The actual erased verifier and typed owner are the same Rc, guarded
        // before entry; both real edges retain full payload correspondence.
        for _ in 0..2 {
            observer.shared_original(MetadataSharedKind::Codec, codec.as_ref())?;
            observer.shared_original(MetadataSharedKind::NativePolicy, policy.as_ref())?;
            policy.observe_owned11_metadata(observer)?;
        }
        let frames = connection
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("native literal owner absent"))?;
        connection.reader.original_owned11_facts(frames)?;
        let bank = frames
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native literal bank borrowed"))?;
        for _ in 0..2 {
            observer.shared_original(MetadataSharedKind::FrameBank, frames.as_ref())?;
            bank.observe_owned11_metadata(observer)?;
        }
        connection
            .native5_blobs
            .as_ref()
            .ok_or(ProviderError::Correlation("native blob owner absent"))?
            .borrowed_owned11_protocol_view()?
            .observe_owned11_metadata(observer)?;
        observer.shared_original(
            MetadataSharedKind::NativeSupervisor,
            connection.supervisor.as_ref(),
        )?;
        connection
            .original_native_owned11_admission()?
            .observe_startup_metadata(connection, observer)
    }
}

impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn observe_original_startup_connection_metadata(
        &mut self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        // Authority failure retains the actual containment behavior. Run this
        // mutable check before taking any service/registrar metadata loan.
        self.authenticate_original_startup_connection_data()?;
        NativeStartupConnectionView(self).observe(observer)
    }

    pub(crate) fn observe_original_startup_connection_unique_metadata(
        &mut self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        // Authority failure retains the actual containment behavior. Run this
        // mutable check before taking any service/registrar metadata loan.
        self.authenticate_original_startup_connection_data()?;
        NativeConnectionView(self).observe_unique_capture_metadata(roots, observer)
    }

    fn authenticate_original_startup_connection_data(&mut self) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.check_authority()?;
        if self.role != EndpointRole::Provider
            || self.fenced
            || self.original_restore_inputs.is_some()
            || self.original_complete_restoration.is_some()
            || self.original_restore_responses.iter().any(Option::is_some)
        {
            return Err(ProviderError::Correlation(
                "native startup Connection owner phase",
            ));
        }
        let token = self.original_native_owned11_admission()?;
        token.authenticate_current(self)?;
        let boot = token
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native startup boot borrowed"))?;
        let _view = boot.borrowed_startup_protocol_view()?;
        Ok(())
    }
}

/// Selects only the data edition of the same actual current connection.
pub(super) struct NativeCurrentConnectionView<'a> {
    connection: &'a Connection<crate::client::DeadlineStream>,
    startup: bool,
}

impl<'a> NativeCurrentConnectionView<'a> {
    pub(super) fn borrow_original(
        connection: &'a Connection<crate::client::DeadlineStream>,
    ) -> Result<Self, ProviderError> {
        let token = connection.original_native_owned11_admission()?;
        token.authenticate_current(connection)?;
        let startup = token
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native startup boot borrowed"))?
            .requires_startup_codec_data()?;
        Ok(Self {
            connection,
            startup,
        })
    }

    pub(super) fn observe(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        if self.startup {
            NativeStartupConnectionView(self.connection).observe(observer)
        } else {
            NativeConnectionView(self.connection).observe(observer)
        }
    }

    pub(super) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        // The existing structured walk calls the boot's data-only edition
        // dispatch, including every actual startup child before finishing roots.
        NativeConnectionView(self.connection).observe_unique_capture_metadata(roots, observer)
    }
}

impl Serialize for NativeCurrentConnectionView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.startup {
            NativeStartupConnectionView(self.connection).serialize(serializer)
        } else {
            NativeConnectionView(self.connection).serialize(serializer)
        }
    }
}

/// Reports only fixed borrowed connection/counter headers for startup codecs.
///
/// Retained roots, physical row/alias banks, compiler and recursive frames and
/// allocator overhead require independent admission before invoking a walk.
pub(crate) fn counter_scratch_data() -> usize {
    [
        std::mem::size_of::<NativeStartupConnectionView<'static>>(),
        std::mem::size_of::<NativeCurrentConnectionView<'static>>(),
        std::mem::size_of::<MetadataObserver<'static>>(),
        std::mem::size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .unwrap_or(usize::MAX)
}
