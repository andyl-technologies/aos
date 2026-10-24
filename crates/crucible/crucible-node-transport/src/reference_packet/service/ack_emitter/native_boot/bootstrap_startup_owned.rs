//! Preserves the actual fixed admitted bootstrap owner in an explicit codec.
//!
//! Its compact336-byte preamble contains private key material and is never
//! formatted for diagnostics. The clock cut is an opaque historical marker;
//! no process-private clock coordinate, thread, descriptor or permission is
//! exported or reconstructed.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use crate::reference_packet::service::native_startup::{
    PacketNativeStartupAllocationRow, decode_original_native_startup_preamble_data,
};

fn refused() -> ProviderError {
    ProviderError::Correlation("native startup private bootstrap owner differs")
}

fn row(
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

pub(super) fn observe_startup(
    startup: &super::super::admitted::OriginalNativeStartupBootstrap,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let super::super::admitted::OriginalNativeStartupBootstrap {
        creator,
        thread: _,
        preamble,
        private_bootstrap,
        native_birth,
        restore_prepare,
        expected_controller_pid,
        expected_controller_uid,
        maximum_launch_bytes,
        maximum_boot_bytes,
        original_cut: _,
        native_issued,
        failed,
    } = startup;
    observer.observe(creator)?;
    observer.observe(&preamble.len())?;
    row(private_bootstrap, observer)?;
    row(native_birth, observer)?;
    observer.observe(&restore_prepare.is_some())?;
    if let Some(prepare) = restore_prepare {
        row(prepare, observer)?;
    }
    observer.observe(expected_controller_pid)?;
    observer.observe(expected_controller_uid)?;
    observer.observe(maximum_launch_bytes)?;
    observer.observe(maximum_boot_bytes)?;
    // Only the existence of the original transferred cut is represented.
    observer.observe(&true)?;
    observer.observe(native_issued)?;
    observer.observe(failed)
}

pub(super) fn authenticate_original(
    original: &Bootstrap<std::io::Stdin>,
    boot: &super::super::super::boot::NativeAckBoot,
    selected: bool,
) -> Result<(), ProviderError> {
    if original.startup.is_some() != selected || boot.requires_startup_codec_data()? != selected {
        return Err(refused());
    }
    let Some(startup) = original.startup.as_ref() else {
        return Ok(());
    };
    if startup.creator != std::process::id()
        || startup.thread != std::thread::current().id()
        || !startup.native_issued
        || startup.failed
        || original.launch_bytes.len() > startup.maximum_launch_bytes
    {
        return Err(refused());
    }
    let facts = decode_original_native_startup_preamble_data(&startup.preamble)?;
    boot.authenticate_startup_bootstrap_preamble_data(&startup.preamble, &facts)?;
    if facts.private_bootstrap != startup.private_bootstrap
        || facts.native_birth != startup.native_birth
        || facts.restore_prepare != startup.restore_prepare
        || facts.controller_pid != startup.expected_controller_pid
        || facts.controller_uid != startup.expected_controller_uid
        || facts.launch_bytes as usize != startup.maximum_launch_bytes
        || facts.maximum_boot_bytes as usize != startup.maximum_boot_bytes
        || original.launch_bytes.len() != startup.maximum_launch_bytes
    {
        return Err(refused());
    }
    let launch = original
        .launch_value
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .ok_or_else(refused)?;
    boot.authenticate_startup_controller_data(launch, facts.controller_pid, facts.controller_uid)?;
    let literals = original
        .literals
        .try_borrow()
        .map_err(|_| ProviderError::Conflict("native private bootstrap bank borrowed"))?;
    let boot_bytes = literals
        .frames()
        .nth(1)
        .ok_or_else(refused)?
        .bytes
        .len()
        .checked_sub(4)
        .ok_or_else(refused)?;
    if boot_bytes > startup.maximum_boot_bytes {
        return Err(refused());
    }
    Ok(())
}

struct StartupFields<'a>(&'a super::super::admitted::OriginalNativeStartupBootstrap);

impl Serialize for StartupFields<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let startup = self.0;
        (
            "source-private.native-startup-bootstrap-owner/14",
            startup.creator,
            "same-original-thread",
            BorrowedCompactBytes::new(&startup.preamble),
            &startup.private_bootstrap,
            &startup.native_birth,
            &startup.restore_prepare,
            startup.expected_controller_pid,
            startup.expected_controller_uid,
            startup.maximum_launch_bytes,
            startup.maximum_boot_bytes,
            "original-startup-cut-transferred",
            startup.native_issued,
            startup.failed,
        )
            .serialize(serializer)
    }
}

pub(super) fn serialize_original<S: Serializer>(
    original: &OriginalNativeBootstrapOwned11<'_>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    authenticate_original(original.original, &original.boot, true)
        .map_err(serde::ser::Error::custom)?;
    ensure_closed_original(original.original).map_err(serde::ser::Error::custom)?;
    let owner = original.original;
    let boot = original
        .boot
        .borrowed_startup_protocol_view()
        .map_err(serde::ser::Error::custom)?;
    let base = (
        "source-private.native-private-bootstrap/14",
        "closed-original-private-stream",
        "original-cut-transferred",
        &original.reader,
        original.literals.protocol_view_with_encoding(true),
        &owner.launch_value,
        (
            owner.launch_bytes.capacity(),
            BorrowedCompactBytes::new(&owner.launch_bytes),
        ),
        owner.launch.is_none(),
        &owner.boot_value,
        boot,
    );
    (
        "source-private.native-private-bootstrap-startup/14",
        base,
        StartupFields(
            owner.startup.as_ref().ok_or_else(|| {
                serde::ser::Error::custom("native bootstrap startup owner absent")
            })?,
        ),
    )
        .serialize(serializer)
}
