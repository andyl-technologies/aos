//! Authenticates the actual closed invocation bootstrap before data observation.
//!
//! No historical label, decoded purpose or MAC alone creates this private loan.
//! The service supplies its same retained Any owner and current admission token.

use super::*;
use crate::reference_packet::service::native_startup::decode_original_native_invocation_preamble_data;

pub(super) fn authenticate_original(
    original: &Bootstrap<OriginalPrivateBootstrapInput>,
    boot: &super::super::super::boot::NativeAckBoot,
) -> Result<(), ProviderError> {
    let invalid = || ProviderError::Correlation("invocation bootstrap owner differs");
    let startup = original.startup.as_ref().ok_or_else(invalid)?;
    if startup.creator != std::process::id()
        || startup.thread != std::thread::current().id()
        || !startup.native_issued
        || startup.failed
        || original.launch_bytes.len() != startup.maximum_launch_bytes
    {
        return Err(invalid());
    }
    let facts = decode_original_native_invocation_preamble_data(&startup.preamble)?;
    boot.authenticate_invocation_bootstrap_preamble_data(&startup.preamble, &facts)?;
    if facts.private_bootstrap != startup.private_bootstrap
        || facts.native_birth != startup.native_birth
        || facts.restore_prepare != startup.restore_prepare
        || facts.controller_pid != startup.expected_controller_pid
        || facts.controller_uid != startup.expected_controller_uid
        || facts.launch_bytes as usize != startup.maximum_launch_bytes
        || facts.maximum_boot_bytes as usize != startup.maximum_boot_bytes
        || blake3::hash(&original.launch_bytes).as_bytes() != &facts.launch_digest
    {
        return Err(invalid());
    }
    let wrapper = original
        .launch_value
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if wrapper.len() != 3
        || wrapper
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(6)
    {
        return Err(invalid());
    }
    let launch = wrapper
        .get("launch")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    boot.authenticate_startup_controller_data(launch, facts.controller_pid, facts.controller_uid)?;
    let literals = original
        .literals
        .try_borrow()
        .map_err(|_| ProviderError::Conflict("invocation private bank borrowed"))?;
    let boot_bytes = literals
        .frames()
        .nth(1)
        .ok_or_else(invalid)?
        .bytes
        .len()
        .checked_sub(4)
        .ok_or_else(invalid)?;
    if boot_bytes > startup.maximum_boot_bytes {
        return Err(invalid());
    }
    Ok(())
}

// The new class preserves the complete byte literal in its compact wire bank.
// Metadata owns one allocation regardless of initialized primitive byte count.
pub(super) fn observe_launch_bytes(
    bytes: &Vec<u8>,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    observer.vector::<u8>(bytes.capacity())?;
    observer.observe(&bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::records::MetadataRecordBank;

    #[test]
    fn invocation_launch_bank_accounts_real_spare_capacity_without_byte_visits() {
        let mut bytes = Vec::with_capacity(450_013);
        bytes.resize(400_000, b'x');
        let mut rows = MetadataRecordBank::reserve(4).unwrap();
        let mut observer = MetadataObserver::recording(&mut rows);
        observe_launch_bytes(&bytes, &mut observer).unwrap();
        let facts = observer.finish();

        assert_eq!(facts.vector_banks, 1);
        assert_eq!(facts.vector_capacity_bytes, bytes.capacity());
        assert_eq!(facts.observed_nodes, 1);
        assert_eq!(rows.rows().len(), 1);
        assert_eq!(rows.rows()[0].extent, bytes.capacity());
        assert_eq!(bytes.len(), 400_000);
        assert!(bytes.iter().all(|byte| *byte == b'x'));
    }
}

struct InvocationStartupFields<'a>(&'a super::super::admitted::OriginalNativeStartupBootstrap);

impl Serialize for InvocationStartupFields<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let owner = self.0;
        (
            "source-private.native-startup-bootstrap-owner/15",
            owner.creator,
            "same-original-thread",
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(&owner.preamble),
            &owner.private_bootstrap,
            &owner.native_birth,
            &owner.restore_prepare,
            owner.expected_controller_pid,
            owner.expected_controller_uid,
            owner.maximum_launch_bytes,
            owner.maximum_boot_bytes,
            "original-startup-cut-transferred",
            owner.native_issued,
            owner.failed,
        )
            .serialize(serializer)
    }
}

pub(super) fn serialize_original<S: Serializer>(
    original: &OriginalNativeBootstrapOwned11<'_>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    authenticate_original(original.original, &original.boot).map_err(serde::ser::Error::custom)?;
    ensure_closed_original(original.original).map_err(serde::ser::Error::custom)?;
    let owner = original.original;
    let boot = original
        .boot
        .borrowed_invocation_protocol_view()
        .map_err(serde::ser::Error::custom)?;
    let base = (
        "source-private.native-private-bootstrap/15",
        "closed-original-private-stream",
        "original-cut-transferred",
        &original.reader,
        original.literals.protocol_view_with_encoding(true),
        &owner.launch_value,
        (
            owner.launch_bytes.capacity(),
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(&owner.launch_bytes),
        ),
        owner.launch.is_none(),
        &owner.boot_value,
        boot,
    );
    (
        "source-private.native-private-bootstrap-invocation/15",
        base,
        InvocationStartupFields(
            owner
                .startup
                .as_ref()
                .ok_or_else(|| serde::ser::Error::custom("invocation startup absent"))?,
        ),
    )
        .serialize(serializer)
}

pub(super) fn wire_counter_scratch_data() -> usize {
    std::mem::size_of::<InvocationStartupFields<'static>>()
        + std::mem::size_of::<[&serde_json::Value; 2]>()
        + 4 * std::mem::size_of::<&str>()
}
