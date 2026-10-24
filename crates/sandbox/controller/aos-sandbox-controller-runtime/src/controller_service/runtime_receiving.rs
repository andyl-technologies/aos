//! Supplies the concrete installed startup shape before its first owner grows.
//!
//! Only the genuine original opening accepts this DATA. The selected runtime
//! keeps the same opening through parent construction, journal enrollment and
//! worker handoff; ordinary activation retains its existing runtime policy.

use std::mem::size_of;

use aos_sandbox_controller_domain::{ControllerRuntimeCredentialShapeV1, ControllerRuntimeStartupShapeV1};
use aos_sandbox_linux::credential::{CredentialOwnerPolicyV1, FixedRoleCredentialReadV1};

use super::*;

pub(super) fn startup_shape<A: ControllerServerAssembly>(
    public_listener: bool,
    publisher: bool,
) -> ControllerRuntimeStartupShapeV1 {
    let arc_words = 2 * size_of::<usize>();
    ControllerRuntimeStartupShapeV1 {
        parent_bytes: size_of::<ControllerParentCustodyV1<A>>(),
        fixed_destination_bytes: ProductionEffectExecutor::inactive_receiving_bytes_v1(),
        worker_bytes: size_of::<ControllerWorkerCustodyV1>() + arc_words
            + resident_custody::ControllerFoundationOriginalsV1::receiving_bytes_v1(),
        bank_bytes: size_of::<Mutex<aos_sandbox_controller_domain::ControllerResourceBankOpeningV1>>() + arc_words,
        sessions_bytes: size_of::<Mutex<ControllerBrokerSessions>>() + arc_words,
        capability_bytes: size_of::<Mutex<CapabilityState>>() + arc_words,
        service_bytes: 2 * (size_of::<CapabilityService>() + arc_words),
        command_bytes: size_of::<ControllerCommand>(),
        event_bytes: size_of::<super::worker::WorkerEvent>(),
        application_bytes: 2 * size_of::<A::Application>(),
        // The exact selected Runtime is allocated once behind this Arc.
        runtime_bytes: size_of::<tokio::runtime::Runtime>() + arc_words,
        publisher_future_bytes: if publisher {
            publisher_ingress::selected_observation_future_bytes()
        } else { 0 },
        publisher_session_bytes: if publisher {
            aos_sandbox_publisher::publisher_sessions::PublisherSessionRegistry::selected_one_slot_bytes_v1()
        } else { 0 },
        publisher,
        public_listener,
    }
}

pub(super) fn credential_shape<A: ControllerServerAssembly>(
    public_api: bool,
    cache_bundle: bool,
    publisher: bool,
) -> ControllerRuntimeCredentialShapeV1 {
    // Five raw policy inputs remain resident: ownership and Host/Mount for
    // each worker/executor signer. Their decoded TrustPolicy vectors are local
    // to sequential constructors, not fields of completed anchors/authorities.
    // At most two models for ONE input coexist while its validator redecodes;
    // prior successful constructors keep canonical bytes and selected keys.
    // Decoder::new still prevalidates COMPLETE canonical CBOR. Wrong-schema
    // one-byte elements count at this unchanged negative allocation frontier.
    const POLICY_BYTES: usize = 64 * 1024;
    const POLICY_INPUTS: usize = 5;
    const POLICY_COPIES: usize = 2;
    const POLICY_PEAK_INPUTS: usize = 1;
    // Explicit conservative selected-key cells beside all parsed policy locals.
    // Actual completed configurations retain six; ten also covers current clones.
    const SELECTED_KEY_SLOTS: usize = 2 * POLICY_INPUTS;
    const OWNERSHIP_BYTES: usize = 2 * 32;
    const WORKER_SIGNER_BYTES: usize = 32 + 2 * 32;
    const EXECUTOR_SIGNER_BYTES: usize = WORKER_SIGNER_BYTES + 2 * 16;
    const SIGNER_BYTES: usize = WORKER_SIGNER_BYTES + EXECUTOR_SIGNER_BYTES;
    const ATTACH_BYTES: usize = 2 * 32 + 8 * 1024 + 2048;
    const PINS_BYTES: usize = 2 * 65;
    const CACHE_HOLD_BYTES: usize = 2 * 32 + 3 * 80;
    const SMALL_INPUTS: usize = 16 + OWNERSHIP_BYTES + SIGNER_BYTES
        + ATTACH_BYTES + PINS_BYTES + CACHE_HOLD_BYTES;

    let genesis = aos_sandbox_controller_domain::hierarchy::controller_genesis_input::
        ControllerSourceGenesisInputStartupV1::credential_geometry();
    let tls = if public_api {
        A::public_receiving_credential_geometry()
    } else {
        Some(aos_sandbox_controller_domain::public_api_session::ControllerStartupCredentialGeometryV1 {
            memory_bytes: 0, open_files: 0, metadata_entries: 0,
        })
    };
    let geometry = genesis.as_ref().zip(tls.as_ref());
    // Constructors consume their converted path before returning from open.
    // One conversion can coexist with the retained directories below; its
    // bound uses the same inherited MAX_ARG_STRLEN and fixed NAME_MAX limits.
    let joined_paths = FixedRoleCredentialReadV1::joined_path_receiving_bytes_for_lengths_v1(
        131_072, 255,
    );
    let bundle = if cache_bundle { 64 * 1024 * 1024 } else { 0 };
    let publisher = usize::from(publisher);
    let raw = POLICY_INPUTS * POLICY_BYTES + SMALL_INPUTS + bundle + publisher * 64;
    ControllerRuntimeCredentialShapeV1 {
        // Credential constructors may retain original read buffers beside
        // their decoder-facing copy; the bundle uses a move, not a clone.
        raw_bytes: 2 * (raw - bundle) + bundle,
        // Concrete inline role slots are already part of Parent/worker.
        // The ownership donation alone has a separate Arc pointee/control row.
        owner_bytes: size_of::<std::sync::OnceLock<ControllerOwnershipConfigurationV1>>()
            + 2 * size_of::<usize>(),
        trust_key_slots: POLICY_PEAK_INPUTS * POLICY_COPIES * POLICY_BYTES + SELECTED_KEY_SLOTS,
        trust_feature_slots: POLICY_PEAK_INPUTS * POLICY_COPIES * POLICY_BYTES,
        trust_text_bytes: POLICY_INPUTS * POLICY_COPIES * POLICY_BYTES,
        // Only the simple-role CBOR/JSON/SSH carriers belong to this row.
        // Rich initial Source/TLS raw/native/typed costs come from their real
        // producers below, including invalid parser prefixes before rejection.
        parser_bytes: POLICY_INPUTS * POLICY_BYTES + 4 * (8 * 1024 + 2048),
        // Each of seven retained constructors keeps its actual directory
        // OsString. One current var_os temporary can coexist. The selected
        // Linux/4KiB-page exec profile bounds each inherited string by
        // MAX_ARG_STRLEN=32 pages, including EnvironmentFile-supplied input.
        // Joined path/CString scratch has its separate existing frontier.
        // Two actual selected process-bus observations coexist. They share
        // the same inherited Linux exec-string frontier as these directories;
        // no absence is inferred from unit defaults or EnvironmentFile state.
        path_bytes: (8 + 3 * publisher) * 131_072 + 32 * (4096 + 64),
        // Simple constructors run serially. The selected executor signer
        // retains seven exact leaves on failure: seed, two policy/key pairs,
        // Controller scope and independent Mount scope. Other constructors
        // preserve their six-slot shape. Positive constructors retire Files.
        // Node, optional bundle and Publisher's original remain separate.
        credential_files: 7 + 2 + publisher,
        extra_memory_bytes: geometry.and_then(|(source, tls)| {
            source.memory_bytes.checked_add(tls.memory_bytes)?
                .checked_add(joined_paths?)
        }),
        extra_metadata_entries: geometry.and_then(|(source, tls)| {
            // Controller and Mount revocation scopes are two distinct fixed
            // credential names; duplicate constructors do not add namespaces.
            source.metadata_entries.checked_add(tls.metadata_entries)?.checked_add(2)
        }),
        // Actual Source capture/positive native disposal precedes the TLS
        // stage. A Source negative terminates before TLS; these auxiliary FD
        // sets therefore compose by peak, while resident carrier rows sum.
        extra_open_files: geometry.map(|(source, tls)| source.open_files.max(tls.open_files)),
        source_proof_files: genesis.as_ref().map(|source| source.open_files),
        public_tls_memory_bytes: tls.as_ref().map(|tls| tls.memory_bytes),
        public_tls_metadata_entries: tls.as_ref().map(|tls| tls.metadata_entries),
        public_tls_proof_files: tls.as_ref().map(|tls| tls.open_files),
    }
}

pub(super) fn build_runtime(selected: Option<aos_sandbox_controller_domain::ControllerRuntimeTaskEnvelopeV1>) -> Result<tokio::runtime::Runtime, ControllerRuntimeError> {
    let mut builder = tokio::runtime::Builder::new_current_thread();
    builder.enable_all();
    if let Some(envelope) = selected {
        configure_runtime(&mut builder, envelope);
    }
    builder.build().map_err(ControllerRuntimeError::Runtime)
}

fn configure_runtime(builder: &mut tokio::runtime::Builder, envelope: aos_sandbox_controller_domain::ControllerRuntimeTaskEnvelopeV1) {
    builder.max_blocking_threads(envelope.blocking_threads_v1())
        .thread_stack_size(aos_sandbox_controller_domain::CONTROLLER_RUNTIME_STACK_BYTES_V1);
}

pub(super) fn read_node_once(
    read: &mut FixedRoleCredentialReadV1,
) -> Result<[u8; 16], ControllerRuntimeError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or(ControllerRuntimeError::InvalidCredential)?;
    read.read_once(Path::new(&directory), "node-id", 16, 16, false,
        CredentialOwnerPolicyV1::RootOrCurrent);
    complete_node_read_v1(read)
}

fn complete_node_read_v1(
    read: &mut FixedRoleCredentialReadV1,
) -> Result<[u8; 16], ControllerRuntimeError> {
    let bytes = match read.outcome() {
        Some(Ok(Some(bytes))) => bytes,
        _ => return Err(ControllerRuntimeError::InvalidCredential),
    };
    let node = super::activation::parse_node_id(bytes)?;
    // The exact native read and complete typed constructor have finished.
    // The same original keeps bytes/metadata/results, not an unused open File.
    if !read.retire_completed_file_once_v1() {
        return Err(ControllerRuntimeError::InvalidCredential);
    }
    Ok(node)
}

pub(super) fn read_bundle_once(
    read: &mut FixedRoleCredentialReadV1,
) -> Result<Option<Vec<u8>>, ControllerRuntimeError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or(ControllerRuntimeError::InvalidCacheReplayBundle)?;
    read.read_once(Path::new(&directory), "cache-replay-bundle", 1, 64 * 1024 * 1024,
        true, CredentialOwnerPolicyV1::RootOrCurrent);
    match read.outcome() {
        Some(Ok(None)) => Ok(None),
        Some(Ok(Some(_))) => read.take_success_bytes_once().map(Some)
            .ok_or(ControllerRuntimeError::InvalidCacheReplayBundle),
        _ => Err(ControllerRuntimeError::InvalidCacheReplayBundle),
    }
}


// The sole caller is after the actual selected Cache importer and all of its
// native/profile posts returned positively. A read alone cannot invoke this
// disposition in the installed path; failed import retains the original File.
pub(super) fn retire_imported_bundle_read_v1(
    read: &mut FixedRoleCredentialReadV1,
) -> Result<(), ControllerRuntimeError> {
    if read.retire_completed_file_once_v1() { Ok(()) }
    else { Err(ControllerRuntimeError::InvalidCacheReplayBundle) }
}

#[cfg(test)]
mod positive_credential_retirement_tests {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn node_read(bytes: &[u8; 16]) -> (tempfile::TempDir, FixedRoleCredentialReadV1) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node-id");
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut read = FixedRoleCredentialReadV1::prearmed();
        read.read_once(directory.path(), "node-id", 16, 16, false,
            CredentialOwnerPolicyV1::RootOrCurrent);
        (directory, read)
    }

    #[test]
    fn completed_node_constructor_retires_only_its_actual_positive_file() {
        const SELECTOR: &str = "AOS_TEST_POSITIVE_NODE_CREDENTIAL";
        if std::env::var_os(SELECTOR).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "controller_service::runtime_receiving::positive_credential_retirement_tests::completed_node_constructor_retires_only_its_actual_positive_file"])
                .env(SELECTOR, "1").status().unwrap();
            assert!(status.success());
            return;
        }
        let (_directory, mut read) = node_read(&[5; 16]);
        let descriptor = match read.view().open {
            Some(Ok(file)) => file.as_raw_fd(),
            _ => panic!("native positive Node read did not retain its original File"),
        };

        assert_eq!(complete_node_read_v1(&mut read).unwrap(), [5; 16]);

        assert!(read.view().retired_completed_file);
        assert!(read.view().open.is_none());
        assert_eq!(std::fs::read_link(format!("/proc/self/fd/{descriptor}"))
            .unwrap_err().kind(), std::io::ErrorKind::NotFound);
        assert!(matches!(read.outcome(), Some(Ok(Some(bytes))) if bytes.as_slice() == [5; 16]));
        assert!(read.failure().is_none());
    }

    #[test]
    fn invalid_node_constructor_keeps_its_native_original_and_bytes() {
        let (_directory, mut read) = node_read(&[0; 16]);

        assert!(complete_node_read_v1(&mut read).is_err());

        assert!(!read.view().retired_completed_file);
        assert!(matches!(read.view().open, Some(Ok(file)) if file.metadata().is_ok()));
        assert!(matches!(read.outcome(), Some(Ok(Some(bytes))) if bytes.as_slice() == [0; 16]));
    }
}
