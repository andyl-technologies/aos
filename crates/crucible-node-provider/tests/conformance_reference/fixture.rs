//! Actual source-built service launch with private controller authorization.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crucible_node_contract::*;
use crucible_node_provider::conformance::measure_executable;
use crucible_node_provider::handshake::Limits;
use crucible_node_provider::reference_service::{
    InstalledContent, PublicReferenceProfile, ReferenceProfile, ReferenceServiceBootstrap,
    ReferenceServiceLaunchBootstrap,
};
use serde_json::{Value, json};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub(super) fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

pub(super) struct NativeService {
    pub(super) directory: PathBuf,
    pub(super) process: Child,
    pub(super) profile: ReferenceProfile,
    pub(super) bootstrap: ReferenceServiceBootstrap,
    pub(super) private_bindings: BTreeMap<String, Value>,
}

impl NativeService {
    pub(super) fn launch(provider: &Path, device: &Path, maximum_operations: u64) -> Self {
        Self::launch_selected(provider, device, maximum_operations, None)
    }

    pub(super) fn launch_public_linked(
        provider: &Path,
        device: &Path,
        maximum_operations: u64,
        closed_ingress: bool,
    ) -> Self {
        Self::launch_selected(
            provider,
            device,
            maximum_operations,
            Some(PublicReferenceProfile::ByteLinkedV1 { closed_ingress }),
        )
    }

    fn launch_selected(
        provider: &Path,
        device: &Path,
        maximum_operations: u64,
        selection: Option<PublicReferenceProfile>,
    ) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "cnp-native-conformance-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let profile = match selection {
            Some(PublicReferenceProfile::ByteLinkedV1 { closed_ingress }) => {
                ReferenceProfile::build_public_linked(
                    id("checksum"),
                    id("checksum-owner"),
                    measure_executable(provider).unwrap(),
                    measure_executable(device).unwrap(),
                    U64::new(1000),
                    U64::new(1_000_000_000),
                    closed_ingress,
                )
            }
            _ => ReferenceProfile::build(
                id("checksum"),
                id("checksum-owner"),
                measure_executable(provider).unwrap(),
                measure_executable(device).unwrap(),
                U64::new(1000),
                U64::new(1_000_000_000),
            ),
        }
        .unwrap();
        let placeholder =
            canonical::content_ref(b"private authorization constructed below", "text/plain")
                .unwrap();
        let authority = LiveAuthority {
            schema_version: 1,
            session_id: fresh_id("conformance-session"),
            incarnation_id: fresh_id("conformance-incarnation"),
            realization_id: fresh_id("reference-realization"),
            activation_id: None,
            world_generation: U64::new(0),
            owner_generation: U64::new(1),
            input_epoch: fresh_id("fixture-input-epoch"),
            host_receipt: placeholder,
            extensions: Extensions::new(),
        };
        let (binding, owner_binding) = profile.bind(authority.clone()).unwrap();
        let mut installed = Vec::new();
        let scenario = install_json(
            &mut installed,
            &json!({
                "schema":"reference-conformance-scenario/1","node":"checksum",
                "input_source":"independent controller fixture","qualification":false
            }),
        );
        let ownership = install_json(
            &mut installed,
            &serde_json::to_value(&owner_binding).unwrap(),
        );
        let coordinator = install_json(
            &mut installed,
            &json!({
                "schema":"reference-conformance-controller/1","ordering":"superdense-v1",
                "quantum_ps":"1000","profile":"quantized checksum only","qualification":false
            }),
        );
        let world = WorldBinding {
            schema_version: 1,
            scenario_ref: scenario,
            node_bindings: vec![NodeBindingRef {
                node_id: profile.descriptor.id.clone(),
                binding_hash: binding.identity().unwrap(),
                extensions: Extensions::new(),
            }],
            connections: Vec::new(),
            ownership_ref: ownership,
            coordinator_contract_ref: coordinator,
            ordering_profile: "superdense-v1".into(),
            initialization_ref: profile.descriptor.initialization_ref.clone(),
            extensions: Extensions::new(),
        };
        let resources = ResourceLimits {
            cpu_budget_ns: U64::new(4_000_000_000),
            memory_bytes: U64::new(512 * 1024 * 1024),
            writable_bytes: U64::new(0),
            processes: U64::new(2),
            descriptors: U64::new(32),
            pending_events: U64::new(16),
            content_bytes: U64::new(16 * 1024 * 1024),
            maximum_operations: U64::new(maximum_operations),
            extensions: Extensions::new(),
        };
        let limits = Limits {
            frame_bytes: U64::new(1_048_576),
            nesting: U64::new(64),
            requests: U64::new(16),
            journal_entries: U64::new(256),
            blob_chunk_bytes: U64::new(16_384),
        };
        let token = entropy();
        let mut bootstrap = ReferenceServiceBootstrap::fixture(
            &profile,
            authority,
            token.clone(),
            U64::new(u64::from(rustix::process::geteuid().as_raw())),
            limits,
            resources,
            world.identity().unwrap(),
        )
        .unwrap();
        bootstrap.installed_content.extend(installed);
        bootstrap.validate().unwrap();
        let private_bindings = BTreeMap::from([
            ("launch-token".into(), serde_json::to_value(token).unwrap()),
            (
                "controller-challenge".into(),
                serde_json::to_value(entropy()).unwrap(),
            ),
            (
                "resume-challenge".into(),
                serde_json::to_value(entropy()).unwrap(),
            ),
        ]);

        let process = Command::new(provider)
            .arg(directory.join("control.sock"))
            .arg(device)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut service = Self {
            directory,
            process,
            profile,
            bootstrap,
            private_bindings,
        };
        let private_launch = match selection {
            Some(profile) => serde_json::to_value(ReferenceServiceLaunchBootstrap {
                schema_version: 2,
                profile,
                bootstrap: service.bootstrap.clone(),
            })
            .unwrap(),
            None => serde_json::to_value(&service.bootstrap).unwrap(),
        };
        crucible_node_provider::transport::write_frame(
            &mut service.process.stdin.take().unwrap(),
            &private_launch,
            16 * 1024 * 1024,
        )
        .unwrap();
        let mut ready = false;
        for _ in 0..300 {
            if service.socket().exists() {
                ready = true;
                break;
            }
            assert!(
                service.process.try_wait().unwrap().is_none(),
                "source-built provider exited before accepting connections"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            ready,
            "source-built provider did not open its endpoint under the bounded launch allowance"
        );
        service
    }

    pub(super) fn socket(&self) -> PathBuf {
        self.directory.join("control.sock")
    }

    pub(super) fn private_file(&self, name: &str, value: &Value) -> PathBuf {
        use std::io::Write;
        let path = self.directory.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&canonical::canonical_json(value).unwrap())
            .unwrap();
        file.sync_all().unwrap();
        path
    }
}

impl Drop for NativeService {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn entropy() -> Bytes {
    let mut bytes = vec![0; 32];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut bytes)
        .unwrap();
    Bytes::new(bytes)
}

fn fresh_id(prefix: &str) -> Id {
    // Public live identities use separate entropy from all secret capabilities.
    let suffix = entropy()
        .as_slice()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    id(&format!("{prefix}/{suffix}"))
}

fn install_json(installed: &mut Vec<InstalledContent>, value: &Value) -> ContentRef {
    let bytes = canonical::canonical_json(value).unwrap();
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    installed.push(InstalledContent {
        reference: reference.clone(),
        bytes: Bytes::new(bytes),
    });
    reference
}
