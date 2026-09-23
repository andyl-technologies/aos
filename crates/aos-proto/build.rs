fn main() -> Result<(), Box<dyn std::error::Error>> {
    verify_sandbox_compatibility()?;
    verify_sandbox_local_compatibility()?;
    verify_sandbox_coordinator_compatibility()?;

    connectrpc_build::Config::new()
        .files(&[
            "src/proto/aos/cache/v1/cache.proto",
            "src/proto/aos/build/v1/build.proto",
            "src/proto/aos/gc/v1/gc.proto",
            "src/proto/aos/auth/v1/auth.proto",
            "src/proto/aos/hub/v1/hub.proto",
            "src/proto/aos/sandbox/v1/sandbox.proto",
            "src/proto/aos/sandbox/local/v1/brokers.proto",
            "src/proto/aos/sandbox/coordinator/v1/coordinator.proto",
        ])
        .includes(&["src/proto/"])
        .include_file("_connectrpc.rs")
        .compile()?;
    Ok(())
}

fn verify_sandbox_coordinator_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("src/proto/aos/sandbox/coordinator/v1/coordinator.proto");
    // This fingerprint covers the complete comment-free schema, including
    // syntax/package declarations, every message and enum field's spelling,
    // type, cardinality, number, oneof membership, and every RPC signature.
    // A V1 compatibility edit therefore requires an explicit baseline review.
    const EXPECTED_COORDINATOR_V1_FINGERPRINT: u64 = 0xd99c_ce9e_ffb7_be9e;
    let actual = complete_schema_fingerprint(source);
    if actual != EXPECTED_COORDINATOR_V1_FINGERPRINT {
        return Err(std::io::Error::other(format!(
            "sandbox coordinator v1 compatibility fingerprint changed: expected \
             {EXPECTED_COORDINATOR_V1_FINGERPRINT:#018x}, found {actual:#018x}"
        ))
        .into());
    }
    println!("cargo:rerun-if-changed=src/proto/aos/sandbox/coordinator/v1/coordinator.proto");
    Ok(())
}

fn complete_schema_fingerprint(source: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut fingerprint = FNV_OFFSET;
    let mut first = true;
    for declaration in source
        .lines()
        .filter_map(|line| line.split("//").next())
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if !first {
            fingerprint ^= u64::from(b'\n');
            fingerprint = fingerprint.wrapping_mul(FNV_PRIME);
        }
        for byte in declaration.bytes() {
            fingerprint ^= u64::from(byte);
            fingerprint = fingerprint.wrapping_mul(FNV_PRIME);
        }
        first = false;
    }
    fingerprint
}

fn verify_sandbox_local_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("src/proto/aos/sandbox/local/v1/brokers.proto");
    // This covers the complete comment-free V1 schema rather than a sample of
    // declarations: every method tag, enum value, message field/type/
    // cardinality/oneof, reserved tag, and RPC signature are compatibility-owned.
    const EXPECTED_SANDBOX_LOCAL_V1_FINGERPRINT: u64 = 0x1c94_df7c_c0a8_7419;
    let actual = complete_schema_fingerprint(source);
    if actual != EXPECTED_SANDBOX_LOCAL_V1_FINGERPRINT {
        return Err(std::io::Error::other(format!(
            "sandbox local v1 compatibility fingerprint changed: expected \
             {EXPECTED_SANDBOX_LOCAL_V1_FINGERPRINT:#018x}, found {actual:#018x}"
        ))
        .into());
    }
    let fixture = include_str!("src/proto/aos/sandbox/local/v1/compatibility-v1.txt");
    let source_declarations = source
        .lines()
        .filter_map(|line| line.split("//").next())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    for (index, line) in fixture.lines().enumerate() {
        let required = line.trim();
        if required.is_empty() || required.starts_with('#') {
            continue;
        }
        if !source_declarations.contains(&required) {
            return Err(std::io::Error::other(format!(
                "sandbox local v1 compatibility fixture line {} is absent: {required}",
                index + 1
            ))
            .into());
        }
    }
    verify_scoped_declarations(
        &source_declarations,
        "message BrokerClientHello {",
        &["bytes signed_session_hello = 7;"],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message BrokerServerHello {",
        &["bytes signed_session_hello = 8;"],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message BrokerRequestEnvelope {",
        &["bytes signed_session_request = 5;"],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message BrokerResponseEnvelope {",
        &["bytes signed_session_outcome = 7;"],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "enum RuntimeEffectStatus {",
        &[
            "RUNTIME_EFFECT_STATUS_ABSENT = 1;",
            "RUNTIME_EFFECT_STATUS_PENDING = 2;",
            "RUNTIME_EFFECT_STATUS_COMPLETE = 3;",
        ],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message QueryRuntimeEffectRequest {",
        &[
            "RequestHeader header = 1;",
            "bytes original_apply_request = 2;",
        ],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message QueryRuntimeEffectResponse {",
        &["RuntimeEffectStatus status = 1;", "bytes receipt = 2;"],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "service HostBroker {",
        &[
            "rpc QueryRuntimeEffect(QueryRuntimeEffectRequest) returns (QueryRuntimeEffectResponse);",
        ],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "enum BrokerMethod {",
        &[
            "BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT = 25;",
            "BROKER_METHOD_HOST_INSTALL_ATTACH_GATE = 28;",
        ],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message InstallHostAttachGateRequestV1 {",
        &["RequestHeader header = 1;", "bytes pending_grant = 2;"],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message HostAttachGateEvidenceV1 {",
        &[
            "bytes operation_id = 1;",
            "bytes execution_id = 2;",
            "bytes route_digest = 14;",
            "bytes gate_observation_commitment = 15;",
            "bytes signed_gate_readback = 16;",
        ],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message ApplyAtomicStorageSnapshotRequest {",
        &[
            "RequestHeader header = 1;",
            "bytes canonical_plan = 2;",
            "AssignmentFence fence = 3;",
        ],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message AtomicStorageSnapshotResponse {",
        &[
            "bytes program_digest = 1;",
            "bytes observation_digest = 2;",
            "bool observation_required = 3;",
        ],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "service StorageBroker {",
        &[
            "rpc ApplyAtomicSnapshot(ApplyAtomicStorageSnapshotRequest)",
            "returns (AtomicStorageSnapshotResponse);",
        ],
    )?;
    println!("cargo:rerun-if-changed=src/proto/aos/sandbox/local/v1/compatibility-v1.txt");
    println!("cargo:rerun-if-changed=src/proto/aos/sandbox/local/v1/brokers.proto");
    Ok(())
}

fn verify_scoped_declarations(
    source: &[&str],
    scope: &str,
    required: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let start = source
        .iter()
        .position(|line| *line == scope)
        .ok_or_else(|| std::io::Error::other(format!("compatibility scope is absent: {scope}")))?;
    let end = source[start + 1..]
        .iter()
        .position(|line| *line == "}")
        .map(|offset| start + 1 + offset)
        .ok_or_else(|| {
            std::io::Error::other(format!("compatibility scope is unterminated: {scope}"))
        })?;
    let declarations = &source[start + 1..end];
    for declaration in required {
        if !declarations.contains(declaration) {
            return Err(std::io::Error::other(format!(
                "compatibility declaration is absent from {scope}: {declaration}"
            ))
            .into());
        }
    }
    Ok(())
}

fn verify_sandbox_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("src/proto/aos/sandbox/v1/sandbox.proto");
    let fixture = include_str!("src/proto/aos/sandbox/v1/compatibility-v1.txt");
    let source_declarations = source.lines().map(str::trim).collect::<Vec<_>>();
    let mut service_scope = None;
    for (index, line) in fixture.lines().enumerate() {
        let required = line.trim();
        if required.is_empty() || required.starts_with('#') {
            continue;
        }
        if required.starts_with("service ") && required.ends_with(" {") {
            service_scope = Some(required);
            verify_scoped_declarations(&source_declarations, required, &[])?;
            continue;
        }
        if required.starts_with("rpc ") {
            let service = service_scope.ok_or_else(|| {
                std::io::Error::other(format!(
                    "sandbox v1 compatibility RPC has no service scope at line {}: {required}",
                    index + 1
                ))
            })?;
            verify_scoped_declarations(&source_declarations, service, &[required]).map_err(
                |_| {
                    std::io::Error::other(format!(
                        "sandbox v1 compatibility RPC is absent from aos.sandbox.v1.{} at line {}: {required}",
                        service
                            .strip_prefix("service ")
                            .and_then(|value| value.strip_suffix(" {"))
                            .unwrap_or(service),
                        index + 1
                    ))
                },
            )?;
            continue;
        }
        if !source.contains(required) {
            return Err(std::io::Error::other(format!(
                "sandbox v1 compatibility fixture line {} is absent: {required}",
                index + 1
            ))
            .into());
        }
    }
    verify_scoped_declarations(
        &source_declarations,
        "message ExecutionControlRequest {",
        &[
            "MutationContext mutation = 6;",
            "bytes client_public_key = 7;",
            "bytes proof_of_possession = 8;",
        ],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message ExecutionControlResult {",
        &[
            "Operation operation = 4;",
            "OpenSshAccessEndpoint access = 5;",
        ],
    )?;
    verify_scoped_declarations(
        &source_declarations,
        "message ForkSnapshotRequest {",
        &[
            "repeated Feature required_features = 7;",
            "bytes expected_project_resource_version = 8;",
            "Duration operation_timeout = 9;",
        ],
    )?;
    println!("cargo:rerun-if-changed=src/proto/aos/sandbox/v1/compatibility-v1.txt");
    Ok(())
}
