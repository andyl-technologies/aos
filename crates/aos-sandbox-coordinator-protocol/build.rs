//! Generates the separately selected coordinator transport schema.

#[path = "../aos-proto/build_support/coordinator_descriptor.rs"]
mod coordinator_descriptor;

use coordinator_descriptor::{
    COORDINATOR_FILE, COORDINATOR_PACKAGE, complete_schema_fingerprint, validate_descriptor,
};

const TRANSPORT_FILE: &str = "aos/sandbox/coordinator/v1/coordinator_transport.proto";
const SHARED_FIELD_TYPES: [&str; 5] = [
    "ProtocolVersion",
    "SemanticEnvelope",
    "WatchCursor",
    "WatchEvent",
    "WatchBinding",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    verify_transport_compatibility()?;

    let out_dir =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| {
            std::io::Error::other("OUT_DIR is missing for protobuf code generation")
        })?);
    let descriptor_path = out_dir.join("aos-coordinator-transport-descriptor.bin");
    compile_descriptor(&descriptor_path)?;
    let descriptor = std::fs::read(&descriptor_path)?;
    validate_descriptor(&descriptor, COORDINATOR_FILE)?;
    validate_descriptor(&descriptor, TRANSPORT_FILE)?;

    // Only the transport file is generated. Imported shared fields retain
    // their one original Rust owner, including its JSON and borrowed views.
    let mut config = buffa_codegen::CodeGenConfig::default();
    config.generate_json = true;
    config.extern_paths = SHARED_FIELD_TYPES
        .iter()
        .map(|name| {
            (
                format!(".{COORDINATOR_PACKAGE}.{name}"),
                format!("::aos_proto::aos::sandbox::coordinator::v1::{name}"),
            )
        })
        .collect();
    connectrpc_build::Config::new()
        .descriptor_set(&descriptor_path)
        .files(&[TRANSPORT_FILE])
        .buffa_config(config)
        .include_file("_connectrpc.rs")
        .emit_rerun_directives(false)
        .compile()?;

    println!("cargo:rerun-if-changed=src/proto/{TRANSPORT_FILE}");
    println!("cargo:rerun-if-changed=../aos-proto/src/proto/{COORDINATOR_FILE}");
    println!("cargo:rerun-if-changed=../aos-proto/build_support/coordinator_descriptor.rs");
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!(
        "cargo:rerun-if-env-changed={}",
        buffa_codegen::ELEMENT_MEMORY_LIMIT_ENV
    );
    Ok(())
}

/// Compiles the authoritative transport file and its shared import once.
fn compile_descriptor(output_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let protoc = std::env::var("PROTOC").unwrap_or_else(|_| "protoc".to_owned());
    let output = std::process::Command::new(&protoc)
        .arg("--include_imports")
        .arg("--include_source_info")
        .arg(format!("--descriptor_set_out={}", output_path.display()))
        .arg("--proto_path=src/proto/")
        .arg("--proto_path=../aos-proto/src/proto/")
        .arg(format!("src/proto/{TRANSPORT_FILE}"))
        .output()?;
    if !output.status.success() {
        // Never consume a stale descriptor after a failed compiler invocation.
        return Err(std::io::Error::other(format!(
            "protoc ({protoc}) failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(())
}

fn verify_transport_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("src/proto/aos/sandbox/coordinator/v1/coordinator_transport.proto");
    // This complete transport pin complements aos-proto's shared
    // 0x2898_7641_eee4_10f1 pin. They replace the original complete
    // 0xd99c_ce9e_ffb7_be9e baseline after byte-exact declaration relocation.
    const EXPECTED_TRANSPORT_V1_FINGERPRINT: u64 = 0x9741_bfae_c3fa_6c09;
    let actual = complete_schema_fingerprint(source);
    if actual != EXPECTED_TRANSPORT_V1_FINGERPRINT {
        return Err(std::io::Error::other(format!(
            "sandbox coordinator transport v1 compatibility fingerprint changed: expected \
             {EXPECTED_TRANSPORT_V1_FINGERPRINT:#018x}, found {actual:#018x}"
        ))
        .into());
    }
    Ok(())
}
