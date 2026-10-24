//! Generates portable Distribution messages and separately bound native services.
//!
//! Both generators consume the same descriptor bytes from the source-built
//! protobuf compiler. Native service code is compiled only with `tokio`;
//! portable codecs never depend on the HTTP server or executor.

use std::{error::Error, path::PathBuf, process::Command};

use buffa_codegen::{CodeGenConfig, generated::descriptor::FileDescriptorSet};
use connectrpc_codegen::codegen::{EncodableImpls, Options};

fn main() -> Result<(), Box<dyn Error>> {
    let output = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR is missing")?);
    let descriptor = output.join("terrane.v1.bin");
    let compiler = std::env::var_os("PROTOC").unwrap_or_else(|| "protoc".into());
    let result = Command::new(compiler)
        .arg("--proto_path=proto")
        .arg("--include_imports")
        .arg("--include_source_info")
        .arg(format!("--descriptor_set_out={}", descriptor.display()))
        .arg("proto/terrane.proto")
        .output()?;
    if !result.status.success() {
        return Err(format!(
            "Terrane protobuf compilation failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }

    let bytes = std::fs::read(descriptor)?;
    let descriptors =
        buffa_codegen::tooling_decode_options()?.decode_from_slice::<FileDescriptorSet>(&bytes)?;
    let files = ["terrane.proto".to_owned()];
    let mut portable = CodeGenConfig::default();
    portable.generate_json = true;
    portable.file_per_package = true;
    portable.emit_register_fn = false;
    for file in buffa_codegen::generate(&descriptors.file, &files, &portable)? {
        std::fs::write(output.join(file.name), file.content)?;
    }

    let mut services = Options::default();
    services.buffa.file_per_package = true;
    services
        .buffa
        .extern_paths
        .push((".terrane.v1".into(), "crate::wire::v1".into()));
    services.gate_client_feature = false;
    services.encodable_impls = EncodableImpls::AllMessages;
    let native = output.join("native");
    std::fs::create_dir_all(&native)?;
    for file in
        connectrpc_codegen::codegen::generate_services(&descriptors.file, &files, &services)?
    {
        std::fs::write(native.join(file.name), file.content)?;
    }

    println!("cargo:rerun-if-changed=proto/terrane.proto");
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!(
        "cargo:rerun-if-env-changed={}",
        buffa_codegen::ELEMENT_MEMORY_LIMIT_ENV
    );
    Ok(())
}
