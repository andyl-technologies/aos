//! Generates the build, cache, authentication, and garbage-collection APIs.
//!
//! Protocol definitions live independently of their native implementations.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../../../api/proto";
    let files = [
        "cache/v1/cache.proto",
        "build/v1/build.proto",
        "gc/v1/gc.proto",
        "auth/v1/auth.proto",
    ]
    .map(|path| format!("{proto_root}/aos/{path}"));

    connectrpc_build::Config::new()
        .files(&files)
        .includes(&[proto_root])
        .include_file("_connectrpc.rs")
        .compile()?;

    for file in &files {
        println!("cargo:rerun-if-changed={file}");
    }
    Ok(())
}
