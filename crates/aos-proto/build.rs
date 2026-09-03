fn main() -> Result<(), Box<dyn std::error::Error>> {
    verify_sandbox_compatibility()?;

    connectrpc_build::Config::new()
        .files(&[
            "src/proto/aos/cache/v1/cache.proto",
            "src/proto/aos/build/v1/build.proto",
            "src/proto/aos/gc/v1/gc.proto",
            "src/proto/aos/auth/v1/auth.proto",
            "src/proto/aos/hub/v1/hub.proto",
            "src/proto/aos/sandbox/v1/sandbox.proto",
            "src/proto/aos/sandbox/local/v1/brokers.proto",
        ])
        .includes(&["src/proto/"])
        .include_file("_connectrpc.rs")
        .compile()?;
    Ok(())
}

fn verify_sandbox_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("src/proto/aos/sandbox/v1/sandbox.proto");
    let fixture = include_str!("src/proto/aos/sandbox/v1/compatibility-v1.txt");
    for (index, line) in fixture.lines().enumerate() {
        let required = line.trim();
        if required.is_empty() || required.starts_with('#') {
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
    println!("cargo:rerun-if-changed=src/proto/aos/sandbox/v1/compatibility-v1.txt");
    Ok(())
}
