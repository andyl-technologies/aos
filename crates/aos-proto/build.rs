fn main() -> Result<(), Box<dyn std::error::Error>> {
    verify_sandbox_compatibility()?;
    verify_sandbox_local_compatibility()?;

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

fn verify_sandbox_local_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("src/proto/aos/sandbox/local/v1/brokers.proto");
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
        &["rpc QueryRuntimeEffect(QueryRuntimeEffectRequest) returns (QueryRuntimeEffectResponse);"],
    )?;
    println!("cargo:rerun-if-changed=src/proto/aos/sandbox/local/v1/compatibility-v1.txt");
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
