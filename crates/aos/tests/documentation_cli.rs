//! Process checks for explicit documentation sources without Nix or a checkout.

use std::process::{Command, Output};

fn run(arguments: &[&str], hub_environment: bool) -> Output {
    let directory = tempfile::tempdir().expect("temporary home");
    let mut command = Command::new(env!("CARGO_BIN_EXE_aos"));
    command
        .args(arguments)
        .env_clear()
        .env("HOME", directory.path())
        .current_dir(directory.path());
    if hub_environment {
        command
            .env("AOS_HUB", "https://unused.invalid")
            .env("AOS_TOKEN", "private-test-token");
    }
    command.output().expect("run documentation command")
}

#[test]
fn installed_search_needs_neither_hub_nix_nor_checkout() {
    for hub_environment in [false, true] {
        let output = run(
            &["--json", "doc", "package", "--search", "missing"],
            hub_environment,
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON search results");
        assert!(value.to_string().contains("[]"), "{value}");
    }
}

#[test]
fn invalid_documentation_modes_fail_before_loading_any_source() {
    let cases: &[(&[&str], &str)] = &[
        (&["doc", "hub", "query"], "requires --hub"),
        (
            &["doc", "hub", "query", "--hub", "https://example.test"],
            "requires --registry",
        ),
        (
            &[
                "doc",
                "hub",
                "query",
                "--hub",
                "file:///tmp",
                "--registry",
                "org/main",
            ],
            "HTTP(S) origin",
        ),
        (
            &[
                "doc",
                "hub",
                "query",
                "--hub",
                "https://example.test/path",
                "--registry",
                "org/main",
            ],
            "HTTP(S) origin",
        ),
        (
            &[
                "doc",
                "hub",
                "query",
                "--hub",
                "https://example.test",
                "--registry",
                "../main",
            ],
            "organization/registry",
        ),
        (
            &["doc", "package", "aos", "--registry", "org/main"],
            "require `aos doc hub",
        ),
        (
            &["doc", "package", "aos", "--token", "private-test-token"],
            "require `aos doc hub",
        ),
        (
            &["doc", ".", "--hub", "https://example.test"],
            "require `aos doc hub",
        ),
        (&["doc", ".", "--version", "1"], "require `aos doc package"),
        (
            &[
                "doc",
                "package",
                "--search",
                "query",
                "--platform",
                "x86_64-linux",
            ],
            "searches do not accept",
        ),
        (
            &["doc", "package", "aos", "--rebuild"],
            "only to repository",
        ),
        (&["doc", "package", "aos", "--search", "query"], "not both"),
    ];
    for (arguments, expected) in cases {
        let output = run(arguments, false);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{arguments:?}");
        assert!(stderr.contains(expected), "{arguments:?}: {stderr}");
        assert!(
            !stderr.contains("private-test-token"),
            "credential disclosure"
        );
    }
}

#[test]
fn hub_environment_selects_only_explicit_hub_mode() {
    let output = run(&["doc", "hub", "query"], true);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires --registry"), "{stderr}");
    assert!(!stderr.contains("private-test-token"));
}

#[test]
fn installed_exact_selectors_reach_local_lookup() {
    let output = run(
        &[
            "doc",
            "package",
            "missing",
            "--version",
            "1",
            "--platform",
            "x86_64-linux",
        ],
        false,
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no installed documentation"));
}

#[test]
fn explicit_hub_search_uses_remote_source_and_never_falls_back() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind("127.0.0.1:0").expect("Hub fixture listener");
    let origin = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "CLI did not contact selected Hub"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept Hub request: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut request = Vec::new();
        let mut bytes = [0; 4096];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut bytes).expect("request headers");
            assert!(count > 0);
            request.extend_from_slice(&bytes[..count]);
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("header terminator")
            + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let length: usize = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().expect("content length"))
            })
            .expect("request body length");
        while request.len() < header_end + length {
            let count = stream.read(&mut bytes).expect("request body");
            assert!(count > 0);
            request.extend_from_slice(&bytes[..count]);
        }
        let payload: serde_json::Value =
            serde_json::from_slice(&request[header_end..]).expect("search payload");
        assert_eq!(payload["registry"], "org/main");
        assert_eq!(payload["query"], "query");
        let request = String::from_utf8_lossy(&request);
        assert!(
            request
                .starts_with("POST /aos.hub.v1.DocumentationService/SearchPackageDocumentation "),
            "{request}"
        );
        let body = r#"{"code":"unauthenticated","message":"fixture authorization required"}"#;
        write!(stream, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("Hub response");
    });
    let output = run(
        &[
            "doc",
            "hub",
            "query",
            "--hub",
            &origin,
            "--registry",
            "org/main",
        ],
        false,
    );
    server.join().expect("Hub fixture");
    assert!(
        !output.status.success(),
        "unauthorized Hub cannot become successful empty local search"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fixture authorization required") || stderr.contains("401"),
        "{stderr}"
    );
}
