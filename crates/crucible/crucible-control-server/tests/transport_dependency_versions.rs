//! Regression checks for the resolved HTTP/2 and TLS transport versions.

fn workspace_lockfile() -> String {
    // Bazel selects its resolved SDK lock; Cargo checks its workspace oracle.
    let path = std::env::var_os("AOS_TRANSPORT_LOCKFILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock")
        });
    std::fs::read_to_string(path).expect("read the selected transport dependency lockfile")
}

#[test]
fn transport_dependencies_retain_required_protocol_fixes() {
    let lockfile = workspace_lockfile();
    assert!(
        package_version(&lockfile, "h2") >= Some((0, 4, 16)),
        "the resolved h2 release must retain bounded empty DATA-frame handling"
    );
    assert!(
        package_version(&lockfile, "rustls") >= Some((0, 23, 46)),
        "the resolved rustls release must retain the required TLS 1.3 handshake fixes"
    );
}

fn package_version(lockfile: &str, package_name: &str) -> Option<(u64, u64, u64)> {
    let expected_name = format!("name = \"{package_name}\"");
    let mut lines = lockfile.lines();

    while let Some(line) = lines.next() {
        if line != expected_name {
            continue;
        }

        for package_line in lines.by_ref() {
            if package_line == "[[package]]" {
                break;
            }
            if let Some(version) = package_line.strip_prefix("version = \"") {
                return parse_version(version.trim_end_matches('"'));
            }
        }
    }

    None
}

fn parse_version(version: &str) -> Option<(u64, u64, u64)> {
    let mut components = version.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let patch = components.next()?.parse().ok()?;

    Some((major, minor, patch))
}
