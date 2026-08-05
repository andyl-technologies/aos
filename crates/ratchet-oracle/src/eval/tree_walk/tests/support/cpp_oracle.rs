//! Tree-walk test support: C++ Nix oracle invocation helpers.

use super::super::*;

pub(crate) fn cpp_nix_oracle() -> String {
    std::env::var("AOS_NIX_ORACLE").unwrap_or_else(|_| "nix-instantiate".to_owned())
}

pub(crate) fn trim_command_stdout(mut stdout: Vec<u8>) -> Vec<u8> {
    while matches!(stdout.last(), Some(b'\n' | b'\r')) {
        let _ = stdout.pop();
    }
    stdout
}

pub(crate) fn cpp_nix_version(oracle: &str) -> String {
    let output = Command::new(oracle)
        .arg("--version")
        .output()
        .expect("C++ Nix oracle runs");
    assert!(
        output.status.success(),
        "C++ Nix oracle version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(trim_command_stdout(output.stdout)).expect("version is UTF-8")
}

pub(crate) fn assert_pinned_cpp_nix_oracle(oracle: &str) {
    let version = cpp_nix_version(oracle);
    let pinned = std::str::from_utf8(PINNED_NIX_VERSION).expect("pinned version is UTF-8");
    assert!(
        version.ends_with(&format!(" {pinned}")) || version.ends_with(&format!("(Nix) {pinned}")),
        "expected pinned C++ Nix {pinned} oracle, got {version}"
    );
    eprintln!("C++ Nix oracle: {version}");
}

pub(crate) fn cpp_nix_eval_json(oracle: &str, source: &str) -> Vec<u8> {
    let mut command = Command::new(oracle);
    command.args(["--eval", "--strict", "--json", "--expr", source]);
    let output = command
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    trim_command_stdout(output.stdout)
}

pub(crate) fn cpp_nix_eval_raw(oracle: &str, source: &str) -> Vec<u8> {
    let mut command = Command::new(oracle);
    command.args(["--eval", "--strict", "--expr", source]);
    let output = command
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    trim_command_stdout(output.stdout)
}

pub(crate) fn cpp_nix_eval_json_with_nix_options(
    oracle: &str,
    source: &str,
    options: &[(&str, &str)],
) -> Vec<u8> {
    let mut command = Command::new(oracle);
    for (name, value) in options {
        command.args(["--option", name, value]);
    }
    command.args(["--eval", "--strict", "--json", "--expr", source]);
    let output = command
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    trim_command_stdout(output.stdout)
}

pub(crate) fn cpp_nix_eval_stderr_with_nix_options(
    oracle: &str,
    source: &str,
    options: &[(&str, &str)],
) -> Vec<u8> {
    let output = cpp_nix_eval_stderr_output_with_nix_options(oracle, source, options);
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stderr
}

pub(crate) fn cpp_nix_eval_failure_stderr_with_nix_options(
    oracle: &str,
    source: &str,
    options: &[(&str, &str)],
) -> Vec<u8> {
    let output = cpp_nix_eval_stderr_output_with_nix_options(oracle, source, options);
    assert!(
        !output.status.success(),
        "C++ Nix oracle unexpectedly succeeded for {source:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    output.stderr
}

pub(crate) fn cpp_nix_eval_stderr_output_with_nix_options(
    oracle: &str,
    source: &str,
    options: &[(&str, &str)],
) -> std::process::Output {
    let mut command = Command::new(oracle);
    let path = std::env::var_os("PATH");
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    command.env("HOME", "/homeless-shelter");
    command.args(["--option", "trace-verbose", "false"]);
    command.args(["--option", "abort-on-warn", "false"]);
    for (name, value) in options {
        command.args(["--option", name, value]);
    }
    command.args(["--eval", "--strict", "--expr", source]);
    command
        .output()
        .expect("C++ Nix oracle evaluates expression")
}

pub(crate) fn cpp_nix_eval_stderr(oracle: &str, source: &str) -> Vec<u8> {
    cpp_nix_eval_stderr_with_nix_options(oracle, source, &[])
}

pub(crate) fn cpp_nix_eval_json_with_pinned_builtin_surface_features(
    oracle: &str,
    source: &str,
) -> Vec<u8> {
    cpp_nix_eval_json_with_nix_options(
        oracle,
        source,
        &[(
            "experimental-features",
            PINNED_BUILTIN_SURFACE_EXPERIMENTAL_FEATURES,
        )],
    )
}

pub(crate) fn cpp_nix_eval_json_with_env(
    oracle: &str,
    source: &str,
    env: &[(&str, &str)],
) -> Vec<u8> {
    let mut command = Command::new(oracle);
    command.args(["--eval", "--strict", "--json", "--expr", source]);
    for (name, value) in env {
        command.env(name, value);
    }
    let output = command
        .output()
        .expect("C++ Nix oracle evaluates expression");
    assert!(
        output.status.success(),
        "C++ Nix oracle failed for {source:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    trim_command_stdout(output.stdout)
}

pub(crate) fn cpp_nix_eval_string(oracle: &str, source: &str) -> Vec<u8> {
    let json = cpp_nix_eval_json(oracle, source);
    serde_json::from_slice::<String>(&json)
        .expect("C++ Nix oracle returned a JSON string")
        .into_bytes()
}
