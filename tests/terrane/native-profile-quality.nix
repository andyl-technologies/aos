{sourceGate}:
# A private hermetic target lets review checks run without taking a worktree's
# shared incremental target. These commands qualify lint and documentation only.
sourceGate "native-profile-quality" ''
  cd crates

  check_profile() {
    profile_name=$1
    shift
    printf 'Checking Terrane profile: %s\n' "$profile_name"
    cargo clippy --frozen --offline -p terrane "$@" --all-targets -- -D warnings
    RUSTDOCFLAGS='-D warnings -D missing_docs' \
      cargo doc --frozen --offline -p terrane "$@" --no-deps --document-private-items
  }

  # Cargo's default feature set is selected by omitting feature flags.
  check_profile default
  check_profile std-send --no-default-features --features std,send
  check_profile native --no-default-features --features tokio,surface-sdk

  printf 'PASS: strict Clippy and private rustdoc for default, std-send and native\n' > "$out/result"
''
