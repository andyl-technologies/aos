# tests/vm/apm/fixtures.nix — Test fixtures for APM/APR VM tests
#
# Provides shell preambles and helpers used by the registry, tracking, and
# package test suites.  Everything runs in a headless Firecracker microVM
# where the test script IS init (PID 1).
#
# Key conventions:
#   - HOME=/tmp so apm/apr discover ~/.local/share/apm/ at /tmp/.local/share/apm/
#   - git is available via rootfsDeps
#   - /nix/store paths for the "aos" tool are used directly
#   - Registry operations are purely local (git init, no network)
{
  pkgs,
  aosPkg,
}:
let
  gitPkg = pkgs.git;
  grepPkg = pkgs.grep;
in
rec {
  # Packages needed in the VM rootfs for all APM tests
  commonDeps = [
    aosPkg
    gitPkg
    grepPkg
    pkgs.coreutils
  ];

  # Shell preamble that sets up the test environment.
  # Creates a local git registry, configures apm to use it, and
  # provides helper functions for the test scripts.
  setupPreamble = ''
    # PATH is set by the Firecracker init; HOME defaults to /tmp
    export HOME=/tmp
    export GIT_AUTHOR_NAME="Test"
    export GIT_AUTHOR_EMAIL="test@test"
    export GIT_COMMITTER_NAME="Test"
    export GIT_COMMITTER_EMAIL="test@test"

    FAIL=0
    fail() {
      echo "FAIL: $1"
      FAIL=1
    }
    pass() {
      echo "PASS: $1"
    }

    assert_file_exists() {
      if [ -f "$1" ]; then
        pass "$2"
      else
        fail "$2 (file not found: $1)"
      fi
    }

    assert_dir_exists() {
      if [ -d "$1" ]; then
        pass "$2"
      else
        fail "$2 (directory not found: $1)"
      fi
    }

    assert_file_contains() {
      if grep -q "$2" "$1" 2>/dev/null; then
        pass "$3"
      else
        fail "$3 (pattern '$2' not found in $1)"
        cat "$1" 2>/dev/null || true
      fi
    }

    assert_file_not_exists() {
      if [ ! -f "$1" ]; then
        pass "$2"
      else
        fail "$2 (file should not exist: $1)"
      fi
    }

    assert_cmd_success() {
      if eval "$1" > /tmp/cmd-stdout 2>/tmp/cmd-stderr; then
        pass "$2"
      else
        fail "$2 (command failed: $1)"
        echo "  stdout: $(cat /tmp/cmd-stdout 2>/dev/null)"
        echo "  stderr: $(cat /tmp/cmd-stderr 2>/dev/null)"
      fi
    }

    assert_cmd_output_contains() {
      eval "$1" > /tmp/cmd-stdout 2>/tmp/cmd-stderr || true
      cat /tmp/cmd-stdout /tmp/cmd-stderr > /tmp/cmd-combined 2>/dev/null || true
      if grep -q "$2" /tmp/cmd-combined 2>/dev/null; then
        pass "$3"
      else
        fail "$3 (output of '$1' does not contain '$2')"
        echo "  stdout: $(cat /tmp/cmd-stdout 2>/dev/null)"
        echo "  stderr: $(cat /tmp/cmd-stderr 2>/dev/null)"
      fi
    }

    assert_cmd_fails() {
      if eval "$1" > /tmp/cmd-stdout 2>/tmp/cmd-stderr; then
        fail "$2 (command should have failed: $1)"
      else
        pass "$2"
      fi
    }

    check_fail() {
      if [ "$FAIL" -ne 0 ]; then
        echo "==> TESTS FAILED"
        exit 1
      fi
      echo "==> All tests passed"
    }

    # APR/APM binary paths
    APR="${aosPkg}/bin/apr"
    APM="${aosPkg}/bin/apm"

    # Registry storage path (matches ~/.local/share/apm/registries/)
    REG_STORAGE="$HOME/.local/share/apm/registries"
    mkdir -p "$REG_STORAGE"

    # Config path (matches ~/.config/apm/)
    APM_CONFIG="$HOME/.config/apm"
    mkdir -p "$APM_CONFIG/registries.d"
  '';

  # Create a bare git repo at a given path to act as a "remote" registry.
  # This is used by apr add (clone) tests.
  mkRemoteRegistry = ''
    create_remote_registry() {
      local path="$1"
      mkdir -p "$path"
      cd "$path"
      git init --bare
      cd /tmp

      # Clone, add structure, push
      git clone "$path" /tmp/remote-setup
      cd /tmp/remote-setup
      mkdir -p packages
      cat > registry.toml << 'REGEOF'
[registry]
name = "remote-test"
description = "Test remote registry"
REGEOF
      git add -A
      git commit -m "Initialize remote registry"
      git push --set-upstream origin "$(git branch --show-current)"
      cd /tmp
      rm -rf /tmp/remote-setup
    }
  '';

  # Create a fake store path that can be used for publish tests.
  # Since we can't create real Nix store paths in the VM, we create
  # fake paths and use --no-commit to avoid nix path-info calls.
  mkFakePackageToml = ''
    # Write a package TOML directly (bypasses nix path-info introspection)
    write_package_toml() {
      local reg_dir="$1"
      local pkg_name="$2"
      local pkg_version="$3"
      local letter
      letter=$(echo "$pkg_name" | cut -c1 | tr '[:upper:]' '[:lower:]')
      local pkg_dir="$reg_dir/packages/$letter"
      mkdir -p "$pkg_dir"
      cat > "$pkg_dir/$pkg_name.toml" << TOMLEOF
[package]
name = "$pkg_name"
description = "Test package $pkg_name"
license = "MIT"
maintainer = "test"

[[versions]]
version = "$pkg_version"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-$pkg_name-$pkg_version"
nar_hash = "sha256:0000000000000000000000000000000000000000000000000000"
nar_size = 1024
download_hash = "sha256:0000000000000000000000000000000000000000000000000000"
download_size = 512
closure_size = 2048
source_drv = ""
source_nar_hash = ""
references = []
TOMLEOF
    }

    # Write a sysroot package TOML with image entry
    write_sysroot_package_toml() {
      local reg_dir="$1"
      local pkg_name="$2"
      local pkg_version="$3"
      local letter
      letter=$(echo "$pkg_name" | cut -c1 | tr '[:upper:]' '[:lower:]')
      local pkg_dir="$reg_dir/packages/$letter"
      mkdir -p "$pkg_dir"
      cat > "$pkg_dir/$pkg_name.toml" << TOMLEOF
[package]
name = "$pkg_name"
description = "Test sysroot package"
sysroot = true
license = "MIT"
maintainer = "test"

[[versions]]
version = "$pkg_version"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-$pkg_name-$pkg_version"
nar_hash = "sha256:0000000000000000000000000000000000000000000000000000"
nar_size = 1024
download_hash = "sha256:0000000000000000000000000000000000000000000000000000"
download_size = 512
closure_size = 2048
source_drv = ""
source_nar_hash = ""
references = []

[[versions.platforms.x86_64-linux.images]]
format = "raw"
store_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-$pkg_name-image-$pkg_version"
nar_hash = "sha256:1111111111111111111111111111111111111111111111111111"
nar_size = 4096
download_hash = "sha256:1111111111111111111111111111111111111111111111111111"
download_size = 2048
TOMLEOF
    }

    # Write a closure file for a store path hash.
    # Args: reg_dir root_hash [dep_hash dep_hash ...]
    # Creates closures/<root_hash> with an adjacency list.
    write_closure_file() {
      local reg_dir="$1"
      local root_hash="$2"
      shift 2
      local closures_dir="$reg_dir/closures"
      mkdir -p "$closures_dir"

      # First line: root + its direct deps (all remaining args)
      local line="$root_hash"
      for dep in "$@"; do
        line="$line $dep"
      done
      echo "$line" > "$closures_dir/$root_hash"

      # Add leaf lines for each dep (no deps of their own)
      for dep in "$@"; do
        echo "$dep" >> "$closures_dir/$root_hash"
      done
    }

    # Write a multi-level closure file with an explicit adjacency list.
    # Args: reg_dir root_hash content
    # content is the raw adjacency list text.
    write_closure_file_raw() {
      local reg_dir="$1"
      local root_hash="$2"
      local content="$3"
      local closures_dir="$reg_dir/closures"
      mkdir -p "$closures_dir"
      echo "$content" > "$closures_dir/$root_hash"
    }

    # Ensure .gitattributes has the closures entry.
    ensure_gitattributes() {
      local reg_dir="$1"
      local ga="$reg_dir/.gitattributes"
      if [ -f "$ga" ] && grep -q "closures/\*\* -diff" "$ga" 2>/dev/null; then
        return 0
      fi
      echo "closures/** -diff" >> "$ga"
    }

    # Write a package TOML with references to other hashes (for closure tests)
    write_package_toml_with_refs() {
      local reg_dir="$1"
      local pkg_name="$2"
      local pkg_version="$3"
      local store_hash="$4"
      shift 4
      local letter
      letter=$(echo "$pkg_name" | cut -c1 | tr '[:upper:]' '[:lower:]')
      local pkg_dir="$reg_dir/packages/$letter"
      mkdir -p "$pkg_dir"

      # Build references array
      local refs="["
      local first=1
      for ref in "$@"; do
        if [ "$first" -eq 1 ]; then
          refs="$refs\"$ref\""
          first=0
        else
          refs="$refs, \"$ref\""
        fi
      done
      refs="$refs]"

      cat > "$pkg_dir/$pkg_name.toml" << TOMLEOF
[package]
name = "$pkg_name"
description = "Test package $pkg_name"
license = "MIT"
maintainer = "test"

[[versions]]
version = "$pkg_version"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/$store_hash-$pkg_name-$pkg_version"
nar_hash = "sha256:0000000000000000000000000000000000000000000000000000"
nar_size = 1024
download_hash = "sha256:0000000000000000000000000000000000000000000000000000"
download_size = 512
closure_size = 2048
source_drv = ""
source_nar_hash = ""
references = $refs
TOMLEOF
    }

    # Commit all changes in a registry directory
    commit_registry() {
      local reg_dir="$1"
      local message="$2"
      cd "$reg_dir"
      git add -A
      git commit -m "$message"
      cd /tmp
    }
  '';
}
