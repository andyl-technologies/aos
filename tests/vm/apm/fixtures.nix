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
}: let
  gitPkg = pkgs.git;
  grepPkg = pkgs.grep;
in rec {
  # Packages needed in the VM rootfs for all APM tests
  commonDeps = [
    aosPkg
    gitPkg
    grepPkg
    pkgs.coreutils
    pkgs.openssh
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

    # Publication requires a roster-backed signer. Give fixture publishers a
    # separate config directory so consumers can add the same registry name.
    register_publish_key() {
      local registry_name="$1"
      local key_id="$2"
      local key_path="$3"
      local config_dir="''${XDG_CONFIG_HOME:-$HOME/.config}/apm/registries.d"
      local registry_dir="''${XDG_DATA_HOME:-$HOME/.local/share}/apm/registries"
      mkdir -p "$config_dir"
      if [ ! -f "$config_dir/$registry_name.toml" ]; then
        {
          printf '[registry]\n'
          printf 'name = "%s"\n' "$registry_name"
          printf 'url = "file://%s/%s"\n' "$registry_dir" "$registry_name"
        } > "$config_dir/$registry_name.toml"
      fi
      $APR keys register "$key_id" --registry "$registry_name" \
        --key "$key_path" > /dev/null
    }

    create_publish_registry() {
      local registry_name="$1"
      shift
      local key_path="/tmp/vm-publish-keys/$registry_name"
      local public_key
      mkdir -p /tmp/vm-publish-keys
      ssh-keygen -q -t ed25519 -N "" -f "$key_path"
      public_key=$(cut -d ' ' -f2 < "$key_path.pub")
      $APR "$@" create "$registry_name" \
        --trust-key "$registry_name:Ed25519:$public_key" \
        --trust-key-id vm --key "$key_path"
      XDG_CONFIG_HOME=/tmp/vm-publish-config \
        register_publish_key "$registry_name" vm "$key_path"
    }

    publish_vm_package() {
      XDG_CONFIG_HOME=/tmp/vm-publish-config \
        "$APR" publish --key-id vm "$@"
    }

    release_vm_package() {
      XDG_CONFIG_HOME=/tmp/vm-publish-config \
        "$APR" release --key-id vm "$@"
    }
  '';

  # Create a bare git repo at a given path to act as a "remote" registry.
  # This is used by apr add (clone) tests.
  mkRemoteRegistry = ''
        create_remote_registry() {
          local path="$1"
          mkdir -p "$path"
          cd "$path"
          git init --bare --object-format=sha256
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
}
