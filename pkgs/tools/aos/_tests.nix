# pkgs/tools/aos/_tests.nix — Integration tests for the aos CLI and cache server
#
# Prefixed with _ so discoverPackages skips it (not a package).
# Called from aos.nix via: import ./_tests.nix { inherit testing self pkgs; }
{
  testing,
  self,
  pkgs,
}: let
  # Shared preamble for server tests: bring up loopback, create mock Nix DB,
  # write server config, start aos serve in background.
  serverPreamble = ''
    # Bring up loopback interface (needed for 127.0.0.1 binding)
    ${pkgs.iproute2}/sbin/ip link set lo up || true
    ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

    # Use /tmp (tmpfs, writable) for all server state.
    # The rootfs is mounted read-only so /run and other paths on the
    # root filesystem are not writable.
    echo "==> Setting up test environment"
    export AOS_ROOT=/tmp/aos
    mkdir -p $AOS_ROOT/var/nix/db
    mkdir -p $AOS_ROOT/store
    mkdir -p $AOS_ROOT/meta
    mkdir -p /tmp/run/aos

    # Create a minimal SQLite DB matching the Nix schema
    echo "==> Creating mock Nix store DB"
    ${pkgs.sqlite}/bin/sqlite3 $AOS_ROOT/var/nix/db/db.sqlite << 'SQL'
    CREATE TABLE IF NOT EXISTS ValidPaths (
      id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
      path TEXT UNIQUE NOT NULL,
      hash TEXT NOT NULL,
      registrationTime INTEGER NOT NULL,
      deriver TEXT,
      narSize INTEGER,
      ultimate INTEGER,
      sigs TEXT,
      ca TEXT
    );
    CREATE TABLE IF NOT EXISTS Refs (
      referrer INTEGER NOT NULL,
      reference INTEGER NOT NULL,
      PRIMARY KEY (referrer, reference),
      FOREIGN KEY (referrer) REFERENCES ValidPaths(id) ON DELETE CASCADE,
      FOREIGN KEY (reference) REFERENCES ValidPaths(id) ON DELETE CASCADE
    );
    PRAGMA journal_mode=WAL;
    SQL
    chmod 666 $AOS_ROOT/var/nix/db/db.sqlite
    chmod 777 $AOS_ROOT/var/nix/db
    echo "==> Test environment ready"
  '';

  # Common rootfsDeps for server tests
  serverDeps = [
    self
    pkgs.curl
    pkgs.coreutils
    pkgs.socat
    pkgs.jq
    pkgs.sqlite
    pkgs.iproute2
    pkgs.grep
  ];
in {
  # ---------------------------------------------------------------------------
  # CLI basics
  # ---------------------------------------------------------------------------

  help = testing.mkVMTest {
    name = "aos-help";
    rootfsDeps = [self];
    memory = 1024;
    testScript = ''
      echo "==> Testing aos --help"
      ${self}/bin/aos --help
      echo "==> aos --help passed"
    '';
  };

  version = testing.mkVMTest {
    name = "aos-describe";
    rootfsDeps = [
      self
      pkgs.git
    ];
    testScript = ''
      echo "==> Testing aos describe"
      ${self}/bin/aos describe
      echo "==> aos describe passed"
    '';
  };

  fmt-check = testing.mkVMTest {
    name = "aos-fmt-check";
    rootfsDeps = [
      self
    ];
    testScript = ''
      mkdir -p /tmp/proj
      cat > /tmp/proj/test.nix << 'EOF'
      { pkgs }: pkgs.hello
      EOF

      echo "==> Testing aos fmt --check on valid file"
      ${self}/bin/aos fmt --check /tmp/proj/test.nix
      echo "==> aos fmt --check passed"
    '';
  };

  host-apr-apm-command-surface = pkgs.mkDerivation {
    pname = "aos-host-apr-apm-command-surface";
    version = "0";
    src = null;

    buildDeps = [
      self
      pkgs.bash
      pkgs.coreutils
      pkgs.findutils
      pkgs.git
      pkgs.grep
      pkgs.jq
      pkgs.nix
      pkgs.openssh
      pkgs.python3
      pkgs.zstd
    ];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          work="$TMPDIR/aos-host-command-surface"
          home="$work/home"
          config="$work/config"
          data="$work/share"
          cache="$work/cache"
          profile_root="$work/profiles"
          aos_root="$work/aos-root"
          store_dir="$aos_root/store"
          state_dir="$aos_root/var/nix"
          nix_conf="$work/nix-conf"
          cache_port="18137"
          install_cache_port="18138"
          mkdir -p "$home" "$config" "$data" "$cache" "$cache/nix" "$profile_root" "$store_dir" "$state_dir/db" "$state_dir/gcroots" "$state_dir/log/nix" "$nix_conf"
          profile="$profile_root/per-user/unknown"
          default_profile="/var/lib/profiles/per-user/unknown"
          cache_server_pid=""
          install_cache_server_pid=""
          cat > "$nix_conf/nix.conf" << NIXCONF
          experimental-features = nix-command
          sandbox = false
          substituters =
          NIXCONF

          cleanup() {
            if test -n "$cache_server_pid"; then
              kill "$cache_server_pid" 2>/dev/null || true
              wait "$cache_server_pid" 2>/dev/null || true
            fi
            if test -n "$install_cache_server_pid"; then
              kill "$install_cache_server_pid" 2>/dev/null || true
              wait "$install_cache_server_pid" 2>/dev/null || true
            fi
          }
          trap cleanup EXIT

          run_clean() {
            env -i \
              HOME="$home" \
              XDG_CONFIG_HOME="$config" \
              XDG_DATA_HOME="$data" \
              XDG_CACHE_HOME="$cache" \
              AOS_PROFILE_ROOT="$profile_root" \
              AOS_ROOT="$aos_root" \
              AOS_NIX_STORE_DIR="$store_dir" \
              AOS_NIX_STATE_DIR="$state_dir" \
              NIX_REMOTE="" \
              NIX_CONF_DIR="$nix_conf" \
              GIT_CONFIG_NOSYSTEM=1 \
              GIT_AUTHOR_NAME="Host Command Test" \
              GIT_AUTHOR_EMAIL="host-command@example.invalid" \
              GIT_COMMITTER_NAME="Host Command Test" \
              GIT_COMMITTER_EMAIL="host-command@example.invalid" \
              PATH="${pkgs.coreutils}/bin:${pkgs.findutils}/bin:${pkgs.git}/bin:${pkgs.nix}/bin:${pkgs.zstd}/bin" \
              "$@"
          }

          assert_path_absent() {
            path="$1"
            if test -e "$path"; then
              find "$path" -maxdepth 2 -print
              exit 1
            fi
          }

          assert_no_profile() {
            assert_path_absent "$profile"
            assert_path_absent "$default_profile"
          }

          assert_default_profile_absent() {
            assert_path_absent "$default_profile"
          }

          profile_generation_count() {
            if test -d "$profile"; then
              find "$profile" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
            else
              printf '0'
            fi
          }

          nix_store() {
            env \
              NIX_REMOTE="" \
              NIX_CONF_DIR="$nix_conf" \
              NIX_STORE_DIR="$store_dir" \
              NIX_STATE_DIR="$state_dir" \
              PATH="${pkgs.coreutils}/bin:${pkgs.findutils}/bin:${pkgs.nix}/bin:${pkgs.zstd}/bin" \
              nix-store "$@"
          }

          nix_build() {
            env \
              HOME="$home" \
              XDG_CACHE_HOME="$cache" \
              NIX_REMOTE="" \
              NIX_CONF_DIR="$nix_conf" \
              NIX_STORE_DIR="$store_dir" \
              NIX_STATE_DIR="$state_dir" \
              NIX_LOG_DIR="$state_dir/log/nix" \
              PATH="${pkgs.coreutils}/bin:${pkgs.findutils}/bin:${pkgs.nix}/bin:${pkgs.zstd}/bin" \
              nix-build "$@"
          }

          nix_store --init > "$work/nix-store-init.out" 2>&1

          run_clean ${self}/bin/apr --help > "$work/apr-help.out"
          grep -q "Usage:" "$work/apr-help.out"
          run_clean ${self}/bin/apm --help > "$work/apm-help.out"
          grep -q "Usage:" "$work/apm-help.out"

          reg="$data/apm/registries/host-reg"
          run_clean ${self}/bin/apr --json create host-reg > "$work/apr-create.json"
          ${pkgs.jq}/bin/jq -e --arg reg "$reg" \
            '.action == "create"
              and .registry == "host-reg"
              and .path == $reg
              and .remote == null
              and .trust_key_id == null
              and .current == "stable"
              and (.head | length == 64)
              and (.branches | any(.name == "stable" and .current == true))' \
            "$work/apr-create.json" >/dev/null
          test -f "$reg/registry.toml"
          test -d "$reg/.git"
          git -C "$reg" config user.name "Host Command Test"
          git -C "$reg" config user.email "host-command@example.invalid"

          git -C "$reg" log -1 --format=%an > "$work/author-name.out"
          git -C "$reg" log -1 --format=%ae > "$work/author-email.out"
          grep -qx "Host Command Test" "$work/author-name.out"
          grep -qx "host-command@example.invalid" "$work/author-email.out"

          run_clean ${self}/bin/apr keys generate root --registry host-reg \
            > "$work/apr-keys-generate-root.out" 2>&1
          host_key_root=$(grep -o 'host-reg:Ed25519:[A-Za-z0-9+/=]*' "$work/apr-keys-generate-root.out" | head -1)
          host_key_root_path="$config/apm/keys/host-reg-root.key"
          test -f "$host_key_root_path"

          run_clean ${self}/bin/apr keys generate backup --registry host-reg \
            > "$work/apr-keys-generate-backup.out" 2>&1
          host_key_backup=$(grep -o 'host-reg:Ed25519:[A-Za-z0-9+/=]*' "$work/apr-keys-generate-backup.out" | head -1)
          host_key_backup_path="$config/apm/keys/host-reg-backup.key"
          test -f "$host_key_backup_path"

          run_clean ${self}/bin/apr keys generate canary --registry host-reg \
            > "$work/apr-keys-generate-canary.out" 2>&1
          host_key_canary=$(grep -o 'host-reg:Ed25519:[A-Za-z0-9+/=]*' "$work/apr-keys-generate-canary.out" | head -1)
          host_key_foreign="other-reg:Ed25519:bWlzbWF0Y2g="
          trust_file="$config/apm/trusted-keys.d/host-reg.pub"

          run_clean ${self}/bin/apr keys list --registry host-reg \
            > "$work/apr-keys-list-empty.out" 2>&1
          grep -q "Registry 'host-reg' has no keys in keys.toml" \
            "$work/apr-keys-list-empty.out"
          run_clean ${self}/bin/apr --json keys list --registry host-reg \
            > "$work/apr-keys-list-empty.json"
          ${pkgs.jq}/bin/jq -e \
            '.registry == "host-reg" and .active == [] and .revoked == []' \
            "$work/apr-keys-list-empty.json" >/dev/null
          assert_no_profile

          run_clean ${self}/bin/apr keys add root "$host_key_root" \
            --registry host-reg \
            --no-commit > "$work/apr-keys-add-root-no-commit.out" 2>&1
          grep -q "Added active signing key 'root'" \
            "$work/apr-keys-add-root-no-commit.out"
          grep -q 'id = "root"' "$reg/keys.toml"
          grep -q "$host_key_root" "$reg/keys.toml"
          run_clean ${self}/bin/apr status --registry host-reg \
            > "$work/apr-status-keys-no-commit.out" 2>&1
          grep -q "keys.toml" "$work/apr-status-keys-no-commit.out"
          run_clean ${self}/bin/apr --json status --registry host-reg \
            > "$work/apr-status-keys-no-commit.json"
          ${pkgs.jq}/bin/jq -e \
            '.clean == false
              and (.entries | any(.status == " M" and .path == "keys.toml"))' \
            "$work/apr-status-keys-no-commit.json" >/dev/null
          if git -C "$reg" log --oneline --grep "registry: add signing key root" \
            | grep -q .; then
            cat "$work/apr-status-keys-no-commit.out"
            exit 1
          fi
          git -C "$reg" add keys.toml
          git -C "$reg" commit -m "registry: add host root signing key" \
            > "$work/git-commit-host-root-key.out" 2>&1

          if run_clean ${self}/bin/apr keys add duplicate "$host_key_root" \
            --key "$host_key_root_path" \
            --registry host-reg > "$work/apr-keys-add-duplicate.out" 2>&1; then
            cat "$work/apr-keys-add-duplicate.out"
            exit 1
          fi
          grep -q "signing key already exists" "$work/apr-keys-add-duplicate.out"

          if run_clean ${self}/bin/apr keys add foreign "$host_key_foreign" \
            --key "$host_key_root_path" \
            --registry host-reg > "$work/apr-keys-add-foreign.out" 2>&1; then
            cat "$work/apr-keys-add-foreign.out"
            exit 1
          fi
          grep -q "belongs to registry 'other-reg', expected 'host-reg'" \
            "$work/apr-keys-add-foreign.out"

          run_clean ${self}/bin/apr keys add backup "$host_key_backup" \
            --key "$host_key_root_path" \
            --registry host-reg > "$work/apr-keys-add-backup.out" 2>&1
          grep -q "Added active signing key 'backup'" \
            "$work/apr-keys-add-backup.out"
          run_clean ${self}/bin/apr keys retire root \
            --key "$host_key_backup_path" \
            --registry host-reg \
            --reason "host rotation" > "$work/apr-keys-retire-root.out" 2>&1
          grep -q "Retired signing key 'root'.*vouched by 'backup'" \
            "$work/apr-keys-retire-root.out"
          run_clean ${self}/bin/apr keys list --registry host-reg \
            > "$work/apr-keys-list-rotated.out" 2>&1
          grep -q "backup:" "$work/apr-keys-list-rotated.out"
          grep -q "root: host rotation" "$work/apr-keys-list-rotated.out"
          run_clean ${self}/bin/apr --json keys list --registry host-reg \
            > "$work/apr-keys-list-rotated.json"
          ${pkgs.jq}/bin/jq -e \
            --arg backup "$host_key_backup" \
            '.registry == "host-reg"
              and (.active | any(.id == "backup" and .key == $backup))
              and (.revoked | any(.id == "root" and .reason == "host rotation"))' \
            "$work/apr-keys-list-rotated.json" >/dev/null
          git -C "$reg" log --oneline > "$work/apr-keys-log.out"
          grep -q "registry: add signing key backup" "$work/apr-keys-log.out"
          grep -q "registry: retire signing key root" "$work/apr-keys-log.out"
          assert_no_profile

          run_clean ${self}/bin/apr trust list host-reg \
            > "$work/apr-trust-list-empty.out" 2>&1
          grep -q "host-reg: no pinned keys" "$work/apr-trust-list-empty.out"
          run_clean ${self}/bin/apr --json trust list host-reg \
            > "$work/apr-trust-list-empty.json"
          ${pkgs.jq}/bin/jq -e \
            'length == 1 and .[0].registry == "host-reg" and .[0].keys == []' \
            "$work/apr-trust-list-empty.json" >/dev/null
          run_clean ${self}/bin/apr trust pin host-reg "$host_key_root" \
            > "$work/apr-trust-pin-root.out" 2>&1
          grep -q "Pinned trust key for registry 'host-reg'" \
            "$work/apr-trust-pin-root.out"
          test -f "$trust_file"
          grep -q "$host_key_root" "$trust_file"
          run_clean ${self}/bin/apr trust pin host-reg "$host_key_backup" \
            > "$work/apr-trust-pin-backup.out" 2>&1
          test "$(wc -l < "$trust_file")" = "2"
          run_clean ${self}/bin/apr trust list host-reg \
            > "$work/apr-trust-list-pinned.out" 2>&1
          grep -q "host-reg: Ed25519" "$work/apr-trust-list-pinned.out"
          run_clean ${self}/bin/apr --json trust list host-reg \
            > "$work/apr-trust-list-pinned.json"
          ${pkgs.jq}/bin/jq -e \
            'length == 1
              and .[0].registry == "host-reg"
              and (.[0].keys | length == 2)
              and (.[0].keys | all(.algorithm == "Ed25519" and .source == "Tofu"))' \
            "$work/apr-trust-list-pinned.json" >/dev/null
          if run_clean ${self}/bin/apr trust pin host-reg "$host_key_foreign" \
            > "$work/apr-trust-pin-foreign.out" 2>&1; then
            cat "$work/apr-trust-pin-foreign.out"
            exit 1
          fi
          grep -q "belongs to registry 'other-reg', expected 'host-reg'" \
            "$work/apr-trust-pin-foreign.out"
          run_clean ${self}/bin/apr trust pin host-reg "$host_key_canary" --replace \
            > "$work/apr-trust-replace.out" 2>&1
          grep -q "Re-pinned trust key for registry 'host-reg'" \
            "$work/apr-trust-replace.out"
          test "$(wc -l < "$trust_file")" = "1"
          grep -q "$host_key_canary" "$trust_file"
          run_clean ${self}/bin/apr trust remove host-reg \
            > "$work/apr-trust-remove.out" 2>&1
          grep -q "Removed pinned trust keys" "$work/apr-trust-remove.out"
          test ! -e "$trust_file"
          run_clean ${self}/bin/apr trust remove host-reg \
            > "$work/apr-trust-remove-repeat.out" 2>&1
          grep -q "No pinned trust keys found" "$work/apr-trust-remove-repeat.out"
          assert_no_profile

          run_clean ${self}/bin/apr status --registry host-reg > "$work/apr-status.out" 2>&1
          if grep -q '[^[:space:]]' "$work/apr-status.out"; then
            cat "$work/apr-status.out"
            exit 1
          fi
          run_clean ${self}/bin/apr --json status --registry host-reg \
            > "$work/apr-status-clean.json"
          ${pkgs.jq}/bin/jq -e \
            '.clean == true and .entries == []' \
            "$work/apr-status-clean.json" >/dev/null
          run_clean ${self}/bin/apr --json packages --registry host-reg > "$work/apr-packages-empty.json"
          ${pkgs.jq}/bin/jq -e 'length == 0' "$work/apr-packages-empty.json" >/dev/null
          pkg_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          mkdir -p "$reg/packages/h" "$reg/closures"
          printf '%s\n' \
            '[package]' \
            'name = "hostpkg"' \
            'description = "Host-authored package metadata"' \
            'homepage = "https://example.invalid/hostpkg"' \
            'license = "MIT"' \
            'maintainer = "host@example.invalid"' \
            "" \
            '[[versions]]' \
            'version = "1.0.0"' \
            "" \
            '[versions.platforms.x86_64-linux]' \
            "store_path = \"/nix/store/$pkg_hash-hostpkg-1.0.0\"" \
            'nar_hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="' \
            'nar_size = 1234' \
            'closure_size = 1234' \
            'source_drv = ""' \
            'source_nar_hash = ""' \
            'references = []' \
            > "$reg/packages/h/hostpkg.toml"
          printf '%s\n' "$pkg_hash" > "$reg/closures/$pkg_hash"
          printf '%s\n' \
            "" \
            '[[caches]]' \
            "url = \"http://127.0.0.1:$cache_port/cache\"" \
            'priority = 42' \
            >> "$reg/registry.toml"

          run_clean ${self}/bin/apr status --registry host-reg > "$work/apr-status-dirty.out" 2>&1
          grep -q "registry.toml" "$work/apr-status-dirty.out"
          grep -q "packages/h/hostpkg.toml" "$work/apr-status-dirty.out"
          grep -q "closures/$pkg_hash" "$work/apr-status-dirty.out"
          run_clean ${self}/bin/apr --json status --registry host-reg \
            > "$work/apr-status-dirty.json"
          ${pkgs.jq}/bin/jq -e --arg closure "closures/$pkg_hash" \
            '.clean == false
              and (.entries | any(.path == "registry.toml"))
              and (.entries | any(.path == "packages/h/hostpkg.toml"))
              and (.entries | any(.path == $closure))' \
            "$work/apr-status-dirty.json" >/dev/null

          run_clean ${self}/bin/apr diff --registry host-reg --stat > "$work/apr-diff-stat.out" 2>&1
          grep -q "registry.toml" "$work/apr-diff-stat.out"
          run_clean ${self}/bin/apr --json diff --registry host-reg --stat \
            > "$work/apr-diff-stat.json"
          ${pkgs.jq}/bin/jq -e \
            '.remote == false
              and .stat == true
              and .clean == false
              and (.changed_files | any(.status == "M" and .path == "registry.toml"))
              and (.output | contains("registry.toml"))' \
            "$work/apr-diff-stat.json" >/dev/null

          git -C "$reg" add -A
          git -C "$reg" commit -m "release: hostpkg 1.0.0" > "$work/git-commit-package.out" 2>&1

          run_clean ${self}/bin/apr --json branch create host-json-feature --registry host-reg \
            > "$work/apr-branch-create-json.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "create"
              and .branch == "host-json-feature"
              and .current == "stable"
              and (.branches | any(.name == "host-json-feature" and .current == false))
              and (.branches | any(.name == "stable" and .current == true))' \
            "$work/apr-branch-create-json.json" >/dev/null
          run_clean ${self}/bin/apr --json branch delete host-json-feature --registry host-reg \
            > "$work/apr-branch-delete-json.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "delete"
              and .branch == "host-json-feature"
              and .current == "stable"
              and (.branches | all(.name != "host-json-feature"))
              and (.branches | any(.name == "stable" and .current == true))' \
            "$work/apr-branch-delete-json.json" >/dev/null

          run_clean ${self}/bin/apr branch create host-feature --registry host-reg > "$work/apr-branch-create.out" 2>&1
          grep -q "Created branch 'host-feature'" "$work/apr-branch-create.out"
          run_clean ${self}/bin/apr branch switch host-feature --registry host-reg > "$work/apr-branch-switch.out" 2>&1
          grep -q "Switched to branch 'host-feature'" "$work/apr-branch-switch.out"
          run_clean ${self}/bin/apr --json branch list --registry host-reg \
            > "$work/apr-branch-list-feature-current.json"
          ${pkgs.jq}/bin/jq -e \
            '.branches
              | (any(.name == "host-feature" and .current == true)
                and any(.name == "stable" and .current == false))' \
            "$work/apr-branch-list-feature-current.json" >/dev/null
          printf '%s\n' \
            '[package]' \
            'name = "hostpkg"' \
            'description = "Host-authored package metadata from feature branch"' \
            'homepage = "https://example.invalid/hostpkg"' \
            'license = "MIT"' \
            'maintainer = "host@example.invalid"' \
            "" \
            '[[versions]]' \
            'version = "1.0.0"' \
            "" \
            '[versions.platforms.x86_64-linux]' \
            "store_path = \"/nix/store/$pkg_hash-hostpkg-1.0.0\"" \
            'nar_hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="' \
            'nar_size = 1234' \
            'closure_size = 1234' \
            'source_drv = ""' \
            'source_nar_hash = ""' \
            'references = []' \
            > "$reg/packages/h/hostpkg.toml"
          git -C "$reg" add packages/h/hostpkg.toml
          git -C "$reg" commit -m "release: hostpkg 1.0.0 feature metadata" \
            > "$work/git-commit-host-feature.out" 2>&1
          run_clean ${self}/bin/apr branch switch stable --registry host-reg > "$work/apr-branch-switch-stable.out" 2>&1
          grep -q "Switched to branch 'stable'" "$work/apr-branch-switch-stable.out"
          run_clean ${self}/bin/apr branch list --registry host-reg > "$work/apr-branch-list.out" 2>&1
          grep -q "host-feature" "$work/apr-branch-list.out"
          run_clean ${self}/bin/apr --json branch list --registry host-reg \
            > "$work/apr-branch-list-stable-current.json"
          ${pkgs.jq}/bin/jq -e \
            '.branches
              | (any(.name == "stable" and .current == true)
                and any(.name == "host-feature" and .current == false))' \
            "$work/apr-branch-list-stable-current.json" >/dev/null
          run_clean ${self}/bin/apr --json merge host-feature --registry host-reg \
            > "$work/apr-merge-feature.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "merge"
              and .branch == "host-feature"
              and .no_ff == false
              and .squash == false
              and .current == "stable"
              and (.head | length == 64)
              and (.output | contains("Fast-forward"))
              and (.branches | any(.name == "stable" and .current == true))' \
            "$work/apr-merge-feature.json" >/dev/null
          run_clean ${self}/bin/apr branch delete host-feature --registry host-reg > "$work/apr-branch-delete-feature.out" 2>&1
          grep -q "Deleted branch 'host-feature'" "$work/apr-branch-delete-feature.out"
          run_clean ${self}/bin/apr branch list --registry host-reg > "$work/apr-branch-list-after-delete.out" 2>&1
          if grep -q "host-feature" "$work/apr-branch-list-after-delete.out"; then
            cat "$work/apr-branch-list-after-delete.out"
            exit 1
          fi
          run_clean ${self}/bin/apr --json branch list --registry host-reg \
            > "$work/apr-branch-list-after-delete.json"
          ${pkgs.jq}/bin/jq -e \
            '.branches
              | (any(.name == "stable" and .current == true)
                and all(.name != "host-feature"))' \
            "$work/apr-branch-list-after-delete.json" >/dev/null

          run_clean ${self}/bin/apr packages --registry host-reg > "$work/apr-packages.out" 2>&1
          grep -q "hostpkg 1.0.0" "$work/apr-packages.out"
          run_clean ${self}/bin/apr --json packages --registry host-reg > "$work/apr-packages.json"
          ${pkgs.jq}/bin/jq -e \
            'length == 1 and .[0].name == "hostpkg" and .[0].version == "1.0.0"' \
            "$work/apr-packages.json" >/dev/null
          run_clean ${self}/bin/apr show hostpkg --registry host-reg > "$work/apr-show.out" 2>&1
          grep -q "Host-authored package metadata" "$work/apr-show.out"
          run_clean ${self}/bin/apr --json show hostpkg --registry host-reg > "$work/apr-show.json"
          ${pkgs.jq}/bin/jq -e \
            '.package.name == "hostpkg"
              and .package.description == "Host-authored package metadata from feature branch"
              and .versions[0].version == "1.0.0"
              and .versions[0].platforms."x86_64-linux".store_path == "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hostpkg-1.0.0"' \
            "$work/apr-show.json" >/dev/null
          run_clean ${self}/bin/apr show hostpkg --registry host-reg --raw > "$work/apr-show-raw.out" 2>&1
          grep -q "store_path = \"/nix/store/$pkg_hash-hostpkg-1.0.0\"" "$work/apr-show-raw.out"
          run_clean ${self}/bin/apr verify --registry host-reg > "$work/apr-verify.out" 2>&1
          grep -q "Verified 1 package(s), 1 closure(s), no errors" "$work/apr-verify.out"
          run_clean ${self}/bin/apr log --registry host-reg --package hostpkg -n 1 > "$work/apr-log-package.out" 2>&1
          grep -q "release: hostpkg 1.0.0" "$work/apr-log-package.out"
          run_clean ${self}/bin/apr --json log --registry host-reg --package hostpkg -n 1 \
            > "$work/apr-log-package.json"
          ${pkgs.jq}/bin/jq -e \
            '.package == "hostpkg"
              and .limit == 1
              and (.commits | length == 1)
              and (.commits[0].subject | contains("release: hostpkg 1.0.0"))
              and (.commits[0].hash | length == 64)
              and (.commits[0].timestamp > 0)' \
            "$work/apr-log-package.json" >/dev/null

          git init --bare --object-format=sha256 "$work/host-origin.git" > "$work/git-init-origin.out" 2>&1
          git -C "$reg" remote add origin "$work/host-origin.git"
          run_clean ${self}/bin/apr push --registry host-reg --branch stable --set-upstream > "$work/apr-push.out" 2>&1
          grep -q "Pushed." "$work/apr-push.out"
          run_clean ${self}/bin/apr --json push --registry host-reg --branch stable \
            > "$work/apr-push-json.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "push"
              and .branch == "stable"
              and .set_upstream == false
              and .force == false
              and .current == "stable"
              and (.head | length == 64)
              and (.branches | any(.name == "origin/stable" and .remote == true))' \
            "$work/apr-push-json.json" >/dev/null
          run_clean ${self}/bin/apr --json pull --registry host-reg \
            > "$work/apr-pull-json.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "pull"
              and .rebase == false
              and .current == "stable"
              and (.head | length == 64)
              and (.output as $out
                | (($out | contains("Already up to date"))
                  or ($out | contains("Already up-to-date"))))' \
            "$work/apr-pull-json.json" >/dev/null
          run_clean ${self}/bin/apr diff --registry host-reg --remote --stat > "$work/apr-diff-remote.out" 2>&1
          grep -q "No pending changes" "$work/apr-diff-remote.out"
          run_clean ${self}/bin/apr --json diff --registry host-reg --remote --stat \
            > "$work/apr-diff-remote.json"
          ${pkgs.jq}/bin/jq -e \
            '.remote == true
              and .stat == true
              and .clean == true
              and .changed_files == []
              and (.base | length > 0)' \
            "$work/apr-diff-remote.json" >/dev/null

          run_clean ${self}/bin/apm registry add --no-verify "file://$reg" --name host-reg-client > "$work/apm-registry-add.out" 2>&1
          grep -q "Registry 'host-reg-client' added" "$work/apm-registry-add.out"
          run_clean ${self}/bin/apm registry list > "$work/apm-registry-list.out" 2>&1
          grep -q "host-reg-client" "$work/apm-registry-list.out"
          run_clean ${self}/bin/apm --json registry list > "$work/apm-registry-list.json"
          ${pkgs.jq}/bin/jq -e \
            'length == 1
              and .[0].name == "host-reg-client"
              and .[0].enabled == true
              and .[0].status == "enabled"
              and .[0].packages == 1' \
            "$work/apm-registry-list.json" >/dev/null
          assert_no_profile
          run_clean ${self}/bin/apm search hostpkg --registry host-reg-client > "$work/apm-search.out" 2>&1
          grep -q "hostpkg/host-reg-client 1.0.0" "$work/apm-search.out"
          run_clean ${self}/bin/apm --json search hostpkg --registry host-reg-client > "$work/apm-search.json"
          ${pkgs.jq}/bin/jq -e \
            'length == 1 and .[0].name == "hostpkg" and .[0].registry == "host-reg-client" and .[0].version == "1.0.0"' \
            "$work/apm-search.json" >/dev/null
          run_clean ${self}/bin/apm search hostpkg --installed > "$work/apm-search-installed.out" 2>&1
          if grep -q "hostpkg" "$work/apm-search-installed.out"; then
            cat "$work/apm-search-installed.out"
            exit 1
          fi
          run_clean ${self}/bin/apm show hostpkg --registry host-reg-client > "$work/apm-show.out" 2>&1
          grep -q "Host-authored package metadata" "$work/apm-show.out"
          run_clean ${self}/bin/apm --json show hostpkg --registry host-reg-client > "$work/apm-show.json"
          ${pkgs.jq}/bin/jq -e \
            '.name == "hostpkg" and .registry == "host-reg-client" and .installed == false and .store_path == "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hostpkg-1.0.0"' \
            "$work/apm-show.json" >/dev/null
          run_clean ${self}/bin/apm list --registry host-reg-client > "$work/apm-list.out" 2>&1
          grep -q "hostpkg/host-reg-client 1.0.0" "$work/apm-list.out"
          run_clean ${self}/bin/apm --json list --registry host-reg-client > "$work/apm-list.json"
          ${pkgs.jq}/bin/jq -e \
            'length == 1 and .[0].name == "hostpkg" and .[0].status == ""' \
            "$work/apm-list.json" >/dev/null
          run_clean ${self}/bin/apm policy hostpkg > "$work/apm-policy.out" 2>&1
          grep -q "Candidate: 1.0.0" "$work/apm-policy.out"
          run_clean ${self}/bin/apm --json policy hostpkg > "$work/apm-policy.json"
          ${pkgs.jq}/bin/jq -e \
            '.package == "hostpkg"
              and .installed == null
              and .candidate == "1.0.0"
              and (.versions | length == 1)
              and .versions[0].registry == "host-reg-client"' \
            "$work/apm-policy.json" >/dev/null
          assert_no_profile
          run_clean ${self}/bin/apm --json depends hostpkg > "$work/apm-depends.json"
          ${pkgs.jq}/bin/jq -e \
            '.package == "hostpkg"
              and .installed == false
              and .registry == "host-reg-client"
              and .tree.name == "hostpkg"
              and .tree.children == []' \
            "$work/apm-depends.json" >/dev/null
          assert_no_profile
          run_clean ${self}/bin/apm --json rdepends hostpkg > "$work/apm-rdepends.json"
          ${pkgs.jq}/bin/jq -e \
            '.package == "hostpkg"
              and .target_versions == "1.0.0"
              and .dependents == []' \
            "$work/apm-rdepends.json" >/dev/null
          assert_no_profile
          run_clean ${self}/bin/apm held > "$work/apm-held.out" 2>&1
          grep -q "No packages are held" "$work/apm-held.out"
          assert_no_profile
          run_clean ${self}/bin/apm --json held > "$work/apm-held.json"
          ${pkgs.jq}/bin/jq -e 'length == 0' "$work/apm-held.json" >/dev/null
          assert_no_profile
          if run_clean ${self}/bin/apm hold hostpkg > "$work/apm-hold-missing.out" 2>&1; then
            cat "$work/apm-hold-missing.out"
            exit 1
          fi
          grep -q "package not found: hostpkg" "$work/apm-hold-missing.out"
          assert_no_profile
          if run_clean ${self}/bin/apm unhold hostpkg > "$work/apm-unhold-missing.out" 2>&1; then
            cat "$work/apm-unhold-missing.out"
            exit 1
          fi
          grep -q "package not found: hostpkg" "$work/apm-unhold-missing.out"
          assert_no_profile
          run_clean ${self}/bin/apm upgrade --yes > "$work/apm-upgrade-empty.out" 2>&1
          grep -q "All packages are up to date" "$work/apm-upgrade-empty.out"
          assert_no_profile
          run_clean ${self}/bin/apm --json clean --generations --keep 1 \
            > "$work/apm-clean-generations-empty.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "clean"
              and .mode == "generations"
              and .status == "current"
              and .keep == 1
              and .current_generation == null
              and .generations_before == []
              and .generations_after == []
              and .removed_generations == []
              and .removed == 0' \
            "$work/apm-clean-generations-empty.json" >/dev/null
          assert_no_profile
          if run_clean ${self}/bin/apm remove hostpkg --yes > "$work/apm-remove-missing.out" 2>&1; then
            cat "$work/apm-remove-missing.out"
            exit 1
          fi
          grep -q "nothing installed" "$work/apm-remove-missing.out"
          assert_no_profile
          if run_clean ${self}/bin/apm autoremove --yes > "$work/apm-autoremove-empty.out" 2>&1; then
            cat "$work/apm-autoremove-empty.out"
            exit 1
          fi
          grep -q "nothing installed" "$work/apm-autoremove-empty.out"
          assert_no_profile
          if run_clean ${self}/bin/apm rollback > "$work/apm-rollback-empty.out" 2>&1; then
            cat "$work/apm-rollback-empty.out"
            exit 1
          fi
          grep -q "no active generation" "$work/apm-rollback-empty.out"
          assert_no_profile
          run_clean ${self}/bin/apm rollback --list > "$work/apm-rollback-list.out" 2>&1
          grep -q "No profile generations" "$work/apm-rollback-list.out"
          assert_no_profile
          run_clean ${self}/bin/apm --json rollback --list > "$work/apm-rollback-list.json"
          ${pkgs.jq}/bin/jq -e 'length == 0' "$work/apm-rollback-list.json" >/dev/null
          assert_no_profile
          if run_clean ${self}/bin/apm files hostpkg > "$work/apm-files.out" 2>&1; then
            cat "$work/apm-files.out"
            exit 1
          fi
          grep -q "package not installed: hostpkg" "$work/apm-files.out"
          assert_no_profile
          run_clean ${self}/bin/apm orphans > "$work/apm-orphans.out" 2>&1
          grep -q "No orphaned packages" "$work/apm-orphans.out"
          assert_no_profile
          run_clean ${self}/bin/apm --json orphans > "$work/apm-orphans.json"
          ${pkgs.jq}/bin/jq -e 'length == 0' "$work/apm-orphans.json" >/dev/null
          assert_no_profile
          run_clean ${self}/bin/apm registry remove host-reg-client --keep-local > "$work/apm-registry-remove.out" 2>&1
          grep -q "Registry 'host-reg-client' removed" "$work/apm-registry-remove.out"
          test -d "$data/apm/registries/host-reg-client"

          cache_root="$work/static-cache"
          mkdir -p "$cache_root/cache/nar" "$reg/packages/m"
          printf '%s\n' "hostpkg NAR payload" > "$cache_root/cache/nar/$pkg_hash-hostpkg.nar"
          printf '%s\n' \
            "StorePath: /nix/store/$pkg_hash-hostpkg-1.0.0" \
            "URL: nar/$pkg_hash-hostpkg.nar" \
            "Compression: none" \
            'NarHash: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
            'NarSize: 1234' \
            'References:' \
            > "$cache_root/cache/$pkg_hash.narinfo"

          missing_hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          printf '%s\n' \
            '[package]' \
            'name = "missingpkg"' \
            'description = "Package metadata for a missing cache entry"' \
            'homepage = "https://example.invalid/missingpkg"' \
            'license = "MIT"' \
            'maintainer = "host@example.invalid"' \
            "" \
            '[[versions]]' \
            'version = "1.0.0"' \
            "" \
            '[versions.platforms.x86_64-linux]' \
            "store_path = \"/nix/store/$missing_hash-missingpkg-1.0.0\"" \
            'nar_hash = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="' \
            'nar_size = 4321' \
            'closure_size = 4321' \
            'source_drv = ""' \
            'source_nar_hash = ""' \
            'references = []' \
            > "$reg/packages/m/missingpkg.toml"
          git -C "$reg" add packages/m/missingpkg.toml
          git -C "$reg" commit -m "release: missingpkg 1.0.0" > "$work/git-commit-missing-package.out" 2>&1

          PYTHONUNBUFFERED=1 ${pkgs.python3}/bin/python3 -m http.server "$cache_port" \
            --bind 127.0.0.1 --directory "$cache_root" \
            > "$work/cache-server.log" 2>&1 &
          cache_server_pid=$!
          ${pkgs.coreutils}/bin/sleep 1
          if ! kill -0 "$cache_server_pid" 2>/dev/null; then
            cat "$work/cache-server.log"
            exit 1
          fi

          if run_clean ${self}/bin/apr validate --registry host-reg --jobs 2 > "$work/apr-validate-missing.out" 2>&1; then
            cat "$work/apr-validate-missing.out"
            exit 1
          fi
          grep -q "hostpkg: /nix/store/$pkg_hash-hostpkg-1.0.0" "$work/apr-validate-missing.out" && {
            cat "$work/apr-validate-missing.out"
            exit 1
          }
          grep -q "missingpkg: /nix/store/$missing_hash-missingpkg-1.0.0 not found in any cache" "$work/apr-validate-missing.out"
          grep -q "1 found, 1 missing" "$work/apr-validate-missing.out"
          test -f "$reg/packages/m/missingpkg.toml"
          assert_no_profile
          if run_clean ${self}/bin/apr --json validate --registry host-reg --jobs 2 \
            > "$work/apr-validate-missing.json" 2>&1; then
            cat "$work/apr-validate-missing.json"
            exit 1
          fi
          ${pkgs.jq}/bin/jq -e \
            --arg store "/nix/store/$missing_hash-missingpkg-1.0.0" \
            '.error
              | contains("1 found, 1 missing")
              and contains("missingpkg")
              and contains($store)' \
            "$work/apr-validate-missing.json" >/dev/null
          test -f "$reg/packages/m/missingpkg.toml"
          assert_no_profile

          run_clean ${self}/bin/apr --json validate --registry host-reg --jobs 2 --fix \
            > "$work/apr-validate-fix.json"
          ${pkgs.jq}/bin/jq -e \
            --arg store "/nix/store/$missing_hash-missingpkg-1.0.0" \
            '.status == "fixed"
              and .fix == true
              and .checked == 2
              and .found == 1
              and .missing == 1
              and .removed == 1
              and (.missing_entries | length == 1)
              and .missing_entries[0].name == "missingpkg"
              and .missing_entries[0].store_path == $store
              and (.missing_entries[0].details | length > 0)' \
            "$work/apr-validate-fix.json" >/dev/null
          test ! -e "$reg/packages/m/missingpkg.toml"
          assert_no_profile

          run_clean ${self}/bin/apr validate --registry host-reg --package hostpkg --jobs 2 > "$work/apr-validate-hostpkg.out" 2>&1
          grep -q "All 1 entries found in caches" "$work/apr-validate-hostpkg.out"
          assert_no_profile
          run_clean ${self}/bin/apr --json validate --registry host-reg --package hostpkg --jobs 2 \
            > "$work/apr-validate-hostpkg.json"
          ${pkgs.jq}/bin/jq -e \
            '.status == "ok"
              and .package == "hostpkg"
              and .fix == false
              and .checked == 1
              and .found == 1
              and .missing == 0
              and .removed == 0
              and .missing_entries == []' \
            "$work/apr-validate-hostpkg.json" >/dev/null
          assert_no_profile

          git -C "$reg" add -A
          git -C "$reg" commit -m "registry: prune missing cache metadata" > "$work/git-commit-validate-fix.out" 2>&1
          run_clean ${self}/bin/apr status --registry host-reg > "$work/apr-status-clean-before-release.out" 2>&1
          if grep -q '[^[:space:]]' "$work/apr-status-clean-before-release.out"; then
            cat "$work/apr-status-clean-before-release.out"
            exit 1
          fi

          ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -f "$work/release-key"
          run_clean ${self}/bin/apr --json release 1.0.0 \
            --registry host-reg \
            --key "$work/release-key" \
            --dry-run \
            --cache-output "$work/dry-cache" \
            --cache-url "http://127.0.0.1:$cache_port/cache" \
            --upload-url "file://$work/dry-upload" \
            > "$work/apr-release-dry-run.json"
          ${pkgs.jq}/bin/jq -e \
            --arg cache "$work/dry-cache" \
            --arg cache_url "http://127.0.0.1:$cache_port/cache" \
            --arg upload_url "file://$work/dry-upload" \
            '.action == "release"
              and .status == "planned"
              and .registry == "host-reg"
              and .version == "1.0.0"
              and .dry_run == true
              and .resume == false
              and .cache_output == $cache
              and .cache_url == $cache_url
              and .upload_urls == [$upload_url]
              and .cache == null
              and .full_pack == null
              and .deltas == []
              and (.planned_steps | index("generate_static_cache") != null)
              and (.planned_steps | index("upload_static_origin") != null)' \
            "$work/apr-release-dry-run.json" >/dev/null
          test ! -e "$work/dry-cache"
          test ! -e "$work/dry-upload"
          if git -C "$reg" rev-parse --verify '1.0.0^{tag}' > "$work/release-dry-run-tag.out" 2>&1; then
            cat "$work/release-dry-run-tag.out"
            exit 1
          fi
          run_clean ${self}/bin/apr status --registry host-reg > "$work/apr-status-after-dry-run.out" 2>&1
          if grep -q '[^[:space:]]' "$work/apr-status-after-dry-run.out"; then
            cat "$work/apr-status-after-dry-run.out"
            exit 1
          fi
          assert_no_profile

          run_clean ${self}/bin/apr --json release 1.0.0 \
            --registry host-reg \
            --key "$work/release-key" \
            > "$work/apr-release.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "release"
              and .status == "released"
              and .registry == "host-reg"
              and .version == "1.0.0"
              and .dry_run == false
              and .resume == false
              and (.full_pack | startswith("pack-") and endswith(".pack"))
              and .deltas == []
              and .cache == null
              and .cache_pointer_updated == false
              and .uploaded_files == null' \
            "$work/apr-release.json" >/dev/null
          git -C "$reg" rev-parse --verify '1.0.0^{tag}' > "$work/release-tag-object.out"
          git -C "$reg" cat-file -p 1.0.0 > "$work/release-tag.out"
          grep -q "BEGIN SSH SIGNATURE" "$work/release-tag.out"
          grep -q "tag 1.0.0" "$work/release-tag.out"
          find "$reg/.git/releases/1/0/0/objects/pack" -name 'pack-*.pack' | grep -q .

          run_clean ${self}/bin/apr --json release 1.0.0 \
            --registry host-reg \
            --key "$work/release-key" \
            --resume \
            > "$work/apr-release-resume.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "release"
              and .status == "released"
              and .registry == "host-reg"
              and .version == "1.0.0"
              and .resume == true
              and (.full_pack | startswith("pack-") and endswith(".pack"))
              and .deltas == []' \
            "$work/apr-release-resume.json" >/dev/null
          assert_no_profile

          if run_clean ${self}/bin/apr sign --registry host-reg --key "$work/release-key" \
            > "$work/apr-sign-missing-tag.out" 2>&1; then
            cat "$work/apr-sign-missing-tag.out"
            exit 1
          fi
          grep -q "pass the existing tag name to re-sign" "$work/apr-sign-missing-tag.out"

          initial_tag_object=$(git -C "$reg" rev-parse '1.0.0^{tag}')
          initial_tag_commit=$(git -C "$reg" rev-parse '1.0.0^{commit}')
          ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -f "$work/release-key-next"
          run_clean ${self}/bin/apr sign 1.0.0 \
            --registry host-reg \
            --key "$work/release-key-next" \
            > "$work/apr-sign.out" 2>&1
          grep -q "Re-signed tag '1.0.0'" "$work/apr-sign.out"
          resigned_tag_object=$(git -C "$reg" rev-parse '1.0.0^{tag}')
          resigned_tag_commit=$(git -C "$reg" rev-parse '1.0.0^{commit}')
          test "$resigned_tag_commit" = "$initial_tag_commit"
          test "$resigned_tag_object" != "$initial_tag_object"
          git -C "$reg" cat-file -p 1.0.0 > "$work/release-tag-resigned.out"
          grep -q "BEGIN SSH SIGNATURE" "$work/release-tag-resigned.out"
          assert_no_profile

          v2_hash="cccccccccccccccccccccccccccccccc"
          printf '%s\n' \
            "" \
            '[[versions]]' \
            'version = "2.0.0"' \
            "" \
            '[versions.platforms.x86_64-linux]' \
            "store_path = \"/nix/store/$v2_hash-hostpkg-2.0.0\"" \
            'nar_hash = "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="' \
            'nar_size = 2345' \
            'closure_size = 2345' \
            'source_drv = ""' \
            'source_nar_hash = ""' \
            'references = []' \
            >> "$reg/packages/h/hostpkg.toml"
          printf '%s\n' "$v2_hash" > "$reg/closures/$v2_hash"
          git -C "$reg" add -A
          git -C "$reg" commit -m "release: hostpkg 2.0.0" > "$work/git-commit-v2-package.out" 2>&1

          run_clean ${self}/bin/apr --json release 2.0.0 \
            --registry host-reg \
            --key "$work/release-key-next" \
            > "$work/apr-release-v2.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "release"
              and .status == "released"
              and .registry == "host-reg"
              and .version == "2.0.0"
              and (.full_pack | startswith("pack-") and endswith(".pack"))
              and (.deltas | index("delta-1.0.0.pack.zst") != null)' \
            "$work/apr-release-v2.json" >/dev/null
          find "$reg/.git/releases/2/0/0/objects/pack" -name 'pack-*.pack' | grep -q .
          test -f "$reg/.git/releases/2/0/0/objects/pack/delta-1.0.0.pack.zst"
          git -C "$reg" rev-parse --verify '2.0.0^{tag}' > "$work/release-v2-tag-object.out"
          git -C "$reg" cat-file -p 2.0.0 > "$work/release-v2-tag.out"
          grep -q "BEGIN SSH SIGNATURE" "$work/release-v2-tag.out"

          run_clean ${self}/bin/apr --json channel init canary 1.0.0 \
            --registry host-reg \
            --key "$work/release-key-next" \
            > "$work/apr-channel-init.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "channel_init"
              and .registry == "host-reg"
              and .channel == "canary"
              and .version == "1.0.0"
              and .partitions == 256
              and .frontier == "1.0.0"' \
            "$work/apr-channel-init.json" >/dev/null
          test -f "$reg/.git/channels/canary/00"
          grep -q "BEGIN SSH SIGNATURE" "$reg/.git/channels/canary/00"
          run_clean ${self}/bin/apr channel status canary --registry host-reg > "$work/apr-channel-status-v1.out" 2>&1
          grep -q "Frontier: 1.0.0" "$work/apr-channel-status-v1.out"
          grep -q "1.0.0: 256/256" "$work/apr-channel-status-v1.out"
          run_clean ${self}/bin/apr --json channel status canary --registry host-reg \
            > "$work/apr-channel-status-v1.json"
          ${pkgs.jq}/bin/jq -e \
            '.channel == "canary"
              and .frontier == "1.0.0"
              and .missing_partitions == 0
              and (.versions | length == 1)
              and .versions[0].version == "1.0.0"
              and .versions[0].partitions == 256' \
            "$work/apr-channel-status-v1.json" >/dev/null

          run_clean ${self}/bin/apr --json channel advance canary 2.0.0 \
            --registry host-reg \
            --key "$work/release-key-next" \
            --partitions 0x00,0x2a \
            > "$work/apr-channel-advance.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "channel_advance"
              and .registry == "host-reg"
              and .channel == "canary"
              and .version == "2.0.0"
              and .status == "advanced"
              and .partition_count == 2
              and (.partitions | index(0) != null)
              and (.partitions | index(42) != null)
              and .frontier == "2.0.0"' \
            "$work/apr-channel-advance.json" >/dev/null
          run_clean ${self}/bin/apr channel status canary --registry host-reg > "$work/apr-channel-status-v2.out" 2>&1
          grep -q "Frontier: 2.0.0" "$work/apr-channel-status-v2.out"
          grep -q "2.0.0: 2/256" "$work/apr-channel-status-v2.out"
          grep -q "1.0.0: 254/256" "$work/apr-channel-status-v2.out"
          run_clean ${self}/bin/apr --json channel status canary --registry host-reg \
            > "$work/apr-channel-status-v2.json"
          ${pkgs.jq}/bin/jq -e \
            '.channel == "canary"
              and .frontier == "2.0.0"
              and .missing_partitions == 0
              and (.versions | any(.version == "2.0.0" and .partitions == 2))
              and (.versions | any(.version == "1.0.0" and .partitions == 254))' \
            "$work/apr-channel-status-v2.json" >/dev/null

          upload_root="$work/uploaded-origin"
          run_clean ${self}/bin/apr --json origin upload \
            --registry host-reg \
            --cache-dir "$cache_root/cache" \
            --upload-url "file://$upload_root" \
            > "$work/apr-origin-upload.json"
          ${pkgs.jq}/bin/jq -e \
            --arg upload_url "file://$upload_root" \
            --arg cache_dir "$cache_root/cache" \
            '.action == "origin_upload"
              and .registry == "host-reg"
              and .upload_urls == [$upload_url]
              and .cache_dir == $cache_dir
              and .files > 0
              and .bytes > 0
              and (.bytes_human | length > 0)' \
            "$work/apr-origin-upload.json" >/dev/null
          test -f "$upload_root/HEAD"
          test -f "$upload_root/info/refs"
          test -f "$upload_root/releases/1/0/0/objects/info/packs"
          test -f "$upload_root/releases/2/0/0/objects/info/packs"
          find "$upload_root/releases/2/0/0/objects/pack" -name 'pack-*.pack' | grep -q .
          test -f "$upload_root/releases/2/0/0/objects/pack/delta-1.0.0.pack.zst"
          test -f "$upload_root/channels/canary/00"
          test -f "$upload_root/$pkg_hash.narinfo"
          test -f "$upload_root/nar/$pkg_hash-hostpkg.nar"
          assert_no_profile

          cat > "$work/host-build-leaf.sh" << 'SCRIPT'
          set -eu
          @AOS_COREUTILS@/bin/mkdir -p "$out/bin" "$out/share/host-leaf"
          {
            printf '%s\n' '#!@AOS_BASH@/bin/bash'
            printf '%s\n' 'printf "host leaf package executed\n"'
          } > "$out/bin/host-leaf-tool"
          @AOS_COREUTILS@/bin/chmod +x "$out/bin/host-leaf-tool"
          printf '%s\n' "host leaf payload" > "$out/share/host-leaf/payload.txt"
          SCRIPT
          cat > "$work/host-build-leaf-v2.sh" << 'SCRIPT'
          set -eu
          @AOS_COREUTILS@/bin/mkdir -p "$out/bin" "$out/share/host-leaf"
          {
            printf '%s\n' '#!@AOS_BASH@/bin/bash'
            printf '%s\n' 'printf "host leaf package v2 executed\n"'
          } > "$out/bin/host-leaf-tool"
          @AOS_COREUTILS@/bin/chmod +x "$out/bin/host-leaf-tool"
          printf '%s\n' "host leaf payload v2" > "$out/share/host-leaf/payload.txt"
          SCRIPT
          cat > "$work/host-build-app-v1.sh" << 'SCRIPT'
          set -eu
          leaf="$1"
          @AOS_COREUTILS@/bin/mkdir -p "$out/bin" "$out/share/host-install"
          {
            printf '%s\n' '#!@AOS_BASH@/bin/bash'
            printf '%s\n' "\"$leaf/bin/host-leaf-tool\""
            printf '%s\n' 'printf "host install package executed\n"'
          } > "$out/bin/host-install-tool"
          @AOS_COREUTILS@/bin/chmod +x "$out/bin/host-install-tool"
          printf '%s\n' "host install payload" > "$out/share/host-install/payload.txt"
          SCRIPT
          cat > "$work/host-build-app-v2.sh" << 'SCRIPT'
          set -eu
          leaf="$1"
          @AOS_COREUTILS@/bin/mkdir -p "$out/bin" "$out/share/host-install"
          {
            printf '%s\n' '#!@AOS_BASH@/bin/bash'
            printf '%s\n' "\"$leaf/bin/host-leaf-tool\""
            printf '%s\n' 'printf "host install package v2 executed\n"'
          } > "$out/bin/host-install-tool"
          @AOS_COREUTILS@/bin/chmod +x "$out/bin/host-install-tool"
          printf '%s\n' "host install payload v2" > "$out/share/host-install/payload.txt"
          SCRIPT
          substitute_fixture_paths() {
            ${pkgs.python3}/bin/python3 - "$1" '${pkgs.bash}' '${pkgs.coreutils}' << 'PY'
          from pathlib import Path
          import sys

          path = Path(sys.argv[1])
          path.write_text(
              path.read_text()
              .replace("@AOS_BASH@", sys.argv[2])
              .replace("@AOS_COREUTILS@", sys.argv[3])
          )
          PY
          }
          substitute_fixture_paths "$work/host-build-leaf.sh"
          substitute_fixture_paths "$work/host-build-leaf-v2.sh"
          substitute_fixture_paths "$work/host-build-app-v1.sh"
          substitute_fixture_paths "$work/host-build-app-v2.sh"
          cat > "$work/host-install-fixtures.nix" << 'NIX'
          let
            bash = "@AOS_BASH@/bin/bash";
            system = "x86_64-linux";
            leafV1 = derivation {
              name = "hostleaf-1.0.0";
              inherit system;
              builder = bash;
              args = [ ./host-build-leaf.sh ];
            };
            leafV2 = derivation {
              name = "hostleaf-2.0.0";
              inherit system;
              builder = bash;
              args = [ ./host-build-leaf-v2.sh ];
            };
            app = name: leaf: builderScript: derivation {
              inherit name system;
              builder = bash;
              args = [
                builderScript
                leaf
              ];
              inherit leaf;
            };
          in {
            leaf = leafV1;
            inherit leafV1 leafV2;
            appV1 = app "hostinstall-1.0.0" leafV1 ./host-build-app-v1.sh;
            appV2 = app "hostinstall-2.0.0" leafV2 ./host-build-app-v2.sh;
          }
          NIX
          substitute_fixture_paths "$work/host-install-fixtures.nix"

          install_leaf_store=$(nix_build "$work/host-install-fixtures.nix" -A leaf --no-out-link)
          install_leaf_hash=$(basename "$install_leaf_store" | cut -d- -f1)
          install_store=$(nix_build "$work/host-install-fixtures.nix" -A appV1 --no-out-link)
          install_hash=$(basename "$install_store" | cut -d- -f1)

          ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -f "$work/host-install-release-key"
          install_release_public_key=$(${pkgs.coreutils}/bin/cut -d ' ' -f2 < "$work/host-install-release-key.pub")
          install_channel_trust_key="host-install-channel:Ed25519:$install_release_public_key"
          run_clean ${self}/bin/apr create host-install-channel \
            --trust-key "$install_channel_trust_key" \
            --trust-key-id channel \
            --key "$work/host-install-release-key" \
            > "$work/apr-create-host-install.out" 2>&1
          install_reg="$data/apm/registries/host-install-channel"
          git -C "$install_reg" config user.name "Host Command Test"
          git -C "$install_reg" config user.email "host-command@example.invalid"
          run_clean ${self}/bin/apr --json publish "$install_leaf_store" \
            --name hostleaf \
            --version 1.0.0 \
            --description "Host APM dependency fixture" \
            --license MIT \
            --maintainer host@example.invalid \
            --registry host-install-channel \
            --no-commit > "$work/apr-publish-host-leaf.json"
          ${pkgs.jq}/bin/jq -e \
            --arg store "$install_leaf_store" \
            '.action == "publish"
              and .registry == "host-install-channel"
              and .package == "hostleaf"
              and .version == "1.0.0"
              and .platform == "x86_64-linux"
              and .store_path == $store
              and (.nar_hash | startswith("sha256-"))
              and (.closure_size > 0)
              and .committed == false' \
            "$work/apr-publish-host-leaf.json" >/dev/null
          run_clean ${self}/bin/apr --json publish "$install_store" \
            --name hostinstall \
            --version 1.0.0 \
            --description "Host APM install fixture" \
            --license MIT \
            --maintainer host@example.invalid \
            --registry host-install-channel \
            --no-commit > "$work/apr-publish-host-install.json"
          ${pkgs.jq}/bin/jq -e \
            --arg store "$install_store" \
            '.action == "publish"
              and .registry == "host-install-channel"
              and .package == "hostinstall"
              and .version == "1.0.0"
              and .platform == "x86_64-linux"
              and .store_path == $store
              and (.nar_hash | startswith("sha256-"))
              and (.nar_size > 0)
              and (.closure_size > 0)
              and .source == null
              and .sysroot == false
              and .previous == null
              and .images == []
              and .package_file == "packages/h/hostinstall.toml"
              and (.closure_file | startswith("closures/"))
              and .committed == false
              and .commit_message == null
              and .current == "stable"
              and (.head | length == 64)' \
            "$work/apr-publish-host-install.json" >/dev/null
          grep -q "$install_leaf_hash" "$install_reg/closures/$install_hash"
          run_clean ${self}/bin/apr --json cache generate \
            --registry host-install-channel \
            --output "$work/install-static-cache-output/cache" \
            --cache-url "http://127.0.0.1:$install_cache_port/cache" \
            --upload-url "file://$work/install-static-cache-upload/cache" \
            --priority 77 \
            --no-commit > "$work/apr-cache-host-install.json"
          ${pkgs.jq}/bin/jq -e \
            --arg output "$work/install-static-cache-output/cache" \
            --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
            --arg upload_url "file://$work/install-static-cache-upload/cache" \
            '.action == "cache_generate"
              and .registry == "host-install-channel"
              and .output_dir == $output
              and .paths >= 2
              and .narinfos >= 2
              and .nars >= 2
              and .cache_url == $cache_url
              and .priority == 77
              and .upload_urls == [$upload_url]
              and .uploaded == true
              and .cache_pointer_updated == true
              and .committed == false' \
            "$work/apr-cache-host-install.json" >/dev/null
          test -f "$work/install-static-cache-output/cache/$install_leaf_hash.narinfo"
          test -f "$work/install-static-cache-output/cache/$install_hash.narinfo"
          test -f "$work/install-static-cache-upload/cache/nix-cache-info"
          test -f "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
          test -f "$work/install-static-cache-upload/cache/$install_hash.narinfo"
          find "$work/install-static-cache-upload/cache/nar" -type f | grep -q .
          git -C "$install_reg" add -A
          git -C "$install_reg" \
            -c gpg.format=ssh \
            -c gpg.ssh.program=${pkgs.openssh}/bin/ssh-keygen \
            -c user.signingkey="$work/host-install-release-key" \
            commit -S -m "release: hostinstall 1.0.0" \
            > "$work/git-commit-host-install.out" 2>&1
          run_clean ${self}/bin/apr --json release 1.0.0 \
            --registry host-install-channel \
            --key "$work/host-install-release-key" \
            --cache-output "$work/install-release-cache/cache" \
            --cache-url "http://127.0.0.1:$install_cache_port/cache" \
            --cache-priority 77 \
            --upload-url "file://$work/install-static-cache-upload/cache" \
            --channel stable \
            --init-channel > "$work/apr-release-host-install-v1.json"
          ${pkgs.jq}/bin/jq -e \
            --arg cache "$work/install-release-cache/cache" \
            --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
            --arg upload_url "file://$work/install-static-cache-upload/cache" \
            '.action == "release"
              and .status == "released"
              and .registry == "host-install-channel"
              and .version == "1.0.0"
              and .dry_run == false
              and .cache_output == $cache
              and .cache_url == $cache_url
              and .cache_priority == 77
              and .cache_pointer_updated == false
              and .upload_urls == [$upload_url]
              and .channel.name == "stable"
              and .channel.action == "init"
              and .channel.touched_partitions == 256
              and (.cache.paths >= 2)
              and (.cache.narinfos >= 2)
              and (.cache.nars >= 2)
              and .cache.output_dir == $cache
              and (.full_pack | startswith("pack-") and endswith(".pack"))
              and .deltas == []
              and (.uploaded_files > 0)
              and (.uploaded_bytes > 0)' \
            "$work/apr-release-host-install-v1.json" >/dev/null
          git -C "$install_reg" rev-parse --verify '1.0.0^{tag}' \
            > "$work/apr-release-host-install-v1-tag.out"
          git -C "$install_reg" cat-file -p 1.0.0 \
            > "$work/apr-release-host-install-v1-tag-object.out"
          grep -q "BEGIN SSH SIGNATURE" \
            "$work/apr-release-host-install-v1-tag-object.out"
          test -f "$work/install-release-cache/cache/$install_leaf_hash.narinfo"
          test -f "$work/install-release-cache/cache/$install_hash.narinfo"
          test -f "$work/install-static-cache-upload/cache/HEAD"
          test -f "$work/install-static-cache-upload/cache/info/refs"
          test -f "$work/install-static-cache-upload/cache/releases/1/0/0/objects/info/packs"
          test -f "$work/install-static-cache-upload/cache/channels/stable/00"
          grep -q "BEGIN SSH SIGNATURE" \
            "$work/install-static-cache-upload/cache/channels/stable/00"
          test -f "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
          test -f "$work/install-static-cache-upload/cache/$install_hash.narinfo"
          find "$work/install-static-cache-upload/cache/releases/1/0/0/objects/pack" \
            -name 'pack-*.pack' | grep -q .
          install_origin="$work/host-install-origin.git"
          git init --bare --object-format=sha256 "$install_origin" \
            > "$work/git-init-host-install-origin.out" 2>&1
          git -C "$install_reg" remote add origin "$install_origin"
          install_remote_v1_commit=$(git -C "$install_reg" rev-parse HEAD)
          run_clean ${self}/bin/apr --json push \
            --registry host-install-channel \
            --branch stable \
            --set-upstream > "$work/apr-push-host-install-v1.json"
          ${pkgs.jq}/bin/jq -e \
            --arg head "$install_remote_v1_commit" \
            '.action == "push"
              and .branch == "stable"
              and .set_upstream == true
              and .force == false
              and .head == $head
              and (.branches | any(.name == "origin/stable" and .remote == true))' \
            "$work/apr-push-host-install-v1.json" >/dev/null

          PYTHONUNBUFFERED=1 ${pkgs.python3}/bin/python3 -m http.server "$install_cache_port" \
            --bind 127.0.0.1 --directory "$work/install-static-cache-upload" \
            > "$work/install-cache-server.log" 2>&1 &
          install_cache_server_pid=$!
          ${pkgs.coreutils}/bin/sleep 1
          if ! kill -0 "$install_cache_server_pid" 2>/dev/null; then
            cat "$work/install-cache-server.log"
            exit 1
          fi
          main_home="$home"
          main_config="$config"
          main_data="$data"
          main_cache="$cache"
          main_profile_root="$profile_root"
          main_profile="$profile"
          home="$work/channel-home"
          config="$work/channel-config"
          data="$work/channel-share"
          cache="$work/channel-cache"
          profile_root="$work/channel-profiles"
          profile="$profile_root/per-user/unknown"
          mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
          run_clean ${self}/bin/apm registry add "http://127.0.0.1:$install_cache_port/cache" \
            --name host-install-channel \
            --channel stable \
            --trust-key "$install_channel_trust_key" \
            > "$work/apm-add-host-install-channel.out" 2>&1
          grep -q "Registry 'host-install-channel' added" \
            "$work/apm-add-host-install-channel.out"
          channel_config="$config/apm/registries.d/host-install-channel.toml"
          grep -q 'channel = "stable"' "$channel_config"
          grep -q 'floor = "1.0.0"' "$channel_config"
          grep -q 'bucket = ' "$channel_config"
          grep -q 'public_key = "host-install-channel:Ed25519:' "$channel_config"
          run_clean ${self}/bin/apm search hostinstall \
            --registry host-install-channel \
            > "$work/apm-search-host-install-channel.out" 2>&1
          grep -q "hostinstall/host-install-channel 1.0.0" \
            "$work/apm-search-host-install-channel.out"
          grep -q "http://127.0.0.1:$install_cache_port/cache" \
            "$data/apm/registries/host-install-channel/registry.toml"
          assert_no_profile
          nix_store --delete --ignore-liveness "$install_store" \
            > "$work/nix-delete-host-install-channel.out" 2>&1
          nix_store --delete --ignore-liveness "$install_leaf_store" \
            > "$work/nix-delete-host-leaf-channel.out" 2>&1
          if nix_store --check-validity "$install_store" \
            > "$work/nix-valid-host-install-channel-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-install-channel-deleted.out"
            exit 1
          fi
          if nix_store --check-validity "$install_leaf_store" \
            > "$work/nix-valid-host-leaf-channel-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-leaf-channel-deleted.out"
            exit 1
          fi
          run_clean ${self}/bin/apm --json install hostinstall \
            --registry host-install-channel \
            --yes > "$work/apm-install-host-install-channel.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
            '.action == "install"
              and .status == "installed"
              and .requested == ["hostinstall"]
              and .generation == 1
              and (.roots | length == 1)
              and .roots[0].name == "hostinstall"
              and .roots[0].registry == "host-install-channel"
              and .roots[0].version == "1.0.0"
              and .roots[0].store_path == $store
              and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
              and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
              and (.downloads.planned >= 2)
              and (.downloads.downloaded >= 2)
              and (.downloads.imported >= 2)' \
            "$work/apm-install-host-install-channel.json" >/dev/null
          nix_store --check-validity "$install_store" \
            > "$work/nix-valid-host-install-channel-imported.out" 2>&1
          nix_store --check-validity "$install_leaf_store" \
            > "$work/nix-valid-host-leaf-channel-imported.out" 2>&1
          "$profile/current/bin/host-install-tool" \
            > "$work/host-install-channel-run.out"
          grep -q "host leaf package executed" "$work/host-install-channel-run.out"
          grep -q "host install package executed" "$work/host-install-channel-run.out"
          "$profile/current/bin/host-leaf-tool" \
            > "$work/host-leaf-channel-run.out"
          grep -q "host leaf package executed" "$work/host-leaf-channel-run.out"
          assert_default_profile_absent
          static_channel_home="$home"
          static_channel_config="$config"
          static_channel_data="$data"
          static_channel_cache="$cache"
          static_channel_profile_root="$profile_root"
          static_channel_profile="$profile"
          home="$main_home"
          config="$main_config"
          data="$main_data"
          cache="$main_cache"
          profile_root="$main_profile_root"
          profile="$main_profile"

          run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
            --name host-install-client \
            --branch stable > "$work/apm-add-host-install.out" 2>&1
          grep -q "Registry 'host-install-client' added" "$work/apm-add-host-install.out"

          nix_store --delete --ignore-liveness "$install_store" \
            > "$work/nix-delete-host-install.out" 2>&1
          nix_store --delete --ignore-liveness "$install_leaf_store" \
            > "$work/nix-delete-host-leaf.out" 2>&1
          if nix_store --check-validity "$install_store" \
            > "$work/nix-valid-host-install-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-install-deleted.out"
            exit 1
          fi
          if nix_store --check-validity "$install_leaf_store" \
            > "$work/nix-valid-host-leaf-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-leaf-deleted.out"
            exit 1
          fi

          run_clean ${self}/bin/apm --json install hostinstall \
            --registry host-install-client \
            --yes > "$work/apm-install-host-install.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
            '.action == "install"
              and .status == "installed"
              and .requested == ["hostinstall"]
              and .reinstall == false
              and .download_only == false
              and .no_deps == false
              and .dry_run == false
              and .generation == 1
              and (.roots | length == 1)
              and .roots[0].name == "hostinstall"
              and .roots[0].registry == "host-install-client"
              and .roots[0].version == "1.0.0"
              and .roots[0].store_path == $store
              and .roots[0].explicit == true
              and (.closure | length >= 2)
              and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
              and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
              and (.downloads.planned >= 2)
              and (.downloads.downloaded >= 2)
              and (.downloads.imported >= 2)' \
            "$work/apm-install-host-install.json" >/dev/null
          nix_store --check-validity "$install_store" \
            > "$work/nix-valid-host-install-imported.out" 2>&1
          nix_store --check-validity "$install_leaf_store" \
            > "$work/nix-valid-host-leaf-imported.out" 2>&1
          "$profile/current/bin/host-install-tool" > "$work/host-install-run.out"
          grep -q "host leaf package executed" "$work/host-install-run.out"
          grep -q "host install package executed" "$work/host-install-run.out"
          "$profile/current/bin/host-leaf-tool" > "$work/host-leaf-run.out"
          grep -q "host leaf package executed" "$work/host-leaf-run.out"
          assert_default_profile_absent

          run_clean ${self}/bin/apm verify hostinstall > "$work/apm-verify-host-install.out" 2>&1
          grep -q "integrity verified" "$work/apm-verify-host-install.out"
          run_clean ${self}/bin/apm --json verify hostinstall > "$work/apm-verify-host-install.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store" \
            '.package == "hostinstall"
              and .registry == "host-install-client"
              and .version == "1.0.0"
              and .store_path == $store
              and .verified == true
              and (.expected_nar_hash | startswith("sha256-"))
              and (.actual_nar_hash | startswith("sha256:"))' \
            "$work/apm-verify-host-install.json" >/dev/null
          assert_default_profile_absent
          run_clean ${self}/bin/apm files hostinstall > "$work/apm-files-host-install.out" 2>&1
          grep -q "bin/host-install-tool" "$work/apm-files-host-install.out"
          run_clean ${self}/bin/apm --json files hostleaf > "$work/apm-files-host-leaf.json"
          ${pkgs.jq}/bin/jq -e \
            'index("bin/host-leaf-tool") != null and index("share/host-leaf/payload.txt") != null' \
            "$work/apm-files-host-leaf.json" >/dev/null
          run_clean ${self}/bin/apm --json depends hostinstall > "$work/apm-depends-host-install.json"
          ${pkgs.jq}/bin/jq -e \
            --arg app "$install_hash" \
            --arg leaf "$install_leaf_hash" \
            '.package == "hostinstall"
              and .registry == "host-install-client"
              and .installed == true
              and .tree.name == "hostinstall"
              and .tree.store_hash == $app
              and (.tree.children | any(.name == "hostleaf"
                and .version == "1.0.0"
                and .store_hash == $leaf))
              and .unique_store_paths >= 2' \
            "$work/apm-depends-host-install.json" >/dev/null
          run_clean ${self}/bin/apm --json rdepends hostleaf > "$work/apm-rdepends-host-leaf.json"
          ${pkgs.jq}/bin/jq -e \
            --arg leaf "$install_leaf_hash" \
            '.package == "hostleaf"
              and .target_versions == "1.0.0"
              and (.target_hashes | index($leaf) != null)
              and (.dependents | any(.name == "hostinstall" and .version == "1.0.0"))' \
            "$work/apm-rdepends-host-leaf.json" >/dev/null
          run_clean ${self}/bin/apm --json policy hostleaf > "$work/apm-policy-host-leaf.json"
          ${pkgs.jq}/bin/jq -e \
            '.package == "hostleaf"
              and .installed == "1.0.0"
              and .candidate == "1.0.0"
              and (.versions | any(.version == "1.0.0"
                and .registry == "host-install-client"
                and .installed == true))' \
            "$work/apm-policy-host-leaf.json" >/dev/null

          install_leaf_store_v2=$(nix_build "$work/host-install-fixtures.nix" -A leafV2 --no-out-link)
          install_leaf_hash_v2=$(basename "$install_leaf_store_v2" | cut -d- -f1)
          install_store_v2=$(nix_build "$work/host-install-fixtures.nix" -A appV2 --no-out-link)
          install_hash_v2=$(basename "$install_store_v2" | cut -d- -f1)
          run_clean ${self}/bin/apr publish "$install_leaf_store_v2" \
            --name hostleaf \
            --version 2.0.0 \
            --description "Host APM dependency fixture v2" \
            --license MIT \
            --maintainer host@example.invalid \
            --registry host-install-channel \
            --no-commit > "$work/apr-publish-host-leaf-v2.out" 2>&1
          run_clean ${self}/bin/apr publish "$install_store_v2" \
            --name hostinstall \
            --version 2.0.0 \
            --description "Host APM install fixture v2" \
            --license MIT \
            --maintainer host@example.invalid \
            --registry host-install-channel \
            --no-commit > "$work/apr-publish-host-install-v2.out" 2>&1
          run_clean ${self}/bin/apr --json cache generate \
            --registry host-install-channel \
            --output "$work/install-static-cache-output/cache" \
            --cache-url "http://127.0.0.1:$install_cache_port/cache" \
            --upload-url "file://$work/install-static-cache-upload/cache" \
            --priority 77 \
            --no-commit > "$work/apr-cache-host-install-v2.json"
          ${pkgs.jq}/bin/jq -e \
            --arg output "$work/install-static-cache-output/cache" \
            --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
            --arg upload_url "file://$work/install-static-cache-upload/cache" \
            '.action == "cache_generate"
              and .registry == "host-install-channel"
              and .output_dir == $output
              and .paths >= 4
              and .narinfos >= 4
              and .nars >= 4
              and .cache_url == $cache_url
              and .priority == 77
              and .upload_urls == [$upload_url]
              and .uploaded == true
              and .cache_pointer_updated == false
              and .committed == false' \
            "$work/apr-cache-host-install-v2.json" >/dev/null
          test -f "$work/install-static-cache-output/cache/$install_leaf_hash.narinfo"
          test -f "$work/install-static-cache-output/cache/$install_leaf_hash_v2.narinfo"
          test -f "$work/install-static-cache-output/cache/$install_hash_v2.narinfo"
          test -f "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
          test -f "$work/install-static-cache-upload/cache/$install_leaf_hash_v2.narinfo"
          test -f "$work/install-static-cache-upload/cache/$install_hash.narinfo"
          test -f "$work/install-static-cache-upload/cache/$install_hash_v2.narinfo"
          find "$work/install-static-cache-upload/cache/nar" -type f | grep -q .
          git -C "$install_reg" add -A
          git -C "$install_reg" \
            -c gpg.format=ssh \
            -c gpg.ssh.program=${pkgs.openssh}/bin/ssh-keygen \
            -c user.signingkey="$work/host-install-release-key" \
            commit -S -m "release: hostinstall 2.0.0" \
            > "$work/git-commit-host-install-v2.out" 2>&1
          run_clean ${self}/bin/apr --json release 2.0.0 \
            --registry host-install-channel \
            --key "$work/host-install-release-key" \
            --cache-output "$work/install-release-cache-v2/cache" \
            --cache-url "http://127.0.0.1:$install_cache_port/cache" \
            --cache-priority 77 \
            --upload-url "file://$work/install-static-cache-upload/cache" \
            --channel stable \
            --count 256 > "$work/apr-release-host-install-v2.json"
          ${pkgs.jq}/bin/jq -e \
            --arg cache "$work/install-release-cache-v2/cache" \
            --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
            --arg upload_url "file://$work/install-static-cache-upload/cache" \
            '.action == "release"
              and .status == "released"
              and .registry == "host-install-channel"
              and .version == "2.0.0"
              and .dry_run == false
              and .cache_output == $cache
              and .cache_url == $cache_url
              and .cache_priority == 77
              and .cache_pointer_updated == false
              and .upload_urls == [$upload_url]
              and .channel.name == "stable"
              and .channel.action == "advance"
              and .channel.count == 256
              and .channel.touched_partitions == 256
              and (.cache.paths >= 4)
              and (.cache.narinfos >= 4)
              and (.cache.nars >= 4)
              and .cache.output_dir == $cache
              and (.full_pack | startswith("pack-") and endswith(".pack"))
              and (.deltas | index("delta-1.0.0.pack.zst") != null)
              and (.uploaded_files > 0)
              and (.uploaded_bytes > 0)' \
            "$work/apr-release-host-install-v2.json" >/dev/null
          git -C "$install_reg" rev-parse --verify '2.0.0^{tag}' \
            > "$work/apr-release-host-install-v2-tag.out"
          test -f "$work/install-release-cache-v2/cache/$install_leaf_hash_v2.narinfo"
          test -f "$work/install-release-cache-v2/cache/$install_hash_v2.narinfo"
          test -f "$work/install-static-cache-upload/cache/releases/2/0/0/objects/info/packs"
          test -f "$work/install-static-cache-upload/cache/releases/2/0/0/objects/pack/delta-1.0.0.pack.zst"
          grep -q "BEGIN SSH SIGNATURE" \
            "$work/install-static-cache-upload/cache/channels/stable/00"

          home="$static_channel_home"
          config="$static_channel_config"
          data="$static_channel_data"
          cache="$static_channel_cache"
          profile_root="$static_channel_profile_root"
          profile="$static_channel_profile"
          channel_config="$config/apm/registries.d/host-install-channel.toml"
          run_clean ${self}/bin/apm --json update --registry host-install-channel \
            > "$work/apm-update-host-install-channel-v2.json" 2>&1 || {
            cat "$work/apm-update-host-install-channel-v2.json"
            exit 1
          }
          ${pkgs.jq}/bin/jq -e \
            '.registry == "host-install-channel"
              and .updated == 1
              and (.registries | length == 1)
              and .registries[0].registry == "host-install-channel"
              and .registries[0].status == "updated"
              and .registries[0].packages == 2
              and .registries[0].updated == 2
              and .registries[0].added == 0
              and .registries[0].removed == 0
              and (.registries[0].commit | length == 64)' \
            "$work/apm-update-host-install-channel-v2.json" >/dev/null || {
            cat "$work/apm-update-host-install-channel-v2.json"
            exit 1
          }
          grep -q 'floor = "2.0.0"' "$channel_config"
          run_clean ${self}/bin/apm list --upgradable \
            > "$work/apm-upgradable-host-install-channel.out" 2>&1 || {
            cat "$work/apm-upgradable-host-install-channel.out"
            exit 1
          }
          grep -q "hostinstall/host-install-channel" \
            "$work/apm-upgradable-host-install-channel.out" || {
            cat "$work/apm-upgradable-host-install-channel.out"
            exit 1
          }
          grep -q "upgradable: 2.0.0" \
            "$work/apm-upgradable-host-install-channel.out" || {
            cat "$work/apm-upgradable-host-install-channel.out"
            exit 1
          }
          nix_store --delete --ignore-liveness "$install_store_v2" \
            > "$work/nix-delete-host-install-channel-upgrade-v2.out" 2>&1
          nix_store --delete --ignore-liveness "$install_leaf_store_v2" \
            > "$work/nix-delete-host-leaf-channel-upgrade-v2.out" 2>&1
          if nix_store --check-validity "$install_store_v2" \
            > "$work/nix-valid-host-install-channel-upgrade-v2-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-install-channel-upgrade-v2-deleted.out"
            exit 1
          fi
          if nix_store --check-validity "$install_leaf_store_v2" \
            > "$work/nix-valid-host-leaf-channel-upgrade-v2-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-leaf-channel-upgrade-v2-deleted.out"
            exit 1
          fi
          run_clean ${self}/bin/apm --json upgrade hostinstall --yes \
            > "$work/apm-upgrade-host-install-channel-v2.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
            '.action == "upgrade"
              and .status == "upgraded"
              and .requested == ["hostinstall"]
              and .exclude == []
              and .dry_run == false
              and .generation == 2
              and .upgraded == 1
              and .held_back == []
              and (.upgrades | length == 1)
              and .upgrades[0].name == "hostinstall"
              and .upgrades[0].registry == "host-install-channel"
              and .upgrades[0].old_version == "1.0.0"
              and .upgrades[0].new_version == "2.0.0"
              and .upgrades[0].new_store_path == $store
              and (.downloads.planned >= 2)
              and (.downloads.downloaded >= 2)
              and (.downloads.imported >= 2)' \
            "$work/apm-upgrade-host-install-channel-v2.json" >/dev/null
          nix_store --check-validity "$install_store_v2" \
            > "$work/nix-valid-host-install-channel-upgrade-v2-imported.out" 2>&1
          nix_store --check-validity "$install_leaf_store_v2" \
            > "$work/nix-valid-host-leaf-channel-upgrade-v2-imported.out" 2>&1
          "$profile/current/bin/host-install-tool" \
            > "$work/host-install-channel-upgrade-v2-run.out"
          grep -q "host leaf package v2 executed" \
            "$work/host-install-channel-upgrade-v2-run.out"
          grep -q "host install package v2 executed" \
            "$work/host-install-channel-upgrade-v2-run.out"
          "$profile/current/bin/host-leaf-tool" \
            > "$work/host-leaf-channel-upgrade-v2-run.out"
          grep -q "host leaf package v2 executed" \
            "$work/host-leaf-channel-upgrade-v2-run.out"
          assert_default_profile_absent
          rm -rf "$profile_root"
          home="$main_home"
          config="$main_config"
          data="$main_data"
          cache="$main_cache"
          profile_root="$main_profile_root"
          profile="$main_profile"

          main_home="$home"
          main_config="$config"
          main_data="$data"
          main_cache="$cache"
          main_profile_root="$profile_root"
          main_profile="$profile"
          home="$work/channel-v2-home"
          config="$work/channel-v2-config"
          data="$work/channel-v2-share"
          cache="$work/channel-v2-cache"
          profile_root="$work/channel-v2-profiles"
          profile="$profile_root/per-user/unknown"
          mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
          run_clean ${self}/bin/apm registry add "http://127.0.0.1:$install_cache_port/cache" \
            --name host-install-channel \
            --channel stable \
            --trust-key "$install_channel_trust_key" \
            > "$work/apm-add-host-install-channel-v2.out" 2>&1
          grep -q "Registry 'host-install-channel' added" \
            "$work/apm-add-host-install-channel-v2.out"
          channel_v2_config="$config/apm/registries.d/host-install-channel.toml"
          grep -q 'channel = "stable"' "$channel_v2_config"
          grep -q 'floor = "2.0.0"' "$channel_v2_config"
          run_clean ${self}/bin/apm search hostinstall \
            --registry host-install-channel \
            > "$work/apm-search-host-install-channel-v2.out" 2>&1
          grep -q "hostinstall/host-install-channel 2.0.0" \
            "$work/apm-search-host-install-channel-v2.out"
          nix_store --delete --ignore-liveness "$install_store_v2" \
            > "$work/nix-delete-host-install-channel-v2.out" 2>&1
          nix_store --delete --ignore-liveness "$install_leaf_store_v2" \
            > "$work/nix-delete-host-leaf-channel-v2.out" 2>&1
          if nix_store --check-validity "$install_store_v2" \
            > "$work/nix-valid-host-install-channel-v2-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-install-channel-v2-deleted.out"
            exit 1
          fi
          if nix_store --check-validity "$install_leaf_store_v2" \
            > "$work/nix-valid-host-leaf-channel-v2-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-leaf-channel-v2-deleted.out"
            exit 1
          fi
          run_clean ${self}/bin/apm --json install hostinstall \
            --registry host-install-channel \
            --yes > "$work/apm-install-host-install-channel-v2.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
            '.action == "install"
              and .status == "installed"
              and .requested == ["hostinstall"]
              and .generation == 1
              and (.roots | length == 1)
              and .roots[0].name == "hostinstall"
              and .roots[0].registry == "host-install-channel"
              and .roots[0].version == "2.0.0"
              and .roots[0].store_path == $store
              and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
              and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
              and (.downloads.planned >= 2)
              and (.downloads.downloaded >= 2)
              and (.downloads.imported >= 2)' \
            "$work/apm-install-host-install-channel-v2.json" >/dev/null
          nix_store --check-validity "$install_store_v2" \
            > "$work/nix-valid-host-install-channel-v2-imported.out" 2>&1
          nix_store --check-validity "$install_leaf_store_v2" \
            > "$work/nix-valid-host-leaf-channel-v2-imported.out" 2>&1
          "$profile/current/bin/host-install-tool" \
            > "$work/host-install-channel-v2-run.out"
          grep -q "host leaf package v2 executed" "$work/host-install-channel-v2-run.out"
          grep -q "host install package v2 executed" "$work/host-install-channel-v2-run.out"
          assert_default_profile_absent
          rm -rf "$profile_root"
          home="$main_home"
          config="$main_config"
          data="$main_data"
          cache="$main_cache"
          profile_root="$main_profile_root"
          profile="$main_profile"

          run_clean ${self}/bin/apm --json update --registry host-install-client \
            > "$work/apm-update-host-install-v2-before-push.json" 2>&1 || {
            cat "$work/apm-update-host-install-v2-before-push.json"
            exit 1
          }
          ${pkgs.jq}/bin/jq -e \
            --arg commit "$install_remote_v1_commit" \
            '.registry == "host-install-client"
              and .updated == 1
              and (.registries | length == 1)
              and .registries[0].registry == "host-install-client"
              and .registries[0].status == "updated"
              and .registries[0].commit == $commit
              and .registries[0].packages == 2
              and .registries[0].updated == 0
              and .registries[0].added == 0
              and .registries[0].removed == 0' \
            "$work/apm-update-host-install-v2-before-push.json" >/dev/null || {
            cat "$work/apm-update-host-install-v2-before-push.json"
            exit 1
          }
          run_clean ${self}/bin/apm list --upgradable \
            > "$work/apm-upgradable-host-install-before-push.out" 2>&1 || {
            cat "$work/apm-upgradable-host-install-before-push.out"
            exit 1
          }
          if grep -q "hostinstall/host-install-client" "$work/apm-upgradable-host-install-before-push.out"; then
            cat "$work/apm-upgradable-host-install-before-push.out"
            exit 1
          fi
          install_remote_v2_commit=$(git -C "$install_reg" rev-parse HEAD)
          run_clean ${self}/bin/apr --json push \
            --registry host-install-channel \
            --branch stable > "$work/apr-push-host-install-v2.json"
          ${pkgs.jq}/bin/jq -e \
            --arg head "$install_remote_v2_commit" \
            '.action == "push"
              and .branch == "stable"
              and .set_upstream == false
              and .force == false
              and .head == $head
              and (.branches | any(.name == "origin/stable" and .remote == true))' \
            "$work/apr-push-host-install-v2.json" >/dev/null

          run_clean ${self}/bin/apm --json update --registry host-install-client \
            > "$work/apm-update-host-install-v2.json" 2>&1 || {
            cat "$work/apm-update-host-install-v2.json"
            exit 1
          }
          ${pkgs.jq}/bin/jq -e \
            '.registry == "host-install-client"
              and .updated == 1
              and (.registries | length == 1)
              and .registries[0].registry == "host-install-client"
              and .registries[0].status == "updated"
              and .registries[0].packages == 2
              and .registries[0].updated == 2
              and .registries[0].added == 0
              and .registries[0].removed == 0
              and (.registries[0].commit | length == 64)' \
            "$work/apm-update-host-install-v2.json" >/dev/null || {
            cat "$work/apm-update-host-install-v2.json"
            exit 1
          }
          run_clean ${self}/bin/apm list --upgradable \
            > "$work/apm-upgradable-host-install.out" 2>&1 || {
            cat "$work/apm-upgradable-host-install.out"
            exit 1
          }
          grep -q "hostinstall/host-install-client" "$work/apm-upgradable-host-install.out" || {
            cat "$work/apm-upgradable-host-install.out"
            exit 1
          }
          grep -q "upgradable: 2.0.0" "$work/apm-upgradable-host-install.out" || {
            cat "$work/apm-upgradable-host-install.out"
            exit 1
          }

          nix_store --delete --ignore-liveness "$install_store_v2" \
            > "$work/nix-delete-host-install-v2.out" 2>&1
          nix_store --delete --ignore-liveness "$install_leaf_store_v2" \
            > "$work/nix-delete-host-leaf-v2.out" 2>&1
          if nix_store --check-validity "$install_store_v2" \
            > "$work/nix-valid-host-install-v2-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-install-v2-deleted.out"
            exit 1
          fi
          if nix_store --check-validity "$install_leaf_store_v2" \
            > "$work/nix-valid-host-leaf-v2-deleted.out" 2>&1; then
            cat "$work/nix-valid-host-leaf-v2-deleted.out"
            exit 1
          fi

          run_clean ${self}/bin/apm --json upgrade hostinstall --yes \
            > "$work/apm-upgrade-host-install.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
            '.action == "upgrade"
              and .status == "upgraded"
              and .requested == ["hostinstall"]
              and .exclude == []
              and .dry_run == false
              and .generation == 2
              and .upgraded == 1
              and .held_back == []
              and (.upgrades | length == 1)
              and .upgrades[0].name == "hostinstall"
              and .upgrades[0].registry == "host-install-client"
              and .upgrades[0].old_version == "1.0.0"
              and .upgrades[0].new_version == "2.0.0"
              and .upgrades[0].new_store_path == $store
              and (.downloads.planned >= 2)
              and (.downloads.downloaded >= 2)
              and (.downloads.imported >= 2)' \
            "$work/apm-upgrade-host-install.json" >/dev/null
          nix_store --check-validity "$install_store_v2" \
            > "$work/nix-valid-host-install-v2-imported.out" 2>&1
          nix_store --check-validity "$install_leaf_store_v2" \
            > "$work/nix-valid-host-leaf-v2-imported.out" 2>&1
          "$profile/current/bin/host-install-tool" > "$work/host-install-v2-run.out"
          grep -q "host leaf package v2 executed" "$work/host-install-v2-run.out"
          grep -q "host install package v2 executed" "$work/host-install-v2-run.out"
          assert_default_profile_absent

          run_clean ${self}/bin/apm verify hostinstall > "$work/apm-verify-host-install-v2.out" 2>&1
          grep -q "integrity verified" "$work/apm-verify-host-install-v2.out"
          run_clean ${self}/bin/apm --json verify hostinstall > "$work/apm-verify-host-install-v2.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
            '.package == "hostinstall"
              and .registry == "host-install-client"
              and .version == "2.0.0"
              and .store_path == $store
              and .verified == true
              and (.expected_nar_hash | startswith("sha256-"))
              and (.actual_nar_hash | startswith("sha256:"))' \
            "$work/apm-verify-host-install-v2.json" >/dev/null
          assert_default_profile_absent
          run_clean ${self}/bin/apm files hostinstall > "$work/apm-files-host-install-v2.out" 2>&1
          grep -q "bin/host-install-tool" "$work/apm-files-host-install-v2.out"
          run_clean ${self}/bin/apm --json files hostinstall > "$work/apm-files-host-install-v2.json"
          ${pkgs.jq}/bin/jq -e \
            'index("bin/host-install-tool") != null and index("share/host-install/payload.txt") != null' \
            "$work/apm-files-host-install-v2.json" >/dev/null

          run_clean ${self}/bin/apm rollback --list > "$work/apm-rollback-list-host-install-v2.out" 2>&1
          grep -q "gen-1: .*hostinstall 1.0.0" "$work/apm-rollback-list-host-install-v2.out"
          grep -q "gen-2: .*hostinstall 2.0.0" "$work/apm-rollback-list-host-install-v2.out"
          grep -q "gen-2: .*current" "$work/apm-rollback-list-host-install-v2.out"
          run_clean ${self}/bin/apm --json rollback --list > "$work/apm-rollback-list-host-install-v2.json"
          ${pkgs.jq}/bin/jq -e \
            'length == 2
              and any(.[]; .generation == 1
                and .current == false
                and (.roots | any(.registry == "host-install-client"
                  and .package.name == "hostinstall"
                  and .package.version == "1.0.0")))
              and any(.[]; .generation == 2
                and .current == true
                and (.roots | any(.registry == "host-install-client"
                  and .package.name == "hostinstall"
                  and .package.version == "2.0.0")))' \
            "$work/apm-rollback-list-host-install-v2.json" >/dev/null

          run_clean ${self}/bin/apm --json rollback --dry-run > "$work/apm-rollback-host-install-dry-run.json"
          ${pkgs.jq}/bin/jq -e \
            --arg old "$install_store" \
            --arg old_leaf "$install_leaf_store" \
            --arg new "$install_store_v2" \
            --arg new_leaf "$install_leaf_store_v2" \
            '.action == "rollback"
              and .status == "planned"
              and .requested_generation == null
              and .from_generation == 2
              and .to_generation == 1
              and .dry_run == true
              and .generation == null
              and (.restored | length == 2)
              and (.restored | any(.store_path == $old
                and .registry == "host-install-client"
                and .package.name == "hostinstall"
                and .package.version == "1.0.0"))
              and (.restored | any(.store_path == $old_leaf
                and .registry == "host-install-client"
                and .package.name == "hostleaf"
                and .package.version == "1.0.0"))
              and (.removed | length == 2)
              and (.removed | any(.store_path == $new
                and .registry == "host-install-client"
                and .package.name == "hostinstall"
                and .package.version == "2.0.0"))
              and (.removed | any(.store_path == $new_leaf
                and .registry == "host-install-client"
                and .package.name == "hostleaf"
                and .package.version == "2.0.0"))
              and (.current_roots | any(.store_path == $new
                and .package.name == "hostinstall"
                and .package.version == "2.0.0"))
              and (.current_roots | any(.store_path == $new_leaf
                and .package.name == "hostleaf"
                and .package.version == "2.0.0"))
              and (.target_roots | any(.store_path == $old
                and .package.name == "hostinstall"
                and .package.version == "1.0.0"))
              and (.target_roots | any(.store_path == $old_leaf
                and .package.name == "hostleaf"
                and .package.version == "1.0.0"))' \
            "$work/apm-rollback-host-install-dry-run.json" >/dev/null
          "$profile/current/bin/host-install-tool" > "$work/host-install-v2-after-rollback-dry-run.out"
          grep -q "host leaf package v2 executed" "$work/host-install-v2-after-rollback-dry-run.out"
          grep -q "host install package v2 executed" "$work/host-install-v2-after-rollback-dry-run.out"
          assert_default_profile_absent

          run_clean ${self}/bin/apm --json rollback > "$work/apm-rollback-host-install.json"
          ${pkgs.jq}/bin/jq -e \
            --arg old "$install_store" \
            --arg old_leaf "$install_leaf_store" \
            --arg new "$install_store_v2" \
            --arg new_leaf "$install_leaf_store_v2" \
            '.action == "rollback"
              and .status == "rolled_back"
              and .requested_generation == null
              and .from_generation == 2
              and .to_generation == 1
              and .dry_run == false
              and .generation == 1
              and (.restored | length == 2)
              and (.restored | any(.store_path == $old
                and .registry == "host-install-client"
                and .package.name == "hostinstall"
                and .package.version == "1.0.0"))
              and (.restored | any(.store_path == $old_leaf
                and .registry == "host-install-client"
                and .package.name == "hostleaf"
                and .package.version == "1.0.0"))
              and (.removed | length == 2)
              and (.removed | any(.store_path == $new
                and .registry == "host-install-client"
                and .package.name == "hostinstall"
                and .package.version == "2.0.0"))
              and (.removed | any(.store_path == $new_leaf
                and .registry == "host-install-client"
                and .package.name == "hostleaf"
                and .package.version == "2.0.0"))
              and (.current_roots | any(.store_path == $new
                and .package.name == "hostinstall"
                and .package.version == "2.0.0"))
              and (.current_roots | any(.store_path == $new_leaf
                and .package.name == "hostleaf"
                and .package.version == "2.0.0"))
              and (.target_roots | any(.store_path == $old
                and .package.name == "hostinstall"
                and .package.version == "1.0.0"))
              and (.target_roots | any(.store_path == $old_leaf
                and .package.name == "hostleaf"
                and .package.version == "1.0.0"))' \
            "$work/apm-rollback-host-install.json" >/dev/null
          "$profile/current/bin/host-install-tool" > "$work/host-install-v1-after-rollback.out"
          grep -q "host leaf package executed" "$work/host-install-v1-after-rollback.out"
          grep -q "host install package executed" "$work/host-install-v1-after-rollback.out"
          run_clean ${self}/bin/apm list --installed > "$work/apm-installed-host-install-rollback.out" 2>&1
          grep -q "hostinstall/host-install-client" "$work/apm-installed-host-install-rollback.out"
          grep -q "1.0.0" "$work/apm-installed-host-install-rollback.out"
          grep -q "upgradable: 2.0.0" "$work/apm-installed-host-install-rollback.out"
          run_clean ${self}/bin/apm --json verify hostinstall > "$work/apm-verify-host-install-rollback.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store" \
            '.package == "hostinstall"
              and .registry == "host-install-client"
              and .version == "1.0.0"
              and .store_path == $store
              and .verified == true' \
            "$work/apm-verify-host-install-rollback.json" >/dev/null
          assert_default_profile_absent

          run_clean ${self}/bin/apm upgrade hostinstall --yes \
            > "$work/apm-upgrade-host-install-after-rollback.out" 2>&1
          grep -q "Upgraded 1 package" "$work/apm-upgrade-host-install-after-rollback.out"
          "$profile/current/bin/host-install-tool" > "$work/host-install-v2-after-rollback-upgrade.out"
          grep -q "host leaf package v2 executed" "$work/host-install-v2-after-rollback-upgrade.out"
          grep -q "host install package v2 executed" "$work/host-install-v2-after-rollback-upgrade.out"
          assert_default_profile_absent

          run_clean ${self}/bin/apm --json hold hostinstall > "$work/apm-hold-host-install.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
            '.action == "hold"
              and .status == "held"
              and .package == "hostinstall"
              and .name == "hostinstall"
              and .version == "2.0.0"
              and .registry == "host-install-client"
              and .store_path == $store
              and .held == true' \
            "$work/apm-hold-host-install.json" >/dev/null
          run_clean ${self}/bin/apm --json held > "$work/apm-held-host-install.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
            'length == 1
              and .[0].name == "hostinstall"
              and .[0].version == "2.0.0"
              and .[0].registry == "host-install-client"
              and .[0].store_path == $store' \
            "$work/apm-held-host-install.json" >/dev/null

          run_clean ${self}/bin/apm --json reinstall hostinstall --yes \
            > "$work/apm-reinstall-held-host-install.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
            '.action == "reinstall"
              and .status == "reinstalled"
              and .requested == ["hostinstall"]
              and .reinstall == true
              and .download_only == false
              and .no_deps == false
              and .dry_run == false
              and .generation == 4
              and (.roots | length == 1)
              and .roots[0].name == "hostinstall"
              and .roots[0].version == "2.0.0"
              and .roots[0].registry == "host-install-client"
              and .roots[0].store_path == $store
              and .roots[0].explicit == true
              and (.downloads.planned >= 1)
              and (.downloads.downloaded >= 1)
              and (.downloads.imported >= 1)' \
            "$work/apm-reinstall-held-host-install.json" >/dev/null
          "$profile/current/bin/host-install-tool" > "$work/host-install-v2-after-reinstall.out"
          grep -q "host leaf package v2 executed" "$work/host-install-v2-after-reinstall.out"
          grep -q "host install package v2 executed" "$work/host-install-v2-after-reinstall.out"
          run_clean ${self}/bin/apm --json held > "$work/apm-held-host-install-after-reinstall.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
            'length == 1
              and .[0].name == "hostinstall"
              and .[0].version == "2.0.0"
              and .[0].registry == "host-install-client"
              and .[0].store_path == $store' \
            "$work/apm-held-host-install-after-reinstall.json" >/dev/null
          assert_default_profile_absent

          if ! find "$cache/apm" -name '*.nar.zst' | grep -q .; then
            find "$cache/apm" -maxdepth 2 -print 2>/dev/null || true
            exit 1
          fi
          run_clean ${self}/bin/apm --json clean > "$work/apm-clean-host-install-cache.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "clean"
              and .mode == "cache"
              and .status == "cleaned"
              and .files_removed >= 1
              and .freed_bytes > 0
              and (.freed | length > 0)' \
            "$work/apm-clean-host-install-cache.json" >/dev/null
          if find "$cache/apm" -name '*.nar.zst' | grep -q .; then
            find "$cache/apm" -maxdepth 2 -print
            exit 1
          fi
          assert_default_profile_absent

          run_clean ${self}/bin/apm --json unhold hostinstall > "$work/apm-unhold-host-install.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
            '.action == "unhold"
              and .status == "unheld"
              and .package == "hostinstall"
              and .name == "hostinstall"
              and .version == "2.0.0"
              and .registry == "host-install-client"
              and .store_path == $store
              and .held == false' \
            "$work/apm-unhold-host-install.json" >/dev/null
          run_clean ${self}/bin/apm --json held > "$work/apm-held-host-install-after-unhold.json"
          ${pkgs.jq}/bin/jq -e 'length == 0' "$work/apm-held-host-install-after-unhold.json" >/dev/null
          assert_default_profile_absent

          run_clean ${self}/bin/apm --json remove hostinstall --yes \
            > "$work/apm-remove-host-install.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
            '.action == "remove"
              and .status == "removed"
              and .requested == ["hostinstall"]
              and .autoremove == false
              and .dry_run == false
              and .generation == 5
              and .removed == 1
              and .explicit_removed == 1
              and .orphan_removed == 0
              and (.packages | length == 1)
              and .packages[0].name == "hostinstall"
              and .packages[0].version == "2.0.0"
              and .packages[0].registry == "host-install-client"
              and .packages[0].store_path == $store
              and .packages[0].explicit == true
              and .packages[0].held == false
              and .orphans == []' \
            "$work/apm-remove-host-install.json" >/dev/null
          run_clean ${self}/bin/apm list --installed > "$work/apm-installed-after-host-remove.out" 2>&1
          if grep -q "hostinstall" "$work/apm-installed-after-host-remove.out"; then
            cat "$work/apm-installed-after-host-remove.out"
            exit 1
          fi
          grep -q "hostleaf/host-install-client" "$work/apm-installed-after-host-remove.out"
          assert_default_profile_absent

          run_clean ${self}/bin/apm --json autoremove --yes \
            > "$work/apm-autoremove-host-leaf.json"
          ${pkgs.jq}/bin/jq -e --arg store "$install_leaf_store_v2" \
            '.action == "autoremove"
              and .status == "removed"
              and .requested == []
              and .autoremove == true
              and .dry_run == false
              and .generation == 6
              and .removed == 1
              and .explicit_removed == 0
              and .orphan_removed == 1
              and .packages == []
              and (.orphans | length == 1)
              and .orphans[0].name == "hostleaf"
              and .orphans[0].version == "2.0.0"
              and .orphans[0].registry == "host-install-client"
              and .orphans[0].store_path == $store
              and .orphans[0].explicit == false' \
            "$work/apm-autoremove-host-leaf.json" >/dev/null
          run_clean ${self}/bin/apm list --installed > "$work/apm-installed-after-host-autoremove.out" 2>&1
          if grep -q "hostleaf" "$work/apm-installed-after-host-autoremove.out"; then
            cat "$work/apm-installed-after-host-autoremove.out"
            exit 1
          fi
          assert_default_profile_absent

          test "$(profile_generation_count)" = "6"
          run_clean ${self}/bin/apm --json clean --generations --keep 1 \
            > "$work/apm-clean-host-install-generations.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "clean"
              and .mode == "generations"
              and .status == "cleaned"
              and .keep == 1
              and .current_generation == 6
              and .generations_before == [1, 2, 3, 4, 5, 6]
              and .generations_after == [6]
              and .removed_generations == [1, 2, 3, 4, 5]
              and .removed == 5' \
            "$work/apm-clean-host-install-generations.json" >/dev/null
          test "$(profile_generation_count)" = "1"
          test -d "$profile/gen-6"
          test ! -e "$profile/gen-1"
          test ! -e "$profile/gen-2"
          test ! -e "$profile/gen-3"
          test ! -e "$profile/gen-4"
          test ! -e "$profile/gen-5"
          assert_default_profile_absent

          run_clean ${self}/bin/apm --json gc > "$work/apm-gc-host-install.json" 2>&1 || {
            cat "$work/apm-gc-host-install.json"
            exit 1
          }
          ${pkgs.jq}/bin/jq -e \
            --arg store_dir "$store_dir" \
            --arg state_dir "$state_dir" \
            '.action == "gc"
              and .status == "completed"
              and .success == true
              and .nix_store_dir == $store_dir
              and .nix_state_dir == $state_dir
              and (.stdout | type == "string")
              and (.stderr | type == "string")' \
            "$work/apm-gc-host-install.json" >/dev/null || {
            cat "$work/apm-gc-host-install.json"
            exit 1
          }
          assert_default_profile_absent

          mkdir -p "$out"
          echo "PASS" > "$out/result"
        '';
      }
    ];
  };

  # ---------------------------------------------------------------------------
  # Cache server — startup, HTTP endpoints, token management
  # ---------------------------------------------------------------------------

  server-startup = testing.mkVMTest {
    name = "aos-server-startup";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "test"
      anonymous_read = true

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      # Start server and verify it responds
      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/test/nix-cache-info)
      echo "==> nix-cache-info HTTP code: $HTTP_CODE"

      kill $SERVER_PID 2>/dev/null || true
      wait $SERVER_PID 2>/dev/null || true

      test "$HTTP_CODE" = "200" || { echo "FAIL: expected 200, got $HTTP_CODE"; exit 1; }
      echo "==> Server startup test passed"
    '';
  };

  cache-info = testing.mkVMTest {
    name = "aos-cache-info";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "test"
      anonymous_read = true
      max_concurrent_builds = 2

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      # Start the server
      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      FAIL=0

      # Test 1: nix-cache-info returns 200 with expected fields
      echo "==> Test: nix-cache-info endpoint"
      BODY=$(curl -s http://127.0.0.1:15000/test/nix-cache-info)
      echo "$BODY"

      echo "$BODY" | grep -q "StoreDir:" || { echo "FAIL: missing StoreDir"; FAIL=1; }
      echo "$BODY" | grep -q "WantMassQuery:" || { echo "FAIL: missing WantMassQuery"; FAIL=1; }
      echo "$BODY" | grep -q "Capabilities:" || { echo "FAIL: missing Capabilities"; FAIL=1; }
      echo "$BODY" | grep -q "pack-upload" || { echo "FAIL: missing pack-upload capability"; FAIL=1; }
      echo "$BODY" | grep -q "sse-logs" || { echo "FAIL: missing sse-logs capability"; FAIL=1; }

      # Test 2: unknown view returns 404
      echo "==> Test: unknown view returns 404"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/nonexistent/nix-cache-info)
      test "$HTTP_CODE" = "404" || { echo "FAIL: expected 404, got $HTTP_CODE"; FAIL=1; }

      # Test 3: narinfo for non-existent path returns 404
      echo "==> Test: narinfo for missing path returns 404"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/test/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo)
      test "$HTTP_CODE" = "404" || { echo "FAIL: expected 404, got $HTTP_CODE"; FAIL=1; }

      # Test 4: query-missing without auth returns 401
      echo "==> Test: query-missing requires auth"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST -H 'Content-Type: application/json' \
        -d '{"paths":[]}' \
        http://127.0.0.1:15000/test/query-missing)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401, got $HTTP_CODE"; FAIL=1; }

      # Test 5: build endpoint without auth returns 401
      echo "==> Test: build endpoint requires auth"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST http://127.0.0.1:15000/test/build?drv=/nix/store/fake.drv)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401, got $HTTP_CODE"; FAIL=1; }

      # Test 6: oauth2 token endpoint without credentials returns 401
      echo "==> Test: token exchange requires credentials"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST http://127.0.0.1:15000/oauth2/token)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401, got $HTTP_CODE"; FAIL=1; }

      kill $SERVER_PID 2>/dev/null || true
      wait $SERVER_PID 2>/dev/null || true

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Cache protocol tests FAILED"
        exit 1
      fi
      echo "==> All cache protocol tests passed"
    '';
  };

  token-management = testing.mkVMTest {
    name = "aos-token-management";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "test"
      anonymous_read = true
      max_concurrent_builds = 2

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      # Start the server
      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      FAIL=0

      # Test 1: Create a token via bootstrap socket
      echo "==> Test: create token via bootstrap socket"
      RESPONSE=$(echo '{"action":"create","views":["test"],"permissions":["read","build"],"comment":"integration test"}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      echo "Create response: $RESPONSE"

      TOKEN=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.token // empty')
      TOKEN_ID=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.id // empty')

      test -n "$TOKEN" || { echo "FAIL: no token in create response"; FAIL=1; }
      test -n "$TOKEN_ID" || { echo "FAIL: no token ID in create response"; FAIL=1; }
      echo "==> Token created: id=$TOKEN_ID"

      # Test 2: List tokens via bootstrap socket
      echo "==> Test: list tokens via bootstrap socket"
      LIST_RESPONSE=$(echo '{"action":"list"}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      echo "List response: $LIST_RESPONSE"

      COUNT=$(echo "$LIST_RESPONSE" | ${pkgs.jq}/bin/jq '.data.tokens | length')
      test "$COUNT" -ge 1 || { echo "FAIL: expected at least 1 token, got $COUNT"; FAIL=1; }

      # Test 3: Exchange token for JWT via oauth2 endpoint
      echo "==> Test: exchange token for JWT"
      JWT_RESPONSE=$(curl -s \
        -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      echo "JWT response: $JWT_RESPONSE"

      ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token // empty')
      test -n "$ACCESS_TOKEN" || { echo "FAIL: no access_token in JWT response"; FAIL=1; }
      echo "==> Got JWT access token"

      # Test 4: Use JWT to call authenticated endpoint (query-missing)
      echo "==> Test: query-missing with JWT auth"
      QM_RESPONSE=$(curl -s \
        -X POST \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"paths":["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fake"]}' \
        http://127.0.0.1:15000/test/query-missing)
      echo "query-missing response: $QM_RESPONSE"

      MISSING=$(echo "$QM_RESPONSE" | ${pkgs.jq}/bin/jq '.missing | length')
      test "$MISSING" -eq 1 || { echo "FAIL: expected 1 missing path, got $MISSING"; FAIL=1; }

      # Test 5: Revoke token via bootstrap socket
      echo "==> Test: revoke token via bootstrap socket"
      REVOKE_RESPONSE=$(echo "{\"action\":\"revoke\",\"token_id\":\"$TOKEN_ID\"}" | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      echo "Revoke response: $REVOKE_RESPONSE"

      # Test 6: Revoked token should fail JWT exchange
      echo "==> Test: revoked token rejected"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401 after revoke, got $HTTP_CODE"; FAIL=1; }

      kill $SERVER_PID 2>/dev/null || true
      wait $SERVER_PID 2>/dev/null || true

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Token management tests FAILED"
        exit 1
      fi
      echo "==> All token management tests passed"
    '';
  };

  auth-enforcement = testing.mkVMTest {
    name = "aos-auth-enforcement";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      # Configure two views: "public" (anon read) and "private" (no anon read)
      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "public"
      anonymous_read = true

      [[views]]
      name = "private"
      anonymous_read = false

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      FAIL=0

      # Test 1: Public view allows anonymous cache-info
      echo "==> Test: public view anonymous read"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/public/nix-cache-info)
      test "$HTTP_CODE" = "200" || { echo "FAIL: expected 200 for public cache-info, got $HTTP_CODE"; FAIL=1; }

      # Test 2: Private view denies anonymous cache-info
      echo "==> Test: private view requires auth"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/private/nix-cache-info)
      test "$HTTP_CODE" = "401" || { echo "FAIL: expected 401 for private cache-info, got $HTTP_CODE"; FAIL=1; }

      # Test 3: Create token scoped to "public" only
      echo "==> Test: view-scoped token"
      RESPONSE=$(echo '{"action":"create","views":["public"],"permissions":["read","build"]}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      TOKEN=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.token // empty')

      JWT_RESPONSE=$(curl -s \
        -X POST -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      echo "JWT response: $JWT_RESPONSE"
      ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token // empty')
      echo "ACCESS_TOKEN length: ''${#ACCESS_TOKEN}"

      # Test 4: Token can access authorized view
      echo "==> Test: token can access authorized view"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"paths":[]}' \
        http://127.0.0.1:15000/public/query-missing)
      test "$HTTP_CODE" = "200" || { echo "FAIL: expected 200 for authorized view, got $HTTP_CODE"; FAIL=1; }

      # Test 5: Token cannot access unauthorized view
      echo "==> Test: token rejected for unauthorized view"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"paths":[]}' \
        http://127.0.0.1:15000/private/query-missing)
      test "$HTTP_CODE" = "403" || { echo "FAIL: expected 403 for unauthorized view, got $HTTP_CODE"; FAIL=1; }

      # Test 6: Create read-only token (no build permission)
      echo "==> Test: read-only token cannot upload"
      RESPONSE2=$(echo '{"action":"create","views":["public"],"permissions":["read"]}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      TOKEN2=$(echo "$RESPONSE2" | ${pkgs.jq}/bin/jq -r '.data.token // empty')

      JWT2_RESPONSE=$(curl -s \
        -X POST -H "Authorization: Bearer $TOKEN2" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      ACCESS_TOKEN2=$(echo "$JWT2_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token // empty')

      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X PUT -H "Authorization: Bearer $ACCESS_TOKEN2" \
        -H "Content-Type: application/octet-stream" \
        -d 'fake-nar-data' \
        http://127.0.0.1:15000/public/store/fakehash)
      test "$HTTP_CODE" = "403" || { echo "FAIL: expected 403 for read-only upload, got $HTTP_CODE"; FAIL=1; }

      kill $SERVER_PID 2>/dev/null || true
      wait $SERVER_PID 2>/dev/null || true

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Auth enforcement tests FAILED"
        exit 1
      fi
      echo "==> All auth enforcement tests passed"
    '';
  };

  drain = testing.mkVMTest {
    name = "aos-drain";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
      ${serverPreamble}

      cat > /tmp/aos-config.toml << 'EOF'
      listen = "127.0.0.1:15000"

      [[views]]
      name = "test"
      anonymous_read = true

      [bootstrap]
      socket = "/tmp/run/aos/bootstrap.sock"
      socket_group = "root"
      EOF

      ${self}/bin/aos serve --config /tmp/aos-config.toml &
      SERVER_PID=$!
      sleep 2

      FAIL=0

      # Verify server is responding
      echo "==> Verify server is up"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:15000/test/nix-cache-info)
      test "$HTTP_CODE" = "200" || { echo "FAIL: server not responding"; FAIL=1; }

      # Get a token for build requests
      RESPONSE=$(echo '{"action":"create","views":["test"],"permissions":["read","build"]}' | \
        ${pkgs.socat}/bin/socat - UNIX-CONNECT:/tmp/run/aos/bootstrap.sock)
      TOKEN=$(echo "$RESPONSE" | ${pkgs.jq}/bin/jq -r '.data.token // empty')
      JWT_RESPONSE=$(curl -s \
        -X POST -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        http://127.0.0.1:15000/oauth2/token)
      ACCESS_TOKEN=$(echo "$JWT_RESPONSE" | ${pkgs.jq}/bin/jq -r '.access_token // empty')

      # Send SIGTERM to trigger drain
      echo "==> Sending SIGTERM to trigger drain"
      kill -TERM $SERVER_PID || true

      # Give drain time to activate
      sleep 1

      # Build requests during drain should return 503
      echo "==> Test: build rejected during drain"
      HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
        http://127.0.0.1:15000/test/build?drv=/nix/store/fake.drv)
      # Server may have already shut down (no in-flight builds to drain)
      if [ "$HTTP_CODE" = "503" ] || [ "$HTTP_CODE" = "000" ]; then
        echo "==> Drain behavior correct (HTTP $HTTP_CODE)"
      else
        echo "FAIL: expected 503 or connection refused during drain, got $HTTP_CODE"
        FAIL=1
      fi

      wait $SERVER_PID 2>/dev/null || true

      if [ "$FAIL" -ne 0 ]; then
        echo "==> Drain tests FAILED"
        exit 1
      fi
      echo "==> All drain tests passed"
    '';
  };
}
