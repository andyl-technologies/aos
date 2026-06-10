# tests/vm/apm/registry.nix — Registry management VM tests
#
# Tests for `apr` registry lifecycle commands: create, add, remove, publish,
# unpublish, branch workflow, validate, signed tags, trust/key workflows, and
# clean-break behavior.
# All tests run in headless Firecracker microVMs.
{
  testing,
  pkgs,
  aosPkg,
}: let
  fixtures = import ./fixtures.nix {inherit pkgs aosPkg;};
  nixRuntimeDeps = [
    pkgs.nix
    pkgs.brotli
    pkgs.curl
    pkgs.openssl
    pkgs.sqlite
    pkgs.boost
    pkgs.editline
    pkgs.libsodium
    pkgs.libarchive
    pkgs.gc
    pkgs.lowdown
    pkgs.bzip2
    pkgs.zlib
  ];
  publishDeps = fixtures.commonDeps ++ nixRuntimeDeps;
  maintainerWorkflowDeps =
    publishDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.openssh
      pkgs.python3
      pkgs.zstd
    ];
  nixLibPath = builtins.concatStringsSep ":" (map (pkg: "${pkg}/lib") nixRuntimeDeps);
  setupNixPublishEnv = ''
    export NIX_REMOTE=""
    export NIX_CONF_DIR=/tmp/nix-conf
    export LD_LIBRARY_PATH="${nixLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    mkdir -p "$NIX_CONF_DIR" /nix/var/nix/db /nix/var/nix/gcroots
    cat > "$NIX_CONF_DIR/nix.conf" << 'NIXCONF'
    experimental-features = nix-command
    sandbox = false
    NIXCONF
    nix-store --init || true
    nix-store --load-db < /aos-registration
  '';
  setupAltNixPublishEnv = ''
    export AOS_ROOT=/tmp/aos-alt-root
    export AOS_NIX_STORE_DIR=/nix/store
    export AOS_NIX_STATE_DIR=/tmp/apr-alt-nix-state/var/nix
    export NIX_REMOTE=""
    export NIX_CONF_DIR=/tmp/nix-conf
    export LD_LIBRARY_PATH="${nixLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    rm -rf /nix/var/nix
    mkdir -p "$NIX_CONF_DIR" "$AOS_NIX_STATE_DIR/db" "$AOS_NIX_STATE_DIR/gcroots"
    cat > "$NIX_CONF_DIR/nix.conf" << 'NIXCONF'
    experimental-features = nix-command
    sandbox = false
    substituters =
    NIXCONF
    NIX_STORE_DIR=/nix/store NIX_STATE_DIR="$AOS_NIX_STATE_DIR" \
      nix-store --init || true
    NIX_STORE_DIR=/nix/store NIX_STATE_DIR="$AOS_NIX_STATE_DIR" \
      nix-store --load-db < /aos-registration
  '';
  mkRegistryTool = {
    pname,
    version,
    program ? pname,
  }:
    pkgs.mkDerivation {
      inherit pname version;
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.bash
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin"
            printf '%s\n' \
              '#!${pkgs.bash}/bin/bash' \
              "printf '${pname} ${version}\\n'" \
              > "$out/bin/${program}"
            chmod +x "$out/bin/${program}"
          '';
        }
      ];
    };
  closureLeafTool = mkRegistryTool {
    pname = "closure-leaf";
    version = "1.0.0";
  };
  closureRootTool = pkgs.mkDerivation {
    pname = "closure-root";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      closureLeafTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'leaf_output="$(${closureLeafTool}/bin/closure-leaf)"' \
            'printf "closure-root 1.0.0 via %s\n" "$leaf_output"' \
            > "$out/bin/closure-root"
          chmod +x "$out/bin/closure-root"
        '';
      }
    ];
  };
  retireDepTool = mkRegistryTool {
    pname = "retire-dep";
    version = "1.0.0";
  };
  retireTool = pkgs.mkDerivation {
    pname = "retire-tool";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      retireDepTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'dep_output="$(${retireDepTool}/bin/retire-dep)"' \
            'printf "retire-tool 1.0.0 via %s\n" "$dep_output"' \
            > "$out/bin/retire-tool"
          chmod +x "$out/bin/retire-tool"
        '';
      }
    ];
  };
  closureWorkflowDeps =
    publishDeps
    ++ [
      closureLeafTool
      closureRootTool
      retireDepTool
      retireTool
    ];
in {
  # -------------------------------------------------------------------------
  # registry-create — Initialize a new empty registry
  # -------------------------------------------------------------------------
  registry-create = testing.mkVMTest {
    name = "apm-registry-create";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: apr create"
      $APR create test-reg

      REG_DIR="$REG_STORAGE/test-reg"

      # Verify git repo exists
      assert_dir_exists "$REG_DIR/.git" "git repo initialized"

      # Verify registry.toml exists
      assert_file_exists "$REG_DIR/registry.toml" "registry.toml exists"

      # Verify packages/ directory exists
      assert_dir_exists "$REG_DIR/packages" "packages/ directory exists"

      # Verify registry.toml contains the registry name
      assert_file_contains "$REG_DIR/registry.toml" "test-reg" "registry.toml contains name"

      # Verify git log shows initial commit
      cd "$REG_DIR"
      COMMIT_COUNT=$(git log --oneline | wc -l)
      if [ "$COMMIT_COUNT" -ge 1 ]; then
        pass "git log shows initial commit"
      else
        fail "git log shows no commits"
      fi
      cd /tmp

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-add-clone — Add a remote registry via clone
  # -------------------------------------------------------------------------
  registry-add-clone = testing.mkVMTest {
    name = "apm-registry-add-clone";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: apr add (clone from local bare repo)"

      # Create a bare remote registry
      create_remote_registry /tmp/remote-registry.git
      git clone /tmp/remote-registry.git /tmp/remote-registry-tag
      cd /tmp/remote-registry-tag
      git tag 1.0.0
      git push origin 1.0.0
      cd /tmp
      rm -rf /tmp/remote-registry-tag

      # Use apm registry add to add the remote
      $APM registry add --no-verify file:///tmp/remote-registry.git --name test-remote

      # Verify config file was created
      assert_file_exists "$APM_CONFIG/registries.d/test-remote.toml" \
        "registry config file created"

      # Verify config contains URL
      assert_file_contains "$APM_CONFIG/registries.d/test-remote.toml" \
        "file:///tmp/remote-registry.git" "config contains URL"

      # apr add should sync the git repo and materialize authenticated metadata by default.
      assert_dir_exists "$HOME/.local/share/apm/remote/test-remote/repo.git" \
        "registry git cache created during add"
      assert_file_exists "$REG_STORAGE/test-remote/registry.toml" \
        "registry root metadata materialized during add"
      assert_dir_exists "$HOME/.local/share/apm/remote/test-remote/packages" \
        "registry package cache materialized during add"

      # Verify apr list shows the registry
      assert_cmd_output_contains "$APR list" "test-remote" "apr list shows registry"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-add-no-clone-publish-hint — Config-only add has recovery hints
  # -------------------------------------------------------------------------
  registry-add-no-clone-publish-hint = testing.mkVMTest {
    name = "apm-registry-add-no-clone-publish-hint";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: apr add --no-clone followed by update and apr publish"

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      create_remote_registry /tmp/no-clone-registry.git

      $APM registry add --no-verify file:///tmp/no-clone-registry.git \
        --name no-clone-reg --no-clone > /tmp/add-no-clone.out 2>&1 || {
        cat /tmp/add-no-clone.out
        fail "apm registry add --no-clone succeeds"
      }
      cat /tmp/add-no-clone.out
      assert_file_contains /tmp/add-no-clone.out \
        "apm update --registry no-clone-reg" \
        "apm registry add --no-clone points to the valid update syntax"
      assert_file_not_contains /tmp/add-no-clone.out \
        "apm update no-clone-reg" \
        "apm registry add --no-clone does not suggest invalid positional update syntax"

      assert_file_exists "$APM_CONFIG/registries.d/no-clone-reg.toml" \
        "registry config file created"

      if [ -e "$REG_STORAGE/no-clone-reg" ]; then
        fail "apr add --no-clone should not create a local clone"
      else
        pass "apr add --no-clone leaves local clone absent"
      fi

      if $APR publish /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dummy-1.0.0 \
        --name dummy --version 1.0.0 --registry no-clone-reg --no-commit \
        > /tmp/publish-no-clone.out 2>&1; then
        fail "apr publish should fail without a local clone"
      else
        cat /tmp/publish-no-clone.out
        assert_file_contains /tmp/publish-no-clone.out \
          "has no writable local clone" "apr publish reports missing writable clone"
        assert_file_contains /tmp/publish-no-clone.out \
          "only syncs consumer metadata" \
          "apr publish explains apm update cannot create a publishing worktree"
        assert_file_not_contains /tmp/publish-no-clone.out \
          "apm update no-clone-reg" \
          "apr publish does not suggest invalid positional update syntax"
        assert_file_contains /tmp/publish-no-clone.out \
          "apr create no-clone-reg" "apr publish points to apr create"
      fi

      $APM update --registry no-clone-reg > /tmp/update-no-clone.out 2>&1 || {
        cat /tmp/update-no-clone.out
        fail "apm update --registry syncs config-only registry metadata"
      }
      cat /tmp/update-no-clone.out
      assert_file_contains /tmp/update-no-clone.out \
        "Registry 'no-clone-reg': done" \
        "apm update --registry follows the no-clone recovery hint for consumers"
      assert_dir_exists "$HOME/.local/share/apm/remote/no-clone-reg/repo.git" \
        "apm update materializes consumer git cache"
      assert_file_exists "$REG_STORAGE/no-clone-reg/registry.toml" \
        "apm update materializes authenticated registry root metadata"
      if [ -d "$REG_STORAGE/no-clone-reg/.git" ]; then
        fail "apm update should not create an APR publishing worktree"
      else
        pass "apm update leaves APR publishing worktree absent"
      fi

      if $APR publish /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dummy-1.0.0 \
        --name dummy --version 1.0.0 --registry no-clone-reg --no-commit \
        > /tmp/publish-after-update.out 2>&1; then
        fail "apr publish should still fail after consumer metadata update"
      else
        cat /tmp/publish-after-update.out
        assert_file_contains /tmp/publish-after-update.out \
          "has no writable local clone" \
          "apr publish still reports missing writable clone after apm update"
        assert_file_contains /tmp/publish-after-update.out \
          "only syncs consumer metadata" \
          "apr publish distinguishes consumer metadata from publishing worktree"
        assert_file_not_contains /tmp/publish-after-update.out \
          "not a git repository" \
          "apr publish does not fall through to a raw git error"
        assert_file_not_contains /tmp/publish-after-update.out \
          "store path" \
          "apr publish validates writable clone before store introspection"
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-remove — Remove a registry
  # -------------------------------------------------------------------------
  registry-remove = testing.mkVMTest {
    name = "apm-registry-remove";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: apr remove"

      # Add a registry first
      $APM registry add --no-verify file:///tmp/fake-remote --name removable-reg

      # Verify it exists
      assert_file_exists "$APM_CONFIG/registries.d/removable-reg.toml" \
        "registry config exists before remove"

      # Remove it
      $APM registry remove removable-reg

      # Verify config file is gone
      assert_file_not_exists "$APM_CONFIG/registries.d/removable-reg.toml" \
        "registry config removed"

      # Verify apr list no longer shows it
      $APR list > /tmp/list-output 2>&1 || true
      if grep -q "removable-reg" /tmp/list-output 2>/dev/null; then
        fail "apr list still shows removed registry"
      else
        pass "apr list no longer shows removed registry"
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-remove-unprivileged — Remove without profile write access
  # -------------------------------------------------------------------------
  registry-remove-unprivileged = testing.mkVMTest {
    name = "apm-registry-remove-unprivileged";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: unprivileged apr remove does not touch package profile"

      USER_HOME=/tmp/apr-user
      mkdir -p "$USER_HOME/.config/apm/registries.d"
      mkdir -p "$USER_HOME/.local/share/apm/registries/unpriv-reg"
      mkdir -p "$USER_HOME/.local/share/apm/remote/unpriv-reg"
      mkdir -p /var/lib/profiles
      chmod 755 /var/lib/profiles

      cat > "$USER_HOME/.config/apm/registries.d/unpriv-reg.toml" << 'EOF'
      [registry]
      name = "unpriv-reg"
      url = "file:///tmp/unpriv-reg"
      priority = 500
      enabled = true
      EOF

      chown -R 1000:1000 "$USER_HOME"

      if env HOME="$USER_HOME" USER=aprtest chroot --userspec=1000:1000 / \
        "$APR" remove unpriv-reg > /tmp/unpriv-remove.out 2>&1; then
        cat /tmp/unpriv-remove.out
        pass "unprivileged apr remove succeeds"
      else
        cat /tmp/unpriv-remove.out
        fail "unprivileged apr remove should not require profile write access"
      fi

      assert_file_not_exists "$USER_HOME/.config/apm/registries.d/unpriv-reg.toml" \
        "registry config removed by unprivileged apr"

      if [ -e /var/lib/profiles/per-user/aprtest ]; then
        fail "apr remove should not create the package profile"
      else
        pass "apr remove leaves package profile untouched"
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-publish — Publish a package entry to the registry
  # -------------------------------------------------------------------------
  registry-publish = testing.mkVMTest {
    name = "apm-registry-publish";
    rootfsDeps = publishDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: publish a package to registry"

      # Create registry
      $APR create test-reg

      REG_DIR="$REG_STORAGE/test-reg"

      $APR publish ${aosPkg} \
        --name testpkg \
        --version 1.0.0 \
        --description "Published by the APR VM workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg

      # Verify packages/t/testpkg.toml exists
      assert_file_exists "$REG_DIR/packages/t/testpkg.toml" \
        "package TOML file exists"

      # Verify TOML has required fields
      assert_file_contains "$REG_DIR/packages/t/testpkg.toml" \
        "store_path" "TOML has store_path"
      assert_file_contains "$REG_DIR/packages/t/testpkg.toml" \
        "nar_hash" "TOML has nar_hash"
      assert_file_contains "$REG_DIR/packages/t/testpkg.toml" \
        "references" "TOML has references"

      STORE_HASH=$(basename ${aosPkg} | cut -d- -f1)
      assert_file_exists "$REG_DIR/closures/$STORE_HASH" \
        "apr publish writes closure metadata"

      # Verify git log shows the publish commit
      cd "$REG_DIR"
      assert_cmd_output_contains "git log --oneline" "publish testpkg" \
        "git log shows publish commit"
      cd /tmp

      $APR publish ${pkgs.curl} \
        --name testpkg \
        --version 2.0.0 \
        --description "Published by the APR VM workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg

      CURL_HASH=$(basename ${pkgs.curl} | cut -d- -f1)
      assert_file_exists "$REG_DIR/closures/$CURL_HASH" \
        "apr publish writes v2 closure metadata"

      $APR packages --registry test-reg > /tmp/packages.out 2>&1 || {
        cat /tmp/packages.out
        fail "apr packages lists published packages"
      }
      cat /tmp/packages.out
      assert_file_contains /tmp/packages.out "testpkg 2.0.0" \
        "apr packages reports latest published version"
      if grep -q "testpkg 1.0.0" /tmp/packages.out; then
        fail "apr packages should not report the older version as current"
      else
        pass "apr packages does not report the older version as current"
      fi

      $APR packages --registry test-reg --outdated \
        > /tmp/packages-outdated.out 2>&1 || {
        cat /tmp/packages-outdated.out
        fail "apr packages --outdated lists multi-version packages"
      }
      assert_file_contains /tmp/packages-outdated.out "testpkg 2.0.0" \
        "apr packages --outdated reports the latest available version"

      $APR show testpkg --registry test-reg --version 1.0.0 \
        > /tmp/show-v1.out 2>&1 || {
        cat /tmp/show-v1.out
        fail "apr show --version selects existing version"
      }
      assert_file_contains /tmp/show-v1.out "Version: 1.0.0" \
        "apr show --version prints selected v1"
      if grep -q "Version: 2.0.0" /tmp/show-v1.out; then
        cat /tmp/show-v1.out
        fail "apr show --version should not print v2"
      else
        pass "apr show --version hides non-selected versions"
      fi

      $APR show testpkg --registry test-reg --version 1.0.0 --raw \
        > /tmp/show-v1-raw.out 2>&1 || {
        cat /tmp/show-v1-raw.out
        fail "apr show --version --raw selects existing version"
      }
      assert_file_contains /tmp/show-v1-raw.out "version = \"1.0.0\"" \
        "apr show --version --raw prints selected v1"
      if grep -q "version = \"2.0.0\"" /tmp/show-v1-raw.out; then
        cat /tmp/show-v1-raw.out
        fail "apr show --version --raw should not print v2"
      else
        pass "apr show --version --raw hides non-selected versions"
      fi

      if $APR show testpkg --registry test-reg --version 9.9.9 \
        > /tmp/show-missing-version.out 2>&1; then
        cat /tmp/show-missing-version.out
        fail "apr show should reject missing versions"
      else
        assert_file_contains /tmp/show-missing-version.out \
          "does not contain version '9.9.9'" \
          "apr show reports missing requested version"
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-publish-alt-nix-state — Publish against re-rooted Nix state
  # -------------------------------------------------------------------------
  registry-publish-alt-nix-state = testing.mkVMTest {
    name = "apm-registry-publish-alt-nix-state";
    rootfsDeps = publishDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupAltNixPublishEnv}

      echo "==> Test: apr publish honors alternate Nix state DB"

      $APR create alt-state-reg
      REG_DIR="$REG_STORAGE/alt-state-reg"
      echo "local maintainer note" > "$REG_DIR/maintainer-notes.txt"

      $APR publish ${aosPkg} \
        --name alt-state-pkg \
        --version 1.0.0 \
        --description "Published from alternate Nix state" \
        --license MIT \
        --maintainer alt-state@example.invalid \
        --registry alt-state-reg > /tmp/alt-state-publish.out 2>&1 || {
        cat /tmp/alt-state-publish.out
        fail "apr publish succeeds using AOS_NIX_STATE_DIR"
      }
      cat /tmp/alt-state-publish.out

      assert_file_exists "$REG_DIR/packages/a/alt-state-pkg.toml" \
        "alternate-state publish writes package metadata"
      assert_file_contains "$REG_DIR/packages/a/alt-state-pkg.toml" \
        "store_path = \"${aosPkg}\"" \
        "alternate-state publish records the requested store path"
      assert_file_contains "$REG_DIR/packages/a/alt-state-pkg.toml" \
        "nar_hash" "alternate-state publish records NAR hash"

      STORE_HASH=$(basename ${aosPkg} | cut -d- -f1)
      assert_file_exists "$REG_DIR/closures/$STORE_HASH" \
        "alternate-state publish writes closure metadata"
      assert_file_contains "$REG_DIR/closures/$STORE_HASH" "$STORE_HASH" \
        "alternate-state closure metadata contains root hash"
      if git -C "$REG_DIR" ls-tree -r --name-only HEAD | grep -q "maintainer-notes.txt"; then
        fail "apr publish should not commit unrelated maintainer scratch files"
      else
        pass "apr publish leaves unrelated maintainer scratch files out of HEAD"
      fi
      git -C "$REG_DIR" status --short --untracked-files=all \
        > /tmp/alt-state-publish-status.out
      assert_file_contains /tmp/alt-state-publish-status.out \
        "maintainer-notes.txt" \
        "apr publish leaves unrelated maintainer scratch file untracked"
      rm -f "$REG_DIR/maintainer-notes.txt"

      $APR verify --registry alt-state-reg > /tmp/alt-state-verify.out 2>&1 || {
        cat /tmp/alt-state-verify.out
        fail "apr verify accepts alternate-state published registry"
      }
      assert_file_contains /tmp/alt-state-verify.out "no errors" \
        "apr verify validates alternate-state published registry"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-publish-sysroot — Publish a sysroot package with images
  # -------------------------------------------------------------------------
  registry-publish-sysroot = testing.mkVMTest {
    name = "apm-registry-publish-sysroot";
    rootfsDeps = publishDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: publish sysroot package with images"

      # Create registry
      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"

      $APR publish ${aosPkg} \
        --name server \
        --version 1.0.0 \
        --description "Published sysroot by the APR VM workflow" \
        --license MIT \
        --maintainer test \
        --sysroot \
        --image ${aosPkg} \
        --image-format raw \
        --registry test-reg

      # Verify sysroot flag
      assert_file_contains "$REG_DIR/packages/s/server.toml" \
        "sysroot = true" "TOML has sysroot = true"

      # Verify images block
      assert_file_contains "$REG_DIR/packages/s/server.toml" \
        "format = \"raw\"" "TOML has image format"
      assert_file_contains "$REG_DIR/packages/s/server.toml" \
        "images" "TOML has images section"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-unpublish — Selectively remove versions and platforms
  # -------------------------------------------------------------------------
  registry-unpublish = testing.mkVMTest {
    name = "apm-registry-unpublish";
    rootfsDeps =
      closureWorkflowDeps
      ++ [
        pkgs.iproute2
        pkgs.python3
        pkgs.zstd
      ];
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: selectively unpublish package versions and platforms"

      LEAF_STORE="${closureLeafTool}"
      ROOT_STORE="${closureRootTool}"
      RETIRE_DEP_STORE="${retireDepTool}"
      RETIRE_STORE="${retireTool}"
      RETIRE_DEP_HASH=$(basename "$RETIRE_DEP_STORE" | cut -d- -f1)
      RETIRE_HASH=$(basename "$RETIRE_STORE" | cut -d- -f1)
      MAINTAINER_HOME=/tmp
      CONSUMER_HOME=/tmp/unpublish-consumer
      PROFILE="/var/lib/profiles/per-user/unpublishuser"

      as_maintainer() {
        export HOME="$MAINTAINER_HOME"
        export USER=root
      }

      as_consumer() {
        export HOME="$CONSUMER_HOME"
        export USER=unpublishuser
        mkdir -p "$HOME"
      }

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/unpublish-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/unpublish-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/unpublish-missing-$label.out" 2>&1; then
          cat "/tmp/unpublish-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/unpublish-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/unpublish-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18109/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      # Create registry and publish a package
      as_maintainer
      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

      $APR publish "$LEAF_STORE" \
        --name removepkg \
        --version 1.0.0 \
        --platform x86_64-linux \
        --description "Published v1 for unpublish workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg
      $APR publish "$ROOT_STORE" \
        --name removepkg \
        --version 2.0.0 \
        --platform x86_64-linux \
        --previous 1.0.0 \
        --description "Published v2 for unpublish workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg
      $APR publish "$ROOT_STORE" \
        --name removepkg \
        --version 2.0.0 \
        --platform aarch64-linux \
        --previous 1.0.0 \
        --description "Published v2 for unpublish workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg
      $APR publish "$RETIRE_DEP_STORE" \
        --name retire-dep \
        --version 1.0.0 \
        --platform x86_64-linux \
        --description "Dependency that remains after retire-tool is unpublished" \
        --license MIT \
        --maintainer test \
        --registry test-reg
      $APR publish "$RETIRE_STORE" \
        --name retire-tool \
        --version 1.0.0 \
        --platform x86_64-linux \
        --description "Installed package retired by unpublish workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg

      # Verify package exists
      assert_file_exists "$REG_DIR/packages/r/removepkg.toml" \
        "package TOML exists before unpublish"
      assert_file_exists "$REG_DIR/packages/r/retire-tool.toml" \
        "consumer package TOML exists before unpublish"
      assert_file_contains "$REG_DIR/packages/r/retire-tool.toml" "$RETIRE_DEP_HASH" \
        "consumer package metadata records dependency"
      assert_file_contains "$REG_DIR/closures/$RETIRE_HASH" "$RETIRE_DEP_HASH" \
        "consumer package closure records dependency"
      $APR show removepkg --registry test-reg --raw > /tmp/unpublish-before.toml 2>&1 || {
        cat /tmp/unpublish-before.toml
        fail "apr show --raw reports initial multi-version package"
      }
      assert_file_contains /tmp/unpublish-before.toml 'version = "1.0.0"' \
        "initial package contains v1"
      assert_file_contains /tmp/unpublish-before.toml 'version = "2.0.0"' \
        "initial package contains v2"
      assert_file_contains /tmp/unpublish-before.toml 'x86_64-linux' \
        "initial package contains x86_64 platform"
      assert_file_contains /tmp/unpublish-before.toml 'aarch64-linux' \
        "initial package contains aarch64 platform"
      $APR packages --registry test-reg --platform aarch64-linux \
        > /tmp/unpublish-packages-aarch64-before.out 2>&1 || {
        cat /tmp/unpublish-packages-aarch64-before.out
        fail "apr packages --platform sees aarch64 package before unpublish"
      }
      assert_file_contains /tmp/unpublish-packages-aarch64-before.out \
        "removepkg 2.0.0" \
        "aarch64 platform filter sees v2 before unpublish"

      $APR cache generate \
        --registry test-reg \
        --output /tmp/unpublish-cache \
        --cache-url http://127.0.0.1:18109 \
        --priority 53 \
        --no-commit > /tmp/unpublish-cache-generate.out 2>&1 || {
        cat /tmp/unpublish-cache-generate.out
        fail "apr cache generate writes consumer unpublish cache"
      }
      cat /tmp/unpublish-cache-generate.out
      assert_file_exists "/tmp/unpublish-cache/$RETIRE_HASH.narinfo" \
        "static cache has retire-tool narinfo"
      assert_file_exists "/tmp/unpublish-cache/$RETIRE_DEP_HASH.narinfo" \
        "static cache has retire-dep narinfo"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "registry: publish unpublish consumer cache"
      git init --bare --object-format=sha256 /tmp/unpublish-origin.git
      git -C "$REG_DIR" remote add origin /tmp/unpublish-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18109 --bind 127.0.0.1 \
        --directory /tmp/unpublish-cache > /tmp/unpublish-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/unpublish-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install package before maintainer unpublishes it"
      as_consumer
      $APM registry add file:///tmp/unpublish-origin.git \
        --name test-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/unpublish-registry-add.out 2>&1 || {
        cat /tmp/unpublish-registry-add.out
        fail "apm registry add syncs unpublish registry"
      }
      cat /tmp/unpublish-registry-add.out
      delete_store_path "$RETIRE_STORE" "retire-tool"
      delete_store_path "$RETIRE_DEP_STORE" "retire-dep"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install retire-tool --registry test-reg --yes \
        > /tmp/unpublish-install-retire-tool.out 2>&1 || {
        cat /tmp/unpublish-install-retire-tool.out
        fail "apm install downloads retire-tool before unpublish"
      }
      cat /tmp/unpublish-install-retire-tool.out
      assert_file_contains /tmp/unpublish-install-retire-tool.out "Downloading" \
        "apm install downloads retire-tool closure"
      assert_store_valid "$RETIRE_STORE" "retire-tool"
      assert_store_valid "$RETIRE_DEP_STORE" "retire-dep"
      "$PROFILE/current/bin/retire-tool" > /tmp/unpublish-retire-tool-run-before.out
      assert_file_contains /tmp/unpublish-retire-tool-run-before.out \
        "^retire-tool 1.0.0 via retire-dep 1.0.0$" \
        "installed retire-tool executable runs before unpublish"
      $APM list --installed > /tmp/unpublish-installed-before.out 2>&1 || {
        cat /tmp/unpublish-installed-before.out
        fail "apm list --installed sees retire-tool before unpublish"
      }
      assert_file_contains /tmp/unpublish-installed-before.out "retire-tool/test-reg 1.0.0" \
        "installed list reports retire-tool before unpublish"

      as_maintainer

      if $APR unpublish removepkg 9.9.9 --registry test-reg --no-commit \
        > /tmp/unpublish-missing-version.out 2>&1; then
        cat /tmp/unpublish-missing-version.out
        fail "apr unpublish should reject a missing version"
      else
        cat /tmp/unpublish-missing-version.out
        pass "apr unpublish rejects a missing version"
      fi
      assert_file_contains /tmp/unpublish-missing-version.out \
        "does not contain version '9.9.9'" \
        "missing-version unpublish error names requested version"

      if $APR unpublish removepkg 2.0.0 --platform riscv64-linux \
        --registry test-reg --no-commit > /tmp/unpublish-missing-platform.out 2>&1; then
        cat /tmp/unpublish-missing-platform.out
        fail "apr unpublish should reject a missing platform"
      else
        cat /tmp/unpublish-missing-platform.out
        pass "apr unpublish rejects a missing platform"
      fi
      assert_file_contains /tmp/unpublish-missing-platform.out \
        "version '2.0.0' does not contain platform 'riscv64-linux'" \
        "missing-platform unpublish error names requested platform"

      HEAD_BEFORE_NO_COMMIT=$(git -C "$REG_DIR" rev-parse HEAD)
      $APR unpublish removepkg 2.0.0 --platform aarch64-linux \
        --registry test-reg --no-commit > /tmp/unpublish-aarch64.out 2>&1 || {
        cat /tmp/unpublish-aarch64.out
        fail "apr unpublish --platform --no-commit removes one platform"
      }
      cat /tmp/unpublish-aarch64.out
      HEAD_AFTER_NO_COMMIT=$(git -C "$REG_DIR" rev-parse HEAD)
      if [ "$HEAD_BEFORE_NO_COMMIT" = "$HEAD_AFTER_NO_COMMIT" ]; then
        pass "apr unpublish --no-commit leaves HEAD unchanged"
      else
        fail "apr unpublish --no-commit should not create a commit"
      fi
      git -C "$REG_DIR" status --short --untracked-files=all \
        > /tmp/unpublish-status-after-no-commit.out
      assert_file_contains /tmp/unpublish-status-after-no-commit.out \
        "packages/r/removepkg.toml" \
        "apr unpublish --no-commit leaves package metadata dirty"

      $APR show removepkg --registry test-reg --version 2.0.0 --raw \
        > /tmp/unpublish-v2-after-aarch64.toml 2>&1 || {
        cat /tmp/unpublish-v2-after-aarch64.toml
        fail "apr show reports v2 after platform unpublish"
      }
      assert_file_contains /tmp/unpublish-v2-after-aarch64.toml 'x86_64-linux' \
        "v2 keeps x86_64 platform after aarch64 unpublish"
      assert_file_not_contains /tmp/unpublish-v2-after-aarch64.toml 'aarch64-linux' \
        "v2 drops aarch64 platform after unpublish"
      $APR packages --registry test-reg --platform aarch64-linux \
        > /tmp/unpublish-packages-aarch64-after.out 2>&1 || {
        cat /tmp/unpublish-packages-aarch64-after.out
        fail "apr packages --platform succeeds after aarch64 unpublish"
      }
      assert_file_not_contains /tmp/unpublish-packages-aarch64-after.out \
        "removepkg" \
        "aarch64 platform filter hides package after unpublish"

      $APR unpublish removepkg 1.0.0 \
        --registry test-reg \
        --message "registry: retire removepkg 1.0.0 and aarch64" \
        > /tmp/unpublish-v1.out 2>&1 || {
        cat /tmp/unpublish-v1.out
        fail "apr unpublish with custom message commits pending removals"
      }
      cat /tmp/unpublish-v1.out
      assert_file_contains /tmp/unpublish-v1.out \
        "registry: retire removepkg 1.0.0 and aarch64" \
        "apr unpublish reports custom commit message"
      git -C "$REG_DIR" log --oneline -1 > /tmp/unpublish-custom-log.out
      assert_file_contains /tmp/unpublish-custom-log.out \
        "registry: retire removepkg 1.0.0 and aarch64" \
        "git log records custom unpublish message"

      if $APR show removepkg --registry test-reg --version 1.0.0 \
        > /tmp/unpublish-show-v1.out 2>&1; then
        cat /tmp/unpublish-show-v1.out
        fail "apr show should not find unpublished v1"
      else
        cat /tmp/unpublish-show-v1.out
        pass "apr show rejects unpublished v1"
      fi
      assert_file_contains /tmp/unpublish-show-v1.out \
        "does not contain version '1.0.0'" \
        "apr show reports v1 was removed"
      $APR show removepkg --registry test-reg --version 2.0.0 \
        > /tmp/unpublish-show-v2.out 2>&1 || {
        cat /tmp/unpublish-show-v2.out
        fail "apr show still finds remaining v2"
      }
      assert_file_contains /tmp/unpublish-show-v2.out "Version: 2.0.0" \
        "apr show reports remaining v2"

      $APR unpublish removepkg 2.0.0 --platform x86_64-linux \
        --registry test-reg \
        --message "registry: remove final removepkg platform" \
        > /tmp/unpublish-final-platform.out 2>&1 || {
        cat /tmp/unpublish-final-platform.out
        fail "apr unpublish removes final platform and package file"
      }
      cat /tmp/unpublish-final-platform.out

      # Verify TOML file removed
      assert_file_not_exists "$REG_DIR/packages/r/removepkg.toml" \
        "package TOML removed after final platform unpublish"
      $APR unpublish retire-tool \
        --registry test-reg \
        --message "registry: retire installed consumer package" \
        > /tmp/unpublish-retire-tool.out 2>&1 || {
        cat /tmp/unpublish-retire-tool.out
        fail "apr unpublish removes installed consumer package from registry"
      }
      cat /tmp/unpublish-retire-tool.out
      assert_file_not_exists "$REG_DIR/packages/r/retire-tool.toml" \
        "consumer package TOML removed by unpublish"
      git -C "$REG_DIR" rm -f "closures/$RETIRE_HASH" \
        > /tmp/unpublish-retire-tool-closure-rm.out 2>&1 || {
        cat /tmp/unpublish-retire-tool-closure-rm.out
        fail "maintainer prunes retired package closure metadata"
      }
      git -C "$REG_DIR" commit -m "registry: prune retired consumer closure" \
        > /tmp/unpublish-retire-tool-closure-commit.out 2>&1 || {
        cat /tmp/unpublish-retire-tool-closure-commit.out
        fail "maintainer commits retired package closure pruning"
      }
      assert_file_not_exists "$REG_DIR/closures/$RETIRE_HASH" \
        "retired package closure metadata pruned"
      $APR packages --registry test-reg > /tmp/unpublish-packages-final.out 2>&1 || {
        cat /tmp/unpublish-packages-final.out
        fail "apr packages succeeds after final unpublish"
      }
      assert_file_not_contains /tmp/unpublish-packages-final.out "removepkg" \
        "apr packages hides fully unpublished package"
      assert_file_not_contains /tmp/unpublish-packages-final.out "retire-tool" \
        "apr packages hides retired consumer package"
      assert_file_contains /tmp/unpublish-packages-final.out "retire-dep" \
        "apr packages keeps dependency that remains published"

      # Verify git log shows removal commit
      cd "$REG_DIR"
      assert_cmd_output_contains "git log --oneline -2" \
        "registry: retire installed consumer package" \
        "git log shows consumer package retirement commit"
      cd /tmp
      $APR verify --registry test-reg > /tmp/unpublish-verify-final.out 2>&1 || {
        cat /tmp/unpublish-verify-final.out
        fail "apr verify accepts registry after unpublish workflow"
      }
      assert_file_contains /tmp/unpublish-verify-final.out "no errors" \
        "apr verify reports no errors after unpublish workflow"

      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: update after maintainer unpublishes installed package"
      as_consumer
      $APM update --registry test-reg > /tmp/unpublish-consumer-update.out 2>&1 || {
        cat /tmp/unpublish-consumer-update.out
        fail "apm update syncs unpublish changeset"
      }
      cat /tmp/unpublish-consumer-update.out
      assert_file_contains /tmp/unpublish-consumer-update.out "removed" \
        "apm update reports package metadata removal"
      $APM list --installed > /tmp/unpublish-installed-after.out 2>&1 || {
        cat /tmp/unpublish-installed-after.out
        fail "apm list --installed succeeds after installed package is unpublished"
      }
      cat /tmp/unpublish-installed-after.out
      assert_file_contains /tmp/unpublish-installed-after.out "retire-tool/test-reg 1.0.0" \
        "installed list keeps installed package after registry unpublish"
      assert_file_contains /tmp/unpublish-installed-after.out "unavailable" \
        "installed list marks unpublished installed package unavailable"
      $APM search retire-tool --registry test-reg --names-only \
        > /tmp/unpublish-search-after.out 2>&1 || {
        cat /tmp/unpublish-search-after.out
        fail "apm search succeeds after package is unpublished"
      }
      assert_file_not_contains /tmp/unpublish-search-after.out "retire-tool" \
        "default search hides package after registry unpublish"
      $APM search retire-tool --installed > /tmp/unpublish-search-installed-after.out 2>&1 || {
        cat /tmp/unpublish-search-installed-after.out
        fail "apm search --installed succeeds after package is unpublished"
      }
      cat /tmp/unpublish-search-installed-after.out
      assert_file_contains /tmp/unpublish-search-installed-after.out \
        "retire-tool/test-reg 1.0.0" \
        "installed search keeps installed package after registry unpublish"
      assert_file_contains /tmp/unpublish-search-installed-after.out "unavailable" \
        "installed search marks unpublished package unavailable"
      $APM --json search retire-tool --installed \
        > /tmp/unpublish-search-installed-after.json || {
        cat /tmp/unpublish-search-installed-after.json
        fail "apm --json search --installed succeeds after package is unpublished"
      }
      assert_file_contains /tmp/unpublish-search-installed-after.json "retire-tool" \
        "installed search JSON keeps unpublished package"
      assert_file_contains /tmp/unpublish-search-installed-after.json "unavailable" \
        "installed search JSON marks unpublished package unavailable"
      $APM policy retire-tool > /tmp/unpublish-policy-after.out 2>&1 || {
        cat /tmp/unpublish-policy-after.out
        fail "apm policy succeeds after installed package is unpublished"
      }
      cat /tmp/unpublish-policy-after.out
      assert_file_contains /tmp/unpublish-policy-after.out "Installed: 1.0.0" \
        "policy reports installed version after registry unpublish"
      assert_file_contains /tmp/unpublish-policy-after.out "Candidate: (none)" \
        "policy reports no candidate after registry unpublish"
      assert_file_contains /tmp/unpublish-policy-after.out "test-reg (installed, unavailable)" \
        "policy marks unpublished installed version unavailable"
      $APM show retire-tool > /tmp/unpublish-show-installed-after.out 2>&1 || {
        cat /tmp/unpublish-show-installed-after.out
        fail "apm show succeeds from installed metadata after registry unpublish"
      }
      cat /tmp/unpublish-show-installed-after.out
      assert_file_contains /tmp/unpublish-show-installed-after.out "Package: retire-tool" \
        "show reports unpublished installed package name"
      assert_file_contains /tmp/unpublish-show-installed-after.out "Version: 1.0.0" \
        "show reports unpublished installed package version"
      assert_file_contains /tmp/unpublish-show-installed-after.out \
        "Status: installed, unavailable in registry" \
        "show marks unpublished installed package unavailable"
      assert_file_contains /tmp/unpublish-show-installed-after.out "Dependencies:.*retire-dep" \
        "show resolves installed dependency after registry unpublish"
      $APM --json show retire-tool > /tmp/unpublish-show-installed-after.json || {
        cat /tmp/unpublish-show-installed-after.json
        fail "apm --json show succeeds from installed metadata after registry unpublish"
      }
      assert_file_contains /tmp/unpublish-show-installed-after.json '"name":"retire-tool"' \
        "show JSON reports unpublished installed package name"
      assert_file_contains /tmp/unpublish-show-installed-after.json '"unavailable":true' \
        "show JSON marks unpublished installed package unavailable"
      assert_file_contains /tmp/unpublish-show-installed-after.json '"retire-dep"' \
        "show JSON resolves installed dependency after registry unpublish"
      $APM depends retire-tool > /tmp/unpublish-depends-after.out 2>&1 || {
        cat /tmp/unpublish-depends-after.out
        fail "apm depends succeeds from installed closure after registry unpublish"
      }
      cat /tmp/unpublish-depends-after.out
      assert_file_contains /tmp/unpublish-depends-after.out "retire-tool (1.0.0)" \
        "depends reports unpublished installed package root"
      assert_file_contains /tmp/unpublish-depends-after.out "retire-dep (1.0.0)" \
        "depends resolves installed dependency after registry unpublish"
      assert_file_contains /tmp/unpublish-depends-after.out \
        "unique store paths in installed dependency tree" \
        "depends reports installed dependency tree summary"
      $APM rdepends retire-dep > /tmp/unpublish-rdepends-after.out 2>&1 || {
        cat /tmp/unpublish-rdepends-after.out
        fail "apm rdepends succeeds from installed closure after dependency metadata prune"
      }
      cat /tmp/unpublish-rdepends-after.out
      assert_file_contains /tmp/unpublish-rdepends-after.out \
        "retire-dep (1.0.0) is required by:" \
        "rdepends reports dependents for retained dependency"
      assert_file_contains /tmp/unpublish-rdepends-after.out "retire-tool (1.0.0)" \
        "rdepends finds unpublished installed dependent via local store closure"
      "$PROFILE/current/bin/retire-tool" > /tmp/unpublish-retire-tool-run-after.out
      assert_file_contains /tmp/unpublish-retire-tool-run-after.out \
        "^retire-tool 1.0.0 via retire-dep 1.0.0$" \
        "installed retire-tool executable still runs after registry unpublish"
      if $APM verify retire-tool > /tmp/unpublish-retire-tool-verify.out 2>&1; then
        cat /tmp/unpublish-retire-tool-verify.out
        fail "apm verify should fail once installed package is unpublished"
      else
        cat /tmp/unpublish-retire-tool-verify.out
        pass "apm verify fails for unpublished installed package"
      fi
      assert_file_contains /tmp/unpublish-retire-tool-verify.out \
        "not present in registry 'test-reg'" \
        "verify error explains installed package is absent from registry"
      $APM upgrade retire-tool --yes > /tmp/unpublish-retire-tool-upgrade.out 2>&1 || {
        cat /tmp/unpublish-retire-tool-upgrade.out
        fail "apm upgrade handles unpublished installed package"
      }
      assert_file_contains /tmp/unpublish-retire-tool-upgrade.out \
        "All packages are up to date" \
        "upgrade does not invent a candidate for unpublished installed package"

      $APM remove retire-tool --autoremove --yes > /tmp/unpublish-remove-retired.out 2>&1 || {
        cat /tmp/unpublish-remove-retired.out
        fail "apm remove --autoremove removes unpublished installed package"
      }
      cat /tmp/unpublish-remove-retired.out
      assert_file_contains /tmp/unpublish-remove-retired.out "retire-tool" \
        "remove lists retired explicit package"
      assert_file_contains /tmp/unpublish-remove-retired.out "retire-dep" \
        "autoremove lists retired package dependency"
      assert_file_contains /tmp/unpublish-remove-retired.out "Removed 2 package" \
        "remove reports retired package and orphan removal"
      assert_file_not_exists "$PROFILE/meta/$RETIRE_HASH.json" \
        "remove deletes retired package metadata"
      assert_file_not_exists "$PROFILE/meta/$RETIRE_DEP_HASH.json" \
        "autoremove deletes retired dependency metadata"
      if [ -e "$PROFILE/current/bin/retire-tool" ]; then
        fail "retired package executable should be absent after remove"
      else
        pass "retired package executable absent after remove"
      fi
      $APM list --installed > /tmp/unpublish-installed-after-remove.out 2>&1 || {
        cat /tmp/unpublish-installed-after-remove.out
        fail "apm list --installed succeeds after retired package removal"
      }
      assert_file_not_contains /tmp/unpublish-installed-after-remove.out "retire-tool" \
        "installed list omits retired package after remove"
      assert_file_not_contains /tmp/unpublish-installed-after-remove.out "retire-dep" \
        "installed list omits retired dependency after autoremove"

      $APM rollback > /tmp/unpublish-rollback-after-remove.out 2>&1 || {
        cat /tmp/unpublish-rollback-after-remove.out
        fail "apm rollback restores retired package generation"
      }
      cat /tmp/unpublish-rollback-after-remove.out
      assert_file_contains /tmp/unpublish-rollback-after-remove.out "Rolled back to generation 1" \
        "rollback returns to retired package generation"
      "$PROFILE/current/bin/retire-tool" > /tmp/unpublish-retire-tool-run-rollback.out
      assert_file_contains /tmp/unpublish-retire-tool-run-rollback.out \
        "^retire-tool 1.0.0 via retire-dep 1.0.0$" \
        "rolled-back retired package executable runs"
      assert_file_exists "$PROFILE/meta/$RETIRE_HASH.json" \
        "rollback restores retired package metadata snapshot"
      assert_file_exists "$PROFILE/meta/$RETIRE_DEP_HASH.json" \
        "rollback restores retired dependency metadata snapshot"
      $APM list --installed > /tmp/unpublish-installed-after-rollback.out 2>&1 || {
        cat /tmp/unpublish-installed-after-rollback.out
        fail "apm list --installed succeeds after retired package rollback"
      }
      cat /tmp/unpublish-installed-after-rollback.out
      assert_file_contains /tmp/unpublish-installed-after-rollback.out "retire-tool/test-reg 1.0.0" \
        "installed list sees retired package after rollback"
      assert_file_contains /tmp/unpublish-installed-after-rollback.out "retire-dep/test-reg 1.0.0" \
        "installed list sees retired dependency after rollback"
      assert_file_contains /tmp/unpublish-installed-after-rollback.out "unavailable" \
        "installed list keeps retired package unavailable after rollback"
      $APM show retire-tool > /tmp/unpublish-show-after-rollback.out 2>&1 || {
        cat /tmp/unpublish-show-after-rollback.out
        fail "apm show works after rolling back retired package"
      }
      assert_file_contains /tmp/unpublish-show-after-rollback.out \
        "Status: installed, unavailable in registry" \
        "show uses restored retired metadata after rollback"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-maintainer-workflow — Real release, cache, install, execute
  # -------------------------------------------------------------------------
  registry-maintainer-workflow = testing.mkVMTest {
    name = "apm-registry-maintainer-workflow";
    rootfsDeps = maintainerWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: full registry maintainer release and consumer install"

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      GIT_STORE="${pkgs.git}"
      CURL_STORE="${pkgs.curl}"
      GIT_HASH=$(basename "$GIT_STORE" | cut -d- -f1)
      CURL_HASH=$(basename "$CURL_STORE" | cut -d- -f1)
      RUNNER_SRC=/tmp/maint-runner-src
      mkdir -p "$RUNNER_SRC/bin" "$RUNNER_SRC/share/maint-runner"
      cat > "$RUNNER_SRC/bin/maint-runner" << 'RUNNEREOF'
      #!/bin/sh
      echo "maint-runner 1.0.0 executed"
      RUNNEREOF
      chmod +x "$RUNNER_SRC/bin/maint-runner"
      ln -s maint-runner "$RUNNER_SRC/bin/maint-runner-link"
      dd if=/dev/zero of="$RUNNER_SRC/share/maint-runner/payload.bin" \
        bs=1M count=12
      ln -s . "$RUNNER_SRC/share/maint-runner/current"
      RUNNER_STORE=$(nix-store --add "$RUNNER_SRC")
      RUNNER_HASH=$(basename "$RUNNER_STORE" | cut -d- -f1)

      # Maintainer creates a local registry and prepares a grouped release branch.
      $APR create maint-reg
      REG_DIR="$REG_STORAGE/maint-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR branch create release-2026q2 --registry maint-reg
      $APR branch switch release-2026q2 --registry maint-reg

      $APR publish "$GIT_STORE" \
        --name maint-git \
        --version 1.0.0 \
        --description "Git from the maintainer workflow" \
        --homepage "https://git-scm.com" \
        --license GPL-2.0-only \
        --maintainer release@example.invalid \
        --registry maint-reg \
        --no-commit
      $APR publish "$CURL_STORE" \
        --name maint-curl \
        --version 1.0.0 \
        --description "Curl from the maintainer workflow" \
        --homepage "https://curl.se" \
        --license curl \
        --maintainer release@example.invalid \
        --registry maint-reg \
        --no-commit
      $APR publish "$RUNNER_STORE" \
        --name maint-runner \
        --version 1.0.0 \
        --description "Executable payload from the maintainer workflow" \
        --license MIT \
        --maintainer release@example.invalid \
        --registry maint-reg \
        --no-commit

      $APR cache generate \
        --registry maint-reg \
        --output /tmp/maint-cache \
        --cache-url http://127.0.0.1:18082 \
        --priority 41 \
        --no-commit

      $APR status --registry maint-reg > /tmp/maint-status.out 2>&1 || {
        cat /tmp/maint-status.out
        fail "apr status reports pending maintainer changes"
      }
      cat /tmp/maint-status.out
      assert_file_contains /tmp/maint-status.out "packages/m/maint-git.toml" \
        "apr status shows git package metadata"
      assert_file_contains /tmp/maint-status.out "packages/m/maint-curl.toml" \
        "apr status shows curl package metadata"
      assert_file_contains /tmp/maint-status.out "packages/m/maint-runner.toml" \
        "apr status shows runner package metadata"
      assert_file_contains /tmp/maint-status.out "registry.toml" \
        "apr status shows cache pointer update"

      $APR diff --registry maint-reg --stat > /tmp/maint-diff-stat.out 2>&1 || {
        cat /tmp/maint-diff-stat.out
        fail "apr diff --stat reports tracked maintainer changes"
      }
      cat /tmp/maint-diff-stat.out
      assert_file_contains /tmp/maint-diff-stat.out "registry.toml" \
        "apr diff --stat shows tracked cache pointer update"

      git -C "$REG_DIR" status --short --untracked-files=all \
        > /tmp/changeset.status
      cat /tmp/changeset.status
      assert_file_contains /tmp/changeset.status "packages/m/maint-git.toml" \
        "changeset includes git package metadata"
      assert_file_contains /tmp/changeset.status "packages/m/maint-curl.toml" \
        "changeset includes curl package metadata"
      assert_file_contains /tmp/changeset.status "packages/m/maint-runner.toml" \
        "changeset includes runner package metadata"
      assert_file_contains /tmp/changeset.status "registry.toml" \
        "changeset includes cache pointer update"
      assert_file_exists "$REG_DIR/closures/$GIT_HASH" \
        "changeset includes git closure metadata"
      assert_file_exists "$REG_DIR/closures/$CURL_HASH" \
        "changeset includes curl closure metadata"
      assert_file_exists "$REG_DIR/closures/$RUNNER_HASH" \
        "changeset includes runner closure metadata"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: publish maintainer tools"
      git -C "$REG_DIR" diff --name-only "$DEFAULT_BRANCH"..HEAD > /tmp/changeset.files
      cat /tmp/changeset.files
      assert_file_contains /tmp/changeset.files "packages/m/maint-git.toml" \
        "release diff carries git package"
      assert_file_contains /tmp/changeset.files "packages/m/maint-curl.toml" \
        "release diff carries curl package"
      assert_file_contains /tmp/changeset.files "packages/m/maint-runner.toml" \
        "release diff carries runner package"
      assert_file_contains /tmp/changeset.files "registry.toml" \
        "release diff carries cache endpoint"
      $APR log --registry maint-reg --package maint-runner -n 1 \
        > /tmp/maint-log-runner.out 2>&1 || {
        cat /tmp/maint-log-runner.out
        fail "apr log --package reports package history"
      }
      cat /tmp/maint-log-runner.out
      assert_file_contains /tmp/maint-log-runner.out \
        "release: publish maintainer tools" \
        "apr log --package shows maintainer package commit"

      $APR packages --registry maint-reg > /tmp/maint-packages.out 2>&1
      assert_file_contains /tmp/maint-packages.out "maint-git" \
        "apr packages lists git"
      assert_file_contains /tmp/maint-packages.out "maint-curl" \
        "apr packages lists curl"
      assert_file_contains /tmp/maint-packages.out "maint-runner" \
        "apr packages lists runner"
      $APR verify --registry maint-reg

      $APR branch switch "$DEFAULT_BRANCH" --registry maint-reg
      $APR merge release-2026q2 --registry maint-reg
      ssh-keygen -q -t ed25519 -N "" -f /tmp/maint-release-key

      $APR release 1.0.0 \
        --registry maint-reg \
        --key /tmp/maint-release-key \
        --cache-url http://127.0.0.1:18084 \
        --cache-output /tmp/maint-release-cache-dry-run \
        --channel stable \
        --init-channel \
        --upload-url file:///tmp/maint-origin-dry-run \
        --dry-run \
        > /tmp/release-dry-run.out 2>&1 || {
        cat /tmp/release-dry-run.out
        fail "apr release --dry-run plans full maintainer release"
      }
      cat /tmp/release-dry-run.out
      assert_file_contains /tmp/release-dry-run.out "Release plan" \
        "apr release --dry-run reports release plan"
      assert_file_contains /tmp/release-dry-run.out \
        "commit registry.toml cache pointer http://127.0.0.1:18084 if needed" \
        "release dry-run plans cache pointer"
      assert_file_contains /tmp/release-dry-run.out "generate static Nix cache files" \
        "release dry-run plans static cache output"
      assert_file_contains /tmp/release-dry-run.out "initialize channel stable" \
        "release dry-run plans channel initialization"
      assert_file_contains /tmp/release-dry-run.out \
        "upload immutable files first and mutable refs/channels last" \
        "release dry-run plans static origin upload"
      if git -C "$REG_DIR" rev-parse "1.0.0^{tag}" >/tmp/release-dry-run-tag.out 2>&1; then
        cat /tmp/release-dry-run-tag.out
        fail "release dry-run should not create release tag"
      else
        pass "release dry-run does not create release tag"
      fi
      if [ -e "$REG_DIR/.git/releases/1/0/0" ]; then
        fail "release dry-run should not write release pack artifacts"
      else
        pass "release dry-run does not write release pack artifacts"
      fi
      if [ -e /tmp/maint-release-cache-dry-run ]; then
        fail "release dry-run should not generate static cache output"
      else
        pass "release dry-run does not generate static cache output"
      fi
      if [ -e /tmp/maint-origin-dry-run ]; then
        fail "release dry-run should not upload static origin files"
      else
        pass "release dry-run does not upload static origin files"
      fi
      if grep -q "http://127.0.0.1:18084" "$REG_DIR/registry.toml"; then
        fail "release dry-run should not mutate registry cache pointer"
      else
        pass "release dry-run leaves registry cache pointer unchanged"
      fi
      if git -C "$REG_DIR" status --short --untracked-files=all | grep -q .; then
        git -C "$REG_DIR" status --short --untracked-files=all
        fail "release dry-run should leave worktree clean"
      else
        pass "release dry-run leaves worktree clean"
      fi

      echo "dirty maintainer scratch note" > "$REG_DIR/maintainer-notes.txt"
      if $APR release 1.0.0 \
        --registry maint-reg \
        --key /tmp/maint-release-key \
        --cache-url http://127.0.0.1:18083 \
        > /tmp/dirty-release.out 2>&1; then
        cat /tmp/dirty-release.out
        fail "apr release should refuse dirty registry before cache pointer commit"
      else
        cat /tmp/dirty-release.out
        assert_file_contains /tmp/dirty-release.out "uncommitted changes" \
          "apr release refuses dirty registry"
        if git -C "$REG_DIR" log --oneline -1 | grep -q "registry: update static cache pointer"; then
          fail "dirty release should not commit cache pointer"
        else
          pass "dirty release does not commit cache pointer"
        fi
        if git -C "$REG_DIR" ls-tree -r --name-only HEAD | grep -q "maintainer-notes.txt"; then
          fail "dirty release should not sweep unrelated files into HEAD"
        else
          pass "dirty release does not commit unrelated dirty file"
        fi
        if grep -q "http://127.0.0.1:18083" "$REG_DIR/registry.toml"; then
          fail "dirty release should not mutate registry cache pointer"
        else
          pass "dirty release leaves registry cache pointer unchanged"
        fi
      fi
      rm -f "$REG_DIR/maintainer-notes.txt"

      $APR release 1.0.0 \
        --registry maint-reg \
        --key /tmp/maint-release-key \
        --cache-url http://127.0.0.1:18082 \
        > /tmp/release.out 2>&1 || {
        cat /tmp/release.out
        fail "apr release signs merged release"
      }
      cat /tmp/release.out
      assert_file_contains /tmp/release.out "Created signed tag '1.0.0'" \
        "apr release creates signed semver tag"
      assert_file_contains /tmp/release.out "Released maint-reg 1.0.0" \
        "apr release completes release pipeline"
      if git -C "$REG_DIR" rev-parse "1.0.0^{tag}" >/tmp/release-tag.out 2>&1; then
        pass "apr release creates annotated tag object"
      else
        cat /tmp/release-tag.out
        fail "apr release should create annotated tag object"
      fi
      assert_file_contains "$REG_DIR/.git/releases/1/0/0/objects/info/packs" \
        "pack-" "apr release records full pack artifact"

      git init --bare --object-format=sha256 /tmp/maint-origin.git
      git -C "$REG_DIR" remote add origin /tmp/maint-origin.git
      $APR push --registry maint-reg --branch "$DEFAULT_BRANCH" \
        > /tmp/maint-push.out 2>&1 || {
        cat /tmp/maint-push.out
        fail "apr push publishes default branch"
      }
      cat /tmp/maint-push.out
      assert_file_contains /tmp/maint-push.out "Pushed." \
        "apr push reports successful branch push"
      $APR diff --registry maint-reg --remote --stat \
        > /tmp/maint-remote-diff.out 2>&1 || {
        cat /tmp/maint-remote-diff.out
        fail "apr diff --remote compares against pushed branch"
      }
      cat /tmp/maint-remote-diff.out
      assert_file_contains /tmp/maint-remote-diff.out "No pending changes" \
        "apr diff --remote is clean after pushing branch"
      git -C "$REG_DIR" push origin 1.0.0

      assert_file_exists "/tmp/maint-cache/$GIT_HASH.narinfo" \
        "static cache contains git narinfo"
      assert_file_exists "/tmp/maint-cache/$CURL_HASH.narinfo" \
        "static cache contains curl narinfo"
      assert_file_exists "/tmp/maint-cache/$RUNNER_HASH.narinfo" \
        "static cache contains runner narinfo"
      assert_dir_exists /tmp/maint-cache/nar \
        "static cache contains NAR directory"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      PYTHONUNBUFFERED=1 python3 -m http.server 18082 --bind 127.0.0.1 \
        --directory /tmp/maint-cache > /tmp/maint-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18082/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if ! curl -sf http://127.0.0.1:18082/nix-cache-info >/dev/null; then
        cat /tmp/maint-cache-http.log || true
        fail "static cache HTTP server started"
      else
        pass "static cache HTTP server started"
      fi
      curl -sf "http://127.0.0.1:18082/$RUNNER_HASH.narinfo" > /tmp/runner.narinfo
      assert_file_contains /tmp/runner.narinfo "URL: nar/" \
        "consumer can fetch runner narinfo over HTTP"

      $APR validate --registry maint-reg --jobs 4 \
        > /tmp/maint-validate.out 2>&1 || {
        cat /tmp/maint-validate.out
        fail "apr validate confirms generated cache contents"
      }
      cat /tmp/maint-validate.out
      assert_file_contains /tmp/maint-validate.out "All 3 entries found in caches" \
        "apr validate checks every published cache entry"
      $APR validate --registry maint-reg \
        --package maint-runner \
        --platform x86_64-linux \
        --jobs 2 > /tmp/maint-validate-runner.out 2>&1 || {
        cat /tmp/maint-validate-runner.out
        fail "apr validate filtered to one package succeeds"
      }
      assert_file_contains /tmp/maint-validate-runner.out "All 1 entries found in caches" \
        "apr validate honors package and platform filters"
      if $APR validate --registry maint-reg --jobs 0 \
        > /tmp/maint-validate-jobs-zero.out 2>&1; then
        cat /tmp/maint-validate-jobs-zero.out
        fail "apr validate should reject zero parallelism"
      else
        assert_file_contains /tmp/maint-validate-jobs-zero.out \
          "jobs must be greater than zero" \
          "apr validate rejects zero parallelism"
      fi

      rm -f "/tmp/maint-cache/$CURL_HASH.narinfo"
      if $APR validate --registry maint-reg --package maint-curl --jobs 1 \
        > /tmp/maint-validate-missing-curl.out 2>&1; then
        cat /tmp/maint-validate-missing-curl.out
        fail "apr validate should fail when a cache entry is missing"
      else
        cat /tmp/maint-validate-missing-curl.out
        assert_file_contains /tmp/maint-validate-missing-curl.out \
          "not found in any cache" \
          "apr validate reports the missing cache entry before fix"
      fi
      $APR validate --registry maint-reg --package maint-curl --jobs 1 --fix \
        > /tmp/maint-validate-fix-curl.out 2>&1 || {
        cat /tmp/maint-validate-fix-curl.out
        fail "apr validate --fix prunes missing cache entry metadata"
      }
      cat /tmp/maint-validate-fix-curl.out
      assert_file_contains /tmp/maint-validate-fix-curl.out \
        "Removed 1 missing cache entry" \
        "apr validate --fix reports pruned missing entry"
      assert_file_not_exists "$REG_DIR/packages/m/maint-curl.toml" \
        "apr validate --fix removes package with no cached versions"
      $APR packages --registry maint-reg \
        > /tmp/maint-packages-after-validate-fix.out 2>&1 || {
        cat /tmp/maint-packages-after-validate-fix.out
        fail "apr packages succeeds after validate --fix"
      }
      assert_file_not_contains /tmp/maint-packages-after-validate-fix.out \
        "maint-curl" \
        "apr packages hides cache-pruned package"
      assert_file_contains /tmp/maint-packages-after-validate-fix.out \
        "maint-runner" \
        "apr packages keeps cache-backed package after validate --fix"
      git -C "$REG_DIR" status --short > /tmp/maint-validate-fix-status.out
      assert_file_contains /tmp/maint-validate-fix-status.out \
        "packages/m/maint-curl.toml" \
        "apr validate --fix leaves a maintainer changeset"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "drop maint-curl missing from cache" \
        > /tmp/maint-validate-fix-commit.out 2>&1 || {
        cat /tmp/maint-validate-fix-commit.out
        fail "maintainer commits validate --fix changeset"
      }
      cat /tmp/maint-validate-fix-commit.out
      $APR verify --registry maint-reg \
        > /tmp/maint-verify-after-validate-fix.out 2>&1 || {
        cat /tmp/maint-verify-after-validate-fix.out
        fail "apr verify accepts registry after validate --fix"
      }
      assert_file_contains /tmp/maint-verify-after-validate-fix.out \
        "no errors" \
        "apr verify validates registry after validate --fix"

      # Consumer uses a fresh HOME and the published git origin.
      export HOME=/tmp/consumer
      export USER=maintconsumer
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/maint-origin.git --name maint-reg --tag 1.0.0
      $APM search maint-runner --registry maint-reg > /tmp/consumer-search.out 2>&1
      assert_file_contains /tmp/consumer-search.out "maint-runner" \
        "consumer registry exposes runner package"
      assert_file_contains "$HOME/.local/share/apm/registries/maint-reg/registry.toml" \
        "http://127.0.0.1:18082" "consumer synced cache endpoint"

      # Force a real download by removing the target package from the VM store.
      mount -o remount,rw / || true
      nix-store --delete --ignore-liveness "$RUNNER_STORE" > /tmp/delete-runner.out 2>&1 || {
        cat /tmp/delete-runner.out
        fail "deleted runner store path before install"
      }
      if nix-store --check-validity "$RUNNER_STORE" >/tmp/runner-valid.out 2>&1; then
        cat /tmp/runner-valid.out
        fail "runner store path should be missing before install"
      else
        pass "runner store path missing before install"
      fi

      $APM install maint-runner --registry maint-reg --yes > /tmp/install-runner.out 2>&1 || {
        cat /tmp/install-runner.out
        fail "apm install downloads and imports runner"
      }
      cat /tmp/install-runner.out
      assert_file_contains /tmp/install-runner.out "Downloading" \
        "apm install performed a download"
      assert_file_contains /tmp/install-runner.out "Installed 1 package" \
        "apm install completed profile update"
      if find "$HOME/.cache/apm" -name '*.nar.zst' | grep -q .; then
        pass "downloaded NAR retained in user cache"
      else
        fail "downloaded NAR retained in user cache"
      fi
      nix-store --check-validity "$RUNNER_STORE" >/tmp/runner-valid-after.out 2>&1

      PROFILE_RUNNER="/var/lib/profiles/per-user/$USER/current/bin/maint-runner"
      if [ -x "$PROFILE_RUNNER" ]; then
        pass "installed profile exposes runner executable"
      else
        fail "installed profile exposes runner executable"
      fi
      "$PROFILE_RUNNER" > /tmp/profile-runner.out
      assert_file_contains /tmp/profile-runner.out "maint-runner 1.0.0 executed" \
        "installed runner executes from profile"
      $APM files maint-runner > /tmp/maint-runner-files.out 2>&1 || {
        cat /tmp/maint-runner-files.out
        fail "apm files lists installed maintainer package"
      }
      cat /tmp/maint-runner-files.out
      assert_file_contains /tmp/maint-runner-files.out "bin/maint-runner" \
        "apm files lists installed executable"
      assert_file_contains /tmp/maint-runner-files.out "bin/maint-runner-link" \
        "apm files lists file symlink without resolving it"
      assert_file_contains /tmp/maint-runner-files.out "share/maint-runner/payload.bin" \
        "apm files lists large payload"
      assert_file_contains /tmp/maint-runner-files.out "share/maint-runner/current" \
        "apm files lists directory symlink without recursing"
      assert_file_not_contains /tmp/maint-runner-files.out "current/current" \
        "apm files does not recurse through directory symlink loop"
      $APM list > /tmp/apm-list.out 2>&1
      assert_file_contains /tmp/apm-list.out "maint-runner" \
        "apm list shows installed maintainer package"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-release-static-origin-closure — Release-uploaded origin + closure
  # -------------------------------------------------------------------------
  registry-release-static-origin-closure = testing.mkVMTest {
    name = "apm-registry-release-static-origin-closure";
    rootfsDeps = maintainerWorkflowDeps ++ [closureLeafTool closureRootTool];
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: release upload serves a complete closure to a fresh consumer"

      LEAF_STORE="${closureLeafTool}"
      ROOT_STORE="${closureRootTool}"
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)
      ROOT_HASH=$(basename "$ROOT_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/staticreleaseuser"

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/static-release-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/static-release-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/static-release-missing-$label.out" 2>&1; then
          cat "/tmp/static-release-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/static-release-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/static-release-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      cache_nar_http_get_count() {
        grep -E 'GET /nar/.*\.nar\.zst HTTP/' /tmp/static-release-http.log 2>/dev/null | wc -l | tr -d ' '
      }

      generation_count() {
        if [ -d "$PROFILE" ]; then
          find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
        else
          printf '0'
        fi
      }

      wait_for_static_origin() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18120/HEAD >/dev/null \
            && curl -sf http://127.0.0.1:18120/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$LEAF_STORE" "closure-leaf"
      assert_store_valid "$ROOT_STORE" "closure-root"
      nix-store -q --references "$ROOT_STORE" > /tmp/static-release-root-refs.out
      assert_file_contains /tmp/static-release-root-refs.out "$LEAF_STORE" \
        "release root has a real Nix reference to closure-leaf"

      $APR create static-release-reg
      REG_DIR="$REG_STORAGE/static-release-reg"
      ssh-keygen -q -t ed25519 -N "" -f /tmp/static-release-key

      $APR release 1.0.0 \
        --registry static-release-reg \
        --store-path "$ROOT_STORE" \
        --name static-closure \
        --description "Static release closure fixture" \
        --license MIT \
        --maintainer static-release@example.invalid \
        --key /tmp/static-release-key \
        --cache-output /tmp/static-release-cache \
        --cache-url http://127.0.0.1:18120 \
        --upload-url file:///tmp/static-release-origin \
        > /tmp/static-release.out 2>&1 || {
        cat /tmp/static-release.out
        fail "apr release uploads static origin and cache"
      }
      cat /tmp/static-release.out
      assert_file_contains /tmp/static-release.out "Created signed tag '1.0.0'" \
        "apr release creates signed tag for uploaded origin"
      assert_file_contains /tmp/static-release.out "Generated static cache" \
        "apr release generates a static cache"
      assert_file_contains /tmp/static-release.out "Uploaded" \
        "apr release uploads static origin files"
      assert_file_contains /tmp/static-release.out "Released static-release-reg 1.0.0" \
        "apr release completes uploaded static origin workflow"

      assert_file_exists "/tmp/static-release-cache/$ROOT_HASH.narinfo" \
        "release cache has root narinfo"
      assert_file_exists "/tmp/static-release-cache/$LEAF_HASH.narinfo" \
        "release cache has unpublished dependency narinfo"
      assert_file_exists "/tmp/static-release-origin/HEAD" \
        "uploaded static origin has HEAD"
      assert_file_exists "/tmp/static-release-origin/info/refs" \
        "uploaded static origin has dumb HTTP refs"
      assert_file_exists "/tmp/static-release-origin/releases/1/0/0/objects/info/packs" \
        "uploaded static origin has release pack metadata"
      assert_file_exists "/tmp/static-release-origin/nix-cache-info" \
        "uploaded static origin includes cache info"
      assert_file_exists "/tmp/static-release-origin/$ROOT_HASH.narinfo" \
        "uploaded static origin has root narinfo"
      assert_file_exists "/tmp/static-release-origin/$LEAF_HASH.narinfo" \
        "uploaded static origin has dependency narinfo"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18120 --bind 127.0.0.1 \
        --directory /tmp/static-release-origin > /tmp/static-release-http.log 2>&1 &
      ORIGIN_PID=$!
      if wait_for_static_origin; then
        pass "uploaded static origin HTTP server started"
      else
        cat /tmp/static-release-http.log || true
        fail "uploaded static origin HTTP server started"
      fi

      export HOME=/tmp/static-release-consumer
      export USER=staticreleaseuser
      mkdir -p "$HOME"
      $APM registry add http://127.0.0.1:18120 \
        --name static-release-reg \
        --tag 1.0.0 > /tmp/static-release-add.out 2>&1 || {
        cat /tmp/static-release-add.out
        fail "apm registry add syncs uploaded static origin"
      }
      cat /tmp/static-release-add.out
      assert_file_contains "$HOME/.local/share/apm/registries/static-release-reg/registry.toml" \
        "http://127.0.0.1:18120" \
        "consumer synced cache endpoint from uploaded origin"
      $APM search static-closure --registry static-release-reg \
        > /tmp/static-release-search.out 2>&1 || {
        cat /tmp/static-release-search.out
        fail "apm search sees uploaded release package"
      }
      assert_file_contains /tmp/static-release-search.out "static-closure" \
        "consumer sees package from uploaded static origin"

      delete_store_path "$ROOT_STORE" "closure-root"
      delete_store_path "$LEAF_STORE" "closure-leaf"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      echo "==> Consumer: no-deps refuses an unpublished missing closure reference"
      if $APM install static-closure \
        --registry static-release-reg \
        --no-deps \
        --yes > /tmp/static-release-no-deps-missing.out 2>&1; then
        cat /tmp/static-release-no-deps-missing.out
        fail "apm install --no-deps should fail when anonymous closure dependency is absent"
      else
        cat /tmp/static-release-no-deps-missing.out
        pass "apm install --no-deps fails before downloading anonymous closure dependency"
      fi
      assert_file_contains /tmp/static-release-no-deps-missing.out \
        "no-deps requested but dependency store path" \
        "failed no-deps install reports missing anonymous dependency"
      assert_file_not_contains /tmp/static-release-no-deps-missing.out "Downloading" \
        "failed no-deps install does not download NAR bodies"
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "failed no-deps install leaves NAR cache empty"
      else
        fail "failed no-deps install should not cache release NARs"
      fi
      assert_store_missing "$ROOT_STORE" "closure-root"
      assert_store_missing "$LEAF_STORE" "closure-leaf"
      if [ "$(generation_count)" = "0" ] && [ ! -e "$PROFILE/current" ]; then
        pass "failed no-deps install creates no profile generation"
      else
        fail "failed no-deps install should not create a profile generation"
      fi

      echo "==> Consumer: download-only fetches anonymous closure without importing"
      NAR_GETS_BEFORE_DOWNLOAD_ONLY=$(cache_nar_http_get_count)
      $APM install static-closure \
        --registry static-release-reg \
        --download-only \
        --yes > /tmp/static-release-download-only.out 2>&1 || {
        cat /tmp/static-release-download-only.out
        fail "apm install --download-only downloads anonymous release closure"
      }
      cat /tmp/static-release-download-only.out
      assert_file_contains /tmp/static-release-download-only.out "Downloading 2 NAR" \
        "download-only downloads root and anonymous dependency NARs"
      assert_file_contains /tmp/static-release-download-only.out "no profile changes made" \
        "download-only reports no profile mutation"
      assert_file_not_contains /tmp/static-release-download-only.out "Importing packages" \
        "download-only does not import release closure"
      assert_file_not_contains /tmp/static-release-download-only.out "Updating profile" \
        "download-only does not update profile"
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "download-only leaves root and dependency NARs in user cache"
      else
        fail "download-only should cache exactly two release NARs"
      fi
      EXPECTED_NAR_GETS_AFTER_DOWNLOAD_ONLY=$((NAR_GETS_BEFORE_DOWNLOAD_ONLY + 2))
      if [ "$(cache_nar_http_get_count)" = "$EXPECTED_NAR_GETS_AFTER_DOWNLOAD_ONLY" ]; then
        pass "download-only fetches exactly two release NAR bodies"
      else
        cat /tmp/static-release-http.log || true
        fail "download-only should fetch exactly two release NAR bodies"
      fi
      assert_store_missing "$ROOT_STORE" "closure-root"
      assert_store_missing "$LEAF_STORE" "closure-leaf"
      if [ "$(generation_count)" = "0" ] && [ ! -e "$PROFILE/current" ]; then
        pass "download-only creates no profile generation"
      else
        fail "download-only should not create a profile generation"
      fi

      echo "==> Consumer: normal install reuses cached anonymous closure and activates"
      NAR_GETS_BEFORE_INSTALL=$(cache_nar_http_get_count)
      $APM install static-closure --registry static-release-reg --yes \
        > /tmp/static-release-install.out 2>&1 || {
        cat /tmp/static-release-install.out
        fail "apm install downloads anonymous closure from uploaded origin"
      }
      cat /tmp/static-release-install.out
      assert_file_contains /tmp/static-release-install.out "Downloading" \
        "apm install downloads release closure NARs"
      assert_file_contains /tmp/static-release-install.out "Installed 1 package" \
        "apm install activates static release package"
      if [ "$(cache_nar_http_get_count)" = "$NAR_GETS_BEFORE_INSTALL" ]; then
        pass "normal install reuses cached anonymous closure NAR bodies"
      else
        cat /tmp/static-release-http.log || true
        fail "normal install should not refetch cached anonymous closure NAR bodies"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "download cache contains the root and dependency NARs"
      else
        fail "download cache should contain exactly two NARs"
      fi
      assert_store_valid "$ROOT_STORE" "closure-root"
      assert_store_valid "$LEAF_STORE" "closure-leaf"

      "$PROFILE/current/bin/closure-root" > /tmp/static-release-run.out
      assert_file_contains /tmp/static-release-run.out \
        "^closure-root 1.0.0 via closure-leaf 1.0.0$" \
        "installed release closure executes with its dependency"

      kill "$ORIGIN_PID" 2>/dev/null || true
      wait "$ORIGIN_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-channel-workflow — Signed channel rollout and consumer upgrade
  # -------------------------------------------------------------------------
  registry-channel-workflow = testing.mkVMTest {
    name = "apm-registry-channel-workflow";
    rootfsDeps = maintainerWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: signed channel rollout, sync, install, and upgrade"

      make_channel_tool() {
        version="$1"
        src="/tmp/channel-tool-$version-src"
        rm -rf "$src"
        mkdir -p "$src/bin" "$src/share/channel-tool"
        cat > "$src/bin/channel-tool" << EOF
      #!/bin/sh
      echo "channel-tool $version executed"
      EOF
        chmod +x "$src/bin/channel-tool"
        printf "payload for channel-tool %s\n" "$version" \
          > "$src/share/channel-tool/payload.txt"
        nix-store --add "$src"
      }

      TOOL_V1_STORE=$(make_channel_tool 1.0.0)
      TOOL_V2_STORE=$(make_channel_tool 2.0.0)
      TOOL_V3_STORE=$(make_channel_tool 3.0.0)
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)
      TOOL_V3_HASH=$(basename "$TOOL_V3_STORE" | cut -d- -f1)

      ssh-keygen -q -t ed25519 -N "" -f /tmp/channel-release-key
      CHANNEL_PUBLIC=$(cut -d ' ' -f2 < /tmp/channel-release-key.pub)
      CHANNEL_TRUST_KEY="chan-reg:Ed25519:$CHANNEL_PUBLIC"

      $APR create chan-reg --trust-key "$CHANNEL_TRUST_KEY" \
        --key /tmp/channel-release-key
      REG_DIR="$REG_STORAGE/chan-reg"
      assert_file_contains "$REG_DIR/keys.toml" "chan-reg:Ed25519" \
        "registry records initial channel trust key"
      {
        printf '[registry]\n'
        printf 'name = "chan-reg"\n'
        printf 'url = "file://%s"\n\n' "$REG_DIR"
        printf '[registry.signing_keys]\n'
        printf 'initial = "/tmp/channel-release-key"\n'
      } > "$APM_CONFIG/registries.d/chan-reg.toml"

      echo "local maintainer note" > "$REG_DIR/maintainer-notes.txt"
      if $APR release 1.0.0 \
        --registry chan-reg \
        --store-path "$TOOL_V1_STORE" \
        --name channel-tool \
        --description "Channel workflow tool" \
        --license MIT \
        --maintainer channel@example.invalid \
        --key /tmp/channel-release-key \
        --cache-output /tmp/channel-cache \
        --cache-url http://127.0.0.1:18091 \
        --channel stable \
        --init-channel \
        > /tmp/channel-release-dirty.out 2>&1; then
        cat /tmp/channel-release-dirty.out
        fail "apr release --store-path should refuse a dirty registry before publishing"
      else
        cat /tmp/channel-release-dirty.out
        assert_file_contains /tmp/channel-release-dirty.out \
          "uncommitted changes" \
          "apr release --store-path reports dirty registry preflight"
      fi
      assert_file_not_exists "$REG_DIR/packages/c/channel-tool.toml" \
        "dirty release does not write package metadata"
      if git -C "$REG_DIR" rev-parse "1.0.0^{tag}" >/tmp/channel-release-dirty-tag.out 2>&1; then
        cat /tmp/channel-release-dirty-tag.out
        fail "dirty release should not create a release tag"
      else
        pass "dirty release does not create a release tag"
      fi
      if git -C "$REG_DIR" ls-tree -r --name-only HEAD | grep -q "maintainer-notes.txt"; then
        fail "dirty release should not commit unrelated maintainer scratch files"
      else
        pass "dirty release leaves unrelated maintainer scratch files out of HEAD"
      fi
      rm -f "$REG_DIR/maintainer-notes.txt"

      $APR release 1.0.0 \
        --registry chan-reg \
        --store-path "$TOOL_V1_STORE" \
        --name channel-tool \
        --description "Channel workflow tool" \
        --license MIT \
        --maintainer channel@example.invalid \
        --key /tmp/channel-release-key \
        --cache-output /tmp/channel-cache \
        --cache-url http://127.0.0.1:18091 \
        --channel stable \
        --init-channel \
        > /tmp/channel-release-v1.out 2>&1 || {
        cat /tmp/channel-release-v1.out
        fail "apr release initializes signed channel"
      }
      cat /tmp/channel-release-v1.out
      assert_file_contains /tmp/channel-release-v1.out \
        "Initialized channel 'stable' with 256/256 partitions on 1.0.0" \
        "apr release initializes every channel partition"
      assert_file_exists "$REG_DIR/.git/channels/stable/00" \
        "channel partition object is written to static origin"
      assert_file_contains "$REG_DIR/.git/channels/stable/00" \
        "BEGIN SSH SIGNATURE" "channel partition object is signed"

      assert_file_exists "/tmp/channel-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has channel-tool v1 narinfo"

      $APR channel init canary 1.0.0 \
        --registry chan-reg \
        --key-id initial \
        > /tmp/channel-init-canary.out 2>&1 || {
        cat /tmp/channel-init-canary.out
        fail "apr channel init initializes canary channel with key id"
      }
      cat /tmp/channel-init-canary.out
      assert_file_contains /tmp/channel-init-canary.out \
        "Initialized channel 'canary' with 256/256 partitions on 1.0.0" \
        "apr channel init reports direct channel initialization"
      assert_file_exists "$REG_DIR/.git/channels/canary/00" \
        "direct channel init writes static partition object"
      assert_file_contains "$REG_DIR/.git/channels/canary/00" \
        "BEGIN SSH SIGNATURE" "direct channel init signs partition object"
      $APR channel status canary --registry chan-reg > /tmp/channel-status-canary.out 2>&1
      assert_file_contains /tmp/channel-status-canary.out "1.0.0" \
        "direct channel init status reports release frontier"
      assert_file_contains /tmp/channel-status-canary.out "256/256" \
        "direct channel init status reports full partition set"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      PYTHONUNBUFFERED=1 python3 -m http.server 18090 --bind 127.0.0.1 \
        --directory "$REG_DIR/.git" > /tmp/channel-origin-http.log 2>&1 &
      ORIGIN_PID=$!
      PYTHONUNBUFFERED=1 python3 -m http.server 18091 --bind 127.0.0.1 \
        --directory /tmp/channel-cache > /tmp/channel-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18090/info/refs >/dev/null \
          && curl -sf http://127.0.0.1:18091/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if curl -sf http://127.0.0.1:18090/channels/stable/00 >/tmp/channel-00.tag \
        && curl -sf http://127.0.0.1:18091/nix-cache-info >/dev/null; then
        pass "static origin and cache HTTP servers started"
      else
        cat /tmp/channel-origin-http.log || true
        cat /tmp/channel-cache-http.log || true
        fail "static origin and cache HTTP servers started"
      fi
      curl -sf http://127.0.0.1:18090/channels/canary/00 \
        >/tmp/channel-canary-00.tag || {
        cat /tmp/channel-origin-http.log || true
        fail "direct channel init is served by static origin"
      }
      assert_file_contains /tmp/channel-canary-00.tag \
        "BEGIN SSH SIGNATURE" "static origin serves direct channel partition"

      export HOME=/tmp/channel-consumer
      export USER=channeluser
      mkdir -p "$HOME"

      $APM registry add http://127.0.0.1:18090 \
        --name chan-reg \
        --channel stable \
        --trust-key "$CHANNEL_TRUST_KEY" \
        > /tmp/channel-add.out 2>&1 || {
        cat /tmp/channel-add.out
        fail "apm registry add syncs signed channel"
      }
      cat /tmp/channel-add.out
      CONSUMER_CONFIG="$HOME/.config/apm/registries.d/chan-reg.toml"
      assert_file_contains "$CONSUMER_CONFIG" 'channel = "stable"' \
        "consumer config records channel tracking"
      assert_file_contains "$CONSUMER_CONFIG" 'public_key = "chan-reg:Ed25519:' \
        "consumer config records trusted signing key"
      assert_file_contains "$CONSUMER_CONFIG" 'floor = "1.0.0"' \
        "initial channel sync records semver floor"
      assert_file_contains "$CONSUMER_CONFIG" "bucket = " \
        "initial channel sync records rollout bucket"
      BUCKET=$(grep '^bucket = ' "$CONSUMER_CONFIG" | cut -d= -f2 | tr -d ' ')
      if [ -n "$BUCKET" ]; then
        pass "consumer rollout bucket is readable"
      else
        fail "consumer rollout bucket is readable"
      fi

      $APM search channel-tool --registry chan-reg > /tmp/channel-search-v1.out 2>&1
      assert_file_contains /tmp/channel-search-v1.out "1.0.0" \
        "consumer sees channel v1 package"
      assert_file_contains "$HOME/.local/share/apm/registries/chan-reg/registry.toml" \
        "http://127.0.0.1:18091" "consumer syncs channel cache endpoint"

      mount -o remount,rw / || true
      nix-store --delete --ignore-liveness "$TOOL_V1_STORE" \
        > /tmp/channel-delete-v1.out 2>&1 || {
        cat /tmp/channel-delete-v1.out
        fail "deleted v1 store path before channel install"
      }

      $APM install channel-tool --registry chan-reg --yes \
        > /tmp/channel-install-v1.out 2>&1 || {
        cat /tmp/channel-install-v1.out
        fail "apm install downloads channel v1"
      }
      cat /tmp/channel-install-v1.out
      assert_file_contains /tmp/channel-install-v1.out "Downloading" \
        "apm install downloads v1 NAR"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/channel-tool"
      "$PROFILE_TOOL" > /tmp/channel-tool-v1.out
      assert_file_contains /tmp/channel-tool-v1.out \
        "channel-tool 1.0.0 executed" "installed v1 channel tool executes"

      export HOME=/tmp
      export USER=root
      $APR release 2.0.0 \
        --registry chan-reg \
        --store-path "$TOOL_V2_STORE" \
        --name channel-tool \
        --description "Channel workflow tool" \
        --license MIT \
        --maintainer channel@example.invalid \
        --previous 1.0.0 \
        --key /tmp/channel-release-key \
        --cache-output /tmp/channel-cache \
        --cache-url http://127.0.0.1:18091 \
        --channel stable \
        --partitions "$BUCKET" \
        > /tmp/channel-release-v2.out 2>&1 || {
        cat /tmp/channel-release-v2.out
        fail "apr release advances consumer channel partition"
      }
      cat /tmp/channel-release-v2.out
      assert_file_contains /tmp/channel-release-v2.out \
        "Advanced channel 'stable' 1 partition(s) to 2.0.0" \
        "apr release advances selected channel partition"
      assert_file_exists "/tmp/channel-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has channel-tool v2 narinfo"
      $APR channel status stable --registry chan-reg > /tmp/channel-status-v2.out 2>&1
      assert_file_contains /tmp/channel-status-v2.out "2.0.0" \
        "channel status reports v2 frontier"
      assert_file_contains /tmp/channel-status-v2.out "1/256" \
        "channel status reports one v2 partition"

      export HOME=/tmp/channel-consumer
      export USER=channeluser
      nix-store --delete --ignore-liveness "$TOOL_V2_STORE" \
        > /tmp/channel-delete-v2.out 2>&1 || {
        cat /tmp/channel-delete-v2.out
        fail "deleted v2 store path before channel upgrade"
      }
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry chan-reg > /tmp/channel-update-v2.out 2>&1 || {
        cat /tmp/channel-update-v2.out
        fail "apm update follows advanced channel partition"
      }
      cat /tmp/channel-update-v2.out
      assert_file_contains "$CONSUMER_CONFIG" 'floor = "2.0.0"' \
        "channel update raises consumer semver floor"
      $APM list --upgradable > /tmp/channel-upgradable.out 2>&1 || {
        cat /tmp/channel-upgradable.out
        fail "apm list --upgradable sees channel upgrade"
      }
      assert_file_contains /tmp/channel-upgradable.out "channel-tool" \
        "channel upgrade candidate names package"
      assert_file_contains /tmp/channel-upgradable.out "2.0.0" \
        "channel upgrade candidate shows v2"

      $APM upgrade channel-tool --yes > /tmp/channel-upgrade.out 2>&1 || {
        cat /tmp/channel-upgrade.out
        fail "apm upgrade downloads and activates channel v2"
      }
      cat /tmp/channel-upgrade.out
      assert_file_contains /tmp/channel-upgrade.out "Downloading" \
        "apm upgrade downloads v2 NAR"
      assert_file_contains /tmp/channel-upgrade.out "Upgraded 1 package" \
        "apm upgrade activates channel v2"
      "$PROFILE_TOOL" > /tmp/channel-tool-v2.out
      assert_file_contains /tmp/channel-tool-v2.out \
        "channel-tool 2.0.0 executed" "upgraded v2 channel tool executes"

      export HOME=/tmp
      export USER=root
      $APR release 3.0.0 \
        --registry chan-reg \
        --store-path "$TOOL_V3_STORE" \
        --name channel-tool \
        --description "Channel workflow tool" \
        --license MIT \
        --maintainer channel@example.invalid \
        --previous 2.0.0 \
        --key /tmp/channel-release-key \
        --cache-output /tmp/channel-cache \
        --cache-url http://127.0.0.1:18091 \
        > /tmp/channel-release-v3.out 2>&1 || {
        cat /tmp/channel-release-v3.out
        fail "apr release creates v3 before direct channel advance"
      }
      cat /tmp/channel-release-v3.out
      assert_file_contains /tmp/channel-release-v3.out \
        "Created signed tag '3.0.0'" \
        "apr release creates signed v3 tag"
      assert_file_exists "/tmp/channel-cache/$TOOL_V3_HASH.narinfo" \
        "static cache has channel-tool v3 narinfo"

      if $APR channel advance stable 3.0.0 \
        --registry chan-reg \
        --key /tmp/channel-release-key \
        --count 1 \
        --partitions "$BUCKET" \
        > /tmp/channel-advance-conflict.out 2>&1; then
        cat /tmp/channel-advance-conflict.out
        fail "apr channel advance should reject conflicting partition selectors"
      else
        cat /tmp/channel-advance-conflict.out
        pass "apr channel advance rejects conflicting partition selectors"
      fi
      assert_file_contains /tmp/channel-advance-conflict.out \
        "use only one of --count or --partitions" \
        "apr channel advance explains selector conflict"

      $APR channel advance stable 3.0.0 \
        --registry chan-reg \
        --key /tmp/channel-release-key \
        --partitions "$BUCKET" \
        > /tmp/channel-advance-v3.out 2>&1 || {
        cat /tmp/channel-advance-v3.out
        fail "apr channel advance moves selected consumer partition"
      }
      cat /tmp/channel-advance-v3.out
      assert_file_contains /tmp/channel-advance-v3.out \
        "Advanced channel 'stable' 1 partition(s) to 3.0.0" \
        "apr channel advance reports direct partition rollout"
      $APR channel status stable --registry chan-reg > /tmp/channel-status-v3.out 2>&1
      assert_file_contains /tmp/channel-status-v3.out "3.0.0" \
        "channel status reports v3 frontier after direct advance"
      assert_file_contains /tmp/channel-status-v3.out "1/256" \
        "channel status keeps one v3 partition after direct advance"

      export HOME=/tmp/channel-consumer
      export USER=channeluser
      nix-store --delete --ignore-liveness "$TOOL_V3_STORE" \
        > /tmp/channel-delete-v3.out 2>&1 || {
        cat /tmp/channel-delete-v3.out
        fail "deleted v3 store path before direct channel upgrade"
      }
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry chan-reg > /tmp/channel-update-v3.out 2>&1 || {
        cat /tmp/channel-update-v3.out
        fail "apm update follows direct channel advance"
      }
      cat /tmp/channel-update-v3.out
      assert_file_contains "$CONSUMER_CONFIG" 'floor = "3.0.0"' \
        "direct channel advance raises consumer semver floor"
      $APM list --upgradable > /tmp/channel-upgradable-v3.out 2>&1 || {
        cat /tmp/channel-upgradable-v3.out
        fail "apm list --upgradable sees direct channel advance"
      }
      assert_file_contains /tmp/channel-upgradable-v3.out "channel-tool" \
        "direct channel upgrade candidate names package"
      assert_file_contains /tmp/channel-upgradable-v3.out "3.0.0" \
        "direct channel upgrade candidate shows v3"

      $APM upgrade channel-tool --yes > /tmp/channel-upgrade-v3.out 2>&1 || {
        cat /tmp/channel-upgrade-v3.out
        fail "apm upgrade downloads and activates directly advanced v3"
      }
      cat /tmp/channel-upgrade-v3.out
      assert_file_contains /tmp/channel-upgrade-v3.out "Downloading" \
        "apm upgrade downloads directly advanced v3 NAR"
      assert_file_contains /tmp/channel-upgrade-v3.out "Upgraded 1 package" \
        "apm upgrade activates directly advanced v3"
      "$PROFILE_TOOL" > /tmp/channel-tool-v3.out
      assert_file_contains /tmp/channel-tool-v3.out \
        "channel-tool 3.0.0 executed" "upgraded v3 channel tool executes"

      kill "$ORIGIN_PID" "$CACHE_PID" 2>/dev/null || true
      wait "$ORIGIN_PID" "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-branch-workflow — Branch create, switch, merge modes, pull
  # -------------------------------------------------------------------------
  registry-branch-workflow = testing.mkVMTest {
    name = "apm-registry-branch-workflow";
    rootfsDeps = closureWorkflowDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: real APR branch create, switch, publish, merge modes, pull"
      export GIT_MERGE_AUTOEDIT=no

      FEATURE_STORE="${closureRootTool}"
      FEATURE_DEP_STORE="${closureLeafTool}"
      FEATURE_HASH=$(basename "$FEATURE_STORE" | cut -d- -f1)
      FEATURE_DEP_HASH=$(basename "$FEATURE_DEP_STORE" | cut -d- -f1)

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      publish_feature_package() {
        $APR publish "$FEATURE_STORE" \
          --name featurepkg \
          --version 1.0.0 \
          --description "Real branch workflow fixture" \
          --license MIT \
          --maintainer branch@example.invalid \
          --registry test-reg \
          --no-commit > /tmp/branch-publish.out 2>&1 || {
          cat /tmp/branch-publish.out
          fail "apr publish featurepkg on feature branch succeeds"
          return 1
        }
        cat /tmp/branch-publish.out
      }

      commit_branch_changes() {
        message="$1"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "$message" > /tmp/branch-commit.out 2>&1 || {
          cat /tmp/branch-commit.out
          fail "registry commit succeeds: $message"
          return 1
        }
        cat /tmp/branch-commit.out
      }

      mount -o remount,rw / || true
      nix-store -q --references "$FEATURE_STORE" > /tmp/branch-feature-refs.out
      assert_file_contains /tmp/branch-feature-refs.out "$FEATURE_DEP_STORE" \
        "feature package has a real Nix reference to its dependency"

      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

      $APR branch create feature-1 --registry test-reg > /tmp/branch-create.out 2>&1 || {
        cat /tmp/branch-create.out
        fail "apr branch create succeeds"
      }
      cat /tmp/branch-create.out
      assert_file_contains /tmp/branch-create.out "Created branch 'feature-1'" \
        "apr branch create reports feature branch"

      $APR branch switch feature-1 --registry test-reg > /tmp/branch-switch-feature.out 2>&1 || {
        cat /tmp/branch-switch-feature.out
        fail "apr branch switch feature-1 succeeds"
      }
      cat /tmp/branch-switch-feature.out
      assert_file_contains /tmp/branch-switch-feature.out "Switched to branch 'feature-1'" \
        "apr branch switch reports feature branch"

      publish_feature_package
      commit_branch_changes "publish featurepkg 1.0.0 on feature branch"
      assert_file_exists "$REG_DIR/packages/f/featurepkg.toml" \
        "published package exists on feature branch"
      assert_file_contains "$REG_DIR/packages/f/featurepkg.toml" "$FEATURE_HASH" \
        "feature branch package metadata records real store hash"
      assert_file_exists "$REG_DIR/closures/$FEATURE_HASH" \
        "feature branch closure file exists"
      assert_file_contains "$REG_DIR/closures/$FEATURE_HASH" "$FEATURE_DEP_HASH" \
        "feature branch closure records dependency"

      $APR packages --registry test-reg > /tmp/branch-packages-feature.out 2>&1 || {
        cat /tmp/branch-packages-feature.out
        fail "apr packages lists feature branch package"
      }
      assert_file_contains /tmp/branch-packages-feature.out "featurepkg 1.0.0" \
        "apr packages sees feature package on feature branch"
      $APR verify --registry test-reg > /tmp/branch-verify-feature.out 2>&1 || {
        cat /tmp/branch-verify-feature.out
        fail "apr verify accepts feature branch package"
      }
      assert_file_contains /tmp/branch-verify-feature.out "no errors" \
        "apr verify validates feature branch closure metadata"

      $APR branch switch "$DEFAULT_BRANCH" --registry test-reg > /tmp/branch-switch-default.out 2>&1 || {
        cat /tmp/branch-switch-default.out
        fail "apr branch switch default succeeds"
      }
      cat /tmp/branch-switch-default.out
      assert_file_contains /tmp/branch-switch-default.out "Switched to branch '$DEFAULT_BRANCH'" \
        "apr branch switch reports default branch"

      assert_file_not_exists "$REG_DIR/packages/f/featurepkg.toml" \
        "package not on default branch before merge"
      assert_file_not_exists "$REG_DIR/closures/$FEATURE_HASH" \
        "closure not on default branch before merge"
      $APR packages --registry test-reg > /tmp/branch-packages-default.out 2>&1 || {
        cat /tmp/branch-packages-default.out
        fail "apr packages succeeds on default branch before merge"
      }
      assert_file_not_contains /tmp/branch-packages-default.out "featurepkg" \
        "apr packages hides feature package before merge"

      $APR merge feature-1 --registry test-reg > /tmp/branch-merge.out 2>&1 || {
        cat /tmp/branch-merge.out
        fail "apr merge feature branch succeeds"
      }
      cat /tmp/branch-merge.out
      assert_file_contains /tmp/branch-merge.out "Merged 'feature-1'" \
        "apr merge reports merged branch"

      assert_file_exists "$REG_DIR/packages/f/featurepkg.toml" \
        "package exists on default branch after merge"
      assert_file_exists "$REG_DIR/closures/$FEATURE_HASH" \
        "closure exists on default branch after merge"
      $APR show featurepkg --registry test-reg > /tmp/branch-show-merged.out 2>&1 || {
        cat /tmp/branch-show-merged.out
        fail "apr show resolves merged package"
      }
      assert_file_contains /tmp/branch-show-merged.out "Real branch workflow fixture" \
        "apr show displays merged package metadata"
      $APR verify --registry test-reg > /tmp/branch-verify-merged.out 2>&1 || {
        cat /tmp/branch-verify-merged.out
        fail "apr verify accepts merged branch package"
      }
      assert_file_contains /tmp/branch-verify-merged.out "no errors" \
        "apr verify validates merged closure metadata"
      $APR branch list --registry test-reg > /tmp/branch-list.out 2>&1 || {
        cat /tmp/branch-list.out
        fail "apr branch list succeeds"
      }
      assert_file_contains /tmp/branch-list.out "feature-1" \
        "apr branch list shows feature branch"

      $APR branch delete feature-1 --registry test-reg \
        > /tmp/branch-delete.out 2>&1 || {
        cat /tmp/branch-delete.out
        fail "apr branch delete removes merged feature branch"
      }
      cat /tmp/branch-delete.out
      assert_file_contains /tmp/branch-delete.out "Deleted branch 'feature-1'" \
        "apr branch delete reports deleted feature branch"
      $APR branch list --registry test-reg > /tmp/branch-list-after-delete.out 2>&1 || {
        cat /tmp/branch-list-after-delete.out
        fail "apr branch list succeeds after delete"
      }
      assert_file_not_contains /tmp/branch-list-after-delete.out "feature-1" \
        "apr branch list hides deleted feature branch"

      echo "==> Test: APR merge --no-ff keeps an explicit maintainer merge commit"

      $APR branch create noff-branch --registry test-reg \
        > /tmp/branch-noff-create.out 2>&1 || {
        cat /tmp/branch-noff-create.out
        fail "apr branch create succeeds for no-ff branch"
      }
      cat /tmp/branch-noff-create.out
      $APR branch switch noff-branch --registry test-reg \
        > /tmp/branch-noff-switch.out 2>&1 || {
        cat /tmp/branch-noff-switch.out
        fail "apr branch switch succeeds for no-ff branch"
      }
      cat /tmp/branch-noff-switch.out

      $APR publish "$FEATURE_DEP_STORE" \
        --name noffpkg \
        --version 1.0.0 \
        --description "No-ff maintainer merge fixture" \
        --license MIT \
        --maintainer branch@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/branch-noff-publish.out 2>&1 || {
        cat /tmp/branch-noff-publish.out
        fail "apr publish creates package on no-ff branch"
      }
      cat /tmp/branch-noff-publish.out
      commit_branch_changes "publish noffpkg 1.0.0 on no-ff branch"

      $APR branch switch "$DEFAULT_BRANCH" --registry test-reg \
        > /tmp/branch-noff-switch-default.out 2>&1 || {
        cat /tmp/branch-noff-switch-default.out
        fail "apr branch switch returns to default before no-ff merge"
      }
      cat /tmp/branch-noff-switch-default.out

      $APR merge noff-branch --no-ff --registry test-reg \
        > /tmp/branch-noff-merge.out 2>&1 || {
        cat /tmp/branch-noff-merge.out
        fail "apr merge --no-ff succeeds"
      }
      cat /tmp/branch-noff-merge.out
      assert_file_contains /tmp/branch-noff-merge.out "Merged 'noff-branch'" \
        "apr merge --no-ff reports merged branch"
      NOFF_HEAD_PARENTS=$(git -C "$REG_DIR" rev-list --parents -n 1 HEAD | wc -w)
      if [ "$NOFF_HEAD_PARENTS" = "3" ]; then
        pass "apr merge --no-ff creates a two-parent merge commit"
      else
        fail "apr merge --no-ff should leave three rev-list fields, got $NOFF_HEAD_PARENTS"
        git -C "$REG_DIR" log --oneline --graph -5
      fi
      $APR show noffpkg --registry test-reg > /tmp/branch-noff-show.out 2>&1 || {
        cat /tmp/branch-noff-show.out
        fail "apr show resolves no-ff merged package"
      }
      assert_file_contains /tmp/branch-noff-show.out "No-ff maintainer merge fixture" \
        "apr show displays no-ff merged package metadata"
      $APR verify --registry test-reg > /tmp/branch-noff-verify.out 2>&1 || {
        cat /tmp/branch-noff-verify.out
        fail "apr verify accepts no-ff merged package"
      }
      assert_file_contains /tmp/branch-noff-verify.out "no errors" \
        "apr verify validates no-ff merged registry metadata"
      $APR branch delete noff-branch --registry test-reg \
        > /tmp/branch-noff-delete.out 2>&1 || {
        cat /tmp/branch-noff-delete.out
        fail "apr branch delete removes no-ff merged branch"
      }
      cat /tmp/branch-noff-delete.out

      echo "==> Test: APR merge --squash stages a maintainer changeset"

      $APR branch create squash-branch --registry test-reg \
        > /tmp/branch-squash-create.out 2>&1 || {
        cat /tmp/branch-squash-create.out
        fail "apr branch create succeeds for squash branch"
      }
      cat /tmp/branch-squash-create.out
      $APR branch switch squash-branch --registry test-reg \
        > /tmp/branch-squash-switch.out 2>&1 || {
        cat /tmp/branch-squash-switch.out
        fail "apr branch switch succeeds for squash branch"
      }
      cat /tmp/branch-squash-switch.out

      $APR publish "$FEATURE_STORE" \
        --name squashpkg \
        --version 1.0.0 \
        --description "Squash maintainer changeset fixture" \
        --license MIT \
        --maintainer branch@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/branch-squash-publish.out 2>&1 || {
        cat /tmp/branch-squash-publish.out
        fail "apr publish creates package on squash branch"
      }
      cat /tmp/branch-squash-publish.out
      commit_branch_changes "publish squashpkg 1.0.0 on squash branch"
      SQUASH_BRANCH_HEAD=$(git -C "$REG_DIR" rev-parse HEAD)

      $APR branch switch "$DEFAULT_BRANCH" --registry test-reg \
        > /tmp/branch-squash-switch-default.out 2>&1 || {
        cat /tmp/branch-squash-switch-default.out
        fail "apr branch switch returns to default before squash merge"
      }
      cat /tmp/branch-squash-switch-default.out
      DEFAULT_BEFORE_SQUASH=$(git -C "$REG_DIR" rev-parse HEAD)

      $APR merge squash-branch --squash --registry test-reg \
        > /tmp/branch-squash-merge.out 2>&1 || {
        cat /tmp/branch-squash-merge.out
        fail "apr merge --squash stages changes"
      }
      cat /tmp/branch-squash-merge.out
      assert_file_contains /tmp/branch-squash-merge.out "Merged 'squash-branch'" \
        "apr merge --squash reports merged branch"
      CURRENT_AFTER_SQUASH=$(git -C "$REG_DIR" rev-parse HEAD)
      if [ "$CURRENT_AFTER_SQUASH" = "$DEFAULT_BEFORE_SQUASH" ]; then
        pass "apr merge --squash does not advance HEAD before maintainer commit"
      else
        fail "apr merge --squash advanced HEAD before the maintainer commit"
        git -C "$REG_DIR" log --oneline --graph -5
      fi
      $APR status --registry test-reg > /tmp/branch-squash-status.out 2>&1 || {
        cat /tmp/branch-squash-status.out
        fail "apr status succeeds after squash merge"
      }
      assert_file_contains /tmp/branch-squash-status.out "packages/s/squashpkg.toml" \
        "apr status shows staged squash package metadata"
      $APR show squashpkg --registry test-reg > /tmp/branch-squash-show-staged.out 2>&1 || {
        cat /tmp/branch-squash-show-staged.out
        fail "apr show resolves staged squash package"
      }
      assert_file_contains /tmp/branch-squash-show-staged.out \
        "Squash maintainer changeset fixture" \
        "apr show displays staged squash package metadata"
      $APR verify --registry test-reg > /tmp/branch-squash-verify-staged.out 2>&1 || {
        cat /tmp/branch-squash-verify-staged.out
        fail "apr verify accepts staged squash package"
      }
      assert_file_contains /tmp/branch-squash-verify-staged.out "no errors" \
        "apr verify validates staged squash registry metadata"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "squash merge squashpkg 1.0.0" \
        > /tmp/branch-squash-commit.out 2>&1 || {
        cat /tmp/branch-squash-commit.out
        fail "maintainer commits squash merge result"
      }
      cat /tmp/branch-squash-commit.out
      SQUASH_HEAD_PARENTS=$(git -C "$REG_DIR" rev-list --parents -n 1 HEAD | wc -w)
      if [ "$SQUASH_HEAD_PARENTS" = "2" ]; then
        pass "apr merge --squash keeps a linear maintainer commit"
      else
        fail "apr merge --squash should leave two rev-list fields, got $SQUASH_HEAD_PARENTS"
        git -C "$REG_DIR" log --oneline --graph -5
      fi
      if git -C "$REG_DIR" merge-base --is-ancestor "$SQUASH_BRANCH_HEAD" HEAD; then
        fail "squash branch commit should not become an ancestor of default"
        git -C "$REG_DIR" log --oneline --graph -8
      else
        pass "squash branch remains a non-ancestor after squash commit"
      fi
      $APR verify --registry test-reg > /tmp/branch-squash-verify.out 2>&1 || {
        cat /tmp/branch-squash-verify.out
        fail "apr verify accepts committed squash package"
      }
      assert_file_contains /tmp/branch-squash-verify.out "no errors" \
        "apr verify validates committed squash registry metadata"
      if $APR branch delete squash-branch --registry test-reg \
        > /tmp/branch-squash-delete.out 2>&1; then
        cat /tmp/branch-squash-delete.out
        fail "apr branch delete should reject a squash-only branch"
      else
        cat /tmp/branch-squash-delete.out
        pass "apr branch delete preserves unmerged squash branch"
      fi
      git -C "$REG_DIR" branch -D squash-branch \
        > /tmp/branch-squash-force-delete.out 2>&1 || {
        cat /tmp/branch-squash-force-delete.out
        fail "test cleanup force-deletes squash branch"
      }
      cat /tmp/branch-squash-force-delete.out

      echo "==> Test: APR pull and pull --rebase between maintainer clones"

      git init --bare --object-format=sha256 /tmp/branch-origin.git
      git -C "$REG_DIR" remote add origin /tmp/branch-origin.git
      git --git-dir=/tmp/branch-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      $APR push --registry test-reg --branch "$DEFAULT_BRANCH" --set-upstream \
        > /tmp/branch-initial-push.out 2>&1 || {
        cat /tmp/branch-initial-push.out
        fail "apr push publishes merged default branch"
      }
      cat /tmp/branch-initial-push.out
      assert_file_contains /tmp/branch-initial-push.out "Pushed." \
        "apr push reports initial default branch push"

      COLLAB_DIR="$REG_STORAGE/collab-reg"
      git clone /tmp/branch-origin.git "$COLLAB_DIR" \
        > /tmp/branch-collab-clone.out 2>&1 || {
        cat /tmp/branch-collab-clone.out
        fail "second maintainer clone succeeds"
      }
      cat /tmp/branch-collab-clone.out
      $APR show featurepkg --registry collab-reg \
        > /tmp/branch-collab-show-feature.out 2>&1 || {
        cat /tmp/branch-collab-show-feature.out
        fail "second maintainer clone can query merged package"
      }
      assert_file_contains /tmp/branch-collab-show-feature.out \
        "Real branch workflow fixture" \
        "second maintainer clone sees merged package metadata"

      $APR publish "$FEATURE_DEP_STORE" \
        --name collab-local \
        --version 1.0.0 \
        --description "Local collaborator package before rebase" \
        --license MIT \
        --maintainer branch@example.invalid \
        --registry collab-reg \
        --no-commit > /tmp/branch-collab-local-publish.out 2>&1 || {
        cat /tmp/branch-collab-local-publish.out
        fail "second maintainer publishes local package before pull --rebase"
      }
      cat /tmp/branch-collab-local-publish.out
      git -C "$COLLAB_DIR" add -A
      git -C "$COLLAB_DIR" commit -m "publish collaborator local package" \
        > /tmp/branch-collab-local-commit.out 2>&1 || {
        cat /tmp/branch-collab-local-commit.out
        fail "second maintainer commits local package before pull --rebase"
      }
      cat /tmp/branch-collab-local-commit.out

      $APR publish "$FEATURE_STORE" \
        --name remote-added \
        --version 1.0.0 \
        --description "Remote maintainer package for pull workflow" \
        --license MIT \
        --maintainer branch@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/branch-remote-added-publish.out 2>&1 || {
        cat /tmp/branch-remote-added-publish.out
        fail "first maintainer publishes remote package"
      }
      cat /tmp/branch-remote-added-publish.out
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "publish remote added package" \
        > /tmp/branch-remote-added-commit.out 2>&1 || {
        cat /tmp/branch-remote-added-commit.out
        fail "first maintainer commits remote package"
      }
      cat /tmp/branch-remote-added-commit.out
      $APR push --registry test-reg --branch "$DEFAULT_BRANCH" \
        > /tmp/branch-remote-added-push.out 2>&1 || {
        cat /tmp/branch-remote-added-push.out
        fail "first maintainer pushes remote package"
      }
      cat /tmp/branch-remote-added-push.out

      $APR packages --registry collab-reg > /tmp/branch-collab-before-rebase.out 2>&1 || {
        cat /tmp/branch-collab-before-rebase.out
        fail "second maintainer lists packages before pull --rebase"
      }
      assert_file_contains /tmp/branch-collab-before-rebase.out "collab-local" \
        "second maintainer sees local package before pull --rebase"
      assert_file_not_contains /tmp/branch-collab-before-rebase.out "remote-added" \
        "second maintainer does not see remote package before pull --rebase"

      $APR pull --registry collab-reg --rebase > /tmp/branch-collab-rebase.out 2>&1 || {
        cat /tmp/branch-collab-rebase.out
        fail "apr pull --rebase updates second maintainer clone"
      }
      cat /tmp/branch-collab-rebase.out
      $APR packages --registry collab-reg > /tmp/branch-collab-after-rebase.out 2>&1 || {
        cat /tmp/branch-collab-after-rebase.out
        fail "second maintainer lists packages after pull --rebase"
      }
      assert_file_contains /tmp/branch-collab-after-rebase.out "collab-local" \
        "pull --rebase preserves local maintainer package"
      assert_file_contains /tmp/branch-collab-after-rebase.out "remote-added" \
        "pull --rebase imports remote maintainer package"
      $APR verify --registry collab-reg > /tmp/branch-collab-verify.out 2>&1 || {
        cat /tmp/branch-collab-verify.out
        fail "rebased maintainer clone verifies"
      }
      assert_file_contains /tmp/branch-collab-verify.out "no errors" \
        "rebased maintainer clone has valid registry metadata"
      COLLAB_HEAD_PARENTS=$(git -C "$COLLAB_DIR" rev-list --parents -n 1 HEAD | wc -w)
      if [ "$COLLAB_HEAD_PARENTS" = "2" ]; then
        pass "apr pull --rebase keeps a linear local maintainer commit"
      else
        fail "apr pull --rebase should leave a linear head, got $COLLAB_HEAD_PARENTS fields"
        git -C "$COLLAB_DIR" log --oneline --graph -5
      fi

      $APR push --registry collab-reg --branch "$DEFAULT_BRANCH" \
        > /tmp/branch-collab-push.out 2>&1 || {
        cat /tmp/branch-collab-push.out
        fail "second maintainer pushes rebased package"
      }
      cat /tmp/branch-collab-push.out
      $APR pull --registry test-reg > /tmp/branch-primary-pull.out 2>&1 || {
        cat /tmp/branch-primary-pull.out
        fail "first maintainer pulls collaborator package"
      }
      cat /tmp/branch-primary-pull.out
      $APR show collab-local --registry test-reg \
        > /tmp/branch-primary-show-collab.out 2>&1 || {
        cat /tmp/branch-primary-show-collab.out
        fail "first maintainer sees collaborator package after pull"
      }
      assert_file_contains /tmp/branch-primary-show-collab.out \
        "Local collaborator package before rebase" \
        "plain apr pull imports collaborator package metadata"
      $APR verify --registry test-reg > /tmp/branch-primary-verify-pulled.out 2>&1 || {
        cat /tmp/branch-primary-verify-pulled.out
        fail "first maintainer registry verifies after pull"
      }
      assert_file_contains /tmp/branch-primary-verify-pulled.out "no errors" \
        "first maintainer registry remains valid after pull"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-validate — Validate registry TOML structure
  # -------------------------------------------------------------------------
  registry-validate = testing.mkVMTest {
    name = "apm-registry-validate";
    rootfsDeps = closureWorkflowDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: apr verify (TOML schema validation)"

      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"

      $APR publish "${closureLeafTool}" \
        --name validpkg \
        --version 1.0.0 \
        --description "Real verify schema fixture" \
        --license MIT \
        --maintainer verify@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/validate-publish.out 2>&1 || {
        cat /tmp/validate-publish.out
        fail "apr publish creates valid package metadata"
      }
      cat /tmp/validate-publish.out
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "publish validpkg 1.0.0"

      $APR verify --registry test-reg > /tmp/verify-valid.out 2>&1 || {
        cat /tmp/verify-valid.out
        fail "apr verify passes with real valid package"
      }
      cat /tmp/verify-valid.out
      assert_file_contains /tmp/verify-valid.out "no errors" \
        "apr verify reports real valid package has no errors"

      mkdir -p "$REG_DIR/packages/b"
      echo 'invalid = "no package section"' > "$REG_DIR/packages/b/badpkg.toml"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "add invalid package"

      if $APR verify --registry test-reg > /tmp/verify-invalid.out 2>&1; then
        cat /tmp/verify-invalid.out
        fail "apr verify should fail with invalid package TOML"
      else
        cat /tmp/verify-invalid.out
        pass "apr verify fails with invalid package TOML"
      fi
      assert_file_contains /tmp/verify-invalid.out "missing \\[package\\] section" \
        "apr verify reports invalid package TOML"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-bundle — Signed tag, re-sign, and no-bundle clean break
  # -------------------------------------------------------------------------
  registry-bundle = testing.mkVMTest {
    name = "apm-registry-signed-tag-clean-break";
    rootfsDeps = closureWorkflowDeps ++ [pkgs.openssh];
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: real APR signed tag, re-sign, and bundle clean break"

      TAG_STORE="${closureRootTool}"
      TAG_DEP_STORE="${closureLeafTool}"
      TAG_HASH=$(basename "$TAG_STORE" | cut -d- -f1)
      TAG_DEP_HASH=$(basename "$TAG_DEP_STORE" | cut -d- -f1)

      mount -o remount,rw / || true
      nix-store -q --references "$TAG_STORE" > /tmp/tagpkg-refs.out
      assert_file_contains /tmp/tagpkg-refs.out "$TAG_DEP_STORE" \
        "tagged package has a real Nix reference to its dependency"

      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"

      $APR publish "$TAG_STORE" \
        --name tagpkg \
        --version 1.0.0 \
        --description "Real signed tag fixture" \
        --license MIT \
        --maintainer tag@example.invalid \
        --registry test-reg \
        --no-commit > /tmp/tag-publish.out 2>&1 || {
        cat /tmp/tag-publish.out
        fail "apr publish creates real tag package"
      }
      cat /tmp/tag-publish.out
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "publish tagpkg 1.0.0"

      assert_file_contains "$REG_DIR/packages/t/tagpkg.toml" "$TAG_HASH" \
        "package metadata records real tagged store hash"
      assert_file_exists "$REG_DIR/closures/$TAG_HASH" \
        "tagged package closure file exists"
      assert_file_contains "$REG_DIR/closures/$TAG_HASH" "$TAG_DEP_HASH" \
        "tagged package closure records dependency"
      $APR verify --registry test-reg > /tmp/tag-verify-before.out 2>&1 || {
        cat /tmp/tag-verify-before.out
        fail "apr verify accepts real package before tag"
      }
      assert_file_contains /tmp/tag-verify-before.out "no errors" \
        "apr verify validates real package before tag"

      ssh-keygen -q -t ed25519 -N "" -f /tmp/release-key
      $APR tag 1.0.0 --registry test-reg --key /tmp/release-key \
        > /tmp/tag-create.out 2>&1 || {
        cat /tmp/tag-create.out
        fail "apr tag creates signed release tag"
      }
      cat /tmp/tag-create.out
      assert_file_contains /tmp/tag-create.out "Created signed tag '1.0.0'" \
        "apr tag reports signed release tag creation"

      cd "$REG_DIR"
      assert_cmd_success "git rev-parse 1.0.0^{tag}" \
        "signed release tag object exists"
      git cat-file -p 1.0.0 > /tmp/tag-object.out
      assert_file_contains /tmp/tag-object.out \
        "BEGIN SSH SIGNATURE" "release tag object carries SSH signature"
      assert_file_contains /tmp/tag-object.out "tag 1.0.0" \
        "release tag object records release name"
      git show 1.0.0:packages/t/tagpkg.toml > /tmp/tagpkg-at-tag.toml
      git show "1.0.0:closures/$TAG_HASH" > /tmp/tag-closure-at-tag.out
      cd /tmp

      assert_file_contains /tmp/tagpkg-at-tag.toml "$TAG_HASH" \
        "signed tag captures real package metadata"
      assert_file_contains /tmp/tagpkg-at-tag.toml "Real signed tag fixture" \
        "signed tag captures maintainer package description"
      assert_file_contains /tmp/tag-closure-at-tag.out "$TAG_DEP_HASH" \
        "signed tag captures real package closure"

      INITIAL_TAG_OBJECT=$(git -C "$REG_DIR" rev-parse '1.0.0^{tag}')
      INITIAL_TAG_COMMIT=$(git -C "$REG_DIR" rev-parse '1.0.0^{commit}')

      ssh-keygen -q -t ed25519 -N "" -f /tmp/release-key-next
      NEXT_PUBLIC=$(cut -d ' ' -f2 < /tmp/release-key-next.pub)
      NEXT_TRUST_KEY="test-reg:Ed25519:$NEXT_PUBLIC"
      $APR keys add next "$NEXT_TRUST_KEY" --registry test-reg \
        > /tmp/sign-key-add.out 2>&1 || {
        cat /tmp/sign-key-add.out
        fail "apr keys add records replacement signing key"
      }
      cat /tmp/sign-key-add.out
      assert_file_contains "$REG_DIR/keys.toml" 'id = "next"' \
        "keys.toml records replacement signing key id"
      assert_file_contains "$REG_DIR/keys.toml" "$NEXT_TRUST_KEY" \
        "keys.toml records replacement signing key value"

      {
        printf '[registry]\n'
        printf 'name = "test-reg"\n'
        printf 'url = "file://%s"\n\n' "$REG_DIR"
        printf '[registry.signing_keys]\n'
        printf 'next = "/tmp/release-key-next"\n'
      } > "$APM_CONFIG/registries.d/test-reg.toml"

      if $APR sign --registry test-reg --key-id next \
        > /tmp/sign-missing-tag.out 2>&1; then
        cat /tmp/sign-missing-tag.out
        fail "apr sign should require an explicit tag name"
      else
        cat /tmp/sign-missing-tag.out
        pass "apr sign rejects missing tag name"
      fi
      assert_file_contains /tmp/sign-missing-tag.out \
        "pass the existing tag name to re-sign" \
        "apr sign explains required tag argument"

      $APR sign 1.0.0 --registry test-reg --key-id next \
        > /tmp/tag-resign.out 2>&1 || {
        cat /tmp/tag-resign.out
        fail "apr sign re-signs existing tag with configured key id"
      }
      cat /tmp/tag-resign.out
      assert_file_contains /tmp/tag-resign.out "Re-signed tag '1.0.0'" \
        "apr sign reports re-signed tag"
      RESIGNED_TAG_OBJECT=$(git -C "$REG_DIR" rev-parse '1.0.0^{tag}')
      RESIGNED_TAG_COMMIT=$(git -C "$REG_DIR" rev-parse '1.0.0^{commit}')
      if [ "$RESIGNED_TAG_COMMIT" = "$INITIAL_TAG_COMMIT" ]; then
        pass "apr sign keeps the release tag target commit"
      else
        fail "apr sign should keep commit $INITIAL_TAG_COMMIT, got $RESIGNED_TAG_COMMIT"
      fi
      if [ "$RESIGNED_TAG_OBJECT" != "$INITIAL_TAG_OBJECT" ]; then
        pass "apr sign replaces the annotated tag object"
      else
        fail "apr sign should replace annotated tag object"
      fi
      git -C "$REG_DIR" cat-file -p 1.0.0 > /tmp/tag-object-resigned.out
      assert_file_contains /tmp/tag-object-resigned.out \
        "BEGIN SSH SIGNATURE" "re-signed tag object carries SSH signature"
      assert_file_contains /tmp/tag-object-resigned.out "$INITIAL_TAG_COMMIT" \
        "re-signed tag object targets original release commit"

      assert_file_not_exists "$REG_DIR/bundle-list.toml" \
        "git-native registry does not emit bundle-list.toml"

      if $APR bundle --tag 1.0.0 --output /tmp/bundles --registry test-reg \
        > /tmp/bundle-out 2>&1; then
        fail "apr bundle should not exist after git-native cutover"
      elif grep -q "unrecognized subcommand" /tmp/bundle-out; then
        pass "apr bundle is removed with a clean CLI error"
      else
        fail "apr bundle failed with unexpected output"
        cat /tmp/bundle-out
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-signed-commit-trust — Trusted commit signatures for git sync
  # -------------------------------------------------------------------------
  registry-signed-commit-trust = testing.mkVMTest {
    name = "apm-registry-signed-commit-trust";
    rootfsDeps = maintainerWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: trusted signed commits for registry sync"

      export GIT_CONFIG_NOSYSTEM=1
      export GIT_CONFIG_GLOBAL=/tmp/empty-gitconfig
      : > "$GIT_CONFIG_GLOBAL"

      make_signed_tool() {
        version="$1"
        src="/tmp/signed-tool-$version-src"
        rm -rf "$src"
        mkdir -p "$src/bin" "$src/share/signed-tool"
        cat > "$src/bin/signed-tool" << EOF
      #!/bin/sh
      echo "signed-tool $version executed"
      EOF
        chmod +x "$src/bin/signed-tool"
        printf "signed-tool payload %s\n" "$version" \
          > "$src/share/signed-tool/payload.txt"
        nix-store --add "$src"
      }

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/signed-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/signed-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/signed-missing-$label.out" 2>&1; then
          cat "/tmp/signed-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/signed-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/signed-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18106/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      commit_signed() {
        key="$1"
        label="$2"
        message="$3"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" \
          -c gpg.format=ssh \
          -c "user.signingkey=$key" \
          commit -S -m "$message" > "/tmp/signed-commit-$label.out" 2>&1 || {
          cat "/tmp/signed-commit-$label.out"
          fail "signed commit succeeds: $message"
          return 1
        }
        cat "/tmp/signed-commit-$label.out"
        git -C "$REG_DIR" cat-file -p HEAD > "/tmp/signed-commit-$label.object"
        assert_file_contains "/tmp/signed-commit-$label.object" \
          "BEGIN SSH SIGNATURE" "registry commit $label carries SSH signature"
      }

      publish_signed_tool() {
        version="$1"
        store="$2"
        label="$3"
        $APR publish "$store" \
          --name signed-tool \
          --version "$version" \
          --description "Signed commit trust workflow tool" \
          --license MIT \
          --maintainer signed-commit@example.invalid \
          --registry signed-reg \
          --no-commit > "/tmp/signed-publish-$label.out" 2>&1 || {
          cat "/tmp/signed-publish-$label.out"
          fail "apr publish signed-tool $version succeeds"
          return 1
        }
        cat "/tmp/signed-publish-$label.out"
        $APR cache generate \
          --registry signed-reg \
          --output /tmp/signed-cache \
          --cache-url http://127.0.0.1:18106 \
          --priority 52 \
          --no-commit > "/tmp/signed-cache-$label.out" 2>&1 || {
          cat "/tmp/signed-cache-$label.out"
          fail "apr cache generate signed-tool $version succeeds"
          return 1
        }
        cat "/tmp/signed-cache-$label.out"
      }

      GOOD_KEY=/tmp/signed-commit-good
      BAD_KEY=/tmp/signed-commit-bad
      ssh-keygen -q -t ed25519 -N "" -f "$GOOD_KEY"
      ssh-keygen -q -t ed25519 -N "" -f "$BAD_KEY"
      GOOD_PUBLIC=$(cut -d ' ' -f2 < "$GOOD_KEY.pub")
      TRUST_KEY="signed-reg:Ed25519:$GOOD_PUBLIC"

      TOOL_V1_STORE=$(make_signed_tool 1.0.0)
      TOOL_V2_STORE=$(make_signed_tool 2.0.0)
      TOOL_V3_STORE=$(make_signed_tool 3.0.0)
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V3_HASH=$(basename "$TOOL_V3_STORE" | cut -d- -f1)

      mount -o remount,rw / || true
      assert_store_valid "$TOOL_V1_STORE" "signed-tool-v1"
      assert_store_valid "$TOOL_V2_STORE" "signed-tool-v2"
      assert_store_valid "$TOOL_V3_STORE" "signed-tool-v3"

      echo "==> Maintainer: publish signed-tool 1.0.0 with trusted commit key"
      $APR create signed-reg
      REG_DIR="$REG_STORAGE/signed-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_signed_tool 1.0.0 "$TOOL_V1_STORE" v1
      assert_file_exists "/tmp/signed-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has signed-tool v1 narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18106" "registry records signed cache URL"
      commit_signed "$GOOD_KEY" v1 "release: signed-tool 1.0.0"

      git init --bare --object-format=sha256 /tmp/signed-origin.git
      git -C /tmp/signed-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/signed-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18106 --bind 127.0.0.1 \
        --directory /tmp/signed-cache > /tmp/signed-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "signed static cache HTTP server started"
      else
        cat /tmp/signed-cache-http.log || true
        fail "signed static cache HTTP server started"
      fi

      echo "==> Consumer: add trusted signed registry and install v1"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      mkdir -p "$HOME"

      $APM registry add file:///tmp/signed-origin.git \
        --name signed-reg \
        --branch "$DEFAULT_BRANCH" \
        --trust-key "$TRUST_KEY" > /tmp/signed-add.out 2>&1 || {
        cat /tmp/signed-add.out
        fail "apm registry add syncs trusted signed registry"
      }
      cat /tmp/signed-add.out
      assert_file_contains /tmp/signed-add.out "Signing.*trusted key pinned" \
        "registry add reports pinned signing key"
      CONFIG_FILE="$APM_CONFIG/registries.d/signed-reg.toml"
      assert_file_contains "$CONFIG_FILE" "required = true" \
        "consumer config requires signed commits"
      assert_file_contains "$CONFIG_FILE" "$TRUST_KEY" \
        "consumer config stores trusted signing key"
      assert_file_contains "$HOME/.local/share/apm/registries/signed-reg/registry.toml" \
        "http://127.0.0.1:18106" "signed registry sync materializes cache endpoint"

      $APM search signed-tool --registry signed-reg > /tmp/signed-search-v1.out 2>&1 || {
        cat /tmp/signed-search-v1.out
        fail "apm search sees trusted signed v1"
      }
      assert_file_contains /tmp/signed-search-v1.out "1.0.0" \
        "trusted signed registry exposes v1"

      delete_store_path "$TOOL_V1_STORE" "signed-tool-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install signed-tool --registry signed-reg --yes \
        > /tmp/signed-install-v1.out 2>&1 || {
        cat /tmp/signed-install-v1.out
        fail "apm install downloads trusted signed v1"
      }
      cat /tmp/signed-install-v1.out
      assert_file_contains /tmp/signed-install-v1.out "Downloading" \
        "apm install downloads signed v1 NAR"
      assert_store_valid "$TOOL_V1_STORE" "signed-tool-v1"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/signed-tool"
      "$PROFILE_TOOL" > /tmp/signed-run-v1.out
      assert_file_contains /tmp/signed-run-v1.out \
        "signed-tool 1.0.0 executed" "trusted signed v1 executable runs"

      echo "==> Maintainer: publish v2 signed by the wrong key"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      publish_signed_tool 2.0.0 "$TOOL_V2_STORE" v2-bad
      commit_signed "$BAD_KEY" v2-bad "release: signed-tool 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: reject wrong-key registry update"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      if $APM update --registry signed-reg > /tmp/signed-update-bad.out 2>&1; then
        cat /tmp/signed-update-bad.out
        fail "apm update should reject commit signed by wrong key"
      else
        cat /tmp/signed-update-bad.out
        pass "apm update rejects commit signed by wrong key"
      fi
      assert_file_contains /tmp/signed-update-bad.out \
        "commit signature verification failed" \
        "wrong-key update reports signature verification failure"
      $APM search signed-tool --registry signed-reg > /tmp/signed-search-after-bad.out 2>&1 || {
        cat /tmp/signed-search-after-bad.out
        fail "apm search still works after rejected signed update"
      }
      assert_file_contains /tmp/signed-search-after-bad.out "1.0.0" \
        "rejected signed update leaves v1 metadata active"
      assert_file_not_contains /tmp/signed-search-after-bad.out "2.0.0" \
        "rejected signed update does not expose wrong-key v2"
      "$PROFILE_TOOL" > /tmp/signed-run-after-bad.out
      assert_file_contains /tmp/signed-run-after-bad.out \
        "signed-tool 1.0.0 executed" "wrong-key update leaves installed v1 active"

      echo "==> Maintainer: publish v3 signed by the trusted key"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      publish_signed_tool 3.0.0 "$TOOL_V3_STORE" v3-good
      assert_file_exists "/tmp/signed-cache/$TOOL_V3_HASH.narinfo" \
        "static cache has signed-tool v3 narinfo"
      commit_signed "$GOOD_KEY" v3-good "release: signed-tool 3.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: recover on trusted signed update and upgrade"
      export HOME=/tmp/signed-consumer
      export USER=signeduser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_V3_STORE" "signed-tool-v3"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM update --registry signed-reg > /tmp/signed-update-good.out 2>&1 || {
        cat /tmp/signed-update-good.out
        fail "apm update accepts trusted signed v3"
      }
      cat /tmp/signed-update-good.out
      $APM list --upgradable > /tmp/signed-upgradable-v3.out 2>&1 || {
        cat /tmp/signed-upgradable-v3.out
        fail "apm list --upgradable sees trusted v3"
      }
      assert_file_contains /tmp/signed-upgradable-v3.out "signed-tool" \
        "trusted signed v3 update names package"
      assert_file_contains /tmp/signed-upgradable-v3.out "3.0.0" \
        "trusted signed v3 update reports candidate"

      $APM upgrade signed-tool --yes > /tmp/signed-upgrade-v3.out 2>&1 || {
        cat /tmp/signed-upgrade-v3.out
        fail "apm upgrade downloads trusted signed v3"
      }
      cat /tmp/signed-upgrade-v3.out
      assert_file_contains /tmp/signed-upgrade-v3.out "Downloading" \
        "apm upgrade downloads signed v3 NAR"
      assert_store_valid "$TOOL_V3_STORE" "signed-tool-v3"
      "$PROFILE_TOOL" > /tmp/signed-run-v3.out
      assert_file_contains /tmp/signed-run-v3.out \
        "signed-tool 3.0.0 executed" "trusted signed v3 executable runs"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "signed static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # registry-trust-keys-workflow — Committed and local trust key commands
  # -------------------------------------------------------------------------
  registry-trust-keys-workflow = testing.mkVMTest {
    name = "apm-registry-trust-keys-workflow";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: APR committed key roster and local trust store workflow"

      # Real keypairs from `apr keys generate` so roster commits can be
      # signed (required whenever the roster is non-empty).
      $APR keys generate root --registry trust-reg > /tmp/keys-generate-root.out 2>&1 || {
        cat /tmp/keys-generate-root.out
        fail "apr keys generate creates root key"
      }
      cat /tmp/keys-generate-root.out
      KEY_ROOT=$(grep -o 'trust-reg:Ed25519:[A-Za-z0-9+/=]*' /tmp/keys-generate-root.out | head -1)
      KEY_ROOT_PATH="$HOME/.config/apm/keys/trust-reg-root.key"
      assert_file_exists "$KEY_ROOT_PATH" "apr keys generate writes private key file"

      $APR keys generate backup --registry trust-reg > /tmp/keys-generate-backup.out 2>&1
      KEY_BACKUP=$(grep -o 'trust-reg:Ed25519:[A-Za-z0-9+/=]*' /tmp/keys-generate-backup.out | head -1)
      KEY_BACKUP_PATH="$HOME/.config/apm/keys/trust-reg-backup.key"

      $APR keys generate canary --registry trust-reg > /tmp/keys-generate-canary.out 2>&1
      KEY_CANARY=$(grep -o 'trust-reg:Ed25519:[A-Za-z0-9+/=]*' /tmp/keys-generate-canary.out | head -1)

      if $APR keys generate root --registry trust-reg \
        > /tmp/keys-generate-overwrite.out 2>&1; then
        cat /tmp/keys-generate-overwrite.out
        fail "apr keys generate should refuse to overwrite an existing key"
      else
        pass "apr keys generate refuses to overwrite an existing key"
      fi

      KEY_FOREIGN="other-reg:Ed25519:bWlzbWF0Y2g="

      $APR create trust-reg --trust-key "$KEY_ROOT" --trust-key-id root \
        --key "$KEY_ROOT_PATH"
      REG_DIR="$REG_STORAGE/trust-reg"
      TRUST_FILE="$HOME/.config/apm/trusted-keys.d/trust-reg.pub"

      assert_file_exists "$REG_DIR/keys.toml" \
        "apr create writes committed keys.toml"
      assert_file_contains "$REG_DIR/keys.toml" 'id = "root"' \
        "initial committed key id is recorded"
      assert_file_contains "$REG_DIR/keys.toml" "$KEY_ROOT" \
        "initial committed key value is recorded"

      $APR keys list --registry trust-reg > /tmp/keys-list-initial.out 2>&1 || {
        cat /tmp/keys-list-initial.out
        fail "apr keys list shows initial roster"
      }
      cat /tmp/keys-list-initial.out
      assert_file_contains /tmp/keys-list-initial.out "root:" \
        "apr keys list reports active root key"
      assert_file_contains /tmp/keys-list-initial.out "revoked: none" \
        "apr keys list reports empty revocation set"

      $APR keys add backup "$KEY_BACKUP" --key "$KEY_ROOT_PATH" --registry trust-reg \
        > /tmp/keys-add-backup.out 2>&1 || {
        cat /tmp/keys-add-backup.out
        fail "apr keys add commits backup key"
      }
      cat /tmp/keys-add-backup.out
      assert_file_contains /tmp/keys-add-backup.out "Added active signing key 'backup'" \
        "apr keys add reports backup key"
      assert_file_contains "$REG_DIR/keys.toml" 'id = "backup"' \
        "backup key is written to keys.toml"
      assert_file_contains "$REG_DIR/keys.toml" "$KEY_BACKUP" \
        "backup key value is written to keys.toml"

      $APR keys add canary "$KEY_CANARY" --key "$KEY_ROOT_PATH" --registry trust-reg \
        > /tmp/keys-add-canary.out 2>&1 || {
        cat /tmp/keys-add-canary.out
        fail "apr keys add commits canary key"
      }
      cat /tmp/keys-add-canary.out
      assert_file_contains "$REG_DIR/keys.toml" 'id = "canary"' \
        "canary key is written to keys.toml"

      if $APR keys add foreign "$KEY_FOREIGN" --key "$KEY_ROOT_PATH" --registry trust-reg \
        > /tmp/keys-add-foreign.out 2>&1; then
        cat /tmp/keys-add-foreign.out
        fail "apr keys add should reject foreign registry key"
      else
        cat /tmp/keys-add-foreign.out
        pass "apr keys add rejects foreign registry key"
      fi
      assert_file_contains /tmp/keys-add-foreign.out \
        "belongs to registry 'other-reg', expected 'trust-reg'" \
        "foreign committed key error names both registries"

      if $APR keys retire root --registry trust-reg \
        > /tmp/keys-retire-missing-vouch.out 2>&1; then
        cat /tmp/keys-retire-missing-vouch.out
        fail "apr keys retire should require --vouched-by with multiple survivors"
      else
        cat /tmp/keys-retire-missing-vouch.out
        pass "apr keys retire requires explicit vouching key"
      fi
      assert_file_contains /tmp/keys-retire-missing-vouch.out \
        "vouched-by is required" \
        "retire error explains required vouching key"

      $APR keys retire root --vouched-by backup --reason "key rotation" \
        --key "$KEY_BACKUP_PATH" \
        --registry trust-reg > /tmp/keys-retire-root.out 2>&1 || {
        cat /tmp/keys-retire-root.out
        fail "apr keys retire commits revoked root key"
      }
      cat /tmp/keys-retire-root.out
      assert_file_contains /tmp/keys-retire-root.out \
        "Retired signing key 'root'" \
        "apr keys retire reports revoked root key"
      $APR keys list --registry trust-reg > /tmp/keys-list-rotated.out 2>&1 || {
        cat /tmp/keys-list-rotated.out
        fail "apr keys list shows rotated roster"
      }
      cat /tmp/keys-list-rotated.out
      assert_file_contains /tmp/keys-list-rotated.out "backup:" \
        "rotated roster keeps backup active"
      assert_file_contains /tmp/keys-list-rotated.out "canary:" \
        "rotated roster keeps canary active"
      assert_file_contains /tmp/keys-list-rotated.out "root: key rotation" \
        "rotated roster records root revocation reason"
      git -C "$REG_DIR" log --oneline > /tmp/keys-git-log.out
      assert_file_contains /tmp/keys-git-log.out \
        "registry: add signing key backup" \
        "keys add creates a maintainer commit"
      assert_file_contains /tmp/keys-git-log.out \
        "registry: retire signing key root" \
        "keys retire creates a maintainer commit"

      $APR trust list trust-reg > /tmp/trust-list-empty.out 2>&1 || {
        cat /tmp/trust-list-empty.out
        fail "apr trust list handles empty store"
      }
      cat /tmp/trust-list-empty.out
      assert_file_contains /tmp/trust-list-empty.out "trust-reg: no pinned keys" \
        "apr trust list reports no pinned keys"

      $APR trust pin trust-reg "$KEY_ROOT" > /tmp/trust-pin-root.out 2>&1 || {
        cat /tmp/trust-pin-root.out
        fail "apr trust pin stores root key"
      }
      cat /tmp/trust-pin-root.out
      assert_file_exists "$TRUST_FILE" \
        "apr trust pin writes trusted key file"
      assert_file_contains "$TRUST_FILE" "$KEY_ROOT" \
        "trusted key file contains pinned root key"

      $APR trust pin trust-reg "$KEY_BACKUP" > /tmp/trust-pin-backup.out 2>&1 || {
        cat /tmp/trust-pin-backup.out
        fail "apr trust pin stores backup key"
      }
      cat /tmp/trust-pin-backup.out
      TRUST_COUNT=$(wc -l < "$TRUST_FILE")
      if [ "$TRUST_COUNT" = "2" ]; then
        pass "trust store keeps both pinned keys during rotation overlap"
      else
        fail "trust store should contain two pinned keys, got $TRUST_COUNT"
        cat "$TRUST_FILE"
      fi

      if $APR trust pin trust-reg "$KEY_FOREIGN" \
        > /tmp/trust-pin-foreign.out 2>&1; then
        cat /tmp/trust-pin-foreign.out
        fail "apr trust pin should reject foreign registry key"
      else
        cat /tmp/trust-pin-foreign.out
        pass "apr trust pin rejects foreign registry key"
      fi
      assert_file_contains /tmp/trust-pin-foreign.out \
        "belongs to registry 'other-reg', expected 'trust-reg'" \
        "foreign trust key error names both registries"

      $APR trust pin trust-reg "$KEY_CANARY" --replace \
        > /tmp/trust-replace.out 2>&1 || {
        cat /tmp/trust-replace.out
        fail "apr trust pin --replace stores only canary key"
      }
      cat /tmp/trust-replace.out
      TRUST_COUNT=$(wc -l < "$TRUST_FILE")
      if [ "$TRUST_COUNT" = "1" ]; then
        pass "trust replace leaves one pinned key"
      else
        fail "trust replace should leave one pinned key, got $TRUST_COUNT"
        cat "$TRUST_FILE"
      fi
      assert_file_contains "$TRUST_FILE" "$KEY_CANARY" \
        "trust replace stores canary key"

      $APR trust list trust-reg > /tmp/trust-list-canary.out 2>&1 || {
        cat /tmp/trust-list-canary.out
        fail "apr trust list shows replacement key"
      }
      cat /tmp/trust-list-canary.out
      assert_file_contains /tmp/trust-list-canary.out "trust-reg: Ed25519" \
        "apr trust list reports pinned canary key"

      $APR trust remove trust-reg > /tmp/trust-remove.out 2>&1 || {
        cat /tmp/trust-remove.out
        fail "apr trust remove deletes trust file"
      }
      cat /tmp/trust-remove.out
      assert_file_not_exists "$TRUST_FILE" \
        "apr trust remove deletes trusted key file"
      $APR trust remove trust-reg > /tmp/trust-remove-repeat.out 2>&1 || {
        cat /tmp/trust-remove-repeat.out
        fail "apr trust remove is idempotent"
      }
      cat /tmp/trust-remove-repeat.out
      assert_file_contains /tmp/trust-remove-repeat.out \
        "No pinned trust keys found" \
        "repeat trust remove reports no pinned keys"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # closure-generate — Closure files created and well-formed
  # -------------------------------------------------------------------------
  closure-generate = testing.mkVMTest {
    name = "apm-closure-generate";
    rootfsDeps = closureWorkflowDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: real APR closure file generation and structure"

      LEAF_STORE="${closureLeafTool}"
      ROOT_STORE="${closureRootTool}"
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)
      ROOT_HASH=$(basename "$ROOT_STORE" | cut -d- -f1)

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/closure-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/closure-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      publish_closure_package() {
        store="$1"
        name="$2"
        version="$3"
        $APR publish "$store" \
          --name "$name" \
          --version "$version" \
          --description "Real closure fixture $name" \
          --license MIT \
          --maintainer closure@example.invalid \
          --registry test-reg \
          --no-commit > "/tmp/closure-publish-$name.out" 2>&1 || {
          cat "/tmp/closure-publish-$name.out"
          fail "apr publish $name succeeds"
          return 1
        }
        cat "/tmp/closure-publish-$name.out"
      }

      mount -o remount,rw / || true
      assert_store_valid "$LEAF_STORE" "closure-leaf"
      assert_store_valid "$ROOT_STORE" "closure-root"
      nix-store -q --references "$ROOT_STORE" > /tmp/closure-root-refs.out
      assert_file_contains /tmp/closure-root-refs.out "$LEAF_STORE" \
        "closure-root has a real Nix reference to closure-leaf"

      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"

      publish_closure_package "$LEAF_STORE" closure-leaf 1.0.0
      publish_closure_package "$ROOT_STORE" closure-root 1.0.0
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "publish real closure packages"

      assert_file_exists "$REG_DIR/packages/c/closure-leaf.toml" \
        "published closure-leaf package metadata exists"
      assert_file_exists "$REG_DIR/packages/c/closure-root.toml" \
        "published closure-root package metadata exists"
      assert_file_exists "$REG_DIR/closures/$LEAF_HASH" \
        "closure-leaf closure file exists"
      assert_file_exists "$REG_DIR/closures/$ROOT_HASH" \
        "closure-root closure file exists"

      LEAF_FIRST_TOKEN=$(head -1 "$REG_DIR/closures/$LEAF_HASH" | cut -d' ' -f1)
      if [ "$LEAF_FIRST_TOKEN" = "$LEAF_HASH" ]; then
        pass "closure-leaf closure starts with leaf hash"
      else
        fail "closure-leaf closure should start with $LEAF_HASH, got $LEAF_FIRST_TOKEN"
        cat "$REG_DIR/closures/$LEAF_HASH"
      fi

      FIRST_LINE=$(head -1 "$REG_DIR/closures/$ROOT_HASH")
      FIRST_TOKEN=$(echo "$FIRST_LINE" | cut -d' ' -f1)
      if [ "$FIRST_TOKEN" = "$ROOT_HASH" ]; then
        pass "closure-root closure starts with root hash"
      else
        fail "closure-root closure should start with $ROOT_HASH, got $FIRST_TOKEN"
        cat "$REG_DIR/closures/$ROOT_HASH"
      fi

      if echo "$FIRST_LINE" | grep -q "$LEAF_HASH"; then
        pass "closure-root root line lists closure-leaf as a direct dep"
      else
        fail "closure-root root line missing closure-leaf dep"
        cat "$REG_DIR/closures/$ROOT_HASH"
      fi

      if grep -q "^$LEAF_HASH" "$REG_DIR/closures/$ROOT_HASH"; then
        pass "closure-root closure has closure-leaf as a member"
      else
        fail "closure-root closure missing closure-leaf member line"
        cat "$REG_DIR/closures/$ROOT_HASH"
      fi

      for ref_path in $(nix-store -q --references "$ROOT_STORE"); do
        ref_hash=$(basename "$ref_path" | cut -d- -f1)
        assert_file_contains "$REG_DIR/closures/$ROOT_HASH" "$ref_hash" \
          "closure-root closure includes direct reference $ref_hash"
      done

      assert_file_contains "$REG_DIR/.gitattributes" \
        "closures/" ".gitattributes has closures entry"

      $APR verify --registry test-reg > /tmp/closure-verify-ok.out 2>&1 || {
        cat /tmp/closure-verify-ok.out
        fail "apr verify accepts real generated closure files"
      }
      cat /tmp/closure-verify-ok.out
      assert_file_contains /tmp/closure-verify-ok.out "no errors" \
        "apr verify reports generated closures are valid"

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # closure-verify — apr verify validates closure consistency
  # -------------------------------------------------------------------------
  closure-verify = testing.mkVMTest {
    name = "apm-closure-verify";
    rootfsDeps = closureWorkflowDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: apr verify rejects broken real closure metadata"

      LEAF_STORE="${closureLeafTool}"
      ROOT_STORE="${closureRootTool}"
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)
      ROOT_HASH=$(basename "$ROOT_STORE" | cut -d- -f1)

      publish_closure_package() {
        store="$1"
        name="$2"
        version="$3"
        $APR publish "$store" \
          --name "$name" \
          --version "$version" \
          --description "Real closure verify fixture $name" \
          --license MIT \
          --maintainer closure@example.invalid \
          --registry test-reg \
          --no-commit > "/tmp/verify-publish-$name.out" 2>&1 || {
          cat "/tmp/verify-publish-$name.out"
          fail "apr publish $name succeeds"
          return 1
        }
        cat "/tmp/verify-publish-$name.out"
      }

      commit_registry_changes() {
        message="$1"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "$message" > /tmp/verify-commit.out 2>&1 || {
          cat /tmp/verify-commit.out
          fail "registry commit succeeds: $message"
          return 1
        }
        cat /tmp/verify-commit.out
      }

      expect_verify_success() {
        label="$1"
        if $APR verify --registry test-reg > "/tmp/verify-$label.out" 2>&1; then
          cat "/tmp/verify-$label.out"
          assert_file_contains "/tmp/verify-$label.out" "no errors" \
            "apr verify reports $label has no errors"
        else
          cat "/tmp/verify-$label.out"
          fail "apr verify should succeed for $label"
        fi
      }

      expect_verify_failure() {
        label="$1"
        pattern="$2"
        if $APR verify --registry test-reg > "/tmp/verify-$label.out" 2>&1; then
          cat "/tmp/verify-$label.out"
          fail "apr verify should fail for $label"
        else
          cat "/tmp/verify-$label.out"
          pass "apr verify fails for $label"
        fi
        assert_file_contains "/tmp/verify-$label.out" "$pattern" \
          "apr verify reports $label"
      }

      mount -o remount,rw / || true
      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"
      publish_closure_package "$LEAF_STORE" closure-leaf 1.0.0
      publish_closure_package "$ROOT_STORE" closure-root 1.0.0
      commit_registry_changes "publish real closure verify packages"

      cp "$REG_DIR/closures/$ROOT_HASH" /tmp/root-closure-good
      expect_verify_success valid-generated

      grep -v "^$LEAF_HASH" "$REG_DIR/closures/$ROOT_HASH" \
        > /tmp/root-closure-broken
      mv /tmp/root-closure-broken "$REG_DIR/closures/$ROOT_HASH"
      commit_registry_changes "break root closure dependency"
      expect_verify_failure broken-reference \
        "reference $LEAF_HASH not found in closure $ROOT_HASH"

      $APR verify --registry test-reg --package closure-root --fix \
        > /tmp/verify-fix-broken-reference.out 2>&1 || {
        cat /tmp/verify-fix-broken-reference.out
        fail "apr verify --fix repairs stale root closure metadata"
      }
      cat /tmp/verify-fix-broken-reference.out
      assert_file_contains /tmp/verify-fix-broken-reference.out \
        "Regenerated 1 closure file" \
        "apr verify --fix reports stale closure repair"
      assert_file_contains /tmp/verify-fix-broken-reference.out "no errors" \
        "apr verify --fix validates repaired stale closure metadata"
      assert_file_contains "$REG_DIR/closures/$ROOT_HASH" "$LEAF_HASH" \
        "apr verify --fix restores missing root closure dependency"
      commit_registry_changes "repair root closure dependency with verify fix"
      expect_verify_success restored-generated

      rm -f "$REG_DIR/closures/$ROOT_HASH"
      commit_registry_changes "remove root closure"
      expect_verify_failure missing-closure \
        "missing closure file for store hash $ROOT_HASH"

      $APR verify --registry test-reg --package closure-leaf \
        > /tmp/verify-filtered-leaf.out 2>&1 || {
        cat /tmp/verify-filtered-leaf.out
        fail "apr verify --package ignores unrelated broken closure metadata"
      }
      cat /tmp/verify-filtered-leaf.out
      assert_file_contains /tmp/verify-filtered-leaf.out "no errors" \
        "apr verify --package validates only the requested package"

      $APR verify --registry test-reg --package closure-root --fix \
        > /tmp/verify-fix-missing-closure.out 2>&1 || {
        cat /tmp/verify-fix-missing-closure.out
        fail "apr verify --fix repairs missing root closure metadata"
      }
      cat /tmp/verify-fix-missing-closure.out
      assert_file_contains /tmp/verify-fix-missing-closure.out \
        "Regenerated 1 closure file" \
        "apr verify --fix reports missing closure repair"
      assert_file_contains /tmp/verify-fix-missing-closure.out "no errors" \
        "apr verify --fix validates repaired missing closure metadata"
      assert_file_exists "$REG_DIR/closures/$ROOT_HASH" \
        "apr verify --fix recreates missing root closure file"
      assert_file_contains "$REG_DIR/closures/$ROOT_HASH" "$LEAF_HASH" \
        "apr verify --fix recreates root closure dependency"
      commit_registry_changes "repair missing root closure with verify fix"
      expect_verify_success fixed-missing-closure

      assert_file_exists "$REG_DIR/closures/$LEAF_HASH" \
        "removing root closure leaves dependency closure intact"

      check_fail
    '';
  };
}
