# tests/vm/apm/registry.nix — Registry management VM tests (15 tests)
#
# Tests for `apr` registry lifecycle commands: create, add, remove, publish,
# unpublish, branch workflow, validate, signed tags, and clean-break behavior.
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
  closureWorkflowDeps =
    publishDeps
    ++ [
      closureLeafTool
      closureRootTool
    ];
in {
  # -------------------------------------------------------------------------
  # 1. registry-create — Initialize a new empty registry
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
  # 2. registry-add-clone — Add a remote registry via clone
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
      $APM registry add file:///tmp/remote-registry.git --name test-remote

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
  # 3. registry-add-no-clone-publish-hint — Config-only add has publish hint
  # -------------------------------------------------------------------------
  registry-add-no-clone-publish-hint = testing.mkVMTest {
    name = "apm-registry-add-no-clone-publish-hint";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkRemoteRegistry}

      echo "==> Test: apr add --no-clone followed by apr publish"

      create_remote_registry /tmp/no-clone-registry.git

      $APM registry add file:///tmp/no-clone-registry.git \
        --name no-clone-reg --no-clone

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
          "has no local clone" "apr publish reports missing local clone"
        assert_file_contains /tmp/publish-no-clone.out \
          "apm update no-clone-reg" "apr publish points to apm update"
        assert_file_contains /tmp/publish-no-clone.out \
          "apr create no-clone-reg" "apr publish points to apr create"
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 4. registry-remove — Remove a registry
  # -------------------------------------------------------------------------
  registry-remove = testing.mkVMTest {
    name = "apm-registry-remove";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: apr remove"

      # Add a registry first
      $APM registry add file:///tmp/fake-remote --name removable-reg

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
  # 5. registry-remove-unprivileged — Remove without profile write access
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
  # 6. registry-publish — Publish a package entry to the registry
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
  # 7. registry-publish-sysroot — Publish a sysroot package with images
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
  # 8. registry-unpublish — Remove a package from the registry
  # -------------------------------------------------------------------------
  registry-unpublish = testing.mkVMTest {
    name = "apm-registry-unpublish";
    rootfsDeps = publishDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: unpublish a package"

      # Create registry and publish a package
      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"
      $APR publish ${aosPkg} \
        --name removepkg \
        --version 1.0.0 \
        --description "Published for unpublish workflow" \
        --license MIT \
        --maintainer test \
        --registry test-reg

      # Verify package exists
      assert_file_exists "$REG_DIR/packages/r/removepkg.toml" \
        "package TOML exists before unpublish"

      $APR unpublish removepkg 1.0.0 --registry test-reg

      # Verify TOML file removed
      assert_file_not_exists "$REG_DIR/packages/r/removepkg.toml" \
        "package TOML removed after unpublish"

      # Verify git log shows removal commit
      cd "$REG_DIR"
      assert_cmd_output_contains "git log --oneline" "unpublish removepkg" \
        "git log shows unpublish commit"
      cd /tmp

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 9. registry-maintainer-workflow — Real release, cache, install, execute
  # -------------------------------------------------------------------------
  registry-maintainer-workflow = testing.mkVMTest {
    name = "apm-registry-maintainer-workflow";
    rootfsDeps = maintainerWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: full registry maintainer release and consumer install"

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
      dd if=/dev/zero of="$RUNNER_SRC/share/maint-runner/payload.bin" \
        bs=1M count=12
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

      python3 -m http.server 18082 --bind 127.0.0.1 \
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

      # Consumer uses a fresh HOME and the published git origin.
      export HOME=/tmp/consumer
      export USER=maintconsumer
      mkdir -p "$HOME"
      $APM registry add file:///tmp/maint-origin.git --name maint-reg --tag 1.0.0
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
      $APM list > /tmp/apm-list.out 2>&1
      assert_file_contains /tmp/apm-list.out "maint-runner" \
        "apm list shows installed maintainer package"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 10. registry-channel-workflow — Signed channel rollout and consumer upgrade
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
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)

      ssh-keygen -q -t ed25519 -N "" -f /tmp/channel-release-key
      CHANNEL_PUBLIC=$(cut -d ' ' -f2 < /tmp/channel-release-key.pub)
      CHANNEL_TRUST_KEY="chan-reg:Ed25519:$CHANNEL_PUBLIC"

      $APR create chan-reg --trust-key "$CHANNEL_TRUST_KEY"
      REG_DIR="$REG_STORAGE/chan-reg"
      assert_file_contains "$REG_DIR/keys.toml" "chan-reg:Ed25519" \
        "registry records initial channel trust key"

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

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      python3 -m http.server 18090 --bind 127.0.0.1 \
        --directory "$REG_DIR/.git" > /tmp/channel-origin-http.log 2>&1 &
      ORIGIN_PID=$!
      python3 -m http.server 18091 --bind 127.0.0.1 \
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

      kill "$ORIGIN_PID" "$CACHE_PID" 2>/dev/null || true
      wait "$ORIGIN_PID" "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 11. registry-branch-workflow — Branch create, switch, merge
  # -------------------------------------------------------------------------
  registry-branch-workflow = testing.mkVMTest {
    name = "apm-registry-branch-workflow";
    rootfsDeps = closureWorkflowDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixPublishEnv}

      echo "==> Test: real APR branch create, switch, publish, merge"

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

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 11. registry-validate — Validate registry TOML structure
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
  # 12. registry-bundle — Legacy selector for signed tag / no-bundle clean break
  # -------------------------------------------------------------------------
  registry-bundle = testing.mkVMTest {
    name = "apm-registry-signed-tag-clean-break";
    rootfsDeps = fixtures.commonDeps ++ [pkgs.openssh];
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${fixtures.mkFakePackageToml}

      echo "==> Test: apr signed tag and bundle clean break"

      # Create registry with packages
      $APR create test-reg
      REG_DIR="$REG_STORAGE/test-reg"
      write_package_toml "$REG_DIR" "tagpkg" "1.0.0"
      commit_registry "$REG_DIR" "publish tagpkg 1.0.0"

      ssh-keygen -q -t ed25519 -N "" -f /tmp/release-key
      $APR tag 1.0.0 --registry test-reg --key /tmp/release-key

      cd "$REG_DIR"
      assert_cmd_success "git rev-parse 1.0.0^{tag}" \
        "signed release tag object exists"
      assert_cmd_output_contains "git cat-file -p 1.0.0" \
        "BEGIN SSH SIGNATURE" "release tag object carries SSH signature"
      cd /tmp

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
  # 13. closure-generate — Closure files created and well-formed
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
  # 14. closure-verify — apr verify validates closure consistency
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

      cp /tmp/root-closure-good "$REG_DIR/closures/$ROOT_HASH"
      commit_registry_changes "restore root closure"
      expect_verify_success restored-generated

      rm -f "$REG_DIR/closures/$ROOT_HASH"
      commit_registry_changes "remove root closure"
      expect_verify_failure missing-closure \
        "missing closure file for store hash $ROOT_HASH"

      assert_file_exists "$REG_DIR/closures/$LEAF_HASH" \
        "removing root closure leaves dependency closure intact"

      check_fail
    '';
  };
}
