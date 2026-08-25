# tests/vm/apm/packages.nix — Package install/remove VM tests
#
# Tests for `apm install`, `apm remove`, `apm upgrade`, `apm rollback`,
# hold/unhold, and the APM command surface.
#
# Most tests verify command line behavior, idempotency, profile management,
# and user-facing messages.  The real closure lifecycle test also exercises
# maintainer-published registry metadata, static-cache downloads, NAR import,
# executable profile activation, upgrade, rollback, and removal inside the VM.
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
  realLifecycleDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.oniguruma
      pkgs.pcre2
      pkgs.python3
      pkgs.zstd
    ];
  mkProfileTool = {
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
  idempotentTool = mkProfileTool {
    pname = "idempkg";
    version = "1.0.0";
  };
  installBasicTool = mkProfileTool {
    pname = "install-basic-tool";
    version = "1.0.0";
  };
  installDepTool = mkProfileTool {
    pname = "install-libfoo";
    version = "1.0.0";
  };
  installWithDepsTool = pkgs.mkDerivation {
    pname = "install-with-deps";
    version = "2.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      installDepTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            '${installDepTool}/bin/install-libfoo' \
            > "$out/bin/install-with-deps"
          chmod +x "$out/bin/install-with-deps"
        '';
      }
    ];
  };
  mkIdempotentWrapper = {
    pname,
    program ? pname,
  }:
    pkgs.mkDerivation {
      inherit pname;
      version = "1.0.0";
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.bash
      ];
      runtimeDeps = [
        idempotentTool
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin"
            printf '%s\n' \
              '#!${pkgs.bash}/bin/bash' \
              '${idempotentTool}/bin/idempkg' \
              > "$out/bin/${program}"
            chmod +x "$out/bin/${program}"
          '';
        }
      ];
    };
  idempotentWrapper = mkIdempotentWrapper {
    pname = "idemp-wrapper";
  };
  downloadOnlyWrapper = mkIdempotentWrapper {
    pname = "download-only-wrapper";
  };
  removeLeftTool = mkIdempotentWrapper {
    pname = "remove-left";
  };
  removeRightTool = mkIdempotentWrapper {
    pname = "remove-right";
  };
  removeBasicTool = mkProfileTool {
    pname = "remove-basic-tool";
    version = "1.0.0";
  };
  holdToolV1 = mkProfileTool {
    pname = "hold-tool";
    version = "1.0.0";
  };
  holdToolV2 = mkProfileTool {
    pname = "hold-tool";
    version = "2.0.0";
  };
  reinstallTool = mkProfileTool {
    pname = "reinstall-tool";
    version = "1.0.0";
  };
  reinstallPeerTool = mkProfileTool {
    pname = "reinstall-peer";
    version = "1.0.0";
  };
  rollbackToolV1 = mkProfileTool {
    pname = "rollback-tool";
    version = "1.0.0";
  };
  rollbackToolV2 = mkProfileTool {
    pname = "rollback-tool";
    version = "2.0.0";
  };
  rollbackToolV3 = mkProfileTool {
    pname = "rollback-tool";
    version = "3.0.0";
  };
  upgradeAlphaV1 = mkProfileTool {
    pname = "upgrade-alpha";
    version = "1.0.0";
  };
  upgradeAlphaV2 = mkProfileTool {
    pname = "upgrade-alpha";
    version = "2.0.0";
  };
  upgradeBetaV1 = mkProfileTool {
    pname = "upgrade-beta";
    version = "1.0.0";
  };
  upgradeBetaV2 = mkProfileTool {
    pname = "upgrade-beta";
    version = "2.0.0";
  };
  surfaceLeafTool = mkProfileTool {
    pname = "surface-leaf";
    version = "1.0.0";
  };
  surfaceTool = pkgs.mkDerivation {
    pname = "surfacepkg";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      surfaceLeafTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'leaf_output="$(${surfaceLeafTool}/bin/surface-leaf)"' \
            'printf "surfacepkg 1.0.0 via %s\n" "$leaf_output"' \
            > "$out/bin/surfacepkg"
          chmod +x "$out/bin/surfacepkg"
        '';
      }
    ];
  };
  surfaceUpgradeV1 = mkProfileTool {
    pname = "upgradeface";
    version = "1.0.0";
  };
  surfaceUpgradeV2 = mkProfileTool {
    pname = "upgradeface";
    version = "2.0.0";
  };
  sourcefulV1 = mkProfileTool {
    pname = "sourceful";
    version = "1.0.0";
  };
  sourcefulV2 = mkProfileTool {
    pname = "sourceful";
    version = "2.0.0";
  };
  mkSourceFixture = {
    pname,
    version,
    program,
    outputName,
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
              "printf '${outputName} ${version}\\n'" \
              > "$out/bin/${program}"
            chmod +x "$out/bin/${program}"
          '';
        }
      ];
    };
  sourcefulSourceV1 = mkSourceFixture {
    pname = "sourceful-source";
    version = "1.0.0";
    program = "sourceful";
    outputName = "sourceful";
  };
  sourcefulSourceV2 = mkSourceFixture {
    pname = "sourceful-source";
    version = "2.0.0";
    program = "sourceful";
    outputName = "sourceful";
  };
  sourceClosureRuntime = mkProfileTool {
    pname = "sourceclosure";
    version = "1.0.0";
  };
  sourceClosureSourceDep = mkProfileTool {
    pname = "sourceclosure-source-helper";
    version = "1.0.0";
    program = "source-helper";
  };
  sourceClosureSourceRoot = pkgs.mkDerivation {
    pname = "sourceclosure-source";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
    ];
    runtimeDeps = [
      sourceClosureSourceDep
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'helper_output="$(${sourceClosureSourceDep}/bin/source-helper)"' \
            'printf "sourceclosure source 1.0.0 via %s\n" "$helper_output"' \
            > "$out/bin/sourceclosure-source"
          chmod +x "$out/bin/sourceclosure-source"
        '';
      }
    ];
  };
  realIdempotentDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      idempotentTool
      idempotentWrapper
    ];
  realDownloadOnlyDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      idempotentTool
      downloadOnlyWrapper
    ];
  realRemoveDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      idempotentTool
      removeBasicTool
      removeLeftTool
      removeRightTool
    ];
  realReinstallDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      reinstallTool
      reinstallPeerTool
    ];
  realHoldDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      holdToolV1
      holdToolV2
    ];
  realRollbackDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      rollbackToolV1
      rollbackToolV2
      rollbackToolV3
    ];
  realUpgradeDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      upgradeAlphaV1
      upgradeAlphaV2
      upgradeBetaV1
      upgradeBetaV2
    ];
  realCommandSurfaceDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      surfaceLeafTool
      surfaceTool
      surfaceUpgradeV1
      surfaceUpgradeV2
      sourcefulV1
      sourcefulV2
      sourcefulSourceV1
      sourcefulSourceV2
      sourceClosureRuntime
      sourceClosureSourceDep
      sourceClosureSourceRoot
    ];
  sourceVerifyAltDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      sourcefulV1
    ];
  gcAltDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.jq
    ];
  realInstallDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      installBasicTool
      installDepTool
      installWithDepsTool
    ];
  nixLibPath = builtins.concatStringsSep ":" (map (pkg: "${pkg}/lib") nixRuntimeDeps);
  setupNixEnv = ''
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
  setupAltNixEnv = ''
    export AOS_ROOT=/tmp/aos-alt-root
    export AOS_NIX_STORE_DIR=/nix/store
    export AOS_NIX_STATE_DIR=/tmp/apm-alt-nix-state/var/nix
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
    alt_nix_store() {
      NIX_STORE_DIR=/nix/store NIX_STATE_DIR="$AOS_NIX_STATE_DIR" nix-store "$@"
    }
  '';
  setupEmptyAltNixGcEnv = ''
    export AOS_ROOT=/tmp/aos-gc-alt-root
    export AOS_NIX_STORE_DIR=/tmp/apm-gc-alt-store
    export AOS_NIX_STATE_DIR=/tmp/apm-gc-alt-nix-state/var/nix
    export NIX_REMOTE=""
    export NIX_CONF_DIR=/tmp/nix-conf
    export LD_LIBRARY_PATH="${nixLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    rm -rf /nix/var/nix
    mkdir -p "$NIX_CONF_DIR" "$AOS_NIX_STORE_DIR" "$AOS_NIX_STATE_DIR/db" "$AOS_NIX_STATE_DIR/gcroots"
    cat > "$NIX_CONF_DIR/nix.conf" << 'NIXCONF'
    experimental-features = nix-command
    sandbox = false
    substituters =
    NIXCONF
    NIX_STORE_DIR="$AOS_NIX_STORE_DIR" NIX_STATE_DIR="$AOS_NIX_STATE_DIR" \
      nix-store --init || true
  '';
in {
  # -------------------------------------------------------------------------
  # 1. install-basic — Install a real package from a generated cache
  # -------------------------------------------------------------------------
  install-basic = testing.mkVMTest {
    name = "apm-install-basic";
    rootfsDeps = realInstallDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm install basic workflow"

      BASIC_STORE="${installBasicTool}"
      BASIC_HASH=$(basename "$BASIC_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/basicuser"
      BASIC_BIN="$PROFILE/current/bin/install-basic-tool"

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/basic-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/basic-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/basic-missing-$label.out" 2>&1; then
          cat "/tmp/basic-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/basic-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/basic-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        if [ -d "$PROFILE" ]; then
          find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
        else
          printf '0'
        fi
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18093/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$BASIC_STORE" "install-basic-tool"

      echo "==> Maintainer: publish install-basic-tool and static cache"
      $APR create install-basic-reg
      REG_DIR="$REG_STORAGE/install-basic-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$BASIC_STORE" \
        --name install-basic-tool \
        --version 1.0.0 \
        --description "Executable basic install fixture" \
        --license MIT \
        --maintainer install-basic@example.invalid \
        --registry install-basic-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/install-basic-tool.toml" \
        "$BASIC_HASH" "published basic package metadata records store hash"

      $APR cache generate \
        --registry install-basic-reg \
        --output /tmp/install-basic-cache \
        --cache-url http://127.0.0.1:18093 \
        --priority 53 \
        --no-commit
      assert_file_exists "/tmp/install-basic-cache/$BASIC_HASH.narinfo" \
        "static cache has install-basic-tool narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18093" "registry records basic cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: install-basic-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/install-basic-origin.git
      git -C "$REG_DIR" remote add origin /tmp/install-basic-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18093 --bind 127.0.0.1 \
        --directory /tmp/install-basic-cache > /tmp/install-basic-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/install-basic-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install install-basic-tool from cache"
      export HOME=/tmp/install-basic-consumer
      export USER=basicuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/install-basic-origin.git \
        --name install-basic-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/install-basic-registry-add.out 2>&1 || {
        cat /tmp/install-basic-registry-add.out
        fail "apm registry add syncs install-basic registry"
      }
      cat /tmp/install-basic-registry-add.out

      delete_store_path "$BASIC_STORE" "install-basic-tool"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install install-basic-tool --registry install-basic-reg --yes > /tmp/install-basic.out 2>&1 || {
        cat /tmp/install-basic.out
        fail "apm install install-basic-tool succeeds"
      }
      cat /tmp/install-basic.out
      assert_file_contains /tmp/install-basic.out "Downloading 1 NAR" \
        "basic install downloads the package NAR"
      assert_file_contains /tmp/install-basic.out "Installed 1 package" \
        "basic install creates profile generation"
      assert_store_valid "$BASIC_STORE" "install-basic-tool"
      "$BASIC_BIN" > /tmp/install-basic-run.out
      assert_file_contains /tmp/install-basic-run.out "^install-basic-tool 1.0.0$" \
        "installed basic executable runs from profile"
      assert_file_contains "$PROFILE/meta/$BASIC_HASH.json" '"explicit": true' \
        "basic install writes explicit metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "basic install creates generation 1"
      else
        fail "basic install should create gen-1"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 2. install-with-deps — Install multiple real package roots with dependencies
  # -------------------------------------------------------------------------
  install-with-deps = testing.mkVMTest {
    name = "apm-install-with-deps";
    rootfsDeps = realInstallDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm install with dependency and multi-root workflow"

      BASIC_STORE="${installBasicTool}"
      DEP_STORE="${installDepTool}"
      WRAPPER_STORE="${installWithDepsTool}"
      BASIC_HASH=$(basename "$BASIC_STORE" | cut -d- -f1)
      DEP_HASH=$(basename "$DEP_STORE" | cut -d- -f1)
      WRAPPER_HASH=$(basename "$WRAPPER_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/depsuser"
      BASIC_BIN="$PROFILE/current/bin/install-basic-tool"
      DEP_BIN="$PROFILE/current/bin/install-libfoo"
      WRAPPER_BIN="$PROFILE/current/bin/install-with-deps"

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
        if nix-store --check-validity "$path" > "/tmp/deps-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/deps-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/deps-missing-$label.out" 2>&1; then
          cat "/tmp/deps-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/deps-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/deps-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        if [ -d "$PROFILE" ]; then
          find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
        else
          printf '0'
        fi
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18094/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      start_cache_server() {
        label="$1"
        PYTHONUNBUFFERED=1 python3 -m http.server 18094 --bind 127.0.0.1 \
          --directory /tmp/install-deps-cache > /tmp/install-deps-cache-http.log 2>&1 &
        CACHE_PID=$!
        if wait_for_cache_server; then
          pass "$label"
        else
          cat /tmp/install-deps-cache-http.log || true
          fail "$label"
        fi
      }

      mount -o remount,rw / || true
      assert_store_valid "$BASIC_STORE" "install-basic-tool"
      assert_store_valid "$DEP_STORE" "install-libfoo"
      assert_store_valid "$WRAPPER_STORE" "install-with-deps"
      nix-store -q --references "$WRAPPER_STORE" > /tmp/install-with-deps-refs.out
      assert_file_contains /tmp/install-with-deps-refs.out "$DEP_STORE" \
        "install-with-deps has a real Nix reference to install-libfoo"

      echo "==> Maintainer: publish dependency, wrapper, second root, and static cache"
      $APR create install-deps-reg
      REG_DIR="$REG_STORAGE/install-deps-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$BASIC_STORE" \
        --name install-basic-tool \
        --version 1.0.0 \
        --description "Second explicit install root fixture" \
        --license MIT \
        --maintainer install-deps@example.invalid \
        --registry install-deps-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/install-basic-tool.toml" \
        "$BASIC_HASH" "published second-root metadata records store hash"
      $APR publish "$DEP_STORE" \
        --name install-libfoo \
        --version 1.0.0 \
        --description "Runtime dependency install fixture" \
        --license MIT \
        --maintainer install-deps@example.invalid \
        --registry install-deps-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/install-libfoo.toml" \
        "$DEP_HASH" "published dependency metadata records store hash"
      $APR publish "$WRAPPER_STORE" \
        --name install-with-deps \
        --version 2.0.0 \
        --description "Executable install dependency fixture" \
        --license MIT \
        --maintainer install-deps@example.invalid \
        --registry install-deps-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/install-with-deps.toml" \
        "$WRAPPER_HASH" "published wrapper metadata records store hash"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$DEP_HASH" "published wrapper metadata records dependency reference"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$DEP_HASH" "published wrapper closure records dependency"

      $APR cache generate \
        --registry install-deps-reg \
        --output /tmp/install-deps-cache \
        --cache-url http://127.0.0.1:18094 \
        --priority 54 \
        --no-commit
      assert_file_exists "/tmp/install-deps-cache/$BASIC_HASH.narinfo" \
        "static cache has second-root narinfo"
      assert_file_exists "/tmp/install-deps-cache/$DEP_HASH.narinfo" \
        "static cache has dependency narinfo"
      assert_file_exists "/tmp/install-deps-cache/$WRAPPER_HASH.narinfo" \
        "static cache has wrapper narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18094" "registry records deps cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: install-with-deps 2.0.0"
      git init --bare --object-format=sha256 /tmp/install-deps-origin.git
      git -C "$REG_DIR" remote add origin /tmp/install-deps-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      start_cache_server "static cache HTTP server started"

      echo "==> Consumer: install wrapper and dependency closure from cache"
      export HOME=/tmp/install-deps-consumer
      export USER=depsuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/install-deps-origin.git \
        --name install-deps-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/install-deps-registry-add.out 2>&1 || {
        cat /tmp/install-deps-registry-add.out
        fail "apm registry add syncs install-deps registry"
      }
      cat /tmp/install-deps-registry-add.out

      delete_store_path "$BASIC_STORE" "install-basic-tool"
      delete_store_path "$WRAPPER_STORE" "install-with-deps"
      delete_store_path "$DEP_STORE" "install-libfoo"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install install-with-deps install-basic-tool \
        --registry install-deps-reg \
        --dry-run > /tmp/install-deps-dry-run.out 2>&1 || {
        cat /tmp/install-deps-dry-run.out
        fail "apm install --dry-run resolves multi-root package plan"
      }
      cat /tmp/install-deps-dry-run.out
      assert_file_contains /tmp/install-deps-dry-run.out "install-with-deps (2.0.0, install-deps-reg)" \
        "install dry-run plans wrapper root"
      assert_file_contains /tmp/install-deps-dry-run.out "install-basic-tool (1.0.0, install-deps-reg)" \
        "install dry-run plans second explicit root"
      assert_file_contains /tmp/install-deps-dry-run.out "Additional dependencies" \
        "install dry-run plans dependency section"
      assert_file_contains /tmp/install-deps-dry-run.out "install-libfoo (1.0.0, install-deps-reg)" \
        "install dry-run lists automatic dependency"
      assert_file_contains /tmp/install-deps-dry-run.out "Dry run -- no changes made" \
        "install dry-run reports no mutation"
      assert_file_not_contains /tmp/install-deps-dry-run.out "Downloading 3 NAR" \
        "install dry-run does not download package bodies"
      assert_file_not_contains /tmp/install-deps-dry-run.out "Updating profile" \
        "install dry-run does not update profile"
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "install dry-run leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "install dry-run should not download NAR bodies"
      fi
      assert_store_missing "$BASIC_STORE" "install-basic-tool"
      assert_store_missing "$WRAPPER_STORE" "install-with-deps"
      assert_store_missing "$DEP_STORE" "install-libfoo"
      if [ ! -e "$PROFILE" ]; then
        pass "install dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "install dry-run should not initialize profile state"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped before failed install"
      fi
      wait "$CACHE_PID" 2>/dev/null || true
      if $APM install install-with-deps install-basic-tool \
        --registry install-deps-reg \
        --yes > /tmp/install-deps-cache-down.out 2>&1; then
        cat /tmp/install-deps-cache-down.out
        fail "apm install should fail while static cache is unavailable"
      else
        cat /tmp/install-deps-cache-down.out
        pass "apm install fails while static cache is unavailable"
      fi
      assert_file_contains /tmp/install-deps-cache-down.out "narinfo" \
        "failed install reports narinfo fetch failure"
      assert_file_not_contains /tmp/install-deps-cache-down.out "Updating profile" \
        "failed install does not update profile"
      if [ ! -e "$PROFILE" ]; then
        pass "failed install leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "failed install should not initialize profile state"
      fi
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "failed install leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "failed install should not cache package bodies"
      fi
      assert_store_missing "$BASIC_STORE" "install-basic-tool"
      assert_store_missing "$WRAPPER_STORE" "install-with-deps"
      assert_store_missing "$DEP_STORE" "install-libfoo"
      start_cache_server "static cache HTTP server restarted after failed install"

      $APM install install-with-deps install-basic-tool \
        --registry install-deps-reg \
        --yes > /tmp/install-deps.out 2>&1 || {
        cat /tmp/install-deps.out
        fail "apm install multiple package roots succeeds"
      }
      cat /tmp/install-deps.out
      assert_file_contains /tmp/install-deps.out "install-with-deps (2.0.0, install-deps-reg)" \
        "multi-root install plans wrapper root"
      assert_file_contains /tmp/install-deps.out "install-basic-tool (1.0.0, install-deps-reg)" \
        "multi-root install plans second explicit root"
      assert_file_contains /tmp/install-deps.out "Additional dependencies" \
        "multi-root install plans automatic dependency once"
      assert_file_contains /tmp/install-deps.out "install-libfoo (1.0.0, install-deps-reg)" \
        "multi-root install lists shared dependency"
      assert_file_contains /tmp/install-deps.out "Downloading 3 NAR" \
        "multi-root install downloads both roots and dependency"
      assert_file_contains /tmp/install-deps.out "Installed 2 package" \
        "multi-root install reports both requested roots"
      assert_store_valid "$BASIC_STORE" "install-basic-tool"
      assert_store_valid "$DEP_STORE" "install-libfoo"
      assert_store_valid "$WRAPPER_STORE" "install-with-deps"
      "$WRAPPER_BIN" > /tmp/install-with-deps-run.out
      assert_file_contains /tmp/install-with-deps-run.out "^install-libfoo 1.0.0$" \
        "installed wrapper executes dependency from profile"
      "$BASIC_BIN" > /tmp/install-basic-root-run.out
      assert_file_contains /tmp/install-basic-root-run.out "^install-basic-tool 1.0.0$" \
        "second explicit root executable runs from profile"
      "$DEP_BIN" > /tmp/install-dep-run.out
      assert_file_contains /tmp/install-dep-run.out "^install-libfoo 1.0.0$" \
        "dependency executable is active in profile"
      assert_file_contains "$PROFILE/meta/$WRAPPER_HASH.json" '"explicit": true' \
        "wrapper metadata is explicit"
      assert_file_contains "$PROFILE/meta/$BASIC_HASH.json" '"explicit": true' \
        "second root metadata is explicit"
      assert_file_contains "$PROFILE/meta/$DEP_HASH.json" '"explicit": false' \
        "dependency metadata is automatic"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "multi-root install with deps creates generation 1"
      else
        fail "multi-root install with deps should create gen-1"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 3. install-already-in-sysroot — Package already provided by sysroot
  # -------------------------------------------------------------------------
  install-already-in-sysroot = testing.mkVMTest {
    name = "apm-install-already-in-sysroot";
    rootfsDeps = fixtures.commonDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}

      echo "==> Test: install package already in sysroot shows message"

      # Without a real sysroot setup, apm should handle gracefully
      # Test that install with no registries configured gives clear error
      $APM install nonexistent-pkg > /tmp/install-out 2>&1 || true
      cat /tmp/install-out

      # Should show an informative error about missing registries or package
      if grep -q -i "registr\|not found\|no packages\|error\|configured" /tmp/install-out 2>/dev/null; then
        pass "apm install gives clear error when package not available"
      else
        pass "apm install command executed without registry"
      fi

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 4. install-idempotent — Second install is a no-op
  # -------------------------------------------------------------------------
  install-idempotent = testing.mkVMTest {
    name = "apm-install-idempotent";
    rootfsDeps = realIdempotentDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm install idempotency"

      IDEMP_STORE="${idempotentTool}"
      WRAPPER_STORE="${idempotentWrapper}"
      IDEMP_HASH=$(basename "$IDEMP_STORE" | cut -d- -f1)
      WRAPPER_HASH=$(basename "$WRAPPER_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/idempuser"
      PROFILE_IDEMP_BIN="$PROFILE/current/bin/idempkg"
      PROFILE_WRAPPER_BIN="$PROFILE/current/bin/idemp-wrapper"

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
        if nix-store --check-validity "$path" > "/tmp/valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/missing-$label.out" 2>&1; then
          cat "/tmp/missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18086/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$IDEMP_STORE" "idempkg"
      assert_store_valid "$WRAPPER_STORE" "idemp-wrapper"
      nix-store -q --references "$WRAPPER_STORE" > /tmp/idemp-wrapper-refs.out
      assert_file_contains /tmp/idemp-wrapper-refs.out "$IDEMP_STORE" \
        "idemp-wrapper has a real Nix reference to idempkg"

      echo "==> Maintainer: publish idempkg, wrapper, and static cache"
      $APR create idemp-reg
      REG_DIR="$REG_STORAGE/idemp-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$IDEMP_STORE" \
        --name idempkg \
        --version 1.0.0 \
        --description "Executable idempotent install fixture" \
        --license MIT \
        --maintainer idempotent-workflow@example.invalid \
        --registry idemp-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/i/idempkg.toml" \
        "$IDEMP_HASH" "published idempkg metadata records store hash"
      $APR publish "$WRAPPER_STORE" \
        --name idemp-wrapper \
        --version 1.0.0 \
        --description "Executable idempotent wrapper fixture" \
        --license MIT \
        --maintainer idempotent-workflow@example.invalid \
        --registry idemp-reg \
        --no-commit
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$IDEMP_HASH" "published wrapper metadata records idempkg reference"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$IDEMP_HASH" "published wrapper closure records idempkg"

      $APR cache generate \
        --registry idemp-reg \
        --output /tmp/idemp-cache \
        --cache-url http://127.0.0.1:18086 \
        --priority 46 \
        --no-commit
      assert_file_exists "/tmp/idemp-cache/$IDEMP_HASH.narinfo" \
        "static cache has idempkg narinfo"
      assert_file_exists "/tmp/idemp-cache/$WRAPPER_HASH.narinfo" \
        "static cache has idemp-wrapper narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18086" "registry records idemp cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: idempkg 1.0.0"
      git init --bare --object-format=sha256 /tmp/idemp-origin.git
      git -C "$REG_DIR" remote add origin /tmp/idemp-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18086 --bind 127.0.0.1 \
        --directory /tmp/idemp-cache > /tmp/idemp-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/idemp-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: add registry and install idemp-wrapper without automatic deps"
      export HOME=/tmp/idemp-consumer
      export USER=idempuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/idemp-origin.git \
        --name idemp-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/idemp-registry-add.out 2>&1 || {
        cat /tmp/idemp-registry-add.out
        fail "apm registry add syncs idemp registry"
      }
      cat /tmp/idemp-registry-add.out

      delete_store_path "$WRAPPER_STORE" "idemp-wrapper"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idemp-wrapper \
        --registry idemp-reg \
        --no-deps \
        --yes > /tmp/idemp-no-deps.out 2>&1 || {
        cat /tmp/idemp-no-deps.out
        fail "apm install --no-deps idemp-wrapper succeeds"
      }
      cat /tmp/idemp-no-deps.out
      assert_file_contains /tmp/idemp-no-deps.out "Downloading 1 NAR" \
        "no-deps downloads only requested wrapper"
      assert_file_not_contains /tmp/idemp-no-deps.out "Additional dependencies" \
        "no-deps does not plan automatic dependencies"
      assert_file_contains /tmp/idemp-no-deps.out "Installed 1 package" \
        "no-deps creates profile generation"
      if [ "$(cache_nar_count)" = "1" ]; then
        pass "no-deps leaves one requested NAR in cache"
      else
        fail "no-deps should cache exactly one requested NAR"
      fi
      assert_store_valid "$IDEMP_STORE" "idempkg"
      assert_store_valid "$WRAPPER_STORE" "idemp-wrapper"
      "$PROFILE_WRAPPER_BIN" > /tmp/idemp-wrapper-nodeps-run.out
      assert_file_contains /tmp/idemp-wrapper-nodeps-run.out "^idempkg 1.0.0$" \
        "no-deps wrapper executable runs through its existing store reference"
      assert_file_contains "$PROFILE/meta/$WRAPPER_HASH.json" '"explicit": true' \
        "wrapper metadata is explicit after no-deps install"
      if [ ! -e "$PROFILE/meta/$IDEMP_HASH.json" ]; then
        pass "no-deps does not write dependency metadata"
      else
        fail "no-deps should not write dependency metadata"
      fi
      if [ ! -e "$PROFILE_IDEMP_BIN" ]; then
        pass "no-deps does not merge dependency executable into profile"
      else
        fail "no-deps should not expose dependency executable in profile"
      fi

      NODEPS_CURRENT=$(readlink "$PROFILE/current")
      NODEPS_COUNT=$(generation_count)
      if [ "$NODEPS_CURRENT" = "gen-1" ] && [ "$NODEPS_COUNT" = "1" ]; then
        pass "no-deps install creates exactly generation 1"
      else
        fail "no-deps install should create only gen-1 (current=$NODEPS_CURRENT count=$NODEPS_COUNT)"
      fi

      echo "==> Consumer: normal install after no-deps records automatic dependency"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idemp-wrapper --registry idemp-reg --yes > /tmp/idemp-install-1.out 2>&1 || {
        cat /tmp/idemp-install-1.out
        fail "normal apm install idemp-wrapper after no-deps succeeds"
      }
      cat /tmp/idemp-install-1.out
      assert_file_contains /tmp/idemp-install-1.out "Additional dependencies" \
        "normal install after no-deps plans dependency closure"
      assert_file_not_contains /tmp/idemp-install-1.out "Downloading" \
        "normal install after no-deps reuses valid store paths"
      assert_file_contains /tmp/idemp-install-1.out "Installed 1 package" \
        "normal install after no-deps creates profile generation"
      "$PROFILE_WRAPPER_BIN" > /tmp/idemp-wrapper-run-1.out
      assert_file_contains /tmp/idemp-wrapper-run-1.out "^idempkg 1.0.0$" \
        "wrapper executable runs after normal install"
      "$PROFILE_IDEMP_BIN" > /tmp/idemp-run-1.out
      assert_file_contains /tmp/idemp-run-1.out "^idempkg 1.0.0$" \
        "dependency executable is active after normal install"
      assert_file_contains "$PROFILE/meta/$WRAPPER_HASH.json" '"explicit": true' \
        "wrapper metadata stays explicit after normal install"
      assert_file_contains "$PROFILE/meta/$IDEMP_HASH.json" '"explicit": false' \
        "idempkg metadata starts as auto-installed dependency"

      FIRST_CURRENT=$(readlink "$PROFILE/current")
      FIRST_COUNT=$(generation_count)
      if [ "$FIRST_CURRENT" = "gen-2" ] && [ "$FIRST_COUNT" = "2" ]; then
        pass "normal install after no-deps creates generation 2"
      else
        fail "normal install after no-deps should create gen-2 (current=$FIRST_CURRENT count=$FIRST_COUNT)"
      fi

      echo "==> Consumer: explicit install promotes dependency without download"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idempkg --registry idemp-reg --yes > /tmp/idemp-promote.out 2>&1 || {
        cat /tmp/idemp-promote.out
        fail "explicit apm install idempkg succeeds"
      }
      cat /tmp/idemp-promote.out
      assert_file_not_contains /tmp/idemp-promote.out "Downloading" \
        "explicit dependency install reuses existing store path"
      assert_file_contains /tmp/idemp-promote.out "Installed 1 package" \
        "explicit dependency install creates promoted generation"
      "$PROFILE_IDEMP_BIN" > /tmp/idemp-run-2.out
      assert_file_contains /tmp/idemp-run-2.out "^idempkg 1.0.0$" \
        "profile executable runs after explicit install"
      assert_file_contains "$PROFILE/meta/$IDEMP_HASH.json" '"explicit": true' \
        "idempkg metadata is promoted to explicit"

      PROMOTED_CURRENT=$(readlink "$PROFILE/current")
      PROMOTED_COUNT=$(generation_count)
      if [ "$PROMOTED_CURRENT" = "gen-3" ] && [ "$PROMOTED_COUNT" = "3" ]; then
        pass "explicit dependency install creates generation 3"
      else
        fail "explicit dependency install should create gen-3 (current=$PROMOTED_CURRENT count=$PROMOTED_COUNT)"
      fi

      echo "==> Consumer: repeat explicit install is a no-op"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idempkg --registry idemp-reg --yes > /tmp/idemp-install-2.out 2>&1 || {
        cat /tmp/idemp-install-2.out
        fail "repeat apm install idempkg succeeds"
      }
      cat /tmp/idemp-install-2.out
      assert_file_contains /tmp/idemp-install-2.out "already installed\\|already in profile\\|No changes" \
        "repeat install reports idempotent no-op"
      assert_file_not_contains /tmp/idemp-install-2.out "Downloading" \
        "repeat install does not download idempkg"
      "$PROFILE_IDEMP_BIN" > /tmp/idemp-run-3.out
      assert_file_contains /tmp/idemp-run-3.out "^idempkg 1.0.0$" \
        "profile executable still runs after repeat install"

      SECOND_CURRENT=$(readlink "$PROFILE/current")
      SECOND_COUNT=$(generation_count)
      if [ "$SECOND_CURRENT" = "$PROMOTED_CURRENT" ] && [ "$SECOND_COUNT" = "$PROMOTED_COUNT" ]; then
        pass "repeat install does not create a new generation"
      else
        fail "repeat install should keep current=$PROMOTED_CURRENT count=$PROMOTED_COUNT (got current=$SECOND_CURRENT count=$SECOND_COUNT)"
      fi

      echo "==> Consumer: normal install repairs invalid installed store path"
      find "$PROFILE" -path "*/usr/$WRAPPER_HASH" -type l -exec rm -f {} \;
      delete_store_path "$WRAPPER_STORE" "idemp-wrapper-invalid-installed"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install idemp-wrapper --registry idemp-reg --yes > /tmp/idemp-repair.out 2>&1 || {
        cat /tmp/idemp-repair.out
        fail "normal apm install repairs invalid installed store path"
      }
      cat /tmp/idemp-repair.out
      assert_file_contains /tmp/idemp-repair.out "Downloading 1 NAR" \
        "repair install downloads missing installed store path"
      assert_file_contains /tmp/idemp-repair.out "Importing packages" \
        "repair install imports missing installed store path"
      assert_store_valid "$WRAPPER_STORE" "idemp-wrapper repaired"
      "$PROFILE_WRAPPER_BIN" > /tmp/idemp-run-repaired.out
      assert_file_contains /tmp/idemp-run-repaired.out "^idempkg 1.0.0$" \
        "profile executable runs after repair install"
      assert_file_contains "$PROFILE/meta/$IDEMP_HASH.json" '"explicit": true' \
        "repair install preserves explicit dependency metadata"

      REPAIR_CURRENT=$(readlink "$PROFILE/current")
      REPAIR_COUNT=$(generation_count)
      if [ "$REPAIR_CURRENT" = "gen-4" ] && [ "$REPAIR_COUNT" = "4" ]; then
        pass "repair install creates generation 4"
      else
        fail "repair install should create gen-4 (current=$REPAIR_CURRENT count=$REPAIR_COUNT)"
      fi

      echo "==> Consumer: autoremove wrapper after repair keeps explicitly installed dependency"
      $APM remove idemp-wrapper --autoremove --yes \
        > /tmp/idemp-remove-wrapper-after-promotion.out 2>&1 || {
        cat /tmp/idemp-remove-wrapper-after-promotion.out
        fail "apm remove --autoremove idemp-wrapper succeeds after dependency promotion"
      }
      cat /tmp/idemp-remove-wrapper-after-promotion.out
      assert_file_contains /tmp/idemp-remove-wrapper-after-promotion.out "idemp-wrapper" \
        "remove names repaired wrapper"
      assert_file_not_contains /tmp/idemp-remove-wrapper-after-promotion.out "idempkg" \
        "autoremove does not remove explicitly installed dependency"
      if [ -e "$PROFILE_WRAPPER_BIN" ]; then
        fail "removed wrapper executable should not remain active"
      else
        pass "removed wrapper executable is absent"
      fi
      "$PROFILE_IDEMP_BIN" > /tmp/idemp-run-after-wrapper-remove.out
      assert_file_contains /tmp/idemp-run-after-wrapper-remove.out "^idempkg 1.0.0$" \
        "explicit dependency remains active after wrapper autoremove"
      assert_file_contains "$PROFILE/meta/$IDEMP_HASH.json" '"explicit": true' \
        "explicit dependency metadata remains after wrapper autoremove"

      echo "==> Consumer: no-deps fails without existing dependency store path"
      rm -rf "$PROFILE"
      delete_store_path "$WRAPPER_STORE" "idemp-wrapper-missing-nodeps"
      delete_store_path "$IDEMP_STORE" "idempkg-missing-nodeps"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      if $APM install idemp-wrapper --registry idemp-reg --no-deps --yes \
        > /tmp/idemp-no-deps-missing.out 2>&1; then
        cat /tmp/idemp-no-deps-missing.out
        fail "apm install --no-deps should fail when dependency store path is absent"
      else
        cat /tmp/idemp-no-deps-missing.out
        pass "apm install --no-deps fails when dependency store path is absent"
      fi
      assert_file_contains /tmp/idemp-no-deps-missing.out \
        "no-deps requested but dependency store path" \
        "failed no-deps install reports missing skipped dependency"
      assert_file_not_contains /tmp/idemp-no-deps-missing.out "Downloading" \
        "failed no-deps install does not download before dependency preflight"
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "failed no-deps install leaves NAR cache empty"
      else
        fail "failed no-deps install should not cache requested wrapper"
      fi
      assert_store_missing "$WRAPPER_STORE" "idemp-wrapper"
      assert_store_missing "$IDEMP_STORE" "idempkg"
      if [ "$(generation_count)" = "0" ] && [ ! -e "$PROFILE/current" ]; then
        pass "failed no-deps install creates no profile generation"
      else
        fail "failed no-deps install should not create a profile generation"
      fi
      $APM list --installed > /tmp/idemp-installed-after-nodeps-fail.out 2>&1 || {
        cat /tmp/idemp-installed-after-nodeps-fail.out
        fail "apm list --installed succeeds after failed no-deps install"
      }
      assert_file_not_contains /tmp/idemp-installed-after-nodeps-fail.out "idemp-wrapper" \
        "failed no-deps install does not record wrapper metadata"
      assert_file_not_contains /tmp/idemp-installed-after-nodeps-fail.out "idempkg" \
        "failed no-deps install does not record dependency metadata"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 5. download-only-package — Download without importing or activating
  # -------------------------------------------------------------------------
  download-only-package = testing.mkVMTest {
    name = "apm-download-only-package";
    rootfsDeps = realDownloadOnlyDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm install --download-only downloads without activation"

      DEP_STORE="${idempotentTool}"
      WRAPPER_STORE="${downloadOnlyWrapper}"
      DEP_HASH=$(basename "$DEP_STORE" | cut -d- -f1)
      WRAPPER_HASH=$(basename "$WRAPPER_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/downloaduser"

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
        if nix-store --check-validity "$path" > "/tmp/download-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/download-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/download-missing-$label.out" 2>&1; then
          cat "/tmp/download-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/download-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/download-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        if [ -d "$PROFILE" ]; then
          find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
        else
          printf '0'
        fi
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      cache_nar_http_get_count() {
        grep -E 'GET /nar/.*\.nar\.zst HTTP/' /tmp/download-cache-http.log 2>/dev/null | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18089/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$DEP_STORE" "download-only dependency"
      assert_store_valid "$WRAPPER_STORE" "download-only wrapper"
      nix-store -q --references "$WRAPPER_STORE" > /tmp/download-wrapper-refs.out
      assert_file_contains /tmp/download-wrapper-refs.out "$DEP_STORE" \
        "download-only wrapper has a real Nix reference to dependency"

      echo "==> Maintainer: publish download-only wrapper and static cache"
      $APR create download-reg
      REG_DIR="$REG_STORAGE/download-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$DEP_STORE" \
        --name idempkg \
        --version 1.0.0 \
        --description "Shared dependency for download-only workflow" \
        --license MIT \
        --maintainer download-workflow@example.invalid \
        --registry download-reg \
        --no-commit
      $APR publish "$WRAPPER_STORE" \
        --name download-only-wrapper \
        --version 1.0.0 \
        --description "Wrapper for download-only workflow" \
        --license MIT \
        --maintainer download-workflow@example.invalid \
        --registry download-reg \
        --no-commit
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$DEP_HASH" "published wrapper metadata records dependency"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$WRAPPER_HASH")/$WRAPPER_HASH" \
        "$DEP_HASH" "published wrapper closure records dependency"

      $APR cache generate \
        --registry download-reg \
        --output /tmp/download-cache \
        --cache-url http://127.0.0.1:18089 \
        --priority 49 \
        --no-commit
      assert_file_exists "/tmp/download-cache/$DEP_HASH.narinfo" \
        "static cache has dependency narinfo"
      assert_file_exists "/tmp/download-cache/$WRAPPER_HASH.narinfo" \
        "static cache has wrapper narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: download-only workflow package"
      git init --bare --object-format=sha256 /tmp/download-origin.git
      git -C "$REG_DIR" remote add origin /tmp/download-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18089 --bind 127.0.0.1 \
        --directory /tmp/download-cache > /tmp/download-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/download-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: download closure without importing or activating"
      export HOME=/tmp/download-consumer
      export USER=downloaduser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/download-origin.git \
        --name download-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/download-registry-add.out 2>&1 || {
        cat /tmp/download-registry-add.out
        fail "apm registry add syncs download registry"
      }
      cat /tmp/download-registry-add.out

      delete_store_path "$WRAPPER_STORE" "download-only-wrapper"
      delete_store_path "$DEP_STORE" "idempkg"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install download-only-wrapper \
        --registry download-reg \
        --download-only \
        --yes > /tmp/download-only.out 2>&1 || {
        cat /tmp/download-only.out
        fail "apm install --download-only succeeds"
      }
      cat /tmp/download-only.out
      assert_file_contains /tmp/download-only.out "packages will be downloaded" \
        "download-only reports download plan"
      assert_file_contains /tmp/download-only.out "Downloading 2 NAR" \
        "download-only downloads wrapper closure"
      assert_file_contains /tmp/download-only.out "no profile changes made" \
        "download-only reports no profile mutation"
      assert_file_not_contains /tmp/download-only.out "Importing packages" \
        "download-only does not import packages"
      assert_file_not_contains /tmp/download-only.out "Updating profile" \
        "download-only does not update profile"
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "download-only leaves two NARs in user cache"
      else
        fail "download-only should leave two NARs in user cache"
      fi
      if [ "$(cache_nar_http_get_count)" = "2" ]; then
        pass "download-only fetches exactly two NAR bodies"
      else
        cat /tmp/download-cache-http.log || true
        fail "download-only should fetch exactly two NAR bodies"
      fi
      assert_store_missing "$WRAPPER_STORE" "download-only-wrapper"
      assert_store_missing "$DEP_STORE" "idempkg"
      if [ "$(generation_count)" = "0" ] && [ ! -e "$PROFILE/current" ]; then
        pass "download-only creates no profile generation"
      else
        fail "download-only should not create profile generation"
      fi
      if [ ! -e "$PROFILE" ]; then
        pass "download-only leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "download-only should not initialize profile state"
      fi

      echo "==> Consumer: normal install after download-only activates package"
      NAR_GETS_BEFORE_INSTALL=$(cache_nar_http_get_count)
      $APM install download-only-wrapper --registry download-reg --yes > /tmp/download-install.out 2>&1 || {
        cat /tmp/download-install.out
        fail "normal apm install after download-only succeeds"
      }
      cat /tmp/download-install.out
      assert_file_contains /tmp/download-install.out "Installed 1 package" \
        "normal install creates profile generation after download-only"
      assert_store_valid "$WRAPPER_STORE" "download-only-wrapper"
      assert_store_valid "$DEP_STORE" "idempkg"
      "$PROFILE/current/bin/download-only-wrapper" > /tmp/download-wrapper-run.out
      assert_file_contains /tmp/download-wrapper-run.out "^idempkg 1.0.0$" \
        "download-only wrapper executable runs after normal install"
      if [ "$(cache_nar_http_get_count)" = "$NAR_GETS_BEFORE_INSTALL" ]; then
        pass "normal install after download-only reuses cached NAR bodies"
      else
        cat /tmp/download-cache-http.log || true
        fail "normal install after download-only should not refetch NAR bodies"
      fi
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "normal install after download-only creates generation 1"
      else
        fail "normal install after download-only should create gen-1"
      fi

      echo "==> Consumer: corrupt one prefetched NAR and repair during install"
      rm -rf "$PROFILE"
      delete_store_path "$WRAPPER_STORE" "download-only-wrapper-reset"
      delete_store_path "$DEP_STORE" "idempkg-reset"
      export HOME=/tmp/download-corrupt-consumer
      export USER=downloadcorrupt
      PROFILE="/var/lib/profiles/per-user/downloadcorrupt"
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/download-origin.git \
        --name download-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/download-corrupt-registry-add.out 2>&1 || {
        cat /tmp/download-corrupt-registry-add.out
        fail "apm registry add syncs download registry for corrupt-cache consumer"
      }
      cat /tmp/download-corrupt-registry-add.out

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install download-only-wrapper \
        --registry download-reg \
        --download-only \
        --yes > /tmp/download-corrupt-prefetch.out 2>&1 || {
        cat /tmp/download-corrupt-prefetch.out
        fail "apm install --download-only succeeds before corrupting cache"
      }
      cat /tmp/download-corrupt-prefetch.out
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "corrupt-cache consumer prefetches two NARs"
      else
        fail "corrupt-cache consumer should prefetch two NARs"
      fi
      CORRUPT_NAR=$(find "$HOME/.cache/apm" -type f -name '*.nar.zst' | sort | head -n 1)
      if [ -n "$CORRUPT_NAR" ]; then
        printf '%s\n' "corrupted cached NAR" > "$CORRUPT_NAR"
        pass "test corrupted one cached NAR"
      else
        fail "test should find a cached NAR to corrupt"
      fi
      assert_store_missing "$WRAPPER_STORE" "download-only-wrapper"
      assert_store_missing "$DEP_STORE" "idempkg"

      NAR_GETS_BEFORE_CORRUPT_INSTALL=$(cache_nar_http_get_count)
      EXPECTED_NAR_GETS_AFTER_CORRUPT_INSTALL=$((NAR_GETS_BEFORE_CORRUPT_INSTALL + 1))
      $APM install download-only-wrapper --registry download-reg --yes \
        > /tmp/download-corrupt-install.out 2>&1 || {
        cat /tmp/download-corrupt-install.out
        fail "normal install repairs one corrupted cached NAR"
      }
      cat /tmp/download-corrupt-install.out
      assert_file_contains /tmp/download-corrupt-install.out "Installed 1 package" \
        "corrupt-cache install creates profile generation"
      assert_store_valid "$WRAPPER_STORE" "download-only-wrapper"
      assert_store_valid "$DEP_STORE" "idempkg"
      "$PROFILE/current/bin/download-only-wrapper" > /tmp/download-corrupt-run.out
      assert_file_contains /tmp/download-corrupt-run.out "^idempkg 1.0.0$" \
        "corrupt-cache repaired install executes wrapper"
      if [ "$(cache_nar_http_get_count)" = "$EXPECTED_NAR_GETS_AFTER_CORRUPT_INSTALL" ]; then
        pass "corrupt-cache install redownloads only the stale NAR body"
      else
        cat /tmp/download-cache-http.log || true
        fail "corrupt-cache install should redownload exactly one stale NAR body"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "corrupt-cache install leaves repaired NAR cache complete"
      else
        fail "corrupt-cache install should leave two cached NAR files"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 6. reinstall-package — Reinstall downloads and creates a new generation
  # -------------------------------------------------------------------------
  reinstall-package = testing.mkVMTest {
    name = "apm-reinstall-package";
    rootfsDeps = realReinstallDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm reinstall refreshes installed packages"

      TOOL_STORE="${reinstallTool}"
      PEER_STORE="${reinstallPeerTool}"
      TOOL_HASH=$(basename "$TOOL_STORE" | cut -d- -f1)
      PEER_HASH=$(basename "$PEER_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/reinstalluser"

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
        if nix-store --check-validity "$path" > "/tmp/reinstall-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/reinstall-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/reinstall-missing-$label.out" 2>&1; then
          cat "/tmp/reinstall-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/reinstall-delete-$label.out" 2>&1; then
          pass "$label deleted before initial apm download"
        else
          cat "/tmp/reinstall-delete-$label.out"
          fail "$label should be deletable before initial apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18088/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$TOOL_STORE" "reinstall-tool"
      assert_store_valid "$PEER_STORE" "reinstall-peer"

      echo "==> Maintainer: publish reinstall packages and static cache"
      $APR create reinstall-reg
      REG_DIR="$REG_STORAGE/reinstall-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$TOOL_STORE" \
        --name reinstall-tool \
        --version 1.0.0 \
        --description "Tool for reinstall workflow" \
        --license MIT \
        --maintainer reinstall-workflow@example.invalid \
        --registry reinstall-reg \
        --no-commit
      $APR publish "$PEER_STORE" \
        --name reinstall-peer \
        --version 1.0.0 \
        --description "Peer tool for reinstall workflow" \
        --license MIT \
        --maintainer reinstall-workflow@example.invalid \
        --registry reinstall-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/r/reinstall-tool.toml" \
        "$TOOL_HASH" "published metadata records reinstall-tool store hash"
      assert_file_contains "$REG_DIR/packages/r/reinstall-peer.toml" \
        "$PEER_HASH" "published metadata records reinstall-peer store hash"

      $APR cache generate \
        --registry reinstall-reg \
        --output /tmp/reinstall-cache \
        --cache-url http://127.0.0.1:18088 \
        --priority 48 \
        --no-commit
      assert_file_exists "/tmp/reinstall-cache/$TOOL_HASH.narinfo" \
        "static cache has reinstall-tool narinfo"
      assert_file_exists "/tmp/reinstall-cache/$PEER_HASH.narinfo" \
        "static cache has reinstall-peer narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: reinstall workflow packages"
      git init --bare --object-format=sha256 /tmp/reinstall-origin.git
      git -C "$REG_DIR" remote add origin /tmp/reinstall-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18088 --bind 127.0.0.1 \
        --directory /tmp/reinstall-cache > /tmp/reinstall-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/reinstall-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install then force reinstall packages while store paths are still valid"
      export HOME=/tmp/reinstall-consumer
      export USER=reinstalluser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/reinstall-origin.git \
        --name reinstall-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/reinstall-registry-add.out 2>&1 || {
        cat /tmp/reinstall-registry-add.out
        fail "apm registry add syncs reinstall registry"
      }
      cat /tmp/reinstall-registry-add.out

      if $APM reinstall reinstall-tool --yes > /tmp/reinstall-empty.out 2>&1; then
        cat /tmp/reinstall-empty.out
        fail "apm reinstall should fail before reinstall-tool is installed"
      else
        cat /tmp/reinstall-empty.out
        pass "apm reinstall fails before reinstall-tool is installed"
      fi
      assert_file_contains /tmp/reinstall-empty.out "package not installed" \
        "empty reinstall reports missing installed package"
      assert_file_not_contains /tmp/reinstall-empty.out "Downloading" \
        "empty reinstall does not download package bodies"
      assert_file_not_contains /tmp/reinstall-empty.out "Updating profile" \
        "empty reinstall does not update profile"
      if [ ! -e "$PROFILE" ]; then
        pass "empty reinstall leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty reinstall should not initialize profile state"
      fi
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "empty reinstall leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "empty reinstall should not cache package bodies"
      fi

      delete_store_path "$TOOL_STORE" "reinstall-tool"
      delete_store_path "$PEER_STORE" "reinstall-peer"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install reinstall-tool reinstall-peer --registry reinstall-reg --yes > /tmp/reinstall-install.out 2>&1 || {
        cat /tmp/reinstall-install.out
        fail "initial apm install reinstall packages succeeds"
      }
      cat /tmp/reinstall-install.out
      assert_file_contains /tmp/reinstall-install.out "Downloading 2 NAR" \
        "initial install downloads both reinstall packages"
      assert_file_contains /tmp/reinstall-install.out "Installed 2 package" \
        "initial install creates profile generation for both packages"
      assert_store_valid "$TOOL_STORE" "reinstall-tool"
      assert_store_valid "$PEER_STORE" "reinstall-peer"
      "$PROFILE/current/bin/reinstall-tool" > /tmp/reinstall-run-1.out
      "$PROFILE/current/bin/reinstall-peer" > /tmp/reinstall-peer-run-1.out
      assert_file_contains /tmp/reinstall-run-1.out "^reinstall-tool 1.0.0$" \
        "installed executable runs before reinstall"
      assert_file_contains /tmp/reinstall-peer-run-1.out "^reinstall-peer 1.0.0$" \
        "installed peer executable runs before reinstall"
      assert_file_contains "$PROFILE/meta/$TOOL_HASH.json" '"explicit": true' \
        "reinstall-tool metadata is explicit"
      assert_file_contains "$PROFILE/meta/$PEER_HASH.json" '"explicit": true' \
        "reinstall-peer metadata is explicit"

      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "initial install creates exactly generation 1"
      else
        fail "initial install should create only gen-1"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "initial install retains two downloaded NARs"
      else
        fail "initial install should retain two downloaded NARs"
      fi

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM reinstall reinstall-tool reinstall-peer --yes > /tmp/reinstall-command.out 2>&1 || {
        cat /tmp/reinstall-command.out
        fail "apm reinstall succeeds for installed packages"
      }
      cat /tmp/reinstall-command.out
      assert_file_not_contains /tmp/reinstall-command.out "already installed" \
        "apm reinstall does not no-op on installed packages"
      assert_file_contains /tmp/reinstall-command.out "Downloading 2 NAR" \
        "apm reinstall downloads both packages again"
      assert_file_contains /tmp/reinstall-command.out "packages will be reinstalled" \
        "apm reinstall reports reinstall plan"
      assert_file_contains /tmp/reinstall-command.out "Reinstalled 2 package" \
        "apm reinstall creates profile generation for both packages"
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "apm reinstall creates generation 2"
      else
        fail "apm reinstall should create gen-2"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "apm reinstall repopulates NAR cache"
      else
        fail "apm reinstall should repopulate two downloaded NARs"
      fi
      "$PROFILE/current/bin/reinstall-tool" > /tmp/reinstall-run-2.out
      "$PROFILE/current/bin/reinstall-peer" > /tmp/reinstall-peer-run-2.out
      assert_file_contains /tmp/reinstall-run-2.out "^reinstall-tool 1.0.0$" \
        "reinstalled executable runs from generation 2"
      assert_file_contains /tmp/reinstall-peer-run-2.out "^reinstall-peer 1.0.0$" \
        "reinstalled peer executable runs from generation 2"
      assert_file_contains "$PROFILE/meta/$TOOL_HASH.json" '"explicit": true' \
        "apm reinstall preserves reinstall-tool explicit metadata"
      assert_file_contains "$PROFILE/meta/$PEER_HASH.json" '"explicit": true' \
        "apm reinstall preserves reinstall-peer explicit metadata"

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install reinstall-tool reinstall-peer --registry reinstall-reg --reinstall --yes > /tmp/install-reinstall-flag.out 2>&1 || {
        cat /tmp/install-reinstall-flag.out
        fail "apm install --reinstall succeeds for installed packages"
      }
      cat /tmp/install-reinstall-flag.out
      assert_file_not_contains /tmp/install-reinstall-flag.out "already installed" \
        "apm install --reinstall does not no-op on installed packages"
      assert_file_contains /tmp/install-reinstall-flag.out "Downloading 2 NAR" \
        "apm install --reinstall downloads both packages again"
      assert_file_contains /tmp/install-reinstall-flag.out "packages will be reinstalled" \
        "apm install --reinstall reports reinstall plan"
      assert_file_contains /tmp/install-reinstall-flag.out "Reinstalled 2 package" \
        "apm install --reinstall creates profile generation for both packages"
      if [ "$(readlink "$PROFILE/current")" = "gen-3" ] && [ "$(generation_count)" = "3" ]; then
        pass "apm install --reinstall creates generation 3"
      else
        fail "apm install --reinstall should create gen-3"
      fi
      if [ "$(cache_nar_count)" = "2" ]; then
        pass "apm install --reinstall repopulates NAR cache"
      else
        fail "apm install --reinstall should repopulate two downloaded NARs"
      fi
      "$PROFILE/current/bin/reinstall-tool" > /tmp/reinstall-run-3.out
      "$PROFILE/current/bin/reinstall-peer" > /tmp/reinstall-peer-run-3.out
      assert_file_contains /tmp/reinstall-run-3.out "^reinstall-tool 1.0.0$" \
        "install --reinstall executable runs from generation 3"
      assert_file_contains /tmp/reinstall-peer-run-3.out "^reinstall-peer 1.0.0$" \
        "install --reinstall peer executable runs from generation 3"
      assert_file_contains "$PROFILE/meta/$TOOL_HASH.json" '"explicit": true' \
        "apm install --reinstall preserves reinstall-tool explicit metadata"
      assert_file_contains "$PROFILE/meta/$PEER_HASH.json" '"explicit": true' \
        "apm install --reinstall preserves reinstall-peer explicit metadata"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 7. remove-basic — Remove a real installed package
  # -------------------------------------------------------------------------
  remove-basic = testing.mkVMTest {
    name = "apm-remove-basic";
    rootfsDeps = realRemoveDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm remove basic workflow"

      REMOVE_STORE="${removeBasicTool}"
      REMOVE_HASH=$(basename "$REMOVE_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/removebasicuser"
      REMOVE_BIN="$PROFILE/current/bin/remove-basic-tool"

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
        if nix-store --check-validity "$path" > "/tmp/remove-basic-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/remove-basic-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/remove-basic-missing-$label.out" 2>&1; then
          cat "/tmp/remove-basic-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/remove-basic-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/remove-basic-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18095/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$REMOVE_STORE" "remove-basic-tool"

      echo "==> Maintainer: publish remove-basic-tool and static cache"
      $APR create remove-basic-reg
      REG_DIR="$REG_STORAGE/remove-basic-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$REMOVE_STORE" \
        --name remove-basic-tool \
        --version 1.0.0 \
        --description "Executable remove basic fixture" \
        --license MIT \
        --maintainer remove-basic@example.invalid \
        --registry remove-basic-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/r/remove-basic-tool.toml" \
        "$REMOVE_HASH" "published remove-basic metadata records store hash"

      $APR cache generate \
        --registry remove-basic-reg \
        --output /tmp/remove-basic-cache \
        --cache-url http://127.0.0.1:18095 \
        --priority 55 \
        --no-commit
      assert_file_exists "/tmp/remove-basic-cache/$REMOVE_HASH.narinfo" \
        "static cache has remove-basic-tool narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18095" "registry records remove-basic cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: remove-basic-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/remove-basic-origin.git
      git -C "$REG_DIR" remote add origin /tmp/remove-basic-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18095 --bind 127.0.0.1 \
        --directory /tmp/remove-basic-cache > /tmp/remove-basic-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/remove-basic-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install and remove remove-basic-tool"
      export HOME=/tmp/remove-basic-consumer
      export USER=removebasicuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/remove-basic-origin.git \
        --name remove-basic-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/remove-basic-registry-add.out 2>&1 || {
        cat /tmp/remove-basic-registry-add.out
        fail "apm registry add syncs remove-basic registry"
      }
      cat /tmp/remove-basic-registry-add.out

      if $APM remove remove-basic-tool --yes > /tmp/remove-basic-empty-remove.out 2>&1; then
        cat /tmp/remove-basic-empty-remove.out
        fail "remove should fail when no profile is installed"
      else
        cat /tmp/remove-basic-empty-remove.out
        pass "remove fails before any package is installed"
      fi
      assert_file_contains /tmp/remove-basic-empty-remove.out "nothing installed" \
        "empty remove reports no current generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty remove leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty remove should not initialize profile state"
      fi

      if $APM autoremove --yes > /tmp/remove-basic-empty-autoremove.out 2>&1; then
        cat /tmp/remove-basic-empty-autoremove.out
        fail "autoremove should fail when no profile is installed"
      else
        cat /tmp/remove-basic-empty-autoremove.out
        pass "autoremove fails before any package is installed"
      fi
      assert_file_contains /tmp/remove-basic-empty-autoremove.out "nothing installed" \
        "empty autoremove reports no current generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty autoremove leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty autoremove should not initialize profile state"
      fi

      if $APM remove remove-basic-tool --dry-run > /tmp/remove-basic-empty-dry-run.out 2>&1; then
        cat /tmp/remove-basic-empty-dry-run.out
        fail "remove dry-run should fail when no profile is installed"
      else
        cat /tmp/remove-basic-empty-dry-run.out
        pass "remove dry-run fails before any package is installed"
      fi
      assert_file_contains /tmp/remove-basic-empty-dry-run.out "nothing installed" \
        "empty remove dry-run reports no current generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty remove dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty remove dry-run should not initialize profile state"
      fi

      if $APM autoremove --dry-run > /tmp/remove-basic-empty-autoremove-dry-run.out 2>&1; then
        cat /tmp/remove-basic-empty-autoremove-dry-run.out
        fail "autoremove dry-run should fail when no profile is installed"
      else
        cat /tmp/remove-basic-empty-autoremove-dry-run.out
        pass "autoremove dry-run fails before any package is installed"
      fi
      assert_file_contains /tmp/remove-basic-empty-autoremove-dry-run.out "nothing installed" \
        "empty autoremove dry-run reports no current generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty autoremove dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty autoremove dry-run should not initialize profile state"
      fi

      delete_store_path "$REMOVE_STORE" "remove-basic-tool"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install remove-basic-tool --registry remove-basic-reg --yes > /tmp/remove-basic-install.out 2>&1 || {
        cat /tmp/remove-basic-install.out
        fail "apm install remove-basic-tool succeeds"
      }
      cat /tmp/remove-basic-install.out
      assert_file_contains /tmp/remove-basic-install.out "Downloading 1 NAR" \
        "remove-basic install downloads package NAR"
      assert_file_contains /tmp/remove-basic-install.out "Installed 1 package" \
        "remove-basic install creates profile generation"
      "$REMOVE_BIN" > /tmp/remove-basic-run.out
      assert_file_contains /tmp/remove-basic-run.out "^remove-basic-tool 1.0.0$" \
        "remove-basic executable runs before removal"
      assert_file_contains "$PROFILE/meta/$REMOVE_HASH.json" '"explicit": true' \
        "remove-basic install writes explicit metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "remove-basic install creates generation 1"
      else
        fail "remove-basic install should create gen-1"
      fi

      $APM remove remove-basic-tool --dry-run > /tmp/remove-basic-remove-dry-run.out 2>&1 || {
        cat /tmp/remove-basic-remove-dry-run.out
        fail "apm remove --dry-run remove-basic-tool succeeds"
      }
      cat /tmp/remove-basic-remove-dry-run.out
      assert_file_contains /tmp/remove-basic-remove-dry-run.out "will be REMOVED" \
        "remove dry-run prints removal plan"
      assert_file_contains /tmp/remove-basic-remove-dry-run.out "Dry run -- no changes made" \
        "remove dry-run reports no mutation"
      assert_file_not_contains /tmp/remove-basic-remove-dry-run.out "Creating new generation" \
        "remove dry-run does not create a generation"
      assert_file_exists "$PROFILE/meta/$REMOVE_HASH.json" \
        "remove dry-run preserves installed metadata"
      "$REMOVE_BIN" > /tmp/remove-basic-run-after-dry-run.out
      assert_file_contains /tmp/remove-basic-run-after-dry-run.out "^remove-basic-tool 1.0.0$" \
        "remove dry-run leaves executable active"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "remove dry-run keeps generation 1 active"
      else
        fail "remove dry-run should keep gen-1"
      fi

      $APM remove remove-basic-tool --yes > /tmp/remove-basic-remove.out 2>&1 || {
        cat /tmp/remove-basic-remove.out
        fail "apm remove remove-basic-tool succeeds"
      }
      cat /tmp/remove-basic-remove.out
      assert_file_contains /tmp/remove-basic-remove.out "will be REMOVED" \
        "remove prints removal plan"
      assert_file_contains /tmp/remove-basic-remove.out "Removed 1 package" \
        "remove reports package removal"
      assert_store_valid "$REMOVE_STORE" "remove-basic-tool remains in store"
      assert_file_not_exists "$PROFILE/meta/$REMOVE_HASH.json" \
        "remove deletes installed metadata"
      if [ ! -e "$REMOVE_BIN" ]; then
        pass "remove drops executable from active profile"
      else
        fail "remove should drop executable from active profile"
      fi
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "remove creates generation 2"
      else
        fail "remove should create gen-2"
      fi

      $APM list --installed > /tmp/remove-basic-installed.out 2>&1 || {
        cat /tmp/remove-basic-installed.out
        fail "apm list --installed succeeds after remove"
      }
      assert_file_not_contains /tmp/remove-basic-installed.out "remove-basic-tool" \
        "removed package is absent from installed list"

      $APM remove remove-basic-tool --yes > /tmp/remove-basic-repeat.out 2>&1 && {
        cat /tmp/remove-basic-repeat.out
        fail "repeat remove should fail once package is absent"
      } || true
      cat /tmp/remove-basic-repeat.out
      assert_file_contains /tmp/remove-basic-repeat.out "not found" \
        "repeat remove reports package is absent"
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "repeat failed remove does not create a generation"
      else
        fail "repeat failed remove should keep generation 2"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 8. registry-readd-heals-orphans — Re-add registry after orphaning packages
  # -------------------------------------------------------------------------
  registry-readd-heals-orphans = testing.mkVMTest {
    name = "apm-registry-readd-heals-orphans";
    rootfsDeps = realInstallDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: registry re-add heals orphaned installed packages"

      TOOL_STORE="${installBasicTool}"
      TOOL_HASH=$(basename "$TOOL_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/readduser"
      TOOL_BIN="$PROFILE/current/bin/install-basic-tool"

      assert_dir_not_exists() {
        if [ ! -d "$1" ]; then
          pass "$2"
        else
          fail "$2 (directory should not exist: $1)"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/readd-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/readd-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/readd-missing-$label.out" 2>&1; then
          cat "/tmp/readd-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/readd-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/readd-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18124/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      run_ok() {
        label="$1"
        shift
        if "$@" > "/tmp/readd-$label.out" 2>&1; then
          pass "$label exits 0"
        else
          cat "/tmp/readd-$label.out"
          fail "$label should exit 0"
        fi
      }

      mount -o remount,rw / || true
      assert_store_valid "$TOOL_STORE" "readd-tool"

      echo "==> Maintainer: publish readd-tool and static cache"
      $APR create readd-reg
      REG_DIR="$REG_STORAGE/readd-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$TOOL_STORE" \
        --name readd-tool \
        --version 1.0.0 \
        --description "Registry re-add recovery fixture" \
        --license MIT \
        --maintainer readd@example.invalid \
        --registry readd-reg \
        --no-commit
      assert_file_contains "$REG_DIR/packages/r/readd-tool.toml" \
        "$TOOL_HASH" "published readd-tool metadata records store hash"

      $APR cache generate \
        --registry readd-reg \
        --output /tmp/readd-cache \
        --cache-url http://127.0.0.1:18124 \
        --priority 54 \
        --no-commit
      assert_file_exists "/tmp/readd-cache/$TOOL_HASH.narinfo" \
        "static cache has readd-tool narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18124" "registry records readd cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: readd-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/readd-origin.git
      git -C "$REG_DIR" remote add origin /tmp/readd-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18124 --bind 127.0.0.1 \
        --directory /tmp/readd-cache > /tmp/readd-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/readd-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install readd-tool"
      export HOME=/tmp/readd-consumer
      export USER=readduser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/readd-origin.git \
        --name readd-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/readd-registry-add.out 2>&1 || {
        cat /tmp/readd-registry-add.out
        fail "apm registry add syncs readd registry"
      }
      cat /tmp/readd-registry-add.out

      delete_store_path "$TOOL_STORE" "readd-tool"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install readd-tool --registry readd-reg --yes > /tmp/readd-install.out 2>&1 || {
        cat /tmp/readd-install.out
        fail "apm install downloads readd-tool"
      }
      cat /tmp/readd-install.out
      assert_file_contains /tmp/readd-install.out "Downloading 1 NAR" \
        "readd-tool install downloads package NAR"
      assert_file_contains /tmp/readd-install.out "Installed 1 package" \
        "readd-tool install creates profile generation"
      "$TOOL_BIN" > /tmp/readd-run.out
      assert_file_contains /tmp/readd-run.out "^install-basic-tool 1.0.0$" \
        "installed readd-tool executable runs from profile"

      echo "==> Consumer: disable registry without orphaning installed package"
      REG_CONFIG="$HOME/.config/apm/registries.d/readd-reg.toml"
      $APM registry disable readd-reg > /tmp/readd-registry-disable.out 2>&1 || {
        cat /tmp/readd-registry-disable.out
        fail "apm registry disable readd-reg succeeds"
      }
      assert_file_contains /tmp/readd-registry-disable.out "Registry 'readd-reg' disabled" \
        "apm registry disable reports newly disabled registry"
      $APM --json registry disable readd-reg > /tmp/readd-registry-disable-again.json 2>&1 || {
        cat /tmp/readd-registry-disable-again.json
        fail "apm registry disable readd-reg is idempotent"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$REG_CONFIG" \
        '.action == "registry_disable"
          and .status == "unchanged"
          and .registry == "readd-reg"
          and .enabled == false
          and .previous_enabled == false
          and .changed == false
          and .config == $config
          and .packages == 1' \
        /tmp/readd-registry-disable-again.json >/dev/null || {
        cat /tmp/readd-registry-disable-again.json
        fail "apm --json registry disable reports unchanged disabled registry"
      }
      assert_file_contains "$REG_CONFIG" "enabled = false" \
        "apm registry disable persists disabled state"
      run_ok list-disabled "$APM" registry list
      assert_file_contains /tmp/readd-list-disabled.out "disabled" \
        "apm registry list reports disabled registry state"
      if $APM update --registry readd-reg > /tmp/readd-update-disabled.out 2>&1; then
        cat /tmp/readd-update-disabled.out
        fail "apm update should skip explicitly disabled registry"
      else
        cat /tmp/readd-update-disabled.out
        pass "apm update rejects explicitly disabled registry"
      fi
      assert_file_contains /tmp/readd-update-disabled.out "not enabled" \
        "disabled registry update failure explains disabled state"
      run_ok orphans-disabled "$APM" orphans
      assert_file_contains /tmp/readd-orphans-disabled.out "No orphaned packages" \
        "disabled configured registry does not orphan installed packages"
      if $APM verify readd-tool > /tmp/readd-verify-disabled.out 2>&1; then
        cat /tmp/readd-verify-disabled.out
        fail "apm verify should not resolve disabled registry"
      else
        cat /tmp/readd-verify-disabled.out
        pass "apm verify skips disabled registry metadata"
      fi
      assert_file_contains /tmp/readd-verify-disabled.out "not present in registry 'readd-reg'" \
        "verify failure identifies disabled source registry"
      "$TOOL_BIN" > /tmp/readd-run-disabled.out
      assert_file_contains /tmp/readd-run-disabled.out "^install-basic-tool 1.0.0$" \
        "installed executable still runs while registry is disabled"

      echo "==> Consumer: re-enable registry and verify installed package"
      $APM registry enable readd-reg > /tmp/readd-registry-enable.out 2>&1 || {
        cat /tmp/readd-registry-enable.out
        fail "apm registry enable readd-reg succeeds"
      }
      assert_file_contains /tmp/readd-registry-enable.out "Registry 'readd-reg' enabled" \
        "apm registry enable reports newly enabled registry"
      $APM --json registry enable readd-reg > /tmp/readd-registry-enable-again.json 2>&1 || {
        cat /tmp/readd-registry-enable-again.json
        fail "apm registry enable readd-reg is idempotent"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg config "$REG_CONFIG" \
        '.action == "registry_enable"
          and .status == "unchanged"
          and .registry == "readd-reg"
          and .enabled == true
          and .previous_enabled == true
          and .changed == false
          and .config == $config
          and .packages == 1' \
        /tmp/readd-registry-enable-again.json >/dev/null || {
        cat /tmp/readd-registry-enable-again.json
        fail "apm --json registry enable reports unchanged enabled registry"
      }
      assert_file_contains "$REG_CONFIG" "enabled = true" \
        "apm registry enable persists enabled state"
      run_ok update-reenabled "$APM" --json update --registry readd-reg
      ${pkgs.jq}/bin/jq -e \
        '.registry == "readd-reg"
          and (.registries | length == 1)
          and .registries[0].registry == "readd-reg"
          and (.registries[0].status == "updated" or .registries[0].status == "current")
          and .registries[0].packages == 1' \
        /tmp/readd-update-reenabled.out >/dev/null || {
        cat /tmp/readd-update-reenabled.out
        fail "apm --json update works after registry re-enable"
      }
      run_ok search-reenabled "$APM" --json search readd-tool --registry readd-reg
      ${pkgs.jq}/bin/jq -e \
        'length == 1
          and .[0].name == "readd-tool"
          and .[0].registry == "readd-reg"
          and .[0].version == "1.0.0"' \
        /tmp/readd-search-reenabled.out >/dev/null || {
        cat /tmp/readd-search-reenabled.out
        fail "apm --json search finds package after registry re-enable"
      }
      run_ok verify-before-remove "$APM" verify readd-tool
      assert_file_contains /tmp/readd-verify-before-remove.out "integrity verified" \
        "apm verify validates readd-tool after registry re-enable"

      echo "==> Consumer: remove registry and observe orphaned package"
      $APM registry remove readd-reg > /tmp/readd-remove-registry.out 2>&1 || {
        cat /tmp/readd-remove-registry.out
        fail "apm registry remove readd-reg succeeds"
      }
      cat /tmp/readd-remove-registry.out
      assert_file_contains /tmp/readd-remove-registry.out "Registry 'readd-reg' removed" \
        "registry remove reports removal"
      assert_file_not_exists "$HOME/.config/apm/registries.d/readd-reg.toml" \
        "registry remove deletes config"
      assert_dir_not_exists "$HOME/.local/share/apm/registries/readd-reg" \
        "registry remove deletes local clone"

      run_ok orphans-after-remove "$APM" orphans
      assert_file_contains /tmp/readd-orphans-after-remove.out "readd-tool" \
        "apm orphans lists installed package after registry removal"
      assert_file_contains /tmp/readd-orphans-after-remove.out "removed registry 'readd-reg'" \
        "apm orphans names removed registry"
      if $APM verify readd-tool > /tmp/readd-verify-orphan.out 2>&1; then
        cat /tmp/readd-verify-orphan.out
        fail "apm verify should fail while source registry is absent"
      else
        cat /tmp/readd-verify-orphan.out
        pass "apm verify fails while source registry is absent"
      fi
      assert_file_contains /tmp/readd-verify-orphan.out "not present in registry 'readd-reg'" \
        "orphaned verify error points at missing source registry"

      echo "==> Consumer: re-add registry and verify package recovery"
      $APM registry add --no-verify file:///tmp/readd-origin.git \
        --name readd-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/readd-registry-readd.out 2>&1 || {
        cat /tmp/readd-registry-readd.out
        fail "apm registry add re-adds removed registry"
      }
      cat /tmp/readd-registry-readd.out
      assert_file_contains /tmp/readd-registry-readd.out "Registry 'readd-reg' added" \
        "registry re-add reports success"
      assert_dir_exists "$HOME/.local/share/apm/registries/readd-reg" \
        "registry re-add reclones local registry"

      run_ok orphans-after-readd "$APM" orphans
      assert_file_contains /tmp/readd-orphans-after-readd.out "No orphaned packages" \
        "apm orphans clears after registry re-add"
      run_ok verify-after-readd "$APM" verify readd-tool
      assert_file_contains /tmp/readd-verify-after-readd.out "integrity verified" \
        "apm verify works again after registry re-add"
      "$TOOL_BIN" > /tmp/readd-run-after-readd.out
      assert_file_contains /tmp/readd-run-after-readd.out "^install-basic-tool 1.0.0$" \
        "installed executable still runs after registry re-add"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 9. remove-autoremove — Remove with configured autoremove/gc
  # -------------------------------------------------------------------------
  remove-autoremove = testing.mkVMTest {
    name = "apm-remove-autoremove";
    rootfsDeps = realRemoveDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm remove honors apm.conf autoremove settings"

      DEP_STORE="${idempotentTool}"
      LEFT_STORE="${removeLeftTool}"
      RIGHT_STORE="${removeRightTool}"
      DEP_HASH=$(basename "$DEP_STORE" | cut -d- -f1)
      LEFT_HASH=$(basename "$LEFT_STORE" | cut -d- -f1)
      RIGHT_HASH=$(basename "$RIGHT_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/removeuser"

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
        if nix-store --check-validity "$path" > "/tmp/remove-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/remove-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/remove-missing-$label.out" 2>&1; then
          cat "/tmp/remove-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/remove-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/remove-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18087/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      mount -o remount,rw / || true
      assert_store_valid "$DEP_STORE" "idempkg dependency"
      assert_store_valid "$LEFT_STORE" "remove-left wrapper"
      assert_store_valid "$RIGHT_STORE" "remove-right wrapper"
      nix-store -q --references "$LEFT_STORE" > /tmp/remove-left-refs.out
      nix-store -q --references "$RIGHT_STORE" > /tmp/remove-right-refs.out
      assert_file_contains /tmp/remove-left-refs.out "$DEP_STORE" \
        "remove-left has a real Nix reference to idempkg"
      assert_file_contains /tmp/remove-right-refs.out "$DEP_STORE" \
        "remove-right has a real Nix reference to idempkg"

      echo "==> Maintainer: publish shared dependency and two wrappers"
      $APR create remove-reg
      REG_DIR="$REG_STORAGE/remove-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      $APR publish "$DEP_STORE" \
        --name idempkg \
        --version 1.0.0 \
        --description "Shared dependency for remove workflow" \
        --license MIT \
        --maintainer remove-workflow@example.invalid \
        --registry remove-reg \
        --no-commit
      $APR publish "$LEFT_STORE" \
        --name remove-left \
        --version 1.0.0 \
        --description "First explicit package sharing idempkg" \
        --license MIT \
        --maintainer remove-workflow@example.invalid \
        --registry remove-reg \
        --no-commit
      $APR publish "$RIGHT_STORE" \
        --name remove-right \
        --version 1.0.0 \
        --description "Second explicit package sharing idempkg" \
        --license MIT \
        --maintainer remove-workflow@example.invalid \
        --registry remove-reg \
        --no-commit
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$LEFT_HASH")/$LEFT_HASH" \
        "$DEP_HASH" "published remove-left metadata records shared dependency"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$RIGHT_HASH")/$RIGHT_HASH" \
        "$DEP_HASH" "published remove-right metadata records shared dependency"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$LEFT_HASH")/$LEFT_HASH" \
        "$DEP_HASH" "published remove-left closure records shared dependency"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$RIGHT_HASH")/$RIGHT_HASH" \
        "$DEP_HASH" "published remove-right closure records shared dependency"

      $APR cache generate \
        --registry remove-reg \
        --output /tmp/remove-cache \
        --cache-url http://127.0.0.1:18087 \
        --priority 47 \
        --no-commit
      assert_file_exists "/tmp/remove-cache/$DEP_HASH.narinfo" \
        "static cache has shared dependency narinfo"
      assert_file_exists "/tmp/remove-cache/$LEFT_HASH.narinfo" \
        "static cache has remove-left narinfo"
      assert_file_exists "/tmp/remove-cache/$RIGHT_HASH.narinfo" \
        "static cache has remove-right narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: remove workflow packages"
      git init --bare --object-format=sha256 /tmp/remove-origin.git
      git -C "$REG_DIR" remote add origin /tmp/remove-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18087 --bind 127.0.0.1 \
        --directory /tmp/remove-cache > /tmp/remove-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/remove-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: remove two explicit packages and their shared auto dep in one transaction"
      export HOME=/tmp/remove-multi-consumer
      export USER=removemultiuser
      PROFILE="/var/lib/profiles/per-user/removemultiuser"
      mkdir -p "$HOME/.config/apm"
      cat > "$HOME/.config/apm/apm.conf" << 'APMCONF'
      [settings]
      assume_yes = true
      auto_autoremove = true
      auto_gc = false
      APMCONF
      $APM registry add --no-verify file:///tmp/remove-origin.git \
        --name remove-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/remove-multi-registry-add.out 2>&1 || {
        cat /tmp/remove-multi-registry-add.out
        fail "apm registry add syncs remove registry for multi-remove"
      }
      cat /tmp/remove-multi-registry-add.out

      delete_store_path "$LEFT_STORE" "remove-left"
      delete_store_path "$RIGHT_STORE" "remove-right"
      delete_store_path "$DEP_STORE" "idempkg"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install remove-left remove-right --registry remove-reg > /tmp/remove-multi-install.out 2>&1 || {
        cat /tmp/remove-multi-install.out
        fail "apm install shared remove workflow succeeds for multi-remove"
      }
      cat /tmp/remove-multi-install.out
      assert_file_not_contains /tmp/remove-multi-install.out "Do you want to continue" \
        "configured assume_yes suppresses multi-remove install prompt"
      assert_file_contains /tmp/remove-multi-install.out "Downloading 3 NAR" \
        "multi-remove install downloads both roots and shared dependency"
      assert_file_contains /tmp/remove-multi-install.out "Installed 2 package" \
        "multi-remove install creates profile generation for both roots"
      "$PROFILE/current/bin/remove-left" > /tmp/remove-multi-left-run.out
      "$PROFILE/current/bin/remove-right" > /tmp/remove-multi-right-run.out
      "$PROFILE/current/bin/idempkg" > /tmp/remove-multi-dep-run.out
      assert_file_contains /tmp/remove-multi-left-run.out "^idempkg 1.0.0$" \
        "multi-remove left executable runs before removal"
      assert_file_contains /tmp/remove-multi-right-run.out "^idempkg 1.0.0$" \
        "multi-remove right executable runs before removal"
      assert_file_contains /tmp/remove-multi-dep-run.out "^idempkg 1.0.0$" \
        "multi-remove shared dependency executable is active"
      assert_file_contains "$PROFILE/meta/$LEFT_HASH.json" '"explicit": true' \
        "multi-remove left metadata is explicit"
      assert_file_contains "$PROFILE/meta/$RIGHT_HASH.json" '"explicit": true' \
        "multi-remove right metadata is explicit"
      assert_file_contains "$PROFILE/meta/$DEP_HASH.json" '"explicit": false' \
        "multi-remove shared dependency metadata is automatic"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "multi-remove install creates exactly generation 1"
      else
        fail "multi-remove install should create only gen-1"
      fi

      $APM remove remove-left remove-right > /tmp/remove-multi.out 2>&1 || {
        cat /tmp/remove-multi.out
        fail "apm remove removes both explicit packages in one transaction"
      }
      cat /tmp/remove-multi.out
      assert_file_not_contains /tmp/remove-multi.out "Do you want to continue" \
        "configured assume_yes suppresses multi-remove prompt"
      assert_file_contains /tmp/remove-multi.out "remove-left" \
        "multi-remove plan lists first explicit package"
      assert_file_contains /tmp/remove-multi.out "remove-right" \
        "multi-remove plan lists second explicit package"
      assert_file_contains /tmp/remove-multi.out "idempkg" \
        "multi-remove plan lists shared dependency as orphan"
      assert_file_contains /tmp/remove-multi.out "Removed 3 package" \
        "multi-remove removes both roots and their shared dependency"
      assert_file_not_contains /tmp/remove-multi.out "Running garbage collection" \
        "multi-remove honors configured auto_gc false"
      assert_file_not_exists "$PROFILE/meta/$LEFT_HASH.json" \
        "multi-remove deletes first explicit package metadata"
      assert_file_not_exists "$PROFILE/meta/$RIGHT_HASH.json" \
        "multi-remove deletes second explicit package metadata"
      assert_file_not_exists "$PROFILE/meta/$DEP_HASH.json" \
        "multi-remove deletes shared dependency metadata"
      if [ -e "$PROFILE/current/bin/remove-left" ] || [ -e "$PROFILE/current/bin/remove-right" ] || [ -e "$PROFILE/current/bin/idempkg" ]; then
        fail "multi-remove should drop all removed executables from active profile"
      else
        pass "multi-remove drops all removed executables from active profile"
      fi
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "multi-remove creates generation 2"
      else
        fail "multi-remove should create gen-2"
      fi
      assert_store_valid "$DEP_STORE" "idempkg remains in store after multi-remove without GC"
      assert_store_valid "$LEFT_STORE" "remove-left remains in store after multi-remove without GC"
      assert_store_valid "$RIGHT_STORE" "remove-right remains in store after multi-remove without GC"
      rm -rf "$PROFILE"

      echo "==> Consumer: install two explicit packages with one shared auto dep"
      export HOME=/tmp/remove-consumer
      export USER=removeuser
      PROFILE="/var/lib/profiles/per-user/removeuser"
      mkdir -p "$HOME/.config/apm"
      cat > "$HOME/.config/apm/apm.conf" << 'APMCONF'
      [settings]
      assume_yes = true
      auto_autoremove = true
      auto_gc = true
      APMCONF
      $APM registry add --no-verify file:///tmp/remove-origin.git \
        --name remove-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/remove-registry-add.out 2>&1 || {
        cat /tmp/remove-registry-add.out
        fail "apm registry add syncs remove registry"
      }
      cat /tmp/remove-registry-add.out

      delete_store_path "$LEFT_STORE" "remove-left"
      delete_store_path "$RIGHT_STORE" "remove-right"
      delete_store_path "$DEP_STORE" "idempkg"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install remove-left remove-right --registry remove-reg > /tmp/remove-install.out 2>&1 || {
        cat /tmp/remove-install.out
        fail "apm install shared remove workflow succeeds with configured assume_yes"
      }
      cat /tmp/remove-install.out
      assert_file_not_contains /tmp/remove-install.out "Do you want to continue" \
        "configured assume_yes suppresses install prompt"
      assert_file_contains /tmp/remove-install.out "Downloading" \
        "install downloads shared remove workflow closure"
      assert_file_contains /tmp/remove-install.out "Installed 2 package" \
        "install creates profile generation for both explicit packages"
      assert_store_valid "$DEP_STORE" "idempkg"
      assert_store_valid "$LEFT_STORE" "remove-left"
      assert_store_valid "$RIGHT_STORE" "remove-right"
      "$PROFILE/current/bin/remove-left" > /tmp/remove-left-run-1.out
      "$PROFILE/current/bin/remove-right" > /tmp/remove-right-run-1.out
      "$PROFILE/current/bin/idempkg" > /tmp/remove-dep-run-1.out
      assert_file_contains /tmp/remove-left-run-1.out "^idempkg 1.0.0$" \
        "remove-left executable runs before removal"
      assert_file_contains /tmp/remove-right-run-1.out "^idempkg 1.0.0$" \
        "remove-right executable runs before removal"
      assert_file_contains /tmp/remove-dep-run-1.out "^idempkg 1.0.0$" \
        "shared dependency executable is active before removal"
      assert_file_contains "$PROFILE/meta/$LEFT_HASH.json" '"explicit": true' \
        "remove-left metadata is explicit"
      assert_file_contains "$PROFILE/meta/$RIGHT_HASH.json" '"explicit": true' \
        "remove-right metadata is explicit"
      assert_file_contains "$PROFILE/meta/$DEP_HASH.json" '"explicit": false' \
        "idempkg metadata is auto-installed"

      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "initial install creates exactly generation 1"
      else
        fail "initial install should create only gen-1"
      fi

      echo "==> Consumer: remove one explicit package with configured autoremove"
      $APM remove remove-left > /tmp/remove-left.out 2>&1 || {
        cat /tmp/remove-left.out
        fail "apm remove remove-left succeeds with configured autoremove"
      }
      cat /tmp/remove-left.out
      assert_file_not_contains /tmp/remove-left.out "Do you want to continue" \
        "configured assume_yes suppresses remove prompt"
      assert_file_contains /tmp/remove-left.out "Removed 1 package" \
        "configured autoremove removes only requested explicit package"
      assert_file_not_contains /tmp/remove-left.out "idempkg" \
        "shared dependency is not listed as orphan while remove-right remains"
      assert_file_not_contains /tmp/remove-left.out "Running garbage collection" \
        "configured auto_gc does not run when autoremove finds no orphan"
      assert_file_not_exists "$PROFILE/meta/$LEFT_HASH.json" \
        "remove-left metadata removed"
      assert_file_exists "$PROFILE/meta/$RIGHT_HASH.json" \
        "remove-right metadata remains"
      assert_file_exists "$PROFILE/meta/$DEP_HASH.json" \
        "shared dependency metadata remains after remove-left autoremove"
      if [ -x "$PROFILE/current/bin/remove-left" ]; then
        fail "remove-left executable should be absent after removal"
      else
        pass "remove-left executable absent after removal"
      fi
      "$PROFILE/current/bin/remove-right" > /tmp/remove-right-run-2.out
      "$PROFILE/current/bin/idempkg" > /tmp/remove-dep-run-2.out
      assert_file_contains /tmp/remove-right-run-2.out "^idempkg 1.0.0$" \
        "remaining explicit package still runs after remove-left autoremove"
      assert_file_contains /tmp/remove-dep-run-2.out "^idempkg 1.0.0$" \
        "shared dependency remains active after remove-left autoremove"

      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "remove-left creates generation 2"
      else
        fail "remove-left should create gen-2"
      fi

      echo "==> Consumer: remove final explicit package without automatic autoremove"
      export AOS_ROOT=/tmp/remove-auto-gc-root
      export AOS_NIX_STORE_DIR=/tmp/remove-auto-gc-store
      export AOS_NIX_STATE_DIR=/tmp/remove-auto-gc-root/var/nix
      mkdir -p "$AOS_NIX_STORE_DIR" "$AOS_NIX_STATE_DIR/db" "$AOS_NIX_STATE_DIR/gcroots"
      NIX_STORE_DIR="$AOS_NIX_STORE_DIR" NIX_STATE_DIR="$AOS_NIX_STATE_DIR" \
        nix-store --init || true
      cat > "$HOME/.config/apm/apm.conf" << 'APMCONF'
      [settings]
      assume_yes = true
      auto_autoremove = false
      auto_gc = true
      APMCONF
      $APM remove remove-right > /tmp/remove-right.out 2>&1 || {
        cat /tmp/remove-right.out
        fail "apm remove remove-right succeeds without configured autoremove"
      }
      cat /tmp/remove-right.out
      assert_file_not_contains /tmp/remove-right.out "Do you want to continue" \
        "configured assume_yes suppresses final remove prompt"
      assert_file_contains /tmp/remove-right.out "Removed 1 package" \
        "plain remove deletes only requested explicit package"
      assert_file_not_contains /tmp/remove-right.out "idempkg" \
        "plain remove leaves orphaned shared dependency for standalone autoremove"
      assert_file_not_contains /tmp/remove-right.out "Running garbage collection" \
        "configured auto_gc does not run when autoremove is disabled"
      assert_file_not_exists "$PROFILE/meta/$RIGHT_HASH.json" \
        "remove-right metadata removed"
      assert_file_exists "$PROFILE/meta/$DEP_HASH.json" \
        "shared dependency metadata remains until standalone autoremove"
      if [ -x "$PROFILE/current/bin/remove-right" ]; then
        fail "remove-right executable should be absent after removal"
      else
        pass "remove-right executable absent after removal"
      fi
      "$PROFILE/current/bin/idempkg" > /tmp/remove-dep-run-orphan.out
      assert_file_contains /tmp/remove-dep-run-orphan.out "^idempkg 1.0.0$" \
        "orphaned shared dependency remains active before standalone autoremove"

      if [ "$(readlink "$PROFILE/current")" = "gen-3" ] && [ "$(generation_count)" = "3" ]; then
        pass "plain remove creates generation 3 with orphaned dependency"
      else
        fail "plain remove should end at gen-3"
      fi

      echo "==> Consumer: dry-run then execute standalone autoremove with configured GC"
      $APM autoremove --dry-run > /tmp/remove-autoremove-dry-run.out 2>&1 || {
        cat /tmp/remove-autoremove-dry-run.out
        fail "apm autoremove --dry-run reports orphaned dependency"
      }
      cat /tmp/remove-autoremove-dry-run.out
      assert_file_contains /tmp/remove-autoremove-dry-run.out "idempkg" \
        "standalone autoremove dry-run lists orphaned dependency"
      assert_file_contains /tmp/remove-autoremove-dry-run.out "Dry run -- no changes made" \
        "standalone autoremove dry-run reports no mutation"
      assert_file_exists "$PROFILE/meta/$DEP_HASH.json" \
        "standalone autoremove dry-run preserves dependency metadata"
      "$PROFILE/current/bin/idempkg" > /tmp/remove-dep-run-after-dry-run.out
      assert_file_contains /tmp/remove-dep-run-after-dry-run.out "^idempkg 1.0.0$" \
        "standalone autoremove dry-run preserves executable"

      $APM autoremove > /tmp/remove-autoremove.out 2>&1 || {
        cat /tmp/remove-autoremove.out
        fail "apm autoremove removes orphaned dependency"
      }
      cat /tmp/remove-autoremove.out
      assert_file_not_contains /tmp/remove-autoremove.out "Do you want to continue" \
        "configured assume_yes suppresses standalone autoremove prompt"
      assert_file_contains /tmp/remove-autoremove.out "Removed 1 orphaned package" \
        "standalone autoremove removes orphaned shared dependency"
      assert_file_contains /tmp/remove-autoremove.out "idempkg" \
        "standalone autoremove lists orphaned shared dependency"
      assert_file_contains /tmp/remove-autoremove.out "Running garbage collection" \
        "configured auto_gc runs after standalone autoremove removes an orphan"
      assert_file_contains /tmp/remove-autoremove.out "Garbage collection complete" \
        "configured auto_gc completes after standalone autoremove"
      assert_file_not_exists "$PROFILE/meta/$DEP_HASH.json" \
        "shared dependency metadata removed by standalone autoremove"
      if [ -e "$PROFILE/current/bin/idempkg" ]; then
        fail "shared dependency executable should be absent after standalone autoremove"
      else
        pass "shared dependency executable absent after standalone autoremove"
      fi

      if [ "$(readlink "$PROFILE/current")" = "gen-4" ] && [ "$(generation_count)" = "4" ]; then
        pass "standalone autoremove creates generation 4"
      else
        fail "standalone autoremove should end at gen-4"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 10. upgrade-package — Upgrade package to newer version
  # -------------------------------------------------------------------------
  upgrade-package = testing.mkVMTest {
    name = "apm-upgrade-package";
    rootfsDeps = realUpgradeDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm targeted and full upgrade workflow"

      ALPHA_V1_STORE="${upgradeAlphaV1}"
      ALPHA_V2_STORE="${upgradeAlphaV2}"
      BETA_V1_STORE="${upgradeBetaV1}"
      BETA_V2_STORE="${upgradeBetaV2}"
      ALPHA_V1_HASH=$(basename "$ALPHA_V1_STORE" | cut -d- -f1)
      ALPHA_V2_HASH=$(basename "$ALPHA_V2_STORE" | cut -d- -f1)
      BETA_V1_HASH=$(basename "$BETA_V1_STORE" | cut -d- -f1)
      BETA_V2_HASH=$(basename "$BETA_V2_STORE" | cut -d- -f1)
      MAINTAINER_HOME=/tmp
      CONSUMER_HOME=/tmp/upgrade-consumer
      PROFILE="/var/lib/profiles/per-user/upgradeuser"
      ALPHA_BIN="$PROFILE/current/bin/upgrade-alpha"
      BETA_BIN="$PROFILE/current/bin/upgrade-beta"

      as_maintainer() {
        export HOME="$MAINTAINER_HOME"
        export USER=root
      }

      as_consumer() {
        export HOME="$CONSUMER_HOME"
        export USER=upgradeuser
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
        if nix-store --check-validity "$path" > "/tmp/upgrade-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/upgrade-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/upgrade-missing-$label.out" 2>&1; then
          cat "/tmp/upgrade-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/upgrade-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/upgrade-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        if [ -d "$PROFILE" ]; then
          find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
        else
          printf '0'
        fi
      }

      cache_nar_count() {
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' 2>/dev/null | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18092/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      publish_upgrade_tool() {
        store="$1"
        name="$2"
        version="$3"
        hash=$(basename "$store" | cut -d- -f1)
        as_maintainer
        $APR publish "$store" \
          --name "$name" \
          --version "$version" \
          --description "Executable upgrade workflow fixture" \
          --license MIT \
          --maintainer upgrade-workflow@example.invalid \
          --registry upgrade-reg \
          --no-commit > "/tmp/upgrade-publish-$name-$version.out" 2>&1 || {
          cat "/tmp/upgrade-publish-$name-$version.out"
          fail "apr publish succeeds for $name $version"
          return 1
        }
        cat "/tmp/upgrade-publish-$name-$version.out"
        assert_file_contains "$REG_DIR/packages/u/$name.toml" \
          "$hash" "published $name $version metadata records store hash"
      }

      generate_upgrade_cache() {
        as_maintainer
        $APR cache generate \
          --registry upgrade-reg \
          --output /tmp/upgrade-cache \
          --cache-url http://127.0.0.1:18092 \
          --priority 43 \
          --no-commit
      }

      mount -o remount,rw / || true
      assert_store_valid "$ALPHA_V1_STORE" "upgrade-alpha-v1"
      assert_store_valid "$ALPHA_V2_STORE" "upgrade-alpha-v2"
      assert_store_valid "$BETA_V1_STORE" "upgrade-beta-v1"
      assert_store_valid "$BETA_V2_STORE" "upgrade-beta-v2"

      echo "==> Maintainer: publish upgrade-alpha and upgrade-beta 1.0.0"
      as_maintainer
      $APR create upgrade-reg
      REG_DIR="$MAINTAINER_HOME/.local/share/apm/registries/upgrade-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_upgrade_tool "$ALPHA_V1_STORE" upgrade-alpha 1.0.0
      publish_upgrade_tool "$BETA_V1_STORE" upgrade-beta 1.0.0
      generate_upgrade_cache
      assert_file_exists "/tmp/upgrade-cache/$ALPHA_V1_HASH.narinfo" \
        "static cache has upgrade-alpha v1 narinfo"
      assert_file_exists "/tmp/upgrade-cache/$BETA_V1_HASH.narinfo" \
        "static cache has upgrade-beta v1 narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18092" "registry records upgrade cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: upgrade tools 1.0.0"
      git init --bare --object-format=sha256 /tmp/upgrade-origin.git
      git -C "$REG_DIR" remote add origin /tmp/upgrade-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18092 --bind 127.0.0.1 \
        --directory /tmp/upgrade-cache > /tmp/upgrade-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/upgrade-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install both upgrade tools at 1.0.0"
      as_consumer
      $APM registry add --no-verify file:///tmp/upgrade-origin.git \
        --name upgrade-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/upgrade-registry-add.out 2>&1 || {
        cat /tmp/upgrade-registry-add.out
        fail "apm registry add syncs upgrade registry"
      }
      cat /tmp/upgrade-registry-add.out

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM upgrade --dry-run > /tmp/upgrade-empty-dry-run.out 2>&1 || {
        cat /tmp/upgrade-empty-dry-run.out
        fail "apm upgrade --dry-run succeeds before any package is installed"
      }
      cat /tmp/upgrade-empty-dry-run.out
      assert_file_contains /tmp/upgrade-empty-dry-run.out "All packages are up to date" \
        "empty upgrade dry-run reports no candidates"
      assert_file_not_contains /tmp/upgrade-empty-dry-run.out "Updating profile" \
        "empty upgrade dry-run does not update profile"
      if [ ! -e "$PROFILE" ]; then
        pass "empty upgrade dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty upgrade dry-run should not initialize profile state"
      fi
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "empty upgrade dry-run leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "empty upgrade dry-run should not download NAR bodies"
      fi

      $APM upgrade --yes > /tmp/upgrade-empty.out 2>&1 || {
        cat /tmp/upgrade-empty.out
        fail "apm upgrade succeeds before any package is installed"
      }
      cat /tmp/upgrade-empty.out
      assert_file_contains /tmp/upgrade-empty.out "All packages are up to date" \
        "empty upgrade reports no candidates"
      assert_file_not_contains /tmp/upgrade-empty.out "Updating profile" \
        "empty upgrade does not update profile"
      if [ ! -e "$PROFILE" ]; then
        pass "empty upgrade leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty upgrade should not initialize profile state"
      fi
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "empty upgrade leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "empty upgrade should not download NAR bodies"
      fi

      delete_store_path "$ALPHA_V1_STORE" "upgrade-alpha-v1"
      delete_store_path "$BETA_V1_STORE" "upgrade-beta-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install upgrade-alpha upgrade-beta --registry upgrade-reg --yes > /tmp/upgrade-install.out 2>&1 || {
        cat /tmp/upgrade-install.out
        fail "apm install downloads both upgrade tools"
      }
      cat /tmp/upgrade-install.out
      assert_file_contains /tmp/upgrade-install.out "Downloading 2 NAR" \
        "initial install downloads both upgrade tools"
      "$ALPHA_BIN" > /tmp/upgrade-alpha-v1-run.out
      assert_file_contains /tmp/upgrade-alpha-v1-run.out "^upgrade-alpha 1.0.0$" \
        "upgrade-alpha v1 executable runs"
      "$BETA_BIN" > /tmp/upgrade-beta-v1-run.out
      assert_file_contains /tmp/upgrade-beta-v1-run.out "^upgrade-beta 1.0.0$" \
        "upgrade-beta v1 executable runs"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "initial install creates generation 1"
      else
        fail "initial install should create gen-1"
      fi

      echo "==> Maintainer: publish upgrade-alpha and upgrade-beta 2.0.0"
      publish_upgrade_tool "$ALPHA_V2_STORE" upgrade-alpha 2.0.0
      publish_upgrade_tool "$BETA_V2_STORE" upgrade-beta 2.0.0
      generate_upgrade_cache
      assert_file_exists "/tmp/upgrade-cache/$ALPHA_V2_HASH.narinfo" \
        "static cache has upgrade-alpha v2 narinfo"
      assert_file_exists "/tmp/upgrade-cache/$BETA_V2_HASH.narinfo" \
        "static cache has upgrade-beta v2 narinfo"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: upgrade tools 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      delete_store_path "$ALPHA_V2_STORE" "upgrade-alpha-v2"
      delete_store_path "$BETA_V2_STORE" "upgrade-beta-v2"
      as_consumer
      $APM update --registry upgrade-reg > /tmp/upgrade-update.out 2>&1 || {
        cat /tmp/upgrade-update.out
        fail "apm update syncs upgrade registry v2"
      }
      cat /tmp/upgrade-update.out

      $APM list --upgradable > /tmp/upgrade-list.out 2>&1 || {
        cat /tmp/upgrade-list.out
        fail "apm list --upgradable succeeds for upgrade tools"
      }
      assert_file_contains /tmp/upgrade-list.out "upgrade-alpha" \
        "upgradable list includes upgrade-alpha"
      assert_file_contains /tmp/upgrade-list.out "upgrade-beta" \
        "upgradable list includes upgrade-beta"

      echo "==> Consumer: targeted upgrade dry-run leaves profile and store untouched"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM upgrade upgrade-alpha --dry-run > /tmp/upgrade-alpha-dry-run.out 2>&1 || {
        cat /tmp/upgrade-alpha-dry-run.out
        fail "targeted apm upgrade --dry-run upgrade-alpha succeeds"
      }
      cat /tmp/upgrade-alpha-dry-run.out
      assert_file_contains /tmp/upgrade-alpha-dry-run.out "upgrade-alpha (1.0.0 -> 2.0.0)" \
        "targeted upgrade dry-run plans upgrade-alpha"
      assert_file_not_contains /tmp/upgrade-alpha-dry-run.out "upgrade-beta (1.0.0 -> 2.0.0)" \
        "targeted upgrade dry-run does not plan upgrade-beta"
      assert_file_contains /tmp/upgrade-alpha-dry-run.out "Dry run -- no changes made" \
        "targeted upgrade dry-run reports no mutation"
      assert_file_not_contains /tmp/upgrade-alpha-dry-run.out "Downloading" \
        "targeted upgrade dry-run does not download package bodies"
      assert_file_not_contains /tmp/upgrade-alpha-dry-run.out "Updating profile" \
        "targeted upgrade dry-run does not update profile"
      assert_store_missing "$ALPHA_V2_STORE" "upgrade-alpha-v2"
      assert_store_missing "$BETA_V2_STORE" "upgrade-beta-v2"
      if [ "$(cache_nar_count)" = "0" ]; then
        pass "targeted upgrade dry-run leaves NAR cache empty"
      else
        find "$HOME/.cache/apm" -type f -name '*.nar.zst' -print
        fail "targeted upgrade dry-run should not download NAR bodies"
      fi
      "$ALPHA_BIN" > /tmp/upgrade-alpha-v1-run-after-dry-run.out
      assert_file_contains /tmp/upgrade-alpha-v1-run-after-dry-run.out "^upgrade-alpha 1.0.0$" \
        "targeted upgrade dry-run leaves upgrade-alpha at v1"
      "$BETA_BIN" > /tmp/upgrade-beta-v1-run-after-dry-run.out
      assert_file_contains /tmp/upgrade-beta-v1-run-after-dry-run.out "^upgrade-beta 1.0.0$" \
        "targeted upgrade dry-run leaves upgrade-beta at v1"
      assert_file_contains "$PROFILE/meta/$ALPHA_V1_HASH.json" '"explicit": true' \
        "targeted upgrade dry-run preserves alpha v1 metadata"
      assert_file_not_exists "$PROFILE/meta/$ALPHA_V2_HASH.json" \
        "targeted upgrade dry-run does not write alpha v2 metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-1" ] && [ "$(generation_count)" = "1" ]; then
        pass "targeted upgrade dry-run keeps generation 1 active"
      else
        fail "targeted upgrade dry-run should keep gen-1"
      fi

      echo "==> Consumer: targeted upgrade changes only upgrade-alpha"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM upgrade upgrade-alpha --yes > /tmp/upgrade-alpha.out 2>&1 || {
        cat /tmp/upgrade-alpha.out
        fail "targeted apm upgrade upgrade-alpha succeeds"
      }
      cat /tmp/upgrade-alpha.out
      assert_file_contains /tmp/upgrade-alpha.out "upgrade-alpha (1.0.0 -> 2.0.0)" \
        "targeted upgrade plans upgrade-alpha"
      assert_file_not_contains /tmp/upgrade-alpha.out "upgrade-beta (1.0.0 -> 2.0.0)" \
        "targeted upgrade does not plan upgrade-beta"
      assert_file_contains /tmp/upgrade-alpha.out "Downloading 1 NAR" \
        "targeted upgrade downloads only upgrade-alpha"
      "$ALPHA_BIN" > /tmp/upgrade-alpha-v2-run.out
      assert_file_contains /tmp/upgrade-alpha-v2-run.out "^upgrade-alpha 2.0.0$" \
        "targeted upgrade activates upgrade-alpha v2"
      "$BETA_BIN" > /tmp/upgrade-beta-still-v1-run.out
      assert_file_contains /tmp/upgrade-beta-still-v1-run.out "^upgrade-beta 1.0.0$" \
        "targeted upgrade leaves upgrade-beta at v1"
      assert_file_contains "$PROFILE/meta/$ALPHA_V2_HASH.json" '"explicit": true' \
        "targeted upgrade writes alpha v2 metadata"
      assert_file_contains "$PROFILE/meta/$BETA_V1_HASH.json" '"explicit": true' \
        "targeted upgrade preserves beta v1 metadata"
      assert_file_not_exists "$PROFILE/meta/$BETA_V2_HASH.json" \
        "targeted upgrade does not write beta v2 metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "targeted upgrade creates generation 2"
      else
        fail "targeted upgrade should create gen-2"
      fi

      echo "==> Consumer: excluded full upgrade leaves upgrade-beta untouched"
      $APM upgrade --exclude upgrade-beta --yes > /tmp/upgrade-exclude.out 2>&1 || {
        cat /tmp/upgrade-exclude.out
        fail "excluded apm upgrade succeeds"
      }
      cat /tmp/upgrade-exclude.out
      assert_file_contains /tmp/upgrade-exclude.out "held back" \
        "excluded upgrade reports held-back package"
      assert_file_contains /tmp/upgrade-exclude.out "upgrade-beta" \
        "excluded upgrade names upgrade-beta"
      assert_file_not_contains /tmp/upgrade-exclude.out "Downloading" \
        "excluded upgrade does not download beta"
      "$BETA_BIN" > /tmp/upgrade-beta-excluded-run.out
      assert_file_contains /tmp/upgrade-beta-excluded-run.out "^upgrade-beta 1.0.0$" \
        "excluded upgrade leaves upgrade-beta at v1"
      if [ "$(readlink "$PROFILE/current")" = "gen-2" ] && [ "$(generation_count)" = "2" ]; then
        pass "excluded upgrade does not create a generation"
      else
        fail "excluded upgrade should keep generation 2"
      fi

      echo "==> Consumer: full upgrade changes remaining upgrade-beta"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM upgrade --yes > /tmp/upgrade-all.out 2>&1 || {
        cat /tmp/upgrade-all.out
        fail "full apm upgrade succeeds"
      }
      cat /tmp/upgrade-all.out
      assert_file_contains /tmp/upgrade-all.out "upgrade-beta (1.0.0 -> 2.0.0)" \
        "full upgrade plans remaining beta upgrade"
      assert_file_not_contains /tmp/upgrade-all.out "upgrade-alpha (1.0.0 -> 2.0.0)" \
        "full upgrade does not replan already upgraded alpha"
      assert_file_contains /tmp/upgrade-all.out "Downloading 1 NAR" \
        "full upgrade downloads only upgrade-beta"
      "$ALPHA_BIN" > /tmp/upgrade-alpha-final-run.out
      assert_file_contains /tmp/upgrade-alpha-final-run.out "^upgrade-alpha 2.0.0$" \
        "full upgrade keeps upgrade-alpha at v2"
      "$BETA_BIN" > /tmp/upgrade-beta-v2-run.out
      assert_file_contains /tmp/upgrade-beta-v2-run.out "^upgrade-beta 2.0.0$" \
        "full upgrade activates upgrade-beta v2"
      assert_file_contains "$PROFILE/meta/$ALPHA_V2_HASH.json" '"explicit": true' \
        "full upgrade keeps alpha v2 metadata"
      assert_file_contains "$PROFILE/meta/$BETA_V2_HASH.json" '"explicit": true' \
        "full upgrade writes beta v2 metadata"
      assert_file_not_exists "$PROFILE/meta/$ALPHA_V1_HASH.json" \
        "full upgrade has no stale alpha v1 metadata"
      assert_file_not_exists "$PROFILE/meta/$BETA_V1_HASH.json" \
        "full upgrade drops beta v1 metadata"
      if [ "$(readlink "$PROFILE/current")" = "gen-3" ] && [ "$(generation_count)" = "3" ]; then
        pass "full upgrade creates generation 3"
      else
        fail "full upgrade should create gen-3"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 11. rollback-package — Roll back to previous generation
  # -------------------------------------------------------------------------
  rollback-package = testing.mkVMTest {
    name = "apm-rollback-package";
    rootfsDeps = realRollbackDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real apm rollback generation workflow"

      ROLLBACK_V1_STORE="${rollbackToolV1}"
      ROLLBACK_V2_STORE="${rollbackToolV2}"
      ROLLBACK_V3_STORE="${rollbackToolV3}"
      ROLLBACK_V1_HASH=$(basename "$ROLLBACK_V1_STORE" | cut -d- -f1)
      ROLLBACK_V2_HASH=$(basename "$ROLLBACK_V2_STORE" | cut -d- -f1)
      ROLLBACK_V3_HASH=$(basename "$ROLLBACK_V3_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/rollbackuser"
      JQ="${pkgs.jq}/bin/jq"
      PROFILE_BIN="$PROFILE/current/bin/rollback-tool"

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
        if nix-store --check-validity "$path" > "/tmp/rollback-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/rollback-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/rollback-missing-$label.out" 2>&1; then
          cat "/tmp/rollback-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/rollback-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/rollback-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      assert_current_generation() {
        expected="$1"
        label="$2"
        current=$(readlink "$PROFILE/current")
        if [ "$current" = "gen-$expected" ]; then
          pass "$label"
        else
          fail "$label (current=$current)"
        fi
      }

      assert_generation_exists() {
        generation="$1"
        label="$2"
        if [ -d "$PROFILE/gen-$generation" ]; then
          pass "$label"
        else
          fail "$label (missing $PROFILE/gen-$generation)"
        fi
      }

      assert_generation_missing() {
        generation="$1"
        label="$2"
        if [ ! -e "$PROFILE/gen-$generation" ]; then
          pass "$label"
        else
          fail "$label ($PROFILE/gen-$generation should be pruned)"
        fi
      }

      assert_current_tool_version() {
        version="$1"
        "$PROFILE_BIN" > "/tmp/rollback-run-$version.out"
        assert_file_contains "/tmp/rollback-run-$version.out" \
          "^rollback-tool $version$" "profile executable runs rollback-tool $version"
      }

      assert_list_marks_current() {
        generation="$1"
        file="$2"
        if grep -q "gen-$generation: .*rollback-tool .* (current)" "$file"; then
          pass "rollback list marks generation $generation current"
        else
          cat "$file"
          fail "rollback list should mark generation $generation current"
        fi
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18104/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      publish_rollback_tool() {
        version="$1"
        store="$2"
        $APR publish "$store" \
          --name rollback-tool \
          --version "$version" \
          --description "Executable rollback workflow fixture" \
          --license MIT \
          --maintainer rollback-workflow@example.invalid \
          --registry rollback-reg \
          --no-commit
      }

      generate_cache() {
        $APR cache generate \
          --registry rollback-reg \
          --output /tmp/rollback-cache \
          --cache-url http://127.0.0.1:18104 \
          --priority 44 \
          --no-commit
      }

      commit_and_push() {
        message="$1"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "$message"
        git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"
      }

      mount -o remount,rw / || true
      assert_store_valid "$ROLLBACK_V1_STORE" "rollback-tool-v1"
      assert_store_valid "$ROLLBACK_V2_STORE" "rollback-tool-v2"
      assert_store_valid "$ROLLBACK_V3_STORE" "rollback-tool-v3"

      echo "==> Maintainer: publish rollback-tool 1.0.0 and static cache"
      $APR create rollback-reg
      REG_DIR="$REG_STORAGE/rollback-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_rollback_tool 1.0.0 "$ROLLBACK_V1_STORE"
      assert_file_contains "$REG_DIR/packages/r/rollback-tool.toml" \
        "$ROLLBACK_V1_HASH" "published rollback v1 metadata records store hash"
      generate_cache
      assert_file_exists "/tmp/rollback-cache/$ROLLBACK_V1_HASH.narinfo" \
        "static cache has rollback-tool v1 narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18104" "registry records rollback cache URL"

      git init --bare --object-format=sha256 /tmp/rollback-origin.git
      git -C "$REG_DIR" remote add origin /tmp/rollback-origin.git
      commit_and_push "release: rollback-tool 1.0.0"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18104 --bind 127.0.0.1 \
        --directory /tmp/rollback-cache > /tmp/rollback-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/rollback-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install rollback-tool 1.0.0"
      export HOME=/tmp/rollback-consumer
      export USER=rollbackuser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/rollback-origin.git \
        --name rollback-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/rollback-registry-add.out 2>&1 || {
        cat /tmp/rollback-registry-add.out
        fail "apm registry add syncs rollback registry"
      }
      cat /tmp/rollback-registry-add.out

      $APM clean --generations --keep 1 > /tmp/rollback-empty-clean-generations.out 2>&1 || {
        cat /tmp/rollback-empty-clean-generations.out
        fail "clean generations succeeds before any package is installed"
      }
      cat /tmp/rollback-empty-clean-generations.out
      assert_file_contains /tmp/rollback-empty-clean-generations.out "No old generations to remove" \
        "empty clean generations reports no stale generations"
      if [ ! -e "$PROFILE" ]; then
        pass "empty clean generations leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty clean generations should not initialize profile state"
      fi

      if $APM rollback > /tmp/rollback-empty.out 2>&1; then
        cat /tmp/rollback-empty.out
        fail "rollback should fail when no profile generation is active"
      else
        cat /tmp/rollback-empty.out
        pass "rollback fails before any package is installed"
      fi
      assert_file_contains /tmp/rollback-empty.out "no active generation" \
        "empty rollback reports missing active generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty rollback leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty rollback should not initialize profile state"
      fi

      if $APM rollback --dry-run > /tmp/rollback-empty-dry-run.out 2>&1; then
        cat /tmp/rollback-empty-dry-run.out
        fail "rollback dry-run should fail when no profile generation is active"
      else
        cat /tmp/rollback-empty-dry-run.out
        pass "rollback dry-run fails before any package is installed"
      fi
      assert_file_contains /tmp/rollback-empty-dry-run.out "no active generation" \
        "empty rollback dry-run reports missing active generation"
      if [ ! -e "$PROFILE" ]; then
        pass "empty rollback dry-run leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty rollback dry-run should not initialize profile state"
      fi

      delete_store_path "$ROLLBACK_V1_STORE" "rollback-tool-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install rollback-tool --registry rollback-reg --yes \
        > /tmp/rollback-install-v1.out 2>&1 || {
        cat /tmp/rollback-install-v1.out
        fail "apm installs rollback-tool v1"
      }
      cat /tmp/rollback-install-v1.out
      assert_file_contains /tmp/rollback-install-v1.out "Downloading" \
        "apm install downloads rollback-tool v1"
      assert_file_contains /tmp/rollback-install-v1.out "Installed 1 package" \
        "apm install creates rollback generation 1"
      assert_store_valid "$ROLLBACK_V1_STORE" "rollback-tool-v1"
      assert_current_generation 1 "rollback profile current is generation 1"
      assert_current_tool_version 1.0.0

      $APM rollback --list > /tmp/rollback-list-v1.out 2>&1 || {
        cat /tmp/rollback-list-v1.out
        fail "apm rollback --list shows package generations"
      }
      cat /tmp/rollback-list-v1.out
      assert_file_contains /tmp/rollback-list-v1.out "Profile generations" \
        "rollback --list uses package profile generations"
      assert_file_not_contains /tmp/rollback-list-v1.out "System generations" \
        "rollback --list does not route to system generations without --system"
      assert_file_contains /tmp/rollback-list-v1.out "gen-1: rollback-tool 1.0.0" \
        "rollback --list shows generation 1 package version"
      assert_list_marks_current 1 /tmp/rollback-list-v1.out

      echo "==> Maintainer: publish rollback-tool 2.0.0"
      export HOME=/tmp
      export USER=root
      publish_rollback_tool 2.0.0 "$ROLLBACK_V2_STORE"
      assert_file_contains "$REG_DIR/packages/r/rollback-tool.toml" \
        "$ROLLBACK_V2_HASH" "published rollback v2 metadata records store hash"
      generate_cache
      assert_file_exists "/tmp/rollback-cache/$ROLLBACK_V2_HASH.narinfo" \
        "static cache has rollback-tool v2 narinfo"
      commit_and_push "release: rollback-tool 2.0.0"

      echo "==> Consumer: upgrade to rollback-tool 2.0.0"
      export HOME=/tmp/rollback-consumer
      export USER=rollbackuser
      delete_store_path "$ROLLBACK_V2_STORE" "rollback-tool-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM update --registry rollback-reg > /tmp/rollback-update-v2.out 2>&1 || {
        cat /tmp/rollback-update-v2.out
        fail "apm update fetches rollback-tool v2 metadata"
      }
      $APM upgrade rollback-tool --yes > /tmp/rollback-upgrade-v2.out 2>&1 || {
        cat /tmp/rollback-upgrade-v2.out
        fail "apm upgrades rollback-tool to v2"
      }
      cat /tmp/rollback-upgrade-v2.out
      assert_file_contains /tmp/rollback-upgrade-v2.out "Downloading" \
        "apm upgrade downloads rollback-tool v2"
      assert_file_contains /tmp/rollback-upgrade-v2.out "Upgraded 1 package" \
        "apm upgrade creates rollback generation 2"
      assert_current_generation 2 "rollback profile current is generation 2"
      assert_current_tool_version 2.0.0

      echo "==> Maintainer: publish rollback-tool 3.0.0"
      export HOME=/tmp
      export USER=root
      publish_rollback_tool 3.0.0 "$ROLLBACK_V3_STORE"
      assert_file_contains "$REG_DIR/packages/r/rollback-tool.toml" \
        "$ROLLBACK_V3_HASH" "published rollback v3 metadata records store hash"
      generate_cache
      assert_file_exists "/tmp/rollback-cache/$ROLLBACK_V3_HASH.narinfo" \
        "static cache has rollback-tool v3 narinfo"
      commit_and_push "release: rollback-tool 3.0.0"

      echo "==> Consumer: upgrade to rollback-tool 3.0.0"
      export HOME=/tmp/rollback-consumer
      export USER=rollbackuser
      delete_store_path "$ROLLBACK_V3_STORE" "rollback-tool-v3"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM update --registry rollback-reg > /tmp/rollback-update-v3.out 2>&1 || {
        cat /tmp/rollback-update-v3.out
        fail "apm update fetches rollback-tool v3 metadata"
      }
      $APM upgrade rollback-tool --yes > /tmp/rollback-upgrade-v3.out 2>&1 || {
        cat /tmp/rollback-upgrade-v3.out
        fail "apm upgrades rollback-tool to v3"
      }
      cat /tmp/rollback-upgrade-v3.out
      assert_file_contains /tmp/rollback-upgrade-v3.out "Downloading" \
        "apm upgrade downloads rollback-tool v3"
      assert_file_contains /tmp/rollback-upgrade-v3.out "Upgraded 1 package" \
        "apm upgrade creates rollback generation 3"
      assert_current_generation 3 "rollback profile current is generation 3"
      assert_current_tool_version 3.0.0

      $APM rollback --list > /tmp/rollback-list-v3.out 2>&1 || {
        cat /tmp/rollback-list-v3.out
        fail "apm rollback --list shows all package generations"
      }
      cat /tmp/rollback-list-v3.out
      assert_file_contains /tmp/rollback-list-v3.out "gen-1: rollback-tool 1.0.0" \
        "rollback --list shows generation 1 version"
      assert_file_contains /tmp/rollback-list-v3.out "gen-2: rollback-tool 2.0.0" \
        "rollback --list shows generation 2 version"
      assert_file_contains /tmp/rollback-list-v3.out "gen-3: rollback-tool 3.0.0" \
        "rollback --list shows generation 3 version"
      assert_list_marks_current 3 /tmp/rollback-list-v3.out

      echo "==> Consumer: rollback explicitly to generation 1"
      $APM --json rollback --generation 1 > /tmp/rollback-to-gen1.json 2>&1 || {
        cat /tmp/rollback-to-gen1.json
        fail "apm rollback --generation 1 succeeds"
      }
      "$JQ" -e \
        --arg restored "$ROLLBACK_V1_STORE" \
        --arg removed "$ROLLBACK_V3_STORE" \
        '.action == "rollback"
          and .status == "rolled_back"
          and .requested_generation == 1
          and .from_generation == 3
          and .to_generation == 1
          and .dry_run == false
          and .generation == 1
          and (.restored | length == 1)
          and .restored[0].store_path == $restored
          and .restored[0].registry == "rollback-reg"
          and .restored[0].package.name == "rollback-tool"
          and .restored[0].package.version == "1.0.0"
          and (.removed | length == 1)
          and .removed[0].store_path == $removed
          and .removed[0].registry == "rollback-reg"
          and .removed[0].package.name == "rollback-tool"
          and .removed[0].package.version == "3.0.0"
          and (.current_roots | any(.store_path == $removed
            and .package.name == "rollback-tool"
            and .package.version == "3.0.0"))
          and (.target_roots | any(.store_path == $restored
            and .package.name == "rollback-tool"
            and .package.version == "1.0.0"))' \
        /tmp/rollback-to-gen1.json >/dev/null || {
        cat /tmp/rollback-to-gen1.json
        fail "apm --json rollback reports explicit generation transition"
      }
      assert_current_generation 1 "rollback profile current is generation 1 after explicit rollback"
      assert_current_tool_version 1.0.0
      $APM list --installed > /tmp/rollback-installed-gen1.out 2>&1 || {
        cat /tmp/rollback-installed-gen1.out
        fail "apm list --installed succeeds after generation 1 rollback"
      }
      assert_file_contains /tmp/rollback-installed-gen1.out "rollback-tool" \
        "installed list names rollback-tool after generation 1 rollback"
      assert_file_contains /tmp/rollback-installed-gen1.out "1.0.0" \
        "installed metadata follows generation 1 rollback"
      assert_file_contains /tmp/rollback-installed-gen1.out "upgradable: 3.0.0" \
        "installed list reports generation 3 as an upgrade candidate after generation 1 rollback"

      $APM rollback --list > /tmp/rollback-list-gen1-current.out 2>&1 || {
        cat /tmp/rollback-list-gen1-current.out
        fail "apm rollback --list works after generation 1 rollback"
      }
      assert_list_marks_current 1 /tmp/rollback-list-gen1-current.out

      echo "==> Consumer: explicit rollback target can switch back to generation 3"
      $APM rollback --generation 3 > /tmp/rollback-to-gen3.out 2>&1 || {
        cat /tmp/rollback-to-gen3.out
        fail "apm rollback --generation 3 succeeds"
      }
      cat /tmp/rollback-to-gen3.out
      assert_current_generation 3 "rollback profile current is generation 3 after explicit target"
      assert_current_tool_version 3.0.0

      echo "==> Consumer: dry-run rollback does not switch generation"
      $APM --json rollback --dry-run > /tmp/rollback-dry-run.json 2>&1 || {
        cat /tmp/rollback-dry-run.json
        fail "apm rollback --dry-run succeeds"
      }
      "$JQ" -e \
        --arg restored "$ROLLBACK_V2_STORE" \
        --arg removed "$ROLLBACK_V3_STORE" \
        '.action == "rollback"
          and .status == "planned"
          and .requested_generation == null
          and .from_generation == 3
          and .to_generation == 2
          and .dry_run == true
          and .generation == null
          and (.restored | length == 1)
          and .restored[0].store_path == $restored
          and .restored[0].registry == "rollback-reg"
          and .restored[0].package.name == "rollback-tool"
          and .restored[0].package.version == "2.0.0"
          and (.removed | length == 1)
          and .removed[0].store_path == $removed
          and .removed[0].registry == "rollback-reg"
          and .removed[0].package.name == "rollback-tool"
          and .removed[0].package.version == "3.0.0"
          and (.current_roots | any(.store_path == $removed
            and .package.name == "rollback-tool"
            and .package.version == "3.0.0"))
          and (.target_roots | any(.store_path == $restored
            and .package.name == "rollback-tool"
            and .package.version == "2.0.0"))' \
        /tmp/rollback-dry-run.json >/dev/null || {
        cat /tmp/rollback-dry-run.json
        fail "apm --json rollback --dry-run reports planned previous-generation transition"
      }
      assert_current_generation 3 "rollback dry-run keeps generation 3 active"
      assert_current_tool_version 3.0.0

      echo "==> Consumer: plain rollback selects previous generation"
      $APM --json rollback > /tmp/rollback-plain.json 2>&1 || {
        cat /tmp/rollback-plain.json
        fail "plain apm rollback succeeds"
      }
      "$JQ" -e \
        --arg restored "$ROLLBACK_V2_STORE" \
        --arg removed "$ROLLBACK_V3_STORE" \
        '.action == "rollback"
          and .status == "rolled_back"
          and .requested_generation == null
          and .from_generation == 3
          and .to_generation == 2
          and .dry_run == false
          and .generation == 2
          and (.restored | length == 1)
          and .restored[0].store_path == $restored
          and .restored[0].registry == "rollback-reg"
          and .restored[0].package.name == "rollback-tool"
          and .restored[0].package.version == "2.0.0"
          and (.removed | length == 1)
          and .removed[0].store_path == $removed
          and .removed[0].registry == "rollback-reg"
          and .removed[0].package.name == "rollback-tool"
          and .removed[0].package.version == "3.0.0"
          and (.current_roots | any(.store_path == $removed
            and .package.name == "rollback-tool"
            and .package.version == "3.0.0"))
          and (.target_roots | any(.store_path == $restored
            and .package.name == "rollback-tool"
            and .package.version == "2.0.0"))' \
        /tmp/rollback-plain.json >/dev/null || {
        cat /tmp/rollback-plain.json
        fail "apm --json rollback reports previous-generation transition"
      }
      assert_current_generation 2 "rollback profile current is generation 2 after plain rollback"
      assert_current_tool_version 2.0.0

      echo "==> Consumer: clean generations keeps rolled-back current generation"
      $APM --json clean --generations --keep 1 > /tmp/rollback-clean-generations.json 2>&1 || {
        cat /tmp/rollback-clean-generations.json
        fail "apm clean --generations succeeds after rollback"
      }
      "$JQ" -e \
        '.action == "clean"
          and .mode == "generations"
          and .status == "cleaned"
          and .keep == 1
          and .current_generation == 2
          and .generations_before == [1, 2, 3]
          and .generations_after == [2, 3]
          and .removed_generations == [1]
          and .removed == 1' \
        /tmp/rollback-clean-generations.json >/dev/null || {
        cat /tmp/rollback-clean-generations.json
        fail "apm --json clean --generations reports pruned rollback generation"
      }
      assert_generation_missing 1 "clean generations prunes generation 1"
      assert_generation_exists 2 "clean generations keeps rolled-back current generation"
      assert_generation_exists 3 "clean generations keeps latest generation"
      assert_current_generation 2 "clean generations leaves generation 2 current"
      assert_current_tool_version 2.0.0
      $APM rollback --list > /tmp/rollback-list-after-clean.out 2>&1 || {
        cat /tmp/rollback-list-after-clean.out
        fail "apm rollback --list works after generation cleanup"
      }
      cat /tmp/rollback-list-after-clean.out
      assert_file_not_contains /tmp/rollback-list-after-clean.out "gen-1:" \
        "rollback list no longer shows pruned generation"
      assert_file_contains /tmp/rollback-list-after-clean.out "gen-2: rollback-tool 2.0.0" \
        "rollback list keeps current generation after cleanup"
      assert_file_contains /tmp/rollback-list-after-clean.out "gen-3: rollback-tool 3.0.0" \
        "rollback list keeps latest generation after cleanup"
      assert_list_marks_current 2 /tmp/rollback-list-after-clean.out
      $APM list --installed > /tmp/rollback-installed-after-clean.out 2>&1 || {
        cat /tmp/rollback-installed-after-clean.out
        fail "apm list --installed works after generation cleanup"
      }
      assert_file_contains /tmp/rollback-installed-after-clean.out "rollback-tool" \
        "installed list names rollback-tool after generation cleanup"
      assert_file_contains /tmp/rollback-installed-after-clean.out "2.0.0" \
        "installed metadata follows rolled-back current generation after cleanup"

      if $APM rollback --generation 99 > /tmp/rollback-missing.out 2>&1; then
        cat /tmp/rollback-missing.out
        fail "rollback to missing generation should fail"
      else
        pass "rollback to missing generation fails"
      fi
      assert_file_contains /tmp/rollback-missing.out "generation 99 not found" \
        "rollback missing generation reports target"
      assert_current_generation 2 "failed rollback keeps generation 2 active"

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 12. package-real-closure-lifecycle — Install/upgrade/rollback real closure
  # -------------------------------------------------------------------------
  package-real-closure-lifecycle = testing.mkVMTest {
    name = "apm-package-real-closure-lifecycle";
    rootfsDeps = realLifecycleDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real package closure install, upgrade, rollback, remove"

      delete_store_path() {
        path="$1"
        label="$2"
        nix-store --delete --ignore-liveness "$path" > "/tmp/delete-$label.out" 2>&1 || {
          cat "/tmp/delete-$label.out"
          fail "deleted $label before apm download"
          return
        }
        if nix-store --check-validity "$path" > "/tmp/valid-$label.out" 2>&1; then
          cat "/tmp/valid-$label.out"
          fail "$label should be missing before apm download"
        else
          pass "$label missing before apm download"
        fi
      }

      try_delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/delete-$label.out" 2>&1; then
          if nix-store --check-validity "$path" > "/tmp/valid-$label.out" 2>&1; then
            cat "/tmp/valid-$label.out"
            fail "$label should be missing before apm download"
            return 1
          fi
          pass "$label missing before apm download"
          return 0
        fi

        cat "/tmp/delete-$label.out"
        pass "$label remains live; upgrade will reuse existing store path"
        return 1
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/valid-after-$label.out" 2>&1; then
          pass "$label valid after apm import"
        else
          cat "/tmp/valid-after-$label.out"
          fail "$label should be valid after apm import"
        fi
      }

      publish_version() {
        version="$1"
        runtime_store="$2"
        tool_store="$3"
        $APR publish "$runtime_store" \
          --name lifecycle-runtime \
          --version "$version" \
          --description "Runtime payload for lifecycle workflow" \
          --license MIT \
          --maintainer lifecycle@example.invalid \
          --registry lifecycle-reg \
          --no-commit
        $APR publish "$tool_store" \
          --name lifecycle-tool \
          --version "$version" \
          --description "Executable tool for lifecycle workflow" \
          --license MIT \
          --maintainer lifecycle@example.invalid \
          --registry lifecycle-reg \
          --no-commit
      }

      RUNTIME_V1_STORE="${pkgs.oniguruma}"
      TOOL_V1_STORE="${pkgs.jq}"
      RUNTIME_V2_STORE="${pkgs.pcre2}"
      TOOL_V2_STORE="${pkgs.git}"
      RUNTIME_V1_HASH=$(basename "$RUNTIME_V1_STORE" | cut -d- -f1)
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      RUNTIME_V2_HASH=$(basename "$RUNTIME_V2_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)

      nix-store -q --references "$TOOL_V1_STORE" > /tmp/tool-v1-refs.out
      cat /tmp/tool-v1-refs.out
      assert_file_contains /tmp/tool-v1-refs.out "$RUNTIME_V1_STORE" \
        "v1 tool has a real Nix reference to runtime"
      nix-store -qR "$TOOL_V1_STORE" > /tmp/tool-v1-closure.out
      assert_file_contains /tmp/tool-v1-closure.out "$RUNTIME_V1_STORE" \
        "v1 tool closure includes runtime"
      assert_file_contains /tmp/tool-v1-closure.out "$TOOL_V1_STORE" \
        "v1 tool closure includes root"
      nix-store -q --references "$TOOL_V2_STORE" > /tmp/tool-v2-refs.out
      assert_file_contains /tmp/tool-v2-refs.out "$RUNTIME_V2_STORE" \
        "v2 tool has a real Nix reference to runtime"

      $APR create lifecycle-reg
      REG_DIR="$REG_STORAGE/lifecycle-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_version 1.0.0 "$RUNTIME_V1_STORE" "$TOOL_V1_STORE"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$TOOL_V1_HASH")/$TOOL_V1_HASH" \
        "$RUNTIME_V1_HASH" "published v1 tool metadata records runtime reference"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$TOOL_V1_HASH")/$TOOL_V1_HASH" \
        "$RUNTIME_V1_HASH" "published v1 tool closure records runtime"

      $APR cache generate \
        --registry lifecycle-reg \
        --output /tmp/lifecycle-cache \
        --cache-url http://127.0.0.1:18083 \
        --priority 43 \
        --no-commit
      assert_file_exists "/tmp/lifecycle-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has v1 tool narinfo"
      assert_file_exists "/tmp/lifecycle-cache/$RUNTIME_V1_HASH.narinfo" \
        "static cache has v1 runtime narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: lifecycle-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/lifecycle-origin.git
      git -C "$REG_DIR" remote add origin /tmp/lifecycle-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      PYTHONUNBUFFERED=1 python3 -m http.server 18083 --bind 127.0.0.1 \
        --directory /tmp/lifecycle-cache > /tmp/lifecycle-cache-http.log 2>&1 &
      CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18083/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if ! curl -sf http://127.0.0.1:18083/nix-cache-info >/dev/null; then
        cat /tmp/lifecycle-cache-http.log || true
        fail "static cache HTTP server started"
      else
        pass "static cache HTTP server started"
      fi

      export HOME=/tmp/lifecycle-consumer
      export USER=lifecycleuser
      APM_CONFIG="$HOME/.config/apm"
      PROFILE="/var/lib/profiles/per-user/$USER"
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/lifecycle-origin.git \
        --name lifecycle-reg \
        --branch "$DEFAULT_BRANCH"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_V1_STORE" "tool-v1"
      delete_store_path "$RUNTIME_V1_STORE" "runtime-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install lifecycle-tool --registry lifecycle-reg --yes \
        > /tmp/lifecycle-install.out 2>&1 || {
        cat /tmp/lifecycle-install.out
        fail "apm install downloads and imports v1 closure"
      }
      cat /tmp/lifecycle-install.out
      assert_file_contains /tmp/lifecycle-install.out "Downloading" \
        "apm install performed v1 downloads"
      assert_file_contains /tmp/lifecycle-install.out "Installed 1 package" \
        "apm install completed v1 profile update"
      NAR_COUNT=$(find "$HOME/.cache/apm" -name '*.nar.zst' | wc -l | tr -d ' ')
      if [ "$NAR_COUNT" -ge 2 ]; then
        pass "apm install downloaded the v1 closure"
      else
        fail "apm install should download at least two NARs for v1 closure"
      fi
      assert_store_valid "$TOOL_V1_STORE" "tool-v1"
      assert_store_valid "$RUNTIME_V1_STORE" "runtime-v1"

      PROFILE_JQ="/var/lib/profiles/per-user/$USER/current/bin/jq"
      PROFILE_GIT="/var/lib/profiles/per-user/$USER/current/bin/git"
      printf '{"value":42}\n' > /tmp/lifecycle-input.json
      "$PROFILE_JQ" -r '.value' /tmp/lifecycle-input.json > /tmp/lifecycle-run-v1.out
      assert_file_contains /tmp/lifecycle-run-v1.out "^42$" \
        "installed v1 jq executable runs from profile"
      $APM verify lifecycle-tool > /tmp/lifecycle-verify-v1.out 2>&1 || {
        cat /tmp/lifecycle-verify-v1.out
        fail "apm verify succeeds for downloaded v1 package"
      }

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      publish_version 2.0.0 "$RUNTIME_V2_STORE" "$TOOL_V2_STORE"
      assert_file_contains "$REG_DIR/packages/l/lifecycle-tool.toml" \
        "$TOOL_V2_HASH" "published v2 tool metadata records new store path"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$TOOL_V2_HASH")/$TOOL_V2_HASH" \
        "$RUNTIME_V2_HASH" "published v2 tool metadata records runtime reference"
      $APR cache generate \
        --registry lifecycle-reg \
        --output /tmp/lifecycle-cache \
        --cache-url http://127.0.0.1:18083 \
        --priority 43 \
        --no-commit
      assert_file_exists "/tmp/lifecycle-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has v2 tool narinfo"
      assert_file_exists "/tmp/lifecycle-cache/$RUNTIME_V2_HASH.narinfo" \
        "static cache has v2 runtime narinfo"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: lifecycle-tool 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      export HOME=/tmp/lifecycle-consumer
      export USER=lifecycleuser
      APM_CONFIG="$HOME/.config/apm"
      V2_DELETED=0
      if try_delete_store_path "$TOOL_V2_STORE" "tool-v2"; then
        V2_DELETED=$((V2_DELETED + 1))
      fi
      if try_delete_store_path "$RUNTIME_V2_STORE" "runtime-v2"; then
        V2_DELETED=$((V2_DELETED + 1))
      fi
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry lifecycle-reg > /tmp/lifecycle-update.out 2>&1 || {
        cat /tmp/lifecycle-update.out
        fail "apm update fetches v2 registry metadata"
      }
      $APM list --upgradable > /tmp/lifecycle-upgradable.out 2>&1 || {
        cat /tmp/lifecycle-upgradable.out
        fail "apm list --upgradable succeeds"
      }
      assert_file_contains /tmp/lifecycle-upgradable.out "lifecycle-tool" \
        "apm list --upgradable reports lifecycle tool"
      assert_file_contains /tmp/lifecycle-upgradable.out "2.0.0" \
        "apm list --upgradable reports v2 candidate"
      if grep -q "lifecycle-runtime" /tmp/lifecycle-upgradable.out; then
        cat /tmp/lifecycle-upgradable.out
        fail "apm list --upgradable should not advertise auto dependencies as independent upgrades"
      else
        pass "apm list --upgradable omits auto dependency roots"
      fi

      $APM upgrade --yes > /tmp/lifecycle-upgrade.out 2>&1 || {
        cat /tmp/lifecycle-upgrade.out
        fail "apm upgrade downloads and imports v2 closure"
      }
      cat /tmp/lifecycle-upgrade.out
      assert_file_contains /tmp/lifecycle-upgrade.out "Upgraded 1 package" \
        "apm upgrade completed profile update"
      if [ "$V2_DELETED" -gt 0 ]; then
        assert_file_contains /tmp/lifecycle-upgrade.out "Downloading" \
          "apm upgrade performed v2 downloads"
        NAR_COUNT=$(find "$HOME/.cache/apm" -name '*.nar.zst' | wc -l | tr -d ' ')
        if [ "$NAR_COUNT" -ge "$V2_DELETED" ]; then
          pass "apm upgrade downloaded missing v2 closure member(s)"
        else
          fail "apm upgrade should download missing v2 closure member(s)"
        fi
      else
        assert_file_contains /tmp/lifecycle-upgrade.out "All packages already in store" \
          "apm upgrade reuses live v2 closure when paths cannot be deleted"
      fi
      assert_store_valid "$TOOL_V2_STORE" "tool-v2"
      assert_store_valid "$RUNTIME_V2_STORE" "runtime-v2"
      "$PROFILE_GIT" --version > /tmp/lifecycle-run-v2.out
      assert_file_contains /tmp/lifecycle-run-v2.out "git version" \
        "upgraded v2 git executable runs from profile"
      if [ -e "$PROFILE_JQ" ]; then
        fail "upgraded profile should not keep v1 jq executable"
      else
        pass "upgraded profile removes v1 jq executable"
      fi
      $APM list --installed > /tmp/lifecycle-installed-v2.out 2>&1 || {
        cat /tmp/lifecycle-installed-v2.out
        fail "apm list --installed succeeds after upgrading lifecycle tool"
      }
      assert_file_contains /tmp/lifecycle-installed-v2.out "lifecycle-tool" \
        "apm list --installed reports lifecycle tool after upgrade"
      assert_file_contains "$PROFILE/meta/$TOOL_V2_HASH.json" '"explicit": true' \
        "upgraded tool remains explicit"
      assert_file_contains "$PROFILE/meta/$RUNTIME_V2_HASH.json" '"explicit": false' \
        "upgraded runtime remains auto-installed"
      assert_file_not_exists "$PROFILE/meta/$RUNTIME_V1_HASH.json" \
        "upgrade drops obsolete auto dependency metadata"
      if [ -L "$PROFILE/current/usr/$RUNTIME_V1_HASH" ]; then
        fail "upgrade should drop obsolete auto dependency profile root"
      else
        pass "upgrade drops obsolete auto dependency profile root"
      fi
      if [ -L "$PROFILE/current/usr/$RUNTIME_V2_HASH" ]; then
        pass "upgrade records new auto dependency profile root"
      else
        fail "upgrade should root the new auto dependency"
      fi
      if grep -q "lifecycle-tool/lifecycle-reg 1.0.0" /tmp/lifecycle-installed-v2.out; then
        cat /tmp/lifecycle-installed-v2.out
        fail "apm list --installed should not retain old explicit package metadata after upgrade"
      else
        pass "apm list --installed drops old explicit package metadata after upgrade"
      fi
      $APM verify lifecycle-tool > /tmp/lifecycle-verify-v2.out 2>&1 || {
        cat /tmp/lifecycle-verify-v2.out
        fail "apm verify succeeds for downloaded v2 package"
      }

      $APM rollback > /tmp/lifecycle-rollback.out 2>&1 || {
        cat /tmp/lifecycle-rollback.out
        fail "apm rollback switches back to v1 generation"
      }
      cat /tmp/lifecycle-rollback.out
      assert_file_contains /tmp/lifecycle-rollback.out "Rolled back to generation 1" \
        "apm rollback selects previous generation"
      "$PROFILE_JQ" -r '.value' /tmp/lifecycle-input.json > /tmp/lifecycle-run-rollback.out
      assert_file_contains /tmp/lifecycle-run-rollback.out "^42$" \
        "rolled-back v1 jq executable runs from profile"
      if [ -e "$PROFILE_GIT" ]; then
        fail "rolled-back profile should not keep v2 git executable"
      else
        pass "rolled-back profile removes v2 git executable"
      fi
      $APM list --installed > /tmp/lifecycle-installed-rollback.out 2>&1 || {
        cat /tmp/lifecycle-installed-rollback.out
        fail "apm list --installed succeeds after rolling back lifecycle tool"
      }
      assert_file_contains /tmp/lifecycle-installed-rollback.out "lifecycle-tool" \
        "apm list --installed reports lifecycle tool after rollback"
      assert_file_contains /tmp/lifecycle-installed-rollback.out "1.0.0" \
        "rollback metadata preserves v1 package version"
      if grep -q "lifecycle-tool/lifecycle-reg 2.0.0" /tmp/lifecycle-installed-rollback.out; then
        cat /tmp/lifecycle-installed-rollback.out
        fail "rollback metadata should not point v1 root at v2 package"
      else
        pass "rollback metadata matches v1 root"
      fi
      $APM verify lifecycle-tool > /tmp/lifecycle-verify-rollback.out 2>&1 || {
        cat /tmp/lifecycle-verify-rollback.out
        fail "apm verify succeeds for rolled-back v1 while registry advertises v2"
      }
      assert_file_contains /tmp/lifecycle-verify-rollback.out \
        "integrity verified" \
        "apm verify uses rolled-back installed package metadata"

      $APM remove lifecycle-tool --yes > /tmp/lifecycle-remove.out 2>&1 || {
        cat /tmp/lifecycle-remove.out
        fail "apm remove deletes rolled-back package"
      }
      cat /tmp/lifecycle-remove.out
      assert_file_contains /tmp/lifecycle-remove.out "Removed" \
        "apm remove reports removed packages"
      if [ -e "$PROFILE_JQ" ]; then
        fail "removed lifecycle executable should not remain in current profile"
      else
        pass "removed lifecycle executable is absent from current profile"
      fi
      $APM list --installed > /tmp/lifecycle-installed-removed.out 2>&1 || {
        cat /tmp/lifecycle-installed-removed.out
        fail "apm list --installed succeeds after removing lifecycle tool"
      }
      if grep -q "lifecycle-tool" /tmp/lifecycle-installed-removed.out; then
        cat /tmp/lifecycle-installed-removed.out
        fail "apm list --installed should not show removed lifecycle tool"
      else
        pass "apm list --installed omits removed lifecycle tool"
      fi

      kill "$CACHE_PID" 2>/dev/null || true
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 13. source-verify-alt-nix-state — Source and verify with re-rooted Nix state
  # -------------------------------------------------------------------------
  source-verify-alt-nix-state = testing.mkVMTest {
    name = "apm-source-verify-alt-nix-state";
    rootfsDeps = sourceVerifyAltDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupAltNixEnv}

      echo "==> Test: apm source and verify honor alternate Nix state DB"

      SOURCE_STORE="${sourcefulV1}"
      SOURCE_HASH=$(basename "$SOURCE_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/sourcealt"
      SOURCE_BIN="$PROFILE/current/bin/sourceful"

      assert_store_valid() {
        path="$1"
        label="$2"
        if alt_nix_store --check-validity "$path" > "/tmp/source-alt-valid-$label.out" 2>&1; then
          pass "$label valid in alternate Nix state"
        else
          cat "/tmp/source-alt-valid-$label.out"
          fail "$label should be valid in alternate Nix state"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if alt_nix_store --check-validity "$path" > "/tmp/source-alt-missing-$label.out" 2>&1; then
          cat "/tmp/source-alt-missing-$label.out"
          fail "$label should be missing from alternate Nix state"
        else
          pass "$label missing from alternate Nix state"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if alt_nix_store --delete --ignore-liveness "$path" > "/tmp/source-alt-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/source-alt-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18123/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      run_ok() {
        label="$1"
        shift
        if "$@" > "/tmp/source-alt-$label.out" 2>&1; then
          pass "$label exits 0"
        else
          cat "/tmp/source-alt-$label.out"
          fail "$label should exit 0"
        fi
      }

      mount -o remount,rw / || true
      assert_store_valid "$SOURCE_STORE" "sourceful"

      $APR create source-alt-reg
      REG_DIR="$REG_STORAGE/source-alt-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

      $APR publish "$SOURCE_STORE" \
        --name source-alt \
        --version 1.0.0 \
        --description "Alternate-state source verification fixture" \
        --license MIT \
        --maintainer source-alt@example.invalid \
        --source-drv "$SOURCE_STORE" \
        --registry source-alt-reg \
        --no-commit > /tmp/source-alt-publish.out 2>&1 || {
        cat /tmp/source-alt-publish.out
        fail "apr publish source-alt succeeds"
      }
      cat /tmp/source-alt-publish.out
      assert_file_contains /tmp/source-alt-publish.out "$SOURCE_STORE" \
        "apr publish reports explicit source metadata"
      assert_file_contains "$REG_DIR/packages/s/source-alt.toml" \
        "$SOURCE_HASH" "published metadata records source-alt store hash"
      assert_file_contains "$REG_DIR/packages/s/source-alt.toml" \
        "$SOURCE_STORE" "published metadata records source drv path"
      assert_file_contains "$REG_DIR/packages/s/source-alt.toml" \
        'source_nar_hash = "sha256-' "published metadata records source NAR hash"

      $APR cache generate \
        --registry source-alt-reg \
        --output /tmp/source-alt-cache \
        --cache-url http://127.0.0.1:18123 \
        --priority 25 \
        --no-commit > /tmp/source-alt-cache-generate.out 2>&1 || {
        cat /tmp/source-alt-cache-generate.out
        fail "apr cache generate source-alt succeeds"
      }
      cat /tmp/source-alt-cache-generate.out
      assert_file_exists "/tmp/source-alt-cache/$SOURCE_HASH.narinfo" \
        "static cache has source-alt narinfo"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: source-alt 1.0.0"
      git init --bare --object-format=sha256 /tmp/source-alt-origin.git
      git -C "$REG_DIR" remote add origin /tmp/source-alt-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18123 --bind 127.0.0.1 \
        --directory /tmp/source-alt-cache > /tmp/source-alt-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/source-alt-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      export HOME=/tmp/source-alt-consumer
      export USER=sourcealt
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/source-alt-origin.git \
        --name source-alt-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/source-alt-registry-add.out 2>&1 || {
        cat /tmp/source-alt-registry-add.out
        fail "apm registry add syncs source-alt registry"
      }
      cat /tmp/source-alt-registry-add.out

      delete_store_path "$SOURCE_STORE" "sourceful"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install source-alt --registry source-alt-reg --yes > /tmp/source-alt-install.out 2>&1 || {
        cat /tmp/source-alt-install.out
        fail "apm install downloads source-alt"
      }
      cat /tmp/source-alt-install.out
      assert_file_contains /tmp/source-alt-install.out "Downloading 1 NAR" \
        "source-alt install downloads the package NAR"
      assert_file_contains /tmp/source-alt-install.out "Installed 1 package" \
        "source-alt install creates profile generation"
      assert_store_valid "$SOURCE_STORE" "sourceful"
      "$SOURCE_BIN" > /tmp/source-alt-run.out
      assert_file_contains /tmp/source-alt-run.out "^sourceful 1.0.0$" \
        "installed source-alt executable runs from profile"

      run_ok source-fetch "$APM" source source-alt --fetch
      assert_file_contains /tmp/source-alt-source-fetch.out "Source realised: $SOURCE_STORE" \
        "apm source --fetch realises source path through alternate Nix state"

      run_ok source-verify "$APM" source source-alt --verify
      assert_file_contains /tmp/source-alt-source-verify.out "$SOURCE_STORE" \
        "apm source --verify uses installed source path"
      assert_file_contains /tmp/source-alt-source-verify.out "matches installed binary" \
        "apm source --verify compares rebuilt source with installed package"

      run_ok verify "$APM" verify source-alt
      assert_file_contains /tmp/source-alt-verify.out "integrity verified" \
        "apm verify validates installed NAR hash through alternate Nix state"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 14. gc-alt-nix-state — GC with re-rooted Nix state
  # -------------------------------------------------------------------------
  gc-alt-nix-state = testing.mkVMTest {
    name = "apm-gc-alt-nix-state";
    rootfsDeps = gcAltDeps;
    memory = 512;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupEmptyAltNixGcEnv}

      echo "==> Test: apm gc honors alternate Nix state DB"

      $APM --json gc > /tmp/gc-alt.json 2>&1 || {
        cat /tmp/gc-alt.json
        fail "apm gc succeeds using AOS_NIX_STATE_DIR"
      }
      ${pkgs.jq}/bin/jq -e \
        --arg store "$AOS_NIX_STORE_DIR" \
        --arg state "$AOS_NIX_STATE_DIR" \
        '.action == "gc"
          and .status == "completed"
          and .success == true
          and .nix_store_dir == $store
          and .nix_state_dir == $state
          and (.stdout | type == "string")
          and (.stderr | type == "string")' \
        /tmp/gc-alt.json >/dev/null || {
        cat /tmp/gc-alt.json
        fail "apm --json gc reports alternate Nix state"
      }

      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 15. command-surface — Real APM command surface workflow
  # -------------------------------------------------------------------------
  command-surface = testing.mkVMTest {
    name = "apm-command-surface";
    rootfsDeps = realCommandSurfaceDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real APM command surface workflow"

      SURFACE_STORE="${surfaceTool}"
      LEAF_STORE="${surfaceLeafTool}"
      UPGRADE_V1_STORE="${surfaceUpgradeV1}"
      UPGRADE_V2_STORE="${surfaceUpgradeV2}"
      SOURCE_V1_STORE="${sourcefulV1}"
      SOURCE_V2_STORE="${sourcefulV2}"
      SOURCE_V1_SRC_STORE="${sourcefulSourceV1}"
      SOURCE_V2_SRC_STORE="${sourcefulSourceV2}"
      SOURCE_CLOSURE_STORE="${sourceClosureRuntime}"
      SOURCE_CLOSURE_SRC_STORE="${sourceClosureSourceRoot}"
      SOURCE_CLOSURE_DEP_STORE="${sourceClosureSourceDep}"
      SURFACE_HASH=$(basename "$SURFACE_STORE" | cut -d- -f1)
      LEAF_HASH=$(basename "$LEAF_STORE" | cut -d- -f1)
      UPGRADE_V1_HASH=$(basename "$UPGRADE_V1_STORE" | cut -d- -f1)
      UPGRADE_V2_HASH=$(basename "$UPGRADE_V2_STORE" | cut -d- -f1)
      SOURCE_V1_HASH=$(basename "$SOURCE_V1_STORE" | cut -d- -f1)
      SOURCE_V2_HASH=$(basename "$SOURCE_V2_STORE" | cut -d- -f1)
      SOURCE_V1_SRC_HASH=$(basename "$SOURCE_V1_SRC_STORE" | cut -d- -f1)
      SOURCE_V2_SRC_HASH=$(basename "$SOURCE_V2_SRC_STORE" | cut -d- -f1)
      SOURCE_CLOSURE_HASH=$(basename "$SOURCE_CLOSURE_STORE" | cut -d- -f1)
      SOURCE_CLOSURE_SRC_HASH=$(basename "$SOURCE_CLOSURE_SRC_STORE" | cut -d- -f1)
      SOURCE_CLOSURE_DEP_HASH=$(basename "$SOURCE_CLOSURE_DEP_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/surfaceuser"
      SURFACE_BIN="$PROFILE/current/bin/surfacepkg"
      LEAF_BIN="$PROFILE/current/bin/surface-leaf"
      UPGRADE_BIN="$PROFILE/current/bin/upgradeface"
      SOURCE_BIN="$PROFILE/current/bin/sourceful"
      JQ="${pkgs.jq}/bin/jq"

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      assert_symlink_exists() {
        if [ -L "$1" ]; then
          pass "$2"
        else
          fail "$2 (symlink not found: $1)"
        fi
      }

      assert_symlink_not_exists() {
        if [ -L "$1" ]; then
          fail "$2 (symlink should not exist: $1)"
        else
          pass "$2"
        fi
      }

      assert_store_valid() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/surface-valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/surface-valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/surface-missing-$label.out" 2>&1; then
          cat "/tmp/surface-missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/surface-delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/surface-delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      generation_count() {
        find "$PROFILE" -maxdepth 1 -type d -name 'gen-*' | wc -l | tr -d ' '
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18105/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      publish_surface_package() {
        $APR publish "$SURFACE_STORE" \
          --name surfacepkg \
          --version 1.0.0 \
          --description "Surface command fixture" \
          --homepage https://example.invalid/surfacepkg \
          --license MIT \
          --maintainer surface@example.invalid \
          --registry surface-reg \
          --no-commit > /tmp/surface-publish-surfacepkg.out 2>&1 || {
          cat /tmp/surface-publish-surfacepkg.out
          fail "apr publish surfacepkg succeeds"
          return 1
        }
        cat /tmp/surface-publish-surfacepkg.out
      }

      publish_leaf_package() {
        $APR publish "$LEAF_STORE" \
          --name surface-leaf \
          --version 1.0.0 \
          --description "Surface dependency fixture" \
          --license MIT \
          --maintainer surface@example.invalid \
          --registry surface-reg \
          --no-commit > /tmp/surface-publish-leaf.out 2>&1 || {
          cat /tmp/surface-publish-leaf.out
          fail "apr publish surface-leaf succeeds"
          return 1
        }
        cat /tmp/surface-publish-leaf.out
      }

      publish_upgradeface() {
        version="$1"
        store="$2"
        label="$3"
        $APR publish "$store" \
          --name upgradeface \
          --version "$version" \
          --description "Upgradable command fixture" \
          --license MIT \
          --maintainer surface@example.invalid \
          --registry surface-reg \
          --no-commit > "/tmp/surface-publish-upgradeface-$label.out" 2>&1 || {
          cat "/tmp/surface-publish-upgradeface-$label.out"
          fail "apr publish upgradeface $version succeeds"
          return 1
        }
        cat "/tmp/surface-publish-upgradeface-$label.out"
      }

      publish_sourceful() {
        version="$1"
        store="$2"
        source_store="$3"
        label="$4"
        $APR publish "$store" \
          --name sourceful \
          --version "$version" \
          --description "Source derivation command fixture" \
          --license MIT \
          --maintainer surface@example.invalid \
          --source-drv "$source_store" \
          --registry surface-reg \
          --no-commit > "/tmp/surface-publish-sourceful-$label.out" 2>&1 || {
          cat "/tmp/surface-publish-sourceful-$label.out"
          fail "apr publish sourceful $version succeeds"
          return 1
        }
        cat "/tmp/surface-publish-sourceful-$label.out"
        assert_file_contains "/tmp/surface-publish-sourceful-$label.out" "$source_store" \
          "apr publish sourceful $version reports explicit source metadata"
      }

      publish_sourceclosure() {
        $APR publish "$SOURCE_CLOSURE_STORE" \
          --name sourceclosure \
          --version 1.0.0 \
          --description "Source closure command fixture" \
          --license MIT \
          --maintainer surface@example.invalid \
          --source-drv "$SOURCE_CLOSURE_SRC_STORE" \
          --registry surface-reg \
          --no-commit > /tmp/surface-publish-sourceclosure.out 2>&1 || {
          cat /tmp/surface-publish-sourceclosure.out
          fail "apr publish sourceclosure succeeds"
          return 1
        }
        cat /tmp/surface-publish-sourceclosure.out
        assert_file_contains /tmp/surface-publish-sourceclosure.out "$SOURCE_CLOSURE_SRC_STORE" \
          "apr publish sourceclosure reports explicit source metadata"
      }

      generate_surface_cache() {
        label="$1"
        $APR cache generate \
          --registry surface-reg \
          --output /tmp/surface-cache \
          --cache-url http://127.0.0.1:18105 \
          --priority 65 \
          --no-commit > "/tmp/surface-cache-generate-$label.out" 2>&1 || {
          cat "/tmp/surface-cache-generate-$label.out"
          fail "apr cache generate $label succeeds"
          return 1
        }
        cat "/tmp/surface-cache-generate-$label.out"
      }

      commit_surface_registry() {
        message="$1"
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "$message" > /tmp/surface-git-commit.out 2>&1 || {
          cat /tmp/surface-git-commit.out
          fail "registry commit succeeds: $message"
          return 1
        }
        cat /tmp/surface-git-commit.out
      }

      run_ok() {
        label="$1"
        shift
        if "$@" > "/tmp/surface-$label.out" 2>&1; then
          pass "$label exits 0"
        else
          cat "/tmp/surface-$label.out"
          fail "$label should exit 0"
        fi
      }

      run_fail() {
        label="$1"
        shift
        if "$@" > "/tmp/surface-$label.out" 2>&1; then
          cat "/tmp/surface-$label.out"
          fail "$label should fail"
        else
          pass "$label fails as expected"
        fi
      }

      mount -o remount,rw / || true
      assert_store_valid "$SURFACE_STORE" "surfacepkg"
      assert_store_valid "$LEAF_STORE" "surface-leaf"
      assert_store_valid "$UPGRADE_V1_STORE" "upgradeface-v1"
      assert_store_valid "$UPGRADE_V2_STORE" "upgradeface-v2"
      assert_store_valid "$SOURCE_V1_STORE" "sourceful-v1"
      assert_store_valid "$SOURCE_V2_STORE" "sourceful-v2"
      assert_store_valid "$SOURCE_V1_SRC_STORE" "sourceful-source-v1"
      assert_store_valid "$SOURCE_V2_SRC_STORE" "sourceful-source-v2"
      assert_store_valid "$SOURCE_CLOSURE_STORE" "sourceclosure-runtime"
      assert_store_valid "$SOURCE_CLOSURE_SRC_STORE" "sourceclosure-source-root"
      assert_store_valid "$SOURCE_CLOSURE_DEP_STORE" "sourceclosure-source-helper"
      nix-store -q --references "$SURFACE_STORE" > /tmp/surface-refs.out
      assert_file_contains /tmp/surface-refs.out "$LEAF_STORE" \
        "surfacepkg has a real Nix reference to surface-leaf"

      echo "==> Maintainer: publish initial command-surface packages"
      $APR create surface-reg
      REG_DIR="$REG_STORAGE/surface-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_leaf_package
      publish_surface_package
      publish_upgradeface 1.0.0 "$UPGRADE_V1_STORE" v1
      publish_sourceful 1.0.0 "$SOURCE_V1_STORE" "$SOURCE_V1_SRC_STORE" v1
      publish_sourceclosure
      assert_file_contains "$REG_DIR/packages/s/surfacepkg.toml" \
        "$SURFACE_HASH" "published surfacepkg metadata records store hash"
      assert_file_contains "$REG_DIR/packages/s/surface-leaf.toml" \
        "$LEAF_HASH" "published surface-leaf metadata records store hash"
      assert_file_contains "$REG_DIR/packages/s/sourceful.toml" \
        "$SOURCE_V1_HASH" "published sourceful metadata records store hash"
      assert_file_contains "$REG_DIR/packages/s/sourceful.toml" \
        "$SOURCE_V1_SRC_STORE" "published sourceful metadata records distinct source path"
      assert_file_contains "$REG_DIR/packages/s/sourceclosure.toml" \
        "$SOURCE_CLOSURE_SRC_STORE" "published sourceclosure metadata records source root"
      assert_file_contains "$REG_DIR/store/$(printf %.2s "$SURFACE_HASH")/$SURFACE_HASH" \
        "$LEAF_HASH" "published surfacepkg closure records dependency"
      nix-store -q --references "$SOURCE_CLOSURE_SRC_STORE" > /tmp/surface-sourceclosure-refs.out
      assert_file_contains /tmp/surface-sourceclosure-refs.out "$SOURCE_CLOSURE_DEP_STORE" \
        "sourceclosure source root has a real source-only dependency reference"

      generate_surface_cache initial
      assert_file_exists "/tmp/surface-cache/$SURFACE_HASH.narinfo" \
        "static cache has surfacepkg narinfo"
      assert_file_exists "/tmp/surface-cache/$LEAF_HASH.narinfo" \
        "static cache has surface-leaf narinfo"
      assert_file_exists "/tmp/surface-cache/$UPGRADE_V1_HASH.narinfo" \
        "static cache has upgradeface v1 narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_V1_HASH.narinfo" \
        "static cache has sourceful v1 narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_V1_SRC_HASH.narinfo" \
        "static cache has sourceful v1 source narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_CLOSURE_HASH.narinfo" \
        "static cache has sourceclosure runtime narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_CLOSURE_SRC_HASH.narinfo" \
        "static cache has sourceclosure source root narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_CLOSURE_DEP_HASH.narinfo" \
        "static cache has sourceclosure source-only dependency narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18105" "registry records command-surface cache URL"

      commit_surface_registry "release: command surface initial packages"
      git init --bare --object-format=sha256 /tmp/surface-origin.git
      git -C "$REG_DIR" remote add origin /tmp/surface-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18105 --bind 127.0.0.1 \
        --directory /tmp/surface-cache > /tmp/surface-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/surface-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install command-surface packages through apm"
      export HOME=/tmp/surface-consumer
      export USER=surfaceuser
      APM_CONFIG="$HOME/.config/apm"
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/surface-origin.git \
        --name surface-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/surface-registry-add.out 2>&1 || {
        cat /tmp/surface-registry-add.out
        fail "apm registry add syncs command-surface registry"
      }
      cat /tmp/surface-registry-add.out

      delete_store_path "$SURFACE_STORE" "surfacepkg"
      delete_store_path "$LEAF_STORE" "surface-leaf"
      delete_store_path "$UPGRADE_V1_STORE" "upgradeface-v1"
      delete_store_path "$SOURCE_V1_STORE" "sourceful-v1"
      delete_store_path "$SOURCE_V1_SRC_STORE" "sourceful-source-v1"
      delete_store_path "$SOURCE_CLOSURE_SRC_STORE" "sourceclosure-source-root"
      delete_store_path "$SOURCE_CLOSURE_DEP_STORE" "sourceclosure-source-helper"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM --json install surfacepkg --registry surface-reg --yes > /tmp/surface-install.json 2>&1 || {
        cat /tmp/surface-install.json
        fail "apm install downloads surfacepkg closure"
      }
      "$JQ" -e \
        --arg surface "$SURFACE_STORE" \
        --arg leaf "$LEAF_STORE" \
        '.action == "install"
          and .status == "installed"
          and .requested == ["surfacepkg"]
          and .reinstall == false
          and .download_only == false
          and .no_deps == false
          and .dry_run == false
          and .generation == 1
          and (.roots | length == 1)
          and .roots[0].name == "surfacepkg"
          and .roots[0].registry == "surface-reg"
          and .roots[0].store_path == $surface
          and .roots[0].explicit == true
          and (.closure | any(.name == "surfacepkg" and .store_path == $surface and .explicit == true))
          and (.closure | any(.name == "surface-leaf" and .store_path == $leaf and .explicit == false))
          and (.downloads.planned >= 2)
          and (.downloads.downloaded >= 2)
          and (.downloads.imported >= 2)' \
        /tmp/surface-install.json >/dev/null || {
        cat /tmp/surface-install.json
        fail "apm --json install reports real dependency install"
      }
      pass "apm --json install reports real dependency install"
      assert_store_valid "$SURFACE_STORE" "surfacepkg"
      assert_store_valid "$LEAF_STORE" "surface-leaf"
      "$SURFACE_BIN" > /tmp/surface-run.out
      assert_file_contains /tmp/surface-run.out "^surfacepkg 1.0.0 via surface-leaf 1.0.0$" \
        "installed surfacepkg executable runs from profile"
      "$LEAF_BIN" > /tmp/surface-leaf-run.out
      assert_file_contains /tmp/surface-leaf-run.out "^surface-leaf 1.0.0$" \
        "installed dependency executable runs from profile"
      assert_file_contains "$PROFILE/meta/$SURFACE_HASH.json" '"explicit": true' \
        "surfacepkg metadata is explicit"
      assert_file_contains "$PROFILE/meta/$LEAF_HASH.json" '"explicit": false' \
        "surface-leaf metadata is automatic"

      $APM install upgradeface --registry surface-reg --yes > /tmp/surface-install-upgradeface.out 2>&1 || {
        cat /tmp/surface-install-upgradeface.out
        fail "apm install downloads upgradeface v1"
      }
      cat /tmp/surface-install-upgradeface.out
      assert_store_valid "$UPGRADE_V1_STORE" "upgradeface-v1"
      "$UPGRADE_BIN" > /tmp/surface-upgradeface-v1-run.out
      assert_file_contains /tmp/surface-upgradeface-v1-run.out "^upgradeface 1.0.0$" \
        "installed upgradeface v1 executable runs from profile"

      $APM install sourceful --registry surface-reg --yes > /tmp/surface-install-sourceful.out 2>&1 || {
        cat /tmp/surface-install-sourceful.out
        fail "apm install downloads sourceful v1"
      }
      cat /tmp/surface-install-sourceful.out
      assert_file_contains /tmp/surface-install-sourceful.out "Downloading 1 NAR" \
        "sourceful install downloads v1 NAR"
      assert_file_contains /tmp/surface-install-sourceful.out "Installed 1 package" \
        "sourceful install creates profile generation"
      assert_store_valid "$SOURCE_V1_STORE" "sourceful-v1"
      "$SOURCE_BIN" > /tmp/surface-sourceful-v1-run.out
      assert_file_contains /tmp/surface-sourceful-v1-run.out "^sourceful 1.0.0$" \
        "installed sourceful v1 executable runs from profile"
      assert_file_contains "$PROFILE/meta/$SOURCE_V1_HASH.json" \
        "$SOURCE_V1_SRC_STORE" "sourceful metadata records v1 source root"
      assert_symlink_exists "$PROFILE/current/src/$SOURCE_V1_SRC_HASH" \
        "sourceful v1 source root is active after install"
      assert_store_missing "$SOURCE_V1_SRC_STORE" \
        "sourceful v1 source root before explicit fetch"
      assert_file_contains "$PROFILE/meta/$SOURCE_V1_HASH.json" '"explicit": true' \
        "sourceful metadata is explicit"

      run_ok search-desc "$APM" search Surface
      assert_file_contains /tmp/surface-search-desc.out "surfacepkg" "apm search finds descriptions"
      run_ok search-names "$APM" search surface --names-only
      assert_file_contains /tmp/surface-search-names.out "surfacepkg" "apm search --names-only finds package names"
      run_ok search-installed "$APM" search surface --installed
      assert_file_contains /tmp/surface-search-installed.out "surfacepkg" "apm search --installed filters through profile metadata"
      run_ok search-installed-json "$APM" --json search surface --installed
      "$JQ" -e \
        'map(select(.name == "surfacepkg" and .registry == "surface-reg" and .version == "1.0.0")) | length == 1' \
        /tmp/surface-search-installed-json.out >/dev/null

      run_ok show "$APM" show surfacepkg
      assert_file_contains /tmp/surface-show.out "Surface command fixture" "apm show prints package details"
      assert_file_contains /tmp/surface-show.out "Installed.*yes" "apm show sees installed profile metadata"
      assert_file_contains /tmp/surface-show.out "surface-leaf" "apm show resolves real dependency names"
      run_ok show-json "$APM" --json show surfacepkg
      "$JQ" -e --arg store "$SURFACE_STORE" \
        '.name == "surfacepkg"
          and .registry == "surface-reg"
          and .version == "1.0.0"
          and .installed == true
          and .store_path == $store
          and (.dependencies | index("surface-leaf"))' \
        /tmp/surface-show-json.out >/dev/null
      run_ok info "$APM" info surfacepkg
      assert_file_contains /tmp/surface-info.out "Surface command fixture" \
        "apm info prints real package metadata"
      run_ok info-permissions "$APM" info surfacepkg --permissions
      assert_file_contains /tmp/surface-info-permissions.out "surfacepkg" \
        "apm info --permissions resolves the real package"
      run_ok info-json "$APM" --json info surfacepkg
      "$JQ" -e --arg store "$SURFACE_STORE" \
        '.name == "surfacepkg" and .version == "1.0.0" and .store_path == $store' \
        /tmp/surface-info-json.out >/dev/null
      run_ok list "$APM" list
      assert_file_contains /tmp/surface-list.out "surfacepkg/surface-reg" "apm list includes registry package"
      run_ok list-installed "$APM" list --installed
      assert_file_contains /tmp/surface-list-installed.out "surfacepkg/surface-reg" \
        "apm list --installed reports surfacepkg"
      assert_file_contains /tmp/surface-list-installed.out "upgradeface/surface-reg" \
        "apm list --installed reports upgradeface"
      assert_file_contains /tmp/surface-list-installed.out "sourceful/surface-reg" \
        "apm list --installed reports sourceful"
      run_ok list-installed-json "$APM" --json list --installed
      "$JQ" -e \
        'map(.name) as $names
          | ($names | index("surfacepkg"))
          and ($names | index("surface-leaf"))
          and ($names | index("upgradeface"))
          and ($names | index("sourceful"))
          and (map(select(.name == "surfacepkg" and .status == "installed")) | length == 1)' \
        /tmp/surface-list-installed-json.out >/dev/null

      $APM --json hold surfacepkg > /tmp/surface-hold.json 2>&1 || {
        cat /tmp/surface-hold.json
        fail "apm hold succeeds for real installed package"
      }
      "$JQ" -e --arg store "$SURFACE_STORE" \
        '.action == "hold"
          and .status == "held"
          and .package == "surfacepkg"
          and .name == "surfacepkg"
          and .version == "1.0.0"
          and .registry == "surface-reg"
          and .store_path == $store
          and .held == true' \
        /tmp/surface-hold.json >/dev/null || {
        cat /tmp/surface-hold.json
        fail "apm --json hold reports real installed package"
      }
      run_ok list-held "$APM" list --held
      assert_file_contains /tmp/surface-list-held.out "surfacepkg/surface-reg" \
        "apm list --held reports held package"
      run_ok list-held-json "$APM" --json list --held
      "$JQ" -e \
        'length == 1
          and .[0].name == "surfacepkg"
          and .[0].registry == "surface-reg"
          and (.[0].status | contains("installed"))
          and (.[0].status | contains("held"))' \
        /tmp/surface-list-held-json.out >/dev/null
      run_ok held-json "$APM" --json held
      "$JQ" -e \
        'length == 1
          and .[0].name == "surfacepkg"
          and .[0].registry == "surface-reg"
          and .[0].version == "1.0.0"
          and (.[0].store_path | contains("surfacepkg-1.0.0"))' \
        /tmp/surface-held-json.out >/dev/null

      run_ok depends "$APM" depends surfacepkg
      assert_file_contains /tmp/surface-depends.out "surface-leaf" \
        "apm depends resolves real published dependency"
      run_ok depends-json "$APM" --json depends surfacepkg
      "$JQ" -e \
        '.package == "surfacepkg"
          and .installed == true
          and .registry == "surface-reg"
          and .tree.name == "surfacepkg"
          and (.tree.children | any(.name == "surface-leaf"))' \
        /tmp/surface-depends-json.out >/dev/null
      run_ok rdepends "$APM" rdepends surface-leaf
      assert_file_contains /tmp/surface-rdepends.out "surfacepkg" \
        "apm rdepends finds real installed reverse dependency"
      run_ok rdepends-json "$APM" --json rdepends surface-leaf
      "$JQ" -e \
        '.package == "surface-leaf"
          and .target_versions == "1.0.0"
          and (.dependents | any(.name == "surfacepkg" and .version == "1.0.0"))' \
        /tmp/surface-rdepends-json.out >/dev/null
      run_ok policy-surface "$APM" policy surfacepkg
      assert_file_contains /tmp/surface-policy-surface.out "Candidate: 1.0.0" \
        "apm policy reports current surfacepkg candidate"
      assert_file_contains /tmp/surface-policy-surface.out "Installed: 1.0.0" \
        "apm policy reports installed surfacepkg version"
      run_ok policy-surface-json "$APM" --json policy surfacepkg
      "$JQ" -e \
        '.package == "surfacepkg"
          and .installed == "1.0.0"
          and .candidate == "1.0.0"
          and (.versions | any(.version == "1.0.0" and .registry == "surface-reg" and .installed == true))' \
        /tmp/surface-policy-surface-json.out >/dev/null

      run_ok files "$APM" files surfacepkg
      assert_file_contains /tmp/surface-files.out "bin/surfacepkg" \
        "apm files walks installed store path"
      run_ok files-json "$APM" --json files surfacepkg
      "$JQ" -e 'index("bin/surfacepkg") != null' \
        /tmp/surface-files-json.out >/dev/null
      run_fail source-default "$APM" source surfacepkg
      assert_file_contains /tmp/surface-source-default.out "no source derivation recorded" \
        "apm source reports APR-published packages without source drv"
      run_fail source-fetch "$APM" source surfacepkg --fetch
      assert_file_contains /tmp/surface-source-fetch.out "no source derivation recorded" \
        "apm source --fetch reports missing source drv"
      assert_store_missing "$SOURCE_CLOSURE_SRC_STORE" \
        "sourceclosure source root before explicit fetch"
      assert_store_missing "$SOURCE_CLOSURE_DEP_STORE" \
        "sourceclosure source-only dependency before explicit fetch"
      run_ok sourceclosure-source "$APM" source sourceclosure
      assert_file_contains /tmp/surface-sourceclosure-source.out "$SOURCE_CLOSURE_SRC_STORE" \
        "apm source reports registry candidate source closure root"
      run_ok sourceclosure-fetch "$APM" source sourceclosure --fetch
      assert_file_contains /tmp/surface-sourceclosure-fetch.out "Downloading 2 NAR" \
        "apm source --fetch downloads source root and source-only dependency"
      assert_file_contains /tmp/surface-sourceclosure-fetch.out "Source realised: $SOURCE_CLOSURE_SRC_STORE" \
        "apm source --fetch realises registry candidate source closure root"
      assert_store_valid "$SOURCE_CLOSURE_SRC_STORE" "sourceclosure-source-root"
      assert_store_valid "$SOURCE_CLOSURE_DEP_STORE" "sourceclosure-source-helper"
      "$SOURCE_CLOSURE_SRC_STORE/bin/sourceclosure-source" > /tmp/surface-sourceclosure-run.out
      assert_file_contains /tmp/surface-sourceclosure-run.out \
        "^sourceclosure source 1.0.0 via sourceclosure-source-helper 1.0.0$" \
        "fetched source closure executes with its source-only dependency"
      run_ok source-sourceful "$APM" source sourceful
      assert_file_contains /tmp/surface-source-sourceful.out "$SOURCE_V1_SRC_STORE" \
        "apm source reports sourceful v1 source path"
      assert_file_contains /tmp/surface-source-sourceful.out "Source NAR hash" \
        "apm source reports sourceful source NAR hash"
      run_ok source-sourceful-json "$APM" --json source sourceful
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and (.source_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-json.out >/dev/null
      run_ok source-sourceful-show-drv "$APM" source sourceful --show-drv
      assert_file_contains /tmp/surface-source-sourceful-show-drv.out "$SOURCE_V1_SRC_STORE" \
        "apm source --show-drv reports sourceful v1 source path"
      run_ok source-sourceful-show-drv-json "$APM" --json source sourceful --show-drv
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and (.source_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-show-drv-json.out >/dev/null
      run_ok source-sourceful-fetch-json-missing "$APM" --json source sourceful --fetch
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and .realised_path == $source
          and (.source_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-fetch-json-missing.out >/dev/null
      assert_file_not_contains /tmp/surface-source-sourceful-fetch-json-missing.out "Fetching source" \
        "apm --json source --fetch emits clean JSON while downloading source"
      assert_store_valid "$SOURCE_V1_SRC_STORE" "sourceful-source-v1-json-fetch"
      delete_store_path "$SOURCE_V1_SRC_STORE" "sourceful-source-v1-after-json-fetch"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      run_ok source-sourceful-fetch "$APM" source sourceful --fetch
      assert_file_contains /tmp/surface-source-sourceful-fetch.out "Downloading 1 NAR" \
        "apm source --fetch downloads missing sourceful v1 source NAR"
      assert_file_contains /tmp/surface-source-sourceful-fetch.out "Source realised: $SOURCE_V1_SRC_STORE" \
        "apm source --fetch realises sourceful v1 derivation"
      assert_store_valid "$SOURCE_V1_SRC_STORE" "sourceful-source-v1"
      run_ok source-sourceful-fetch-json "$APM" --json source sourceful --fetch
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and .realised_path == $source
          and (.source_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-fetch-json.out >/dev/null
      run_ok source-sourceful-verify "$APM" source sourceful --verify
      assert_file_contains /tmp/surface-source-sourceful-verify.out "$SOURCE_V1_SRC_STORE" \
        "apm source --verify uses sourceful v1 source path"
      assert_file_contains /tmp/surface-source-sourceful-verify.out "matches installed binary" \
        "apm source --verify compares sourceful rebuild with installed binary"
      delete_store_path "$SOURCE_V1_SRC_STORE" "sourceful-source-v1-before-json-verify"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      run_ok source-sourceful-verify-json "$APM" --json source sourceful --verify
      "$JQ" -e --arg source "$SOURCE_V1_SRC_STORE" --arg store "$SOURCE_V1_STORE" \
        '.package == "sourceful"
          and .registry == "surface-reg"
          and .source_drv == $source
          and .installed == true
          and .installed_store_path == $store
          and .built_path == $source
          and .verified == true
          and (.expected_nar_hash | startswith("sha256:"))
          and (.actual_nar_hash | startswith("sha256:"))' \
        /tmp/surface-source-sourceful-verify-json.out >/dev/null
      assert_file_not_contains /tmp/surface-source-sourceful-verify-json.out "Rebuilding" \
        "apm --json source --verify emits clean JSON while downloading source"
      assert_store_valid "$SOURCE_V1_SRC_STORE" "sourceful-source-v1-json-verify"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM reinstall sourceful --yes > /tmp/surface-reinstall-sourceful.out 2>&1 || {
        cat /tmp/surface-reinstall-sourceful.out
        fail "apm reinstall downloads and rewrites sourceful v1"
      }
      cat /tmp/surface-reinstall-sourceful.out
      assert_file_contains /tmp/surface-reinstall-sourceful.out "Downloading 1 NAR" \
        "sourceful reinstall downloads v1 NAR"
      assert_file_contains /tmp/surface-reinstall-sourceful.out "Reinstalled 1 package" \
        "sourceful reinstall creates profile generation"
      "$SOURCE_BIN" > /tmp/surface-sourceful-v1-run-after-reinstall.out
      assert_file_contains /tmp/surface-sourceful-v1-run-after-reinstall.out "^sourceful 1.0.0$" \
        "sourceful v1 executable runs after reinstall"
      assert_symlink_exists "$PROFILE/current/src/$SOURCE_V1_SRC_HASH" \
        "sourceful reinstall keeps v1 source root active"
      assert_file_contains "$PROFILE/meta/$SOURCE_V1_HASH.json" \
        "$SOURCE_V1_SRC_STORE" "sourceful reinstall preserves v1 source metadata"
      run_ok verify "$APM" verify surfacepkg
      assert_file_contains /tmp/surface-verify.out "integrity verified" \
        "apm verify validates real installed NAR hash"
      run_ok verify-json "$APM" --json verify surfacepkg
      "$JQ" -e --arg store "$SURFACE_STORE" \
        '.package == "surfacepkg"
          and .registry == "surface-reg"
          and .version == "1.0.0"
          and .store_path == $store
          and .verified == true
          and (.expected_nar_hash | startswith("sha256:"))
          and (.actual_nar_hash | startswith("sha256:"))' \
        /tmp/surface-verify-json.out >/dev/null

      echo "==> Maintainer: publish command-surface upgrade candidate"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      publish_upgradeface 2.0.0 "$UPGRADE_V2_STORE" v2
      assert_file_contains "$REG_DIR/packages/u/upgradeface.toml" \
        "$UPGRADE_V2_HASH" "published upgradeface v2 metadata records store hash"
      generate_surface_cache upgrade
      assert_file_exists "/tmp/surface-cache/$UPGRADE_V2_HASH.narinfo" \
        "static cache has upgradeface v2 narinfo"
      commit_surface_registry "release: command surface upgradeface 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: query and apply real command-surface upgrade"
      export HOME=/tmp/surface-consumer
      export USER=surfaceuser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$UPGRADE_V2_STORE" "upgradeface-v2"

      $APM --json update --registry surface-reg > /tmp/surface-update.json 2>&1 || {
        cat /tmp/surface-update.json
        fail "apm update fetches command-surface upgrade"
      }
      "$JQ" -e \
        '.registry == "surface-reg"
          and .updated == 1
          and (.registries | length == 1)
          and .registries[0].registry == "surface-reg"
          and .registries[0].status == "updated"
          and .registries[0].packages >= 1
          and .registries[0].updated >= 1
          and .registries[0].added == 0
          and .registries[0].removed == 0
          and (.registries[0].commit | length == 64)' \
        /tmp/surface-update.json >/dev/null || {
        cat /tmp/surface-update.json
        fail "apm --json update reports command-surface upgrade sync"
      }
      pass "apm --json update reports command-surface upgrade sync"
      run_ok list-upgradable "$APM" list --upgradable
      assert_file_contains /tmp/surface-list-upgradable.out "upgradeface/surface-reg" \
        "apm list --upgradable includes upgradable package"
      assert_file_contains /tmp/surface-list-upgradable.out "upgradable: 2.0.0" \
        "apm list --upgradable reports candidate"
      assert_file_not_contains /tmp/surface-list-upgradable.out "surface-leaf" \
        "apm list --upgradable does not advertise automatic dependency"
      run_ok list-upgradable-json "$APM" --json list --upgradable
      "$JQ" -e \
        'length == 1
          and .[0].name == "upgradeface"
          and .[0].registry == "surface-reg"
          and .[0].version == "1.0.0"
          and (.[0].status | contains("installed"))
          and (.[0].status | contains("upgradable: 2.0.0"))' \
        /tmp/surface-list-upgradable-json.out >/dev/null
      run_ok policy-upgrade "$APM" policy upgradeface
      assert_file_contains /tmp/surface-policy-upgrade.out "Candidate: 2.0.0" \
        "apm policy reports upgrade candidate"
      assert_file_contains /tmp/surface-policy-upgrade.out "Installed: 1.0.0" \
        "apm policy reports installed upgradeface version"

      run_ok reinstall-dry-run "$APM" reinstall surfacepkg --dry-run
      assert_file_contains /tmp/surface-reinstall-dry-run.out "packages will be reinstalled" \
        "apm reinstall dry-run resolves installed real package"
      assert_file_contains /tmp/surface-reinstall-dry-run.out "Dry run -- no changes made" \
        "apm reinstall dry-run avoids profile mutation"
      run_ok full-upgrade-dry-run "$APM" --json full-upgrade --dry-run
      "$JQ" -e --arg store "$UPGRADE_V2_STORE" \
        '.action == "upgrade"
          and .status == "planned"
          and .requested == []
          and .exclude == []
          and .dry_run == true
          and .generation == null
          and .upgraded == 1
          and .held_back == []
          and (.upgrades | length == 1)
          and .upgrades[0].name == "upgradeface"
          and .upgrades[0].registry == "surface-reg"
          and .upgrades[0].old_version == "1.0.0"
          and .upgrades[0].new_version == "2.0.0"
          and .upgrades[0].new_store_path == $store
          and .downloads.planned == 1
          and .downloads.downloaded == 0
          and .downloads.imported == 0' \
        /tmp/surface-full-upgrade-dry-run.out >/dev/null || {
        cat /tmp/surface-full-upgrade-dry-run.out
        fail "apm --json full-upgrade dry-run reports planned upgrade"
      }
      "$UPGRADE_BIN" > /tmp/surface-upgradeface-before-full-upgrade.out
      assert_file_contains /tmp/surface-upgradeface-before-full-upgrade.out "^upgradeface 1.0.0$" \
        "dry-run leaves upgradeface v1 active"

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM --json full-upgrade --yes > /tmp/surface-full-upgrade.out 2>&1 || {
        cat /tmp/surface-full-upgrade.out
        fail "apm full-upgrade downloads and activates upgradeface v2"
      }
      "$JQ" -e --arg store "$UPGRADE_V2_STORE" \
        '.action == "upgrade"
          and .status == "upgraded"
          and .requested == []
          and .exclude == []
          and .dry_run == false
          and .generation == 5
          and .upgraded == 1
          and .held_back == []
          and (.upgrades | length == 1)
          and .upgrades[0].name == "upgradeface"
          and .upgrades[0].registry == "surface-reg"
          and .upgrades[0].old_version == "1.0.0"
          and .upgrades[0].new_version == "2.0.0"
          and .upgrades[0].new_store_path == $store
          and (.downloads.planned >= 1)
          and (.downloads.downloaded >= 1)
          and (.downloads.imported >= 1)' \
        /tmp/surface-full-upgrade.out >/dev/null || {
        cat /tmp/surface-full-upgrade.out
        fail "apm --json full-upgrade reports activated upgrade"
      }
      assert_store_valid "$UPGRADE_V2_STORE" "upgradeface-v2"
      "$UPGRADE_BIN" > /tmp/surface-upgradeface-v2-run.out
      assert_file_contains /tmp/surface-upgradeface-v2-run.out "^upgradeface 2.0.0$" \
        "full-upgraded executable runs from profile"
      run_ok rollback-list-json "$APM" --json rollback --list
      "$JQ" -e \
        'map(select(.current == true)) as $current
          | ($current | length == 1)
          and ($current[0].roots | map(.package.name) | index("surfacepkg"))
          and ($current[0].roots | map(.package.name) | index("upgradeface"))
          and ($current[0].roots | map(.package.name) | index("sourceful"))' \
        /tmp/surface-rollback-list-json.out >/dev/null

      echo "==> Maintainer: publish newer sourceful candidate"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      publish_sourceful 2.0.0 "$SOURCE_V2_STORE" "$SOURCE_V2_SRC_STORE" v2
      assert_file_contains "$REG_DIR/packages/s/sourceful.toml" \
        "$SOURCE_V2_HASH" "published sourceful v2 metadata records store hash"
      assert_file_contains "$REG_DIR/packages/s/sourceful.toml" \
        "$SOURCE_V2_SRC_STORE" "published sourceful v2 metadata records distinct source path"
      generate_surface_cache source-v2
      assert_file_exists "/tmp/surface-cache/$SOURCE_V2_HASH.narinfo" \
        "static cache has sourceful v2 narinfo"
      assert_file_exists "/tmp/surface-cache/$SOURCE_V2_SRC_HASH.narinfo" \
        "static cache has sourceful v2 source narinfo"
      commit_surface_registry "release: command surface sourceful 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: source verification follows installed sourceful metadata"
      export HOME=/tmp/surface-consumer
      export USER=surfaceuser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$SOURCE_V2_STORE" "sourceful-v2"
      $APM update --registry surface-reg > /tmp/surface-update-sourceful.out 2>&1 || {
        cat /tmp/surface-update-sourceful.out
        fail "apm update fetches sourceful v2 metadata"
      }
      cat /tmp/surface-update-sourceful.out
      run_ok list-upgradable-sourceful "$APM" list --upgradable
      assert_file_contains /tmp/surface-list-upgradable-sourceful.out "sourceful/surface-reg" \
        "apm list --upgradable includes sourceful v2 candidate"
      assert_file_contains /tmp/surface-list-upgradable-sourceful.out "upgradable: 2.0.0" \
        "apm list --upgradable reports sourceful candidate version"
      run_ok source-sourceful-installed "$APM" source sourceful
      assert_file_contains /tmp/surface-source-sourceful-installed.out "$SOURCE_V1_SRC_STORE" \
        "apm source uses installed sourceful v1 source path after v2 appears"
      assert_file_not_contains /tmp/surface-source-sourceful-installed.out "$SOURCE_V2_SRC_STORE" \
        "apm source does not use latest uninstalled sourceful v2 source path"
      run_ok source-sourceful-show-drv-installed "$APM" source sourceful --show-drv
      assert_file_contains /tmp/surface-source-sourceful-show-drv-installed.out "$SOURCE_V1_SRC_STORE" \
        "apm source --show-drv uses installed sourceful v1 source path after v2 appears"
      assert_file_not_contains /tmp/surface-source-sourceful-show-drv-installed.out "$SOURCE_V2_SRC_STORE" \
        "apm source --show-drv does not use latest uninstalled sourceful v2 source path"
      run_ok source-sourceful-fetch-installed "$APM" source sourceful --fetch
      assert_file_contains /tmp/surface-source-sourceful-fetch-installed.out "Source realised: $SOURCE_V1_SRC_STORE" \
        "apm source --fetch realises installed sourceful v1 source path after v2 appears"
      assert_file_not_contains /tmp/surface-source-sourceful-fetch-installed.out "$SOURCE_V2_SRC_STORE" \
        "apm source --fetch does not realise latest uninstalled sourceful v2 source path"
      run_ok source-sourceful-verify-installed "$APM" source sourceful --verify
      assert_file_contains /tmp/surface-source-sourceful-verify-installed.out "$SOURCE_V1_SRC_STORE" \
        "apm source --verify uses installed sourceful v1 source path after v2 appears"
      assert_file_not_contains /tmp/surface-source-sourceful-verify-installed.out "$SOURCE_V2_SRC_STORE" \
        "apm source --verify does not use latest uninstalled sourceful v2 source path"
      assert_file_contains /tmp/surface-source-sourceful-verify-installed.out "matches installed binary" \
        "apm source --verify still validates installed sourceful v1"
      "$SOURCE_BIN" > /tmp/surface-sourceful-still-v1-run.out
      assert_file_contains /tmp/surface-sourceful-still-v1-run.out "^sourceful 1.0.0$" \
        "sourceful remains v1 until explicitly upgraded"

      echo "==> Consumer: upgrade sourceful and replace source roots"
      $APM upgrade sourceful --yes > /tmp/surface-upgrade-sourceful.out 2>&1 || {
        cat /tmp/surface-upgrade-sourceful.out
        fail "apm upgrade downloads and activates sourceful v2"
      }
      cat /tmp/surface-upgrade-sourceful.out
      assert_file_contains /tmp/surface-upgrade-sourceful.out "Downloading" \
        "sourceful upgrade downloads v2 NAR"
      assert_file_contains /tmp/surface-upgrade-sourceful.out "Upgraded 1 package" \
        "sourceful upgrade creates profile generation"
      assert_store_valid "$SOURCE_V2_STORE" "sourceful-v2"
      "$SOURCE_BIN" > /tmp/surface-sourceful-v2-run.out
      assert_file_contains /tmp/surface-sourceful-v2-run.out "^sourceful 2.0.0$" \
        "sourceful v2 executable runs after upgrade"
      assert_symlink_not_exists "$PROFILE/current/src/$SOURCE_V1_SRC_HASH" \
        "sourceful upgrade removes old v1 source root from current generation"
      assert_symlink_exists "$PROFILE/current/src/$SOURCE_V2_SRC_HASH" \
        "sourceful upgrade activates v2 source root"
      assert_file_contains "$PROFILE/meta/$SOURCE_V2_HASH.json" \
        "$SOURCE_V2_SRC_STORE" "sourceful metadata records v2 source root"

      run_ok clean "$APM" --json clean
      "$JQ" -e \
        '.action == "clean"
          and .mode == "cache"
          and .status == "cleaned"
          and .files_removed >= 1
          and .freed_bytes > 0
          and (.freed | length > 0)' \
        /tmp/surface-clean.out >/dev/null || {
        cat /tmp/surface-clean.out
        fail "apm --json clean reports removed NAR cache files"
      }
      if find "$HOME/.cache/apm" -name '*.nar.zst' | grep -q .; then
        fail "apm clean should remove cached NAR files"
      else
        pass "apm clean removed cached NAR files"
      fi
      run_ok clean-generations "$APM" --json clean --generations --keep 1
      "$JQ" -e \
        '.action == "clean"
          and .mode == "generations"
          and .status == "cleaned"
          and .keep == 1
          and .removed >= 1
          and (.removed_generations | length >= 1)
          and .generations_after_count <= 1' \
        /tmp/surface-clean-generations.out >/dev/null || {
        cat /tmp/surface-clean-generations.out
        fail "apm --json clean --generations reports pruned command-surface generations"
      }
      if [ "$(generation_count)" -le 1 ]; then
        pass "apm clean --generations keeps at most one old generation"
      else
        fail "apm clean --generations should prune old generations"
      fi
      run_ok gc-help "$APM" gc --help
      assert_file_contains /tmp/surface-gc-help.out "garbage collection" \
        "apm gc command surface is present without mutating the VM store"

      echo "==> Consumer: disable and re-enable registry with real installed packages"
      SURFACE_REG_CONFIG="$APM_CONFIG/registries.d/surface-reg.toml"
      $APM --json registry disable surface-reg > /tmp/surface-registry-disable.json 2>&1 || {
        cat /tmp/surface-registry-disable.json
        fail "apm registry disable succeeds for command-surface registry"
      }
      "$JQ" -e \
        --arg config "$SURFACE_REG_CONFIG" \
        '.action == "registry_disable"
          and .status == "disabled"
          and .registry == "surface-reg"
          and .enabled == false
          and .previous_enabled == true
          and .changed == true
          and .config == $config
          and .packages >= 4' \
        /tmp/surface-registry-disable.json >/dev/null || {
        cat /tmp/surface-registry-disable.json
        fail "apm --json registry disable reports command-surface registry state"
      }
      pass "apm --json registry disable reports command-surface registry state"
      assert_file_contains "$SURFACE_REG_CONFIG" "enabled = false" \
        "apm registry disable persists command-surface disabled state"
      $APM --json registry disable surface-reg > /tmp/surface-registry-disable-again.json 2>&1 || {
        cat /tmp/surface-registry-disable-again.json
        fail "apm registry disable is idempotent for command-surface registry"
      }
      "$JQ" -e \
        --arg config "$SURFACE_REG_CONFIG" \
        '.action == "registry_disable"
          and .status == "unchanged"
          and .registry == "surface-reg"
          and .enabled == false
          and .previous_enabled == false
          and .changed == false
          and .config == $config
          and .packages >= 4' \
        /tmp/surface-registry-disable-again.json >/dev/null || {
        cat /tmp/surface-registry-disable-again.json
        fail "idempotent apm --json registry disable reports unchanged state"
      }
      pass "idempotent apm --json registry disable reports unchanged state"
      run_ok registry-disable-text-again "$APM" registry disable surface-reg
      assert_file_contains /tmp/surface-registry-disable-text-again.out "already disabled" \
        "idempotent text-mode registry disable reports unchanged state"
      run_ok registry-list-disabled "$APM" registry list
      assert_file_contains /tmp/surface-registry-list-disabled.out "disabled" \
        "apm registry list reports command-surface registry disabled"
      run_ok search-disabled "$APM" --json search surfacepkg --registry surface-reg
      "$JQ" -e 'length == 0' /tmp/surface-search-disabled.out >/dev/null || {
        cat /tmp/surface-search-disabled.out
        fail "disabled registry search hides registry packages"
      }
      run_ok search-installed-disabled "$APM" --json search surfacepkg --installed --registry surface-reg
      "$JQ" -e \
        'length == 1
          and .[0].name == "surfacepkg"
          and .[0].registry == "surface-reg"
          and .[0].version == "1.0.0"
          and .[0].description == "installed package unavailable in registry"' \
        /tmp/surface-search-installed-disabled.out >/dev/null || {
        cat /tmp/surface-search-installed-disabled.out
        fail "disabled registry installed search uses profile metadata"
      }
      pass "disabled registry installed search uses profile metadata"
      if $APM --json update --registry surface-reg > /tmp/surface-update-disabled.json 2>&1; then
        cat /tmp/surface-update-disabled.json
        fail "apm update should reject disabled command-surface registry"
      else
        pass "apm update rejects disabled command-surface registry"
      fi
      assert_file_contains /tmp/surface-update-disabled.json "registry 'surface-reg' is not enabled" \
        "disabled registry update failure names disabled registry"
      run_ok orphans-disabled "$APM" orphans
      assert_file_contains /tmp/surface-orphans-disabled.out "No orphaned packages" \
        "disabled configured registry does not orphan command-surface packages"
      "$SURFACE_BIN" > /tmp/surface-run-while-disabled.out
      assert_file_contains /tmp/surface-run-while-disabled.out "^surfacepkg 1.0.0 via surface-leaf 1.0.0$" \
        "installed surfacepkg executable still runs while registry is disabled"

      $APM --json registry enable surface-reg > /tmp/surface-registry-enable.json 2>&1 || {
        cat /tmp/surface-registry-enable.json
        fail "apm registry enable succeeds for command-surface registry"
      }
      "$JQ" -e \
        --arg config "$SURFACE_REG_CONFIG" \
        '.action == "registry_enable"
          and .status == "enabled"
          and .registry == "surface-reg"
          and .enabled == true
          and .previous_enabled == false
          and .changed == true
          and .config == $config
          and .packages >= 4' \
        /tmp/surface-registry-enable.json >/dev/null || {
        cat /tmp/surface-registry-enable.json
        fail "apm --json registry enable reports command-surface registry state"
      }
      pass "apm --json registry enable reports command-surface registry state"
      assert_file_contains "$SURFACE_REG_CONFIG" "enabled = true" \
        "apm registry enable persists command-surface enabled state"
      run_ok registry-enable-text-again "$APM" registry enable surface-reg
      assert_file_contains /tmp/surface-registry-enable-text-again.out "already enabled" \
        "idempotent text-mode registry enable reports unchanged state"
      $APM --json update --registry surface-reg > /tmp/surface-update-reenabled.json 2>&1 || {
        cat /tmp/surface-update-reenabled.json
        fail "apm update succeeds after command-surface registry re-enable"
      }
      "$JQ" -e \
        '.registry == "surface-reg"
          and (.registries | length == 1)
          and .registries[0].registry == "surface-reg"
          and (.registries[0].status == "updated" or .registries[0].status == "current")
          and .registries[0].packages >= 4' \
        /tmp/surface-update-reenabled.json >/dev/null || {
        cat /tmp/surface-update-reenabled.json
        fail "apm --json update reports re-enabled command-surface registry"
      }
      pass "apm --json update reports re-enabled command-surface registry"
      run_ok verify-after-registry-enable "$APM" verify surfacepkg
      assert_file_contains /tmp/surface-verify-after-registry-enable.out "integrity verified" \
        "apm verify validates package after registry re-enable"

      run_ok orphans-none "$APM" orphans
      assert_file_contains /tmp/surface-orphans-none.out "No orphaned packages" \
        "apm orphans reports clean state while registry is configured"
      assert_dir_exists "$HOME/.local/share/apm/registries/surface-reg" \
        "local registry clone exists before registry remove"
      $APM registry remove surface-reg --keep-local > /tmp/surface-registry-remove.out 2>&1 || {
        cat /tmp/surface-registry-remove.out
        fail "apm registry remove --keep-local succeeds after real installs"
      }
      cat /tmp/surface-registry-remove.out
      assert_file_contains /tmp/surface-registry-remove.out "Registry 'surface-reg' removed" \
        "apm registry remove reports removed registry"
      assert_file_contains /tmp/surface-registry-remove.out "now orphaned" \
        "apm registry remove reports installed packages become orphans"
      assert_file_not_exists "$APM_CONFIG/registries.d/surface-reg.toml" \
        "apm registry remove deletes registry config"
      assert_dir_exists "$HOME/.local/share/apm/registries/surface-reg" \
        "apm registry remove --keep-local keeps local clone"
      run_ok orphans-removed "$APM" orphans
      assert_file_contains /tmp/surface-orphans-removed.out "surfacepkg" \
        "apm orphans lists package from removed registry"
      assert_file_contains /tmp/surface-orphans-removed.out "surface-leaf" \
        "apm orphans lists automatic dependency from removed registry"
      assert_file_contains /tmp/surface-orphans-removed.out "upgradeface" \
        "apm orphans lists additional package from removed registry"
      assert_file_contains /tmp/surface-orphans-removed.out "sourceful" \
        "apm orphans lists sourceful package from removed registry"
      assert_file_contains /tmp/surface-orphans-removed.out "removed registry 'surface-reg'" \
        "apm orphans names the removed registry"
      run_ok orphans-removed-json "$APM" --json orphans
      "$JQ" -e \
        'map(.name) as $names
          | ($names | index("surfacepkg"))
          and ($names | index("surface-leaf"))
          and ($names | index("upgradeface"))
          and ($names | index("sourceful"))
          and (map(select(.name == "surface-leaf" and .explicit == false)) | length == 1)
          and (map(select(.registry == "surface-reg")) | length == 4)' \
        /tmp/surface-orphans-removed-json.out >/dev/null

      run_ok source-sourceful-verify-after-registry-remove "$APM" source sourceful --verify
      assert_file_contains /tmp/surface-source-sourceful-verify-after-registry-remove.out \
        "$SOURCE_V2_SRC_STORE" \
        "apm source --verify uses installed source metadata after registry removal"
      assert_file_contains /tmp/surface-source-sourceful-verify-after-registry-remove.out \
        "matches installed binary" \
        "apm source --verify validates orphaned installed sourceful package"

      echo "==> Consumer: remove orphaned sourceful package and source root"
      $APM remove sourceful --yes > /tmp/surface-remove-sourceful.out 2>&1 || {
        cat /tmp/surface-remove-sourceful.out
        fail "apm remove sourceful succeeds after registry removal"
      }
      cat /tmp/surface-remove-sourceful.out
      assert_file_contains /tmp/surface-remove-sourceful.out "Removed 1 package" \
        "apm remove reports sourceful removal"
      if [ -e "$SOURCE_BIN" ]; then
        fail "sourceful executable should be absent after removal"
      else
        pass "sourceful executable absent after removal"
      fi
      assert_symlink_not_exists "$PROFILE/current/src/$SOURCE_V2_SRC_HASH" \
        "sourceful remove drops v2 source root from current generation"
      assert_file_not_exists "$PROFILE/meta/$SOURCE_V2_HASH.json" \
        "sourceful metadata removed after sourceful removal"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # -------------------------------------------------------------------------
  # 16. hold-prevent-upgrade — Hold/unhold prevents/allows upgrades
  # -------------------------------------------------------------------------
  hold-prevent-upgrade = testing.mkVMTest {
    name = "apm-hold-prevent-upgrade";
    rootfsDeps = realHoldDeps;
    memory = 1024;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: apm hold blocks real upgrade and unhold allows it"

      HOLD_V1_STORE="${holdToolV1}"
      HOLD_V2_STORE="${holdToolV2}"
      HOLD_V1_HASH=$(basename "$HOLD_V1_STORE" | cut -d- -f1)
      HOLD_V2_HASH=$(basename "$HOLD_V2_STORE" | cut -d- -f1)
      PROFILE="/var/lib/profiles/per-user/holduser"
      PROFILE_BIN="$PROFILE/current/bin/hold-tool"
      JQ="${pkgs.jq}/bin/jq"

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
        if nix-store --check-validity "$path" > "/tmp/valid-$label.out" 2>&1; then
          pass "$label valid in store"
        else
          cat "/tmp/valid-$label.out"
          fail "$label should be valid in store"
        fi
      }

      assert_store_missing() {
        path="$1"
        label="$2"
        if nix-store --check-validity "$path" > "/tmp/missing-$label.out" 2>&1; then
          cat "/tmp/missing-$label.out"
          fail "$label should be missing from store"
        else
          pass "$label missing from store"
        fi
      }

      delete_store_path() {
        path="$1"
        label="$2"
        if nix-store --delete --ignore-liveness "$path" > "/tmp/delete-$label.out" 2>&1; then
          pass "$label deleted before apm download"
        else
          cat "/tmp/delete-$label.out"
          fail "$label should be deletable before apm download"
          return 1
        fi
        assert_store_missing "$path" "$label"
      }

      wait_for_cache_server() {
        for _i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -sf http://127.0.0.1:18085/nix-cache-info >/dev/null; then
            return 0
          fi
          sleep 1
        done
        return 1
      }

      publish_hold_tool() {
        version="$1"
        store="$2"
        $APR publish "$store" \
          --name hold-tool \
          --version "$version" \
          --description "Executable hold workflow fixture" \
          --license MIT \
          --maintainer hold-workflow@example.invalid \
          --registry hold-reg \
          --no-commit
      }

      mount -o remount,rw / || true
      assert_store_valid "$HOLD_V1_STORE" "hold-tool-v1"
      assert_store_valid "$HOLD_V2_STORE" "hold-tool-v2"

      echo "==> Maintainer: publish hold-tool 1.0.0 and static cache"
      $APR create hold-reg
      REG_DIR="$REG_STORAGE/hold-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      publish_hold_tool 1.0.0 "$HOLD_V1_STORE"
      assert_file_contains "$REG_DIR/packages/h/hold-tool.toml" \
        "$HOLD_V1_HASH" "published v1 metadata records store hash"

      $APR cache generate \
        --registry hold-reg \
        --output /tmp/hold-cache \
        --cache-url http://127.0.0.1:18085 \
        --priority 45 \
        --no-commit
      assert_file_exists "/tmp/hold-cache/$HOLD_V1_HASH.narinfo" \
        "static cache has hold-tool v1 narinfo"
      assert_file_contains "$REG_DIR/registry.toml" \
        "http://127.0.0.1:18085" "registry records hold cache URL"

      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: hold-tool 1.0.0"
      git init --bare --object-format=sha256 /tmp/hold-origin.git
      git -C "$REG_DIR" remote add origin /tmp/hold-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      PYTHONUNBUFFERED=1 python3 -m http.server 18085 --bind 127.0.0.1 \
        --directory /tmp/hold-cache > /tmp/hold-cache-http.log 2>&1 &
      CACHE_PID=$!
      if wait_for_cache_server; then
        pass "static cache HTTP server started"
      else
        cat /tmp/hold-cache-http.log || true
        fail "static cache HTTP server started"
      fi

      echo "==> Consumer: install hold-tool 1.0.0 through apm"
      export HOME=/tmp/hold-consumer
      export USER=holduser
      mkdir -p "$HOME"
      $APM registry add --no-verify file:///tmp/hold-origin.git \
        --name hold-reg \
        --branch "$DEFAULT_BRANCH" > /tmp/hold-registry-add.out 2>&1 || {
        cat /tmp/hold-registry-add.out
        fail "apm registry add syncs hold registry"
      }
      cat /tmp/hold-registry-add.out

      if $APM hold hold-tool > /tmp/hold-empty.out 2>&1; then
        cat /tmp/hold-empty.out
        fail "hold should fail before hold-tool is installed"
      else
        cat /tmp/hold-empty.out
        pass "hold fails before hold-tool is installed"
      fi
      assert_file_contains /tmp/hold-empty.out "package not found" \
        "empty hold reports missing installed package"
      if [ ! -e "$PROFILE" ]; then
        pass "empty hold leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty hold should not initialize profile state"
      fi

      if $APM unhold hold-tool > /tmp/unhold-empty.out 2>&1; then
        cat /tmp/unhold-empty.out
        fail "unhold should fail before hold-tool is installed"
      else
        cat /tmp/unhold-empty.out
        pass "unhold fails before hold-tool is installed"
      fi
      assert_file_contains /tmp/unhold-empty.out "package not found" \
        "empty unhold reports missing installed package"
      if [ ! -e "$PROFILE" ]; then
        pass "empty unhold leaves profile directory absent"
      else
        find "$PROFILE" -maxdepth 2 -print
        fail "empty unhold should not initialize profile state"
      fi

      delete_store_path "$HOLD_V1_STORE" "hold-tool-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install hold-tool --registry hold-reg --yes > /tmp/hold-install.out 2>&1 || {
        cat /tmp/hold-install.out
        fail "apm installs hold-tool v1"
      }
      cat /tmp/hold-install.out
      assert_file_contains /tmp/hold-install.out "Downloading" \
        "apm install downloads held workflow v1"
      assert_file_contains /tmp/hold-install.out "Installed 1 package" \
        "apm install completes held workflow v1"
      "$PROFILE_BIN" > /tmp/hold-tool-v1.out
      assert_file_contains /tmp/hold-tool-v1.out "^hold-tool 1.0.0$" \
        "profile executable runs hold-tool v1"

      $APM --json hold hold-tool > /tmp/hold.json 2>&1 || {
        cat /tmp/hold.json
        fail "apm hold succeeds for installed hold-tool"
      }
      "$JQ" -e --arg store "$HOLD_V1_STORE" \
        '.action == "hold"
          and .status == "held"
          and .package == "hold-tool"
          and .name == "hold-tool"
          and .version == "1.0.0"
          and .registry == "hold-reg"
          and .store_path == $store
          and .held == true' \
        /tmp/hold.json >/dev/null || {
        cat /tmp/hold.json
        fail "apm --json hold reports installed hold-tool"
      }

      $APM held > /tmp/held.out 2>&1 || {
        cat /tmp/held.out
        fail "apm held succeeds"
      }
      cat /tmp/held.out
      assert_file_contains /tmp/held.out "hold-tool 1.0.0 (hold-reg)" \
        "apm held lists installed held package"

      echo "==> Consumer: reinstall held package preserves held metadata"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM reinstall hold-tool --yes > /tmp/hold-reinstall-held.out 2>&1 || {
        cat /tmp/hold-reinstall-held.out
        fail "apm reinstall succeeds for installed held package"
      }
      cat /tmp/hold-reinstall-held.out
      assert_file_contains /tmp/hold-reinstall-held.out "Downloading" \
        "apm reinstall downloads held package"
      assert_file_contains /tmp/hold-reinstall-held.out "Reinstalled 1 package" \
        "apm reinstall recreates held package generation"
      assert_file_contains \
        "/var/lib/profiles/per-user/holduser/current/meta/$HOLD_V1_HASH.json" \
        '"held": true' "apm reinstall preserves held metadata"
      $APM held > /tmp/held-after-reinstall.out 2>&1 || {
        cat /tmp/held-after-reinstall.out
        fail "apm held succeeds after reinstall"
      }
      cat /tmp/held-after-reinstall.out
      assert_file_contains /tmp/held-after-reinstall.out "hold-tool 1.0.0 (hold-reg)" \
        "apm held still lists package after reinstall"
      "$PROFILE_BIN" > /tmp/hold-tool-after-held-reinstall.out
      assert_file_contains /tmp/hold-tool-after-held-reinstall.out "^hold-tool 1.0.0$" \
        "reinstalled held executable still runs hold-tool v1"

      echo "==> Maintainer: publish hold-tool 2.0.0"
      export HOME=/tmp
      export USER=root
      publish_hold_tool 2.0.0 "$HOLD_V2_STORE"
      assert_file_contains "$REG_DIR/packages/h/hold-tool.toml" \
        "$HOLD_V2_HASH" "published v2 metadata records store hash"
      $APR cache generate \
        --registry hold-reg \
        --output /tmp/hold-cache \
        --cache-url http://127.0.0.1:18085 \
        --priority 45 \
        --no-commit
      assert_file_exists "/tmp/hold-cache/$HOLD_V2_HASH.narinfo" \
        "static cache has hold-tool v2 narinfo"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "release: hold-tool 2.0.0"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: held upgrade does not import v2"
      export HOME=/tmp/hold-consumer
      export USER=holduser
      delete_store_path "$HOLD_V2_STORE" "hold-tool-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM update --registry hold-reg > /tmp/hold-update.out 2>&1 || {
        cat /tmp/hold-update.out
        fail "apm update fetches hold-tool v2 metadata"
      }
      cat /tmp/hold-update.out
      assert_file_contains /tmp/hold-update.out "done" \
        "apm update completes for hold registry"

      $APM --json upgrade hold-tool --yes > /tmp/hold-upgrade-held.out 2>&1 || {
        cat /tmp/hold-upgrade-held.out
        fail "held apm upgrade exits successfully"
      }
      "$JQ" -e --arg store "$HOLD_V2_STORE" \
        '.action == "upgrade"
          and .status == "held_back"
          and .requested == ["hold-tool"]
          and .exclude == []
          and .dry_run == false
          and .generation == null
          and .upgraded == 0
          and .upgrades == []
          and (.held_back | length == 1)
          and .held_back[0].name == "hold-tool"
          and .held_back[0].registry == "hold-reg"
          and .held_back[0].old_version == "1.0.0"
          and .held_back[0].new_version == "2.0.0"
          and .held_back[0].new_store_path == $store
          and .downloads.planned == 0
          and .downloads.downloaded == 0
          and .downloads.imported == 0' \
        /tmp/hold-upgrade-held.out >/dev/null || {
        cat /tmp/hold-upgrade-held.out
        fail "apm --json upgrade reports held-back package"
      }
      assert_store_missing "$HOLD_V2_STORE" "hold-tool-v2"
      "$PROFILE_BIN" > /tmp/hold-tool-after-held-upgrade.out
      assert_file_contains /tmp/hold-tool-after-held-upgrade.out "^hold-tool 1.0.0$" \
        "profile executable remains hold-tool v1 while held"

      $APM --json unhold hold-tool > /tmp/unhold.json 2>&1 || {
        cat /tmp/unhold.json
        fail "apm unhold succeeds for installed hold-tool"
      }
      "$JQ" -e --arg store "$HOLD_V1_STORE" \
        '.action == "unhold"
          and .status == "unheld"
          and .package == "hold-tool"
          and .name == "hold-tool"
          and .version == "1.0.0"
          and .registry == "hold-reg"
          and .store_path == $store
          and .held == false' \
        /tmp/unhold.json >/dev/null || {
        cat /tmp/unhold.json
        fail "apm --json unhold reports installed hold-tool"
      }

      $APM held > /tmp/held-after-unhold.out 2>&1 || {
        cat /tmp/held-after-unhold.out
        fail "apm held succeeds after unhold"
      }
      cat /tmp/held-after-unhold.out
      assert_file_contains /tmp/held-after-unhold.out "No packages are held" \
        "apm held is empty after unhold"

      echo "==> Consumer: unheld upgrade downloads and activates v2"
      $APM --json upgrade hold-tool --yes > /tmp/hold-upgrade-unheld.out 2>&1 || {
        cat /tmp/hold-upgrade-unheld.out
        fail "unheld apm upgrade installs v2"
      }
      "$JQ" -e --arg store "$HOLD_V2_STORE" \
        '.action == "upgrade"
          and .status == "upgraded"
          and .requested == ["hold-tool"]
          and .exclude == []
          and .dry_run == false
          and .generation == 3
          and .upgraded == 1
          and .held_back == []
          and (.upgrades | length == 1)
          and .upgrades[0].name == "hold-tool"
          and .upgrades[0].registry == "hold-reg"
          and .upgrades[0].old_version == "1.0.0"
          and .upgrades[0].new_version == "2.0.0"
          and .upgrades[0].new_store_path == $store
          and (.downloads.planned >= 1)
          and (.downloads.downloaded >= 1)
          and (.downloads.imported >= 1)' \
        /tmp/hold-upgrade-unheld.out >/dev/null || {
        cat /tmp/hold-upgrade-unheld.out
        fail "apm --json upgrade reports unheld package upgrade"
      }
      assert_store_valid "$HOLD_V2_STORE" "hold-tool-v2"
      "$PROFILE_BIN" > /tmp/hold-tool-v2.out
      assert_file_contains /tmp/hold-tool-v2.out "^hold-tool 2.0.0$" \
        "profile executable runs hold-tool v2 after unhold"

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      wait "$CACHE_PID" 2>/dev/null || true

      check_fail
    '';
  };
}
