# tests/vm/apm/e2e.nix -- End-to-end APR/APM lifecycle tests
#
# These tests exercise maintainer and consumer workflows with real Nix store
# paths, APR-published registry metadata, generated static caches, and APM
# install/upgrade/rollback commands. They intentionally avoid hand-written
# package TOML and fake cache database rows.
{
  testing,
  self,
  pkgs,
}: let
  fixtures = import ./fixtures.nix {
    pkgs = pkgs;
    aosPkg = self;
  };

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
    mkdir -p /var/lib/profiles /nix/var/nix/gcroots/aos-profiles
    if ! ${pkgs.util-linux}/bin/mountpoint -q /nix/var/nix/gcroots/aos-profiles; then
      ${pkgs.util-linux}/bin/mount --bind \
        /var/lib/profiles /nix/var/nix/gcroots/aos-profiles
    fi
  '';

  shellHelpers = ''
    assert_file_not_contains() {
      file="$1"
      pattern="$2"
      label="$3"
      if grep -q "$pattern" "$file" 2>/dev/null; then
        fail "$label (pattern '$pattern' unexpectedly found in $file)"
        cat "$file" 2>/dev/null || true
      else
        pass "$label"
      fi
    }

    assert_store_valid() {
      path="$1"
      label="$2"
      if nix-store --check-validity "$path" > "/tmp/e2e-valid-$label.out" 2>&1; then
        pass "$label valid in store"
      else
        cat "/tmp/e2e-valid-$label.out"
        fail "$label should be valid in store"
      fi
    }

    delete_store_path() {
      path="$1"
      label="$2"
      if nix-store --delete --ignore-liveness "$path" > "/tmp/e2e-delete-$label.out" 2>&1; then
        pass "$label deleted before APM download"
      else
        cat "/tmp/e2e-delete-$label.out"
        fail "$label should be deletable before APM download"
        return
      fi

      if nix-store --check-validity "$path" > "/tmp/e2e-missing-$label.out" 2>&1; then
        cat "/tmp/e2e-missing-$label.out"
        fail "$label should be missing before APM download"
      else
        pass "$label missing before APM download"
      fi
    }

    run_logged() {
      log="$1"
      shift
      status_file="$log.status"
      rm -f "$log" "$status_file"

      (
        set +e
        "$@"
        status="$?"
        printf '%s\n' "$status" > "$status_file"
        exit "$status"
      ) 2>&1 | tee "$log"

      status=$(cat "$status_file" 2>/dev/null || printf '125\n')
      rm -f "$status_file"
      return "$status"
    }

    start_static_cache() {
      port="$1"
      directory="$2"
      log="$3"
      PYTHONUNBUFFERED=1 python3 -m http.server "$port" --bind 127.0.0.1 \
        --directory "$directory" > "$log" 2>&1 &
      CACHE_PID=$!

      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf "http://127.0.0.1:$port/nix-cache-info" >/dev/null; then
          pass "static cache HTTP server started on $port"
          return
        fi
        sleep 1
      done

      cat "$log" 2>/dev/null || true
      fail "static cache HTTP server started on $port"
    }

    stop_static_cache() {
      if [ "''${CACHE_PID:-}" ]; then
        kill "$CACHE_PID" 2>/dev/null || true
        wait "$CACHE_PID" 2>/dev/null || true
      fi
    }
  '';

  mkProfileTool = {
    pname,
    version,
    program,
    message,
    extraCommands ? "",
    extraRuntimeDeps ? [],
  }:
    pkgs.mkDerivation {
      inherit pname version;
      src = null;
      buildDeps = [
        pkgs.bash
        pkgs.coreutils
      ];
      runtimeDeps = extraRuntimeDeps;
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin" "$out/share/${program}"
            cat > "$out/bin/${program}" << 'TOOLEOF'
            #!${pkgs.bash}/bin/bash
            set -euo pipefail
            ${extraCommands}
            printf '%s\n' '${message}'
            TOOLEOF
            chmod +x "$out/bin/${program}"
            printf '%s\n' '${pname} ${version}' > "$out/share/${program}/payload.txt"
          '';
        }
      ];
    };

  e2eHelperV1 = mkProfileTool {
    pname = "e2e-helper";
    version = "1.0.0";
    program = "e2e-helper";
    message = "e2e-helper 1.0.0 executed";
  };

  e2eHelperV2 = mkProfileTool {
    pname = "e2e-helper";
    version = "2.0.0";
    program = "e2e-helper";
    message = "e2e-helper 2.0.0 executed";
  };

  e2eToolV1 = mkProfileTool {
    pname = "e2e-tool";
    version = "1.0.0";
    program = "e2e-tool";
    message = "e2e-tool 1.0.0 executed";
    extraCommands = ''
      "${e2eHelperV1}/bin/e2e-helper"
    '';
    extraRuntimeDeps = [e2eHelperV1];
  };

  e2eToolV2 = mkProfileTool {
    pname = "e2e-tool";
    version = "2.0.0";
    program = "e2e-tool";
    message = "e2e-tool 2.0.0 executed";
    extraCommands = ''
      "${e2eHelperV2}/bin/e2e-helper"
    '';
    extraRuntimeDeps = [e2eHelperV2];
  };

  fleetHelperV1 = mkProfileTool {
    pname = "fleet-helper";
    version = "1.0.0";
    program = "fleet-helper";
    message = "fleet-helper 1.0.0 executed";
  };

  fleetHelperV2 = mkProfileTool {
    pname = "fleet-helper";
    version = "2.0.0";
    program = "fleet-helper";
    message = "fleet-helper 2.0.0 executed";
  };

  fleetToolV1 = mkProfileTool {
    pname = "fleet-tool";
    version = "1.0.0";
    program = "fleet-tool";
    message = "fleet-tool 1.0.0 executed";
    extraCommands = ''
      "${fleetHelperV1}/bin/fleet-helper"
    '';
    extraRuntimeDeps = [fleetHelperV1];
  };

  fleetToolV2 = mkProfileTool {
    pname = "fleet-tool";
    version = "2.0.0";
    program = "fleet-tool";
    message = "fleet-tool 2.0.0 executed";
    extraCommands = ''
      "${fleetHelperV2}/bin/fleet-helper"
    '';
    extraRuntimeDeps = [fleetHelperV2];
  };

  mkSystemToplevel = {
    version,
    marker,
    serviceDescription,
  }:
    pkgs.mkDerivation {
      pname = "e2e-system-toplevel";
      inherit version;
      src = null;
      buildDeps = [
        pkgs.bash
        pkgs.coreutils
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin" "$out/etc/systemd/system" "$out/etc"
            cat > "$out/etc/os-release" << 'OSRELEASE'
            ID=aos
            NAME="ANDYL OS"
            VERSION_ID=${version}
            OSRELEASE
            cat > "$out/etc/systemd/system/e2e-app.service" << 'SERVICEEOF'
            [Unit]
            Description=${serviceDescription}

            [Service]
            Type=oneshot
            ExecStart=${pkgs.coreutils}/bin/true
            RemainAfterExit=yes

            [Install]
            WantedBy=multi-user.target
            SERVICEEOF
            cat > "$out/bin/e2e-system-version" << 'VERSIONEOF'
            #!${pkgs.bash}/bin/bash
            set -euo pipefail
            printf '%s\n' '${marker}'
            VERSIONEOF
            chmod +x "$out/bin/e2e-system-version"
            cat > "$out/activate" << 'ACTIVATEEOF'
            #!${pkgs.bash}/bin/bash
            set -euo pipefail
            echo "Activating e2e system ${version}"
            ${pkgs.coreutils}/bin/mkdir -p /tmp
            echo "${version}" > /tmp/e2e-system-activated-${version}
            echo "${version}" > /tmp/e2e-system-activated-current
            ACTIVATEEOF
            chmod +x "$out/activate"
          '';
        }
      ];
    };

  systemV1 = mkSystemToplevel {
    version = "2026.03";
    marker = "e2e system 2026.03";
    serviceDescription = "E2E system v1 service";
  };

  systemV2 = mkSystemToplevel {
    version = "2026.04";
    marker = "e2e system 2026.04";
    serviceDescription = "E2E system v2 service";
  };

  workflowDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.curl
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      e2eHelperV1
      e2eHelperV2
      e2eToolV1
      e2eToolV2
      fleetHelperV1
      fleetHelperV2
      fleetToolV1
      fleetToolV2
    ];

  systemWorkflowDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.curl
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      systemV1
      systemV2
    ];
in {
  # ---------------------------------------------------------------------------
  # Test 1: e2e-full-lifecycle -- package publish/install/upgrade/rollback/remove
  # ---------------------------------------------------------------------------
  e2e-full-lifecycle = testing.mkVMTest {
    name = "e2e-full-lifecycle";
    rootfsDeps = workflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}
      ${shellHelpers}

      echo "==> Test: APR/APM package lifecycle with real downloads"

      TOOL_V1_STORE="${e2eToolV1}"
      TOOL_V2_STORE="${e2eToolV2}"
      TOOL_V1_DEP_STORE="${e2eHelperV1}"
      TOOL_V2_DEP_STORE="${e2eHelperV2}"
      TOOL_V1_HASH=$(basename "$TOOL_V1_STORE" | cut -d- -f1)
      TOOL_V2_HASH=$(basename "$TOOL_V2_STORE" | cut -d- -f1)
      TOOL_V1_DEP_HASH=$(basename "$TOOL_V1_DEP_STORE" | cut -d- -f1)
      TOOL_V2_DEP_HASH=$(basename "$TOOL_V2_DEP_STORE" | cut -d- -f1)

      publish_e2e_tool() {
        version="$1"
        store_path="$2"
        dep_store_path="$3"
        run_logged "/tmp/e2e-publish-helper-$version.out" "$APR" publish "$dep_store_path" \
          --name e2e-helper \
          --version "$version" \
          --description "End-to-end package lifecycle dependency" \
          --license MIT \
          --maintainer e2e@example.invalid \
          --registry e2e-reg \
          --no-commit || {
          fail "apr publish e2e-helper $version"
        }

        run_logged "/tmp/e2e-publish-$version.out" "$APR" publish "$store_path" \
          --name e2e-tool \
          --version "$version" \
          --description "End-to-end package lifecycle tool" \
          --license MIT \
          --maintainer e2e@example.invalid \
          --registry e2e-reg \
          --no-commit || {
          fail "apr publish e2e-tool $version"
        }

        run_logged "/tmp/e2e-verify-$version.out" "$APR" verify --registry e2e-reg || {
          fail "apr verify accepts e2e-tool $version"
        }

        run_logged "/tmp/e2e-cache-$version.out" "$APR" cache generate \
          --registry e2e-reg \
          --output /tmp/e2e-cache \
          --cache-url http://127.0.0.1:18120 \
          --priority 45 \
          --no-commit || {
          fail "apr cache generate e2e-tool $version"
        }

        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: e2e-tool $version"
      }

      $APR create e2e-reg
      REG_DIR="$REG_STORAGE/e2e-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      git init --bare --object-format=sha256 /tmp/e2e-origin.git
      git -C /tmp/e2e-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/e2e-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      publish_e2e_tool 1.0.0 "$TOOL_V1_STORE" "$TOOL_V1_DEP_STORE"
      assert_file_exists "/tmp/e2e-cache/$TOOL_V1_HASH.narinfo" \
        "static cache has e2e-tool v1 narinfo"
      assert_file_exists "/tmp/e2e-cache/$TOOL_V1_DEP_HASH.narinfo" \
        "static cache has e2e-helper v1 narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      start_static_cache 18120 /tmp/e2e-cache /tmp/e2e-cache-http.log

      export HOME=/tmp/e2e-consumer
      export USER=e2euser
      PROFILE="/var/lib/profiles/per-user/$USER"
      mkdir -p "$HOME"
      run_logged /tmp/e2e-registry-add.out "$APM" registry add --no-verify file:///tmp/e2e-origin.git \
        --name e2e-reg \
        --branch "$DEFAULT_BRANCH" || {
        fail "apm registry add syncs e2e registry"
      }

      run_logged /tmp/e2e-search.out "$APM" search e2e-tool --registry e2e-reg || {
        fail "apm search finds e2e-tool"
      }
      assert_file_contains /tmp/e2e-search.out "e2e-tool" \
        "apm search reports published e2e-tool"
      run_logged /tmp/e2e-show-v1.out "$APM" show e2e-tool --registry e2e-reg || {
        fail "apm show resolves e2e-tool v1"
      }
      assert_file_contains /tmp/e2e-show-v1.out "Version.*1.0.0" \
        "apm show reports e2e-tool v1"

      mount -o remount,rw / || true
      delete_store_path "$TOOL_V1_STORE" "e2e-tool-v1"
      delete_store_path "$TOOL_V1_DEP_STORE" "e2e-helper-v1"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      run_logged /tmp/e2e-install-v1.out "$APM" install e2e-tool --registry e2e-reg --yes || {
        fail "apm install downloads e2e-tool v1"
      }
      assert_file_contains /tmp/e2e-install-v1.out "Downloading 2 NAR" \
        "apm install downloads e2e-tool v1 closure"
      assert_file_contains /tmp/e2e-install-v1.out "Installed 1 package" \
        "apm install creates e2e profile generation"
      assert_store_valid "$TOOL_V1_STORE" "e2e-tool-v1"
      assert_store_valid "$TOOL_V1_DEP_STORE" "e2e-helper-v1"
      "$PROFILE/current/bin/e2e-tool" > /tmp/e2e-run-v1.out
      assert_file_contains /tmp/e2e-run-v1.out "e2e-helper 1.0.0 executed" \
        "installed e2e-tool v1 executes dependency"
      assert_file_contains /tmp/e2e-run-v1.out "e2e-tool 1.0.0 executed" \
        "installed e2e-tool v1 executes from profile"
      "$PROFILE/current/bin/e2e-helper" > /tmp/e2e-helper-run-v1.out
      assert_file_contains /tmp/e2e-helper-run-v1.out "e2e-helper 1.0.0 executed" \
        "installed e2e-helper v1 executes from profile"
      run_logged /tmp/e2e-verify-installed-v1.out "$APM" verify e2e-tool || {
        fail "apm verify succeeds for installed e2e-tool v1"
      }
      run_logged /tmp/e2e-installed-v1.out "$APM" list --installed || {
        fail "apm list --installed succeeds after installing e2e-tool v1"
      }
      assert_file_contains /tmp/e2e-installed-v1.out "e2e-tool/e2e-reg" \
        "apm list --installed reports e2e-tool v1"
      assert_file_contains /tmp/e2e-installed-v1.out "1.0.0" \
        "apm list --installed reports e2e-tool v1 version"
      assert_file_contains /tmp/e2e-installed-v1.out "e2e-helper/e2e-reg" \
        "apm list --installed reports e2e-helper dependency v1"

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      publish_e2e_tool 2.0.0 "$TOOL_V2_STORE" "$TOOL_V2_DEP_STORE"
      assert_file_exists "/tmp/e2e-cache/$TOOL_V2_HASH.narinfo" \
        "static cache has e2e-tool v2 narinfo"
      assert_file_exists "/tmp/e2e-cache/$TOOL_V2_DEP_HASH.narinfo" \
        "static cache has e2e-helper v2 narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      export HOME=/tmp/e2e-consumer
      export USER=e2euser
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$TOOL_V2_STORE" "e2e-tool-v2"
      delete_store_path "$TOOL_V2_DEP_STORE" "e2e-helper-v2"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      run_logged /tmp/e2e-update-v2.out "$APM" update --registry e2e-reg || {
        fail "apm update syncs e2e-tool v2"
      }
      run_logged /tmp/e2e-upgradable.out "$APM" list --upgradable || {
        fail "apm list --upgradable succeeds for e2e-tool"
      }
      assert_file_contains /tmp/e2e-upgradable.out "e2e-tool" \
        "apm list --upgradable reports e2e-tool"
      assert_file_contains /tmp/e2e-upgradable.out "2.0.0" \
        "apm list --upgradable reports e2e-tool v2"

      run_logged /tmp/e2e-upgrade.out "$APM" upgrade --yes || {
        fail "apm upgrade downloads e2e-tool v2"
      }
      assert_file_contains /tmp/e2e-upgrade.out "Downloading 2 NAR" \
        "apm upgrade downloads e2e-tool v2 closure"
      assert_file_contains /tmp/e2e-upgrade.out "Upgraded 1 package" \
        "apm upgrade creates e2e v2 generation"
      assert_store_valid "$TOOL_V2_STORE" "e2e-tool-v2"
      assert_store_valid "$TOOL_V2_DEP_STORE" "e2e-helper-v2"
      "$PROFILE/current/bin/e2e-tool" > /tmp/e2e-run-v2.out
      assert_file_contains /tmp/e2e-run-v2.out "e2e-helper 2.0.0 executed" \
        "upgraded e2e-tool v2 executes dependency"
      assert_file_contains /tmp/e2e-run-v2.out "e2e-tool 2.0.0 executed" \
        "upgraded e2e-tool v2 executes from profile"
      "$PROFILE/current/bin/e2e-helper" > /tmp/e2e-helper-run-v2.out
      assert_file_contains /tmp/e2e-helper-run-v2.out "e2e-helper 2.0.0 executed" \
        "upgraded e2e-helper v2 executes from profile"
      run_logged /tmp/e2e-installed-v2.out "$APM" list --installed || {
        fail "apm list --installed succeeds after upgrading e2e-tool v2"
      }
      assert_file_contains /tmp/e2e-installed-v2.out "e2e-tool/e2e-reg" \
        "apm list --installed reports e2e-tool v2"
      assert_file_contains /tmp/e2e-installed-v2.out "2.0.0" \
        "apm list --installed reports e2e-tool v2 version"
      assert_file_not_contains /tmp/e2e-installed-v2.out "1.0.0" \
        "apm list --installed drops e2e-tool v1 after upgrade"
      assert_file_contains /tmp/e2e-installed-v2.out "e2e-helper/e2e-reg" \
        "apm list --installed reports e2e-helper dependency v2"

      run_logged /tmp/e2e-rollback.out "$APM" rollback || {
        fail "apm rollback returns e2e-tool to v1"
      }
      assert_file_contains /tmp/e2e-rollback.out "Rolled back to generation 1" \
        "apm rollback selects e2e v1 generation"
      "$PROFILE/current/bin/e2e-tool" > /tmp/e2e-run-rollback.out
      assert_file_contains /tmp/e2e-run-rollback.out "e2e-helper 1.0.0 executed" \
        "rolled-back e2e-tool v1 executes dependency"
      assert_file_contains /tmp/e2e-run-rollback.out "e2e-tool 1.0.0 executed" \
        "rolled-back e2e-tool v1 executes from profile"
      "$PROFILE/current/bin/e2e-helper" > /tmp/e2e-helper-run-rollback.out
      assert_file_contains /tmp/e2e-helper-run-rollback.out "e2e-helper 1.0.0 executed" \
        "rolled-back e2e-helper v1 executes from profile"
      run_logged /tmp/e2e-verify-rollback.out "$APM" verify e2e-tool || {
        fail "apm verify succeeds after e2e rollback"
      }
      run_logged /tmp/e2e-installed-rollback.out "$APM" list --installed || {
        fail "apm list --installed succeeds after rolling back e2e-tool"
      }
      assert_file_contains /tmp/e2e-installed-rollback.out "e2e-tool/e2e-reg" \
        "apm list --installed reports rolled-back e2e-tool"
      assert_file_contains /tmp/e2e-installed-rollback.out "1.0.0" \
        "apm list --installed reports rolled-back e2e-tool v1"
      assert_file_contains /tmp/e2e-installed-rollback.out "e2e-helper/e2e-reg" \
        "apm list --installed reports rolled-back e2e-helper v1"

      run_logged /tmp/e2e-remove.out "$APM" remove e2e-tool --yes || {
        fail "apm remove deletes e2e-tool"
      }
      assert_file_contains /tmp/e2e-remove.out "Removed" \
        "apm remove reports e2e-tool removal"
      if [ -e "$PROFILE/current/bin/e2e-tool" ]; then
        fail "removed e2e-tool executable should not remain in current profile"
      else
        pass "removed e2e-tool executable is absent from current profile"
      fi
      run_logged /tmp/e2e-installed-after-remove.out "$APM" list --installed || {
        fail "apm list --installed succeeds after removing e2e-tool"
      }
      assert_file_not_contains /tmp/e2e-installed-after-remove.out "e2e-tool" \
        "apm list --installed omits removed e2e-tool"
      assert_file_contains /tmp/e2e-installed-after-remove.out "e2e-helper/e2e-reg" \
        "apm list --installed keeps orphaned e2e-helper before autoremove"

      run_logged /tmp/e2e-autoremove.out "$APM" autoremove --yes || {
        fail "apm autoremove deletes orphaned e2e-helper"
      }
      assert_file_contains /tmp/e2e-autoremove.out "Removed" \
        "apm autoremove reports orphaned e2e-helper removal"
      run_logged /tmp/e2e-installed-after-autoremove.out "$APM" list --installed || {
        fail "apm list --installed succeeds after autoremoving e2e-helper"
      }
      assert_file_not_contains /tmp/e2e-installed-after-autoremove.out "e2e-helper" \
        "apm list --installed omits autoremoved e2e-helper"

      stop_static_cache
      check_fail
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 2: e2e-system-lifecycle -- non-image hosts reject sysroot activation
  # ---------------------------------------------------------------------------
  e2e-system-lifecycle = testing.mkVMTest {
    name = "e2e-system-lifecycle";
    rootfsDeps = systemWorkflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}
      ${shellHelpers}

      echo "==> Test: APR/APM sysroot downloads fail closed without image authority"

      SYSTEM_V1_STORE="${systemV1}"
      SYSTEM_V2_STORE="${systemV2}"
      SYSTEM_V1_HASH=$(basename "$SYSTEM_V1_STORE" | cut -d- -f1)
      SYSTEM_V2_HASH=$(basename "$SYSTEM_V2_STORE" | cut -d- -f1)

      publish_system_version() {
        version="$1"
        store_path="$2"
        run_logged "/tmp/e2e-system-publish-$version.out" "$APR" publish "$store_path" \
          --name server \
          --version "$version" \
          --description "End-to-end system sysroot" \
          --license MIT \
          --maintainer e2e-system@example.invalid \
          --sysroot \
          --registry e2e-system-reg \
          --no-commit || {
          fail "apr publish system $version"
        }

        run_logged "/tmp/e2e-system-verify-$version.out" "$APR" verify --registry e2e-system-reg || {
          fail "apr verify accepts system $version"
        }

        run_logged "/tmp/e2e-system-cache-$version.out" "$APR" cache generate \
          --registry e2e-system-reg \
          --output /tmp/e2e-system-cache \
          --cache-url http://127.0.0.1:18121 \
          --priority 46 \
          --no-commit || {
          fail "apr cache generate system $version"
        }

        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: server $version"
      }

      $APR create e2e-system-reg
      REG_DIR="$REG_STORAGE/e2e-system-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      git init --bare --object-format=sha256 /tmp/e2e-system-origin.git
      git -C /tmp/e2e-system-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/e2e-system-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      publish_system_version 2026.03 "$SYSTEM_V1_STORE"
      assert_file_exists "/tmp/e2e-system-cache/$SYSTEM_V1_HASH.narinfo" \
        "static cache has system v1 narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      start_static_cache 18121 /tmp/e2e-system-cache /tmp/e2e-system-cache-http.log

      mkdir -p /etc/apm/registries.d /var/lib/apm/registries /var/lib/apm/remote \
        /var/lib/apm/cache /var/lib/profiles/system
      cat > /etc/apm/registries.d/e2e-system-reg.toml << CFGEOF
      [registry]
      name = "e2e-system-reg"
      url = "file:///tmp/e2e-system-origin.git"
      priority = 500
      enabled = true
      branch = "$DEFAULT_BRANCH"
      CFGEOF
      run_logged /tmp/e2e-system-clone.out git clone --branch "$DEFAULT_BRANCH" \
        /tmp/e2e-system-origin.git /var/lib/apm/registries/e2e-system-reg || {
        fail "system registry clone succeeds"
      }
      ln -sfn /var/lib/apm/registries/e2e-system-reg \
        /var/lib/apm/remote/e2e-system-reg

      mount -o remount,rw / || true
      delete_store_path "$SYSTEM_V1_STORE" "system-v1"
      if run_logged /tmp/e2e-system-install.out "$APM" install server --system \
        --registry e2e-system-reg --yes; then
        fail "apm install --system must reject a host without image-generation authority"
      else
        pass "apm install --system rejects a host without image-generation authority"
      fi
      assert_file_contains /tmp/e2e-system-install.out "Downloading" \
        "apm install --system downloads v1 sysroot"
      assert_file_contains /tmp/e2e-system-install.out "image generation state is absent" \
        "apm install --system explains the missing image-generation authority"
      assert_store_valid "$SYSTEM_V1_STORE" "system-v1"
      "$SYSTEM_V1_STORE/bin/e2e-system-version" > /tmp/e2e-system-run-v1.out
      assert_file_contains /tmp/e2e-system-run-v1.out "e2e system 2026.03" \
        "downloaded system v1 closure runs directly"
      if [ -e /var/lib/profiles/system/current ] || \
        [ -e /var/lib/profiles/system/state.json ] || \
        [ -e /tmp/e2e-system-activated-current ]; then
        fail "rejected v1 activation must not create or activate a system generation"
      else
        pass "rejected v1 activation leaves system generation state untouched"
      fi

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      publish_system_version 2026.04 "$SYSTEM_V2_STORE"
      assert_file_exists "/tmp/e2e-system-cache/$SYSTEM_V2_HASH.narinfo" \
        "static cache has system v2 narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      run_logged /tmp/e2e-system-pull-v2.out git -C /var/lib/apm/registries/e2e-system-reg pull --ff-only || {
        fail "system registry clone fast-forwards to v2"
      }

      delete_store_path "$SYSTEM_V2_STORE" "system-v2"
      if run_logged /tmp/e2e-system-install-v2.out "$APM" install server --system \
        --registry e2e-system-reg --yes; then
        fail "apm install --system must reject v2 without image-generation authority"
      else
        pass "apm install --system rejects v2 without image-generation authority"
      fi
      assert_file_contains /tmp/e2e-system-install-v2.out "Downloading" \
        "apm install --system downloads v2 sysroot before activation"
      assert_file_contains /tmp/e2e-system-install-v2.out "image generation state is absent" \
        "v2 activation reports the same image-generation authority boundary"
      assert_store_valid "$SYSTEM_V2_STORE" "system-v2"
      "$SYSTEM_V2_STORE/bin/e2e-system-version" > /tmp/e2e-system-run-v2.out
      assert_file_contains /tmp/e2e-system-run-v2.out "e2e system 2026.04" \
        "downloaded system v2 closure runs directly"

      if run_logged /tmp/e2e-system-upgrade.out "$APM" upgrade --system; then
        fail "apm upgrade --system must reject a host with no image generation"
      else
        pass "apm upgrade --system rejects a host with no image generation"
      fi
      if run_logged /tmp/e2e-system-rollback.out "$APM" rollback --system; then
        fail "apm rollback --system must reject a host with no image generation"
      else
        pass "apm rollback --system rejects a host with no image generation"
      fi
      if [ -e /var/lib/profiles/system/current ] || \
        [ -e /var/lib/profiles/system/state.json ] || \
        [ -e /tmp/e2e-system-activated-current ]; then
        fail "rejected legacy lifecycle commands must not create system state"
      else
        pass "rejected legacy lifecycle commands leave system state untouched"
      fi

      stop_static_cache
      check_fail
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 3: e2e-fleet-rolling-update -- two profile consumers rolling forward
  # ---------------------------------------------------------------------------
  e2e-fleet-rolling-update = testing.mkVMTest {
    name = "e2e-fleet-rolling-update";
    rootfsDeps = workflowDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}
      ${shellHelpers}

      echo "==> Test: APR/APM rolling update across two profile consumers"

      FLEET_V1_STORE="${fleetToolV1}"
      FLEET_V2_STORE="${fleetToolV2}"
      FLEET_V1_DEP_STORE="${fleetHelperV1}"
      FLEET_V2_DEP_STORE="${fleetHelperV2}"
      FLEET_V1_HASH=$(basename "$FLEET_V1_STORE" | cut -d- -f1)
      FLEET_V2_HASH=$(basename "$FLEET_V2_STORE" | cut -d- -f1)
      FLEET_V1_DEP_HASH=$(basename "$FLEET_V1_DEP_STORE" | cut -d- -f1)
      FLEET_V2_DEP_HASH=$(basename "$FLEET_V2_DEP_STORE" | cut -d- -f1)

      publish_fleet_tool() {
        version="$1"
        store_path="$2"
        dep_store_path="$3"
        run_logged "/tmp/fleet-publish-helper-$version.out" "$APR" publish "$dep_store_path" \
          --name fleet-helper \
          --version "$version" \
          --description "Fleet rolling update dependency" \
          --license MIT \
          --maintainer fleet@example.invalid \
          --registry fleet-reg \
          --no-commit || {
          fail "apr publish fleet-helper $version"
        }
        run_logged "/tmp/fleet-publish-$version.out" "$APR" publish "$store_path" \
          --name fleet-tool \
          --version "$version" \
          --description "Fleet rolling update tool" \
          --license MIT \
          --maintainer fleet@example.invalid \
          --registry fleet-reg \
          --no-commit || {
          fail "apr publish fleet-tool $version"
        }
        run_logged "/tmp/fleet-cache-$version.out" "$APR" cache generate \
          --registry fleet-reg \
          --output /tmp/fleet-cache \
          --cache-url http://127.0.0.1:18122 \
          --priority 47 \
          --no-commit || {
          fail "apr cache generate fleet-tool $version"
        }
        git -C "$REG_DIR" add -A
        git -C "$REG_DIR" commit -m "release: fleet-tool $version"
      }

      run_fleet_profile() {
        user="$1"
        expected_helper="$2"
        expected_tool="$3"
        "/var/lib/profiles/per-user/$user/current/bin/fleet-tool" \
          > "/tmp/fleet-run-$user.out"
        assert_file_contains "/tmp/fleet-run-$user.out" "$expected_helper" \
          "fleet profile $user runs dependency $expected_helper"
        assert_file_contains "/tmp/fleet-run-$user.out" "$expected_tool" \
          "fleet profile $user runs root $expected_tool"
        "/var/lib/profiles/per-user/$user/current/bin/fleet-helper" \
          > "/tmp/fleet-helper-run-$user.out"
        assert_file_contains "/tmp/fleet-helper-run-$user.out" "$expected_helper" \
          "fleet profile $user exposes dependency $expected_helper"
      }

      $APR create fleet-reg
      REG_DIR="$REG_STORAGE/fleet-reg"
      DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
      git init --bare --object-format=sha256 /tmp/fleet-origin.git
      git -C /tmp/fleet-origin.git symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
      git -C "$REG_DIR" remote add origin /tmp/fleet-origin.git
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      publish_fleet_tool 1.0.0 "$FLEET_V1_STORE" "$FLEET_V1_DEP_STORE"
      assert_file_exists "/tmp/fleet-cache/$FLEET_V1_HASH.narinfo" \
        "static cache has fleet-tool v1 narinfo"
      assert_file_exists "/tmp/fleet-cache/$FLEET_V1_DEP_HASH.narinfo" \
        "static cache has fleet-helper v1 narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
      start_static_cache 18122 /tmp/fleet-cache /tmp/fleet-cache-http.log

      mount -o remount,rw / || true
      delete_store_path "$FLEET_V1_STORE" "fleet-tool-v1"
      delete_store_path "$FLEET_V1_DEP_STORE" "fleet-helper-v1"

      export HOME=/tmp/fleet-a
      export USER=fleet_a
      mkdir -p "$HOME"
      run_logged /tmp/fleet-a-add.out "$APM" registry add --no-verify file:///tmp/fleet-origin.git \
        --name fleet-reg \
        --branch "$DEFAULT_BRANCH" || {
        fail "fleet A registry add succeeds"
      }
      run_logged /tmp/fleet-a-install-v1.out "$APM" install fleet-tool --registry fleet-reg --yes || {
        fail "fleet A installs v1"
      }
      assert_file_contains /tmp/fleet-a-install-v1.out "Downloading 2 NAR" \
        "fleet A downloads v1 closure"
      run_fleet_profile fleet_a \
        "fleet-helper 1.0.0 executed" \
        "fleet-tool 1.0.0 executed"

      export HOME=/tmp/fleet-b
      export USER=fleet_b
      mkdir -p "$HOME"
      delete_store_path "$FLEET_V1_STORE" "fleet-tool-v1-fleet-b"
      delete_store_path "$FLEET_V1_DEP_STORE" "fleet-helper-v1-fleet-b"
      run_logged /tmp/fleet-b-add.out "$APM" registry add --no-verify file:///tmp/fleet-origin.git \
        --name fleet-reg \
        --branch "$DEFAULT_BRANCH" || {
        fail "fleet B registry add succeeds"
      }
      run_logged /tmp/fleet-b-install-v1.out "$APM" install fleet-tool --registry fleet-reg --yes || {
        fail "fleet B installs v1"
      }
      assert_file_contains /tmp/fleet-b-install-v1.out "Downloading 2 NAR" \
        "fleet B downloads v1 closure"
      run_fleet_profile fleet_a \
        "fleet-helper 1.0.0 executed" \
        "fleet-tool 1.0.0 executed"
      run_fleet_profile fleet_b \
        "fleet-helper 1.0.0 executed" \
        "fleet-tool 1.0.0 executed"

      export HOME=/tmp
      APM_CONFIG="$HOME/.config/apm"
      publish_fleet_tool 2.0.0 "$FLEET_V2_STORE" "$FLEET_V2_DEP_STORE"
      assert_file_exists "/tmp/fleet-cache/$FLEET_V2_HASH.narinfo" \
        "static cache has fleet-tool v2 narinfo"
      assert_file_exists "/tmp/fleet-cache/$FLEET_V2_DEP_HASH.narinfo" \
        "static cache has fleet-helper v2 narinfo"
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      export HOME=/tmp/fleet-a
      export USER=fleet_a
      APM_CONFIG="$HOME/.config/apm"
      delete_store_path "$FLEET_V2_STORE" "fleet-tool-v2"
      delete_store_path "$FLEET_V2_DEP_STORE" "fleet-helper-v2"
      run_logged /tmp/fleet-a-update-v2.out "$APM" update --registry fleet-reg || {
        fail "fleet A update syncs v2"
      }
      run_logged /tmp/fleet-a-upgrade-v2.out "$APM" upgrade --yes || {
        fail "fleet A upgrades to v2"
      }
      assert_file_contains /tmp/fleet-a-upgrade-v2.out "Upgraded 1 package" \
        "fleet A upgrade creates v2 generation"
      assert_file_contains /tmp/fleet-a-upgrade-v2.out "Downloading 2 NAR" \
        "fleet A downloads v2 closure"
      run_fleet_profile fleet_a \
        "fleet-helper 2.0.0 executed" \
        "fleet-tool 2.0.0 executed"

      export HOME=/tmp/fleet-b
      export USER=fleet_b
      APM_CONFIG="$HOME/.config/apm"
      run_fleet_profile fleet_b \
        "fleet-helper 1.0.0 executed" \
        "fleet-tool 1.0.0 executed"

      delete_store_path "$FLEET_V2_STORE" "fleet-tool-v2-fleet-b"
      delete_store_path "$FLEET_V2_DEP_STORE" "fleet-helper-v2-fleet-b"
      run_logged /tmp/fleet-b-update-v2.out "$APM" update --registry fleet-reg || {
        fail "fleet B update syncs v2"
      }
      run_logged /tmp/fleet-b-upgrade-v2.out "$APM" upgrade --yes || {
        fail "fleet B upgrades to v2"
      }
      assert_file_contains /tmp/fleet-b-upgrade-v2.out "Downloading 2 NAR" \
        "fleet B downloads v2 closure"
      run_fleet_profile fleet_a \
        "fleet-helper 2.0.0 executed" \
        "fleet-tool 2.0.0 executed"
      run_fleet_profile fleet_b \
        "fleet-helper 2.0.0 executed" \
        "fleet-tool 2.0.0 executed"

      export HOME=/tmp/fleet-a
      export USER=fleet_a
      APM_CONFIG="$HOME/.config/apm"
      run_logged /tmp/fleet-a-rollback.out "$APM" rollback || {
        fail "fleet A rolls back to v1"
      }
      assert_file_contains /tmp/fleet-a-rollback.out "Rolled back to generation 1" \
        "fleet A rollback selects v1 generation"
      run_fleet_profile fleet_a \
        "fleet-helper 1.0.0 executed" \
        "fleet-tool 1.0.0 executed"

      export HOME=/tmp/fleet-b
      export USER=fleet_b
      APM_CONFIG="$HOME/.config/apm"
      run_fleet_profile fleet_b \
        "fleet-helper 2.0.0 executed" \
        "fleet-tool 2.0.0 executed"

      stop_static_cache
      check_fail
    '';
  };
}
