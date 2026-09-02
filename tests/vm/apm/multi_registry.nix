# tests/vm/apm/multi_registry.nix -- Multi-registry priority, cross-containment, mirror
#
# Three headless VM tests exercising multi-registry scenarios:
#   multi-registry-priority          -- higher priority registry wins end-to-end
#   multi-registry-cross-containment -- deps shared across registries
#   multi-registry-mirror            -- registry mirroring
{
  testing,
  self,
  pkgs,
}: let
  fixtures = import ./fixtures.nix {
    inherit pkgs;
    aosPkg = self;
  };
  iproute2Bin = "${pkgs.iproute2}/sbin/ip";
  sqliteBin = "${pkgs.sqlite}/bin/sqlite3";
  socatBin = "${pkgs.socat}/bin/socat";
  jqBin = "${pkgs.jq}/bin/jq";
  curlBin = "${pkgs.curl}/bin/curl";
  grepBin = "${pkgs.grep}/bin/grep";
  aosBin = "${self}/bin/aos";
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
  '';
  mkPriorityTool = {
    version,
    origin,
  }:
    pkgs.mkDerivation {
      pname = "priority-tool";
      inherit version;
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.bash
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin" "$out/share/priority-tool"
            printf '%s\n' \
              '#!${pkgs.bash}/bin/bash' \
              "printf 'priority-tool ${version} from ${origin}\\n'" \
              > "$out/bin/priority-tool"
            chmod +x "$out/bin/priority-tool"
            printf 'priority-tool ${version} from ${origin}\n' \
              > "$out/share/priority-tool/origin.txt"
          '';
        }
      ];
    };
  priorityLowTool = mkPriorityTool {
    version = "9.0.0";
    origin = "low-priority";
  };
  priorityHighTool = mkPriorityTool {
    version = "2.0.0";
    origin = "high-priority";
  };
  priorityHighUpgradeTool = mkPriorityTool {
    version = "2.1.0";
    origin = "high-priority";
  };
  mkSameVersionTool = origin:
    pkgs.mkDerivation {
      pname = "same-version-tool";
      version = "1.0.0";
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.bash
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin" "$out/share/same-version-tool"
            printf '%s\n' \
              '#!${pkgs.bash}/bin/bash' \
              "printf 'same-version-tool 1.0.0 from ${origin}\\n'" \
              > "$out/bin/same-version-tool"
            chmod +x "$out/bin/same-version-tool"
            printf 'same-version-tool 1.0.0 from ${origin}\n' \
              > "$out/share/same-version-tool/origin.txt"
          '';
        }
      ];
    };
  sameVersionLowTool = mkSameVersionTool "low-priority";
  sameVersionHighTool = mkSameVersionTool "high-priority";
  mkSwitchTool = origin:
    pkgs.mkDerivation {
      pname = "switch-tool";
      version = "1.0.0";
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.bash
      ];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out/bin" "$out/share/switch-tool"
            printf '%s\n' \
              '#!${pkgs.bash}/bin/bash' \
              "printf 'switch-tool 1.0.0 from ${origin}\\n'" \
              > "$out/bin/switch-tool"
            chmod +x "$out/bin/switch-tool"
            printf 'switch-tool 1.0.0 from ${origin}\n' \
              > "$out/share/switch-tool/origin.txt"
          '';
        }
      ];
    };
  switchLowTool = mkSwitchTool "low-priority";
  switchHighTool = mkSwitchTool "high-priority";
  priorityLowClient = pkgs.mkDerivation {
    pname = "priority-client";
    version = "1.0.0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.bash
      priorityLowTool
    ];
    runtimeDeps = [
      priorityLowTool
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin" "$out/share/priority-client"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            '"$(dirname "$0")/priority-tool"' \
            > "$out/bin/priority-client"
          chmod +x "$out/bin/priority-client"
          printf '%s\n' "${priorityLowTool}" \
            > "$out/share/priority-client/runtime-dep.txt"
        '';
      }
    ];
  };

  mkStoreDb = dir: ''
        ${sqliteBin} ${dir}/var/nix/db/db.sqlite << 'SQL'
        CREATE TABLE IF NOT EXISTS ValidPaths (
          id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
          path TEXT UNIQUE NOT NULL, hash TEXT NOT NULL,
          registrationTime INTEGER NOT NULL,
          deriver TEXT, narSize INTEGER, ultimate INTEGER, sigs TEXT, ca TEXT
        );
        CREATE TABLE IF NOT EXISTS Refs (
          referrer INTEGER NOT NULL, reference INTEGER NOT NULL,
          PRIMARY KEY (referrer, reference)
        );
        PRAGMA journal_mode=WAL;
    SQL
        chmod 666 ${dir}/var/nix/db/db.sqlite
        chmod 666 ${dir}/var/nix/db/db.sqlite-wal 2>/dev/null || true
        chmod 666 ${dir}/var/nix/db/db.sqlite-shm 2>/dev/null || true
        chmod 777 ${dir}/var/nix/db
  '';

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
  realPriorityDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.jq
      pkgs.python3
      pkgs.zstd
      priorityLowTool
      priorityHighTool
      priorityHighUpgradeTool
      priorityLowClient
      sameVersionLowTool
      sameVersionHighTool
      switchLowTool
      switchHighTool
    ];
in {
  # ---------------------------------------------------------------------------
  # Test 1: multi-registry-priority -- higher priority registry wins end-to-end
  # ---------------------------------------------------------------------------
  multi-registry-priority = testing.mkVMTest {
    name = "multi-registry-priority";
    rootfsDeps = realPriorityDeps;
    memory = 2048;
    testScript = ''
      ${fixtures.setupPreamble}
      ${setupNixEnv}

      echo "==> Test: real multi-registry priority resolution and install"

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

      maintainer_apr() {
        HOME=/tmp \
        USER=root \
        XDG_CONFIG_HOME=/tmp/.config \
        XDG_DATA_HOME=/tmp/.local/share \
        XDG_CACHE_HOME=/tmp/.cache \
          "$APR" "$@"
      }

      publish_priority_registry() {
        registry="$1"
        store_path="$2"
        version="$3"
        cache_dir="$4"
        cache_url="$5"

        maintainer_apr create "$registry"
        reg_dir="$REG_STORAGE/$registry"
        maintainer_apr publish "$store_path" \
          --name priority-tool \
          --version "$version" \
          --description "Priority-selected package from $registry" \
          --license MIT \
          --maintainer priority@example.invalid \
          --registry "$registry" \
          --no-commit
        maintainer_apr cache generate \
          --registry "$registry" \
          --output "$cache_dir" \
          --cache-url "$cache_url" \
          --priority 45 \
          --no-commit
        git -C "$reg_dir" add -A
        git -C "$reg_dir" commit -m "release: priority-tool $version"
        git init --bare --object-format=sha256 "/tmp/$registry-origin.git"
        git -C "$reg_dir" remote add origin "/tmp/$registry-origin.git"
        branch=$(git -C "$reg_dir" symbolic-ref --short HEAD)
        git -C "$reg_dir" push origin "$branch"
      }

      publish_priority_tool_update() {
        registry="$1"
        store_path="$2"
        version="$3"
        cache_dir="$4"
        cache_url="$5"

        reg_dir="$REG_STORAGE/$registry"
        maintainer_apr publish "$store_path" \
          --name priority-tool \
          --version "$version" \
          --description "Priority-selected package from $registry" \
          --license MIT \
          --maintainer priority@example.invalid \
          --registry "$registry" \
          --no-commit
        maintainer_apr cache generate \
          --registry "$registry" \
          --output "$cache_dir" \
          --cache-url "$cache_url" \
          --priority 45 \
          --no-commit
        git -C "$reg_dir" add -A
        git -C "$reg_dir" commit -m "release: priority-tool $version"
        branch=$(git -C "$reg_dir" symbolic-ref --short HEAD)
        git -C "$reg_dir" push origin "$branch"
      }

      publish_priority_client() {
        registry="$1"
        store_path="$2"
        cache_dir="$3"
        cache_url="$4"

        reg_dir="$REG_STORAGE/$registry"
        maintainer_apr publish "$store_path" \
          --name priority-client \
          --version 1.0.0 \
          --description "Client package depending on $registry priority-tool" \
          --license MIT \
          --maintainer priority@example.invalid \
          --registry "$registry" \
          --no-commit
        maintainer_apr cache generate \
          --registry "$registry" \
          --output "$cache_dir" \
          --cache-url "$cache_url" \
          --priority 45 \
          --no-commit
        git -C "$reg_dir" add -A
        git -C "$reg_dir" commit -m "release: priority-client 1.0.0"
        branch=$(git -C "$reg_dir" symbolic-ref --short HEAD)
        git -C "$reg_dir" push origin "$branch"
      }

      publish_same_version_tool() {
        registry="$1"
        store_path="$2"
        cache_dir="$3"
        cache_url="$4"

        reg_dir="$REG_STORAGE/$registry"
        maintainer_apr publish "$store_path" \
          --name same-version-tool \
          --version 1.0.0 \
          --description "Same-version package from $registry" \
          --license MIT \
          --maintainer priority@example.invalid \
          --registry "$registry" \
          --no-commit
        maintainer_apr cache generate \
          --registry "$registry" \
          --output "$cache_dir" \
          --cache-url "$cache_url" \
          --priority 45 \
          --no-commit
        git -C "$reg_dir" add -A
        git -C "$reg_dir" commit -m "release: same-version-tool 1.0.0"
        branch=$(git -C "$reg_dir" symbolic-ref --short HEAD)
        git -C "$reg_dir" push origin "$branch"
      }

      publish_switch_tool() {
        registry="$1"
        store_path="$2"
        cache_dir="$3"
        cache_url="$4"

        reg_dir="$REG_STORAGE/$registry"
        maintainer_apr publish "$store_path" \
          --name switch-tool \
          --version 1.0.0 \
          --description "Source-switch package from $registry" \
          --license MIT \
          --maintainer priority@example.invalid \
          --registry "$registry" \
          --no-commit
        maintainer_apr cache generate \
          --registry "$registry" \
          --output "$cache_dir" \
          --cache-url "$cache_url" \
          --priority 45 \
          --no-commit
        git -C "$reg_dir" add -A
        git -C "$reg_dir" commit -m "release: switch-tool 1.0.0"
        branch=$(git -C "$reg_dir" symbolic-ref --short HEAD)
        git -C "$reg_dir" push origin "$branch"
      }

      LOW_STORE="${priorityLowTool}"
      HIGH_STORE="${priorityHighTool}"
      HIGH_UPGRADE_STORE="${priorityHighUpgradeTool}"
      LOW_CLIENT_STORE="${priorityLowClient}"
      SAME_LOW_STORE="${sameVersionLowTool}"
      SAME_HIGH_STORE="${sameVersionHighTool}"
      SWITCH_LOW_STORE="${switchLowTool}"
      SWITCH_HIGH_STORE="${switchHighTool}"
      LOW_HASH=$(basename "$LOW_STORE" | cut -d- -f1)
      HIGH_HASH=$(basename "$HIGH_STORE" | cut -d- -f1)
      HIGH_UPGRADE_HASH=$(basename "$HIGH_UPGRADE_STORE" | cut -d- -f1)
      LOW_CLIENT_HASH=$(basename "$LOW_CLIENT_STORE" | cut -d- -f1)
      SAME_LOW_HASH=$(basename "$SAME_LOW_STORE" | cut -d- -f1)
      SAME_HIGH_HASH=$(basename "$SAME_HIGH_STORE" | cut -d- -f1)
      SWITCH_LOW_HASH=$(basename "$SWITCH_LOW_STORE" | cut -d- -f1)
      SWITCH_HIGH_HASH=$(basename "$SWITCH_HIGH_STORE" | cut -d- -f1)

      publish_priority_registry low-priority "$LOW_STORE" 9.0.0 \
        /tmp/low-priority-cache http://127.0.0.1:18101
      publish_priority_client low-priority "$LOW_CLIENT_STORE" \
        /tmp/low-priority-cache http://127.0.0.1:18101
      publish_same_version_tool low-priority "$SAME_LOW_STORE" \
        /tmp/low-priority-cache http://127.0.0.1:18101
      publish_switch_tool low-priority "$SWITCH_LOW_STORE" \
        /tmp/low-priority-cache http://127.0.0.1:18101
      publish_priority_registry high-priority "$HIGH_STORE" 2.0.0 \
        /tmp/high-priority-cache http://127.0.0.1:18102
      publish_same_version_tool high-priority "$SAME_HIGH_STORE" \
        /tmp/high-priority-cache http://127.0.0.1:18102
      publish_switch_tool high-priority "$SWITCH_HIGH_STORE" \
        /tmp/high-priority-cache http://127.0.0.1:18102
      LOW_BRANCH=$(git -C "$REG_STORAGE/low-priority" symbolic-ref --short HEAD)
      HIGH_BRANCH=$(git -C "$REG_STORAGE/high-priority" symbolic-ref --short HEAD)

      assert_file_exists "/tmp/low-priority-cache/$LOW_HASH.narinfo" \
        "low priority cache has package narinfo"
      assert_file_exists "/tmp/low-priority-cache/$LOW_CLIENT_HASH.narinfo" \
        "low priority cache has client narinfo"
      assert_file_exists "/tmp/high-priority-cache/$HIGH_HASH.narinfo" \
        "high priority cache has package narinfo"
      assert_file_exists "/tmp/low-priority-cache/$SAME_LOW_HASH.narinfo" \
        "low priority cache has same-version narinfo"
      assert_file_exists "/tmp/high-priority-cache/$SAME_HIGH_HASH.narinfo" \
        "high priority cache has same-version narinfo"
      assert_file_exists "/tmp/low-priority-cache/$SWITCH_LOW_HASH.narinfo" \
        "low priority cache has switch-tool narinfo"
      assert_file_exists "/tmp/high-priority-cache/$SWITCH_HIGH_HASH.narinfo" \
        "high priority cache has switch-tool narinfo"

      ${iproute2Bin} link set lo up || true
      ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      PYTHONUNBUFFERED=1 python3 -m http.server 18101 --bind 127.0.0.1 \
        --directory /tmp/low-priority-cache > /tmp/low-priority-cache-http.log 2>&1 &
      LOW_CACHE_PID=$!
      PYTHONUNBUFFERED=1 python3 -m http.server 18102 --bind 127.0.0.1 \
        --directory /tmp/high-priority-cache > /tmp/high-priority-cache-http.log 2>&1 &
      HIGH_CACHE_PID=$!
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if ${curlBin} -sf http://127.0.0.1:18101/nix-cache-info >/dev/null \
          && ${curlBin} -sf http://127.0.0.1:18102/nix-cache-info >/dev/null; then
          break
        fi
        sleep 1
      done
      if ${curlBin} -sf http://127.0.0.1:18101/nix-cache-info >/dev/null \
        && ${curlBin} -sf http://127.0.0.1:18102/nix-cache-info >/dev/null; then
        pass "priority static cache HTTP servers started"
      else
        cat /tmp/low-priority-cache-http.log || true
        cat /tmp/high-priority-cache-http.log || true
        fail "priority static cache HTTP servers started"
      fi

      export HOME=/tmp/priority-consumer
      export USER=priorityuser
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/low-priority-origin.git \
        --name low-priority \
        --branch "$LOW_BRANCH" \
        --priority 100
      $APM registry add --no-verify file:///tmp/high-priority-origin.git \
        --name high-priority \
        --branch "$HIGH_BRANCH" \
        --priority 900

      $APR list > /tmp/priority-registry-list.out 2>&1
      assert_file_contains /tmp/priority-registry-list.out \
        "high-priority (priority 900)" "apr list shows high priority registry"
      assert_file_contains /tmp/priority-registry-list.out \
        "low-priority (priority 100)" "apr list shows low priority registry"
      $APR --json list > /tmp/priority-registry-list.json 2>&1 || {
        cat /tmp/priority-registry-list.json
        fail "apr --json list reports configured priority registries"
      }
      if ${jqBin} -e '
        (map(select(.name == "high-priority"
          and .priority == 900
          and .status == "enabled"
          and .tracking == "branch:'"$HIGH_BRANCH"'")) | length == 1)
        and (map(select(.name == "low-priority"
          and .priority == 100
          and .status == "enabled"
          and .tracking == "branch:'"$LOW_BRANCH"'")) | length == 1)
      ' /tmp/priority-registry-list.json >/dev/null; then
        pass "apr --json list preserves priority and tracking metadata"
      else
        cat /tmp/priority-registry-list.json
        fail "apr --json list preserves priority and tracking metadata"
      fi
      ${aosBin} --json package registry list \
        > /tmp/priority-aos-registry-list.json 2>&1 || {
        cat /tmp/priority-aos-registry-list.json
        fail "apm registry list reports configured priority registries"
      }
      if ${jqBin} -e '
        (map(select(.name == "high-priority"
          and .priority == 900
          and .status == "enabled"
          and .tracking == "branch:'"$HIGH_BRANCH"'")) | length == 1)
        and (map(select(.name == "low-priority"
          and .priority == 100
          and .status == "enabled"
          and .tracking == "branch:'"$LOW_BRANCH"'")) | length == 1)
      ' /tmp/priority-aos-registry-list.json >/dev/null; then
        pass "apm registry list preserves priority and tracking metadata"
      else
        cat /tmp/priority-aos-registry-list.json
        fail "apm registry list preserves priority and tracking metadata"
      fi

      $APM search priority-tool > /tmp/priority-search.out 2>&1 || {
        cat /tmp/priority-search.out
        fail "apm search resolves priority-selected package"
      }
      cat /tmp/priority-search.out
      assert_file_contains /tmp/priority-search.out \
        "priority-tool/high-priority 2.0.0" \
        "search returns the high priority package"
      if grep -q "priority-tool/low-priority" /tmp/priority-search.out; then
        cat /tmp/priority-search.out
        fail "search should deduplicate lower priority package"
      else
        pass "search hides lower priority duplicate"
      fi
      $APM --json search priority-tool > /tmp/priority-search.json 2>&1 || {
        cat /tmp/priority-search.json
        fail "apm --json search resolves priority-selected package"
      }
      if ${jqBin} -e '
        (map(select(.name == "priority-tool"
          and .registry == "high-priority"
          and .version == "2.0.0")) | length == 1)
        and (map(select(.name == "priority-tool"
          and .registry == "low-priority")) | length == 0)
      ' /tmp/priority-search.json >/dev/null; then
        pass "apm --json search deduplicates priority-tool to high priority package"
      else
        cat /tmp/priority-search.json
        fail "apm --json search deduplicates priority-tool to high priority package"
      fi
      ${aosBin} --json package search priority-tool \
        > /tmp/priority-aos-package-search.json 2>&1 || {
        cat /tmp/priority-aos-package-search.json
        fail "apm search resolves priority-selected package"
      }
      if ${jqBin} -e '
        (map(select(.name == "priority-tool"
          and .registry == "high-priority"
          and .version == "2.0.0")) | length == 1)
        and (map(select(.name == "priority-tool"
          and .registry == "low-priority")) | length == 0)
      ' /tmp/priority-aos-package-search.json >/dev/null; then
        pass "apm search deduplicates priority-tool to high priority package"
      else
        cat /tmp/priority-aos-package-search.json
        fail "apm search deduplicates priority-tool to high priority package"
      fi
      $APM --json search priority-tool --registry low-priority \
        > /tmp/priority-search-low.json 2>&1 || {
        cat /tmp/priority-search-low.json
        fail "apm --json search --registry resolves lower priority package"
      }
      if ${jqBin} -e '
        (map(select(.name == "priority-tool"
          and .registry == "low-priority"
          and .version == "9.0.0")) | length == 1)
        and (map(select(.name == "priority-tool"
          and .registry == "high-priority")) | length == 0)
      ' /tmp/priority-search-low.json >/dev/null; then
        pass "apm --json search --registry reports selected lower priority package"
      else
        cat /tmp/priority-search-low.json
        fail "apm --json search --registry reports selected lower priority package"
      fi

      $APM policy priority-tool > /tmp/priority-policy.out 2>&1 || {
        cat /tmp/priority-policy.out
        fail "apm policy reports all registry candidates"
      }
      cat /tmp/priority-policy.out
      assert_file_contains /tmp/priority-policy.out "Candidate: 2.0.0" \
        "policy candidate follows registry priority over higher version"
      assert_file_contains /tmp/priority-policy.out "2.0.0  900  high-priority" \
        "policy lists high priority candidate"
      assert_file_contains /tmp/priority-policy.out "9.0.0  100  low-priority" \
        "policy lists lower priority candidate"
      $APM --json policy priority-tool > /tmp/priority-policy.json 2>&1 || {
        cat /tmp/priority-policy.json
        fail "apm --json policy reports all registry candidates"
      }
      if ${jqBin} -e '
        .package == "priority-tool"
        and .installed == null
        and .candidate == "2.0.0"
        and (.versions | length == 2)
        and (.versions[0].version == "2.0.0")
        and (.versions[0].priority == 900)
        and (.versions[0].registry == "high-priority")
        and (.versions[0].installed == false)
        and (.versions[1].version == "9.0.0")
        and (.versions[1].priority == 100)
        and (.versions[1].registry == "low-priority")
        and (.versions[1].installed == false)
      ' /tmp/priority-policy.json >/dev/null; then
        pass "apm --json policy orders duplicate candidates by priority"
      else
        cat /tmp/priority-policy.json
        fail "apm --json policy orders duplicate candidates by priority"
      fi

      $APM show priority-tool > /tmp/priority-show.out 2>&1 || {
        cat /tmp/priority-show.out
        fail "apm show uses priority-selected package"
      }
      assert_file_contains /tmp/priority-show.out "high-priority" \
        "show reports the high priority registry"
      assert_file_contains /tmp/priority-show.out "2.0.0" \
        "show reports the high priority version"

      export HOME=/tmp/priority-client-consumer
      export USER=priorityclient
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/low-priority-origin.git \
        --name low-priority \
        --branch "$LOW_BRANCH" \
        --priority 100
      $APM registry add --no-verify file:///tmp/high-priority-origin.git \
        --name high-priority \
        --branch "$HIGH_BRANCH" \
        --priority 900

      mount -o remount,rw / || true
      delete_store_path "$LOW_CLIENT_STORE" "low-priority-client-fresh"
      delete_store_path "$LOW_STORE" "low-priority-tool-client-dep"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install priority-client --registry low-priority --yes \
        > /tmp/priority-install-client-fresh.out 2>&1 || {
        cat /tmp/priority-install-client-fresh.out
        fail "apm install priority-client downloads selected-registry dependency"
      }
      cat /tmp/priority-install-client-fresh.out
      assert_file_contains /tmp/priority-install-client-fresh.out \
        "Additional dependencies" \
        "client install plans selected-registry priority-tool dependency"
      assert_file_contains /tmp/priority-install-client-fresh.out \
        "Downloading 2 NAR" \
        "client install downloads root and selected-registry dependency"
      assert_store_valid "$LOW_CLIENT_STORE" "fresh low priority client"
      assert_store_valid "$LOW_STORE" "fresh low priority client dependency"
      PROFILE_CLIENT="/var/lib/profiles/per-user/$USER/current/bin/priority-client"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/priority-tool"
      "$PROFILE_CLIENT" > /tmp/priority-run-client-fresh.out
      assert_file_contains /tmp/priority-run-client-fresh.out \
        "priority-tool 9.0.0 from low-priority" \
        "fresh client executes low-priority dependency"
      "$PROFILE_TOOL" > /tmp/priority-run-client-dep-fresh.out
      assert_file_contains /tmp/priority-run-client-dep-fresh.out \
        "priority-tool 9.0.0 from low-priority" \
        "fresh client exposes low-priority dependency executable"
      CURRENT_PROFILE="/var/lib/profiles/per-user/$USER/current"
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_CLIENT_HASH.json" \
        '"explicit": true' "client metadata is explicit"
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"explicit": false' "selected-registry dependency metadata is automatic"
      $APM list --installed > /tmp/priority-installed-client-fresh.out 2>&1
      assert_file_contains /tmp/priority-installed-client-fresh.out \
        "priority-client/low-priority 1.0.0" \
        "fresh client install records low-priority client"
      assert_file_contains /tmp/priority-installed-client-fresh.out \
        "priority-tool/low-priority 9.0.0" \
        "fresh client install records low-priority dependency"
      if ${grepBin} -q "priority-tool/high-priority" \
        /tmp/priority-installed-client-fresh.out; then
        cat /tmp/priority-installed-client-fresh.out
        fail "fresh client install should not pull high-priority duplicate dependency"
      else
        pass "fresh client install excludes high-priority duplicate dependency"
      fi

      delete_store_path "$HIGH_STORE" "high-priority-tool-client-explicit"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM install priority-tool --yes \
        > /tmp/priority-client-install-high-tool.out 2>&1 || {
        cat /tmp/priority-client-install-high-tool.out
        fail "apm install adds explicit high-priority duplicate beside client dependency"
      }
      cat /tmp/priority-client-install-high-tool.out
      assert_file_contains /tmp/priority-client-install-high-tool.out "Downloading" \
        "explicit duplicate install downloads high-priority NAR"
      assert_store_valid "$HIGH_STORE" "explicit high priority duplicate"
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"explicit": false' "explicit duplicate install keeps low dependency automatic"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_HASH.json" \
        '"explicit": true' "explicit duplicate install records high package as explicit"
      $APM --json list --installed \
        > /tmp/priority-installed-client-with-high-tool.json 2>&1 || {
        cat /tmp/priority-installed-client-with-high-tool.json
        fail "apm --json list --installed reports duplicate installed sources"
      }
      if ${jqBin} -e '
        map(select(.name == "priority-tool")) as $matches
        | ($matches | length == 2)
          and (map(select(.name == "priority-client"
            and .registry == "low-priority"
            and .version == "1.0.0")) | length == 1)
          and ($matches
            | map(select(.registry == "low-priority"
              and .version == "9.0.0"
              and (.status | contains("installed"))))
            | length == 1)
          and ($matches
            | map(select(.registry == "high-priority"
              and .version == "2.0.0"
              and (.status | contains("installed"))))
            | length == 1)
      ' /tmp/priority-installed-client-with-high-tool.json >/dev/null; then
        pass "apm --json list --installed keeps both duplicate sources visible"
      else
        cat /tmp/priority-installed-client-with-high-tool.json
        fail "apm --json list --installed keeps both duplicate sources visible"
      fi

      $APM --json hold priority-tool \
        > /tmp/priority-client-hold-high-tool.json 2>&1 || {
        cat /tmp/priority-client-hold-high-tool.json
        fail "apm --json hold selects explicit duplicate-name package"
      }
      if ${jqBin} -e --arg store "$HIGH_STORE" '
        .action == "hold"
        and .status == "held"
        and .name == "priority-tool"
        and .registry == "high-priority"
        and .store_path == $store
        and .held == true
      ' /tmp/priority-client-hold-high-tool.json >/dev/null; then
        pass "duplicate-name hold selects the explicit high-priority package"
      else
        cat /tmp/priority-client-hold-high-tool.json
        fail "duplicate-name hold should not hold the automatic low-priority dependency"
      fi
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"held": false' "duplicate-name hold leaves low dependency unheld"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_HASH.json" \
        '"held": true' "duplicate-name hold marks high explicit package held"
      $APM --json held > /tmp/priority-client-held-high-tool.json 2>&1 || {
        cat /tmp/priority-client-held-high-tool.json
        fail "apm --json held reports explicit duplicate-name hold"
      }
      if ${jqBin} -e --arg store "$HIGH_STORE" '
        length == 1
        and .[0].name == "priority-tool"
        and .[0].registry == "high-priority"
        and .[0].store_path == $store
      ' /tmp/priority-client-held-high-tool.json >/dev/null; then
        pass "held list reports only the high-priority duplicate"
      else
        cat /tmp/priority-client-held-high-tool.json
        fail "held list should not include the automatic low-priority dependency"
      fi

      $APM --json reinstall priority-tool --dry-run \
        > /tmp/priority-client-reinstall-high-tool-dry-run.json 2>&1 || {
        cat /tmp/priority-client-reinstall-high-tool-dry-run.json
        fail "apm --json reinstall --dry-run preserves explicit duplicate source"
      }
      if ${jqBin} -e --arg store "$HIGH_STORE" '
        .action == "reinstall"
        and .status == "planned"
        and .dry_run == true
        and (.roots | length == 1)
        and .roots[0].name == "priority-tool"
        and .roots[0].registry == "high-priority"
        and .roots[0].store_path == $store
      ' /tmp/priority-client-reinstall-high-tool-dry-run.json >/dev/null; then
        pass "duplicate-name reinstall dry-run preserves explicit high-priority source"
      else
        cat /tmp/priority-client-reinstall-high-tool-dry-run.json
        fail "duplicate-name reinstall dry-run should not select low-priority dependency"
      fi

      $APM --json reinstall priority-tool --yes \
        > /tmp/priority-client-reinstall-high-tool.json 2>&1 || {
        cat /tmp/priority-client-reinstall-high-tool.json
        fail "apm --json reinstall preserves explicit duplicate source"
      }
      if ${jqBin} -e --arg store "$HIGH_STORE" '
        .action == "reinstall"
        and .status == "reinstalled"
        and .dry_run == false
        and (.roots | length == 1)
        and .roots[0].registry == "high-priority"
        and .roots[0].store_path == $store
      ' /tmp/priority-client-reinstall-high-tool.json >/dev/null; then
        pass "duplicate-name reinstall preserves explicit high-priority source"
      else
        cat /tmp/priority-client-reinstall-high-tool.json
        fail "duplicate-name reinstall should not switch to low-priority dependency"
      fi
      PRE_UPGRADE_DUPLICATE_GENERATION=$(${jqBin} -r '.generation' \
        /tmp/priority-client-reinstall-high-tool.json)
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"explicit": false' "duplicate-name reinstall keeps low dependency automatic"
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"held": false' "duplicate-name reinstall keeps low dependency unheld"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_HASH.json" \
        '"explicit": true' "duplicate-name reinstall keeps high package explicit"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_HASH.json" \
        '"held": true' "duplicate-name reinstall preserves high package hold"
      "$PROFILE_TOOL" > /tmp/priority-tool-after-reinstall-high.out
      assert_file_contains /tmp/priority-tool-after-reinstall-high.out \
        "priority-tool 2.0.0 from high-priority" \
        "duplicate-name reinstall keeps high-priority executable active"

      $APM --json unhold priority-tool \
        > /tmp/priority-client-unhold-high-tool.json 2>&1 || {
        cat /tmp/priority-client-unhold-high-tool.json
        fail "apm --json unhold selects explicit duplicate-name package"
      }
      if ${jqBin} -e --arg store "$HIGH_STORE" '
        .action == "unhold"
        and .status == "unheld"
        and .name == "priority-tool"
        and .registry == "high-priority"
        and .store_path == $store
        and .held == false
      ' /tmp/priority-client-unhold-high-tool.json >/dev/null; then
        pass "duplicate-name unhold selects the explicit high-priority package"
      else
        cat /tmp/priority-client-unhold-high-tool.json
        fail "duplicate-name unhold should not target the automatic low-priority dependency"
      fi
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"held": false' "duplicate-name unhold leaves low dependency unheld"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_HASH.json" \
        '"held": false' "duplicate-name unhold clears high explicit package hold"
      $APM --json held > /tmp/priority-client-held-after-unhold.json 2>&1 || {
        cat /tmp/priority-client-held-after-unhold.json
        fail "apm --json held reports no duplicate holds after unhold"
      }
      if ${jqBin} -e 'length == 0' \
        /tmp/priority-client-held-after-unhold.json >/dev/null; then
        pass "held list is empty after duplicate-name unhold"
      else
        cat /tmp/priority-client-held-after-unhold.json
        fail "held list should be empty after duplicate-name unhold"
      fi

      CONSUMER_HOME="$HOME"
      CONSUMER_USER="$USER"
      CONSUMER_APM_CONFIG="$APM_CONFIG"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      publish_priority_tool_update high-priority "$HIGH_UPGRADE_STORE" 2.1.0 \
        /tmp/high-priority-cache http://127.0.0.1:18102
      export HOME="$CONSUMER_HOME"
      export USER="$CONSUMER_USER"
      APM_CONFIG="$CONSUMER_APM_CONFIG"
      assert_file_exists "/tmp/high-priority-cache/$HIGH_UPGRADE_HASH.narinfo" \
        "high priority cache has upgraded duplicate narinfo"
      delete_store_path "$HIGH_UPGRADE_STORE" "high-priority-tool-upgrade"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM --json update --registry high-priority \
        > /tmp/priority-client-update-high-upgrade.json 2>&1 || {
        cat /tmp/priority-client-update-high-upgrade.json
        fail "apm --json update fetches upgraded duplicate registry metadata"
      }
      if ${jqBin} -e '
        .registry == "high-priority"
        and .updated == 1
        and (.registries | length == 1)
        and .registries[0].registry == "high-priority"
        and .registries[0].status == "updated"
        and .registries[0].packages == 3
        and .registries[0].updated >= 1
        and (.registries[0].commit | length == 64)
      ' /tmp/priority-client-update-high-upgrade.json >/dev/null; then
        pass "apm --json update reports upgraded high-priority duplicate"
      else
        cat /tmp/priority-client-update-high-upgrade.json
        fail "apm --json update should report upgraded high-priority duplicate"
      fi
      $APM list --upgradable --registry high-priority \
        > /tmp/priority-client-upgradable-high-tool.out 2>&1 || {
        cat /tmp/priority-client-upgradable-high-tool.out
        fail "apm list --upgradable reports upgraded explicit duplicate"
      }
      assert_file_contains /tmp/priority-client-upgradable-high-tool.out \
        "priority-tool/high-priority 2.0.0" \
        "upgradable duplicate list keeps installed high-priority source"
      assert_file_contains /tmp/priority-client-upgradable-high-tool.out \
        "upgradable: 2.1.0" \
        "upgradable duplicate list reports upgraded high-priority version"
      $APM --json upgrade priority-tool --dry-run \
        > /tmp/priority-client-upgrade-high-tool-dry-run.json 2>&1 || {
        cat /tmp/priority-client-upgrade-high-tool-dry-run.json
        fail "apm --json upgrade --dry-run plans explicit duplicate upgrade"
      }
      if ${jqBin} -e \
        --arg old_hash "$HIGH_HASH" \
        --arg new_store "$HIGH_UPGRADE_STORE" \
        '.action == "upgrade"
          and .status == "planned"
          and .dry_run == true
          and .upgraded == 1
          and (.upgrades | length == 1)
          and .upgrades[0].name == "priority-tool"
          and .upgrades[0].registry == "high-priority"
          and .upgrades[0].old_store_hash == $old_hash
          and .upgrades[0].new_version == "2.1.0"
          and .upgrades[0].new_store_path == $new_store
          and .downloads.planned >= 1
          and (.downloads.paths
            | map(select(.store_path == $new_store))
            | length == 1)' \
        /tmp/priority-client-upgrade-high-tool-dry-run.json >/dev/null; then
        pass "duplicate-name upgrade dry-run selects explicit high-priority root"
      else
        cat /tmp/priority-client-upgrade-high-tool-dry-run.json
        fail "duplicate-name upgrade dry-run should not target low-priority dependency"
      fi
      $APM --json upgrade priority-tool --yes \
        > /tmp/priority-client-upgrade-high-tool.json 2>&1 || {
        cat /tmp/priority-client-upgrade-high-tool.json
        fail "apm --json upgrade preserves explicit duplicate source"
      }
      if ${jqBin} -e \
        --arg old_hash "$HIGH_HASH" \
        --arg new_store "$HIGH_UPGRADE_STORE" \
        '.action == "upgrade"
          and .status == "upgraded"
          and .dry_run == false
          and .upgraded == 1
          and (.upgrades | length == 1)
          and .upgrades[0].registry == "high-priority"
          and .upgrades[0].old_store_hash == $old_hash
          and .upgrades[0].new_store_path == $new_store
          and .downloads.downloaded >= 1
          and .downloads.imported >= 1' \
        /tmp/priority-client-upgrade-high-tool.json >/dev/null; then
        pass "duplicate-name upgrade preserves explicit high-priority source"
      else
        cat /tmp/priority-client-upgrade-high-tool.json
        fail "duplicate-name upgrade should preserve explicit high-priority source"
      fi
      UPGRADED_DUPLICATE_GENERATION=$(${jqBin} -r '.generation' \
        /tmp/priority-client-upgrade-high-tool.json)
      assert_store_valid "$HIGH_UPGRADE_STORE" "upgraded high priority duplicate"
      if [ -e "$CURRENT_PROFILE/meta/$HIGH_HASH.json" ]; then
        cat "$CURRENT_PROFILE/meta/$HIGH_HASH.json"
        fail "duplicate-name upgrade should delete old high-priority metadata"
      else
        pass "duplicate-name upgrade deletes old high-priority metadata"
      fi
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"explicit": false' "duplicate-name upgrade keeps low dependency automatic"
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"held": false' "duplicate-name upgrade keeps low dependency unheld"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_UPGRADE_HASH.json" \
        '"explicit": true' "duplicate-name upgrade keeps high package explicit"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_UPGRADE_HASH.json" \
        '"held": false' "duplicate-name upgrade keeps high package unheld"
      "$PROFILE_TOOL" > /tmp/priority-tool-after-upgrade-high.out
      assert_file_contains /tmp/priority-tool-after-upgrade-high.out \
        "priority-tool 2.1.0 from high-priority" \
        "duplicate-name upgrade activates high-priority executable"

      $APM --json rollback --generation "$PRE_UPGRADE_DUPLICATE_GENERATION" \
        > /tmp/priority-client-rollback-pre-upgrade.json 2>&1 || {
        cat /tmp/priority-client-rollback-pre-upgrade.json
        fail "apm --json rollback restores pre-upgrade duplicate generation"
      }
      if ${jqBin} -e \
        --argjson from "$UPGRADED_DUPLICATE_GENERATION" \
        --argjson to "$PRE_UPGRADE_DUPLICATE_GENERATION" \
        --arg restored_store "$HIGH_STORE" \
        --arg removed_store "$HIGH_UPGRADE_STORE" \
        '.action == "rollback"
          and .status == "rolled_back"
          and .from_generation == $from
          and .to_generation == $to
          and .generation == $to
          and (.restored
            | map(select(.store_path == $restored_store))
            | length == 1)
          and (.removed
            | map(select(.store_path == $removed_store))
            | length == 1)' \
        /tmp/priority-client-rollback-pre-upgrade.json >/dev/null; then
        pass "duplicate-name rollback restores pre-upgrade high-priority root"
      else
        cat /tmp/priority-client-rollback-pre-upgrade.json
        fail "duplicate-name rollback should switch back to the pre-upgrade root"
      fi
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"explicit": false' "duplicate-name rollback keeps low dependency automatic"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_HASH.json" \
        '"explicit": true' "duplicate-name rollback restores old high package explicit"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_HASH.json" \
        '"held": false' "duplicate-name rollback preserves old high package unheld"
      if [ -e "$CURRENT_PROFILE/meta/$HIGH_UPGRADE_HASH.json" ]; then
        cat "$CURRENT_PROFILE/meta/$HIGH_UPGRADE_HASH.json"
        fail "duplicate-name rollback should remove upgraded high metadata from current generation"
      else
        pass "duplicate-name rollback removes upgraded high metadata from current generation"
      fi
      "$PROFILE_TOOL" > /tmp/priority-tool-after-rollback-high.out
      assert_file_contains /tmp/priority-tool-after-rollback-high.out \
        "priority-tool 2.0.0 from high-priority" \
        "duplicate-name rollback reactivates pre-upgrade high-priority executable"

      $APM --json rollback --generation "$UPGRADED_DUPLICATE_GENERATION" \
        > /tmp/priority-client-rollback-upgraded.json 2>&1 || {
        cat /tmp/priority-client-rollback-upgraded.json
        fail "apm --json rollback restores upgraded duplicate generation"
      }
      if ${jqBin} -e \
        --argjson from "$PRE_UPGRADE_DUPLICATE_GENERATION" \
        --argjson to "$UPGRADED_DUPLICATE_GENERATION" \
        --arg restored_store "$HIGH_UPGRADE_STORE" \
        --arg removed_store "$HIGH_STORE" \
        '.action == "rollback"
          and .status == "rolled_back"
          and .from_generation == $from
          and .to_generation == $to
          and .generation == $to
          and (.restored
            | map(select(.store_path == $restored_store))
            | length == 1)
          and (.removed
            | map(select(.store_path == $removed_store))
            | length == 1)' \
        /tmp/priority-client-rollback-upgraded.json >/dev/null; then
        pass "duplicate-name rollback restores upgraded high-priority root"
      else
        cat /tmp/priority-client-rollback-upgraded.json
        fail "duplicate-name rollback should switch forward to the upgraded root"
      fi
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"explicit": false' "duplicate-name roll-forward keeps low dependency automatic"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_UPGRADE_HASH.json" \
        '"explicit": true' "duplicate-name roll-forward restores upgraded high package explicit"
      assert_file_contains "$CURRENT_PROFILE/meta/$HIGH_UPGRADE_HASH.json" \
        '"held": false' "duplicate-name roll-forward preserves upgraded high package unheld"
      if [ -e "$CURRENT_PROFILE/meta/$HIGH_HASH.json" ]; then
        cat "$CURRENT_PROFILE/meta/$HIGH_HASH.json"
        fail "duplicate-name roll-forward should remove old high metadata from current generation"
      else
        pass "duplicate-name roll-forward removes old high metadata from current generation"
      fi
      "$PROFILE_TOOL" > /tmp/priority-tool-after-roll-forward-high.out
      assert_file_contains /tmp/priority-tool-after-roll-forward-high.out \
        "priority-tool 2.1.0 from high-priority" \
        "duplicate-name roll-forward reactivates upgraded high-priority executable"

      $APM --json remove priority-tool --dry-run \
        > /tmp/priority-client-remove-high-tool-dry-run.json 2>&1 || {
        cat /tmp/priority-client-remove-high-tool-dry-run.json
        fail "apm --json remove --dry-run plans duplicate-name explicit removal"
      }
      if ${jqBin} -e --arg store "$HIGH_UPGRADE_STORE" '
        .action == "remove"
        and .status == "planned"
        and .requested == ["priority-tool"]
        and .dry_run == true
        and .removed == 1
        and .explicit_removed == 1
        and .orphan_removed == 0
        and (.orphans | length == 0)
        and (.packages | length == 1)
        and .packages[0].name == "priority-tool"
        and .packages[0].registry == "high-priority"
        and .packages[0].store_path == $store
        and .packages[0].explicit == true
      ' /tmp/priority-client-remove-high-tool-dry-run.json >/dev/null; then
        pass "duplicate-name dry-run removes only the explicit high-priority package"
      else
        cat /tmp/priority-client-remove-high-tool-dry-run.json
        fail "duplicate-name dry-run should preserve the automatic low-priority dependency"
      fi

      $APM --json remove priority-tool --yes \
        > /tmp/priority-client-remove-high-tool.json 2>&1 || {
        cat /tmp/priority-client-remove-high-tool.json
        fail "apm --json remove deletes duplicate-name explicit package"
      }
      if ${jqBin} -e --arg store "$HIGH_UPGRADE_STORE" '
        .action == "remove"
        and .status == "removed"
        and .dry_run == false
        and .removed == 1
        and .explicit_removed == 1
        and .orphan_removed == 0
        and (.orphans | length == 0)
        and (.packages | length == 1)
        and .packages[0].registry == "high-priority"
        and .packages[0].store_path == $store
      ' /tmp/priority-client-remove-high-tool.json >/dev/null; then
        pass "duplicate-name remove deletes only the explicit high-priority package"
      else
        cat /tmp/priority-client-remove-high-tool.json
        fail "duplicate-name remove should leave the automatic low-priority dependency"
      fi
      if [ -L "$CURRENT_PROFILE/usr/$LOW_HASH" ]; then
        pass "duplicate-name remove preserves low-priority dependency root"
      else
        fail "duplicate-name remove should preserve low-priority dependency root"
      fi
      if [ -L "$CURRENT_PROFILE/usr/$HIGH_UPGRADE_HASH" ]; then
        fail "duplicate-name remove should drop high-priority explicit root"
      else
        pass "duplicate-name remove drops high-priority explicit root"
      fi
      assert_file_contains "$CURRENT_PROFILE/meta/$LOW_HASH.json" \
        '"explicit": false' "duplicate-name remove preserves low dependency metadata"
      if [ -e "$CURRENT_PROFILE/meta/$HIGH_UPGRADE_HASH.json" ]; then
        cat "$CURRENT_PROFILE/meta/$HIGH_UPGRADE_HASH.json"
        fail "duplicate-name remove should delete high-priority metadata"
      else
        pass "duplicate-name remove deletes high-priority metadata"
      fi
      "$PROFILE_CLIENT" > /tmp/priority-client-after-high-remove.out
      assert_file_contains /tmp/priority-client-after-high-remove.out \
        "priority-tool 9.0.0 from low-priority" \
        "client still executes low-priority dependency after duplicate remove"
      "$PROFILE_TOOL" > /tmp/priority-tool-after-high-remove.out
      assert_file_contains /tmp/priority-tool-after-high-remove.out \
        "priority-tool 9.0.0 from low-priority" \
        "profile executable falls back to low-priority dependency after duplicate remove"
      $APM --json autoremove --dry-run \
        > /tmp/priority-client-autoremove-after-high-remove.json 2>&1 || {
        cat /tmp/priority-client-autoremove-after-high-remove.json
        fail "apm --json autoremove --dry-run handles preserved duplicate dependency"
      }
      if ${jqBin} -e '
        .action == "autoremove"
        and .status == "current"
        and .removed == 0
        and .orphan_removed == 0
      ' /tmp/priority-client-autoremove-after-high-remove.json >/dev/null; then
        pass "preserved duplicate dependency is still needed by remaining client"
      else
        cat /tmp/priority-client-autoremove-after-high-remove.json
        fail "preserved duplicate dependency should not become an orphan"
      fi

      export HOME=/tmp/priority-consumer
      export USER=priorityuser
      APM_CONFIG="$HOME/.config/apm"

      mount -o remount,rw / || true
      delete_store_path "$HIGH_STORE" "high-priority-tool"
      delete_store_path "$SAME_HIGH_STORE" "high-priority-same-version-tool"
      delete_store_path "$SWITCH_HIGH_STORE" "high-priority-switch-tool"
      delete_store_path "$LOW_CLIENT_STORE" "low-priority-client"
      delete_store_path "$LOW_STORE" "low-priority-tool"
      delete_store_path "$SAME_LOW_STORE" "low-priority-same-version-tool"
      delete_store_path "$SWITCH_LOW_STORE" "low-priority-switch-tool"
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install priority-tool --yes > /tmp/priority-install-high.out 2>&1 || {
        cat /tmp/priority-install-high.out
        fail "apm install downloads high priority package"
      }
      cat /tmp/priority-install-high.out
      assert_file_contains /tmp/priority-install-high.out "Downloading" \
        "unfiltered install downloads the high priority NAR"
      assert_file_contains /tmp/priority-install-high.out "Installed 1 package" \
        "unfiltered install updates profile"
      assert_store_valid "$HIGH_STORE" "high priority tool"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/priority-tool"
      "$PROFILE_TOOL" > /tmp/priority-run-high.out
      assert_file_contains /tmp/priority-run-high.out \
        "priority-tool 2.0.0 from high-priority" \
        "unfiltered install executes high priority package"
      $APM list --installed > /tmp/priority-installed-high.out 2>&1
      assert_file_contains /tmp/priority-installed-high.out \
        "priority-tool/high-priority 2.0.0" \
        "installed metadata records high priority registry"
      if grep -q "priority-tool/low-priority" /tmp/priority-installed-high.out; then
        cat /tmp/priority-installed-high.out
        fail "unfiltered install should not install lower priority duplicate"
      else
        pass "unfiltered install excludes lower priority duplicate"
      fi
      $APM --json list --installed > /tmp/priority-installed-high.json 2>&1 || {
        cat /tmp/priority-installed-high.json
        fail "apm --json list --installed reports high priority install"
      }
      if ${jqBin} -e '
        map(select(.name == "priority-tool")) as $matches
        | ($matches | length == 1)
          and $matches[0].registry == "high-priority"
          and $matches[0].version == "2.0.0"
          and ($matches[0].status | contains("installed"))
      ' /tmp/priority-installed-high.json >/dev/null; then
        pass "apm --json list --installed records high priority source"
      else
        cat /tmp/priority-installed-high.json
        fail "apm --json list --installed records high priority source"
      fi

      $APM install switch-tool --yes > /tmp/switch-install-high.out 2>&1 || {
        cat /tmp/switch-install-high.out
        fail "apm install downloads high priority switch-tool"
      }
      cat /tmp/switch-install-high.out
      assert_file_contains /tmp/switch-install-high.out "Downloading" \
        "unfiltered switch-tool install downloads high priority NAR"
      assert_store_valid "$SWITCH_HIGH_STORE" "high priority switch-tool"
      CURRENT_PROFILE="/var/lib/profiles/per-user/$USER/current"
      if [ -L "$CURRENT_PROFILE/usr/$SWITCH_HIGH_HASH" ]; then
        pass "unfiltered switch-tool install records high priority profile root"
      else
        fail "unfiltered switch-tool install should root the high priority package"
      fi
      PROFILE_SWITCH_TOOL="/var/lib/profiles/per-user/$USER/current/bin/switch-tool"
      "$PROFILE_SWITCH_TOOL" > /tmp/switch-run-high.out
      assert_file_contains /tmp/switch-run-high.out \
        "switch-tool 1.0.0 from high-priority" \
        "unfiltered switch-tool install executes high priority package"
      $APM hold switch-tool > /tmp/switch-hold-high.out 2>&1 || {
        cat /tmp/switch-hold-high.out
        fail "apm hold marks high priority switch-tool held"
      }
      cat /tmp/switch-hold-high.out
      assert_file_contains /tmp/switch-hold-high.out "set on hold" \
        "apm hold reports high priority switch-tool hold"
      $APM held > /tmp/switch-held-high.out 2>&1 || {
        cat /tmp/switch-held-high.out
        fail "apm held lists high priority switch-tool"
      }
      assert_file_contains /tmp/switch-held-high.out \
        "switch-tool 1.0.0 (high-priority)" \
        "held list reports high priority switch-tool before source switch"

      $APM install switch-tool --registry low-priority --yes \
        > /tmp/switch-install-low.out 2>&1 || {
        cat /tmp/switch-install-low.out
        fail "apm install --registry switches installed package source"
      }
      cat /tmp/switch-install-low.out
      assert_file_contains /tmp/switch-install-low.out "Downloading" \
        "source switch downloads lower priority NAR"
      assert_store_valid "$SWITCH_LOW_STORE" "low priority switch-tool"
      "$PROFILE_SWITCH_TOOL" > /tmp/switch-run-low.out
      assert_file_contains /tmp/switch-run-low.out \
        "switch-tool 1.0.0 from low-priority" \
        "source switch profile executable comes from selected registry"
      assert_file_contains "$CURRENT_PROFILE/meta/$SWITCH_LOW_HASH.json" \
        '"held": true' "source switch preserves held metadata"
      $APM held > /tmp/switch-held-low.out 2>&1 || {
        cat /tmp/switch-held-low.out
        fail "apm held lists selected registry switch-tool after source switch"
      }
      assert_file_contains /tmp/switch-held-low.out \
        "switch-tool 1.0.0 (low-priority)" \
        "held list follows selected registry after source switch"
      if [ -L "$CURRENT_PROFILE/usr/$SWITCH_LOW_HASH" ]; then
        pass "source switch records selected registry profile root"
      else
        fail "source switch should root the selected registry package"
      fi
      if [ -L "$CURRENT_PROFILE/usr/$SWITCH_HIGH_HASH" ]; then
        fail "source switch should drop previous registry profile root"
      else
        pass "source switch drops previous registry profile root"
      fi
      $APM list --installed > /tmp/switch-installed-low.out 2>&1
      assert_file_contains /tmp/switch-installed-low.out \
        "switch-tool/low-priority 1.0.0" \
        "source switch records selected registry metadata"
      if ${grepBin} -q "switch-tool/high-priority" /tmp/switch-installed-low.out; then
        cat /tmp/switch-installed-low.out
        fail "source switch should drop previous registry metadata"
      else
        pass "source switch drops previous registry metadata"
      fi
      $APM --json list --installed > /tmp/switch-installed-low.json 2>&1 || {
        cat /tmp/switch-installed-low.json
        fail "apm --json list --installed reports selected source switch"
      }
      if ${jqBin} -e '
        map(select(.name == "switch-tool")) as $matches
        | ($matches | length == 1)
          and $matches[0].registry == "low-priority"
          and $matches[0].version == "1.0.0"
          and ($matches[0].status | contains("installed"))
          and ($matches[0].status | contains("held"))
      ' /tmp/switch-installed-low.json >/dev/null; then
        pass "apm --json list --installed follows selected registry after source switch"
      else
        cat /tmp/switch-installed-low.json
        fail "apm --json list --installed follows selected registry after source switch"
      fi

      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"
      $APM reinstall switch-tool --yes > /tmp/switch-reinstall-low-source.out 2>&1 || {
        cat /tmp/switch-reinstall-low-source.out
        fail "apm reinstall preserves selected registry source"
      }
      cat /tmp/switch-reinstall-low-source.out
      assert_file_contains /tmp/switch-reinstall-low-source.out "Downloading" \
        "source-preserving reinstall downloads selected lower priority NAR"
      assert_file_contains /tmp/switch-reinstall-low-source.out "Reinstalled 1 package" \
        "source-preserving reinstall creates repair generation"
      "$PROFILE_SWITCH_TOOL" > /tmp/switch-run-low-after-reinstall.out
      assert_file_contains /tmp/switch-run-low-after-reinstall.out \
        "switch-tool 1.0.0 from low-priority" \
        "plain reinstall keeps selected registry executable"
      assert_file_contains "$CURRENT_PROFILE/meta/$SWITCH_LOW_HASH.json" \
        '"held": true' "plain reinstall preserves held metadata"
      $APM held > /tmp/switch-held-low-after-reinstall.out 2>&1 || {
        cat /tmp/switch-held-low-after-reinstall.out
        fail "apm held lists selected registry switch-tool after reinstall"
      }
      assert_file_contains /tmp/switch-held-low-after-reinstall.out \
        "switch-tool 1.0.0 (low-priority)" \
        "held list follows selected registry after reinstall"
      if [ -L "$CURRENT_PROFILE/usr/$SWITCH_LOW_HASH" ]; then
        pass "plain reinstall keeps selected registry profile root"
      else
        fail "plain reinstall should keep selected registry profile root"
      fi
      if [ -L "$CURRENT_PROFILE/usr/$SWITCH_HIGH_HASH" ]; then
        fail "plain reinstall should not restore higher priority duplicate"
      else
        pass "plain reinstall does not restore higher priority duplicate"
      fi
      $APM list --installed > /tmp/switch-installed-after-reinstall.out 2>&1
      assert_file_contains /tmp/switch-installed-after-reinstall.out \
        "switch-tool/low-priority 1.0.0" \
        "plain reinstall keeps selected registry metadata"
      if ${grepBin} -q "switch-tool/high-priority" /tmp/switch-installed-after-reinstall.out; then
        cat /tmp/switch-installed-after-reinstall.out
        fail "plain reinstall should not restore high priority metadata"
      else
        pass "plain reinstall keeps high priority metadata absent"
      fi

      export HOME=/tmp/priority-filter-consumer
      export USER=priorityfilter
      mkdir -p "$HOME"
      APM_CONFIG="$HOME/.config/apm"

      $APM registry add --no-verify file:///tmp/low-priority-origin.git \
        --name low-priority \
        --branch "$LOW_BRANCH" \
        --priority 100
      $APM registry add --no-verify file:///tmp/high-priority-origin.git \
        --name high-priority \
        --branch "$HIGH_BRANCH" \
        --priority 900
      rm -rf "$HOME/.cache/apm"
      mkdir -p "$HOME/.cache/apm"

      $APM install priority-tool --registry low-priority --yes \
        > /tmp/priority-install-low.out 2>&1 || {
        cat /tmp/priority-install-low.out
        fail "apm install --registry downloads selected lower priority package"
      }
      cat /tmp/priority-install-low.out
      assert_file_contains /tmp/priority-install-low.out "Downloading" \
        "registry-filtered install downloads the lower priority NAR"
      assert_store_valid "$LOW_STORE" "low priority tool"
      PROFILE_TOOL="/var/lib/profiles/per-user/$USER/current/bin/priority-tool"
      "$PROFILE_TOOL" > /tmp/priority-run-low.out
      assert_file_contains /tmp/priority-run-low.out \
        "priority-tool 9.0.0 from low-priority" \
        "registry-filtered install executes lower priority package"
      $APM list --installed > /tmp/priority-installed-low.out 2>&1
      assert_file_contains /tmp/priority-installed-low.out \
        "priority-tool/low-priority 9.0.0" \
        "registry-filtered install records selected registry"
      $APM --json list --installed --registry low-priority \
        > /tmp/priority-installed-low.json 2>&1 || {
        cat /tmp/priority-installed-low.json
        fail "apm --json list --installed --registry reports selected lower priority install"
      }
      if ${jqBin} -e '
        length == 1
        and .[0].name == "priority-tool"
        and .[0].registry == "low-priority"
        and .[0].version == "9.0.0"
        and (.[0].status | contains("installed"))
      ' /tmp/priority-installed-low.json >/dev/null; then
        pass "apm --json list --installed --registry filters to selected lower priority install"
      else
        cat /tmp/priority-installed-low.json
        fail "apm --json list --installed --registry filters to selected lower priority install"
      fi

      $APM depends priority-tool > /tmp/priority-depends-low.out 2>&1 || {
        cat /tmp/priority-depends-low.out
        fail "apm depends uses installed lower priority duplicate"
      }
      cat /tmp/priority-depends-low.out
      assert_file_contains /tmp/priority-depends-low.out \
        "priority-tool (9.0.0).*\\[low-priority, installed\\]" \
        "depends reports installed lower priority duplicate root"
      if ${grepBin} -q "priority-tool (2.0.0)" /tmp/priority-depends-low.out; then
        cat /tmp/priority-depends-low.out
        fail "depends should not report higher priority duplicate for installed package"
      else
        pass "depends does not report higher priority duplicate for installed package"
      fi

      $APM install priority-client --registry low-priority --yes \
        > /tmp/priority-install-client.out 2>&1 || {
        cat /tmp/priority-install-client.out
        fail "apm install downloads lower priority client package"
      }
      cat /tmp/priority-install-client.out
      assert_file_contains /tmp/priority-install-client.out "Downloading" \
        "registry-filtered install downloads the lower priority client NAR"
      assert_store_valid "$LOW_CLIENT_STORE" "low priority client"
      PROFILE_CLIENT="/var/lib/profiles/per-user/$USER/current/bin/priority-client"
      "$PROFILE_CLIENT" > /tmp/priority-run-client.out
      assert_file_contains /tmp/priority-run-client.out \
        "priority-tool 9.0.0 from low-priority" \
        "lower priority client executes against its registry dependency"

      $APM rdepends priority-tool > /tmp/priority-rdepends-low.out 2>&1 || {
        cat /tmp/priority-rdepends-low.out
        fail "apm rdepends handles installed lower priority dependency target"
      }
      cat /tmp/priority-rdepends-low.out
      assert_file_contains /tmp/priority-rdepends-low.out \
        "priority-client (1.0.0)" \
        "rdepends follows installed dependency target instead of higher priority duplicate"

      $APM install same-version-tool --registry low-priority --yes \
        > /tmp/same-version-install-low.out 2>&1 || {
        cat /tmp/same-version-install-low.out
        fail "apm install --registry downloads selected same-version package"
      }
      cat /tmp/same-version-install-low.out
      assert_file_contains /tmp/same-version-install-low.out "Downloading" \
        "registry-filtered install downloads the same-version low priority NAR"
      assert_store_valid "$SAME_LOW_STORE" "low priority same-version tool"
      PROFILE_SAME_TOOL="/var/lib/profiles/per-user/$USER/current/bin/same-version-tool"
      "$PROFILE_SAME_TOOL" > /tmp/same-version-run-low.out
      assert_file_contains /tmp/same-version-run-low.out \
        "same-version-tool 1.0.0 from low-priority" \
        "registry-filtered install executes selected same-version package"

      $APM policy same-version-tool > /tmp/same-version-policy-low.out 2>&1 || {
        cat /tmp/same-version-policy-low.out
        fail "apm policy handles same-version duplicate registry package"
      }
      cat /tmp/same-version-policy-low.out
      assert_file_contains /tmp/same-version-policy-low.out \
        "\*\*\* 1.0.0  100  low-priority" \
        "policy marks the installed low-priority same-version candidate"
      if ${grepBin} -Eq '^ \*\*\* 1\.0\.0  900  high-priority$' \
        /tmp/same-version-policy-low.out; then
        cat /tmp/same-version-policy-low.out
        fail "policy should not mark the high-priority duplicate as installed"
      else
        pass "policy does not mark the uninstalled same-version high-priority candidate"
      fi
      $APM --json policy same-version-tool > /tmp/same-version-policy-low.json 2>&1 || {
        cat /tmp/same-version-policy-low.json
        fail "apm --json policy handles same-version duplicate registry package"
      }
      if ${jqBin} -e '
        .package == "same-version-tool"
        and .installed == "1.0.0"
        and .candidate == "1.0.0"
        and (.versions | length == 2)
        and (.versions[0].registry == "high-priority")
        and (.versions[0].priority == 900)
        and (.versions[0].installed == false)
        and (.versions[1].registry == "low-priority")
        and (.versions[1].priority == 100)
        and (.versions[1].installed == true)
      ' /tmp/same-version-policy-low.json >/dev/null; then
        pass "apm --json policy marks only the installed same-version source"
      else
        cat /tmp/same-version-policy-low.json
        fail "apm --json policy marks only the installed same-version source"
      fi

      $APM list --upgradable > /tmp/priority-upgradable-low.out 2>&1 || {
        cat /tmp/priority-upgradable-low.out
        fail "apm list --upgradable handles same-name lower priority install"
      }
      if grep -q "priority-tool" /tmp/priority-upgradable-low.out; then
        cat /tmp/priority-upgradable-low.out
        fail "lower priority install should not upgrade across registries"
      else
        pass "lower priority install is not upgraded across registries"
      fi

      kill "$LOW_CACHE_PID" "$HIGH_CACHE_PID" 2>/dev/null || true
      wait "$LOW_CACHE_PID" "$HIGH_CACHE_PID" 2>/dev/null || true
      check_fail
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 2: multi-registry-cross-containment -- overlapping deps
  # ---------------------------------------------------------------------------
  multi-registry-cross-containment = testing.mkVMTest {
    name = "multi-registry-cross-containment";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
            ${iproute2Bin} link set lo up || true
            ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

            FAIL=0

            # --- Registry A (sysroot provider, port 15001) ---
            mkdir -p /tmp/reg-a/var/nix/db /tmp/reg-a/store /tmp/reg-a/meta /tmp/run/reg-a
            ${mkStoreDb "/tmp/reg-a"}

            LIBZ="/tmp/reg-a/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-libz-1.0"
            mkdir -p "$LIBZ/lib"
            echo "libz.so.1 stub" > "$LIBZ/lib/libz.so.1"
            ${sqliteBin} /tmp/reg-a/var/nix/db/db.sqlite \
              "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$LIBZ', 'sha256:zzzz', 1000000, 4096, 1, '''''');"
            LIBZ_HASH=$(basename "$LIBZ" | cut -d- -f1)
            mkdir -p /tmp/reg-a/gcroots/default/bin
            ln -sfn "$LIBZ" "/tmp/reg-a/gcroots/default/bin/$LIBZ_HASH"

            cat > /tmp/reg-a-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15001"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/reg-a/bootstrap.sock"
            socket_group = "root"
      CFGEOF
            AOS_ROOT=/tmp/reg-a ${aosBin} serve --config /tmp/reg-a-config.toml &
            REG_A_PID=$!

            # --- Registry B (package provider, port 15002) ---
            mkdir -p /tmp/reg-b/var/nix/db /tmp/reg-b/store /tmp/reg-b/meta /tmp/run/reg-b
            ${mkStoreDb "/tmp/reg-b"}

            # Same libz hash in registry B
            LIBZ_B="/tmp/reg-b/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-libz-1.0"
            mkdir -p "$LIBZ_B/lib"
            echo "libz.so.1 stub" > "$LIBZ_B/lib/libz.so.1"
            ${sqliteBin} /tmp/reg-b/var/nix/db/db.sqlite \
              "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$LIBZ_B', 'sha256:zzzz', 1000000, 4096, 1, '''''');"
            LIBZ_B_HASH=$(basename "$LIBZ_B" | cut -d- -f1)
            mkdir -p /tmp/reg-b/gcroots/default/bin
            ln -sfn "$LIBZ_B" "/tmp/reg-b/gcroots/default/bin/$LIBZ_B_HASH"

            PKG="/tmp/reg-b/store/pppppppppppppppppppppppppppppppppp-mypkg-1.0"
            mkdir -p "$PKG/bin"
            echo '#!/bin/sh' > "$PKG/bin/mypkg"
            echo 'echo "mypkg works"' >> "$PKG/bin/mypkg"
            chmod +x "$PKG/bin/mypkg"
            ${sqliteBin} /tmp/reg-b/var/nix/db/db.sqlite \
              "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$PKG', 'sha256:pppp', 1000000, 2048, 1, '''''');"
            PKG_HASH=$(basename "$PKG" | cut -d- -f1)
            ln -sfn "$PKG" "/tmp/reg-b/gcroots/default/bin/$PKG_HASH"

            cat > /tmp/reg-b-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15002"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/reg-b/bootstrap.sock"
            socket_group = "root"
      CFGEOF
            AOS_ROOT=/tmp/reg-b ${aosBin} serve --config /tmp/reg-b-config.toml &
            REG_B_PID=$!

            for _i in 1 2 3 4 5 6 7 8 9 10; do
              HTTP_A=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15001/default/nix-cache-info 2>/dev/null) || true
              HTTP_B=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15002/default/nix-cache-info 2>/dev/null) || true
              if [ "$HTTP_A" = "200" ] && [ "$HTTP_B" = "200" ]; then break; fi
              sleep 1
            done
            test "$HTTP_A" = "200" || { echo "FAIL: registry A not up"; FAIL=1; }
            test "$HTTP_B" = "200" || { echo "FAIL: registry B not up"; FAIL=1; }

            echo "==> Cross-containment: checking libz in both registries"
            HASH_Z="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            HTTP_Z_A=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:15001/default/$HASH_Z.narinfo")
            HTTP_Z_B=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:15002/default/$HASH_Z.narinfo")
            echo "Registry A libz: HTTP $HTTP_Z_A"
            echo "Registry B libz: HTTP $HTTP_Z_B"
            test "$HTTP_Z_A" = "200" || {
              echo "FAIL: registry A should serve shared libz narinfo"
              FAIL=1
            }
            test "$HTTP_Z_B" = "200" || {
              echo "FAIL: registry B should serve shared libz narinfo"
              FAIL=1
            }

            HASH_P="pppppppppppppppppppppppppppppppppp"
            HTTP_P=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:15002/default/$HASH_P.narinfo")
            echo "Registry B mypkg: HTTP $HTTP_P"
            test "$HTTP_P" = "200" || {
              echo "FAIL: registry B should serve package narinfo"
              FAIL=1
            }

            kill -9 $REG_A_PID $REG_B_PID 2>/dev/null || true
            wait $REG_A_PID $REG_B_PID 2>/dev/null || true

            if [ "$FAIL" -ne 0 ]; then
              echo "==> multi-registry-cross-containment FAILED"
              exit 1
            fi
            echo "==> multi-registry-cross-containment passed"
    '';
  };

  # ---------------------------------------------------------------------------
  # Test 3: multi-registry-mirror -- upstream and mirror
  # ---------------------------------------------------------------------------
  multi-registry-mirror = testing.mkVMTest {
    name = "multi-registry-mirror";
    rootfsDeps = serverDeps;
    memory = 1024;
    testScript = ''
            ${iproute2Bin} link set lo up || true
            ${iproute2Bin} addr add 127.0.0.1/8 dev lo 2>/dev/null || true

            FAIL=0

            # --- Upstream (port 15001) ---
            mkdir -p /tmp/upstream/var/nix/db /tmp/upstream/store /tmp/upstream/meta /tmp/run/upstream
            ${mkStoreDb "/tmp/upstream"}

            for i in 1 2 3; do
              MPKG="/tmp/upstream/store/mirrortest000000000000000000000$i-mirror-pkg-$i"
              mkdir -p "$MPKG/bin"
              echo "mirror pkg $i" > "$MPKG/bin/data"
              ${sqliteBin} /tmp/upstream/var/nix/db/db.sqlite \
                "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$MPKG', 'sha256:mirror$i', 1000000, 1024, 1, '''''');"
            done

            cat > /tmp/upstream-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15001"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/upstream/bootstrap.sock"
            socket_group = "root"
      CFGEOF
            AOS_ROOT=/tmp/upstream ${aosBin} serve --config /tmp/upstream-config.toml &
            UPSTREAM_PID=$!

            # --- Mirror (port 15002, starts empty) ---
            mkdir -p /tmp/mirror/var/nix/db /tmp/mirror/store /tmp/mirror/meta /tmp/run/mirror
            ${mkStoreDb "/tmp/mirror"}

            cat > /tmp/mirror-config.toml << 'CFGEOF'
            listen = "127.0.0.1:15002"
            [[views]]
            name = "default"
            anonymous_read = true
            [bootstrap]
            socket = "/tmp/run/mirror/bootstrap.sock"
            socket_group = "root"
      CFGEOF
            AOS_ROOT=/tmp/mirror ${aosBin} serve --config /tmp/mirror-config.toml &
            MIRROR_PID=$!

            for _i in 1 2 3 4 5 6 7 8 9 10; do
              HTTP_UP=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15001/default/nix-cache-info 2>/dev/null) || true
              HTTP_MR=$(${curlBin} -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15002/default/nix-cache-info 2>/dev/null) || true
              if [ "$HTTP_UP" = "200" ] && [ "$HTTP_MR" = "200" ]; then break; fi
              sleep 1
            done
            test "$HTTP_UP" = "200" || { echo "FAIL: upstream not responding"; FAIL=1; }
            test "$HTTP_MR" = "200" || { echo "FAIL: mirror not responding"; FAIL=1; }

            # Get auth for upstream
            RESP_UP=$(echo '{"action":"create","views":["default"],"permissions":["read","build"]}' | \
              ${socatBin} - UNIX-CONNECT:/tmp/run/upstream/bootstrap.sock)
            TOKEN_UP=$(echo "$RESP_UP" | ${jqBin} -r '.data.token // empty')
            JWT_UP=$(${curlBin} -s -X POST -H "Authorization: Bearer $TOKEN_UP" \
              -H "Content-Type: application/x-www-form-urlencoded" \
              -d "grant_type=client_credentials" \
              http://127.0.0.1:15001/oauth2/token | ${jqBin} -r '.access_token // empty')

            # Get auth for mirror
            RESP_MR=$(echo '{"action":"create","views":["default"],"permissions":["read","build"]}' | \
              ${socatBin} - UNIX-CONNECT:/tmp/run/mirror/bootstrap.sock)
            TOKEN_MR=$(echo "$RESP_MR" | ${jqBin} -r '.data.token // empty')
            JWT_MR=$(${curlBin} -s -X POST -H "Authorization: Bearer $TOKEN_MR" \
              -H "Content-Type: application/x-www-form-urlencoded" \
              -d "grant_type=client_credentials" \
              http://127.0.0.1:15002/oauth2/token | ${jqBin} -r '.access_token // empty')

            echo "==> Verify upstream has packages"
            QM_UP=$(${curlBin} -s -X POST -H "Authorization: Bearer $JWT_UP" \
              -H "Content-Type: application/json" \
              -d '{"paths":["/tmp/upstream/store/mirrortest0000000000000000000001-mirror-pkg-1"]}' \
              http://127.0.0.1:15001/default/query-missing)
            UP_MISSING=$(echo "$QM_UP" | ${jqBin} '.missing | length')
            echo "Upstream missing: $UP_MISSING"

            echo "==> Verify mirror is initially empty"
            QM_MR=$(${curlBin} -s -X POST -H "Authorization: Bearer $JWT_MR" \
              -H "Content-Type: application/json" \
              -d '{"paths":["/tmp/mirror/store/mirrortest0000000000000000000001-mirror-pkg-1"]}' \
              http://127.0.0.1:15002/default/query-missing)
            MR_MISSING=$(echo "$QM_MR" | ${jqBin} '.missing | length')
            echo "Mirror missing: $MR_MISSING"

            echo "==> Mirror comparison: upstream=$UP_MISSING, mirror=$MR_MISSING"
            test "$UP_MISSING" = "0" || {
              echo "FAIL: upstream should contain mirror package"
              FAIL=1
            }
            test "$MR_MISSING" = "1" || {
              echo "FAIL: empty mirror should miss mirror package"
              FAIL=1
            }

            kill -9 $UPSTREAM_PID $MIRROR_PID 2>/dev/null || true
            wait $UPSTREAM_PID $MIRROR_PID 2>/dev/null || true

            if [ "$FAIL" -ne 0 ]; then
              echo "==> multi-registry-mirror FAILED"
              exit 1
            fi
            echo "==> multi-registry-mirror passed"
    '';
  };
}
