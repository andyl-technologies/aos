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
      pkgs.python3
      pkgs.zstd
      priorityLowTool
      priorityHighTool
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

      publish_priority_registry() {
        registry="$1"
        store_path="$2"
        version="$3"
        cache_dir="$4"
        cache_url="$5"

        $APR create "$registry"
        reg_dir="$REG_STORAGE/$registry"
        $APR publish "$store_path" \
          --name priority-tool \
          --version "$version" \
          --description "Priority-selected package from $registry" \
          --license MIT \
          --maintainer priority@example.invalid \
          --registry "$registry" \
          --no-commit
        $APR cache generate \
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

      publish_priority_client() {
        registry="$1"
        store_path="$2"
        cache_dir="$3"
        cache_url="$4"

        reg_dir="$REG_STORAGE/$registry"
        $APR publish "$store_path" \
          --name priority-client \
          --version 1.0.0 \
          --description "Client package depending on $registry priority-tool" \
          --license MIT \
          --maintainer priority@example.invalid \
          --registry "$registry" \
          --no-commit
        $APR cache generate \
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
        $APR publish "$store_path" \
          --name same-version-tool \
          --version 1.0.0 \
          --description "Same-version package from $registry" \
          --license MIT \
          --maintainer priority@example.invalid \
          --registry "$registry" \
          --no-commit
        $APR cache generate \
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
        $APR publish "$store_path" \
          --name switch-tool \
          --version 1.0.0 \
          --description "Source-switch package from $registry" \
          --license MIT \
          --maintainer priority@example.invalid \
          --registry "$registry" \
          --no-commit
        $APR cache generate \
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
      LOW_CLIENT_STORE="${priorityLowClient}"
      SAME_LOW_STORE="${sameVersionLowTool}"
      SAME_HIGH_STORE="${sameVersionHighTool}"
      SWITCH_LOW_STORE="${switchLowTool}"
      SWITCH_HIGH_STORE="${switchHighTool}"
      LOW_HASH=$(basename "$LOW_STORE" | cut -d- -f1)
      HIGH_HASH=$(basename "$HIGH_STORE" | cut -d- -f1)
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

      $APM show priority-tool > /tmp/priority-show.out 2>&1 || {
        cat /tmp/priority-show.out
        fail "apm show uses priority-selected package"
      }
      assert_file_contains /tmp/priority-show.out "high-priority" \
        "show reports the high priority registry"
      assert_file_contains /tmp/priority-show.out "2.0.0" \
        "show reports the high priority version"

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

            PKG="/tmp/reg-b/store/pppppppppppppppppppppppppppppppppp-mypkg-1.0"
            mkdir -p "$PKG/bin"
            echo '#!/bin/sh' > "$PKG/bin/mypkg"
            echo 'echo "mypkg works"' >> "$PKG/bin/mypkg"
            chmod +x "$PKG/bin/mypkg"
            ${sqliteBin} /tmp/reg-b/var/nix/db/db.sqlite \
              "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$PKG', 'sha256:pppp', 1000000, 2048, 1, '''''');"

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

            HASH_P="pppppppppppppppppppppppppppppppppp"
            HTTP_P=$(${curlBin} -s -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:15002/default/$HASH_P.narinfo")
            echo "Registry B mypkg: HTTP $HTTP_P"

            kill $REG_A_PID $REG_B_PID 2>/dev/null || true
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

            kill $UPSTREAM_PID $MIRROR_PID 2>/dev/null || true
            wait $UPSTREAM_PID $MIRROR_PID 2>/dev/null || true

            if [ "$FAIL" -ne 0 ]; then
              echo "==> multi-registry-mirror FAILED"
              exit 1
            fi
            echo "==> multi-registry-mirror passed"
    '';
  };
}
