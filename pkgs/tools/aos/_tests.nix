# pkgs/tools/aos/_tests.nix — Integration tests for the aos CLI and cache server
#
# Prefixed with _ so discoverPackages skips it (not a package).
# Called from aos.nix via: import ./_tests.nix { inherit testing self pkgs; }
{
  testing,
  self,
  pkgs,
}: let
  repoSrc = builtins.path {
    path = ../../..;
    name = "aos-cache-validation-smoke-src";
    filter = path: type: let
      base = baseNameOf path;
    in
      base != ".aos-benchmarks"
      && base != ".claude"
      && base != ".codex"
      && base != ".git"
      && base != ".jj"
      && base != "result"
      && base != "target";
  };
  parityJsonCorpusSrc = builtins.path {
    path = ../../../fuzz/corpus/parity_json;
    name = "aos-parity-json-corpus-src";
    filter = path: type: let
      base = baseNameOf path;
    in
      type != "directory" || base != "generated";
  };

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

  cache-validation-smoke = pkgs.runCommand "aos-cache-validation-smoke" {
    buildDeps = [
      self
      pkgs.nix
    ];
  } ''
    set -eu

    work="$TMPDIR/aos-cache-validation-smoke"
    nix_conf="$work/nix-conf"
    export HOME="$work/home"
    export AOS_ROOT="$work/aos-root"
    export AOS_NIX_STORE_DIR="$work/store"
    export AOS_NIX_STATE_DIR="$work/state"
    export AOS_NIX_LOG_DIR="$work/log"
    export NIX_STORE_DIR="$AOS_NIX_STORE_DIR"
    export NIX_STATE_DIR="$AOS_NIX_STATE_DIR"
    export NIX_LOG_DIR="$AOS_NIX_LOG_DIR"
    export NIX_REMOTE=""
    export NIX_CONF_DIR="$nix_conf"
    export AOS_NIX_CACHE="$work/native-cache"

    mkdir -p \
      "$HOME" \
      "$AOS_ROOT" \
      "$AOS_NIX_STORE_DIR" \
      "$AOS_NIX_STATE_DIR" \
      "$AOS_NIX_LOG_DIR" \
      "$NIX_CONF_DIR" \
      "$AOS_NIX_CACHE"

    printf 'substituters =\n' > "$NIX_CONF_DIR/nix.conf"

    ${pkgs.nix}/bin/nix-store --init

    ${self}/bin/aos \
      --eval-system=${self.system} \
      nix-diff \
      --smoke \
      --cache-validation \
      --mode=byte \
      -- \
      ${repoSrc}/default.nix

    echo "PASS" > "$out/result"
  '';

  eval-json-corpus-smoke = pkgs.runCommand "aos-eval-json-corpus-smoke" {
    buildDeps = [
      self
      pkgs.nix
    ];
  } ''
    set -eu

    work="$TMPDIR/aos-eval-json-corpus-smoke"
    nix_conf="$work/nix-conf"
    export HOME="$work/home"
    export AOS_ROOT="$work/aos-root"
    export AOS_NIX_STORE_DIR="$work/store"
    export AOS_NIX_STATE_DIR="$work/state"
    export AOS_NIX_LOG_DIR="$work/log"
    export NIX_STORE_DIR="$AOS_NIX_STORE_DIR"
    export NIX_STATE_DIR="$AOS_NIX_STATE_DIR"
    export NIX_LOG_DIR="$AOS_NIX_LOG_DIR"
    export NIX_REMOTE=""
    export NIX_CONF_DIR="$nix_conf"
    export AOS_NIX_CACHE="$work/native-cache"

    mkdir -p \
      "$HOME" \
      "$AOS_ROOT" \
      "$AOS_NIX_STORE_DIR" \
      "$AOS_NIX_STATE_DIR" \
      "$AOS_NIX_LOG_DIR" \
      "$NIX_CONF_DIR" \
      "$AOS_NIX_CACHE"

    printf 'substituters =\n' > "$NIX_CONF_DIR/nix.conf"

    ${pkgs.nix}/bin/nix-store --init

    ${self}/bin/aos \
      --eval-system=${self.system} \
      nix-diff \
      --eval-json \
      --eval-json-corpus \
      ${parityJsonCorpusSrc}

    echo "PASS" > "$out/result"
  '';

  eval-json-generated-corpus-smoke = pkgs.runCommand "aos-eval-json-generated-corpus-smoke" {
    buildDeps = [
      self
      pkgs.nix
    ];
  } ''
    set -eu

    work="$TMPDIR/aos-eval-json-generated-corpus-smoke"
    nix_conf="$work/nix-conf"
    fixture="$work/generated-corpus-root.nix"
    generated="$work/generated"
    export HOME="$work/home"
    export AOS_ROOT="$work/aos-root"
    export AOS_NIX_STORE_DIR="$work/store"
    export AOS_NIX_STATE_DIR="$work/state"
    export AOS_NIX_LOG_DIR="$work/log"
    export NIX_STORE_DIR="$AOS_NIX_STORE_DIR"
    export NIX_STATE_DIR="$AOS_NIX_STATE_DIR"
    export NIX_LOG_DIR="$AOS_NIX_LOG_DIR"
    export NIX_REMOTE=""
    export NIX_CONF_DIR="$nix_conf"
    export AOS_NIX_CACHE="$work/native-cache"

    mkdir -p \
      "$HOME" \
      "$AOS_ROOT" \
      "$AOS_NIX_STORE_DIR" \
      "$AOS_NIX_STATE_DIR" \
      "$AOS_NIX_LOG_DIR" \
      "$NIX_CONF_DIR" \
      "$AOS_NIX_CACHE" \
      "$generated"

    printf 'substituters =\n' > "$NIX_CONF_DIR/nix.conf"

    cat > "$fixture" <<'EOF'
    { system ? builtins.currentSystem }:
    {
      pkgs = {
        generatedEvalJsonPackage = {
          a = [ true null "pkg" ];
          z = system;
        };
      };
      conformance = {
        evalOkayGeneratedSmoke = {
          b = 2;
          a = [ "conformance" system ];
        };
      };
    }
    EOF

    ${pkgs.nix}/bin/nix-store --init

    ${self}/bin/aos \
      --eval-system=${self.system} \
      nix-fuzz-corpus \
      --file "$fixture" \
      --output-dir "$generated" \
      --clean \
      --attr pkgs.generatedEvalJsonPackage \
      --attr conformance.evalOkayGeneratedSmoke

    ${self}/bin/aos \
      --eval-system=${self.system} \
      nix-diff \
      --eval-json \
      --eval-json-corpus \
      "$generated"

    echo "PASS" > "$out/result"
  '';

  # Budgeted full generated eval-json corpus (RFC-0007 doc 15 §2.7 / decision
  # C-4): auto-enumerates the package set, the explicit toolchain overlay, the
  # `systems.*` toplevels, and the pinned C++ Nix `tests/functional/lang`
  # conformance corpus into source seeds, then replays every seed through the
  # nix-cli/native strict-JSON diff under a wall-clock time budget. The C++
  # oracle runs against a throwaway sandbox-local store (`nix-store --init`
  # plus redirected NIX_STORE_DIR/NIX_STATE_DIR), so no network or host store
  # access is needed; the repo itself is imported from the filtered
  # `repoSrc` store path.
  eval-json-corpus-full = pkgs.runCommand "aos-eval-json-corpus-full" {
    buildDeps = [
      self
      pkgs.nix
    ];
  } ''
    set -eu

    work="$TMPDIR/aos-eval-json-corpus-full"
    nix_conf="$work/nix-conf"
    generated="$work/generated"
    export HOME="$work/home"
    export AOS_ROOT="$work/aos-root"
    export AOS_NIX_STORE_DIR="$work/store"
    export AOS_NIX_STATE_DIR="$work/state"
    export AOS_NIX_LOG_DIR="$work/log"
    export NIX_STORE_DIR="$AOS_NIX_STORE_DIR"
    export NIX_STATE_DIR="$AOS_NIX_STATE_DIR"
    export NIX_LOG_DIR="$AOS_NIX_LOG_DIR"
    export NIX_REMOTE=""
    export NIX_CONF_DIR="$nix_conf"
    export AOS_NIX_CACHE="$work/native-cache"

    mkdir -p \
      "$HOME" \
      "$AOS_ROOT" \
      "$AOS_NIX_STORE_DIR" \
      "$AOS_NIX_STATE_DIR" \
      "$AOS_NIX_LOG_DIR" \
      "$NIX_CONF_DIR" \
      "$AOS_NIX_CACHE" \
      "$generated"

    # The pinned C++ `tests/functional/lang` corpus includes flake-conformance
    # seeds (`builtins.parseFlakeRef`, `flakeRefToString`) that C++ Nix 2.24.12
    # gates behind the `flakes` experimental feature; the native evaluator
    # implements them unconditionally. Enable flakes on the oracle so those
    # seeds compare against a flakes-enabled C++ Nix (matching upstream
    # `lang.sh`) instead of failing oracle-side. `substituters` stays empty so
    # the run remains hermetic.
    printf 'substituters =\nexperimental-features = flakes\n' > "$NIX_CONF_DIR/nix.conf"

    ${pkgs.nix}/bin/nix-store --init

    # Unpack the pinned C++ Nix source so the generator can synthesize the
    # eval-okay conformance seed set from tests/functional/lang.
    tar -xzf ${pkgs.nix.src} -C "$work"
    export AOS_NIX_LANG_TESTS="$work/nix-${pkgs.nix.version}/tests/functional/lang"

    # Exclusions — eval-time IFD (hermetically infeasible here): evaluating
    # these attrs forces builtins.readFile on a built derivation output (the
    # cc-wrapper's / bootstrap tools' nix-support metadata), which the
    # sandbox store cannot realize without network. They stay covered by the
    # networked `.drv` acceptance-gate runs (`aos nix-diff --all --systems`
    # on builders).
    #   systems, pkgs.bazel*, pkgs.envoy, pkgs.linux,
    #   pkgs.gcc-libs (readFile on the bootstrap dynamic-linker path,
    #   pkgs/libs/gcc-libs.nix)
    ${self}/bin/aos \
      --eval-system=${self.system} \
      nix-fuzz-corpus \
      --file ${repoSrc}/default.nix \
      --output-dir "$generated" \
      --clean \
      --exclude systems \
      --exclude pkgs.bazel-bootstrap \
      --exclude pkgs.bazel-7 \
      --exclude pkgs.bazel-8 \
      --exclude pkgs.bazel-9 \
      --exclude pkgs.bazel \
      --exclude pkgs.envoy \
      --exclude pkgs.linux \
      --exclude pkgs.gcc-libs

    # The budget bounds the corpus replay: entries are compared in
    # deterministic seed-name order until the budget is exhausted, and any
    # divergence in the compared prefix fails the check.
    ${self}/bin/aos \
      --eval-system=${self.system} \
      nix-diff \
      --eval-json \
      --eval-json-corpus "$generated" \
      --time-budget 900

    echo "PASS" > "$out/result"
  '';

  # Unbudgeted, deterministic full generated eval-json corpus (RFC-0007 doc 15
  # §2.7 / task #33 pre-flip hardening). Identical to `eval-json-corpus-full`
  # except it drops `--time-budget`, so `aos nix-diff` compares EVERY generated
  # seed (native vs the AOS-built C++ oracle) instead of stopping at a wall-clock
  # budget. This is the shape intended for a REQUIRED merge gate: a budgeted
  # check's coverage depends on runner speed (which seeds get compared varies
  # run to run), so it is a smoke, not a gate. Absence of `--time-budget` maps to
  # `time_budget = None`, and the replay loop only breaks on a budget when one is
  # set (crates/aos/src/commands/nix_diff.rs), so all entries run.
  #
  # KNOWN GAP (documented so a green result is not misread as full-tree): this
  # hermetic check EXCLUDES the eval-time-IFD attrs `systems`, `pkgs.bazel*`,
  # `pkgs.envoy`, `pkgs.linux`, and `pkgs.gcc-libs` — evaluating them forces
  # `builtins.readFile` on a built derivation output, which the sandbox store
  # cannot realize without network. Those attrs stay covered by the networked
  # `.drv` acceptance-gate runs (`aos nix-diff --all --systems` on builders).
  # So: green here == native/C++ eval parity across the whole hermetically-
  # evaluable package set + toolchain + `systems.*` toplevels + the pinned C++
  # `tests/functional/lang` conformance corpus; the IFD corners are a separate,
  # networked gate.
  eval-json-corpus-required = pkgs.runCommand "aos-eval-json-corpus-required" {
    buildDeps = [
      self
      pkgs.nix
    ];
  } ''
    set -eu

    work="$TMPDIR/aos-eval-json-corpus-required"
    nix_conf="$work/nix-conf"
    generated="$work/generated"
    export HOME="$work/home"
    export AOS_ROOT="$work/aos-root"
    export AOS_NIX_STORE_DIR="$work/store"
    export AOS_NIX_STATE_DIR="$work/state"
    export AOS_NIX_LOG_DIR="$work/log"
    export NIX_STORE_DIR="$AOS_NIX_STORE_DIR"
    export NIX_STATE_DIR="$AOS_NIX_STATE_DIR"
    export NIX_LOG_DIR="$AOS_NIX_LOG_DIR"
    export NIX_REMOTE=""
    export NIX_CONF_DIR="$nix_conf"
    export AOS_NIX_CACHE="$work/native-cache"

    mkdir -p \
      "$HOME" \
      "$AOS_ROOT" \
      "$AOS_NIX_STORE_DIR" \
      "$AOS_NIX_STATE_DIR" \
      "$AOS_NIX_LOG_DIR" \
      "$NIX_CONF_DIR" \
      "$AOS_NIX_CACHE" \
      "$generated"

    # The pinned C++ `tests/functional/lang` corpus includes flake-conformance
    # seeds (`builtins.parseFlakeRef`, `flakeRefToString`) that C++ Nix 2.24.12
    # gates behind the `flakes` experimental feature; the native evaluator
    # implements them unconditionally. Enable flakes on the oracle so those
    # seeds compare against a flakes-enabled C++ Nix (matching upstream
    # `lang.sh`) instead of failing oracle-side. `substituters` stays empty so
    # the run remains hermetic.
    printf 'substituters =\nexperimental-features = flakes\n' > "$NIX_CONF_DIR/nix.conf"

    ${pkgs.nix}/bin/nix-store --init

    # Unpack the pinned C++ Nix source so the generator can synthesize the
    # eval-okay conformance seed set from tests/functional/lang.
    tar -xzf ${pkgs.nix.src} -C "$work"
    export AOS_NIX_LANG_TESTS="$work/nix-${pkgs.nix.version}/tests/functional/lang"

    # Exclusions — eval-time IFD (hermetically infeasible here); see the KNOWN
    # GAP note above. These stay covered by the networked `.drv` acceptance gate.
    ${self}/bin/aos \
      --eval-system=${self.system} \
      nix-fuzz-corpus \
      --file ${repoSrc}/default.nix \
      --output-dir "$generated" \
      --clean \
      --exclude systems \
      --exclude pkgs.bazel-bootstrap \
      --exclude pkgs.bazel-7 \
      --exclude pkgs.bazel-8 \
      --exclude pkgs.bazel-9 \
      --exclude pkgs.bazel \
      --exclude pkgs.envoy \
      --exclude pkgs.linux \
      --exclude pkgs.gcc-libs

    # No `--time-budget`: every seed is compared in deterministic seed-name
    # order, and any divergence in ANY seed fails the check.
    ${self}/bin/aos \
      --eval-system=${self.system} \
      nix-diff \
      --eval-json \
      --eval-json-corpus "$generated"

    echo "PASS" > "$out/result"
  '';

  # Representative `.drv` byte-parity differential (RFC-0007 doc 15 §2):
  # instantiates a fixed witness set spanning the compression/crypto/coreutils/
  # shell corners of the package graph with both the C++ Nix oracle and the
  # native evaluator, requiring byte-identical `.drv` closures. Uses the same
  # sandbox-local store pattern as the eval-json checks.
  drv-parity-representative = pkgs.runCommand "aos-drv-parity-representative" {
    buildDeps = [
      self
      pkgs.nix
    ];
  } ''
    set -eu

    work="$TMPDIR/aos-drv-parity-representative"
    nix_conf="$work/nix-conf"
    export HOME="$work/home"
    export AOS_ROOT="$work/aos-root"
    export AOS_NIX_STORE_DIR="$work/store"
    export AOS_NIX_STATE_DIR="$work/state"
    export AOS_NIX_LOG_DIR="$work/log"
    export NIX_STORE_DIR="$AOS_NIX_STORE_DIR"
    export NIX_STATE_DIR="$AOS_NIX_STATE_DIR"
    export NIX_LOG_DIR="$AOS_NIX_LOG_DIR"
    export NIX_REMOTE=""
    export NIX_CONF_DIR="$nix_conf"
    export AOS_NIX_CACHE="$work/native-cache"

    mkdir -p \
      "$HOME" \
      "$AOS_ROOT" \
      "$AOS_NIX_STORE_DIR" \
      "$AOS_NIX_STATE_DIR" \
      "$AOS_NIX_LOG_DIR" \
      "$NIX_CONF_DIR" \
      "$AOS_NIX_CACHE"

    printf 'substituters =\n' > "$NIX_CONF_DIR/nix.conf"

    ${pkgs.nix}/bin/nix-store --init

    for attr in pkgs.zlib pkgs.openssl pkgs.coreutils pkgs.bash; do
      echo "==> nix-diff --mode=byte -A $attr"
      ${self}/bin/aos \
        --eval-system=${self.system} \
        nix-diff \
        --mode=byte \
        -A "$attr" \
        -- \
        ${repoSrc}/default.nix
    done

    echo "PASS" > "$out/result"
  '';

  host-apr-apm-command-surface = let
    hostAprApmCommandSurfaceDeps = [
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

    hostAprApmCommandSurfaceScript = pkgs.writeTextFile {
      name = "aos-host-apr-apm-command-surface-script";
      destination = "/bin/aos-host-apr-apm-command-surface";
      executable = true;
      text = ''
        #!${pkgs.runtimeShell}
        set -eu

        work="$TMPDIR/aos-host-command-surface"
        home="$work/home"
        config="$work/config"
        data="$work/share"
        cache="$work/cache"
        system_config="$work/system-config"
        profile_root="$work/profiles"
        aos_root="$work/aos-root"
        store_dir="$aos_root/store"
        state_dir="$aos_root/var/nix"
        nix_conf="$work/nix-conf"
        host_bin="$work/host-bin"
        cache_port="18137"
        install_cache_port="18138"
        mkdir -p "$home" "$config" "$data" "$cache" "$cache/nix" "$system_config" "$profile_root" "$store_dir" "$state_dir/db" "$state_dir/gcroots" "$state_dir/log/nix" "$nix_conf" "$host_bin"
        profile="$profile_root/per-user/unknown"
        default_profile="/var/lib/profiles/per-user/unknown"
        cache_server_pid=""
        install_cache_server_pid=""
        failed_line=""
        failed_command=""
        cat > "$nix_conf/nix.conf" << NIXCONF
        experimental-features = nix-command
        sandbox = false
        substituters =
        NIXCONF
        # Keep harness tracing out of command output files that intentionally
        # capture stderr with 2>&1.
        exec 3>&2

        record_failure() {
          status=$?
          failed_line="$1"
          failed_command="$2"
          return "$status"
        }
        trap 'record_failure "$LINENO" "$BASH_COMMAND"' ERR

        dump_recent_work_files() {
          if ! test -d "$work"; then
            return
          fi
          printf '\nRecent host APR/APM workflow logs:\n' >&2
          for path in $(${pkgs.findutils}/bin/find "$work" -maxdepth 1 -type f -printf '%T@ %p\n' | ${pkgs.coreutils}/bin/sort -nr | ${pkgs.coreutils}/bin/head -20 | ${pkgs.coreutils}/bin/cut -d ' ' -f2-); do
            printf '\n--- %s ---\n' "$path" >&2
            ${pkgs.coreutils}/bin/tail -n 80 "$path" >&2 || true
          done
        }

        cleanup() {
          status=$?
          if test "$status" -ne 0; then
            printf '\nhost APR/APM command-surface workflow failed with exit %s\n' "$status" >&2
            if test -n "$failed_line"; then
              printf 'Failed near line %s: %s\n' "$failed_line" "$failed_command" >&2
            fi
            dump_recent_work_files
          fi
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

        print_command() {
          if test "$#" -eq 0; then
            printf '<empty>\n'
            return
          fi
          printf '%s' "$1"
          shift
          for arg in "$@"; do
            printf ' %s' "$arg"
          done
          printf '\n'
        }

        log_command() {
          {
            printf '>>> '
            print_command "$@"
          } >&3
          {
            printf '>>> '
            print_command "$@"
          } >> "$work/commands.log"
        }

        run_clean() {
          log_command "$@"
          env -i \
            HOME="$home" \
            XDG_CONFIG_HOME="$config" \
            XDG_DATA_HOME="$data" \
            XDG_CACHE_HOME="$cache" \
            APM_SYSTEM_CONFIG_DIR="$system_config" \
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
            PATH="$host_bin:${pkgs.coreutils}/bin:${pkgs.findutils}/bin:${pkgs.git}/bin:${pkgs.nix}/bin:${pkgs.zstd}/bin" \
            "$@"
        }

        run_without_git_identity() {
          log_command "$@"
          env -i \
            HOME="$home" \
            XDG_CONFIG_HOME="$config" \
            XDG_DATA_HOME="$data" \
            XDG_CACHE_HOME="$cache" \
            APM_SYSTEM_CONFIG_DIR="$system_config" \
            AOS_PROFILE_ROOT="$profile_root" \
            AOS_ROOT="$aos_root" \
            AOS_NIX_STORE_DIR="$store_dir" \
            AOS_NIX_STATE_DIR="$state_dir" \
            NIX_REMOTE="" \
            NIX_CONF_DIR="$nix_conf" \
            GIT_CONFIG_NOSYSTEM=1 \
            PATH="$host_bin:${pkgs.coreutils}/bin:${pkgs.findutils}/bin:${pkgs.git}/bin:${pkgs.nix}/bin:${pkgs.zstd}/bin" \
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

        assert_default_system_config_unused() {
          if ${pkgs.findutils}/bin/find "$system_config" -mindepth 1 -print -quit | ${pkgs.grep}/bin/grep -q .; then
            ${pkgs.findutils}/bin/find "$system_config" -mindepth 1 -maxdepth 3 -print
            exit 1
          fi
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
        run_clean ${self}/bin/apm --json gc > "$work/apm-gc-alt-store.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$store_dir" \
          --arg state "$state_dir" \
          '.action == "gc"
            and .status == "completed"
            and .success == true
            and .nix_store_dir == $store
            and .nix_state_dir == $state
            and (.stdout | type == "string")
            and (.stderr | type == "string")' \
          "$work/apm-gc-alt-store.json" >/dev/null

        invalid_config="$work/invalid-config"
        mkdir -p "$invalid_config/apm"
        cat > "$invalid_config/apm/apm.conf" << 'EOF'
        [settings]
        parallel_downloads = 0
        EOF
        if run_clean ${pkgs.coreutils}/bin/env \
          XDG_CONFIG_HOME="$invalid_config" \
          ${self}/bin/apm --json gc > "$work/apm-invalid-parallel-downloads.out" 2>&1; then
          cat "$work/apm-invalid-parallel-downloads.out"
          exit 1
        fi
        grep -q "parallel_downloads must be at least 1" \
          "$work/apm-invalid-parallel-downloads.out"

        invalid_registry_config="$work/invalid-registry-config"
        mkdir -p "$invalid_registry_config/apm/registries.d"
        cat > "$invalid_registry_config/apm/registries.d/escape.toml" << 'EOF'
        [registry]
        name = "../escaped-config"
        url = "file:///invalid"
        EOF
        if run_clean ${pkgs.coreutils}/bin/env \
          XDG_CONFIG_HOME="$invalid_registry_config" \
          ${self}/bin/apm registry list \
          > "$work/apm-invalid-registry-config.out" 2>&1; then
          cat "$work/apm-invalid-registry-config.out"
          exit 1
        fi
        grep -q "the name must match the file stem" \
          "$work/apm-invalid-registry-config.out"

        if run_clean ${self}/bin/apr create ../escaped-create \
          > "$work/apr-create-invalid-registry-name.out" 2>&1; then
          cat "$work/apr-create-invalid-registry-name.out"
          exit 1
        fi
        grep -q "invalid registry name" \
          "$work/apr-create-invalid-registry-name.out"
        test ! -e "$data/apm/escaped-create"

        invalid_bootstrap_key="invalid-bootstrap:Ed25519:bWlzbWF0Y2g="
        if run_clean ${self}/bin/apr create invalid-bootstrap \
          --trust-key "$invalid_bootstrap_key" \
          --trust-key-id bad/id \
          > "$work/apr-create-invalid-trust-key-id.out" 2>&1; then
          cat "$work/apr-create-invalid-trust-key-id.out"
          exit 1
        fi
        grep -q "key id" \
          "$work/apr-create-invalid-trust-key-id.out"
        test ! -e "$data/apm/registries/invalid-bootstrap"

        if run_clean ${self}/bin/apm registry add --no-verify "file://$work" \
          --name ../escaped-add \
          > "$work/apm-add-invalid-registry-name.out" 2>&1; then
          cat "$work/apm-add-invalid-registry-name.out"
          exit 1
        fi
        grep -q "invalid registry name" \
          "$work/apm-add-invalid-registry-name.out"
        test ! -e "$config/apm/escaped-add.toml"
        test ! -e "$data/apm/registries/escaped-add"

        if run_clean ${self}/bin/apm registry add --no-verify --no-clone "file://$work" \
          --name invalid-branch-tracking \
          --branch feature..bad \
          > "$work/apm-add-invalid-branch-tracking.out" 2>&1; then
          cat "$work/apm-add-invalid-branch-tracking.out"
          exit 1
        fi
        grep -q "invalid branch name" \
          "$work/apm-add-invalid-branch-tracking.out"
        test ! -e "$config/apm/registries.d/invalid-branch-tracking.toml"
        test ! -e "$data/apm/registries/invalid-branch-tracking"

        if run_clean ${self}/bin/apm registry add --no-verify --no-clone "file://$work" \
          --name invalid-tag-tracking \
          --tag 'release@{1}' \
          > "$work/apm-add-invalid-tag-tracking.out" 2>&1; then
          cat "$work/apm-add-invalid-tag-tracking.out"
          exit 1
        fi
        grep -q "invalid git ref name" \
          "$work/apm-add-invalid-tag-tracking.out"
        test ! -e "$config/apm/registries.d/invalid-tag-tracking.toml"
        test ! -e "$data/apm/registries/invalid-tag-tracking"

        if run_clean ${self}/bin/apm registry add --no-verify --no-clone "file://$work" \
          --name invalid-commit-tracking \
          --commit main \
          > "$work/apm-add-invalid-commit-tracking.out" 2>&1; then
          cat "$work/apm-add-invalid-commit-tracking.out"
          exit 1
        fi
        grep -q "invalid commit hash" \
          "$work/apm-add-invalid-commit-tracking.out"
        test ! -e "$config/apm/registries.d/invalid-commit-tracking.toml"
        test ! -e "$data/apm/registries/invalid-commit-tracking"

        quoted_registry_url="file://$work/registry \"quoted\""
        run_clean ${self}/bin/apm --json registry add --no-verify --no-clone "$quoted_registry_url" \
          --name quoted-url-reg \
          --branch stable \
          > "$work/apm-add-quoted-url-reg.json"
        ${pkgs.jq}/bin/jq -e \
          --arg url "$quoted_registry_url" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "quoted-url-reg"
            and .url == $url
            and .tracking == "branch:stable"
            and .clone == false
            and .verification_disabled == true' \
          "$work/apm-add-quoted-url-reg.json" >/dev/null
        run_clean ${self}/bin/apm --json registry list \
          > "$work/apm-list-quoted-url-reg.json"
        ${pkgs.jq}/bin/jq -e \
          --arg url "$quoted_registry_url" \
          'any(.name == "quoted-url-reg"
            and .url == $url
            and .tracking == "branch:stable"
            and .signing_required == false)' \
          "$work/apm-list-quoted-url-reg.json" >/dev/null
        run_clean ${self}/bin/apm registry remove quoted-url-reg \
          > "$work/apm-remove-quoted-url-reg.out" 2>&1
        test ! -e "$config/apm/registries.d/quoted-url-reg.toml"

        escaped_remove="$data/apm/escaped-remove"
        mkdir -p "$escaped_remove"
        printf '%s\n' "must stay put" > "$escaped_remove/sentinel"
        if run_clean ${self}/bin/apm registry remove ../escaped-remove --force \
          > "$work/apm-remove-invalid-registry-name.out" 2>&1; then
          cat "$work/apm-remove-invalid-registry-name.out"
          exit 1
        fi
        grep -q "invalid registry name" \
          "$work/apm-remove-invalid-registry-name.out"
        test -f "$escaped_remove/sentinel"

        invalid_trust_key="../escaped-trust:Ed25519:bWlzbWF0Y2g="
        if run_clean ${self}/bin/apr trust pin ../escaped-trust "$invalid_trust_key" \
          > "$work/apr-trust-pin-invalid-registry-name.out" 2>&1; then
          cat "$work/apr-trust-pin-invalid-registry-name.out"
          exit 1
        fi
        grep -q "invalid registry name" \
          "$work/apr-trust-pin-invalid-registry-name.out"
        test ! -e "$config/apm/escaped-trust.pub"

        if run_clean ${self}/bin/apr trust list ../escaped-trust \
          > "$work/apr-trust-list-invalid-registry-name.out" 2>&1; then
          cat "$work/apr-trust-list-invalid-registry-name.out"
          exit 1
        fi
        grep -q "invalid registry name" \
          "$work/apr-trust-list-invalid-registry-name.out"

        mkdir -p "$config/apm"
        printf '%s\n' "must stay put" > "$config/apm/escaped-trust.pub"
        if run_clean ${self}/bin/apr trust remove ../escaped-trust \
          > "$work/apr-trust-remove-invalid-registry-name.out" 2>&1; then
          cat "$work/apr-trust-remove-invalid-registry-name.out"
          exit 1
        fi
        grep -q "invalid registry name" \
          "$work/apr-trust-remove-invalid-registry-name.out"
        grep -qx "must stay put" "$config/apm/escaped-trust.pub"

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

        remove_keep="$data/apm/registries/remove-keep-local"
        run_clean ${self}/bin/apr create remove-keep-local \
          > "$work/apr-create-remove-keep-local.out" 2>&1
        if run_clean ${self}/bin/apm registry remove remove-keep-local \
          > "$work/apm-registry-remove-keep-local-unsafe.out" 2>&1; then
          cat "$work/apm-registry-remove-keep-local-unsafe.out"
          exit 1
        fi
        grep -q "local authoring clone" \
          "$work/apm-registry-remove-keep-local-unsafe.out"
        grep -q "no remote is configured" \
          "$work/apm-registry-remove-keep-local-unsafe.out"
        test -d "$remove_keep"
        run_clean ${self}/bin/apr remove remove-keep-local --keep-local \
          > "$work/apr-remove-keep-local.out" 2>&1
        grep -q "Registry 'remove-keep-local' removed" \
          "$work/apr-remove-keep-local.out"
        test -d "$remove_keep"
        run_clean ${self}/bin/apr remove remove-keep-local --force \
          > "$work/apr-remove-keep-local-force.out" 2>&1
        grep -q "Registry 'remove-keep-local' removed" \
          "$work/apr-remove-keep-local-force.out"
        test ! -e "$remove_keep"

        remove_dirty="$data/apm/registries/remove-dirty"
        run_clean ${self}/bin/apr create remove-dirty \
          > "$work/apr-create-remove-dirty.out" 2>&1
        printf '%s\n' "local maintainer notes" \
          > "$remove_dirty/maintainer-notes.txt"
        if run_clean ${self}/bin/apm registry remove remove-dirty \
          > "$work/apm-registry-remove-dirty.out" 2>&1; then
          cat "$work/apm-registry-remove-dirty.out"
          exit 1
        fi
        grep -q "local authoring clone" "$work/apm-registry-remove-dirty.out"
        grep -q "uncommitted changes" "$work/apm-registry-remove-dirty.out"
        test -f "$remove_dirty/maintainer-notes.txt"
        run_clean ${self}/bin/apr --json remove remove-dirty --force \
          > "$work/apr-remove-dirty-force.json"
        ${pkgs.jq}/bin/jq -e \
          --arg local_path "$remove_dirty" \
          '.action == "registry_remove"
            and .status == "removed"
            and .registry == "remove-dirty"
            and .name == "remove-dirty"
            and .keep_local == false
            and .force == true
            and .config_removed == false
            and .local == $local_path
            and .local_removed == true
            and .cache_removed == false
            and .trusted_keys_removed == false
            and .orphan_command == "apm orphans"' \
          "$work/apr-remove-dirty-force.json" >/dev/null
        test ! -e "$remove_dirty"

        remove_unpushed_origin="$work/remove-unpushed-origin.git"
        git init --bare --object-format=sha256 "$remove_unpushed_origin" \
          > "$work/git-init-remove-unpushed-origin.out" 2>&1
        remove_unpushed="$data/apm/registries/remove-unpushed"
        run_clean ${self}/bin/apr create remove-unpushed \
          --remote "$remove_unpushed_origin" \
          > "$work/apr-create-remove-unpushed.out" 2>&1
        git -C "$remove_unpushed" remote get-url origin \
          > "$work/git-remove-unpushed-origin.out"
        grep -qx "$remove_unpushed_origin" \
          "$work/git-remove-unpushed-origin.out"
        if run_clean ${self}/bin/apm registry remove remove-unpushed \
          > "$work/apm-registry-remove-unpushed.out" 2>&1; then
          cat "$work/apm-registry-remove-unpushed.out"
          exit 1
        fi
        grep -q "local authoring clone" "$work/apm-registry-remove-unpushed.out"
        grep -q "not pushed to any remote" \
          "$work/apm-registry-remove-unpushed.out"
        test -d "$remove_unpushed"
        git -C "$remove_unpushed" push origin stable \
          > "$work/git-push-remove-unpushed.out" 2>&1
        run_clean ${self}/bin/apr remove remove-unpushed \
          > "$work/apr-remove-unpushed-after-push.out" 2>&1
        grep -q "Registry 'remove-unpushed' removed" \
          "$work/apr-remove-unpushed-after-push.out"
        test ! -e "$remove_unpushed"

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
        run_clean ${self}/bin/apr --json trust pin host-reg "$host_key_root" \
          > "$work/apr-trust-pin-root.json"
        ${pkgs.jq}/bin/jq -e \
          --arg key "$host_key_root" \
          '.action == "trust_pin"
            and .status == "pinned"
            and .registry == "host-reg"
            and .replace == false
            and .key == $key
            and .algorithm == "Ed25519"
            and .source == "Tofu"
            and (.fingerprint | length > 0)' \
          "$work/apr-trust-pin-root.json" >/dev/null
        test -f "$trust_file"
        grep -q "$host_key_root" "$trust_file"
        run_clean ${self}/bin/apr --json trust pin host-reg "$host_key_backup" \
          > "$work/apr-trust-pin-backup.json"
        ${pkgs.jq}/bin/jq -e \
          --arg key "$host_key_backup" \
          '.action == "trust_pin"
            and .status == "pinned"
            and .registry == "host-reg"
            and .replace == false
            and .key == $key
            and .algorithm == "Ed25519"
            and .source == "Tofu"
            and (.fingerprint | length > 0)' \
          "$work/apr-trust-pin-backup.json" >/dev/null
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
        run_clean ${self}/bin/apr --json trust pin host-reg "$host_key_canary" --replace \
          > "$work/apr-trust-replace.json"
        ${pkgs.jq}/bin/jq -e \
          --arg key "$host_key_canary" \
          '.action == "trust_pin"
            and .status == "replaced"
            and .registry == "host-reg"
            and .replace == true
            and .key == $key
            and .algorithm == "Ed25519"
            and .source == "Tofu"
            and (.fingerprint | length > 0)' \
          "$work/apr-trust-replace.json" >/dev/null
        test "$(wc -l < "$trust_file")" = "1"
        grep -q "$host_key_canary" "$trust_file"
        run_clean ${self}/bin/apr --json trust remove host-reg \
          > "$work/apr-trust-remove.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "trust_remove"
            and .status == "removed"
            and .registry == "host-reg"
            and .removed == true' \
          "$work/apr-trust-remove.json" >/dev/null
        test ! -e "$trust_file"
        run_clean ${self}/bin/apr --json trust remove host-reg \
          > "$work/apr-trust-remove-repeat.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "trust_remove"
            and .status == "current"
            and .registry == "host-reg"
            and .removed == false' \
          "$work/apr-trust-remove-repeat.json" >/dev/null
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
        mkdir -p "$reg/packages/e"
        cat > "$reg/packages/e/escaped-package.toml" << 'EOF'
        [package]
        name = "../escaped-package"
        description = "Invalid hand-written package metadata"
        license = "MIT"
        maintainer = "host@example.invalid"
        EOF
        if run_clean ${self}/bin/apr packages --registry host-reg \
          > "$work/apr-packages-invalid-package-name.out" 2>&1; then
          cat "$work/apr-packages-invalid-package-name.out"
          exit 1
        fi
        grep -q "invalid package name" \
          "$work/apr-packages-invalid-package-name.out"
        ${pkgs.coreutils}/bin/rm -f "$reg/packages/e/escaped-package.toml"
        invalid_package="../../escaped-package"
        printf '%s\n' "must stay put" > "$reg/escaped-package.toml"
        if run_clean ${self}/bin/apr show "$invalid_package" \
          --registry host-reg > "$work/apr-show-invalid-package-name.out" 2>&1; then
          cat "$work/apr-show-invalid-package-name.out"
          exit 1
        fi
        grep -q "invalid package name" \
          "$work/apr-show-invalid-package-name.out"
        if run_clean ${self}/bin/apr log --package "$invalid_package" \
          --registry host-reg > "$work/apr-log-invalid-package-name.out" 2>&1; then
          cat "$work/apr-log-invalid-package-name.out"
          exit 1
        fi
        grep -q "invalid package name" \
          "$work/apr-log-invalid-package-name.out"
        if run_clean ${self}/bin/apr unpublish "$invalid_package" \
          --registry host-reg \
          --no-commit > "$work/apr-unpublish-invalid-package-name.out" 2>&1; then
          cat "$work/apr-unpublish-invalid-package-name.out"
          exit 1
        fi
        grep -q "invalid package name" \
          "$work/apr-unpublish-invalid-package-name.out"
        grep -qx "must stay put" "$reg/escaped-package.toml"
        pkg_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        mkdir -p "$reg/packages/h" "$reg/store/$(printf %.2s "$pkg_hash")"
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
        printf 'nar:sha256:0000000000000000000000000000000000000000000000000000:1234\n' > "$reg/store/$(printf %.2s "$pkg_hash")/$pkg_hash"
        printf '%s\n' \
          "" \
          '[[caches]]' \
          "url = \"http://127.0.0.1:$cache_port/cache\"" \
          'priority = 42' \
          >> "$reg/registry.toml"

        run_clean ${self}/bin/apr status --registry host-reg > "$work/apr-status-dirty.out" 2>&1
        grep -q "registry.toml" "$work/apr-status-dirty.out"
        grep -q "packages/h/hostpkg.toml" "$work/apr-status-dirty.out"
        grep -q "store/$(printf %.2s "$pkg_hash")/$pkg_hash" "$work/apr-status-dirty.out"
        run_clean ${self}/bin/apr --json status --registry host-reg \
          > "$work/apr-status-dirty.json"
        ${pkgs.jq}/bin/jq -e --arg closure "store/$(printf %.2s "$pkg_hash")/$pkg_hash" \
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

        run_clean ${self}/bin/apr --json branch create release/host-json-feature --registry host-reg \
          > "$work/apr-branch-create-json.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "create"
            and .branch == "release/host-json-feature"
            and .current == "stable"
            and (.branches | any(.name == "release/host-json-feature" and .current == false))
            and (.branches | any(.name == "stable" and .current == true))' \
          "$work/apr-branch-create-json.json" >/dev/null
        run_clean ${self}/bin/apr --json branch delete release/host-json-feature --registry host-reg \
          > "$work/apr-branch-delete-json.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "delete"
            and .branch == "release/host-json-feature"
            and .current == "stable"
            and (.branches | all(.name != "release/host-json-feature"))
            and (.branches | any(.name == "stable" and .current == true))' \
          "$work/apr-branch-delete-json.json" >/dev/null

        if run_clean ${self}/bin/apr branch create --registry host-reg -- -bad-branch \
          > "$work/apr-branch-create-invalid-option.out" 2>&1; then
          cat "$work/apr-branch-create-invalid-option.out"
          exit 1
        fi
        grep -q "invalid branch name" "$work/apr-branch-create-invalid-option.out"
        if git -C "$reg" show-ref --verify --quiet refs/heads/-bad-branch; then
          exit 1
        fi
        if run_clean ${self}/bin/apr branch switch 'feature@{1}' --registry host-reg \
          > "$work/apr-branch-switch-invalid-refexpr.out" 2>&1; then
          cat "$work/apr-branch-switch-invalid-refexpr.out"
          exit 1
        fi
        grep -q "invalid branch name" "$work/apr-branch-switch-invalid-refexpr.out"
        if run_clean ${self}/bin/apr branch delete feature//bad --registry host-reg \
          > "$work/apr-branch-delete-invalid-path.out" 2>&1; then
          cat "$work/apr-branch-delete-invalid-path.out"
          exit 1
        fi
        grep -q "invalid branch name" "$work/apr-branch-delete-invalid-path.out"

        run_clean ${self}/bin/apr branch create feature/hostpkg-metadata --registry host-reg > "$work/apr-branch-create.out" 2>&1
        grep -q "Created branch 'feature/hostpkg-metadata'" "$work/apr-branch-create.out"
        run_clean ${self}/bin/apr branch switch feature/hostpkg-metadata --registry host-reg > "$work/apr-branch-switch.out" 2>&1
        grep -q "Switched to branch 'feature/hostpkg-metadata'" "$work/apr-branch-switch.out"
        run_clean ${self}/bin/apr --json branch list --registry host-reg \
          > "$work/apr-branch-list-feature-current.json"
        ${pkgs.jq}/bin/jq -e \
          '.branches
            | (any(.name == "feature/hostpkg-metadata" and .current == true)
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
        grep -q "feature/hostpkg-metadata" "$work/apr-branch-list.out"
        run_clean ${self}/bin/apr --json branch list --registry host-reg \
          > "$work/apr-branch-list-stable-current.json"
        ${pkgs.jq}/bin/jq -e \
          '.branches
            | (any(.name == "stable" and .current == true)
              and any(.name == "feature/hostpkg-metadata" and .current == false))' \
          "$work/apr-branch-list-stable-current.json" >/dev/null
        if run_clean ${self}/bin/apr merge feature..bad --registry host-reg \
          > "$work/apr-merge-invalid-branch-name.out" 2>&1; then
          cat "$work/apr-merge-invalid-branch-name.out"
          exit 1
        fi
        grep -q "invalid branch name" \
          "$work/apr-merge-invalid-branch-name.out"
        run_clean ${self}/bin/apr --json merge feature/hostpkg-metadata --registry host-reg \
          > "$work/apr-merge-feature.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "merge"
            and .branch == "feature/hostpkg-metadata"
            and .no_ff == false
            and .squash == false
            and .current == "stable"
            and (.head | length == 64)
            and (.output | contains("Fast-forward"))
            and (.branches | any(.name == "stable" and .current == true))' \
          "$work/apr-merge-feature.json" >/dev/null
        run_clean ${self}/bin/apr branch delete feature/hostpkg-metadata --registry host-reg > "$work/apr-branch-delete-feature.out" 2>&1
        grep -q "Deleted branch 'feature/hostpkg-metadata'" "$work/apr-branch-delete-feature.out"
        run_clean ${self}/bin/apr branch list --registry host-reg > "$work/apr-branch-list-after-delete.out" 2>&1
        if grep -q "feature/hostpkg-metadata" "$work/apr-branch-list-after-delete.out"; then
          cat "$work/apr-branch-list-after-delete.out"
          exit 1
        fi
        run_clean ${self}/bin/apr --json branch list --registry host-reg \
          > "$work/apr-branch-list-after-delete.json"
        ${pkgs.jq}/bin/jq -e \
          '.branches
            | (any(.name == "stable" and .current == true)
              and all(.name != "feature/hostpkg-metadata"))' \
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
        grep -q "Verified 1 package(s), 1 closure root(s), no errors" "$work/apr-verify.out"
        run_clean ${self}/bin/apr --json verify --registry host-reg \
          > "$work/apr-verify.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "verify"
            and .status == "ok"
            and .registry == "host-reg"
            and .package == null
            and .fix == false
            and .checked == 1
            and .roots == 1
            and .repaired == 0
            and .errors == 0' \
          "$work/apr-verify.json" >/dev/null
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
        if run_clean ${self}/bin/apr push --registry host-reg --branch feature..bad \
          > "$work/apr-push-invalid-branch-name.out" 2>&1; then
          cat "$work/apr-push-invalid-branch-name.out"
          exit 1
        fi
        grep -q "invalid branch name" \
          "$work/apr-push-invalid-branch-name.out"
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

        system_registry_config="$aos_root/var/lib/apm/config/registries.d/host-reg-system.toml"
        user_shadow_config="$config/apm/registries.d/host-reg-system.toml"
        system_registry_cache="$aos_root/var/lib/apm/remote/host-reg-system"
        system_registry_clone="$aos_root/var/lib/apm/registries/host-reg-system"
        run_clean ${self}/bin/apm --json registry --system add \
          --no-verify "file://$work/host-origin.git" \
          --name host-reg-system \
          --branch stable \
          --priority 777 > "$work/apm-system-registry-add.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$system_registry_config" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-reg-system"
            and .priority == 777
            and .tracking == "branch:stable"
            and .clone == true
            and .synced == true
            and .verification_disabled == true
            and .config == $config_path
            and .packages == 1
            and (.last_commit | length == 64)' \
          "$work/apm-system-registry-add.json" >/dev/null
        grep -q 'last_commit = ' "$system_registry_config"
        test -d "$system_registry_cache/packages"
        test -d "$system_registry_clone"
        test ! -e "$user_shadow_config"
        test ! -e "$data/apm/remote/host-reg-system"
        run_clean ${self}/bin/apm --json registry --system list \
          > "$work/apm-system-registry-list.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "host-reg-system"
            and .[0].priority == 777
            and .[0].enabled == true
            and .[0].packages == 1
            and .[0].tracking == "branch:stable"' \
          "$work/apm-system-registry-list.json" >/dev/null
        run_clean ${self}/bin/apm --json registry --system disable host-reg-system \
          > "$work/apm-system-registry-disable.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$system_registry_config" \
          '.action == "registry_disable"
            and .status == "disabled"
            and .registry == "host-reg-system"
            and .enabled == false
            and .previous_enabled == true
            and .changed == true
            and .config == $config_path' \
          "$work/apm-system-registry-disable.json" >/dev/null
        grep -q 'enabled = false' "$system_registry_config"
        if run_clean ${self}/bin/apm update --registry host-reg-system \
          > "$work/apm-system-registry-update-disabled.out" 2>&1; then
          cat "$work/apm-system-registry-update-disabled.out"
          exit 1
        fi
        grep -q "registry 'host-reg-system' is not enabled" \
          "$work/apm-system-registry-update-disabled.out"
        run_clean ${self}/bin/apm --json registry --system enable host-reg-system \
          > "$work/apm-system-registry-enable.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$system_registry_config" \
          '.action == "registry_enable"
            and .status == "enabled"
            and .registry == "host-reg-system"
            and .enabled == true
            and .previous_enabled == false
            and .changed == true
            and .config == $config_path' \
          "$work/apm-system-registry-enable.json" >/dev/null
        grep -q 'enabled = true' "$system_registry_config"
        run_clean ${self}/bin/apm --json registry --system remove host-reg-system \
          > "$work/apm-system-registry-remove.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$system_registry_config" \
          --arg local_path "$system_registry_clone" \
          '.action == "registry_remove"
            and .status == "removed"
            and .registry == "host-reg-system"
            and .keep_local == false
            and .config == $config_path
            and .config_removed == true
            and .local == $local_path
            and .local_removed == true
            and .cache_removed == true' \
          "$work/apm-system-registry-remove.json" >/dev/null
        test ! -e "$system_registry_config"
        test ! -e "$system_registry_cache"
        test ! -e "$system_registry_clone"
        test ! -e "$user_shadow_config"
        ${pkgs.coreutils}/bin/rmdir "$aos_root/var/lib/apm/config/registries.d"
        assert_no_profile

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
        printf '%s\n' \
          'StoreDir: /nix/store' \
          'WantMassQuery: 1' \
          'Priority: 41' \
          > "$cache_root/cache/nix-cache-info"
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
        manual_tag_head=$(git -C "$reg" rev-parse HEAD)
        if run_clean ${self}/bin/apr tag \
          --registry host-reg \
          --key "$work/release-key" \
          -- -bad-tag > "$work/apr-tag-invalid-option.out" 2>&1; then
          cat "$work/apr-tag-invalid-option.out"
          exit 1
        fi
        grep -q "git ref name" "$work/apr-tag-invalid-option.out"
        if git -C "$reg" show-ref --verify --quiet refs/tags/-bad-tag; then
          exit 1
        fi
        run_clean ${self}/bin/apr --json tag manual-checkpoint \
          --registry host-reg \
          --message "manual checkpoint before release" \
          --key "$work/release-key" \
          > "$work/apr-tag-manual-checkpoint.json"
        manual_tag_object=$(git -C "$reg" rev-parse 'manual-checkpoint^{tag}')
        manual_tag_commit=$(git -C "$reg" rev-parse 'manual-checkpoint^{commit}')
        test "$manual_tag_commit" = "$manual_tag_head"
        ${pkgs.jq}/bin/jq -e \
          --arg target "$manual_tag_head" \
          --arg object "$manual_tag_object" \
          '.action == "tag"
            and .status == "tagged"
            and .registry == "host-reg"
            and .tag == "manual-checkpoint"
            and .message == "manual checkpoint before release"
            and .target == $target
            and .tag_object == $object' \
          "$work/apr-tag-manual-checkpoint.json" >/dev/null
        git -C "$reg" cat-file -p manual-checkpoint \
          > "$work/apr-tag-manual-checkpoint.out"
        grep -q "manual checkpoint before release" \
          "$work/apr-tag-manual-checkpoint.out"
        grep -q "BEGIN SSH SIGNATURE" \
          "$work/apr-tag-manual-checkpoint.out"
        grep -q "refs/tags/manual-checkpoint" "$reg/.git/info/refs"
        run_clean ${self}/bin/apr status --registry host-reg \
          > "$work/apr-status-after-manual-tag.out" 2>&1
        if grep -q '[^[:space:]]' "$work/apr-status-after-manual-tag.out"; then
          cat "$work/apr-status-after-manual-tag.out"
          exit 1
        fi
        assert_no_profile

        run_clean ${self}/bin/apr --json release 1.0.0 \
          --registry host-reg \
          --key "$work/release-key" \
          --dry-run \
          --cache-url "http://127.0.0.1:$cache_port/cache" \
          --upload-url "file://$work/dry-upload" \
          > "$work/apr-release-dry-run.json"
        ${pkgs.jq}/bin/jq -e \
          --arg cache_url "http://127.0.0.1:$cache_port/cache" \
          --arg upload_url "file://$work/dry-upload" \
          '.action == "release"
            and .status == "planned"
            and .registry == "host-reg"
            and .version == "1.0.0"
            and .dry_run == true
            and .resume == false
            and (.cache_dir | endswith("/apm/registry-static/host-reg"))
            and .cache_url == $cache_url
            and .upload_urls == [$upload_url]
            and .cache == null
            and .full_pack == null
            and .deltas == []
            and (.planned_steps | index("generate_static_cache") != null)
            and (.planned_steps | index("upload_static_origin") != null)' \
          "$work/apr-release-dry-run.json" >/dev/null
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

        run_clean ${self}/bin/apr create host-resume \
          > "$work/apr-create-host-resume.out" 2>&1
        resume_reg="$data/apm/registries/host-resume"
        git -C "$resume_reg" config user.name "Host Command Test"
        git -C "$resume_reg" config user.email "host-command@example.invalid"
        ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -f "$work/resume-release-key"
        # Build a small real package registered in this test's Nix store to
        # release (apr release introspects the store path via `nix path-info`).
        cat > "$work/resume-build.sh" << 'SCRIPT'
        set -eu
        @AOS_COREUTILS@/bin/mkdir -p "$out/bin"
        {
          printf '%s\n' '#!@AOS_BASH@/bin/bash'
          printf '%s\n' 'printf "host resume package executed\n"'
        } > "$out/bin/hostresume-tool"
        @AOS_COREUTILS@/bin/chmod +x "$out/bin/hostresume-tool"
        SCRIPT
        cat > "$work/resume-fixture.nix" << 'NIX'
        derivation {
          name = "hostresume-1.0.0";
          system = "x86_64-linux";
          builder = "@AOS_BASH@/bin/bash";
          args = [ ./resume-build.sh ];
        }
        NIX
        ${pkgs.python3}/bin/python3 - "$work/resume-build.sh" "$work/resume-fixture.nix" \
          '${pkgs.bash}' '${pkgs.coreutils}' << 'PY'
        from pathlib import Path
        import sys
        for p in sys.argv[1:3]:
            path = Path(p)
            path.write_text(
                path.read_text()
                .replace("@AOS_BASH@", sys.argv[3])
                .replace("@AOS_COREUTILS@", sys.argv[4])
            )
        PY
        resume_store=$(nix_build "$work/resume-fixture.nix" --no-out-link)
        # The release pipeline now generates and uploads the static cache
        # before creating the signed tag, so a partially-interrupted release
        # can no longer be simulated with a missing store path. Instead drive
        # the resume contract directly: a completed release creates a signed
        # tag + release pack; re-releasing the same version must refuse unless
        # --resume is given, and --resume reuses the existing tag/pack.
        run_clean ${self}/bin/apr --json release 1.0.0 \
          --registry host-resume \
          --store-path "$resume_store" \
          --name hostresume \
          --description "Host release resume fixture" \
          --license MIT \
          --maintainer host@example.invalid \
          --key "$work/resume-release-key" \
          --cache-url "http://127.0.0.1:$cache_port/resume-cache" \
          --upload-url "file://$work/resume-upload" \
          > "$work/apr-release-host-resume-initial.json"
        ${pkgs.jq}/bin/jq -e '.status == "released" and .version == "1.0.0"' \
          "$work/apr-release-host-resume-initial.json" >/dev/null
        git -C "$resume_reg" rev-parse --verify '1.0.0^{tag}' \
          > "$work/apr-release-host-resume-tag.out"
        resume_pack_dir="$resume_reg/.git/releases/1/0/0/objects/pack"
        test "$(find "$resume_pack_dir" -name 'pack-*.pack' | grep -c .)" = "1"
        if run_clean ${self}/bin/apr --json release 1.0.0 \
          --registry host-resume \
          --key "$work/resume-release-key" \
          --cache-url "http://127.0.0.1:$cache_port/resume-cache" \
          --upload-url "file://$work/resume-upload" \
          > "$work/apr-release-host-resume-without-flag.json" 2>&1; then
          cat "$work/apr-release-host-resume-without-flag.json"
          exit 1
        fi
        grep -q "already exists" \
          "$work/apr-release-host-resume-without-flag.json"
        run_clean ${self}/bin/apr --json release 1.0.0 \
          --registry host-resume \
          --key "$work/resume-release-key" \
          --cache-url "http://127.0.0.1:$cache_port/resume-cache" \
          --upload-url "file://$work/resume-upload" \
          --resume > "$work/apr-release-host-resume-after-interrupt.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "release"
            and .status == "released"
            and .registry == "host-resume"
            and .version == "1.0.0"
            and .resume == true
            and (.full_pack | startswith("pack-") and endswith(".pack"))' \
          "$work/apr-release-host-resume-after-interrupt.json" >/dev/null
        test "$(find "$resume_pack_dir" -name 'pack-*.pack' | grep -c .)" = "1"
        assert_no_profile

        if run_clean ${self}/bin/apr sign --registry host-reg --key "$work/release-key" \
          > "$work/apr-sign-missing-tag.out" 2>&1; then
          cat "$work/apr-sign-missing-tag.out"
          exit 1
        fi
        grep -q "pass the existing tag name to re-sign" "$work/apr-sign-missing-tag.out"

        if run_clean ${self}/bin/apr sign bad..tag \
          --registry host-reg \
          --key "$work/release-key" \
          > "$work/apr-sign-invalid-refexpr.out" 2>&1; then
          cat "$work/apr-sign-invalid-refexpr.out"
          exit 1
        fi
        grep -q "git ref name" "$work/apr-sign-invalid-refexpr.out"

        initial_tag_object=$(git -C "$reg" rev-parse '1.0.0^{tag}')
        initial_tag_commit=$(git -C "$reg" rev-parse '1.0.0^{commit}')
        ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -f "$work/release-key-next"
        run_without_git_identity ${self}/bin/apr --json sign 1.0.0 \
          --registry host-reg \
          --key "$work/release-key-next" \
          > "$work/apr-sign.json"
        resigned_tag_object=$(git -C "$reg" rev-parse '1.0.0^{tag}')
        resigned_tag_commit=$(git -C "$reg" rev-parse '1.0.0^{commit}')
        test "$resigned_tag_commit" = "$initial_tag_commit"
        test "$resigned_tag_object" != "$initial_tag_object"
        ${pkgs.jq}/bin/jq -e \
          --arg target "$initial_tag_commit" \
          --arg previous "$initial_tag_object" \
          --arg object "$resigned_tag_object" \
          '.action == "sign"
            and .status == "signed"
            and .registry == "host-reg"
            and .tag == "1.0.0"
            and .target == $target
            and .previous_tag_object == $previous
            and .tag_object == $object' \
          "$work/apr-sign.json" >/dev/null
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
        mkdir -p "$reg/store/$(printf %.2s "$v2_hash")"
        printf 'nar:sha256:0000000000000000000000000000000000000000000000000000:1234\n' > "$reg/store/$(printf %.2s "$v2_hash")/$v2_hash"
        git -C "$reg" add -A
        git -C "$reg" commit -m "release: hostpkg 2.0.0" > "$work/git-commit-v2-package.out" 2>&1

        run_clean ${self}/bin/apr --json release 2.0.0 \
          --registry host-reg \
          --key "$work/release-key-next" \
          --rotate-from "$work/release-key" \
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

        run_clean ${self}/bin/apr --json packages --registry host-reg --outdated \
          > "$work/apr-packages-outdated.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostpkg"
            and .[0].version == "2.0.0"' \
          "$work/apr-packages-outdated.json" >/dev/null
        run_clean ${self}/bin/apr packages --registry host-reg --outdated \
          > "$work/apr-packages-outdated.out" 2>&1
        grep -q "hostpkg 2.0.0" "$work/apr-packages-outdated.out"
        run_clean ${self}/bin/apr --json packages --registry host-reg --outdated \
          --platform x86_64-linux > "$work/apr-packages-outdated-x86_64.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostpkg"
            and .[0].version == "2.0.0"' \
          "$work/apr-packages-outdated-x86_64.json" >/dev/null
        run_clean ${self}/bin/apr --json packages --registry host-reg --outdated \
          --platform aarch64-linux > "$work/apr-packages-outdated-aarch64.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apr-packages-outdated-aarch64.json" >/dev/null
        run_clean ${self}/bin/apr --json show hostpkg --registry host-reg \
          --version 1.0.0 > "$work/apr-show-hostpkg-v1.json"
        ${pkgs.jq}/bin/jq -e \
          '.package.name == "hostpkg"
            and (.versions | length == 1)
            and .versions[0].version == "1.0.0"
            and .versions[0].platforms."x86_64-linux".store_path == "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hostpkg-1.0.0"' \
          "$work/apr-show-hostpkg-v1.json" >/dev/null
        run_clean ${self}/bin/apr --json show hostpkg --registry host-reg \
          --version 2.0.0 > "$work/apr-show-hostpkg-v2.json"
        ${pkgs.jq}/bin/jq -e \
          '.package.name == "hostpkg"
            and (.versions | length == 1)
            and .versions[0].version == "2.0.0"
            and .versions[0].platforms."x86_64-linux".store_path == "/nix/store/cccccccccccccccccccccccccccccccc-hostpkg-2.0.0"' \
          "$work/apr-show-hostpkg-v2.json" >/dev/null
        if run_clean ${self}/bin/apr --json show hostpkg --registry host-reg \
          --version 9.9.9 > "$work/apr-show-hostpkg-missing-version.json" 2>&1; then
          cat "$work/apr-show-hostpkg-missing-version.json"
          exit 1
        fi
        ${pkgs.jq}/bin/jq -e \
          '.error | contains("does not contain version")' \
          "$work/apr-show-hostpkg-missing-version.json" >/dev/null

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
        upload_root_mirror="$work/uploaded-origin-mirror"
        run_clean ${self}/bin/apr --json origin upload \
          --registry host-reg \
          --cache-dir "$cache_root/cache" \
          --upload-url "file://$upload_root" \
          --upload-url "file://$upload_root_mirror" \
          > "$work/apr-origin-upload.json"
        ${pkgs.jq}/bin/jq -e \
          --arg upload_url "file://$upload_root" \
          --arg upload_url_mirror "file://$upload_root_mirror" \
          --arg cache_dir "$cache_root/cache" \
          '.action == "origin_upload"
            and .registry == "host-reg"
            and .upload_urls == [$upload_url, $upload_url_mirror]
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
        test -f "$upload_root_mirror/HEAD"
        test -f "$upload_root_mirror/info/refs"
        test -f "$upload_root_mirror/releases/1/0/0/objects/info/packs"
        test -f "$upload_root_mirror/releases/2/0/0/objects/info/packs"
        find "$upload_root_mirror/releases/2/0/0/objects/pack" -name 'pack-*.pack' | grep -q .
        test -f "$upload_root_mirror/releases/2/0/0/objects/pack/delta-1.0.0.pack.zst"
        test -f "$upload_root_mirror/channels/canary/00"
        test -f "$upload_root_mirror/$pkg_hash.narinfo"
        test -f "$upload_root_mirror/nar/$pkg_hash-hostpkg.nar"
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
        cat > "$work/host-build-leaf-v11.sh" << 'SCRIPT'
        set -eu
        @AOS_COREUTILS@/bin/mkdir -p "$out/bin" "$out/share/host-leaf"
        {
          printf '%s\n' '#!@AOS_BASH@/bin/bash'
          printf '%s\n' 'printf "host leaf package v1.1 executed\n"'
        } > "$out/bin/host-leaf-tool"
        @AOS_COREUTILS@/bin/chmod +x "$out/bin/host-leaf-tool"
        printf '%s\n' "host leaf payload v1.1" > "$out/share/host-leaf/payload.txt"
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
        cat > "$work/host-build-app-v11.sh" << 'SCRIPT'
        set -eu
        leaf="$1"
        @AOS_COREUTILS@/bin/mkdir -p "$out/bin" "$out/share/host-install"
        {
          printf '%s\n' '#!@AOS_BASH@/bin/bash'
          printf '%s\n' "\"$leaf/bin/host-leaf-tool\""
          printf '%s\n' 'printf "host install package v1.1 executed\n"'
        } > "$out/bin/host-install-tool"
        @AOS_COREUTILS@/bin/chmod +x "$out/bin/host-install-tool"
        printf '%s\n' "host install payload v1.1" > "$out/share/host-install/payload.txt"
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
        cat > "$work/host-build-bulk.sh" << 'SCRIPT'
        set -eu
        @AOS_COREUTILS@/bin/mkdir -p "$out/bin" "$out/share/host-bulk/data"

        i=1
        while [ "$i" -le 48 ]; do
          suffix=$(printf '%02d' "$i")
          file="$out/share/host-bulk/data/chunk-$suffix.txt"
          : > "$file"
          j=1
          while [ "$j" -le 512 ]; do
            printf 'hostbulk file=%02d line=%04d payload=abcdefghijklmnopqrstuvwxyz0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ\n' \
              "$i" "$j" >> "$file"
            j=$((j + 1))
          done
          i=$((i + 1))
        done

        @AOS_COREUTILS@/bin/cat > "$out/bin/host-bulk-verify" << EOF
        #!@AOS_BASH@/bin/bash
        set -eu
        data="$out/share/host-bulk/data"
        count=\$(@AOS_FINDUTILS@/bin/find "\$data" -type f -name 'chunk-*.txt' | @AOS_COREUTILS@/bin/wc -l)
        count=\$(printf '%s' "\$count" | @AOS_COREUTILS@/bin/tr -d ' ')
        if [ "\$count" != "48" ]; then
          printf 'expected 48 data files, got %s\n' "\$count" >&2
          exit 1
        fi
        @AOS_GREP@/bin/grep -q 'hostbulk file=01 line=0001' "\$data/chunk-01.txt"
        @AOS_GREP@/bin/grep -q 'hostbulk file=48 line=0512' "\$data/chunk-48.txt"
        bytes=\$(@AOS_COREUTILS@/bin/wc -c "\$data"/chunk-*.txt | @AOS_COREUTILS@/bin/tail -n 1 | @AOS_COREUTILS@/bin/tr -dc '0-9')
        printf 'host bulk package verified %s files %s bytes\n' "\$count" "\$bytes"
        EOF
        @AOS_COREUTILS@/bin/chmod +x "$out/bin/host-bulk-verify"
        SCRIPT
        cat > "$work/host-build-sysroot.sh" << 'SCRIPT'
        set -eu
        @AOS_COREUTILS@/bin/mkdir -p "$out/bin" "$out/etc"
        {
          printf '%s\n' '#!@AOS_BASH@/bin/bash'
          printf '%s\n' 'printf "host sysroot fixture activated\n"'
        } > "$out/activate"
        @AOS_COREUTILS@/bin/chmod +x "$out/activate"
        printf '%s\n' "host sysroot payload" > "$out/etc/host-sysroot-release"
        SCRIPT
        cat > "$work/host-build-sysroot-image.sh" << 'SCRIPT'
        set -eu
        @AOS_COREUTILS@/bin/mkdir -p "$out"
        {
          printf '%s\n' "host sysroot image qcow2 fixture"
          printf '%s\n' "boot-marker=hostsysroot"
        } > "$out/hostsysroot.qcow2"
        SCRIPT
        substitute_fixture_paths() {
          ${pkgs.python3}/bin/python3 - "$1" '${pkgs.bash}' '${pkgs.coreutils}' '${pkgs.findutils}' '${pkgs.grep}' << 'PY'
        from pathlib import Path
        import sys

        path = Path(sys.argv[1])
        path.write_text(
            path.read_text()
            .replace("@AOS_BASH@", sys.argv[2])
            .replace("@AOS_COREUTILS@", sys.argv[3])
            .replace("@AOS_FINDUTILS@", sys.argv[4])
            .replace("@AOS_GREP@", sys.argv[5])
        )
        PY
        }
        substitute_fixture_paths "$work/host-build-leaf.sh"
        substitute_fixture_paths "$work/host-build-leaf-v11.sh"
        substitute_fixture_paths "$work/host-build-leaf-v2.sh"
        substitute_fixture_paths "$work/host-build-app-v1.sh"
        substitute_fixture_paths "$work/host-build-app-v11.sh"
        substitute_fixture_paths "$work/host-build-app-v2.sh"
        substitute_fixture_paths "$work/host-build-bulk.sh"
        substitute_fixture_paths "$work/host-build-sysroot.sh"
        substitute_fixture_paths "$work/host-build-sysroot-image.sh"
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
          leafV11 = derivation {
            name = "hostleaf-1.1.0";
            inherit system;
            builder = bash;
            args = [ ./host-build-leaf-v11.sh ];
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
          bulk = derivation {
            name = "hostbulk-1.0.0";
            inherit system;
            builder = bash;
            args = [ ./host-build-bulk.sh ];
          };
          sysroot = derivation {
            name = "hostsysroot-1.0.0";
            inherit system;
            builder = bash;
            args = [ ./host-build-sysroot.sh ];
          };
          sysrootImage = derivation {
            name = "hostsysroot-image-1.0.0";
            inherit system;
            builder = bash;
            args = [ ./host-build-sysroot-image.sh ];
          };
        in {
          leaf = leafV1;
          inherit leafV1 leafV11 leafV2 bulk sysroot sysrootImage;
          appV1 = app "hostinstall-1.0.0" leafV1 ./host-build-app-v1.sh;
          appV11 = app "hostinstall-1.1.0" leafV11 ./host-build-app-v11.sh;
          appV2 = app "hostinstall-2.0.0" leafV2 ./host-build-app-v2.sh;
        }
        NIX
        substitute_fixture_paths "$work/host-install-fixtures.nix"

        install_leaf_store=$(nix_build "$work/host-install-fixtures.nix" -A leaf --no-out-link)
        install_leaf_hash=$(basename "$install_leaf_store" | cut -d- -f1)
        install_leaf_drv=$(nix_store -q --deriver "$install_leaf_store")
        test -e "$install_leaf_drv"
        install_store=$(nix_build "$work/host-install-fixtures.nix" -A appV1 --no-out-link)
        install_hash=$(basename "$install_store" | cut -d- -f1)
        install_drv=$(nix_store -q --deriver "$install_store")
        test -e "$install_drv"
        bulk_store=$(nix_build "$work/host-install-fixtures.nix" -A bulk --no-out-link)
        bulk_hash=$(basename "$bulk_store" | cut -d- -f1)
        bulk_drv=$(nix_store -q --deriver "$bulk_store")
        test -e "$bulk_drv"
        sysroot_store=$(nix_build "$work/host-install-fixtures.nix" -A sysroot --no-out-link)
        sysroot_hash=$(basename "$sysroot_store" | cut -d- -f1)
        sysroot_drv=$(nix_store -q --deriver "$sysroot_store")
        test -e "$sysroot_drv"
        sysroot_image_store=$(nix_build "$work/host-install-fixtures.nix" -A sysrootImage --no-out-link)
        sysroot_image_hash=$(basename "$sysroot_image_store" | cut -d- -f1)
        sysroot_image_drv=$(nix_store -q --deriver "$sysroot_image_store")
        test -e "$sysroot_image_drv"

        ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -f "$work/host-install-release-key"
        install_release_public_key=$(${pkgs.coreutils}/bin/cut -d ' ' -f2 < "$work/host-install-release-key.pub")
        install_channel_trust_key="host-install-channel:Ed25519:$install_release_public_key"
        ${pkgs.python3}/bin/python3 - << 'PY' > "$work/host-install-cache-signing-key"
        import base64

        print("hostcache:" + base64.b64encode(bytes(range(32))).decode("ascii"))
        PY
        run_clean ${self}/bin/apr create host-install-channel \
          --trust-key "$install_channel_trust_key" \
          --trust-key-id channel \
          --key "$work/host-install-release-key" \
          > "$work/apr-create-host-install.out" 2>&1
        install_reg="$data/apm/registries/host-install-channel"
        git -C "$install_reg" config user.name "Host Command Test"
        git -C "$install_reg" config user.email "host-command@example.invalid"
        run_clean ${self}/bin/apm --json registry add --no-verify --no-clone "file://$install_reg" \
          --name host-install-channel \
          > "$work/apm-add-host-install-author-config.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$config/apm/registries.d/host-install-channel.toml" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-install-channel"
            and .clone == false
            and .synced == false
            and .config == $config_path
            and .verification_disabled == true' \
          "$work/apm-add-host-install-author-config.json" >/dev/null
        if run_clean ${self}/bin/apr publish "$install_store" \
          --name ../../escaped-publish \
          --registry host-install-channel \
          --no-commit > "$work/apr-publish-invalid-package-name.out" 2>&1; then
          cat "$work/apr-publish-invalid-package-name.out"
          exit 1
        fi
        grep -q "invalid package name" \
          "$work/apr-publish-invalid-package-name.out"
        test ! -e "$install_reg/escaped-publish.toml"
        if run_clean ${self}/bin/apr publish "$install_leaf_store" \
          --name hostbadplatform \
          --version 1.0.0 \
          --platform 'x86_64-linux]' \
          --description "Invalid platform fixture" \
          --license MIT \
          --maintainer host@example.invalid \
          --registry host-install-channel \
          --no-commit > "$work/apr-publish-invalid-platform.out" 2>&1; then
          cat "$work/apr-publish-invalid-platform.out"
          exit 1
        fi
        grep -q "invalid platform name" \
          "$work/apr-publish-invalid-platform.out"
        test ! -e "$install_reg/packages/h/hostbadplatform.toml"
        run_clean ${self}/bin/apr --json publish "$install_leaf_store" \
          --name hostleaf \
          --version 1.0.0 \
          --description "Host \"APM\" dependency fixture" \
          --license MIT \
          --maintainer host@example.invalid \
          --registry host-install-channel \
          --no-commit > "$work/apr-publish-host-leaf.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_leaf_store" \
          --arg source "$install_leaf_drv" \
          '.action == "publish"
            and .registry == "host-install-channel"
            and .package == "hostleaf"
            and .version == "1.0.0"
            and .platform == "x86_64-linux"
            and .store_path == $store
            and (.nar_hash | startswith("sha256-"))
            and (.closure_size > 0)
            and .source.store_path == $source
            and (.source.nar_hash | startswith("sha256-"))
            and (.source.nar_size > 0)
            and .committed == false' \
          "$work/apr-publish-host-leaf.json" >/dev/null
        run_clean ${self}/bin/apr --json show hostleaf \
          --registry host-install-channel > "$work/apr-show-host-leaf-quoted-description.json"
        ${pkgs.jq}/bin/jq -e \
          '.package.name == "hostleaf"
            and .package.description == "Host \"APM\" dependency fixture"' \
          "$work/apr-show-host-leaf-quoted-description.json" >/dev/null
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
          --arg source "$install_drv" \
          '.action == "publish"
            and .registry == "host-install-channel"
            and .package == "hostinstall"
            and .version == "1.0.0"
            and .platform == "x86_64-linux"
            and .store_path == $store
            and (.nar_hash | startswith("sha256-"))
            and (.nar_size > 0)
            and (.closure_size > 0)
            and .source.store_path == $source
            and (.source.nar_hash | startswith("sha256-"))
            and (.source.nar_size > 0)
            and .sysroot == false
            and .previous == null
            and .images == []
            and .package_file == "packages/h/hostinstall.toml"
            and .committed == false
            and .commit_message == null
            and .current == "stable"
            and (.head | length == 64)' \
          "$work/apr-publish-host-install.json" >/dev/null
        run_clean ${self}/bin/apr --json publish "$bulk_store" \
          --name hostbulk \
          --version 1.0.0 \
          --description "Host APM bulk data fixture" \
          --license MIT \
          --maintainer host@example.invalid \
          --registry host-install-channel \
          --no-commit > "$work/apr-publish-host-bulk.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$bulk_store" \
          --arg source "$bulk_drv" \
          '.action == "publish"
            and .registry == "host-install-channel"
            and .package == "hostbulk"
            and .version == "1.0.0"
            and .platform == "x86_64-linux"
            and .store_path == $store
            and (.nar_hash | startswith("sha256-"))
            and (.nar_size > 1000000)
            and (.closure_size > 1000000)
            and .source.store_path == $source
            and (.source.nar_hash | startswith("sha256-"))
            and (.source.nar_size > 0)
            and .sysroot == false
            and .previous == null
            and .images == []
            and .package_file == "packages/h/hostbulk.toml"
            and .committed == false
            and .commit_message == null
            and .current == "stable"
            and (.head | length == 64)' \
          "$work/apr-publish-host-bulk.json" >/dev/null
        grep -q "$install_leaf_hash" "$install_reg/store/$(printf %.2s "$install_hash")/$install_hash"
        run_clean ${self}/bin/apr --json verify \
          --registry host-install-channel > "$work/apr-verify-host-install-all.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "verify"
            and .status == "ok"
            and .registry == "host-install-channel"
            and .package == null
            and .fix == false
            and .checked == 3
            and .roots == 3
            and .repaired == 0
            and .errors == 0' \
          "$work/apr-verify-host-install-all.json" >/dev/null
        ${pkgs.coreutils}/bin/rm "$install_reg/store/$(printf %.2s "$install_hash")/$install_hash"
        run_clean ${self}/bin/apr --json verify \
          --registry host-install-channel \
          --package hostinstall \
          --fix > "$work/apr-verify-host-install-fix.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "verify"
            and .status == "ok"
            and .registry == "host-install-channel"
            and .package == "hostinstall"
            and .fix == true
            and .checked == 1
            and .roots == 1
            and .repaired == 1
            and .errors == 0' \
          "$work/apr-verify-host-install-fix.json" >/dev/null
        grep -q "$install_leaf_hash" "$install_reg/store/$(printf %.2s "$install_hash")/$install_hash"
        install_default_upload="file://$work/install-static-cache-upload/cache"
        install_default_upload_mirror="file://$work/install-static-cache-upload/cache-mirror"
        run_clean ${self}/bin/apr --json origin config \
          --registry host-install-channel \
          --upload-url "$install_default_upload" \
          --upload-url "$install_default_upload_mirror" \
          --header "X-Test-Workflow: host-install" \
          > "$work/apr-origin-config-host-install.json"
        ${pkgs.jq}/bin/jq -e \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          --arg config_path "$config/apm/registries.d/host-install-channel.toml" \
          '.action == "origin_config"
            and .registry == "host-install-channel"
            and .config == $config_path
            and .upload_auth.upload_urls == [$upload_url, $upload_url_mirror]
            and .upload_auth.headers == ["X-Test-Workflow: host-install"]' \
          "$work/apr-origin-config-host-install.json" >/dev/null
        grep -q '\[registry.upload_auth\]' \
          "$config/apm/registries.d/host-install-channel.toml"
        grep -q 'upload_urls = \[' \
          "$config/apm/registries.d/host-install-channel.toml"
        run_clean ${self}/bin/apr --json origin config \
          --registry host-install-channel \
          > "$work/apr-origin-config-host-install-show.json"
        ${pkgs.jq}/bin/jq -e \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          '.action == "origin_config"
            and .registry == "host-install-channel"
            and .upload_auth.upload_urls == [$upload_url, $upload_url_mirror]
            and .upload_auth.headers == ["X-Test-Workflow: host-install"]' \
          "$work/apr-origin-config-host-install-show.json" >/dev/null
        run_clean ${self}/bin/apr --json origin config \
          --registry host-install-channel \
          --unset headers \
          > "$work/apr-origin-config-host-install-unset-headers.json"
        ${pkgs.jq}/bin/jq -e \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          '.action == "origin_config"
            and .registry == "host-install-channel"
            and .upload_auth.upload_urls == [$upload_url, $upload_url_mirror]
            and .upload_auth.headers == []' \
          "$work/apr-origin-config-host-install-unset-headers.json" >/dev/null
        if grep -q '^headers = ' \
          "$config/apm/registries.d/host-install-channel.toml"; then
          cat "$config/apm/registries.d/host-install-channel.toml"
          exit 1
        fi
        grep -q 'upload_urls = \[' \
          "$config/apm/registries.d/host-install-channel.toml"
        run_clean ${self}/bin/apr --json cache generate \
          --registry host-install-channel \
          --output "$work/install-static-cache-output/cache" \
          --key "$work/host-install-cache-signing-key" \
          --cache-url "http://127.0.0.1:$install_cache_port/cache" \
          --priority 77 \
          --no-commit > "$work/apr-cache-host-install.json"
        ${pkgs.jq}/bin/jq -e \
          --arg output "$work/install-static-cache-output/cache" \
          --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          '.action == "cache_generate"
            and .registry == "host-install-channel"
            and .output_dir == $output
            and .paths >= 3
            and .narinfos >= 3
            and .nars >= 3
            and .cache_url == $cache_url
            and .priority == 77
            and .upload_urls == [$upload_url, $upload_url_mirror]
            and .uploaded == true
            and .cache_pointer_updated == true
            and .committed == false' \
          "$work/apr-cache-host-install.json" >/dev/null
        test -f "$work/install-static-cache-output/cache/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-output/cache/$install_hash.narinfo"
        test -f "$work/install-static-cache-output/cache/$bulk_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-output/cache/$install_leaf_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-output/cache/$install_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-output/cache/$bulk_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/nix-cache-info"
        test -f "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/$bulk_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$bulk_hash.narinfo"
        find "$work/install-static-cache-upload/cache/nar" -type f | grep -q .
        test -f "$work/install-static-cache-upload/cache-mirror/nix-cache-info"
        test -f "$work/install-static-cache-upload/cache-mirror/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache-mirror/$install_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache-mirror/$bulk_hash.narinfo"
        find "$work/install-static-cache-upload/cache-mirror/nar" -type f | grep -q .
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
          --cache-key "$work/host-install-cache-signing-key" \
          --cache-url "http://127.0.0.1:$install_cache_port/cache" \
          --cache-priority 77 \
          --channel stable \
          --init-channel > "$work/apr-release-host-install-v1.json"
        ${pkgs.jq}/bin/jq -e \
          --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          '.action == "release"
            and .status == "released"
            and .registry == "host-install-channel"
            and .version == "1.0.0"
            and .dry_run == false
            and .cache_url == $cache_url
            and .cache_priority == 77
            and .cache_pointer_updated == false
            and .upload_urls == [$upload_url, $upload_url_mirror]
            and .channel.name == "stable"
            and .channel.action == "init"
            and .channel.touched_partitions == 256
            and (.cache.paths >= 3)
            and (.cache.remote_skipped >= 3)
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
        test -f "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/$bulk_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$bulk_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/HEAD"
        test -f "$work/install-static-cache-upload/cache/info/refs"
        test -f "$work/install-static-cache-upload/cache/releases/1/0/0/objects/info/packs"
        test -f "$work/install-static-cache-upload/cache/channels/stable/00"
        grep -q "BEGIN SSH SIGNATURE" \
          "$work/install-static-cache-upload/cache/channels/stable/00"
        test -f "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/$bulk_hash.narinfo"
        find "$work/install-static-cache-upload/cache/releases/1/0/0/objects/pack" \
          -name 'pack-*.pack' | grep -q .
        test -f "$work/install-static-cache-upload/cache-mirror/HEAD"
        test -f "$work/install-static-cache-upload/cache-mirror/info/refs"
        test -f "$work/install-static-cache-upload/cache-mirror/releases/1/0/0/objects/info/packs"
        test -f "$work/install-static-cache-upload/cache-mirror/channels/stable/00"
        test -f "$work/install-static-cache-upload/cache-mirror/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache-mirror/$install_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache-mirror/$bulk_hash.narinfo"
        find "$work/install-static-cache-upload/cache-mirror/releases/1/0/0/objects/pack" \
          -name 'pack-*.pack' | grep -q .
        run_clean ${self}/bin/apr --json origin upload \
          --registry host-install-channel \
          --cache-dir "$cache/apm/registry-static/host-install-channel" \
          > "$work/apr-origin-upload-host-install-defaults.json"
        ${pkgs.jq}/bin/jq -e \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          --arg cache_dir "$cache/apm/registry-static/host-install-channel" \
          '.action == "origin_upload"
            and .registry == "host-install-channel"
            and .upload_urls == [$upload_url, $upload_url_mirror]
            and .cache_dir == $cache_dir
            and .files > 0
            and .bytes > 0' \
          "$work/apr-origin-upload-host-install-defaults.json" >/dev/null
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

        collab_origin="$work/host-collab-origin.git"
        git init --bare --object-format=sha256 "$collab_origin" \
          > "$work/git-init-host-collab-origin.out" 2>&1
        run_clean ${self}/bin/apr create host-collab \
          --remote "$collab_origin" \
          > "$work/apr-create-host-collab.out" 2>&1
        collab_a_reg="$data/apm/registries/host-collab"
        git -C "$collab_a_reg" config user.name "Host Maintainer A"
        git -C "$collab_a_reg" config user.email "host-maintainer-a@example.invalid"
        run_clean ${self}/bin/apr --json publish "$install_leaf_store" \
          --name hostcollab \
          --version 1.0.0 \
          --description "Host collaboration fixture" \
          --license MIT \
          --maintainer maintainer-a@example.invalid \
          --registry host-collab \
          --message "publish hostcollab from maintainer A" \
          > "$work/apr-publish-host-collab-a.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_leaf_store" \
          '.action == "publish"
            and .registry == "host-collab"
            and .package == "hostcollab"
            and .version == "1.0.0"
            and .store_path == $store
            and .committed == true
            and .commit_message == "publish hostcollab from maintainer A"' \
          "$work/apr-publish-host-collab-a.json" >/dev/null
        collab_a_commit=$(git -C "$collab_a_reg" rev-parse HEAD)
        run_clean ${self}/bin/apr --json push \
          --registry host-collab \
          --branch stable \
          --set-upstream > "$work/apr-push-host-collab-a.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$collab_a_commit" \
          '.action == "push"
            and .branch == "stable"
            and .set_upstream == true
            and .force == false
            and .head == $head' \
          "$work/apr-push-host-collab-a.json" >/dev/null

        collab_main_home="$home"
        collab_main_config="$config"
        collab_main_data="$data"
        collab_main_cache="$cache"
        collab_main_profile_root="$profile_root"
        collab_main_profile="$profile"
        home="$work/collab-b-home"
        config="$work/collab-b-config"
        data="$work/collab-b-share"
        cache="$work/collab-b-cache"
        profile_root="$work/collab-b-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data/apm/registries" "$cache" "$profile_root"
        collab_b_reg="$data/apm/registries/host-collab"
        git clone --branch stable "$collab_origin" "$collab_b_reg" \
          > "$work/git-clone-host-collab-b.out" 2>&1
        git -C "$collab_b_reg" config user.name "Host Maintainer B"
        git -C "$collab_b_reg" config user.email "host-maintainer-b@example.invalid"
        run_clean ${self}/bin/apr --json show hostcollab \
          --registry host-collab > "$work/apr-show-host-collab-b-base.json"
        ${pkgs.jq}/bin/jq -e \
          '.package.name == "hostcollab"
            and .versions[0].version == "1.0.0"' \
          "$work/apr-show-host-collab-b-base.json" >/dev/null
        run_clean ${self}/bin/apr --json publish "$bulk_store" \
          --name hostcollabbulk \
          --version 1.0.0 \
          --description "Host collaboration bulk fixture" \
          --license MIT \
          --maintainer maintainer-b@example.invalid \
          --registry host-collab \
          --message "publish hostcollabbulk from maintainer B" \
          > "$work/apr-publish-host-collab-b.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$bulk_store" \
          '.action == "publish"
            and .registry == "host-collab"
            and .package == "hostcollabbulk"
            and .version == "1.0.0"
            and .store_path == $store
            and (.nar_size > 1000000)
            and .committed == true
            and .commit_message == "publish hostcollabbulk from maintainer B"' \
          "$work/apr-publish-host-collab-b.json" >/dev/null
        collab_b_commit=$(git -C "$collab_b_reg" rev-parse HEAD)
        run_clean ${self}/bin/apr --json push \
          --registry host-collab \
          --branch stable > "$work/apr-push-host-collab-b.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$collab_b_commit" \
          '.action == "push"
            and .branch == "stable"
            and .set_upstream == false
            and .force == false
            and .head == $head' \
          "$work/apr-push-host-collab-b.json" >/dev/null
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$collab_main_home"
        config="$collab_main_config"
        data="$collab_main_data"
        cache="$collab_main_cache"
        profile_root="$collab_main_profile_root"
        profile="$collab_main_profile"

        run_clean ${self}/bin/apr --json pull --rebase \
          --registry host-collab > "$work/apr-pull-host-collab-a.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$collab_b_commit" \
          '.action == "pull"
            and .rebase == true
            and .current == "stable"
            and .head == $head
            and (.branches | any(.name == "origin/stable" and .remote == true))' \
          "$work/apr-pull-host-collab-a.json" >/dev/null
        run_clean ${self}/bin/apr --json show hostcollabbulk \
          --registry host-collab > "$work/apr-show-host-collab-a-after-pull.json"
        ${pkgs.jq}/bin/jq -e \
          '.package.name == "hostcollabbulk"
            and .versions[0].version == "1.0.0"
            and .versions[0].platforms."x86_64-linux".closure_size > 1000000' \
          "$work/apr-show-host-collab-a-after-pull.json" >/dev/null
        run_clean ${self}/bin/apr --json packages \
          --registry host-collab > "$work/apr-packages-host-collab-after-pull.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and any(.[]; .name == "hostcollab" and .version == "1.0.0")
            and any(.[]; .name == "hostcollabbulk" and .version == "1.0.0")' \
          "$work/apr-packages-host-collab-after-pull.json" >/dev/null

        home="$work/collab-consumer-home"
        config="$work/collab-consumer-config"
        data="$work/collab-consumer-share"
        cache="$work/collab-consumer-cache"
        profile_root="$work/collab-consumer-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm --json registry add --no-verify \
          "file://$collab_origin" \
          --name host-collab-client \
          --branch stable > "$work/apm-add-host-collab-client.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$collab_b_commit" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-collab-client"
            and .tracking == "branch:stable"
            and .synced == true
            and .last_commit == $head
            and .packages == 2' \
          "$work/apm-add-host-collab-client.json" >/dev/null
        run_clean ${self}/bin/apm --json search hostcollab \
          --registry host-collab-client > "$work/apm-search-host-collab-client.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and any(.[]; .name == "hostcollab" and .version == "1.0.0")
            and any(.[]; .name == "hostcollabbulk" and .version == "1.0.0")' \
          "$work/apm-search-host-collab-client.json" >/dev/null
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$collab_main_home"
        config="$collab_main_config"
        data="$collab_main_data"
        cache="$collab_main_cache"
        profile_root="$collab_main_profile_root"
        profile="$collab_main_profile"

        subtree_origin="$work/host-subtree-origin.git"
        git init --bare --object-format=sha256 "$subtree_origin" \
          > "$work/git-init-host-subtree-origin.out" 2>&1
        run_clean ${self}/bin/aos --json package registry create host-subtree \
          --remote "$subtree_origin" \
          > "$work/aos-package-registry-create-host-subtree.json"
        subtree_reg="$data/apm/registries/host-subtree"
        ${pkgs.jq}/bin/jq -e --arg reg "$subtree_reg" \
          '.action == "create"
            and .registry == "host-subtree"
            and .path == $reg
            and .remote != null
            and .current == "stable"
            and (.head | length == 64)' \
          "$work/aos-package-registry-create-host-subtree.json" >/dev/null
        git -C "$subtree_reg" config user.name "Host Subtree Maintainer"
        git -C "$subtree_reg" config user.email "host-subtree@example.invalid"
        run_clean ${self}/bin/aos --json package registry publish "$install_leaf_store" \
          --name hostsubtree \
          --version 1.0.0 \
          --description "Host aos package subtree fixture" \
          --license MIT \
          --maintainer host-subtree@example.invalid \
          --registry host-subtree \
          --message "publish hostsubtree via aos package registry" \
          > "$work/aos-package-registry-publish-host-subtree.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_leaf_store" \
          '.action == "publish"
            and .registry == "host-subtree"
            and .package == "hostsubtree"
            and .version == "1.0.0"
            and .store_path == $store
            and .committed == true
            and .commit_message == "publish hostsubtree via aos package registry"' \
          "$work/aos-package-registry-publish-host-subtree.json" >/dev/null
        subtree_commit=$(git -C "$subtree_reg" rev-parse HEAD)
        run_clean ${self}/bin/aos --json package registry push \
          --registry host-subtree \
          --branch stable \
          --set-upstream > "$work/aos-package-registry-push-host-subtree.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$subtree_commit" \
          '.action == "push"
            and .branch == "stable"
            and .set_upstream == true
            and .force == false
            and .head == $head' \
          "$work/aos-package-registry-push-host-subtree.json" >/dev/null

        subtree_main_home="$home"
        subtree_main_config="$config"
        subtree_main_data="$data"
        subtree_main_cache="$cache"
        subtree_main_profile_root="$profile_root"
        subtree_main_profile="$profile"
        home="$work/subtree-consumer-home"
        config="$work/subtree-consumer-config"
        data="$work/subtree-consumer-share"
        cache="$work/subtree-consumer-cache"
        profile_root="$work/subtree-consumer-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/aos --json package registry add --no-verify \
          "file://$subtree_origin" \
          --name host-subtree-client \
          --branch stable > "$work/aos-package-registry-add-host-subtree-client.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$subtree_commit" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-subtree-client"
            and .tracking == "branch:stable"
            and .synced == true
            and .last_commit == $head
            and .packages == 1' \
          "$work/aos-package-registry-add-host-subtree-client.json" >/dev/null
        run_clean ${self}/bin/aos --json package registry list \
          > "$work/aos-package-registry-list-host-subtree-client.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$subtree_commit" \
          'length == 1
            and .[0].name == "host-subtree-client"
            and .[0].enabled == true
            and .[0].status == "enabled"
            and .[0].packages == 1
            and .[0].last_commit == $head' \
          "$work/aos-package-registry-list-host-subtree-client.json" >/dev/null
        run_clean ${self}/bin/aos --json package search hostsubtree \
          --registry host-subtree-client > "$work/aos-package-search-host-subtree-client.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostsubtree"
            and .[0].version == "1.0.0"
            and .[0].registry == "host-subtree-client"' \
          "$work/aos-package-search-host-subtree-client.json" >/dev/null
        run_clean ${self}/bin/aos --json package --yes install hostsubtree \
          --registry host-subtree-client > "$work/aos-package-install-host-subtree.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostsubtree"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostsubtree"
            and .roots[0].registry == "host-subtree-client"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | length == 1)
            and .closure[0].name == "hostsubtree"
            and .closure[0].store_path == $store
            and .closure[0].explicit == true' \
          "$work/aos-package-install-host-subtree.json" >/dev/null
        "$profile/current/bin/host-leaf-tool" \
          > "$work/aos-package-host-subtree-run.out"
        grep -q "host leaf package executed" \
          "$work/aos-package-host-subtree-run.out"
        run_clean ${self}/bin/aos --json package show hostsubtree \
          --registry host-subtree-client > "$work/aos-package-show-host-subtree.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_leaf_store" \
          '.name == "hostsubtree"
            and .registry == "host-subtree-client"
            and .version == "1.0.0"
            and .installed == true
            and .store_path == $store
            and .description == "Host aos package subtree fixture"' \
          "$work/aos-package-show-host-subtree.json" >/dev/null
        run_clean ${self}/bin/aos --json package list --installed \
          --registry host-subtree-client > "$work/aos-package-list-installed-host-subtree.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostsubtree"
            and .[0].registry == "host-subtree-client"
            and .[0].version == "1.0.0"
            and .[0].status == "installed"' \
          "$work/aos-package-list-installed-host-subtree.json" >/dev/null
        run_clean ${self}/bin/aos --json package files hostsubtree \
          > "$work/aos-package-files-host-subtree.json"
        ${pkgs.jq}/bin/jq -e \
          'index("bin/host-leaf-tool") != null
            and index("share/host-leaf/payload.txt") != null' \
          "$work/aos-package-files-host-subtree.json" >/dev/null
        run_clean ${self}/bin/aos --json package verify hostsubtree \
          > "$work/aos-package-verify-host-subtree.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_leaf_store" \
          '.package == "hostsubtree"
            and .registry == "host-subtree-client"
            and .version == "1.0.0"
            and .store_path == $store
            and .verified == true
            and (.expected_nar_hash | startswith("sha256:"))
            and (.actual_nar_hash | startswith("sha256:"))' \
          "$work/aos-package-verify-host-subtree.json" >/dev/null
        run_clean ${self}/bin/aos --json package --yes remove hostsubtree \
          > "$work/aos-package-remove-host-subtree.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_leaf_store" \
          '.action == "remove"
            and .status == "removed"
            and .requested == ["hostsubtree"]
            and .autoremove == false
            and .dry_run == false
            and .generation == 2
            and .removed == 1
            and .explicit_removed == 1
            and .orphan_removed == 0
            and (.packages | length == 1)
            and .packages[0].name == "hostsubtree"
            and .packages[0].registry == "host-subtree-client"
            and .packages[0].version == "1.0.0"
            and .packages[0].store_path == $store
            and .orphans == []' \
          "$work/aos-package-remove-host-subtree.json" >/dev/null
        run_clean ${self}/bin/aos --json package list --installed \
          --registry host-subtree-client > "$work/aos-package-list-installed-host-subtree-removed.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/aos-package-list-installed-host-subtree-removed.json" >/dev/null
        if test -e "$profile/current/bin/host-leaf-tool"; then
          "$profile/current/bin/host-leaf-tool"
          exit 1
        fi
        run_clean ${self}/bin/aos --json package registry remove host-subtree-client \
          > "$work/aos-package-registry-remove-host-subtree-client.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$config/apm/registries.d/host-subtree-client.toml" \
          --arg local_path "$data/apm/registries/host-subtree-client" \
          '.action == "registry_remove"
            and .status == "removed"
            and .registry == "host-subtree-client"
            and .name == "host-subtree-client"
            and .keep_local == false
            and .force == false
            and .config == $config_path
            and .config_removed == true
            and .local == $local_path
            and .local_removed == true
            and .cache_removed == true
            and .trusted_keys_removed == false' \
          "$work/aos-package-registry-remove-host-subtree-client.json" >/dev/null
        run_clean ${self}/bin/aos --json package registry list \
          > "$work/aos-package-registry-list-after-host-subtree-remove.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/aos-package-registry-list-after-host-subtree-remove.json" >/dev/null
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$subtree_main_home"
        config="$subtree_main_config"
        data="$subtree_main_data"
        cache="$subtree_main_cache"
        profile_root="$subtree_main_profile_root"
        profile="$subtree_main_profile"

        run_clean ${self}/bin/apr create host-merge-review \
          > "$work/apr-create-host-merge-review.out" 2>&1
        merge_reg="$data/apm/registries/host-merge-review"
        git -C "$merge_reg" config user.name "Host Merge Reviewer"
        git -C "$merge_reg" config user.email "host-merge-reviewer@example.invalid"
        run_clean ${self}/bin/apr --json publish "$install_leaf_store" \
          --name hostmergeleaf \
          --version 1.0.0 \
          --description "Host merge review base fixture" \
          --license MIT \
          --maintainer merge-reviewer@example.invalid \
          --registry host-merge-review \
          --message "publish hostmergeleaf base" \
          > "$work/apr-publish-host-merge-base.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_leaf_store" \
          '.action == "publish"
            and .registry == "host-merge-review"
            and .package == "hostmergeleaf"
            and .version == "1.0.0"
            and .store_path == $store
            and .committed == true
            and .commit_message == "publish hostmergeleaf base"' \
          "$work/apr-publish-host-merge-base.json" >/dev/null

        run_clean ${self}/bin/apr branch create feature/hostmerge-no-ff \
          --registry host-merge-review > "$work/apr-branch-create-host-merge-no-ff.out" 2>&1
        run_clean ${self}/bin/apr branch switch feature/hostmerge-no-ff \
          --registry host-merge-review > "$work/apr-branch-switch-host-merge-no-ff.out" 2>&1
        run_clean ${self}/bin/apr --json publish "$install_store" \
          --name hostmergeapp \
          --version 1.0.0 \
          --description "Host merge review no-ff fixture" \
          --license MIT \
          --maintainer merge-reviewer@example.invalid \
          --registry host-merge-review \
          --message "publish hostmergeapp feature" \
          > "$work/apr-publish-host-merge-no-ff.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_store" \
          '.action == "publish"
            and .registry == "host-merge-review"
            and .package == "hostmergeapp"
            and .version == "1.0.0"
            and .store_path == $store
            and .committed == true' \
          "$work/apr-publish-host-merge-no-ff.json" >/dev/null
        run_clean ${self}/bin/apr branch switch stable \
          --registry host-merge-review > "$work/apr-branch-switch-host-merge-stable-before-no-ff.out" 2>&1
        merge_before_no_ff=$(git -C "$merge_reg" rev-parse HEAD)
        run_clean ${self}/bin/apr --json merge feature/hostmerge-no-ff \
          --no-ff \
          --registry host-merge-review > "$work/apr-merge-host-merge-no-ff.json"
        ${pkgs.jq}/bin/jq -e \
          --arg before "$merge_before_no_ff" \
          '.action == "merge"
            and .branch == "feature/hostmerge-no-ff"
            and .no_ff == true
            and .squash == false
            and .current == "stable"
            and .head != $before
            and (.head | length == 64)
            and (.output | contains("Merge made"))
            and (.branches | any(.name == "stable" and .current == true))' \
          "$work/apr-merge-host-merge-no-ff.json" >/dev/null
        merge_no_ff_parents=$(git -C "$merge_reg" rev-list --parents -n 1 HEAD)
        set -- $merge_no_ff_parents
        test "$#" = "3"
        run_clean ${self}/bin/apr --json show hostmergeapp \
          --registry host-merge-review > "$work/apr-show-host-merge-no-ff.json"
        ${pkgs.jq}/bin/jq -e \
          '.package.name == "hostmergeapp"
            and .versions[0].version == "1.0.0"' \
          "$work/apr-show-host-merge-no-ff.json" >/dev/null
        run_clean ${self}/bin/apr branch delete feature/hostmerge-no-ff \
          --registry host-merge-review > "$work/apr-branch-delete-host-merge-no-ff.out" 2>&1

        run_clean ${self}/bin/apr branch create feature/hostmerge-squash \
          --registry host-merge-review > "$work/apr-branch-create-host-merge-squash.out" 2>&1
        run_clean ${self}/bin/apr branch switch feature/hostmerge-squash \
          --registry host-merge-review > "$work/apr-branch-switch-host-merge-squash.out" 2>&1
        run_clean ${self}/bin/apr --json publish "$bulk_store" \
          --name hostmergebulk \
          --version 1.0.0 \
          --description "Host merge review squash fixture" \
          --license MIT \
          --maintainer merge-reviewer@example.invalid \
          --registry host-merge-review \
          --message "publish hostmergebulk feature" \
          > "$work/apr-publish-host-merge-squash.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$bulk_store" \
          '.action == "publish"
            and .registry == "host-merge-review"
            and .package == "hostmergebulk"
            and .version == "1.0.0"
            and .store_path == $store
            and (.nar_size > 1000000)
            and .committed == true' \
          "$work/apr-publish-host-merge-squash.json" >/dev/null
        run_clean ${self}/bin/apr branch switch stable \
          --registry host-merge-review > "$work/apr-branch-switch-host-merge-stable-before-squash.out" 2>&1
        merge_before_squash=$(git -C "$merge_reg" rev-parse HEAD)
        run_clean ${self}/bin/apr --json merge feature/hostmerge-squash \
          --squash \
          --registry host-merge-review > "$work/apr-merge-host-merge-squash.json"
        ${pkgs.jq}/bin/jq -e \
          --arg before "$merge_before_squash" \
          '.action == "merge"
            and .branch == "feature/hostmerge-squash"
            and .no_ff == false
            and .squash == true
            and .current == "stable"
            and .head == $before
            and (.output | contains("Squash commit"))
            and (.branches | any(.name == "stable" and .current == true))' \
          "$work/apr-merge-host-merge-squash.json" >/dev/null
        run_clean ${self}/bin/apr --json status \
          --registry host-merge-review > "$work/apr-status-host-merge-squash.json"
        ${pkgs.jq}/bin/jq -e \
          '.clean == false
            and (.entries | any(.index == "A" and .path == "packages/h/hostmergebulk.toml"))' \
          "$work/apr-status-host-merge-squash.json" >/dev/null
        git -C "$merge_reg" commit -m "merge: squash hostmergebulk feature" \
          > "$work/git-commit-host-merge-squash.out" 2>&1
        run_clean ${self}/bin/apr --json show hostmergebulk \
          --registry host-merge-review > "$work/apr-show-host-merge-squash.json"
        ${pkgs.jq}/bin/jq -e \
          '.package.name == "hostmergebulk"
            and .versions[0].version == "1.0.0"
            and .versions[0].platforms."x86_64-linux".closure_size > 1000000' \
          "$work/apr-show-host-merge-squash.json" >/dev/null

        run_clean ${self}/bin/apr branch create feature/hostmerge-conflict \
          --registry host-merge-review > "$work/apr-branch-create-host-merge-conflict.out" 2>&1
        run_clean ${self}/bin/apr branch switch feature/hostmerge-conflict \
          --registry host-merge-review > "$work/apr-branch-switch-host-merge-conflict.out" 2>&1
        run_clean ${self}/bin/apr --json publish "$install_store" \
          --name hostmergeleaf \
          --version 1.0.0 \
          --description "Feature-side conflicting host merge fixture" \
          --license MIT \
          --maintainer merge-reviewer@example.invalid \
          --registry host-merge-review \
          --message "feature: update conflicting hostmergeleaf" \
          > "$work/apr-publish-host-merge-conflict-feature.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_store" \
          '.action == "publish"
            and .registry == "host-merge-review"
            and .package == "hostmergeleaf"
            and .version == "1.0.0"
            and .store_path == $store
            and .committed == true' \
          "$work/apr-publish-host-merge-conflict-feature.json" >/dev/null
        run_clean ${self}/bin/apr branch switch stable \
          --registry host-merge-review > "$work/apr-branch-switch-host-merge-stable-before-conflict.out" 2>&1
        run_clean ${self}/bin/apr --json publish "$bulk_store" \
          --name hostmergeleaf \
          --version 1.0.0 \
          --description "Stable-side conflicting host merge fixture" \
          --license MIT \
          --maintainer merge-reviewer@example.invalid \
          --registry host-merge-review \
          --message "stable: update conflicting hostmergeleaf" \
          > "$work/apr-publish-host-merge-conflict-stable.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$bulk_store" \
          '.action == "publish"
            and .registry == "host-merge-review"
            and .package == "hostmergeleaf"
            and .version == "1.0.0"
            and .store_path == $store
            and (.nar_size > 1000000)
            and .committed == true' \
          "$work/apr-publish-host-merge-conflict-stable.json" >/dev/null
        merge_before_conflict=$(git -C "$merge_reg" rev-parse HEAD)
        if run_clean ${self}/bin/apr --json merge feature/hostmerge-conflict \
          --registry host-merge-review > "$work/apr-merge-host-merge-conflict.out" 2>&1; then
          cat "$work/apr-merge-host-merge-conflict.out"
          exit 1
        fi
        grep -q "git merge -- feature/hostmerge-conflict failed" \
          "$work/apr-merge-host-merge-conflict.out"
        grep -q "merge has conflicts" "$work/apr-merge-host-merge-conflict.out"
        test "$(git -C "$merge_reg" rev-parse HEAD)" = "$merge_before_conflict"
        # libgit2 performs the merge in-process and refuses a conflicting merge
        # cleanly: HEAD is unchanged and no half-merged index/worktree is left
        # behind (unlike the git CLI, which would leave UU conflict markers and a
        # MERGE_HEAD to `git merge --abort`). The repository stays recoverable
        # without any cleanup.
        git -C "$merge_reg" status --porcelain \
          > "$work/git-status-host-merge-conflict.out"
        test ! -s "$work/git-status-host-merge-conflict.out"
        test ! -e "$merge_reg/.git/MERGE_HEAD"
        run_clean ${self}/bin/apr --json status \
          --registry host-merge-review > "$work/apr-status-host-merge-after-conflict-abort.json"
        ${pkgs.jq}/bin/jq -e \
          '.clean == true and .entries == []' \
          "$work/apr-status-host-merge-after-conflict-abort.json" >/dev/null

        run_clean ${self}/bin/apr --json packages \
          --registry host-merge-review > "$work/apr-packages-host-merge-review.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 3
            and any(.[]; .name == "hostmergeleaf" and .version == "1.0.0")
            and any(.[]; .name == "hostmergeapp" and .version == "1.0.0")
            and any(.[]; .name == "hostmergebulk" and .version == "1.0.0")' \
          "$work/apr-packages-host-merge-review.json" >/dev/null
        assert_no_profile

        run_clean ${self}/bin/apr create host-direct-release \
          > "$work/apr-create-host-direct-release.out" 2>&1
        direct_reg="$data/apm/registries/host-direct-release"
        direct_release_url="http://127.0.0.1:$install_cache_port/direct-release"
        run_clean ${self}/bin/apr --json release 1.0.0 \
          --registry host-direct-release \
          --store-path "$install_store" \
          --name hostdirect \
          --description "Host direct release fixture" \
          --license MIT \
          --maintainer host@example.invalid \
          --key "$work/host-install-release-key" \
          --cache-key "$work/host-install-cache-signing-key" \
          --cache-url "$direct_release_url" \
          --cache-priority 66 \
          --upload-url "file://$work/install-static-cache-upload/direct-release" \
          > "$work/apr-release-host-direct.json"
        ${pkgs.jq}/bin/jq -e \
          --arg cache_url "$direct_release_url" \
          --arg upload_url "file://$work/install-static-cache-upload/direct-release" \
          '.action == "release"
            and .status == "released"
            and .registry == "host-direct-release"
            and .version == "1.0.0"
            and .dry_run == false
            and .cache_url == $cache_url
            and .cache_priority == 66
            and .cache_pointer_updated == true
            and .upload_urls == [$upload_url]
            and (.cache.paths >= 2)
            and (.cache.narinfos >= 2)
            and (.cache.nars >= 2)
            and (.full_pack | startswith("pack-") and endswith(".pack"))
            and .deltas == []
            and (.uploaded_files > 0)
            and (.uploaded_bytes > 0)' \
          "$work/apr-release-host-direct.json" >/dev/null
        test -f "$direct_reg/packages/h/hostdirect.toml"
        grep -q "$direct_release_url" "$direct_reg/registry.toml"
        git -C "$direct_reg" rev-parse --verify '1.0.0^{tag}' \
          > "$work/apr-release-host-direct-tag.out"
        git -C "$direct_reg" cat-file -p 1.0.0 \
          > "$work/apr-release-host-direct-tag-object.out"
        grep -q "BEGIN SSH SIGNATURE" \
          "$work/apr-release-host-direct-tag-object.out"
        test -f "$work/install-static-cache-upload/direct-release/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-upload/direct-release/$install_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/direct-release/$install_leaf_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/direct-release/$install_hash.narinfo"
        test -f "$work/install-static-cache-upload/direct-release/HEAD"
        test -f "$work/install-static-cache-upload/direct-release/info/refs"
        test -f "$work/install-static-cache-upload/direct-release/releases/1/0/0/objects/info/packs"
        test -f "$work/install-static-cache-upload/direct-release/nix-cache-info"
        test -f "$work/install-static-cache-upload/direct-release/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-upload/direct-release/$install_hash.narinfo"
        find "$work/install-static-cache-upload/direct-release/releases/1/0/0/objects/pack" \
          -name 'pack-*.pack' | grep -q .

        keyadd_public_key=$(${pkgs.coreutils}/bin/cut -d ' ' -f2 < "$work/host-install-release-key.pub")
        keyadd_initial_trust_key="host-keyadd:Ed25519:$keyadd_public_key"
        run_clean ${self}/bin/apr create host-keyadd \
          --trust-key "$keyadd_initial_trust_key" \
          --trust-key-id initial \
          --key "$work/host-install-release-key" \
          > "$work/apr-create-host-keyadd.out" 2>&1
        keyadd_reg="$data/apm/registries/host-keyadd"
        run_clean ${self}/bin/apm --json registry add --no-verify "file://$keyadd_reg" \
          --name host-keyadd \
          --no-clone > "$work/apm-add-host-keyadd-config.json"
        ${pkgs.jq}/bin/jq -e \
          --arg url "file://$keyadd_reg" \
          --arg config_path "$config/apm/registries.d/host-keyadd.toml" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-keyadd"
            and .name == "host-keyadd"
            and .url == $url
            and .priority == 500
            and .enabled == true
            and .tracking == "default"
            and .clone == false
            and .synced == false
            and .config == $config_path
            and .signing_required == false
            and .verification_disabled == true
            and .trusted_key_pinned == false' \
          "$work/apm-add-host-keyadd-config.json" >/dev/null
        ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" \
          -f "$work/host-keyadd-external-key"
        cat > "$host_bin/emit-host-keyadd-key" << EOF
        #!${pkgs.runtimeShell}
        exec ${pkgs.coreutils}/bin/cat "$work/host-keyadd-external-key"
        EOF
        chmod +x "$host_bin/emit-host-keyadd-key"
        run_clean ${self}/bin/apr --json keys register external \
          --registry host-keyadd \
          --key-command "emit-host-keyadd-key" \
          > "$work/apr-keys-register-external.json"
        host_keyadd_external=$(${pkgs.jq}/bin/jq -r '.public_key' \
          "$work/apr-keys-register-external.json")
        ${pkgs.jq}/bin/jq -e \
          --arg key "$host_keyadd_external" \
          --arg config_path "$config/apm/registries.d/host-keyadd.toml" \
          '.action == "keys_register"
            and .status == "registered"
            and .registry == "host-keyadd"
            and .id == "external"
            and .source == "command"
            and .configured == true
            and .config == $config_path
            and .public_key == $key
            and (.fingerprint | length > 0)' \
          "$work/apr-keys-register-external.json" >/dev/null
        grep -q '"external" = { command = "' \
          "$config/apm/registries.d/host-keyadd.toml"
        grep -q 'command = "emit-host-keyadd-key"' \
          "$config/apm/registries.d/host-keyadd.toml"
        run_clean ${self}/bin/apr --json keys add external "$host_keyadd_external" \
          --registry host-keyadd \
          --key "$work/host-install-release-key" \
          > "$work/apr-keys-add-external.json"
        ${pkgs.jq}/bin/jq -e \
          --arg key "$host_keyadd_external" \
          '.action == "keys_add"
            and .status == "added"
            and .registry == "host-keyadd"
            and .id == "external"
            and .key == $key
            and .committed == true' \
          "$work/apr-keys-add-external.json" >/dev/null
        run_clean ${self}/bin/apr --json keys list --registry host-keyadd \
          > "$work/apr-keys-list-host-keyadd-external.json"
        ${pkgs.jq}/bin/jq -e \
          --arg initial "$keyadd_initial_trust_key" \
          --arg external "$host_keyadd_external" \
          '.registry == "host-keyadd"
            and (.active | any(.id == "initial" and .key == $initial))
            and (.active | any(.id == "external" and .key == $external))
            and .revoked == []' \
          "$work/apr-keys-list-host-keyadd-external.json" >/dev/null
        run_clean ${self}/bin/apr --json release 0.1.0 \
          --registry host-keyadd \
          --store-path "$install_leaf_store" \
          --name hostexternal \
          --description "Host external key-command release fixture" \
          --license MIT \
          --maintainer host@example.invalid \
          --key-id external \
          > "$work/apr-release-host-keyadd-external.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "release"
            and .status == "released"
            and .registry == "host-keyadd"
            and .version == "0.1.0"
            and .dry_run == false
            and .cache == null
            and .cache_pointer_updated == false
            and .uploaded_files == null
            and (.full_pack | startswith("pack-") and endswith(".pack"))' \
          "$work/apr-release-host-keyadd-external.json" >/dev/null
        test -f "$keyadd_reg/packages/h/hostexternal.toml"
        git -C "$keyadd_reg" rev-parse --verify '0.1.0^{tag}' \
          > "$work/apr-release-host-keyadd-external-tag.out"
        git -C "$keyadd_reg" cat-file -p 0.1.0 \
          > "$work/apr-release-host-keyadd-external-tag-object.out"
        grep -q "BEGIN SSH SIGNATURE" \
          "$work/apr-release-host-keyadd-external-tag-object.out"
        run_clean ${self}/bin/apr --json keys generate next \
          --registry host-keyadd \
          --add \
          --key "$work/host-install-release-key" \
          > "$work/apr-keys-generate-add-next.json"
        host_keyadd_next=$(${pkgs.jq}/bin/jq -r '.public_key' \
          "$work/apr-keys-generate-add-next.json")
        host_keyadd_next_path="$config/apm/keys/host-keyadd-next.key"
        ${pkgs.jq}/bin/jq -e \
          --arg key "$host_keyadd_next" \
          --arg key_path "$host_keyadd_next_path" \
          --arg config_path "$config/apm/registries.d/host-keyadd.toml" \
          '.action == "keys_generate"
            and .status == "generated"
            and .registry == "host-keyadd"
            and .id == "next"
            and .private_key == $key_path
            and .public_key == $key
            and .configured == true
            and .config == $config_path
            and .added == true
            and .committed == true
            and (.fingerprint | length > 0)' \
          "$work/apr-keys-generate-add-next.json" >/dev/null
        test -f "$host_keyadd_next_path"
        grep -q "$host_keyadd_next" "$keyadd_reg/keys.toml"
        grep -q 'id = "next"' "$keyadd_reg/keys.toml"
        grep -q '"next" = "' "$config/apm/registries.d/host-keyadd.toml"
        git -C "$keyadd_reg" log --oneline -1 \
          > "$work/git-log-host-keyadd-next.out"
        grep -q "registry: add signing key next" \
          "$work/git-log-host-keyadd-next.out"
        run_clean ${self}/bin/apr --json keys list --registry host-keyadd \
          > "$work/apr-keys-list-host-keyadd.json"
        ${pkgs.jq}/bin/jq -e \
          --arg initial "$keyadd_initial_trust_key" \
          --arg next "$host_keyadd_next" \
          '.registry == "host-keyadd"
            and (.active | any(.id == "initial" and .key == $initial))
            and (.active | any(.id == "next" and .key == $next))
            and .revoked == []' \
          "$work/apr-keys-list-host-keyadd.json" >/dev/null
        run_clean ${self}/bin/apr --json release 1.0.0 \
          --registry host-keyadd \
          --store-path "$install_leaf_store" \
          --name hostkeyed \
          --description "Host generated key-id release fixture" \
          --license MIT \
          --maintainer host@example.invalid \
          --key-id next \
          > "$work/apr-release-host-keyadd.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "release"
            and .status == "released"
            and .registry == "host-keyadd"
            and .version == "1.0.0"
            and .dry_run == false
            and .cache == null
            and .cache_pointer_updated == false
            and .uploaded_files == null
            and (.full_pack | startswith("pack-") and endswith(".pack"))' \
          "$work/apr-release-host-keyadd.json" >/dev/null
        test -f "$keyadd_reg/packages/h/hostkeyed.toml"
        git -C "$keyadd_reg" rev-parse --verify '1.0.0^{tag}' \
          > "$work/apr-release-host-keyadd-tag.out"
        git -C "$keyadd_reg" cat-file -p 1.0.0 \
          > "$work/apr-release-host-keyadd-tag-object.out"
        grep -q "BEGIN SSH SIGNATURE" \
          "$work/apr-release-host-keyadd-tag-object.out"
        run_clean ${self}/bin/apr --json keys retire next \
          --registry host-keyadd \
          --vouched-by initial \
          --reason "manual rotation" \
          --key "$work/host-install-release-key" \
          --no-resign > "$work/apr-keys-retire-next-no-resign.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "keys_retire"
            and .status == "retired"
            and .registry == "host-keyadd"
            and .id == "next"
            and .reason == "manual rotation"
            and .vouched_by == "initial"
            and .committed == true
            and .resigned == false
            and (.resign_plan.release_tags | index("1.0.0") != null)
            and (.resign_plan.release_tags | index("0.1.0") == null)
            and .resign_plan.channel_partitions == []' \
          "$work/apr-keys-retire-next-no-resign.json" >/dev/null
        git -C "$keyadd_reg" log --oneline -1 \
          > "$work/git-log-host-keyadd-retire-next.out"
        grep -q "registry: retire signing key next" \
          "$work/git-log-host-keyadd-retire-next.out"
        run_clean ${self}/bin/apr --json keys list --registry host-keyadd \
          > "$work/apr-keys-list-host-keyadd-retired.json"
        ${pkgs.jq}/bin/jq -e \
          --arg initial "$keyadd_initial_trust_key" \
          '.registry == "host-keyadd"
            and (.active | any(.id == "initial" and .key == $initial))
            and (.active | all(.id != "next"))
            and (.revoked | any(.id == "next"
              and .reason == "manual rotation"))' \
          "$work/apr-keys-list-host-keyadd-retired.json" >/dev/null

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

        system_provisioned_config="$work/system-provisioned-etc-apm"
        mkdir -p "$system_provisioned_config/registries.d"
        cat > "$system_provisioned_config/registries.d/host-install-channel.toml" << EOF
        [registry]
        name = "host-install-channel"
        url = "file://$install_origin"
        priority = 650
        enabled = true
        branch = "stable"

        [registry.signing]
        required = true
        public_key = "$install_channel_trust_key"
        EOF
        home="$work/system-provisioned-home"
        config="$work/system-provisioned-config"
        data="$work/system-provisioned-share"
        cache="$work/system-provisioned-cache"
        profile_root="$work/system-provisioned-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${pkgs.coreutils}/bin/env \
          APM_SYSTEM_CONFIG_DIR="$system_provisioned_config" \
          ${self}/bin/apm --json registry list \
          > "$work/apm-system-provisioned-registry-list-before-update.json"
        ${pkgs.jq}/bin/jq -e \
          --arg url "file://$install_origin" \
          'length == 1
            and .[0].name == "host-install-channel"
            and .[0].url == $url
            and .[0].priority == 650
            and .[0].tracking == "branch:stable"
            and .[0].packages == 0
            and .[0].last_commit == null
            and .[0].signing_required == true' \
          "$work/apm-system-provisioned-registry-list-before-update.json" >/dev/null
        test ! -e "$config/apm/registries.d/host-install-channel.toml"
        run_clean ${pkgs.coreutils}/bin/env \
          APM_SYSTEM_CONFIG_DIR="$system_provisioned_config" \
          ${self}/bin/apm --json update --registry host-install-channel \
          > "$work/apm-system-provisioned-update.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$install_remote_v1_commit" \
          '.action == "update"
            and .registry == "host-install-channel"
            and .updated == 1
            and .registries[0].registry == "host-install-channel"
            and .registries[0].status == "updated"
            and .registries[0].tracking == "branch:stable"
            and .registries[0].commit == $head
            and .registries[0].packages >= 3
            and .registries[0].added >= 3
            and .registries[0].updated == 0
            and .registries[0].removed == 0' \
          "$work/apm-system-provisioned-update.json" >/dev/null
        # A user-scope `apm update` reads the registry from the immutable /etc
        # seed (APM_SYSTEM_CONFIG_DIR) but records sync state as a delta in the
        # user writable layer (XDG config). The seed is never mutated.
        system_provisioned_state_config="$config/apm/registries.d/host-install-channel.toml"
        grep -q "last_commit = \"$install_remote_v1_commit\"" \
          "$system_provisioned_state_config"
        grep -q "last_update = \"" \
          "$system_provisioned_state_config"
        if grep -q "last_commit = " \
          "$system_provisioned_config/registries.d/host-install-channel.toml"; then
          cat "$system_provisioned_config/registries.d/host-install-channel.toml"
          exit 1
        fi
        grep -q "$install_channel_trust_key" \
          "$config/apm/trusted-keys.d/host-install-channel.pub"
        run_clean ${pkgs.coreutils}/bin/env \
          APM_SYSTEM_CONFIG_DIR="$system_provisioned_config" \
          ${self}/bin/apm search hostinstall \
          --registry host-install-channel \
          > "$work/apm-system-provisioned-search.out" 2>&1
        grep -q "hostinstall/host-install-channel 1.0.0" \
          "$work/apm-system-provisioned-search.out"
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-system-provisioned-install-before-delete.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_store" \
            > "$work/nix-delete-system-provisioned-install-before-download.out" 2>&1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-system-provisioned-leaf-before-delete.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_leaf_store" \
            > "$work/nix-delete-system-provisioned-leaf-before-download.out" 2>&1
        fi
        run_clean ${pkgs.coreutils}/bin/env \
          APM_SYSTEM_CONFIG_DIR="$system_provisioned_config" \
          ${self}/bin/apm --json install hostinstall \
          --registry host-install-channel \
          --yes > "$work/apm-system-provisioned-install.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_store" \
          --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-channel"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-system-provisioned-install.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/system-provisioned-host-install-run.out"
        grep -q "host leaf package executed" \
          "$work/system-provisioned-host-install-run.out"
        grep -q "host install package executed" \
          "$work/system-provisioned-host-install-run.out"
        run_clean ${pkgs.coreutils}/bin/env \
          APM_SYSTEM_CONFIG_DIR="$system_provisioned_config" \
          ${self}/bin/apm --json registry list \
          > "$work/apm-system-provisioned-registry-list-after-install.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$install_remote_v1_commit" \
          'length == 1
            and .[0].name == "host-install-channel"
            and .[0].packages >= 3
            and .[0].tracking == "branch:stable"
            and .[0].signing_required == true
            and .[0].last_commit == $head' \
          "$work/apm-system-provisioned-registry-list-after-install.json" >/dev/null
        grep -q '\[registry.state\]' \
          "$system_provisioned_state_config"
        grep -q "last_commit = \"$install_remote_v1_commit\"" \
          "$system_provisioned_state_config"
        # A registry defined by an immutable /etc seed cannot be removed through
        # apm; the mutation is refused with a clear error. The supported way to
        # retract it is to blank the seed fragment (a provisioning operation).
        if run_clean ${pkgs.coreutils}/bin/env \
          APM_SYSTEM_CONFIG_DIR="$system_provisioned_config" \
          ${self}/bin/apm --json registry remove host-install-channel \
          > "$work/apm-system-provisioned-registry-remove.out" 2>&1; then
          cat "$work/apm-system-provisioned-registry-remove.out"
          exit 1
        fi
        grep -q "read-only seed" \
          "$work/apm-system-provisioned-registry-remove.out"
        # The seed-backed registry stays configured until the seed is blanked.
        run_clean ${pkgs.coreutils}/bin/env \
          APM_SYSTEM_CONFIG_DIR="$system_provisioned_config" \
          ${self}/bin/apm --json registry list \
          > "$work/apm-system-provisioned-registry-list-before-blank.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1 and .[0].name == "host-install-channel"' \
          "$work/apm-system-provisioned-registry-list-before-blank.json" >/dev/null
        # Blank the seed fragment to retract the registry; runtime deltas in the
        # writable layer fall away once the seed no longer declares a `[registry]`.
        : > "$system_provisioned_config/registries.d/host-install-channel.toml"
        run_clean ${pkgs.coreutils}/bin/env \
          APM_SYSTEM_CONFIG_DIR="$system_provisioned_config" \
          ${self}/bin/apm --json registry list \
          > "$work/apm-system-provisioned-registry-list-after-remove.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apm-system-provisioned-registry-list-after-remove.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/system-provisioned-host-install-after-registry-remove.out"
        grep -q "host leaf package executed" \
          "$work/system-provisioned-host-install-after-registry-remove.out"
        grep -q "host install package executed" \
          "$work/system-provisioned-host-install-after-registry-remove.out"
        run_clean ${pkgs.coreutils}/bin/env \
          APM_SYSTEM_CONFIG_DIR="$system_provisioned_config" \
          ${self}/bin/apm --json orphans \
          > "$work/apm-system-provisioned-orphans-after-registry-remove.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and any(.[]; .name == "hostinstall"
              and .version == "1.0.0"
              and .registry == "host-install-channel"
              and .explicit == true)
            and any(.[]; .name == "hostleaf"
              and .version == "1.0.0"
              and .registry == "host-install-channel"
              and .explicit == false)' \
          "$work/apm-system-provisioned-orphans-after-registry-remove.json" >/dev/null
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$main_home"
        config="$main_config"
        data="$main_data"
        cache="$main_cache"
        profile_root="$main_profile_root"
        profile="$main_profile"

        image_channel_trust_key="host-image-channel:Ed25519:$install_release_public_key"
        image_cache_url="http://127.0.0.1:$install_cache_port/image-cache"
        image_upload_url="file://$work/install-static-cache-upload/image-cache"
        run_clean ${self}/bin/apr create host-image-channel \
          --trust-key "$image_channel_trust_key" \
          --trust-key-id channel \
          --key "$work/host-install-release-key" \
          > "$work/apr-create-host-image-channel.out" 2>&1
        image_reg="$data/apm/registries/host-image-channel"
        git -C "$image_reg" config user.name "Host Command Test"
        git -C "$image_reg" config user.email "host-command@example.invalid"
        run_clean ${self}/bin/apr --json publish "$sysroot_store" \
          --name hostsysroot \
          --version 1.0.0 \
          --description "Host sysroot image fixture" \
          --license MIT \
          --maintainer host@example.invalid \
          --sysroot \
          --image "$sysroot_image_store" \
          --image-format qcow2 \
          --registry host-image-channel \
          --no-commit > "$work/apr-publish-host-sysroot-image.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$sysroot_store" \
          --arg source "$sysroot_drv" \
          --arg image "$sysroot_image_store" \
          '.action == "publish"
            and .registry == "host-image-channel"
            and .package == "hostsysroot"
            and .version == "1.0.0"
            and .platform == "x86_64-linux"
            and .store_path == $store
            and .source.store_path == $source
            and .sysroot == true
            and (.images | length == 1)
            and .images[0].format == "qcow2"
            and .images[0].store_path == $image
            and (.images[0].nar_hash | startswith("sha256-"))
            and (.images[0].nar_size > 0)
            and .package_file == "packages/h/hostsysroot.toml"
            and .committed == false' \
          "$work/apr-publish-host-sysroot-image.json" >/dev/null
        grep -q '\[\[versions.platforms.x86_64-linux.images\]\]' \
          "$image_reg/packages/h/hostsysroot.toml"
        run_clean ${self}/bin/apr --json cache generate \
          --registry host-image-channel \
          --output "$work/image-static-cache-output/cache" \
          --key "$work/host-install-cache-signing-key" \
          --cache-url "$image_cache_url" \
          --upload-url "$image_upload_url" \
          --priority 71 \
          --no-commit > "$work/apr-cache-host-image-channel.json"
        ${pkgs.jq}/bin/jq -e \
          --arg output "$work/image-static-cache-output/cache" \
          --arg cache_url "$image_cache_url" \
          --arg upload_url "$image_upload_url" \
          '.action == "cache_generate"
            and .registry == "host-image-channel"
            and .output_dir == $output
            and .paths >= 2
            and .narinfos >= 2
            and .nars >= 2
            and .cache_url == $cache_url
            and .priority == 71
            and .upload_urls == [$upload_url]
            and .uploaded == true
            and .cache_pointer_updated == true
            and .committed == false' \
          "$work/apr-cache-host-image-channel.json" >/dev/null
        test -f "$work/install-static-cache-upload/image-cache/$sysroot_hash.narinfo"
        test -f "$work/install-static-cache-upload/image-cache/$sysroot_image_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/image-cache/$sysroot_image_hash.narinfo"
        git -C "$image_reg" add -A
        git -C "$image_reg" \
          -c gpg.format=ssh \
          -c gpg.ssh.program=${pkgs.openssh}/bin/ssh-keygen \
          -c user.signingkey="$work/host-install-release-key" \
          commit -S -m "release: hostsysroot 1.0.0 image" \
          > "$work/git-commit-host-image-channel.out" 2>&1
        run_clean ${self}/bin/apr --json release 1.0.0 \
          --registry host-image-channel \
          --key "$work/host-install-release-key" \
          --cache-key "$work/host-install-cache-signing-key" \
          --cache-url "$image_cache_url" \
          --cache-priority 71 \
          --upload-url "$image_upload_url" \
          --channel stable \
          --init-channel > "$work/apr-release-host-image-channel.json"
        ${pkgs.jq}/bin/jq -e \
          --arg cache_url "$image_cache_url" \
          --arg upload_url "$image_upload_url" \
          '.action == "release"
            and .status == "released"
            and .registry == "host-image-channel"
            and .version == "1.0.0"
            and .cache_url == $cache_url
            and .cache_priority == 71
            and .upload_urls == [$upload_url]
            and .channel.name == "stable"
            and .channel.action == "init"
            and .channel.touched_partitions == 256
            and (.cache.paths >= 2)
            and (.cache.remote_skipped >= 2)
            and (.uploaded_files > 0)
            and (.uploaded_bytes > 0)' \
          "$work/apr-release-host-image-channel.json" >/dev/null
        test -f "$work/install-static-cache-upload/image-cache/channels/stable/00"
        test -f "$work/install-static-cache-upload/image-cache/$sysroot_image_hash.narinfo"

        if nix_store --check-validity "$sysroot_image_store" \
          > "$work/nix-valid-host-sysroot-image-before-delete.out" 2>&1; then
          nix_store --delete --ignore-liveness "$sysroot_image_store" \
            > "$work/nix-delete-host-sysroot-image-before-download.out" 2>&1
        fi
        if nix_store --check-validity "$sysroot_image_store" \
          > "$work/nix-valid-host-sysroot-image-after-delete.out" 2>&1; then
          cat "$work/nix-valid-host-sysroot-image-after-delete.out"
          exit 1
        fi
        home="$work/image-client-home"
        config="$work/image-client-config"
        data="$work/image-client-share"
        cache="$work/image-client-cache"
        profile_root="$work/image-client-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add "$image_cache_url" \
          --name host-image-channel \
          --channel stable \
          --trust-key "$image_channel_trust_key" \
          > "$work/apm-add-host-image-channel.out" 2>&1
        grep -q "Registry 'host-image-channel' added" \
          "$work/apm-add-host-image-channel.out"
        run_clean ${self}/bin/apm search hostsysroot \
          --registry host-image-channel \
          > "$work/apm-search-host-image-channel.out" 2>&1
        grep -q "hostsysroot/host-image-channel 1.0.0" \
          "$work/apm-search-host-image-channel.out"
        run_clean ${self}/bin/apm --json install hostsysroot \
          --registry host-image-channel \
          --image qcow2 \
          --output "$work/hostsysroot-dry-run.qcow2" \
          --dry-run > "$work/apm-install-host-sysroot-image-dry-run.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$sysroot_image_store" \
          --arg output "$work/hostsysroot-dry-run.qcow2" \
          '.action == "image_download"
            and .status == "planned"
            and .package == "hostsysroot"
            and .version == "1.0.0"
            and .format == "qcow2"
            and .store_path == $store
            and .output == $output
            and .dry_run == true
            and .downloads.planned == 1
            and .downloads.downloaded == 0
            and .downloads.imported == 0' \
          "$work/apm-install-host-sysroot-image-dry-run.json" >/dev/null
        test ! -e "$work/hostsysroot-dry-run.qcow2"
        if nix_store --check-validity "$sysroot_image_store" \
          > "$work/nix-valid-host-sysroot-image-after-dry-run.out" 2>&1; then
          cat "$work/nix-valid-host-sysroot-image-after-dry-run.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json install hostsysroot \
          --registry host-image-channel \
          --image qcow2 \
          --output "$work/hostsysroot-downloaded.qcow2" \
          --yes > "$work/apm-install-host-sysroot-image.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$sysroot_image_store" \
          --arg output "$work/hostsysroot-downloaded.qcow2" \
          '.action == "image_download"
            and .status == "downloaded"
            and .package == "hostsysroot"
            and .version == "1.0.0"
            and .format == "qcow2"
            and .store_path == $store
            and .output == $output
            and .dry_run == false
            and .downloads.planned == 1
            and .downloads.downloaded == 1
            and .downloads.imported == 1' \
          "$work/apm-install-host-sysroot-image.json" >/dev/null
        grep -q "host sysroot image qcow2 fixture" \
          "$work/hostsysroot-downloaded.qcow2"
        grep -q "boot-marker=hostsysroot" \
          "$work/hostsysroot-downloaded.qcow2"
        nix_store --check-validity "$sysroot_image_store" \
          > "$work/nix-valid-host-sysroot-image-imported.out" 2>&1
        assert_default_profile_absent
        assert_no_profile
        rm -rf "$profile_root"
        home="$main_home"
        config="$main_config"
        data="$main_data"
        cache="$main_cache"
        profile_root="$main_profile_root"
        profile="$main_profile"

        home="$work/direct-home"
        config="$work/direct-config"
        data="$work/direct-share"
        cache="$work/direct-cache"
        profile_root="$work/direct-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add --no-verify "$direct_release_url" \
          --name host-direct-release \
          --tag 1.0.0 > "$work/apm-add-host-direct-release.out" 2>&1
        grep -q "Registry 'host-direct-release' added" \
          "$work/apm-add-host-direct-release.out"
        grep -q 'tag = "1.0.0"' \
          "$config/apm/registries.d/host-direct-release.toml"
        run_clean ${self}/bin/apm search hostdirect \
          --registry host-direct-release \
          > "$work/apm-search-host-direct-release.out" 2>&1
        grep -q "hostdirect/host-direct-release 1.0.0" \
          "$work/apm-search-host-direct-release.out"
        nix_store --delete --ignore-liveness "$install_store" \
          > "$work/nix-delete-host-direct-install.out" 2>&1
        nix_store --delete --ignore-liveness "$install_leaf_store" \
          > "$work/nix-delete-host-direct-leaf.out" 2>&1
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-direct-install-deleted.out" 2>&1; then
          cat "$work/nix-valid-host-direct-install-deleted.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-direct-leaf-deleted.out" 2>&1; then
          cat "$work/nix-valid-host-direct-leaf-deleted.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json install hostdirect \
          --registry host-direct-release \
          --yes > "$work/apm-install-host-direct-release.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostdirect"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostdirect"
            and .roots[0].registry == "host-direct-release"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostdirect" and .store_path == $store and .explicit == true))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-host-direct-release.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-direct-release-run.out"
        grep -q "host leaf package executed" "$work/host-direct-release-run.out"
        grep -q "host install package executed" "$work/host-direct-release-run.out"
        assert_default_profile_absent
        rm -rf "$profile_root"
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
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "install"
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
            and (.downloads.imported >= 2)
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
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
        home="$work/bulk-home"
        config="$work/bulk-config"
        data="$work/bulk-share"
        cache="$work/bulk-cache"
        profile_root="$work/bulk-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add "http://127.0.0.1:$install_cache_port/cache" \
          --name host-install-channel \
          --channel stable \
          --trust-key "$install_channel_trust_key" \
          > "$work/apm-add-host-bulk-channel.out" 2>&1
        grep -q "Registry 'host-install-channel' added" \
          "$work/apm-add-host-bulk-channel.out"
        run_clean ${self}/bin/apm search hostbulk \
          --registry host-install-channel \
          > "$work/apm-search-host-bulk-channel.out" 2>&1
        grep -q "hostbulk/host-install-channel 1.0.0" \
          "$work/apm-search-host-bulk-channel.out"
        nix_store --delete --ignore-liveness "$bulk_store" \
          > "$work/nix-delete-host-bulk-channel.out" 2>&1
        if nix_store --check-validity "$bulk_store" \
          > "$work/nix-valid-host-bulk-channel-deleted.out" 2>&1; then
          cat "$work/nix-valid-host-bulk-channel-deleted.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json install hostbulk \
          --registry host-install-channel \
          --yes > "$work/apm-install-host-bulk-channel.json"
        ${pkgs.jq}/bin/jq -e --arg store "$bulk_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostbulk"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostbulk"
            and .roots[0].registry == "host-install-channel"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostbulk" and .store_path == $store and .explicit == true))
            and (.downloads.planned >= 1)
            and (.downloads.downloaded >= 1)
            and (.downloads.imported >= 1)' \
          "$work/apm-install-host-bulk-channel.json" >/dev/null
        nix_store --check-validity "$bulk_store" \
          > "$work/nix-valid-host-bulk-channel-imported.out" 2>&1
        "$profile/current/bin/host-bulk-verify" \
          > "$work/host-bulk-channel-run.out"
        grep -q "host bulk package verified 48 files" \
          "$work/host-bulk-channel-run.out"
        run_clean ${self}/bin/apm --json show hostbulk \
          --registry host-install-channel > "$work/apm-show-host-bulk-channel.json"
        ${pkgs.jq}/bin/jq -e --arg store "$bulk_store" \
          '.name == "hostbulk"
            and .registry == "host-install-channel"
            and .version == "1.0.0"
            and .installed == true
            and .store_path == $store
            and (.nar_size > 1000000)' \
          "$work/apm-show-host-bulk-channel.json" >/dev/null
        run_clean ${self}/bin/apm --json files hostbulk \
          > "$work/apm-files-host-bulk-channel.json"
        ${pkgs.jq}/bin/jq -e \
          'index("bin/host-bulk-verify") != null
            and index("share/host-bulk/data/chunk-01.txt") != null
            and index("share/host-bulk/data/chunk-48.txt") != null' \
          "$work/apm-files-host-bulk-channel.json" >/dev/null
        run_clean ${self}/bin/apm --json verify hostbulk \
          > "$work/apm-verify-host-bulk-channel.json"
        ${pkgs.jq}/bin/jq -e --arg store "$bulk_store" \
          '.package == "hostbulk"
            and .registry == "host-install-channel"
            and .version == "1.0.0"
            and .store_path == $store
            and .verified == true
            and (.expected_nar_hash | startswith("sha256:"))
            and (.actual_nar_hash | startswith("sha256:"))' \
          "$work/apm-verify-host-bulk-channel.json" >/dev/null
        assert_default_profile_absent
        rm -rf "$profile_root"
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

        run_clean ${self}/bin/apm --json source hostinstall --show-drv \
          > "$work/apm-source-host-install-preinstall.json"
        ${pkgs.jq}/bin/jq -e \
          --arg source "$install_drv" \
          '.package == "hostinstall"
            and .registry == "host-install-client"
            and .source_drv == $source
            and (.source_nar_hash | startswith("sha256-"))
            and .installed == false
            and .installed_store_path == null' \
          "$work/apm-source-host-install-preinstall.json" >/dev/null
        run_clean ${self}/bin/apm --json source hostinstall --fetch \
          > "$work/apm-source-host-install-fetch.json"
        ${pkgs.jq}/bin/jq -e \
          --arg source "$install_drv" \
          --arg store "$install_store" \
          '.package == "hostinstall"
            and .registry == "host-install-client"
            and .source_drv == $source
            and (.source_nar_hash | startswith("sha256-"))
            and .installed == false
            and .installed_store_path == null
            and .realised_path == $store' \
          "$work/apm-source-host-install-fetch.json" >/dev/null
        nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-source-fetch.out" 2>&1
        nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-source-fetch.out" 2>&1
        "$install_store/bin/host-install-tool" \
          > "$work/host-install-source-fetch-run.out"
        grep -q "host leaf package executed" "$work/host-install-source-fetch-run.out"
        grep -q "host install package executed" "$work/host-install-source-fetch-run.out"
        nix_store --delete --ignore-liveness "$install_store" \
          > "$work/nix-delete-host-install-after-source-fetch.out" 2>&1
        nix_store --delete --ignore-liveness "$install_leaf_store" \
          > "$work/nix-delete-host-leaf-after-source-fetch.out" 2>&1
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-after-source-fetch-delete.out" 2>&1; then
          cat "$work/nix-valid-host-install-after-source-fetch-delete.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-after-source-fetch-delete.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-after-source-fetch-delete.out"
          exit 1
        fi

        promote_home="$home"
        promote_config="$config"
        promote_data="$data"
        promote_cache="$cache"
        promote_profile_root="$profile_root"
        promote_profile="$profile"
        home="$work/promote-home"
        config="$work/promote-config"
        data="$work/promote-share"
        cache="$work/promote-cache"
        profile_root="$work/promote-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
          --name host-install-promote \
          --branch stable > "$work/apm-add-host-install-promote.out" 2>&1
        grep -q "Registry 'host-install-promote' added" \
          "$work/apm-add-host-install-promote.out"
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-promote \
          --yes > "$work/apm-install-host-install-promote-base.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-promote"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-host-install-promote-base.json" >/dev/null
        ${pkgs.jq}/bin/jq -e \
          '.apm.name == "hostleaf" and .apm.explicit == false' \
          "$profile/meta/$install_leaf_hash.json" >/dev/null
        run_clean ${self}/bin/apm --json install hostleaf \
          --registry host-install-promote \
          --yes > "$work/apm-install-host-leaf-promote.json"
        ${pkgs.jq}/bin/jq -e --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostleaf"]
            and .generation == 2
            and (.roots | length == 1)
            and .roots[0].name == "hostleaf"
            and .roots[0].registry == "host-install-promote"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $leaf
            and .roots[0].explicit == true
            and (.closure | length == 1)
            and .closure[0].name == "hostleaf"
            and .closure[0].store_path == $leaf
            and .closure[0].explicit == true
            and .downloads.planned == 0
            and .downloads.downloaded == 0
            and .downloads.imported == 0' \
          "$work/apm-install-host-leaf-promote.json" >/dev/null
        ${pkgs.jq}/bin/jq -e \
          '.apm.name == "hostleaf" and .apm.explicit == true' \
          "$profile/meta/$install_leaf_hash.json" >/dev/null
        run_clean ${self}/bin/apm --json remove hostinstall --autoremove --dry-run \
          > "$work/apm-remove-host-install-promote-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" \
          '.action == "remove"
            and .status == "planned"
            and .requested == ["hostinstall"]
            and .autoremove == true
            and .dry_run == true
            and .generation == null
            and .removed == 1
            and .explicit_removed == 1
            and .orphan_removed == 0
            and (.packages | length == 1)
            and .packages[0].name == "hostinstall"
            and .packages[0].store_path == $store
            and .packages[0].explicit == true
            and .orphans == []' \
          "$work/apm-remove-host-install-promote-dry-run.json" >/dev/null
        run_clean ${self}/bin/apm --json remove hostinstall --autoremove --yes \
          > "$work/apm-remove-host-install-promote.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" \
          '.action == "remove"
            and .status == "removed"
            and .requested == ["hostinstall"]
            and .autoremove == true
            and .dry_run == false
            and .generation == 3
            and .removed == 1
            and .explicit_removed == 1
            and .orphan_removed == 0
            and (.packages | length == 1)
            and .packages[0].name == "hostinstall"
            and .packages[0].store_path == $store
            and .orphans == []' \
          "$work/apm-remove-host-install-promote.json" >/dev/null
        run_clean ${self}/bin/apm --json list --installed \
          --registry host-install-promote > "$work/apm-list-host-leaf-promoted.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostleaf"
            and .[0].registry == "host-install-promote"
            and .[0].version == "1.0.0"
            and .[0].status == "installed"' \
          "$work/apm-list-host-leaf-promoted.json" >/dev/null
        "$profile/current/bin/host-leaf-tool" \
          > "$work/host-leaf-promoted-after-app-remove.out"
        grep -q "host leaf package executed" \
          "$work/host-leaf-promoted-after-app-remove.out"
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$promote_home"
        config="$promote_config"
        data="$promote_data"
        cache="$promote_cache"
        profile_root="$promote_profile_root"
        profile="$promote_profile"
        nix_store --delete --ignore-liveness "$install_store" \
          > "$work/nix-delete-host-install-after-promote.out" 2>&1
        nix_store --delete --ignore-liveness "$install_leaf_store" \
          > "$work/nix-delete-host-leaf-after-promote.out" 2>&1
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-after-promote-delete.out" 2>&1; then
          cat "$work/nix-valid-host-install-after-promote-delete.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-after-promote-delete.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-after-promote-delete.out"
          exit 1
        fi
        assert_no_profile

        multi_root_home="$home"
        multi_root_config="$config"
        multi_root_data="$data"
        multi_root_cache="$cache"
        multi_root_profile_root="$profile_root"
        multi_root_profile="$profile"
        home="$work/multi-root-home"
        config="$work/multi-root-config"
        data="$work/multi-root-share"
        cache="$work/multi-root-cache"
        profile_root="$work/multi-root-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
          --name host-install-multi-root \
          --branch stable > "$work/apm-add-host-install-multi-root.out" 2>&1
        grep -q "Registry 'host-install-multi-root' added" \
          "$work/apm-add-host-install-multi-root.out"
        run_clean ${self}/bin/apm --json install hostinstall hostleaf \
          --registry host-install-multi-root \
          --yes > "$work/apm-install-host-install-multi-root.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall", "hostleaf"]
            and .generation == 1
            and (.roots | length == 2)
            and (.roots | any(.name == "hostinstall"
              and .registry == "host-install-multi-root"
              and .version == "1.0.0"
              and .store_path == $store
              and .explicit == true))
            and (.roots | any(.name == "hostleaf"
              and .registry == "host-install-multi-root"
              and .version == "1.0.0"
              and .store_path == $leaf
              and .explicit == true))
            and (.closure | length == 2)
            and (.closure | any(.name == "hostinstall"
              and .store_path == $store
              and .explicit == true))
            and (.closure | any(.name == "hostleaf"
              and .store_path == $leaf
              and .explicit == true))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-host-install-multi-root.json" >/dev/null
        ${pkgs.jq}/bin/jq -e \
          '.apm.name == "hostleaf" and .apm.explicit == true' \
          "$profile/meta/$install_leaf_hash.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-multi-root-run.out"
        grep -q "host leaf package executed" \
          "$work/host-install-multi-root-run.out"
        grep -q "host install package executed" \
          "$work/host-install-multi-root-run.out"
        "$profile/current/bin/host-leaf-tool" \
          > "$work/host-leaf-multi-root-run.out"
        grep -q "host leaf package executed" \
          "$work/host-leaf-multi-root-run.out"
        run_clean ${self}/bin/apm --json remove hostinstall --autoremove --yes \
          > "$work/apm-remove-host-install-multi-root.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" \
          '.action == "remove"
            and .status == "removed"
            and .requested == ["hostinstall"]
            and .autoremove == true
            and .dry_run == false
            and .generation == 2
            and .removed == 1
            and .explicit_removed == 1
            and .orphan_removed == 0
            and (.packages | length == 1)
            and .packages[0].name == "hostinstall"
            and .packages[0].registry == "host-install-multi-root"
            and .packages[0].store_path == $store
            and .packages[0].explicit == true
            and .orphans == []' \
          "$work/apm-remove-host-install-multi-root.json" >/dev/null
        run_clean ${self}/bin/apm --json list --installed \
          --registry host-install-multi-root > "$work/apm-list-host-leaf-multi-root.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostleaf"
            and .[0].registry == "host-install-multi-root"
            and .[0].version == "1.0.0"
            and .[0].status == "installed"' \
          "$work/apm-list-host-leaf-multi-root.json" >/dev/null
        "$profile/current/bin/host-leaf-tool" \
          > "$work/host-leaf-multi-root-after-app-remove.out"
        grep -q "host leaf package executed" \
          "$work/host-leaf-multi-root-after-app-remove.out"
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$multi_root_home"
        config="$multi_root_config"
        data="$multi_root_data"
        cache="$multi_root_cache"
        profile_root="$multi_root_profile_root"
        profile="$multi_root_profile"
        nix_store --delete --ignore-liveness "$install_store" \
          > "$work/nix-delete-host-install-after-multi-root.out" 2>&1
        nix_store --delete --ignore-liveness "$install_leaf_store" \
          > "$work/nix-delete-host-leaf-after-multi-root.out" 2>&1
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-after-multi-root-delete.out" 2>&1; then
          cat "$work/nix-valid-host-install-after-multi-root-delete.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-after-multi-root-delete.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-after-multi-root-delete.out"
          exit 1
        fi
        assert_no_profile

        disabled_home="$home"
        disabled_config_root="$config"
        disabled_data="$data"
        disabled_cache="$cache"
        disabled_profile_root="$profile_root"
        disabled_profile="$profile"
        home="$work/disabled-home"
        config="$work/disabled-config"
        data="$work/disabled-share"
        cache="$work/disabled-cache"
        profile_root="$work/disabled-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
          --name host-install-disabled \
          --branch stable > "$work/apm-add-host-install-disabled.out" 2>&1
        grep -q "Registry 'host-install-disabled' added" \
          "$work/apm-add-host-install-disabled.out"
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-disabled \
          --yes > "$work/apm-install-host-install-disabled.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-disabled"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-host-install-disabled.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-disabled-before-disable.out"
        grep -q "host leaf package executed" \
          "$work/host-install-disabled-before-disable.out"
        grep -q "host install package executed" \
          "$work/host-install-disabled-before-disable.out"
        disabled_registry_config="$config/apm/registries.d/host-install-disabled.toml"
        run_clean ${self}/bin/aos --json package registry disable host-install-disabled \
          > "$work/apm-registry-disable-host-install-disabled.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$disabled_registry_config" \
          '.action == "registry_disable"
            and .status == "disabled"
            and .registry == "host-install-disabled"
            and .enabled == false
            and .previous_enabled == true
            and .changed == true
            and .config == $config_path
            and .packages == 3' \
          "$work/apm-registry-disable-host-install-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json registry disable host-install-disabled \
          > "$work/apm-registry-disable-host-install-disabled-again.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "registry_disable"
            and .status == "unchanged"
            and .registry == "host-install-disabled"
            and .enabled == false
            and .previous_enabled == false
            and .changed == false
            and .packages == 3' \
          "$work/apm-registry-disable-host-install-disabled-again.json" >/dev/null
        grep -q 'enabled = false' "$disabled_registry_config"
        run_clean ${self}/bin/apm --json registry list \
          > "$work/apm-registry-list-disabled.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "host-install-disabled"
            and .[0].enabled == false
            and .[0].status == "disabled"
            and .[0].packages == 3' \
          "$work/apm-registry-list-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json search hostinstall \
          --registry host-install-disabled > "$work/apm-search-disabled.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apm-search-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json search hostinstall --installed \
          --registry host-install-disabled > "$work/apm-search-installed-disabled.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].registry == "host-install-disabled"
            and .[0].version == "1.0.0"
            and .[0].description == "installed package unavailable in registry"' \
          "$work/apm-search-installed-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json list --installed \
          --registry host-install-disabled > "$work/apm-list-installed-disabled.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and any(.[]; .name == "hostinstall"
              and .registry == "host-install-disabled"
              and .version == "1.0.0"
              and (.status | contains("installed"))
              and (.status | contains("unavailable")))
            and any(.[]; .name == "hostleaf"
              and .registry == "host-install-disabled"
              and .version == "1.0.0"
              and (.status | contains("installed"))
              and (.status | contains("unavailable")))' \
          "$work/apm-list-installed-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json policy hostinstall \
          > "$work/apm-policy-disabled.json"
        ${pkgs.jq}/bin/jq -e \
          '.package == "hostinstall"
            and .installed == "1.0.0"
            and .candidate == null
            and .versions == []
            and (.unavailable_installed | length == 1)
            and .unavailable_installed[0].version == "1.0.0"
            and .unavailable_installed[0].registry == "host-install-disabled"' \
          "$work/apm-policy-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json source hostinstall --show-drv \
          > "$work/apm-source-disabled.json"
        ${pkgs.jq}/bin/jq -e \
          --arg source "$install_drv" \
          --arg store "$install_store" \
          '.package == "hostinstall"
            and .registry == "host-install-disabled"
            and .source_drv == $source
            and .installed == true
            and .installed_store_path == $store' \
          "$work/apm-source-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json depends hostinstall \
          > "$work/apm-depends-disabled.json"
        ${pkgs.jq}/bin/jq -e \
          --arg app "$install_hash" \
          --arg leaf "$install_leaf_hash" \
          '.package == "hostinstall"
            and .registry == "host-install-disabled"
            and .installed == true
            and .tree.name == "hostinstall"
            and .tree.store_hash == $app
            and (.tree.children | any(.name == "hostleaf"
              and .version == "1.0.0"
              and .store_hash == $leaf))
            and .unique_store_paths >= 2' \
          "$work/apm-depends-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json rdepends hostleaf \
          > "$work/apm-rdepends-disabled.json"
        ${pkgs.jq}/bin/jq -e \
          --arg leaf "$install_leaf_hash" \
          '.package == "hostleaf"
            and .target_versions == "1.0.0"
            and (.target_hashes | index($leaf) != null)
            and (.dependents | any(.name == "hostinstall"
              and .version == "1.0.0"))' \
          "$work/apm-rdepends-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json orphans \
          > "$work/apm-orphans-disabled.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apm-orphans-disabled.json" >/dev/null
        run_clean ${self}/bin/apm --json upgrade --dry-run \
          > "$work/apm-upgrade-disabled-dry-run.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "upgrade"
            and .status == "current"
            and .requested == []
            and .exclude == []
            and .dry_run == true
            and .generation == null
            and .upgraded == 0
            and .held_back == []
            and .upgrades == []
            and .downloads.planned == 0
            and .downloads.downloaded == 0
            and .downloads.imported == 0' \
          "$work/apm-upgrade-disabled-dry-run.json" >/dev/null
        if run_clean ${self}/bin/apm --json update --registry host-install-disabled \
          > "$work/apm-update-disabled-registry.out" 2>&1; then
          cat "$work/apm-update-disabled-registry.out"
          exit 1
        fi
        grep -q "registry 'host-install-disabled' is not enabled" \
          "$work/apm-update-disabled-registry.out"
        run_clean ${self}/bin/aos --json package registry enable host-install-disabled \
          > "$work/apm-registry-enable-host-install-disabled.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$disabled_registry_config" \
          '.action == "registry_enable"
            and .status == "enabled"
            and .registry == "host-install-disabled"
            and .enabled == true
            and .previous_enabled == false
            and .changed == true
            and .config == $config_path
            and .packages == 3' \
          "$work/apm-registry-enable-host-install-disabled.json" >/dev/null
        grep -q 'enabled = true' "$disabled_registry_config"
        run_clean ${self}/bin/apm --json update --registry host-install-disabled \
          > "$work/apm-update-reenabled-registry.json"
        ${pkgs.jq}/bin/jq -e \
          '.registry == "host-install-disabled"
            and (.registries | length == 1)
            and .registries[0].registry == "host-install-disabled"
            and (.registries[0].status == "updated" or .registries[0].status == "current")
            and .registries[0].packages == 3' \
          "$work/apm-update-reenabled-registry.json" >/dev/null
        run_clean ${self}/bin/apm --json search hostinstall \
          --registry host-install-disabled > "$work/apm-search-reenabled.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].registry == "host-install-disabled"
            and .[0].version == "1.0.0"' \
          "$work/apm-search-reenabled.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-disabled-after-queries.out"
        grep -q "host leaf package executed" \
          "$work/host-install-disabled-after-queries.out"
        grep -q "host install package executed" \
          "$work/host-install-disabled-after-queries.out"
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$disabled_home"
        config="$disabled_config_root"
        data="$disabled_data"
        cache="$disabled_cache"
        profile_root="$disabled_profile_root"
        profile="$disabled_profile"
        nix_store --delete --ignore-liveness "$install_store" \
          > "$work/nix-delete-host-install-after-disabled.out" 2>&1
        nix_store --delete --ignore-liveness "$install_leaf_store" \
          > "$work/nix-delete-host-leaf-after-disabled.out" 2>&1
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-after-disabled-delete.out" 2>&1; then
          cat "$work/nix-valid-host-install-after-disabled-delete.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-after-disabled-delete.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-after-disabled-delete.out"
          exit 1
        fi
        assert_no_profile

        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-client \
          --dry-run > "$work/apm-install-host-install-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "install"
            and .status == "planned"
            and .requested == ["hostinstall"]
            and .reinstall == false
            and .download_only == false
            and .no_deps == false
            and .dry_run == true
            and .generation == null
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-client"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and .downloads.downloaded == 0
            and .downloads.imported == 0
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
          "$work/apm-install-host-install-dry-run.json" >/dev/null
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-after-install-dry-run.out" 2>&1; then
          cat "$work/nix-valid-host-install-after-install-dry-run.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-after-install-dry-run.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-after-install-dry-run.out"
          exit 1
        fi
        assert_no_profile

        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-client \
          --download-only \
          --yes > "$work/apm-download-only-host-install.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "install"
            and .status == "downloaded"
            and .requested == ["hostinstall"]
            and .reinstall == false
            and .download_only == true
            and .no_deps == false
            and .dry_run == false
            and .generation == null
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-client"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and .downloads.imported == 0
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
          "$work/apm-download-only-host-install.json" >/dev/null
        find "$cache/apm" -type f | grep -q .
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-after-download-only.out" 2>&1; then
          cat "$work/nix-valid-host-install-after-download-only.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-after-download-only.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-after-download-only.out"
          exit 1
        fi
        assert_no_profile

        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-client \
          --yes > "$work/apm-install-host-install.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "install"
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
            and (.downloads.imported >= 2)
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
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

        run_clean ${self}/bin/apm --json search hostinstall --installed \
          --registry host-install-client > "$work/apm-search-installed-host-install.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].registry == "host-install-client"
            and .[0].version == "1.0.0"' \
          "$work/apm-search-installed-host-install.json" >/dev/null
        run_clean ${self}/bin/apm --json list --installed \
          --registry host-install-client > "$work/apm-list-installed-host-install.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and any(.[]; .name == "hostinstall"
              and .registry == "host-install-client"
              and .version == "1.0.0"
              and .status == "installed")
            and any(.[]; .name == "hostleaf"
              and .registry == "host-install-client"
              and .version == "1.0.0"
              and .status == "installed")' \
          "$work/apm-list-installed-host-install.json" >/dev/null
        run_clean ${self}/bin/apm --json show hostinstall \
          --registry host-install-client > "$work/apm-show-installed-host-install.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" \
          '.name == "hostinstall"
            and .registry == "host-install-client"
            and .version == "1.0.0"
            and .installed == true
            and .store_path == $store
            and (.dependencies | index("hostleaf") != null)' \
          "$work/apm-show-installed-host-install.json" >/dev/null
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
            and (.expected_nar_hash | startswith("sha256:"))
            and (.actual_nar_hash | startswith("sha256:"))' \
          "$work/apm-verify-host-install.json" >/dev/null
        assert_default_profile_absent
        run_clean ${self}/bin/apm source hostinstall --show-drv \
          > "$work/apm-source-host-install.out" 2>&1
        grep -q "$install_drv" "$work/apm-source-host-install.out"
        run_clean ${self}/bin/apm --json source hostinstall --show-drv \
          > "$work/apm-source-host-install.json"
        ${pkgs.jq}/bin/jq -e \
          --arg source "$install_drv" \
          --arg store "$install_store" \
          '.package == "hostinstall"
            and .registry == "host-install-client"
            and .source_drv == $source
            and (.source_nar_hash | startswith("sha256-"))
            and .installed == true
            and .installed_store_path == $store' \
          "$work/apm-source-host-install.json" >/dev/null
        run_clean ${self}/bin/apm --json source hostinstall --fetch --verify \
          > "$work/apm-source-host-install-verify.json"
        ${pkgs.jq}/bin/jq -e \
          --arg source "$install_drv" \
          --arg store "$install_store" \
          '.package == "hostinstall"
            and .registry == "host-install-client"
            and .source_drv == $source
            and (.source_nar_hash | startswith("sha256-"))
            and .installed == true
            and .installed_store_path == $store
            and .built_path == $store
            and (.expected_nar_hash | startswith("sha256:"))
            and (.actual_nar_hash | startswith("sha256:"))
            and .verified == true' \
          "$work/apm-source-host-install-verify.json" >/dev/null
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
        install_leaf_drv_v2=$(nix_store -q --deriver "$install_leaf_store_v2")
        test -e "$install_leaf_drv_v2"
        install_store_v2=$(nix_build "$work/host-install-fixtures.nix" -A appV2 --no-out-link)
        install_hash_v2=$(basename "$install_store_v2" | cut -d- -f1)
        install_drv_v2=$(nix_store -q --deriver "$install_store_v2")
        test -e "$install_drv_v2"
        run_clean ${self}/bin/apr --json publish "$install_leaf_store_v2" \
          --name hostleaf \
          --version 2.0.0 \
          --description "Host APM dependency fixture v2" \
          --license MIT \
          --maintainer host@example.invalid \
          --registry host-install-channel \
          --no-commit > "$work/apr-publish-host-leaf-v2.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_leaf_store_v2" \
          --arg source "$install_leaf_drv_v2" \
          '.action == "publish"
            and .registry == "host-install-channel"
            and .package == "hostleaf"
            and .version == "2.0.0"
            and .store_path == $store
            and .source.store_path == $source
            and (.source.nar_hash | startswith("sha256-"))
            and (.source.nar_size > 0)
            and .committed == false' \
          "$work/apr-publish-host-leaf-v2.json" >/dev/null
        run_clean ${self}/bin/apr --json publish "$install_store_v2" \
          --name hostinstall \
          --version 2.0.0 \
          --description "Host APM install fixture v2" \
          --license MIT \
          --maintainer host@example.invalid \
          --registry host-install-channel \
          --no-commit > "$work/apr-publish-host-install-v2.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_store_v2" \
          --arg source "$install_drv_v2" \
          '.action == "publish"
            and .registry == "host-install-channel"
            and .package == "hostinstall"
            and .version == "2.0.0"
            and .store_path == $store
            and .source.store_path == $source
            and (.source.nar_hash | startswith("sha256-"))
            and (.source.nar_size > 0)
            and .committed == false' \
          "$work/apr-publish-host-install-v2.json" >/dev/null
        run_clean ${self}/bin/apr --json cache generate \
          --registry host-install-channel \
          --output "$work/install-static-cache-output/cache" \
          --key "$work/host-install-cache-signing-key" \
          --cache-url "http://127.0.0.1:$install_cache_port/cache" \
          --priority 77 \
          --no-commit > "$work/apr-cache-host-install-v2.json"
        ${pkgs.jq}/bin/jq -e \
          --arg output "$work/install-static-cache-output/cache" \
          --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          '.action == "cache_generate"
            and .registry == "host-install-channel"
            and .output_dir == $output
            and .paths >= 4
            and .narinfos >= 4
            and .nars >= 4
            and .cache_url == $cache_url
            and .priority == 77
            and .upload_urls == [$upload_url, $upload_url_mirror]
            and .uploaded == true
            and .cache_pointer_updated == false
            and .committed == false' \
          "$work/apr-cache-host-install-v2.json" >/dev/null
        test -f "$work/install-static-cache-output/cache/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-output/cache/$install_leaf_hash_v2.narinfo"
        test -f "$work/install-static-cache-output/cache/$install_hash_v2.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-output/cache/$install_leaf_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-output/cache/$install_leaf_hash_v2.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-output/cache/$install_hash_v2.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_leaf_hash_v2.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_hash.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_hash_v2.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_leaf_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_leaf_hash_v2.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_hash.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_hash_v2.narinfo"
        find "$work/install-static-cache-upload/cache/nar" -type f | grep -q .
        test -f "$work/install-static-cache-upload/cache-mirror/$install_leaf_hash_v2.narinfo"
        test -f "$work/install-static-cache-upload/cache-mirror/$install_hash_v2.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache-mirror/$install_leaf_hash_v2.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache-mirror/$install_hash_v2.narinfo"
        find "$work/install-static-cache-upload/cache-mirror/nar" -type f | grep -q .
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
          --cache-key "$work/host-install-cache-signing-key" \
          --cache-url "http://127.0.0.1:$install_cache_port/cache" \
          --cache-priority 77 \
          --channel stable \
          --count 256 > "$work/apr-release-host-install-v2.json"
        ${pkgs.jq}/bin/jq -e \
          --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          '.action == "release"
            and .status == "released"
            and .registry == "host-install-channel"
            and .version == "2.0.0"
            and .dry_run == false
            and .cache_url == $cache_url
            and .cache_priority == 77
            and .cache_pointer_updated == false
            and .upload_urls == [$upload_url, $upload_url_mirror]
            and .channel.name == "stable"
            and .channel.action == "advance"
            and .channel.count == 256
            and .channel.touched_partitions == 256
            and (.cache.paths >= 4)
            and (.cache.remote_skipped >= 4)
            and (.full_pack | startswith("pack-") and endswith(".pack"))
            and (.deltas | index("delta-1.0.0.pack.zst") != null)
            and (.uploaded_files > 0)
            and (.uploaded_bytes > 0)' \
          "$work/apr-release-host-install-v2.json" >/dev/null
        git -C "$install_reg" rev-parse --verify '2.0.0^{tag}' \
          > "$work/apr-release-host-install-v2-tag.out"
        test -f "$work/install-static-cache-upload/cache/$install_leaf_hash_v2.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_hash_v2.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_leaf_hash_v2.narinfo"
        grep -q '^Sig: hostcache:' \
          "$work/install-static-cache-upload/cache/$install_hash_v2.narinfo"
        test -f "$work/install-static-cache-upload/cache/releases/2/0/0/objects/info/packs"
        test -f "$work/install-static-cache-upload/cache/releases/2/0/0/objects/pack/delta-1.0.0.pack.zst"
        grep -q "BEGIN SSH SIGNATURE" \
          "$work/install-static-cache-upload/cache/channels/stable/00"
        test -f "$work/install-static-cache-upload/cache-mirror/releases/2/0/0/objects/info/packs"
        test -f "$work/install-static-cache-upload/cache-mirror/releases/2/0/0/objects/pack/delta-1.0.0.pack.zst"
        grep -q "BEGIN SSH SIGNATURE" \
          "$work/install-static-cache-upload/cache-mirror/channels/stable/00"

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
            and .registries[0].packages == 3
            and .registries[0].updated == 3
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

        git -C "$install_reg" push origin 1.0.0 2.0.0 \
          > "$work/git-push-host-install-tags.out" 2>&1
        main_home="$home"
        main_config="$config"
        main_data="$data"
        main_cache="$cache"
        main_profile_root="$profile_root"
        main_profile="$profile"
        home="$work/tagged-home"
        config="$work/tagged-config"
        data="$work/tagged-share"
        cache="$work/tagged-cache"
        profile_root="$work/tagged-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
          --name host-install-tag \
          --tag 1.0.0 > "$work/apm-add-host-install-tag.out" 2>&1
        grep -q "Registry 'host-install-tag' added" \
          "$work/apm-add-host-install-tag.out"
        tag_config="$config/apm/registries.d/host-install-tag.toml"
        grep -q 'tag = "1.0.0"' "$tag_config"
        run_clean ${self}/bin/apm search hostinstall \
          --registry host-install-tag \
          > "$work/apm-search-host-install-tag.out" 2>&1
        grep -q "hostinstall/host-install-tag 1.0.0" \
          "$work/apm-search-host-install-tag.out"
        if grep -q "2.0.0" "$work/apm-search-host-install-tag.out"; then
          cat "$work/apm-search-host-install-tag.out"
          exit 1
        fi
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-before-tag.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_store" \
            > "$work/nix-delete-host-install-before-tag.out" 2>&1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-before-tag.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_leaf_store" \
            > "$work/nix-delete-host-leaf-before-tag.out" 2>&1
        fi
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-tag \
          --yes > "$work/apm-install-host-install-tag.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-tag"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-host-install-tag.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-tag-run.out"
        grep -q "host leaf package executed" "$work/host-install-tag-run.out"
        grep -q "host install package executed" "$work/host-install-tag-run.out"
        if grep -q "v2 executed" "$work/host-install-tag-run.out"; then
          cat "$work/host-install-tag-run.out"
          exit 1
        fi
        run_clean ${self}/bin/apm list --upgradable \
          > "$work/apm-upgradable-host-install-tag.out" 2>&1
        if grep -q "hostinstall/host-install-tag" \
          "$work/apm-upgradable-host-install-tag.out"; then
          cat "$work/apm-upgradable-host-install-tag.out"
          exit 1
        fi
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
        home="$work/version-home"
        config="$work/version-config"
        data="$work/version-share"
        cache="$work/version-cache"
        profile_root="$work/version-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm --json registry add --no-verify "file://$install_origin" \
          --name host-install-version \
          --version '^1.0' > "$work/apm-add-host-install-version.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$config/apm/registries.d/host-install-version.toml" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-install-version"
            and .name == "host-install-version"
            and .tracking == "version:^1.0"
            and .clone == true
            and .synced == true
            and .packages == 3
            and .config == $config_path
            and .verification_disabled == true
            and (.last_commit | length == 64)' \
          "$work/apm-add-host-install-version.json" >/dev/null
        version_config="$config/apm/registries.d/host-install-version.toml"
        grep -q 'version = "^1.0"' "$version_config"
        run_clean ${self}/bin/apm search hostinstall \
          --registry host-install-version \
          > "$work/apm-search-host-install-version.out" 2>&1
        grep -q "hostinstall/host-install-version 1.0.0" \
          "$work/apm-search-host-install-version.out"
        if grep -q "2.0.0" "$work/apm-search-host-install-version.out"; then
          cat "$work/apm-search-host-install-version.out"
          exit 1
        fi
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-before-version.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_store" \
            > "$work/nix-delete-host-install-before-version.out" 2>&1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-before-version.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_leaf_store" \
            > "$work/nix-delete-host-leaf-before-version.out" 2>&1
        fi
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-version \
          --yes > "$work/apm-install-host-install-version.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-version"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-host-install-version.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-version-run.out"
        grep -q "host leaf package executed" "$work/host-install-version-run.out"
        grep -q "host install package executed" "$work/host-install-version-run.out"
        if grep -q "v2 executed" "$work/host-install-version-run.out"; then
          cat "$work/host-install-version-run.out"
          exit 1
        fi
        assert_default_profile_absent
        version_home="$home"
        version_config_root="$config"
        version_data="$data"
        version_cache="$cache"
        version_profile_root="$profile_root"
        version_profile="$profile"
        home="$main_home"
        config="$main_config"
        data="$main_data"
        cache="$main_cache"
        profile_root="$main_profile_root"
        profile="$main_profile"

        install_leaf_store_v11=$(nix_build "$work/host-install-fixtures.nix" -A leafV11 --no-out-link)
        install_leaf_hash_v11=$(basename "$install_leaf_store_v11" | cut -d- -f1)
        install_leaf_drv_v11=$(nix_store -q --deriver "$install_leaf_store_v11")
        test -e "$install_leaf_drv_v11"
        install_store_v11=$(nix_build "$work/host-install-fixtures.nix" -A appV11 --no-out-link)
        install_hash_v11=$(basename "$install_store_v11" | cut -d- -f1)
        install_drv_v11=$(nix_store -q --deriver "$install_store_v11")
        test -e "$install_drv_v11"
        run_clean ${self}/bin/apr --json publish "$install_leaf_store_v11" \
          --name hostleaf \
          --version 1.1.0 \
          --description "Host APM dependency fixture v1.1" \
          --license MIT \
          --maintainer host@example.invalid \
          --registry host-install-channel \
          --no-commit > "$work/apr-publish-host-leaf-v11.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_leaf_store_v11" \
          --arg source "$install_leaf_drv_v11" \
          '.action == "publish"
            and .registry == "host-install-channel"
            and .package == "hostleaf"
            and .version == "1.1.0"
            and .store_path == $store
            and .source.store_path == $source
            and (.source.nar_hash | startswith("sha256-"))
            and (.source.nar_size > 0)
            and .committed == false' \
          "$work/apr-publish-host-leaf-v11.json" >/dev/null
        run_clean ${self}/bin/apr --json publish "$install_store_v11" \
          --name hostinstall \
          --version 1.1.0 \
          --description "Host APM install fixture v1.1" \
          --license MIT \
          --maintainer host@example.invalid \
          --registry host-install-channel \
          --no-commit > "$work/apr-publish-host-install-v11.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_store_v11" \
          --arg source "$install_drv_v11" \
          '.action == "publish"
            and .registry == "host-install-channel"
            and .package == "hostinstall"
            and .version == "1.1.0"
            and .store_path == $store
            and .source.store_path == $source
            and (.source.nar_hash | startswith("sha256-"))
            and (.source.nar_size > 0)
            and .committed == false' \
          "$work/apr-publish-host-install-v11.json" >/dev/null
        run_clean ${self}/bin/apr --json cache generate \
          --registry host-install-channel \
          --output "$work/install-static-cache-output/cache" \
          --key "$work/host-install-cache-signing-key" \
          --cache-url "http://127.0.0.1:$install_cache_port/cache" \
          --priority 77 \
          --no-commit > "$work/apr-cache-host-install-v11.json"
        ${pkgs.jq}/bin/jq -e \
          --arg output "$work/install-static-cache-output/cache" \
          --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          '.action == "cache_generate"
            and .registry == "host-install-channel"
            and .output_dir == $output
            and .paths >= 6
            and .narinfos >= 6
            and .nars >= 6
            and .cache_url == $cache_url
            and .priority == 77
            and .upload_urls == [$upload_url, $upload_url_mirror]
            and .uploaded == true
            and .cache_pointer_updated == false
            and .committed == false' \
          "$work/apr-cache-host-install-v11.json" >/dev/null
        test -f "$work/install-static-cache-output/cache/$install_leaf_hash_v11.narinfo"
        test -f "$work/install-static-cache-output/cache/$install_hash_v11.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_leaf_hash_v11.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_hash_v11.narinfo"
        test -f "$work/install-static-cache-upload/cache-mirror/$install_leaf_hash_v11.narinfo"
        test -f "$work/install-static-cache-upload/cache-mirror/$install_hash_v11.narinfo"
        git -C "$install_reg" add -A
        git -C "$install_reg" \
          -c gpg.format=ssh \
          -c gpg.ssh.program=${pkgs.openssh}/bin/ssh-keygen \
          -c user.signingkey="$work/host-install-release-key" \
          commit -S -m "release: hostinstall 1.1.0" \
          > "$work/git-commit-host-install-v11.out" 2>&1
        run_clean ${self}/bin/apr --json release 1.1.0 \
          --registry host-install-channel \
          --key "$work/host-install-release-key" \
          --cache-key "$work/host-install-cache-signing-key" \
          --cache-url "http://127.0.0.1:$install_cache_port/cache" \
          --cache-priority 77 > "$work/apr-release-host-install-v11.json"
        ${pkgs.jq}/bin/jq -e \
          --arg cache_url "http://127.0.0.1:$install_cache_port/cache" \
          --arg upload_url "$install_default_upload" \
          --arg upload_url_mirror "$install_default_upload_mirror" \
          '.action == "release"
            and .status == "released"
            and .registry == "host-install-channel"
            and .version == "1.1.0"
            and .dry_run == false
            and .cache_url == $cache_url
            and .cache_priority == 77
            and .cache_pointer_updated == false
            and .upload_urls == [$upload_url, $upload_url_mirror]
            and .channel == null
            and (.cache.paths >= 6)
            and (.cache.narinfos + .cache.remote_skipped >= 6)
            and (.full_pack | startswith("pack-") and endswith(".pack"))
            and (.uploaded_files > 0)
            and (.uploaded_bytes > 0)' \
          "$work/apr-release-host-install-v11.json" >/dev/null
        git -C "$install_reg" rev-parse --verify '1.1.0^{tag}' \
          > "$work/apr-release-host-install-v11-tag.out"
        test -f "$work/install-static-cache-upload/cache/$install_leaf_hash_v11.narinfo"
        test -f "$work/install-static-cache-upload/cache/$install_hash_v11.narinfo"
        test -f "$work/install-static-cache-upload/cache/releases/1/1/0/objects/info/packs"
        test -f "$work/install-static-cache-upload/cache-mirror/releases/1/1/0/objects/info/packs"
        git -C "$install_reg" push origin 1.1.0 \
          > "$work/git-push-host-install-version-tag.out" 2>&1

        home="$version_home"
        config="$version_config_root"
        data="$version_data"
        cache="$version_cache"
        profile_root="$version_profile_root"
        profile="$version_profile"
        run_clean ${self}/bin/apm --json update --registry host-install-version \
          > "$work/apm-update-host-install-version-v11.json" 2>&1 || {
          cat "$work/apm-update-host-install-version-v11.json"
          exit 1
        }
        ${pkgs.jq}/bin/jq -e \
          '.registry == "host-install-version"
            and .updated == 1
            and (.registries | length == 1)
            and .registries[0].registry == "host-install-version"
            and .registries[0].status == "updated"
            and .registries[0].packages == 3
            and .registries[0].updated == 3
            and .registries[0].added == 0
            and .registries[0].removed == 0
            and (.registries[0].commit | length == 64)' \
          "$work/apm-update-host-install-version-v11.json" >/dev/null || {
          cat "$work/apm-update-host-install-version-v11.json"
          exit 1
        }
        run_clean ${self}/bin/apm search hostinstall \
          --registry host-install-version \
          > "$work/apm-search-host-install-version-v11.out" 2>&1
        grep -q "hostinstall/host-install-version 1.1.0" \
          "$work/apm-search-host-install-version-v11.out"
        if grep -q "2.0.0" "$work/apm-search-host-install-version-v11.out"; then
          cat "$work/apm-search-host-install-version-v11.out"
          exit 1
        fi
        run_clean ${self}/bin/apm list --upgradable \
          > "$work/apm-upgradable-host-install-version.out" 2>&1 || {
          cat "$work/apm-upgradable-host-install-version.out"
          exit 1
        }
        grep -q "hostinstall/host-install-version" \
          "$work/apm-upgradable-host-install-version.out" || {
          cat "$work/apm-upgradable-host-install-version.out"
          exit 1
        }
        grep -q "upgradable: 1.1.0" \
          "$work/apm-upgradable-host-install-version.out" || {
          cat "$work/apm-upgradable-host-install-version.out"
          exit 1
        }
        if grep -q "2.0.0" "$work/apm-upgradable-host-install-version.out"; then
          cat "$work/apm-upgradable-host-install-version.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json list --upgradable \
          --registry host-install-version > "$work/apm-upgradable-host-install-version.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].registry == "host-install-version"
            and .[0].version == "1.0.0"
            and (.[0].status | contains("installed"))
            and (.[0].status | contains("upgradable: 1.1.0"))
            and (.[0].status | contains("2.0.0") | not)' \
          "$work/apm-upgradable-host-install-version.json" >/dev/null
        nix_store --delete --ignore-liveness "$install_store_v11" \
          > "$work/nix-delete-host-install-version-v11.out" 2>&1
        nix_store --delete --ignore-liveness "$install_leaf_store_v11" \
          > "$work/nix-delete-host-leaf-version-v11.out" 2>&1
        if nix_store --check-validity "$install_store_v11" \
          > "$work/nix-valid-host-install-version-v11-deleted.out" 2>&1; then
          cat "$work/nix-valid-host-install-version-v11-deleted.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store_v11" \
          > "$work/nix-valid-host-leaf-version-v11-deleted.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-version-v11-deleted.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json full-upgrade --yes \
          > "$work/apm-full-upgrade-host-install-version.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v11" \
          '.action == "upgrade"
            and .status == "upgraded"
            and .requested == []
            and .exclude == []
            and .dry_run == false
            and .generation == 2
            and .upgraded == 1
            and .held_back == []
            and (.upgrades | length == 1)
            and .upgrades[0].name == "hostinstall"
            and .upgrades[0].registry == "host-install-version"
            and .upgrades[0].old_version == "1.0.0"
            and .upgrades[0].new_version == "1.1.0"
            and .upgrades[0].new_store_path == $store
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-full-upgrade-host-install-version.json" >/dev/null
        nix_store --check-validity "$install_store_v11" \
          > "$work/nix-valid-host-install-version-v11-imported.out" 2>&1
        nix_store --check-validity "$install_leaf_store_v11" \
          > "$work/nix-valid-host-leaf-version-v11-imported.out" 2>&1
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-version-v11-run.out"
        grep -q "host leaf package v1.1 executed" \
          "$work/host-install-version-v11-run.out"
        grep -q "host install package v1.1 executed" \
          "$work/host-install-version-v11-run.out"
        if grep -q "v2 executed" "$work/host-install-version-v11-run.out"; then
          cat "$work/host-install-version-v11-run.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json list --installed \
          --registry host-install-version > "$work/apm-list-installed-host-install-version-v11.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and any(.[]; .name == "hostinstall"
              and .registry == "host-install-version"
              and .version == "1.1.0"
              and .status == "installed")
            and any(.[]; .name == "hostleaf"
              and .registry == "host-install-version"
              and .version == "1.1.0"
              and .status == "installed")' \
          "$work/apm-list-installed-host-install-version-v11.json" >/dev/null
        run_clean ${self}/bin/apm --json policy hostinstall \
          > "$work/apm-policy-host-install-version-v11.json"
        ${pkgs.jq}/bin/jq -e \
          '.package == "hostinstall"
            and .installed == "1.1.0"
            and .candidate == "1.1.0"
            and (.versions | length == 1)
            and .versions[0].version == "1.1.0"
            and .versions[0].registry == "host-install-version"
            and .versions[0].installed == true
            and .unavailable_installed == []' \
          "$work/apm-policy-host-install-version-v11.json" >/dev/null
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
            and .registries[0].packages == 3
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

        main_home="$home"
        main_config="$config"
        main_data="$data"
        main_cache="$cache"
        main_profile_root="$profile_root"
        main_profile="$profile"
        if nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-no-deps-before-delete.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_store_v2" \
            > "$work/nix-delete-host-install-no-deps-before.out" 2>&1
        fi
        if nix_store --check-validity "$install_leaf_store_v2" \
          > "$work/nix-valid-host-leaf-no-deps-before-delete.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_leaf_store_v2" \
            > "$work/nix-delete-host-leaf-no-deps-before.out" 2>&1
        fi
        home="$work/no-deps-home"
        config="$work/no-deps-config"
        data="$work/no-deps-share"
        cache="$work/no-deps-cache"
        profile_root="$work/no-deps-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
          --name host-install-no-deps \
          --branch stable > "$work/apm-add-host-install-no-deps.out" 2>&1
        grep -q "Registry 'host-install-no-deps' added" \
          "$work/apm-add-host-install-no-deps.out"
        if run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-no-deps \
          --no-deps \
          --yes > "$work/apm-install-host-install-no-deps-missing.json" 2>&1; then
          cat "$work/apm-install-host-install-no-deps-missing.json"
          exit 1
        fi
        ${pkgs.jq}/bin/jq -e \
          '.error
            | contains("--no-deps requested")
            and contains("hostleaf")
            and contains("store path")' \
          "$work/apm-install-host-install-no-deps-missing.json" >/dev/null
        if nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-no-deps-missing.out" 2>&1; then
          cat "$work/nix-valid-host-install-no-deps-missing.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store_v2" \
          > "$work/nix-valid-host-leaf-no-deps-missing.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-no-deps-missing.out"
          exit 1
        fi
        assert_no_profile
        run_clean ${self}/bin/apm --json install hostleaf \
          --registry host-install-no-deps \
          --yes > "$work/apm-install-host-leaf-no-deps-base.json"
        ${pkgs.jq}/bin/jq -e --arg leaf "$install_leaf_store_v2" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostleaf"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostleaf"
            and .roots[0].registry == "host-install-no-deps"
            and .roots[0].version == "2.0.0"
            and .roots[0].store_path == $leaf
            and (.downloads.planned >= 1)
            and (.downloads.downloaded >= 1)
            and (.downloads.imported >= 1)' \
          "$work/apm-install-host-leaf-no-deps-base.json" >/dev/null
        nix_store --check-validity "$install_leaf_store_v2" \
          > "$work/nix-valid-host-leaf-no-deps-base-imported.out" 2>&1
        "$profile/current/bin/host-leaf-tool" \
          > "$work/host-leaf-no-deps-base-run.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-leaf-no-deps-base-run.out"
        if nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-no-deps-before-app.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_store_v2" \
            > "$work/nix-delete-host-install-no-deps-before-app.out" 2>&1
        fi
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-no-deps \
          --no-deps \
          --yes > "$work/apm-install-host-install-no-deps.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .reinstall == false
            and .download_only == false
            and .no_deps == true
            and .dry_run == false
            and .generation == 2
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-no-deps"
            and .roots[0].version == "2.0.0"
            and .roots[0].store_path == $store
            and (.closure | length == 1)
            and .closure[0].name == "hostinstall"
            and .closure[0].store_path == $store
            and .closure[0].explicit == true
            and .downloads.planned == 1
            and .downloads.downloaded == 1
            and .downloads.imported == 1' \
          "$work/apm-install-host-install-no-deps.json" >/dev/null
        nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-no-deps-imported.out" 2>&1
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-no-deps-run.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-install-no-deps-run.out"
        grep -q "host install package v2 executed" \
          "$work/host-install-no-deps-run.out"
        run_clean ${self}/bin/apm list --installed \
          > "$work/apm-installed-host-install-no-deps.out" 2>&1
        grep -q "hostleaf/host-install-no-deps" \
          "$work/apm-installed-host-install-no-deps.out"
        grep -q "hostinstall/host-install-no-deps" \
          "$work/apm-installed-host-install-no-deps.out"
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$main_home"
        config="$main_config"
        data="$main_data"
        cache="$main_cache"
        profile_root="$main_profile_root"
        profile="$main_profile"

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
            and .registries[0].packages == 3
            and .registries[0].updated == 3
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
        run_clean ${self}/bin/apm --json list --upgradable \
          --registry host-install-client > "$work/apm-upgradable-host-install.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].registry == "host-install-client"
            and .[0].version == "1.0.0"
            and (.[0].status | contains("installed"))
            and (.[0].status | contains("upgradable: 2.0.0"))' \
          "$work/apm-upgradable-host-install.json" >/dev/null
        run_clean ${self}/bin/apm --json policy hostinstall \
          > "$work/apm-policy-host-install-upgradable.json"
        ${pkgs.jq}/bin/jq -e \
          '.package == "hostinstall"
            and .installed == "1.0.0"
            and .candidate == "2.0.0"
            and (.versions | length == 1)
            and .versions[0].version == "2.0.0"
            and .versions[0].registry == "host-install-client"
            and .versions[0].installed == false
            and (.unavailable_installed | any(.version == "1.0.0"
              and .registry == "host-install-client"))' \
          "$work/apm-policy-host-install-upgradable.json" >/dev/null

        run_clean ${self}/bin/apm --json hold hostinstall \
          > "$work/apm-hold-host-install-before-upgrade.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" \
          '.action == "hold"
            and .status == "held"
            and .package == "hostinstall"
            and .name == "hostinstall"
            and .version == "1.0.0"
            and .registry == "host-install-client"
            and .store_path == $store
            and .held == true' \
          "$work/apm-hold-host-install-before-upgrade.json" >/dev/null
        run_clean ${self}/bin/apm --json upgrade hostinstall --dry-run \
          > "$work/apm-upgrade-host-install-held-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
          '.action == "upgrade"
            and .status == "held_back"
            and .requested == ["hostinstall"]
            and .exclude == []
            and .dry_run == true
            and .generation == null
            and .upgraded == 0
            and .upgrades == []
            and (.held_back | length == 1)
            and .held_back[0].name == "hostinstall"
            and .held_back[0].registry == "host-install-client"
            and .held_back[0].old_version == "1.0.0"
            and .held_back[0].new_version == "2.0.0"
            and .held_back[0].new_store_path == $store
            and .downloads.planned == 0
            and .downloads.downloaded == 0
            and .downloads.imported == 0' \
          "$work/apm-upgrade-host-install-held-dry-run.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-after-held-upgrade-dry-run.out"
        grep -q "host leaf package executed" \
          "$work/host-install-after-held-upgrade-dry-run.out"
        grep -q "host install package executed" \
          "$work/host-install-after-held-upgrade-dry-run.out"
        if grep -q "v2 executed" "$work/host-install-after-held-upgrade-dry-run.out"; then
          cat "$work/host-install-after-held-upgrade-dry-run.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json unhold hostinstall \
          > "$work/apm-unhold-host-install-before-upgrade.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" \
          '.action == "unhold"
            and .status == "unheld"
            and .package == "hostinstall"
            and .name == "hostinstall"
            and .version == "1.0.0"
            and .registry == "host-install-client"
            and .store_path == $store
            and .held == false' \
          "$work/apm-unhold-host-install-before-upgrade.json" >/dev/null
        run_clean ${self}/bin/apm --json upgrade --exclude hostinstall --dry-run \
          > "$work/apm-upgrade-host-install-excluded-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
          '.action == "upgrade"
            and .status == "held_back"
            and .requested == []
            and .exclude == ["hostinstall"]
            and .dry_run == true
            and .generation == null
            and .upgraded == 0
            and .upgrades == []
            and (.held_back | length == 1)
            and .held_back[0].name == "hostinstall"
            and .held_back[0].registry == "host-install-client"
            and .held_back[0].old_version == "1.0.0"
            and .held_back[0].new_version == "2.0.0"
            and .held_back[0].new_store_path == $store
            and .downloads.planned == 0
            and .downloads.downloaded == 0
            and .downloads.imported == 0' \
          "$work/apm-upgrade-host-install-excluded-dry-run.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-after-excluded-upgrade-dry-run.out"
        grep -q "host leaf package executed" \
          "$work/host-install-after-excluded-upgrade-dry-run.out"
        grep -q "host install package executed" \
          "$work/host-install-after-excluded-upgrade-dry-run.out"
        if grep -q "v2 executed" "$work/host-install-after-excluded-upgrade-dry-run.out"; then
          cat "$work/host-install-after-excluded-upgrade-dry-run.out"
          exit 1
        fi
        test "$(profile_generation_count)" = "1"
        assert_default_profile_absent

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

        run_clean ${self}/bin/apm --json upgrade hostinstall --dry-run \
          > "$work/apm-upgrade-host-install-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "upgrade"
            and .status == "planned"
            and .requested == ["hostinstall"]
            and .exclude == []
            and .dry_run == true
            and .generation == null
            and .upgraded == 1
            and .held_back == []
            and (.upgrades | length == 1)
            and .upgrades[0].name == "hostinstall"
            and .upgrades[0].registry == "host-install-client"
            and .upgrades[0].old_version == "1.0.0"
            and .upgrades[0].new_version == "2.0.0"
            and .upgrades[0].new_store_path == $store
            and (.downloads.planned >= 2)
            and .downloads.downloaded == 0
            and .downloads.imported == 0
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
          "$work/apm-upgrade-host-install-dry-run.json" >/dev/null
        if nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-v2-after-upgrade-dry-run.out" 2>&1; then
          cat "$work/nix-valid-host-install-v2-after-upgrade-dry-run.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store_v2" \
          > "$work/nix-valid-host-leaf-v2-after-upgrade-dry-run.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-v2-after-upgrade-dry-run.out"
          exit 1
        fi
        "$profile/current/bin/host-install-tool" > "$work/host-install-after-upgrade-dry-run.out"
        grep -q "host leaf package executed" "$work/host-install-after-upgrade-dry-run.out"
        grep -q "host install package executed" "$work/host-install-after-upgrade-dry-run.out"
        assert_default_profile_absent

        run_clean ${self}/bin/apm --json full-upgrade --dry-run \
          > "$work/apm-full-upgrade-host-install-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
          '.action == "upgrade"
            and .status == "planned"
            and .requested == []
            and .exclude == []
            and .dry_run == true
            and .generation == null
            and .upgraded == 1
            and .held_back == []
            and (.upgrades | length == 1)
            and .upgrades[0].name == "hostinstall"
            and .upgrades[0].registry == "host-install-client"
            and .upgrades[0].old_version == "1.0.0"
            and .upgrades[0].new_version == "2.0.0"
            and .upgrades[0].new_store_path == $store
            and (.downloads.planned >= 2)
            and .downloads.downloaded == 0
            and .downloads.imported == 0' \
          "$work/apm-full-upgrade-host-install-dry-run.json" >/dev/null
        if nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-v2-after-full-upgrade-dry-run.out" 2>&1; then
          cat "$work/nix-valid-host-install-v2-after-full-upgrade-dry-run.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store_v2" \
          > "$work/nix-valid-host-leaf-v2-after-full-upgrade-dry-run.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-v2-after-full-upgrade-dry-run.out"
          exit 1
        fi
        "$profile/current/bin/host-install-tool" > "$work/host-install-after-full-upgrade-dry-run.out"
        grep -q "host leaf package executed" "$work/host-install-after-full-upgrade-dry-run.out"
        grep -q "host install package executed" "$work/host-install-after-full-upgrade-dry-run.out"
        assert_default_profile_absent

        run_clean ${self}/bin/apm --json upgrade hostinstall --yes \
          > "$work/apm-upgrade-host-install.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "upgrade"
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
            and (.downloads.imported >= 2)
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
          "$work/apm-upgrade-host-install.json" >/dev/null
        nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-v2-imported.out" 2>&1
        nix_store --check-validity "$install_leaf_store_v2" \
          > "$work/nix-valid-host-leaf-v2-imported.out" 2>&1
        "$profile/current/bin/host-install-tool" > "$work/host-install-v2-run.out"
        grep -q "host leaf package v2 executed" "$work/host-install-v2-run.out"
        grep -q "host install package v2 executed" "$work/host-install-v2-run.out"
        assert_default_profile_absent

        run_clean ${self}/bin/apm --json list --installed \
          --registry host-install-client > "$work/apm-list-installed-host-install-v2.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and any(.[]; .name == "hostinstall"
              and .registry == "host-install-client"
              and .version == "2.0.0"
              and .status == "installed")
            and any(.[]; .name == "hostleaf"
              and .registry == "host-install-client"
              and .version == "2.0.0"
              and .status == "installed")' \
          "$work/apm-list-installed-host-install-v2.json" >/dev/null
        run_clean ${self}/bin/apm --json policy hostinstall \
          > "$work/apm-policy-host-install-v2.json"
        ${pkgs.jq}/bin/jq -e \
          '.package == "hostinstall"
            and .installed == "2.0.0"
            and .candidate == "2.0.0"
            and (.versions | length == 1)
            and .versions[0].version == "2.0.0"
            and .versions[0].registry == "host-install-client"
            and .versions[0].installed == true
            and .unavailable_installed == []' \
          "$work/apm-policy-host-install-v2.json" >/dev/null
        run_clean ${self}/bin/apm --json depends hostinstall \
          > "$work/apm-depends-host-install-v2.json"
        ${pkgs.jq}/bin/jq -e \
          --arg app "$install_hash_v2" \
          --arg leaf "$install_leaf_hash_v2" \
          '.package == "hostinstall"
            and .registry == "host-install-client"
            and .installed == true
            and .tree.name == "hostinstall"
            and .tree.store_hash == $app
            and (.tree.children | any(.name == "hostleaf"
              and .version == "2.0.0"
              and .store_hash == $leaf))
            and .unique_store_paths >= 2' \
          "$work/apm-depends-host-install-v2.json" >/dev/null
        run_clean ${self}/bin/apm --json rdepends hostleaf \
          > "$work/apm-rdepends-host-leaf-v2.json"
        ${pkgs.jq}/bin/jq -e \
          --arg leaf "$install_leaf_hash_v2" \
          '.package == "hostleaf"
            and .target_versions == "2.0.0"
            and (.target_hashes | index($leaf) != null)
            and (.dependents | any(.name == "hostinstall"
              and .version == "2.0.0"))' \
          "$work/apm-rdepends-host-leaf-v2.json" >/dev/null
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
            and (.expected_nar_hash | startswith("sha256:"))
            and (.actual_nar_hash | startswith("sha256:"))' \
          "$work/apm-verify-host-install-v2.json" >/dev/null
        assert_default_profile_absent
        run_clean ${self}/bin/apm files hostinstall > "$work/apm-files-host-install-v2.out" 2>&1
        grep -q "bin/host-install-tool" "$work/apm-files-host-install-v2.out"
        run_clean ${self}/bin/apm --json files hostinstall > "$work/apm-files-host-install-v2.json"
        ${pkgs.jq}/bin/jq -e \
          'index("bin/host-install-tool") != null and index("share/host-install/payload.txt") != null' \
          "$work/apm-files-host-install-v2.json" >/dev/null

        main_home="$home"
        main_config="$config"
        main_data="$data"
        main_cache="$cache"
        main_profile_root="$profile_root"
        main_profile="$profile"
        home="$work/commit-pin-home"
        config="$work/commit-pin-config"
        data="$work/commit-pin-share"
        cache="$work/commit-pin-cache"
        profile_root="$work/commit-pin-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        install_remote_v1_tracking="commit:$(${pkgs.coreutils}/bin/printf '%s' "$install_remote_v1_commit" | ${pkgs.coreutils}/bin/cut -c1-12)"
        run_clean ${self}/bin/apm --json registry add --no-verify "file://$install_origin" \
          --name host-install-commit \
          --commit "$install_remote_v1_commit" \
          > "$work/apm-add-host-install-commit.json"
        ${pkgs.jq}/bin/jq -e \
          --arg url "file://$install_origin" \
          --arg commit "$install_remote_v1_commit" \
          --arg tracking "$install_remote_v1_tracking" \
          --arg config_path "$config/apm/registries.d/host-install-commit.toml" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-install-commit"
            and .name == "host-install-commit"
            and .url == $url
            and .priority == 500
            and .enabled == true
            and .tracking == $tracking
            and .clone == true
            and .synced == true
            and .sync_error == null
            and .packages == 3
            and .last_commit == $commit
            and .config == $config_path
            and .signing_required == false
            and .verification_disabled == true
            and .trusted_key_pinned == false' \
          "$work/apm-add-host-install-commit.json" >/dev/null
        grep -q "commit = \"$install_remote_v1_commit\"" \
          "$config/apm/registries.d/host-install-commit.toml"
        run_clean ${self}/bin/apm --json search hostinstall \
          --registry host-install-commit \
          > "$work/apm-search-host-install-commit.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].registry == "host-install-commit"
            and .[0].version == "1.0.0"' \
          "$work/apm-search-host-install-commit.json" >/dev/null
        run_clean ${self}/bin/apm --json update --registry host-install-commit \
          > "$work/apm-update-host-install-commit-current.json"
        ${pkgs.jq}/bin/jq -e \
          --arg commit "$install_remote_v1_commit" \
          --arg tracking "$install_remote_v1_tracking" \
          '.registry == "host-install-commit"
            and .updated == 0
            and (.registries | length == 1)
            and .registries[0].registry == "host-install-commit"
            and .registries[0].status == "current"
            and .registries[0].tracking == $tracking
            and .registries[0].commit == $commit' \
          "$work/apm-update-host-install-commit-current.json" >/dev/null
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-before-commit-pin.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_store" \
            > "$work/nix-delete-host-install-before-commit-pin.out" 2>&1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-before-commit-pin.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_leaf_store" \
            > "$work/nix-delete-host-leaf-before-commit-pin.out" 2>&1
        fi
        if nix_store --check-validity "$install_store" \
          > "$work/nix-valid-host-install-commit-pin-deleted.out" 2>&1; then
          cat "$work/nix-valid-host-install-commit-pin-deleted.out"
          exit 1
        fi
        if nix_store --check-validity "$install_leaf_store" \
          > "$work/nix-valid-host-leaf-commit-pin-deleted.out" 2>&1; then
          cat "$work/nix-valid-host-leaf-commit-pin-deleted.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-commit \
          --yes > "$work/apm-install-host-install-commit.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-commit"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-host-install-commit.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-commit-run.out"
        grep -q "host leaf package executed" "$work/host-install-commit-run.out"
        grep -q "host install package executed" "$work/host-install-commit-run.out"
        if grep -q "v2 executed" "$work/host-install-commit-run.out"; then
          cat "$work/host-install-commit-run.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json list --upgradable \
          --registry host-install-commit > "$work/apm-upgradable-host-install-commit.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apm-upgradable-host-install-commit.json" >/dev/null
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
        home="$work/provider-switch-home"
        config="$work/provider-switch-config"
        data="$work/provider-switch-share"
        cache="$work/provider-switch-cache"
        profile_root="$work/provider-switch-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm --json registry add --no-verify "file://$install_origin" \
          --name host-install-low \
          --commit "$install_remote_v1_commit" \
          --priority 100 > "$work/apm-add-host-install-low.json"
        ${pkgs.jq}/bin/jq -e \
          --arg commit "$install_remote_v1_commit" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-install-low"
            and .priority == 100
            and .enabled == true
            and .synced == true
            and .last_commit == $commit
            and .packages == 3' \
          "$work/apm-add-host-install-low.json" >/dev/null
        run_clean ${self}/bin/apm --json registry add --no-verify "file://$install_origin" \
          --name host-install-high \
          --branch stable \
          --priority 900 > "$work/apm-add-host-install-high.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-install-high"
            and .priority == 900
            and .enabled == true
            and .synced == true
            and (.last_commit | length == 64)
            and .packages == 3' \
          "$work/apm-add-host-install-high.json" >/dev/null
        run_clean ${self}/bin/apm --json search hostinstall \
          > "$work/apm-search-provider-priority.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].registry == "host-install-high"
            and .[0].version == "2.0.0"' \
          "$work/apm-search-provider-priority.json" >/dev/null
        run_clean ${self}/bin/apm --json policy hostinstall \
          > "$work/apm-policy-provider-priority-before-install.json"
        ${pkgs.jq}/bin/jq -e \
          '.package == "hostinstall"
            and .installed == null
            and .candidate == "2.0.0"
            and (.versions | length == 2)
            and .versions[0].version == "2.0.0"
            and .versions[0].registry == "host-install-high"
            and .versions[0].priority == 900
            and .versions[0].installed == false
            and .versions[1].version == "1.0.0"
            and .versions[1].registry == "host-install-low"
            and .versions[1].priority == 100
            and .versions[1].installed == false
            and .unavailable_installed == []' \
          "$work/apm-policy-provider-priority-before-install.json" >/dev/null
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-low \
          --yes > "$work/apm-install-host-install-low.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-low"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and .downloads.planned == 0
            and .downloads.downloaded == 0
            and .downloads.imported == 0' \
          "$work/apm-install-host-install-low.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-provider-low-run.out"
        grep -q "host leaf package executed" \
          "$work/host-install-provider-low-run.out"
        grep -q "host install package executed" \
          "$work/host-install-provider-low-run.out"
        if grep -q "v2 executed" "$work/host-install-provider-low-run.out"; then
          cat "$work/host-install-provider-low-run.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json policy hostinstall \
          > "$work/apm-policy-provider-priority-low-installed.json"
        ${pkgs.jq}/bin/jq -e \
          '.package == "hostinstall"
            and .installed == "1.0.0"
            and .candidate == "2.0.0"
            and (.versions | length == 2)
            and .versions[0].version == "2.0.0"
            and .versions[0].registry == "host-install-high"
            and .versions[0].installed == false
            and .versions[1].version == "1.0.0"
            and .versions[1].registry == "host-install-low"
            and .versions[1].installed == true
            and .unavailable_installed == []' \
          "$work/apm-policy-provider-priority-low-installed.json" >/dev/null
        run_clean ${self}/bin/apm --json upgrade hostinstall --dry-run \
          > "$work/apm-upgrade-provider-low-dry-run.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "upgrade"
            and .status == "current"
            and .requested == ["hostinstall"]
            and .exclude == []
            and .dry_run == true
            and .generation == null
            and .upgraded == 0
            and .held_back == []
            and .upgrades == []
            and .downloads.planned == 0
            and .downloads.downloaded == 0
            and .downloads.imported == 0' \
          "$work/apm-upgrade-provider-low-dry-run.json" >/dev/null
        run_clean ${self}/bin/apm --json reinstall hostinstall --dry-run \
          > "$work/apm-reinstall-provider-low-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "reinstall"
            and .status == "planned"
            and .requested == ["hostinstall"]
            and .reinstall == true
            and .dry_run == true
            and .generation == null
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-low"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.downloads.planned >= 2)
            and .downloads.downloaded == 0
            and .downloads.imported == 0
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
          "$work/apm-reinstall-provider-low-dry-run.json" >/dev/null
        run_clean ${self}/bin/apm --json reinstall hostinstall --yes \
          > "$work/apm-reinstall-provider-low.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "reinstall"
            and .status == "reinstalled"
            and .requested == ["hostinstall"]
            and .reinstall == true
            and .dry_run == false
            and .generation == 2
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-low"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
          "$work/apm-reinstall-provider-low.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-provider-low-after-reinstall.out"
        grep -q "host leaf package executed" \
          "$work/host-install-provider-low-after-reinstall.out"
        grep -q "host install package executed" \
          "$work/host-install-provider-low-after-reinstall.out"
        if grep -q "v2 executed" "$work/host-install-provider-low-after-reinstall.out"; then
          cat "$work/host-install-provider-low-after-reinstall.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-high \
          --yes > "$work/apm-install-provider-switch-high.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 3
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-high"
            and .roots[0].version == "2.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and .downloads.planned == 0
            and .downloads.downloaded == 0
            and .downloads.imported == 0' \
          "$work/apm-install-provider-switch-high.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-provider-high-run.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-install-provider-high-run.out"
        grep -q "host install package v2 executed" \
          "$work/host-install-provider-high-run.out"
        run_clean ${self}/bin/apm --json list --installed \
          > "$work/apm-installed-provider-switch-high.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and all(.[]; .registry == "host-install-high")
            and any(.[]; .name == "hostinstall"
              and .version == "2.0.0"
              and .status == "installed")
            and any(.[]; .name == "hostleaf"
              and .version == "2.0.0"
              and .status == "installed")' \
          "$work/apm-installed-provider-switch-high.json" >/dev/null
        run_clean ${self}/bin/apm --json autoremove --dry-run \
          > "$work/apm-autoremove-provider-switch-high.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "autoremove"
            and .status == "current"
            and .requested == []
            and .autoremove == true
            and .dry_run == false
            and .generation == null
            and .removed == 0
            and .explicit_removed == 0
            and .orphan_removed == 0
            and .packages == []
            and .orphans == []' \
          "$work/apm-autoremove-provider-switch-high.json" >/dev/null
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
        home="$work/provider-explicit-dep-home"
        config="$work/provider-explicit-dep-config"
        data="$work/provider-explicit-dep-share"
        cache="$work/provider-explicit-dep-cache"
        profile_root="$work/provider-explicit-dep-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm --json registry add --no-verify "file://$install_origin" \
          --name host-explicit-low \
          --commit "$install_remote_v1_commit" \
          --priority 100 > "$work/apm-add-host-explicit-low.json"
        ${pkgs.jq}/bin/jq -e \
          --arg commit "$install_remote_v1_commit" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-explicit-low"
            and .priority == 100
            and .enabled == true
            and .synced == true
            and .last_commit == $commit
            and .packages == 3' \
          "$work/apm-add-host-explicit-low.json" >/dev/null
        run_clean ${self}/bin/apm --json registry add --no-verify "file://$install_origin" \
          --name host-explicit-high \
          --branch stable \
          --priority 900 > "$work/apm-add-host-explicit-high.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "host-explicit-high"
            and .priority == 900
            and .enabled == true
            and .synced == true
            and (.last_commit | length == 64)
            and .packages == 3' \
          "$work/apm-add-host-explicit-high.json" >/dev/null
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-explicit-low \
          --yes > "$work/apm-install-host-explicit-low.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store" --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-explicit-low"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))' \
          "$work/apm-install-host-explicit-low.json" >/dev/null
        ${pkgs.jq}/bin/jq -e \
          '.apm.name == "hostleaf" and .apm.explicit == false' \
          "$profile/meta/$install_leaf_hash.json" >/dev/null
        run_clean ${self}/bin/apm --json install hostleaf \
          --registry host-explicit-low \
          --yes > "$work/apm-promote-host-explicit-leaf.json"
        ${pkgs.jq}/bin/jq -e --arg leaf "$install_leaf_store" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostleaf"]
            and .generation == 2
            and (.roots | length == 1)
            and .roots[0].name == "hostleaf"
            and .roots[0].registry == "host-explicit-low"
            and .roots[0].version == "1.0.0"
            and .roots[0].store_path == $leaf
            and .roots[0].explicit == true
            and (.closure | length == 1)
            and .closure[0].name == "hostleaf"
            and .closure[0].store_path == $leaf
            and .closure[0].explicit == true' \
          "$work/apm-promote-host-explicit-leaf.json" >/dev/null
        ${pkgs.jq}/bin/jq -e \
          '.apm.name == "hostleaf" and .apm.explicit == true' \
          "$profile/meta/$install_leaf_hash.json" >/dev/null
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-explicit-high \
          --yes > "$work/apm-switch-host-explicit-parent-high.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 3
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-explicit-high"
            and .roots[0].version == "2.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))' \
          "$work/apm-switch-host-explicit-parent-high.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-explicit-parent-high-run.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-explicit-parent-high-run.out"
        grep -q "host install package v2 executed" \
          "$work/host-explicit-parent-high-run.out"
        run_clean ${self}/bin/apm --json list --installed \
          > "$work/apm-installed-host-explicit-provider-switch.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 3
            and any(.[]; .name == "hostinstall"
              and .registry == "host-explicit-high"
              and .version == "2.0.0"
              and .status == "installed")
            and any(.[]; .name == "hostleaf"
              and .registry == "host-explicit-high"
              and .version == "2.0.0"
              and .status == "installed")
            and any(.[]; .name == "hostleaf"
              and .registry == "host-explicit-low"
              and .version == "1.0.0"
              and .status == "installed")' \
          "$work/apm-installed-host-explicit-provider-switch.json" >/dev/null
        run_clean ${self}/bin/apm --json remove hostinstall --autoremove --dry-run \
          > "$work/apm-remove-host-explicit-parent-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "remove"
            and .status == "planned"
            and .requested == ["hostinstall"]
            and .autoremove == true
            and .dry_run == true
            and .generation == null
            and .removed == 2
            and .explicit_removed == 1
            and .orphan_removed == 1
            and (.packages | length == 1)
            and .packages[0].name == "hostinstall"
            and .packages[0].registry == "host-explicit-high"
            and .packages[0].version == "2.0.0"
            and .packages[0].store_path == $store
            and .packages[0].explicit == true
            and (.orphans | length == 1)
            and .orphans[0].name == "hostleaf"
            and .orphans[0].registry == "host-explicit-high"
            and .orphans[0].version == "2.0.0"
            and .orphans[0].store_path == $leaf
            and .orphans[0].explicit == false' \
          "$work/apm-remove-host-explicit-parent-dry-run.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-explicit-parent-after-remove-dry-run.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-explicit-parent-after-remove-dry-run.out"
        grep -q "host install package v2 executed" \
          "$work/host-explicit-parent-after-remove-dry-run.out"
        run_clean ${self}/bin/apm --json remove hostinstall --autoremove --yes \
          > "$work/apm-remove-host-explicit-parent.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "remove"
            and .status == "removed"
            and .requested == ["hostinstall"]
            and .autoremove == true
            and .dry_run == false
            and .generation == 4
            and .removed == 2
            and .explicit_removed == 1
            and .orphan_removed == 1
            and (.packages | length == 1)
            and .packages[0].name == "hostinstall"
            and .packages[0].registry == "host-explicit-high"
            and .packages[0].version == "2.0.0"
            and .packages[0].store_path == $store
            and (.orphans | length == 1)
            and .orphans[0].name == "hostleaf"
            and .orphans[0].registry == "host-explicit-high"
            and .orphans[0].version == "2.0.0"
            and .orphans[0].store_path == $leaf' \
          "$work/apm-remove-host-explicit-parent.json" >/dev/null
        run_clean ${self}/bin/apm --json list --installed \
          > "$work/apm-installed-host-explicit-after-parent-remove.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostleaf"
            and .[0].registry == "host-explicit-low"
            and .[0].version == "1.0.0"
            and .[0].status == "installed"' \
          "$work/apm-installed-host-explicit-after-parent-remove.json" >/dev/null
        "$profile/current/bin/host-leaf-tool" \
          > "$work/host-explicit-leaf-after-parent-remove.out"
        grep -q "host leaf package executed" \
          "$work/host-explicit-leaf-after-parent-remove.out"
        if grep -q "v2 executed" "$work/host-explicit-leaf-after-parent-remove.out"; then
          cat "$work/host-explicit-leaf-after-parent-remove.out"
          exit 1
        fi
        run_clean ${self}/bin/apm --json autoremove --dry-run \
          > "$work/apm-autoremove-host-explicit-after-parent-remove.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "autoremove"
            and .status == "current"
            and .requested == []
            and .autoremove == true
            and .dry_run == false
            and .generation == null
            and .removed == 0
            and .explicit_removed == 0
            and .orphan_removed == 0
            and .packages == []
            and .orphans == []' \
          "$work/apm-autoremove-host-explicit-after-parent-remove.json" >/dev/null
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$main_home"
        config="$main_config"
        data="$main_data"
        cache="$main_cache"
        profile_root="$main_profile_root"
        profile="$main_profile"

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

        run_clean ${self}/bin/apm rollback --list \
          > "$work/apm-rollback-list-host-install-after-roll-forward.out" 2>&1
        grep -q "gen-1: .*hostinstall 1.0.0" \
          "$work/apm-rollback-list-host-install-after-roll-forward.out"
        grep -q "gen-3: .*hostinstall 2.0.0" \
          "$work/apm-rollback-list-host-install-after-roll-forward.out"
        grep -q "gen-3: .*current" \
          "$work/apm-rollback-list-host-install-after-roll-forward.out"
        run_clean ${self}/bin/apm --json rollback --generation 1 \
          > "$work/apm-rollback-host-install-explicit-v1.json"
        ${pkgs.jq}/bin/jq -e \
          --arg old "$install_store" \
          --arg old_leaf "$install_leaf_store" \
          --arg new "$install_store_v2" \
          --arg new_leaf "$install_leaf_store_v2" \
          '.action == "rollback"
            and .status == "rolled_back"
            and .requested_generation == 1
            and .from_generation == 3
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
              and .package.version == "2.0.0"))' \
          "$work/apm-rollback-host-install-explicit-v1.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-v1-after-explicit-rollback.out"
        grep -q "host leaf package executed" \
          "$work/host-install-v1-after-explicit-rollback.out"
        grep -q "host install package executed" \
          "$work/host-install-v1-after-explicit-rollback.out"
        if grep -q "v2 executed" "$work/host-install-v1-after-explicit-rollback.out"; then
          cat "$work/host-install-v1-after-explicit-rollback.out"
          exit 1
        fi
        assert_default_profile_absent
        run_clean ${self}/bin/apm --json rollback --generation 3 \
          > "$work/apm-rollback-host-install-explicit-v2.json"
        ${pkgs.jq}/bin/jq -e \
          --arg old "$install_store" \
          --arg old_leaf "$install_leaf_store" \
          --arg new "$install_store_v2" \
          --arg new_leaf "$install_leaf_store_v2" \
          '.action == "rollback"
            and .status == "rolled_back"
            and .requested_generation == 3
            and .from_generation == 1
            and .to_generation == 3
            and .dry_run == false
            and .generation == 3
            and (.restored | length == 2)
            and (.restored | any(.store_path == $new
              and .registry == "host-install-client"
              and .package.name == "hostinstall"
              and .package.version == "2.0.0"))
            and (.restored | any(.store_path == $new_leaf
              and .registry == "host-install-client"
              and .package.name == "hostleaf"
              and .package.version == "2.0.0"))
            and (.removed | length == 2)
            and (.removed | any(.store_path == $old
              and .registry == "host-install-client"
              and .package.name == "hostinstall"
              and .package.version == "1.0.0"))
            and (.removed | any(.store_path == $old_leaf
              and .registry == "host-install-client"
              and .package.name == "hostleaf"
              and .package.version == "1.0.0"))' \
          "$work/apm-rollback-host-install-explicit-v2.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-v2-after-explicit-roll-forward.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-install-v2-after-explicit-roll-forward.out"
        grep -q "host install package v2 executed" \
          "$work/host-install-v2-after-explicit-roll-forward.out"
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
        run_clean ${self}/bin/apm --json list --held \
          --registry host-install-client > "$work/apm-list-held-host-install.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].registry == "host-install-client"
            and .[0].version == "2.0.0"
            and (.[0].status | contains("installed"))
            and (.[0].status | contains("held"))' \
          "$work/apm-list-held-host-install.json" >/dev/null

        run_clean ${self}/bin/apm --json reinstall hostinstall --dry-run \
          > "$work/apm-reinstall-held-host-install-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "reinstall"
            and .status == "planned"
            and .requested == ["hostinstall"]
            and .reinstall == true
            and .download_only == false
            and .no_deps == false
            and .dry_run == true
            and .generation == null
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].version == "2.0.0"
            and .roots[0].registry == "host-install-client"
            and .roots[0].store_path == $store
            and .roots[0].explicit == true
            and (.downloads.planned >= 2)
            and .downloads.downloaded == 0
            and .downloads.imported == 0
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
          "$work/apm-reinstall-held-host-install-dry-run.json" >/dev/null
        "$profile/current/bin/host-install-tool" > "$work/host-install-v2-after-reinstall-dry-run.out"
        grep -q "host leaf package v2 executed" "$work/host-install-v2-after-reinstall-dry-run.out"
        grep -q "host install package v2 executed" "$work/host-install-v2-after-reinstall-dry-run.out"
        run_clean ${self}/bin/apm --json held > "$work/apm-held-host-install-after-reinstall-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].version == "2.0.0"
            and .[0].registry == "host-install-client"
            and .[0].store_path == $store' \
          "$work/apm-held-host-install-after-reinstall-dry-run.json" >/dev/null
        test "$(profile_generation_count)" = "3"
        assert_default_profile_absent

        run_clean ${self}/bin/apm --json reinstall hostinstall --yes \
          > "$work/apm-reinstall-held-host-install.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '[.downloads.paths[].store_path] as $downloaded_paths
          | .action == "reinstall"
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
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)
            and ($downloaded_paths | index($store) != null)
            and ($downloaded_paths | index($leaf) != null)' \
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

        # The consumer NAR download cache lives directly under <cache>/apm as
        # <hash>.nar.zst; producer static caches under <cache>/apm/registry-static
        # are a separate artifact that `apm clean` does not manage. Scope the
        # download-cache assertions to maxdepth 1 so they only cover what clean
        # is responsible for.
        if ! find "$cache/apm" -maxdepth 1 -name '*.nar.zst' | grep -q .; then
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
        if find "$cache/apm" -maxdepth 1 -name '*.nar.zst' | grep -q .; then
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

        run_clean ${self}/bin/apm --json remove hostinstall --autoremove --dry-run \
          > "$work/apm-remove-host-install-autoremove-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "remove"
            and .status == "planned"
            and .requested == ["hostinstall"]
            and .autoremove == true
            and .dry_run == true
            and .generation == null
            and .removed == 2
            and .explicit_removed == 1
            and .orphan_removed == 1
            and (.packages | length == 1)
            and .packages[0].name == "hostinstall"
            and .packages[0].version == "2.0.0"
            and .packages[0].registry == "host-install-client"
            and .packages[0].store_path == $store
            and .packages[0].explicit == true
            and .packages[0].held == false
            and (.orphans | length == 1)
            and .orphans[0].name == "hostleaf"
            and .orphans[0].version == "2.0.0"
            and .orphans[0].registry == "host-install-client"
            and .orphans[0].store_path == $leaf
            and .orphans[0].explicit == false' \
          "$work/apm-remove-host-install-autoremove-dry-run.json" >/dev/null
        "$profile/current/bin/host-install-tool" > "$work/host-install-v2-after-remove-dry-run.out"
        grep -q "host leaf package v2 executed" "$work/host-install-v2-after-remove-dry-run.out"
        grep -q "host install package v2 executed" "$work/host-install-v2-after-remove-dry-run.out"
        run_clean ${self}/bin/apm list --installed > "$work/apm-installed-after-remove-dry-run.out" 2>&1
        grep -q "hostinstall/host-install-client" "$work/apm-installed-after-remove-dry-run.out"
        grep -q "hostleaf/host-install-client" "$work/apm-installed-after-remove-dry-run.out"
        test "$(profile_generation_count)" = "4"
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

        auto_home="$home"
        auto_config="$config"
        auto_data="$data"
        auto_cache="$cache"
        auto_profile_root="$profile_root"
        auto_profile="$profile"
        home="$work/auto-autoremove-home"
        config="$work/auto-autoremove-config"
        data="$work/auto-autoremove-share"
        cache="$work/auto-autoremove-cache"
        profile_root="$work/auto-autoremove-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config/apm" "$data" "$cache" "$profile_root"
        cat > "$config/apm/apm.conf" << 'EOF'
        [settings]
        assume_yes = true
        auto_autoremove = true
        EOF
        run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
          --name host-install-auto-remove \
          --branch stable > "$work/apm-add-host-install-auto-remove.out" 2>&1
        grep -q "Registry 'host-install-auto-remove' added" \
          "$work/apm-add-host-install-auto-remove.out"
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-auto-remove \
          > "$work/apm-install-host-install-auto-remove.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-auto-remove"
            and .roots[0].version == "2.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-host-install-auto-remove.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-auto-remove-before-remove.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-install-auto-remove-before-remove.out"
        grep -q "host install package v2 executed" \
          "$work/host-install-auto-remove-before-remove.out"
        run_clean ${self}/bin/apm --json remove hostinstall --dry-run \
          > "$work/apm-remove-host-install-auto-remove-dry-run.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "remove"
            and .status == "planned"
            and .requested == ["hostinstall"]
            and .autoremove == true
            and .dry_run == true
            and .generation == null
            and .removed == 2
            and .explicit_removed == 1
            and .orphan_removed == 1
            and (.packages | length == 1)
            and .packages[0].name == "hostinstall"
            and .packages[0].version == "2.0.0"
            and .packages[0].registry == "host-install-auto-remove"
            and .packages[0].store_path == $store
            and .packages[0].explicit == true
            and (.orphans | length == 1)
            and .orphans[0].name == "hostleaf"
            and .orphans[0].version == "2.0.0"
            and .orphans[0].registry == "host-install-auto-remove"
            and .orphans[0].store_path == $leaf
            and .orphans[0].explicit == false' \
          "$work/apm-remove-host-install-auto-remove-dry-run.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-auto-remove-after-dry-run.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-install-auto-remove-after-dry-run.out"
        grep -q "host install package v2 executed" \
          "$work/host-install-auto-remove-after-dry-run.out"
        test "$(profile_generation_count)" = "1"
        run_clean ${self}/bin/apm --json remove hostinstall \
          > "$work/apm-remove-host-install-auto-remove.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "remove"
            and .status == "removed"
            and .requested == ["hostinstall"]
            and .autoremove == true
            and .dry_run == false
            and .generation == 2
            and .removed == 2
            and .explicit_removed == 1
            and .orphan_removed == 1
            and (.packages | length == 1)
            and .packages[0].name == "hostinstall"
            and .packages[0].version == "2.0.0"
            and .packages[0].registry == "host-install-auto-remove"
            and .packages[0].store_path == $store
            and .packages[0].explicit == true
            and (.orphans | length == 1)
            and .orphans[0].name == "hostleaf"
            and .orphans[0].version == "2.0.0"
            and .orphans[0].registry == "host-install-auto-remove"
            and .orphans[0].store_path == $leaf
            and .orphans[0].explicit == false' \
          "$work/apm-remove-host-install-auto-remove.json" >/dev/null
        run_clean ${self}/bin/apm --json list --installed \
          --registry host-install-auto-remove > "$work/apm-installed-auto-remove-empty.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apm-installed-auto-remove-empty.json" >/dev/null
        test "$(profile_generation_count)" = "2"
        assert_default_profile_absent
        rm -rf "$profile_root"
        home="$auto_home"
        config="$auto_config"
        data="$auto_data"
        cache="$auto_cache"
        profile_root="$auto_profile_root"
        profile="$auto_profile"

        bad_parallel_home="$work/bad-parallel-home"
        bad_parallel_config="$work/bad-parallel-config"
        bad_parallel_data="$work/bad-parallel-share"
        bad_parallel_cache="$work/bad-parallel-cache"
        bad_parallel_profile_root="$work/bad-parallel-profiles"
        home="$bad_parallel_home"
        config="$bad_parallel_config"
        data="$bad_parallel_data"
        cache="$bad_parallel_cache"
        profile_root="$bad_parallel_profile_root"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
          --name bad-parallel-reg \
          --branch stable > "$work/apm-add-bad-parallel-reg.out" 2>&1
        grep -q "Registry 'bad-parallel-reg' added" \
          "$work/apm-add-bad-parallel-reg.out"
        cat > "$config/apm/apm.conf" << 'EOF'
        [settings]
        parallel_downloads = 0
        EOF
        if nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-v2-before-bad-parallel.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_store_v2" \
            > "$work/nix-delete-host-install-v2-before-bad-parallel.out" 2>&1
        fi
        if nix_store --check-validity "$install_leaf_store_v2" \
          > "$work/nix-valid-host-leaf-v2-before-bad-parallel.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_leaf_store_v2" \
            > "$work/nix-delete-host-leaf-v2-before-bad-parallel.out" 2>&1
        fi
        set +e
        run_clean ${pkgs.coreutils}/bin/timeout 10s \
          ${self}/bin/apm --json install hostinstall \
          --registry bad-parallel-reg \
          --yes > "$work/apm-install-bad-parallel.json" 2>&1
        bad_parallel_status=$?
        set -e
        if test "$bad_parallel_status" = "0"; then
          cat "$work/apm-install-bad-parallel.json"
          exit 1
        fi
        if test "$bad_parallel_status" = "124"; then
          echo "apm install hung with parallel_downloads = 0"
          cat "$work/apm-install-bad-parallel.json"
          exit 1
        fi
        grep -q "parallel_downloads must be at least 1" \
          "$work/apm-install-bad-parallel.json"
        assert_default_profile_absent

        home="$auto_home"
        config="$auto_config"
        data="$auto_data"
        cache="$auto_cache"
        profile_root="$auto_profile_root"
        profile="$auto_profile"

        if nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-v2-before-orphan.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_store_v2" \
            > "$work/nix-delete-host-install-v2-before-orphan.out" 2>&1
        fi
        if nix_store --check-validity "$install_leaf_store_v2" \
          > "$work/nix-valid-host-leaf-v2-before-orphan.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_leaf_store_v2" \
            > "$work/nix-delete-host-leaf-v2-before-orphan.out" 2>&1
        fi
        home="$work/orphan-home"
        config="$work/orphan-config"
        data="$work/orphan-share"
        cache="$work/orphan-cache"
        profile_root="$work/orphan-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
          --name orphan-reg \
          --branch stable > "$work/apm-add-orphan-reg.out" 2>&1
        grep -q "Registry 'orphan-reg' added" "$work/apm-add-orphan-reg.out"
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry orphan-reg \
          --yes > "$work/apm-install-orphan-reg.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "orphan-reg"
            and .roots[0].version == "2.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-orphan-reg.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-orphan-before-remove.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-install-orphan-before-remove.out"
        grep -q "host install package v2 executed" \
          "$work/host-install-orphan-before-remove.out"
        run_clean ${self}/bin/apm --json orphans \
          > "$work/apm-orphans-before-registry-remove.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apm-orphans-before-registry-remove.json" >/dev/null
        run_clean ${self}/bin/apm --json registry remove orphan-reg \
          > "$work/apm-registry-remove-orphan-reg.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$config/apm/registries.d/orphan-reg.toml" \
          --arg local_path "$data/apm/registries/orphan-reg" \
          '.action == "registry_remove"
            and .status == "removed"
            and .registry == "orphan-reg"
            and .name == "orphan-reg"
            and .keep_local == false
            and .force == false
            and .config == $config_path
            and .config_removed == true
            and .local == $local_path
            and .local_removed == true
            and .cache_removed == true
            and .trusted_keys_removed == false
            and .orphan_command == "apm orphans"' \
          "$work/apm-registry-remove-orphan-reg.json" >/dev/null
        test ! -e "$config/apm/registries.d/orphan-reg.toml"
        test ! -e "$data/apm/registries/orphan-reg"
        test ! -e "$data/apm/remote/orphan-reg"
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-orphan-after-remove.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-install-orphan-after-remove.out"
        grep -q "host install package v2 executed" \
          "$work/host-install-orphan-after-remove.out"
        run_clean ${self}/bin/apm --json orphans \
          > "$work/apm-orphans-after-registry-remove.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and any(.[]; .name == "hostinstall"
              and .version == "2.0.0"
              and .registry == "orphan-reg"
              and .explicit == true)
            and any(.[]; .name == "hostleaf"
              and .version == "2.0.0"
              and .registry == "orphan-reg"
              and .explicit == false)' \
          "$work/apm-orphans-after-registry-remove.json" >/dev/null
        run_clean ${self}/bin/apm --json registry add --no-verify "file://$install_origin" \
          --name orphan-reg \
          --branch stable > "$work/apm-registry-reattach-orphan-reg.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$config/apm/registries.d/orphan-reg.toml" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "orphan-reg"
            and .name == "orphan-reg"
            and .tracking == "branch:stable"
            and .clone == true
            and .synced == true
            and .verification_disabled == true
            and .config == $config_path
            and .packages >= 3' \
          "$work/apm-registry-reattach-orphan-reg.json" >/dev/null
        run_clean ${self}/bin/apm --json orphans \
          > "$work/apm-orphans-after-registry-reattach.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apm-orphans-after-registry-reattach.json" >/dev/null
        run_clean ${self}/bin/apm --json verify hostinstall \
          > "$work/apm-verify-orphan-reattached.json"
        ${pkgs.jq}/bin/jq -e \
          --arg store "$install_store_v2" \
          '.package == "hostinstall"
            and .registry == "orphan-reg"
            and .version == "2.0.0"
            and .store_path == $store
            and .verified == true
            and (.expected_nar_hash | startswith("sha256:"))
            and (.actual_nar_hash | startswith("sha256:"))' \
          "$work/apm-verify-orphan-reattached.json" >/dev/null
        run_clean ${self}/bin/apm --json registry remove orphan-reg --keep-local \
          > "$work/apm-registry-remove-orphan-reg-keep-local.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$config/apm/registries.d/orphan-reg.toml" \
          --arg local_path "$data/apm/registries/orphan-reg" \
          '.action == "registry_remove"
            and .status == "removed"
            and .registry == "orphan-reg"
            and .name == "orphan-reg"
            and .keep_local == true
            and .force == false
            and .config == $config_path
            and .config_removed == true
            and .local == $local_path
            and .local_removed == false
            and .cache_removed == false
            and .trusted_keys_removed == false
            and .orphan_command == "apm orphans"' \
          "$work/apm-registry-remove-orphan-reg-keep-local.json" >/dev/null
        test ! -e "$config/apm/registries.d/orphan-reg.toml"
        test -d "$data/apm/registries/orphan-reg"
        test -d "$data/apm/remote/orphan-reg"
        run_clean ${self}/bin/apm --json orphans \
          > "$work/apm-orphans-after-registry-keep-local-remove.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 2
            and any(.[]; .name == "hostinstall"
              and .version == "2.0.0"
              and .registry == "orphan-reg"
              and .explicit == true)
            and any(.[]; .name == "hostleaf"
              and .version == "2.0.0"
              and .registry == "orphan-reg"
              and .explicit == false)' \
          "$work/apm-orphans-after-registry-keep-local-remove.json" >/dev/null
        run_clean ${self}/bin/apm --json registry add --no-verify "file://$install_origin" \
          --name orphan-reg \
          --branch stable > "$work/apm-registry-reattach-orphan-reg-after-keep-local.json"
        ${pkgs.jq}/bin/jq -e \
          --arg config_path "$config/apm/registries.d/orphan-reg.toml" \
          '.action == "registry_add"
            and .status == "added"
            and .registry == "orphan-reg"
            and .name == "orphan-reg"
            and .tracking == "branch:stable"
            and .clone == true
            and .synced == true
            and .verification_disabled == true
            and .config == $config_path
            and .packages >= 3' \
          "$work/apm-registry-reattach-orphan-reg-after-keep-local.json" >/dev/null
        run_clean ${self}/bin/apm --json orphans \
          > "$work/apm-orphans-after-keep-local-reattach.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apm-orphans-after-keep-local-reattach.json" >/dev/null
        assert_default_profile_absent

        home="$main_home"
        config="$main_config"
        data="$main_data"
        cache="$main_cache"
        profile_root="$main_profile_root"
        profile="$main_profile"
        if nix_store --check-validity "$install_store_v2" \
          > "$work/nix-valid-host-install-before-unpublish-client.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_store_v2" \
            > "$work/nix-delete-host-install-before-unpublish-client.out" 2>&1
        fi
        if nix_store --check-validity "$install_leaf_store_v2" \
          > "$work/nix-valid-host-leaf-before-unpublish-client.out" 2>&1; then
          nix_store --delete --ignore-liveness "$install_leaf_store_v2" \
            > "$work/nix-delete-host-leaf-before-unpublish-client.out" 2>&1
        fi
        home="$work/unpublish-home"
        config="$work/unpublish-config"
        data="$work/unpublish-share"
        cache="$work/unpublish-cache"
        profile_root="$work/unpublish-profiles"
        profile="$profile_root/per-user/unknown"
        mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
        run_clean ${self}/bin/apm registry add --no-verify "file://$install_origin" \
          --name host-install-retired \
          --branch stable > "$work/apm-add-host-install-retired.out" 2>&1
        grep -q "Registry 'host-install-retired' added" \
          "$work/apm-add-host-install-retired.out"
        run_clean ${self}/bin/apm --json install hostinstall \
          --registry host-install-retired \
          --yes > "$work/apm-install-host-install-retired-before-unpublish.json"
        ${pkgs.jq}/bin/jq -e --arg store "$install_store_v2" --arg leaf "$install_leaf_store_v2" \
          '.action == "install"
            and .status == "installed"
            and .requested == ["hostinstall"]
            and .generation == 1
            and (.roots | length == 1)
            and .roots[0].name == "hostinstall"
            and .roots[0].registry == "host-install-retired"
            and .roots[0].version == "2.0.0"
            and .roots[0].store_path == $store
            and (.closure | any(.name == "hostinstall" and .store_path == $store and .explicit == true))
            and (.closure | any(.name == "hostleaf" and .store_path == $leaf and .explicit == false))
            and (.downloads.planned >= 2)
            and (.downloads.downloaded >= 2)
            and (.downloads.imported >= 2)' \
          "$work/apm-install-host-install-retired-before-unpublish.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-retired-before-unpublish-run.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-install-retired-before-unpublish-run.out"
        grep -q "host install package v2 executed" \
          "$work/host-install-retired-before-unpublish-run.out"
        retired_home="$home"
        retired_config="$config"
        retired_data="$data"
        retired_cache="$cache"
        retired_profile_root="$profile_root"
        retired_profile="$profile"

        home="$main_home"
        config="$main_config"
        data="$main_data"
        cache="$main_cache"
        profile_root="$main_profile_root"
        profile="$main_profile"
        run_clean ${self}/bin/apr --json unpublish hostinstall 1.0.0 \
          --registry host-install-channel \
          --no-commit > "$work/apr-unpublish-host-install-v1.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "unpublish"
            and .registry == "host-install-channel"
            and .package == "hostinstall"
            and .version == "1.0.0"
            and .platform == null
            and .status == "updated"
            and .package_file == "packages/h/hostinstall.toml"
            and .package_file_removed == false
            and .committed == false
            and .commit_message == null' \
          "$work/apr-unpublish-host-install-v1.json" >/dev/null
        run_clean ${self}/bin/apr status --registry host-install-channel \
          > "$work/apr-status-host-install-after-unpublish-v1.out" 2>&1
        grep -q "packages/h/hostinstall.toml" \
          "$work/apr-status-host-install-after-unpublish-v1.out"
        run_clean ${self}/bin/apr --json unpublish hostinstall 1.1.0 \
          --registry host-install-channel \
          --no-commit > "$work/apr-unpublish-host-install-v11.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "unpublish"
            and .registry == "host-install-channel"
            and .package == "hostinstall"
            and .version == "1.1.0"
            and .platform == null
            and .status == "updated"
            and .package_file == "packages/h/hostinstall.toml"
            and .package_file_removed == false
            and .committed == false
            and .commit_message == null' \
          "$work/apr-unpublish-host-install-v11.json" >/dev/null
        run_clean ${self}/bin/apr --json unpublish hostinstall 2.0.0 \
          --registry host-install-channel \
          --message "retire hostinstall package" \
          --key "$work/host-install-release-key" \
          > "$work/apr-unpublish-host-install-v2.json"
        ${pkgs.jq}/bin/jq -e \
          '.action == "unpublish"
            and .registry == "host-install-channel"
            and .package == "hostinstall"
            and .version == "2.0.0"
            and .platform == null
            and .status == "removed"
            and .package_file == "packages/h/hostinstall.toml"
            and .package_file_removed == true
            and .committed == true
            and .commit_message == "retire hostinstall package"
            and (.head | length == 64)' \
          "$work/apr-unpublish-host-install-v2.json" >/dev/null
        test ! -e "$install_reg/packages/h/hostinstall.toml"
        test -f "$install_reg/store/$(printf %.2s "$install_hash")/$install_hash"
        test -f "$install_reg/store/$(printf %.2s "$install_hash_v11")/$install_hash_v11"
        test -f "$install_reg/store/$(printf %.2s "$install_hash_v2")/$install_hash_v2"
        if run_clean ${self}/bin/apr --json show hostinstall \
          --registry host-install-channel > "$work/apr-show-host-install-after-unpublish.json" 2>&1; then
          cat "$work/apr-show-host-install-after-unpublish.json"
          exit 1
        fi
        ${pkgs.jq}/bin/jq -e \
          --arg message "package 'hostinstall' not found in registry" \
          '.error | contains($message)' \
          "$work/apr-show-host-install-after-unpublish.json" >/dev/null
        run_clean ${self}/bin/apr --json packages --registry host-install-channel \
          > "$work/apr-packages-after-host-install-unpublish.json"
        ${pkgs.jq}/bin/jq -e \
          'all(.[]; .name != "hostinstall")
            and any(.[]; .name == "hostleaf" and .version == "2.0.0")' \
          "$work/apr-packages-after-host-install-unpublish.json" >/dev/null
        unpublish_head=$(git -C "$install_reg" rev-parse HEAD)
        run_clean ${self}/bin/apr --json push \
          --registry host-install-channel \
          --branch stable > "$work/apr-push-host-install-unpublish.json"
        ${pkgs.jq}/bin/jq -e \
          --arg head "$unpublish_head" \
          '.action == "push"
            and .branch == "stable"
            and .set_upstream == false
            and .force == false
            and .head == $head
            and (.branches | any(.name == "origin/stable" and .remote == true))' \
          "$work/apr-push-host-install-unpublish.json" >/dev/null

        home="$retired_home"
        config="$retired_config"
        data="$retired_data"
        cache="$retired_cache"
        profile_root="$retired_profile_root"
        profile="$retired_profile"
        run_clean ${self}/bin/apm --json update --registry host-install-retired \
          > "$work/apm-update-host-install-retired-after-unpublish.json" 2>&1 || {
          cat "$work/apm-update-host-install-retired-after-unpublish.json"
          exit 1
        }
        ${pkgs.jq}/bin/jq -e \
          --arg head "$unpublish_head" \
          '.registry == "host-install-retired"
            and .updated == 1
            and (.registries | length == 1)
            and .registries[0].registry == "host-install-retired"
            and .registries[0].status == "updated"
            and .registries[0].commit == $head
            and .registries[0].packages == 2
            and .registries[0].added == 0
            and .registries[0].updated == 2
            and .registries[0].removed == 1' \
          "$work/apm-update-host-install-retired-after-unpublish.json" >/dev/null || {
          cat "$work/apm-update-host-install-retired-after-unpublish.json"
          exit 1
        }
        run_clean ${self}/bin/apm --json search hostinstall \
          --registry host-install-retired \
          > "$work/apm-search-host-install-retired-after-unpublish.json"
        ${pkgs.jq}/bin/jq -e 'length == 0' \
          "$work/apm-search-host-install-retired-after-unpublish.json" >/dev/null
        run_clean ${self}/bin/apm policy hostinstall \
          > "$work/apm-policy-host-install-retired-after-unpublish.out" 2>&1
        grep -q "Installed: 2.0.0" \
          "$work/apm-policy-host-install-retired-after-unpublish.out"
        grep -q "Candidate: (none)" \
          "$work/apm-policy-host-install-retired-after-unpublish.out"
        grep -q "installed, unavailable" \
          "$work/apm-policy-host-install-retired-after-unpublish.out"
        run_clean ${self}/bin/apm --json policy hostinstall \
          > "$work/apm-policy-host-install-retired-after-unpublish.json"
        ${pkgs.jq}/bin/jq -e \
          '.package == "hostinstall"
            and .installed == "2.0.0"
            and .candidate == null
            and .versions == []
            and (.unavailable_installed | length == 1)
            and .unavailable_installed[0].version == "2.0.0"
            and .unavailable_installed[0].registry == "host-install-retired"' \
          "$work/apm-policy-host-install-retired-after-unpublish.json" >/dev/null
        run_clean ${self}/bin/apm --json search hostinstall --installed \
          > "$work/apm-search-installed-host-install-retired-after-unpublish.json"
        ${pkgs.jq}/bin/jq -e \
          'length == 1
            and .[0].name == "hostinstall"
            and .[0].registry == "host-install-retired"
            and .[0].version == "2.0.0"' \
          "$work/apm-search-installed-host-install-retired-after-unpublish.json" >/dev/null
        run_clean ${self}/bin/apm --json source hostinstall --show-drv \
          > "$work/apm-source-host-install-retired-after-unpublish.json"
        ${pkgs.jq}/bin/jq -e \
          --arg source "$install_drv_v2" \
          --arg store "$install_store_v2" \
          '.package == "hostinstall"
            and .registry == "host-install-retired"
            and .source_drv == $source
            and (.source_nar_hash | startswith("sha256-"))
            and .installed == true
            and .installed_store_path == $store' \
          "$work/apm-source-host-install-retired-after-unpublish.json" >/dev/null
        "$profile/current/bin/host-install-tool" \
          > "$work/host-install-retired-after-unpublish-run.out"
        grep -q "host leaf package v2 executed" \
          "$work/host-install-retired-after-unpublish-run.out"
        grep -q "host install package v2 executed" \
          "$work/host-install-retired-after-unpublish-run.out"
        assert_default_profile_absent
        assert_default_system_config_unused

        mkdir -p "$out"
        echo "PASS" > "$out/result"
      '';
    };
  in
    pkgs.mkDerivation {
      pname = "aos-host-apr-apm-command-surface";
      version = "0";
      src = null;

      buildDeps = hostAprApmCommandSurfaceDeps;

      phases = [
        {
          name = "check";
          script = ''
            ${hostAprApmCommandSurfaceScript}/bin/aos-host-apr-apm-command-surface
          '';
        }
      ];
    };

  host-apr-key-retirement-http = pkgs.mkDerivation {
    pname = "aos-host-apr-key-retirement-http";
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

          work="$TMPDIR/aos-host-key-retirement-http"
          home="$work/home"
          config="$work/config"
          data="$work/share"
          cache="$work/cache"
          profile_root="$work/profiles"
          aos_root="$work/aos-root"
          store_dir="$aos_root/store"
          state_dir="$aos_root/var/nix"
          nix_conf="$work/nix-conf"
          port="18139"
          server_pid=""
          mkdir -p "$home" "$config" "$data" "$cache" "$cache/nix" "$profile_root" "$store_dir" "$state_dir/db" "$state_dir/gcroots" "$state_dir/log/nix" "$nix_conf"
          cat > "$nix_conf/nix.conf" << NIXCONF
          experimental-features = nix-command
          sandbox = false
          substituters =
          NIXCONF
          # Keep harness tracing out of command output files that intentionally
          # capture stderr with 2>&1.
          exec 3>&2

          dump_recent_work_files() {
            if ! test -d "$work"; then
              return
            fi
            printf '\nRecent host APR key-retirement logs:\n' >&2
            for path in $(${pkgs.findutils}/bin/find "$work" -maxdepth 1 -type f -printf '%T@ %p\n' | ${pkgs.coreutils}/bin/sort -nr | ${pkgs.coreutils}/bin/head -20 | ${pkgs.coreutils}/bin/cut -d ' ' -f2-); do
              printf '\n--- %s ---\n' "$path" >&2
              ${pkgs.coreutils}/bin/tail -n 80 "$path" >&2 || true
            done
          }

          cleanup() {
            status=$?
            if test "$status" -ne 0; then
              printf '\nhost APR key-retirement HTTP workflow failed with exit %s\n' "$status" >&2
              dump_recent_work_files
            fi
            if test -n "$server_pid"; then
              kill "$server_pid" 2>/dev/null || true
              wait "$server_pid" 2>/dev/null || true
            fi
          }
          trap cleanup EXIT

          print_command() {
            if test "$#" -eq 0; then
              printf '<empty>\n'
              return
            fi
            printf '%s' "$1"
            shift
            for arg in "$@"; do
              printf ' %s' "$arg"
            done
            printf '\n'
          }

          log_command() {
            {
              printf '>>> '
              print_command "$@"
            } >&3
            {
              printf '>>> '
              print_command "$@"
            } >> "$work/commands.log"
          }

          run_clean() {
            log_command "$@"
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
              GIT_AUTHOR_NAME="Host Key Retirement Test" \
              GIT_AUTHOR_EMAIL="host-key-retirement@example.invalid" \
              GIT_COMMITTER_NAME="Host Key Retirement Test" \
              GIT_COMMITTER_EMAIL="host-key-retirement@example.invalid" \
              PATH="${pkgs.coreutils}/bin:${pkgs.findutils}/bin:${pkgs.git}/bin:${pkgs.nix}/bin:${pkgs.zstd}/bin" \
              "$@"
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

          cat > "$work/build-package.sh" << SCRIPT
          set -eu
          ${pkgs.coreutils}/bin/mkdir -p "\$out/bin"
          {
            printf '%s\n' '#!${pkgs.bash}/bin/bash'
            printf '%s\n' 'printf "host key retirement package executed\n"'
          } > "\$out/bin/host-key-retirement-tool"
          ${pkgs.coreutils}/bin/chmod +x "\$out/bin/host-key-retirement-tool"
          SCRIPT
          cat > "$work/package.nix" << NIX
          derivation {
            name = "hostkeyresign-1.0.0";
            system = "x86_64-linux";
            builder = "${pkgs.bash}/bin/bash";
            args = [ ./build-package.sh ];
          }
          NIX
          store_path=$(nix_build "$work/package.nix" --no-out-link)

          ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -f "$work/initial-release-key"
          public_key=$(${pkgs.coreutils}/bin/cut -d ' ' -f2 < "$work/initial-release-key.pub")
          trust_key="host-keyresign:Ed25519:$public_key"
          run_clean ${self}/bin/apr create host-keyresign \
            --trust-key "$trust_key" \
            --trust-key-id initial \
            --key "$work/initial-release-key" \
            > "$work/apr-create-host-keyresign.out" 2>&1
          reg="$data/apm/registries/host-keyresign"
          run_clean ${self}/bin/apm registry add --no-verify "file://$reg" \
            --name host-keyresign \
            --no-clone > "$work/apm-add-host-keyresign-config.out" 2>&1
          run_clean ${self}/bin/apr keys generate next \
            --registry host-keyresign \
            --add \
            --key "$work/initial-release-key" \
            > "$work/apr-keys-generate-next.out" 2>&1
          host_keyresign_next=$(grep -o 'host-keyresign:Ed25519:[A-Za-z0-9+/=]*' \
            "$work/apr-keys-generate-next.out" | head -1)
          grep -q "$host_keyresign_next" "$reg/keys.toml"
          run_clean ${self}/bin/apr --json release 1.0.0 \
            --registry host-keyresign \
            --store-path "$store_path" \
            --name hostkeyresign \
            --description "Host key retirement re-sign fixture" \
            --license MIT \
            --maintainer host@example.invalid \
            --key "$work/initial-release-key" \
            > "$work/apr-release-host-keyresign.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "release"
              and .status == "released"
              and .registry == "host-keyresign"
              and .version == "1.0.0"' \
            "$work/apr-release-host-keyresign.json" >/dev/null
          initial_tag=$(git -C "$reg" rev-parse '1.0.0^{tag}')
          run_clean ${self}/bin/apr sign 1.0.0 \
            --registry host-keyresign \
            --key-id next \
            > "$work/apr-sign-next.out" 2>&1
          next_tag=$(git -C "$reg" rev-parse '1.0.0^{tag}')
          test "$next_tag" != "$initial_tag"

          # The consumer fetches this registry over dumb HTTP; refresh the
          # server-info advertisement so info/refs lists the current branch and
          # the re-signed 1.0.0 tag (and packed objects) the TUF root verifies
          # against.
          run_clean ${pkgs.git}/bin/git -C "$reg" update-server-info \
            > "$work/git-update-server-info.out" 2>&1
          PYTHONUNBUFFERED=1 ${pkgs.python3}/bin/python3 -m http.server "$port" \
            --bind 127.0.0.1 --directory "$data/apm/registries" \
            > "$work/http-server.log" 2>&1 &
          server_pid=$!
          ${pkgs.coreutils}/bin/sleep 1
          if ! kill -0 "$server_pid" 2>/dev/null; then
            cat "$work/http-server.log"
            exit 1
          fi

          producer_home="$home"
          producer_config="$config"
          producer_data="$data"
          producer_cache="$cache"
          producer_profile_root="$profile_root"

          home="$work/new-key-tag-client-home"
          config="$work/new-key-tag-client-config"
          data="$work/new-key-tag-client-share"
          cache="$work/new-key-tag-client-cache"
          profile_root="$work/new-key-tag-client-profiles"
          new_key_tag_home="$home"
          new_key_tag_config="$config"
          new_key_tag_data="$data"
          new_key_tag_cache="$cache"
          new_key_tag_profile_root="$profile_root"
          mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
          run_clean ${self}/bin/apm registry add "http://127.0.0.1:$port/host-keyresign/.git" \
            --name host-keyresign \
            --tag 1.0.0 \
            --trust-key "$trust_key" \
            > "$work/apm-add-host-keyresign-new-key-tag.out" 2>&1
          grep -q "Registry 'host-keyresign' added" \
            "$work/apm-add-host-keyresign-new-key-tag.out"
          run_clean ${self}/bin/apm search hostkeyresign \
            --registry host-keyresign \
            > "$work/apm-search-host-keyresign-new-key-tag.out" 2>&1
          grep -q "hostkeyresign/host-keyresign 1.0.0" \
            "$work/apm-search-host-keyresign-new-key-tag.out"
          new_key_tag_trust_file="$config/apm/trusted-keys.d/host-keyresign.pub"
          grep -q "$trust_key" "$new_key_tag_trust_file"
          grep -q "$host_keyresign_next" "$new_key_tag_trust_file"
          grep -q 'last_roster_commit = "' \
            "$config/apm/registries.d/host-keyresign.toml"

          home="$work/new-key-version-client-home"
          config="$work/new-key-version-client-config"
          data="$work/new-key-version-client-share"
          cache="$work/new-key-version-client-cache"
          profile_root="$work/new-key-version-client-profiles"
          new_key_version_home="$home"
          new_key_version_config="$config"
          new_key_version_data="$data"
          new_key_version_cache="$cache"
          new_key_version_profile_root="$profile_root"
          mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
          run_clean ${self}/bin/apm registry add "http://127.0.0.1:$port/host-keyresign/.git" \
            --name host-keyresign \
            --version '^1.0' \
            --trust-key "$trust_key" \
            > "$work/apm-add-host-keyresign-new-key-version.out" 2>&1
          grep -q "Registry 'host-keyresign' added" \
            "$work/apm-add-host-keyresign-new-key-version.out"
          run_clean ${self}/bin/apm search hostkeyresign \
            --registry host-keyresign \
            > "$work/apm-search-host-keyresign-new-key-version.out" 2>&1
          grep -q "hostkeyresign/host-keyresign 1.0.0" \
            "$work/apm-search-host-keyresign-new-key-version.out"
          new_key_version_trust_file="$config/apm/trusted-keys.d/host-keyresign.pub"
          grep -q "$trust_key" "$new_key_version_trust_file"
          grep -q "$host_keyresign_next" "$new_key_version_trust_file"
          grep -q 'last_roster_commit = "' \
            "$config/apm/registries.d/host-keyresign.toml"

          home="$producer_home"
          config="$producer_config"
          data="$producer_data"
          cache="$producer_cache"
          profile_root="$producer_profile_root"

          run_clean ${self}/bin/apr keys retire next \
            --registry host-keyresign \
            --vouched-by initial \
            --reason "rotation complete" \
            --key "$work/initial-release-key" \
            > "$work/apr-keys-retire-next.out" 2>&1
          grep -q "Retired signing key 'next'" "$work/apr-keys-retire-next.out"
          resigned_tag=$(git -C "$reg" rev-parse '1.0.0^{tag}')
          test "$resigned_tag" != "$next_tag"

          git ls-remote "http://127.0.0.1:$port/host-keyresign/.git" \
            "refs/tags/1.0.0" > "$work/git-ls-remote-host-keyresign.out" 2>&1 || {
            cat "$work/git-ls-remote-host-keyresign.out"
            exit 1
          }
          grep -q "$resigned_tag" "$work/git-ls-remote-host-keyresign.out" || {
            cat "$work/git-ls-remote-host-keyresign.out"
            exit 1
          }

          home="$new_key_tag_home"
          config="$new_key_tag_config"
          data="$new_key_tag_data"
          cache="$new_key_tag_cache"
          profile_root="$new_key_tag_profile_root"
          run_clean ${self}/bin/apm update --registry host-keyresign \
            > "$work/apm-update-host-keyresign-new-key-tag-retired.out" 2>&1
          grep -q "$trust_key" "$new_key_tag_trust_file"
          if grep -q "$host_keyresign_next" "$new_key_tag_trust_file"; then
            cat "$new_key_tag_trust_file"
            exit 1
          fi

          home="$new_key_version_home"
          config="$new_key_version_config"
          data="$new_key_version_data"
          cache="$new_key_version_cache"
          profile_root="$new_key_version_profile_root"
          run_clean ${self}/bin/apm update --registry host-keyresign \
            > "$work/apm-update-host-keyresign-new-key-version-retired.out" 2>&1
          grep -q "$trust_key" "$new_key_version_trust_file"
          if grep -q "$host_keyresign_next" "$new_key_version_trust_file"; then
            cat "$new_key_version_trust_file"
            exit 1
          fi

          home="$producer_home"
          config="$producer_config"
          data="$producer_data"
          cache="$producer_cache"
          profile_root="$producer_profile_root"

          producer_home="$home"
          producer_config="$config"
          producer_data="$data"
          producer_cache="$cache"
          producer_profile_root="$profile_root"

          # Retiring 'next' revokes it in the roster and re-signs the release
          # tags, but the TUF root sealed at 1.0.0 still lists 'next' with a
          # 2-of-2 threshold, so a fresh consumer cannot bootstrap that release
          # with only the surviving key. Rotating the root happens at the next
          # release: re-seal a 1.1.0 release whose new 1-of-1 root is co-signed
          # by the retiring key (--rotate-from), authorizing the transition off
          # the old root. Fresh consumers then bootstrap the clean root.
          cat > "$work/build-package-v11.sh" << SCRIPT
          set -eu
          ${pkgs.coreutils}/bin/mkdir -p "\$out/bin"
          {
            printf '%s\n' '#!${pkgs.bash}/bin/bash'
            printf '%s\n' 'printf "host key retirement package 1.1.0 executed\n"'
          } > "\$out/bin/host-key-retirement-tool"
          ${pkgs.coreutils}/bin/chmod +x "\$out/bin/host-key-retirement-tool"
          SCRIPT
          cat > "$work/package-v11.nix" << NIX
          derivation {
            name = "hostkeyresign-1.1.0";
            system = "x86_64-linux";
            builder = "${pkgs.bash}/bin/bash";
            args = [ ./build-package-v11.sh ];
          }
          NIX
          store_path_v11=$(nix_build "$work/package-v11.nix" --no-out-link)
          run_clean ${self}/bin/apr --json release 1.1.0 \
            --registry host-keyresign \
            --store-path "$store_path_v11" \
            --name hostkeyresign \
            --description "Host key retirement re-seal fixture" \
            --license MIT \
            --maintainer host@example.invalid \
            --previous 1.0.0 \
            --key "$work/initial-release-key" \
            --rotate-from "$config/apm/keys/host-keyresign-next.key" \
            > "$work/apr-release-host-keyresign-v11.json"
          ${pkgs.jq}/bin/jq -e \
            '.action == "release"
              and .status == "released"
              and .registry == "host-keyresign"
              and .version == "1.1.0"' \
            "$work/apr-release-host-keyresign-v11.json" >/dev/null
          # The rotated 1-of-1 root must drop 'next' entirely.
          git -C "$reg" show HEAD:tuf/root.json \
            > "$work/host-keyresign-rotated-root.json"
          if grep -q "$host_keyresign_next" "$work/host-keyresign-rotated-root.json"; then
            cat "$work/host-keyresign-rotated-root.json"
            exit 1
          fi
          run_clean ${pkgs.git}/bin/git -C "$reg" update-server-info \
            > "$work/git-update-server-info-v11.out" 2>&1

          home="$work/tag-client-home"
          config="$work/tag-client-config"
          data="$work/tag-client-share"
          cache="$work/tag-client-cache"
          profile_root="$work/tag-client-profiles"
          mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
          run_clean ${self}/bin/apm registry add "http://127.0.0.1:$port/host-keyresign/.git" \
            --name host-keyresign \
            --tag 1.1.0 \
            --trust-key "$trust_key" \
            > "$work/apm-add-host-keyresign-tag.out" 2>&1
          grep -q "Registry 'host-keyresign' added" \
            "$work/apm-add-host-keyresign-tag.out"
          run_clean ${self}/bin/apm search hostkeyresign \
            --registry host-keyresign \
            > "$work/apm-search-host-keyresign-tag.out" 2>&1
          grep -q "hostkeyresign/host-keyresign 1.1.0" \
            "$work/apm-search-host-keyresign-tag.out"
          tag_trust_file="$config/apm/trusted-keys.d/host-keyresign.pub"
          grep -q "$trust_key" "$tag_trust_file"
          if grep -q "$host_keyresign_next" "$tag_trust_file"; then
            cat "$tag_trust_file"
            exit 1
          fi
          grep -q 'last_roster_commit = "' \
            "$config/apm/registries.d/host-keyresign.toml"

          home="$work/version-client-home"
          config="$work/version-client-config"
          data="$work/version-client-share"
          cache="$work/version-client-cache"
          profile_root="$work/version-client-profiles"
          mkdir -p "$home" "$config" "$data" "$cache" "$profile_root"
          run_clean ${self}/bin/apm registry add "http://127.0.0.1:$port/host-keyresign/.git" \
            --name host-keyresign \
            --version '^1.1' \
            --trust-key "$trust_key" \
            > "$work/apm-add-host-keyresign-version.out" 2>&1
          grep -q "Registry 'host-keyresign' added" \
            "$work/apm-add-host-keyresign-version.out"
          run_clean ${self}/bin/apm search hostkeyresign \
            --registry host-keyresign \
            > "$work/apm-search-host-keyresign-version.out" 2>&1
          grep -q "hostkeyresign/host-keyresign 1.1.0" \
            "$work/apm-search-host-keyresign-version.out"
          version_trust_file="$config/apm/trusted-keys.d/host-keyresign.pub"
          grep -q "$trust_key" "$version_trust_file"
          if grep -q "$host_keyresign_next" "$version_trust_file"; then
            cat "$version_trust_file"
            exit 1
          fi
          grep -q 'last_roster_commit = "' \
            "$config/apm/registries.d/host-keyresign.toml"

          home="$producer_home"
          config="$producer_config"
          data="$producer_data"
          cache="$producer_cache"
          profile_root="$producer_profile_root"

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

  # ---------------------------------------------------------------------------
  # apr origin upload → s3:// against a real SigV4 endpoint (garage)
  # ---------------------------------------------------------------------------
  # The s3:// scheme of the cache/upload backend (crates/aos-cache/src/
  # backend/s3.rs over crates/aos-net/src/protocol/s3.rs, aws-sdk-s3 with
  # a custom endpoint + forced path style) had no end-to-end coverage —
  # every other test uploads via file:// and reads via http://. This test
  # stands up a single-node garage, uploads a registry's static origin
  # surface plus a cache dir via `apr origin upload s3://...`, and reads
  # the objects back through garage's web endpoint to verify bytes.
  origin-upload-s3 = testing.mkVMTest {
    name = "aos-origin-upload-s3";
    rootfsDeps = [
      self
      pkgs.garage
      pkgs.git
      pkgs.curl
      pkgs.coreutils
      pkgs.diffutils # cmp — NOT part of coreutils
      pkgs.gawk
      pkgs.grep
      pkgs.iproute2
    ];
    memory = 2048;
    testScript = ''
      set -eu
      ${pkgs.iproute2}/sbin/ip link set lo up || true
      ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

      export HOME=/tmp
      export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
      export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test

      GARAGE=${pkgs.garage}/bin/garage
      CFG=/tmp/garage.toml

      echo "==> Starting single-node garage"
      mkdir -p /tmp/garage/meta /tmp/garage/data
      cat > "$CFG" << 'EOF'
      metadata_dir = "/tmp/garage/meta"
      data_dir = "/tmp/garage/data"
      db_engine = "sqlite"
      replication_factor = 1

      rpc_bind_addr = "127.0.0.1:3901"
      rpc_public_addr = "127.0.0.1:3901"
      rpc_secret = "1799bccfd7411eddcf9ebd316bc1f5287ad12a68094e1c6ac6abde7e6feae1ec"

      [s3_api]
      s3_region = "garage"
      api_bind_addr = "127.0.0.1:3900"
      root_domain = ".s3.garage.localhost"

      [s3_web]
      bind_addr = "127.0.0.1:3902"
      root_domain = ".web.garage.localhost"
      index = "index.html"
      EOF

      "$GARAGE" -c "$CFG" server > /tmp/garage.log 2>&1 &
      GARAGE_PID=$!

      ready=0
      for _i in $(seq 1 60); do
        if "$GARAGE" -c "$CFG" status > /tmp/garage-status.out 2>&1; then
          ready=1
          break
        fi
        sleep 1
      done
      if [ "$ready" -ne 1 ]; then
        echo "FAIL: garage did not come up"
        cat /tmp/garage.log
        exit 1
      fi

      echo "==> Single-node layout"
      NODE_ID=$("$GARAGE" -c "$CFG" node id -q 2>/dev/null | cut -d@ -f1)
      test -n "$NODE_ID" || { echo "FAIL: no garage node id"; exit 1; }
      "$GARAGE" -c "$CFG" layout assign -z dc1 -c 1G "$NODE_ID"
      "$GARAGE" -c "$CFG" layout apply --version 1

      echo "==> Bucket + key"
      "$GARAGE" -c "$CFG" key create test-key > /tmp/garage-key.out
      cat /tmp/garage-key.out
      AWS_ACCESS_KEY_ID=$(awk -F': *' '/Key ID/ {print $2}' /tmp/garage-key.out | tr -d ' ')
      AWS_SECRET_ACCESS_KEY=$(awk -F': *' '/Secret key/ {print $2}' /tmp/garage-key.out | tr -d ' ')
      test -n "$AWS_ACCESS_KEY_ID" || { echo "FAIL: no access key id"; exit 1; }
      test -n "$AWS_SECRET_ACCESS_KEY" || { echo "FAIL: no secret key"; exit 1; }
      export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

      "$GARAGE" -c "$CFG" bucket create test-bucket
      "$GARAGE" -c "$CFG" bucket allow --read --write --owner test-bucket --key test-key
      # Website access gives us an unauthenticated HTTP read path on :3902
      # for byte-level verification of what the SigV4 upload stored.
      "$GARAGE" -c "$CFG" bucket website --allow test-bucket

      echo "==> Registry + handmade static cache dir"
      ${self}/bin/apr create s3reg

      mkdir -p /tmp/fake-cache/nar
      printf 'StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n' \
        > /tmp/fake-cache/nix-cache-info
      {
        printf 'StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture-1.0\n'
        printf 'URL: nar/fixture.nar\n'
        printf 'Compression: none\n'
        printf 'NarHash: sha256:0000000000000000000000000000000000000000000000000000000000000000\n'
        printf 'NarSize: 128\n'
      } > /tmp/fake-cache/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo
      head -c 128 /dev/zero > /tmp/fake-cache/nar/fixture.nar

      echo "==> apr origin upload over s3://"
      ${self}/bin/apr origin upload \
        --registry s3reg \
        --cache-dir /tmp/fake-cache \
        --upload-url s3://test-bucket/origin \
        --s3-region garage \
        --s3-endpoint http://127.0.0.1:3900 \
        2>&1 | tee /tmp/upload.out
      grep -q "Uploaded" /tmp/upload.out || { echo "FAIL: upload not confirmed"; exit 1; }

      echo "==> Read objects back through the web endpoint"
      webget() {
        curl -sf -H "Host: test-bucket.web.garage.localhost" \
          "http://127.0.0.1:3902/$1"
      }

      webget origin/HEAD > /tmp/back-HEAD
      grep -q . /tmp/back-HEAD || { echo "FAIL: HEAD empty"; exit 1; }

      webget origin/info/refs > /tmp/back-refs
      grep -q refs/heads /tmp/back-refs || { echo "FAIL: info/refs missing heads"; exit 1; }

      assert_same_bytes() {
        if ! cmp "$1" "$2"; then
          echo "FAIL: $3 bytes differ"
          echo "--- got:"; od -c "$1" | head -10
          echo "--- want:"; od -c "$2" | head -10
          exit 1
        fi
      }

      webget origin/nix-cache-info > /tmp/back-cache-info
      assert_same_bytes /tmp/back-cache-info /tmp/fake-cache/nix-cache-info nix-cache-info

      webget origin/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo > /tmp/back-narinfo
      assert_same_bytes /tmp/back-narinfo \
        /tmp/fake-cache/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo narinfo

      webget origin/nar/fixture.nar > /tmp/back-nar
      assert_same_bytes /tmp/back-nar /tmp/fake-cache/nar/fixture.nar NAR

      kill "$GARAGE_PID" 2>/dev/null || true
      echo "==> All s3 origin upload tests passed"
    '';
  };
}
