##! aos-fuse-transport — Narrow owning libfuse transport for immutable views.
##!
##! The shared library borrows one inherited, already-connected FUSE descriptor
##! and owns a duplicate for a synchronous single-threaded session. Its
##! versioned C ABI carries copied scalars and caller-bounded buffers only;
##! libfuse remains the sole kernel-wire parser and reply authority. Mounting
##! and descriptor
##! acquisition remain privileged broker responsibilities.
{
  lib,
  mkDerivation,
  aos-fuse3,
  linux-headers,
  sed,
}: let
  source = ./aos-fuse-transport;
in
  mkDerivation {
    pname = "aos-fuse-transport";
    version = "0.1.0";

    src = source;
    buildDeps = [linux-headers sed];
    runtimeDeps = [aos-fuse3];
    propagatedDeps = [];

    outputChecks = {
      out = {
        disallowedReferences = [linux-headers sed];
      };
    };

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R $src source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "build";
        script = ''
          $CC -std=c17 -O2 -fPIC \
            -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
            -I. -I${aos-fuse3}/include/fuse3 \
            -shared -Wl,-soname,libaos-fuse-transport.so.1 \
            transport.c -L${aos-fuse3}/lib -lfuse3 \
            -o libaos-fuse-transport.so.1.0.0
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/include $out/lib/pkgconfig
          cp aos_fuse_transport.h $out/include/
          cp libaos-fuse-transport.so.1.0.0 $out/lib/
          ln -s libaos-fuse-transport.so.1.0.0 \
            $out/lib/libaos-fuse-transport.so.1
          ln -s libaos-fuse-transport.so.1 \
            $out/lib/libaos-fuse-transport.so

          sed "s|@PREFIX@|$out|g" \
            ${./aos-fuse-transport/aos-fuse-transport.pc.in} \
            > $out/lib/pkgconfig/aos-fuse-transport.pc
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: let
      probeSource = builtins.path {
        path = ../../tests/sandbox/fuse-transport-probe.c;
        name = "aos-fuse-transport-probe.c";
      };
      retainedProbeSource = builtins.path {
        path = ../../tests/sandbox/fuse-retained-idmap-probe.c;
        name = "aos-fuse-retained-idmap-probe.c";
      };
      rustWorker = pkgs.mkCargoPackage {
        pname = "aos-filesystem-fuse-kernel-worker";
        version = "0.0.0";
        src = import ../tools/aos/_workspace-source.nix {inherit lib;};
        cargoDeps = pkgs.aos.passthru.cargoDeps;
        cargoRoot = "crates";
        cargoFlags = "-p aos-filesystem-fuse-kernel-worker --bin aos-filesystem-fuse-kernel-worker";
        # This executable requires inherited real mount descriptors; its test
        # runs below inside the VM rather than in the package build sandbox.
        doCheck = false;
        buildDeps = [pkgs.pkg-config pkgs.aos-fuse3];
        runtimeDeps = [self];
        cargoEnv.RUSTFLAGS = "-C link-arg=-Wl,-rpath,${self}/lib";
      };

      # Capture the shared scripts unchanged for parser/control-flow unit
      # fixtures. Tool output doubles do not prove real ELF or VM behavior.
      fixtureChecks = import ../../lib/testing/integration.nix {
        inherit lib pkgs;
        mkVMTest = args: args.testScript;
      };
      fixturePackage = {
        pname = "library-check-fixture";
        __toString = _: "./fixture";
      };
      sonameFixtureScript = fixtureChecks.mkSONAMECheck {
        pkg = fixturePackage;
        libs = ["library.so"];
        expectedSONAMEs."library.so" = "library.so.1";
      };
      symbolFixtureScript = fixtureChecks.mkSymbolCheck {
        pkg = fixturePackage;
        libName = "library.so";
        symbols = ["required_symbol"];
      };
    in {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libaos-fuse-transport.so"];
        expectedSONAMEs."libaos-fuse-transport.so" = "libaos-fuse-transport.so.1";
      };

      symbols = testing.mkSymbolCheck {
        pkg = self;
        libName = "libaos-fuse-transport.so";
        symbols = [
          "aos_fuse_transport_run"
          "aos_fuse_transport_run_fallback_v2"
          "aos_fuse_transport_prepare_v1"
          "aos_fuse_transport_continue_prepared_v1"
          "aos_fuse_transport_continue_prepared_v3"
          "aos_fuse_transport_destroy_prepared_v1"
        ];
      };

      library-check-fixtures = pkgs.mkDerivation {
        pname = "aos-fuse-transport-library-check-fixtures";
        version = "0";
        src = null;
        buildDeps = [pkgs.bash pkgs.coreutils pkgs.grep pkgs.sed];
        phases = [
          {
            name = "check";
            script = ''
              set -eu
              cat > soname-check.bash << 'SONAME_SCRIPT'
              ${sonameFixtureScript}
              SONAME_SCRIPT
              cat > symbol-check.bash << 'SYMBOL_SCRIPT'
              ${symbolFixtureScript}
              SYMBOL_SCRIPT

              # Exported functions supply only inspection output and status;
              # the production script still owns all checking decisions.
              readelf() {
                printf '%s\n' "$TOOL_OUTPUT"
                return "$TOOL_STATUS"
              }

              nm() {
                printf '%s\n' "$TOOL_OUTPUT"
                return "$TOOL_STATUS"
              }

              export -f readelf nm
              export TOOL_OUTPUT TOOL_STATUS
              mkdir -p fixture/lib
              CASES=0

              run_fixture() {
                LABEL="$1"
                SCRIPT="$2"
                EXPECTED="$3"
                MARKER="$4"
                TOOL_OUTPUT="$5"
                TOOL_STATUS="$6"

                if ${pkgs.bash}/bin/bash -e "$SCRIPT" > "$LABEL.log" 2>&1; then
                  STATUS=0
                else
                  STATUS=$?
                fi
                if { [ "$EXPECTED" = pass ] && [ "$STATUS" -ne 0 ]; } ||
                   { [ "$EXPECTED" = fail ] && [ "$STATUS" -eq 0 ]; }; then
                  cat "$LABEL.log"
                  echo "unexpected exit status $STATUS for $LABEL" >&2
                  exit 1
                fi
                if ! ${pkgs.grep}/bin/grep -Fq "$MARKER" "$LABEL.log"; then
                  cat "$LABEL.log"
                  echo "missing expected diagnostic for $LABEL" >&2
                  exit 1
                fi
                CASES=$((CASES + 1))
                printf 'PASS unit fixture: %s\n' "$LABEL"
              }

              run_fixture missing-soname soname-check.bash fail 'not found' "" 0
              run_fixture missing-symbol symbol-check.bash fail 'not found' "" 0
              touch fixture/lib/library.so

              GOOD_SONAME='0x000000000000000e (SONAME) Library soname: [library.so.1]'
              run_fixture failed-readelf soname-check.bash fail 'readelf failed' "$GOOD_SONAME" 1
              run_fixture absent-soname soname-check.bash fail 'has no SONAME' "" 0
              run_fixture wrong-soname soname-check.bash fail 'expected library.so.1' \
                '0x000000000000000e (SONAME) Library soname: [library.so.10]' 0
              run_fixture exact-soname soname-check.bash pass 'All SONAME checks passed' "$GOOD_SONAME" 0

              run_fixture failed-nm symbol-check.bash fail 'nm failed' 'required_symbol T 100 20' 1
              run_fixture prefix-symbol symbol-check.bash fail 'missing symbol required_symbol' \
                'required_symbol_extra T 100 20' 0
              run_fixture non-text-symbol symbol-check.bash fail 'missing symbol required_symbol' \
                'required_symbol D 100 20' 0
              run_fixture undefined-symbol symbol-check.bash fail 'missing symbol required_symbol' \
                'required_symbol U' 0
              run_fixture exact-symbol symbol-check.bash pass 'All symbol checks passed' \
                'required_symbol T 100 20' 0
              run_fixture versioned-symbol symbol-check.bash pass 'All symbol checks passed' \
                'required_symbol@VERSION_1 T 100 20' 0
              run_fixture default-version-symbol symbol-check.bash pass 'All symbol checks passed' \
                'required_symbol@@VERSION_1 T 100 20' 0
              run_fixture empty-version-symbol symbol-check.bash fail 'missing symbol required_symbol' \
                'required_symbol@@ T 100 20' 0
              run_fixture malformed-version-symbol symbol-check.bash fail 'missing symbol required_symbol' \
                'required_symbol@@VERSION@OTHER T 100 20' 0

              test "$CASES" -eq 15
              mkdir -p "$out"
              cp ./*.log "$out/"
              printf 'parser/control-flow unit fixtures: %s\n' "$CASES" > "$out/result"
            '';
          }
        ];
      };

      link = testing.mkLinkCheck {
        pname = "aos-fuse-transport-link";
        library = self;
        includes = ["${self}/include"];
        libs = ["-laos-fuse-transport"];
        testSource = ''
          #include <aos_fuse_transport.h>
          #include <stddef.h>

          _Static_assert(sizeof(struct aos_fuse_attributes) == 48,
                         "attribute ABI changed");
          _Static_assert(offsetof(struct aos_fuse_attributes, kind) == 42,
                         "attribute field offset changed");
          _Static_assert(sizeof(struct aos_fuse_directory_entry) == 24,
                         "directory-entry ABI changed");
          _Static_assert(offsetof(struct aos_fuse_directory_entry, kind) == 22,
                         "directory-entry field offset changed");
          _Static_assert(sizeof(struct aos_fuse_limits) == 64,
                         "limit ABI changed");
          _Static_assert(offsetof(struct aos_fuse_limits, entry_valid_ns) == 48,
                         "limit field offset changed");
          _Static_assert(sizeof(struct aos_fuse_core_operations) == 96,
                         "operation-table ABI changed");
          _Static_assert(offsetof(struct aos_fuse_core_operations, lookup) == 32,
                         "operation-table field offset changed");
          _Static_assert(sizeof(struct aos_fuse_fallback_operations_v2) == 136,
                         "fallback operation-table ABI changed");
          _Static_assert(offsetof(struct aos_fuse_fallback_operations_v2, open) == 112,
                         "fallback operation-table embedding changed");
          _Static_assert(sizeof(struct aos_fuse_fallback_limits_v2) == 80,
                         "fallback limit-table ABI changed");
          _Static_assert(sizeof(struct aos_fuse_preparation_v1) == 88,
                         "prepared-session v1 ABI changed");
          _Static_assert(offsetof(struct aos_fuse_preparation_v1, limits) == 24,
                         "prepared-session limit offset changed");
          _Static_assert(sizeof(struct aos_fuse_scoped_operations_v3) == 192,
                         "reply-scoped operation ABI changed");
          _Static_assert(offsetof(struct aos_fuse_scoped_operations_v3, legacy) == 16,
                         "reply-scoped legacy embedding changed");
          _Static_assert(offsetof(struct aos_fuse_scoped_operations_v3, lookup) == 152,
                         "reply-scoped callback offset changed");

          int main(void) {
            int (*volatile run)(
              int, int, const struct aos_fuse_core_operations *, void *,
              const struct aos_fuse_limits *) = aos_fuse_transport_run;
            int (*volatile prepare)(
              int, int, const struct aos_fuse_preparation_v1 *,
              struct aos_fuse_prepared_session_v1 **) =
                aos_fuse_transport_prepare_v1;
            int (*volatile resume)(
              struct aos_fuse_prepared_session_v1 *,
              const struct aos_fuse_core_operations *, void *) =
                aos_fuse_transport_continue_prepared_v1;
            void (*volatile destroy)(struct aos_fuse_prepared_session_v1 *) =
              aos_fuse_transport_destroy_prepared_v1;
            int (*volatile scoped)(
              struct aos_fuse_prepared_session_v1 *,
              const struct aos_fuse_scoped_operations_v3 *, void *) =
                aos_fuse_transport_continue_prepared_v3;
            return AOS_FUSE_TRANSPORT_ABI_MAJOR == 1U &&
                           AOS_FUSE_TRANSPORT_ABI_MINOR == 0U && run != 0 &&
                           AOS_FUSE_PREPARED_SESSION_ABI_MAJOR == 1U &&
                           AOS_FUSE_PREPARED_SESSION_ABI_MINOR == 0U &&
                           prepare != 0 && resume != 0 && destroy != 0 &&
                           AOS_FUSE_SCOPED_ABI_MAJOR == 3U && scoped != 0
                       ? 0
                       : 1;
          }
        '';
      };

      fake-core = pkgs.mkDerivation {
        pname = "aos-fuse-transport-fake-core-check";
        version = "0";
        src = source;
        buildDeps = [pkgs.linux-headers];
        runtimeDeps = [pkgs.aos-fuse3];
        propagatedDeps = [];
        phases = [
          {
            name = "unpack";
            script = ''
              cp -R $src source
              chmod -R u+w source
              cd source
            '';
          }
          {
            name = "check";
            script = ''
              # Inlining must not move packet-sized fixture scratch onto the stack.
              $CC -std=c17 -O2 \
                -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
                -Wframe-larger-than=65536 \
                -DAOS_FUSE_TRANSPORT_TESTING \
                -I. -I${pkgs.aos-fuse3}/include/fuse3 \
                transport.c test.c -L${pkgs.aos-fuse3}/lib -lfuse3 \
                -o transport-test
              ./transport-test > result
              grep -Fxq \
                'aos-fuse-transport fake core and ABI 7.45 wire conformance passed' \
                result
              mkdir -p $out
              cp result $out/result
            '';
          }
        ];
      };

      # This metadata fixture proves transport lifetime and actual kernel ID
      # mapping, never production Root authority or a backing-content read grant.
      kernel-retained-idmap = testing.mkVMTest {
        name = "aos-fuse-transport-kernel-retained-idmap";
        rootfsDeps = [self retainedProbeSource pkgs.linux-headers];
        memory = 256;
        testScript = ''
          test -c /dev/fuse
          cd /tmp
          gcc -std=c17 -O2 -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
            -Wformat=2 -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
            -I${self}/include -I${pkgs.linux-headers}/include \
            ${retainedProbeSource} -L${self}/lib \
            -Wl,-rpath,${self}/lib -laos-fuse-transport \
            -o fuse-retained-idmap-probe
          unset LD_LIBRARY_PATH
          ./fuse-retained-idmap-probe
        '';
      };

      kernel-metadata = testing.mkVMTest {
        name = "aos-fuse-transport-kernel-metadata";
        rootfsDeps = [self probeSource pkgs.linux-headers];
        memory = 256;
        testScript = ''
          test -c /dev/fuse
          cd /tmp
          gcc -std=c17 -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
            -I${self}/include -I${pkgs.linux-headers}/include ${probeSource} \
            -L${self}/lib -Wl,-rpath,${self}/lib -laos-fuse-transport \
            -o aos-fuse-transport-probe

          # The guest compiler uses the harness bootstrap environment. The
          # installed bridge must resolve its own runtime closure during the
          # proof, without LD_LIBRARY_PATH overriding those dependencies.
          unset LD_LIBRARY_PATH
          ./aos-fuse-transport-probe
        '';
      };

      kernel-rust-metadata = testing.mkVMTest {
        name = "aos-fuse-transport-kernel-rust-metadata";
        rootfsDeps = [self probeSource rustWorker pkgs.e2fsprogs pkgs.util-linux pkgs.coreutils pkgs.linux-headers];
        memory = 256;
        testScript = ''
          test -c /dev/fuse
          cd /tmp
          gcc -std=c17 -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
            -I${self}/include -I${pkgs.linux-headers}/include ${probeSource} \
            -L${self}/lib -Wl,-rpath,${self}/lib -laos-fuse-transport \
            -o aos-fuse-transport-probe
          unset LD_LIBRARY_PATH
          ./aos-fuse-transport-probe \
            --rust-worker ${rustWorker}/bin/aos-filesystem-fuse-kernel-worker

          # Fixture-owned fs-verity data is not a production consumer grant.
          # Reuse the same kernel mount/teardown coordinator and six-record
          # worker; the added mode exercises only bounded file callbacks.
          mkdir -p /var/lib/aos/fuse-fallback-proof
          ${pkgs.coreutils}/bin/truncate -s 64M /tmp/fuse-fallback.img
          ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -q -b 4096 -O verity /tmp/fuse-fallback.img
          ${pkgs.util-linux}/bin/mount -o loop,nosuid,nodev \
            /tmp/fuse-fallback.img /var/lib/aos/fuse-fallback-proof
          chmod 0700 /var/lib/aos/fuse-fallback-proof
          mkdir -m 0700 /var/lib/aos/fuse-fallback-proof/objects \
            /var/lib/aos/fuse-fallback-proof/journal
          ./aos-fuse-transport-probe --rust-fallback \
            ${rustWorker}/bin/aos-filesystem-fuse-kernel-worker \
            /var/lib/aos/fuse-fallback-proof
          ${pkgs.util-linux}/bin/umount /var/lib/aos/fuse-fallback-proof
        '';
      };

      closure = pkgs.mkDerivation {
        pname = "aos-fuse-transport-runtime-closure-check";
        version = "0";
        src = null;

        outputChecks = {};
        exportReferencesGraph.runtime = [self];
        buildDeps = [pkgs.jq];
        dontStrip = true;
        dontNukeRefs = true;

        phases = [
          {
            name = "check";
            script = ''
              set -eu

              size=$(jq '[.runtime[].narSize] | add // 0' "$NIX_ATTRS_JSON_FILE")
              maxBytes=$((40 * 1024 * 1024))
              if [ "$size" -gt "$maxBytes" ]; then
                echo "aos-fuse-transport runtime closure is $size bytes (max: $maxBytes)" >&2
                exit 1
              fi

              if ! jq -e \
                --arg self ${self} \
                --arg fuse3 ${pkgs.aos-fuse3} \
                --arg glibc ${pkgs.glibc} \
                '([.runtime[].path] | sort) == ([$self, $fuse3, $glibc] | sort)' \
                "$NIX_ATTRS_JSON_FILE" >/dev/null; then
                echo "aos-fuse-transport runtime closure differs from its allowlist:" >&2
                jq -r '.runtime[].path' "$NIX_ATTRS_JSON_FILE" >&2
                exit 1
              fi

              if ! find ${self} -mindepth 1 \
                ! -type d ! -type f ! -type l -print0 -quit \
                > special-files; then
                echo "failed to scan transport output for special files" >&2
                exit 1
              fi
              if [ -s special-files ]; then
                echo "transport output contains a special file" >&2
                exit 1
              fi

              if ! find ${self} -mindepth 1 -type d \
                -printf 'directory %P\0' > manifest-directories; then
                echo "failed to scan transport output directories" >&2
                exit 1
              fi
              if ! find ${self} -type f \
                -printf 'file %P\0' > manifest-files; then
                echo "failed to scan transport output files" >&2
                exit 1
              fi
              if ! find ${self} -type l \
                -printf 'symlink %P -> %l\0' > manifest-symlinks; then
                echo "failed to scan transport output symlinks" >&2
                exit 1
              fi
              sort -z manifest-directories manifest-files manifest-symlinks \
                > manifest-actual

              printf '%s\0' \
                'directory include' \
                'directory lib' \
                'directory lib/pkgconfig' \
                'directory nix-support' \
                'file include/aos_fuse_transport.h' \
                'file lib/libaos-fuse-transport.so.1.0.0' \
                'file lib/pkgconfig/aos-fuse-transport.pc' \
                'file nix-support/aos-target-platform' \
                'symlink lib/libaos-fuse-transport.so -> libaos-fuse-transport.so.1' \
                'symlink lib/libaos-fuse-transport.so.1 -> libaos-fuse-transport.so.1.0.0' \
                > manifest-expected-unsorted
              sort -z manifest-expected-unsorted > manifest-expected

              if ! cmp -s manifest-actual manifest-expected; then
                echo "unexpected aos-fuse-transport final-output manifest" >&2
                exit 1
              fi

              mkdir -p "$out"
              printf 'closure-bytes=%s\n' "$size" > "$out/result"
            '';
          }
        ];
      };
    };

    meta = {
      description = "Bounded libfuse transport for AOS immutable filesystem views";
      license = "Apache-2.0";
    };
  }
