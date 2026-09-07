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
    in {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libaos-fuse-transport.so"];
      };

      symbols = testing.mkSymbolCheck {
        pkg = self;
        libName = "libaos-fuse-transport.so";
        symbols = ["aos_fuse_transport_run"];
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

          int main(void) {
            int (*volatile run)(
              int, int, const struct aos_fuse_core_operations *, void *,
              const struct aos_fuse_limits *) = aos_fuse_transport_run;
            return AOS_FUSE_TRANSPORT_ABI_MAJOR == 1U &&
                           AOS_FUSE_TRANSPORT_ABI_MINOR == 0U && run != 0
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
              $CC -std=c17 -O2 \
                -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
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

      kernel-metadata = testing.mkVMTest {
        name = "aos-fuse-transport-kernel-metadata";
        rootfsDeps = [self probeSource];
        memory = 256;
        testScript = ''
          test -c /dev/fuse
          cd /tmp
          gcc -std=c17 -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
            -I${self}/include ${probeSource} \
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
        rootfsDeps = [self probeSource rustWorker];
        memory = 256;
        testScript = ''
          test -c /dev/fuse
          cd /tmp
          gcc -std=c17 -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
            -I${self}/include ${probeSource} \
            -L${self}/lib -Wl,-rpath,${self}/lib -laos-fuse-transport \
            -o aos-fuse-transport-probe
          unset LD_LIBRARY_PATH
          ./aos-fuse-transport-probe \
            --rust-worker ${rustWorker}/bin/aos-filesystem-fuse-kernel-worker
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
