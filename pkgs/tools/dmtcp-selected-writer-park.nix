##! DMTCP — Userspace process checkpoint and fresh-process restart
{
  mkDerivation,
  autoconf,
  automake,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
  bash,
  python3,
  gzip,
  readline,
  ncurses,
  gcc-libs,
  coreutils,
  findutils,
  diffutils,
  sed,
  binutils,
  grep,
  patch,
}: let
  version = "4.2.0";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = [stdenv.buildPlatform.constraints.cpu];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };

    pname = "dmtcp-selected-writer-park";
    inherit version;
    outputs = ["out" "source"];
    src = fetchurl {
      urls = ["https://codeload.github.com/dmtcp/dmtcp/tar.gz/refs/tags/v${version}"];
      hash = "sha256-BDQQVm/XwJ8h4OxIXPculIFyJinqh3ZQFCt1BeDX8tI=";
    };

    buildDeps = [autoconf automake gnumake python3 coreutils findutils diffutils sed binutils grep patch];
    runtimeDeps = [bash gzip coreutils readline ncurses gcc-libs];
    ac_cv_prog_HAS_GZIP = "yes";

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd dmtcp-${version}
          patch --fuzz=0 -p1 < ${./_dmtcp/restart-environment-bounds.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/checkpoint-signal-parse.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/capture-context-ledger.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/capture-kernel-thread-identity.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/capture-descriptor-ledger.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/capture-mapping-ledger.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/capture-file-mapping-ledger.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/restore-saved-file-relocation.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/restore-file-mode-preservation.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/selected-writer-terminal-park.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/selected-exec-custody.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/selected-source-custody.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/selected-map-envelope.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/selected-source-owners.patch}
          patch --fuzz=0 -p1 < ${./_dmtcp/source-command-dispatch.patch}
          cat > src/dmtcp_source_command_paths.h <<'EOF'
          // SPDX-License-Identifier: LGPL-3.0-or-later
          // Copyright (c) 2026 Andyl, Inc.
          #ifndef DMTCP_SOURCE_COMMAND_PATHS_H
          #define DMTCP_SOURCE_COMMAND_PATHS_H
          #define DMTCP_SOURCE_COMMAND_SHELL "${bash}/bin/bash"
          #define DMTCP_SOURCE_COMMAND_COPY "${coreutils}/bin/cp"
          #endif
          EOF
          ${findutils}/bin/find . -type f -name '*.py' \
            -exec ${sed}/bin/sed -i "1s|^#!.*python.*$|#!${python3}/bin/python3|" {} +
          ${findutils}/bin/find . -type f -name '*.sh' \
            -exec ${sed}/bin/sed -i "1s|^#!.*$|#!${bash}/bin/bash|" {} +
          ${sed}/bin/sed -i \
            -e 's|/bin/bash|${bash}/bin/bash|g' \
            -e 's|/bin/sh|${bash}/bin/bash|g' \
            src/restartscript.cpp src/glibcsystem.cpp src/popen.cpp
          ${sed}/bin/sed -i 's|/usr/bin/env |${coreutils}/bin/env |g' \
            src/plugin/ipc/ssh/ssh.cpp
          ${sed}/bin/sed -i 's|/usr/bin/readelf|${binutils}/bin/readelf|g' \
            configure configure.ac
          ${sed}/bin/sed -i \
            's|-aW ${binutils}/bin/readelf|-aW ${bash}/bin/bash|g' \
            configure configure.ac
          # Store-path ELF interpreters exceed upstream's conventional-path
          # buffer. Keep loader discovery bounded by the platform path limit.
          ${sed}/bin/sed -i 's|char buf\[80\];|char buf[PATH_MAX];|' \
            src/util_exec.cpp
        '';
      }
      {
        name = "generate-build-inputs";
        script = ''
          # The added native implementation participates in the real shared
          # library build. Regenerate build rules from the retained sources.
          ${autoconf}/bin/autoreconf -fi
        '';
      }
      {
        name = "corresponding-source";
        script = ''
          mkdir -p "$source/patches" "$source/build" "$source/licenses"
          cp "$src" "$source/dmtcp-upstream.tar.gz"
          cp ${./_dmtcp}/*.patch "$source/patches/"
          cp ${./_dmtcp/selected-writer-LICENSES.md} "$source/licenses/patch-inventory.md"
          cp COPYING COPYING.LESSER "$source/licenses/"
          cp ${./dmtcp-selected-writer-park.nix} "$source/build/recipe.nix"
          cp ${./_dmtcp/continuation-check.c} "$source/build/continuation-check.c"
          cp ${./_dmtcp/exec-custody-controls.cpp} "$source/build/exec-custody-controls.cpp"
          cp ${./_dmtcp/source-capsule-controls.cpp} "$source/build/source-capsule-controls.cpp"
          cp ${./_dmtcp/map-custody-controls.cpp} "$source/build/map-custody-controls.cpp"
          cp ${./_dmtcp/map-capsule-reader.cpp} "$source/build/map-capsule-reader.cpp"
          cp ${./_dmtcp/shared-area-controls.cpp} "$source/build/shared-area-controls.cpp"
          cp ${./_dmtcp/thread-owner-controls.cpp} "$source/build/thread-owner-controls.cpp"
          cp ${./_dmtcp/source-launch-probe.cpp} "$source/build/source-launch-probe.cpp"
          cp ${./_dmtcp/source-launch-controls.cpp} "$source/build/source-launch-controls.cpp"
          cp ${./_dmtcp/source-unselected-probe.cpp} "$source/build/source-unselected-probe.cpp"
          cp ${./_dmtcp/source-unselected-controls.cpp} "$source/build/source-unselected-controls.cpp"
          cp ${./_dmtcp/source-command-controls.cpp} "$source/build/source-command-controls.cpp"
          cp ${./_dmtcp/source-launch-peer-controls.h} "$source/build/source-launch-peer-controls.h"
          cp ${./dmtcp-source-owners-check.nix} "$source/build/source-owners-check.nix"
          cp ${./dmtcp-setuid-launch-check.nix} "$source/build/setuid-launch-check.nix"
          # Retain the actual tree after all patches and hermetic substitutions,
          # before generated build objects or installed binaries enter it.
          tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
            -czf "$source/dmtcp-patched-source.tar.gz" .
          cat > "$source/build/toolchain.json" <<'EOF'
          ${builtins.toJSON {
            compiler = "${buildPackages.cc}";
            inherit autoconf automake gnumake bash python3 coreutils findutils diffutils sed binutils grep patch;
            upstreamRevision = "f8009ce7b4ad211311ca2f72a929b975e4aa1155";
            license = "LGPL-3.0-or-later";
            relinkModel = "shared-preload-library-with-matching-complete-source";
          }}
          EOF
        '';
      }
      {
        name = "configure";
        script = ''
          # Source-owned thread banks require lock-free constexpr assertions.
          # Avoid mixing the bootstrap static C++ personality with the
          # shared runtime used by libc's pthread cancellation unwinder.
          LDFLAGS="''${LDFLAGS-} -L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib" \
            CXXFLAGS="''${CXXFLAGS-} -std=c++17" \
            $CONFIG_SHELL ./configure --prefix="$out" $configureFlags
          grep -q '^#define ELF_INTERPRETER "/nix/store/' include/config.h
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"'';
      }
      {
        name = "install";
        script = ''
          make SHELL="$CONFIG_SHELL" install
          # The public header includes this generated header by its source
          # subdirectory; upstream's install target also flattens a copy.
          mkdir -p "$out/include/dmtcp"
          cp include/dmtcp/version.h "$out/include/dmtcp/version.h"
          mkdir -p "$out/share/licenses/dmtcp"
          cp COPYING COPYING.LESSER "$out/share/licenses/dmtcp/"
          ln -s "$source" "$out/share/corresponding-source"
        '';
      }
      {
        name = "check";
        script = ''
          "$out/bin/dmtcp_launch" --version
          "$out/bin/dmtcp_restart" --version

          # Check actual durable process reconstruction after the original
          # application exits, with pending equal-time events and PRNG state.
          # This does not qualify gem5's models or its external resources.
          mkdir -p continuation-check/images continuation-check/tmp
          cc -std=c11 -Wall -Wextra -Werror -fPIC \
            -I"$out/include" ${./_dmtcp/continuation-check.c} \
            -o continuation-check/application
          cd continuation-check
          ./application baseline "$PWD/baseline"
          ${coreutils}/bin/timeout 60 "$out/bin/dmtcp_launch" \
            --new-coordinator --coord-port 0 --interval 0 --no-gzip \
            --ckpt-signal 40 \
            --ckptdir "$PWD/images" --tmpdir "$PWD/tmp" \
            ./application capture "$PWD/capture"
          cmp baseline.original capture.original
          set -- images/*.dmtcp
          test "$#" -eq 1
          test -s "$1"
          ${coreutils}/bin/timeout 60 "$out/bin/dmtcp_restart" \
            --new-coordinator --coord-port 0 --interval 0 \
            --tmpdir "$PWD/tmp" "$1"
          cmp baseline.original capture.restored
          cp capture.restored first-restored
          ${coreutils}/bin/timeout 60 "$out/bin/dmtcp_restart" \
            --new-coordinator --coord-port 0 --interval 0 \
            --tmpdir "$PWD/tmp" "$1"
          cmp first-restored capture.restored
          cmp baseline.original capture.original
        '';
      }
    ];

    meta = {
      description = "Private selected writer terminal-park toolkit candidate; capture admission and authenticated restart remain refused pending separate qualification";
      homepage = "https://dmtcp.github.io/";
      license = "LGPL-3.0-or-later";
      mainProgram = "dmtcp_launch";
    };
  }
