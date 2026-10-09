##! DMTCP — Userspace process checkpoint and fresh-process restart
{
  mkDerivation,
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

    pname = "dmtcp";
    inherit version;
    outputs = ["out" "source"];
    src = fetchurl {
      urls = ["https://codeload.github.com/dmtcp/dmtcp/tar.gz/refs/tags/v${version}"];
      hash = "sha256-BDQQVm/XwJ8h4OxIXPculIFyJinqh3ZQFCt1BeDX8tI=";
    };

    buildDeps = [gnumake python3 coreutils findutils diffutils sed binutils grep patch];
    runtimeDeps = [bash gzip readline ncurses gcc-libs];
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
        name = "corresponding-source";
        script = ''
          mkdir -p "$source/patches" "$source/build" "$source/licenses"
          cp "$src" "$source/dmtcp-upstream.tar.gz"
          cp ${./_dmtcp}/*.patch "$source/patches/"
          cp ${./_dmtcp/LICENSES.md} "$source/licenses/patch-inventory.md"
          cp COPYING COPYING.LESSER "$source/licenses/"
          cp ${./dmtcp.nix} "$source/build/recipe.nix"
          cp ${./_dmtcp/continuation-check.c} "$source/build/continuation-check.c"
          # Retain the actual tree after all patches and hermetic substitutions,
          # before generated build objects or installed binaries enter it.
          tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
            -czf "$source/dmtcp-patched-source.tar.gz" .
          cat > "$source/build/toolchain.json" <<'EOF'
          ${builtins.toJSON {
            compiler = "${buildPackages.cc}";
            inherit gnumake bash python3 coreutils findutils diffutils sed binutils grep patch;
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
      description = "Userspace process checkpoint/restart toolkit; provider-specific exact continuation requires separate qualification";
      homepage = "https://dmtcp.github.io/";
      license = "LGPL-3.0-or-later";
      mainProgram = "dmtcp_launch";
    };
  }
