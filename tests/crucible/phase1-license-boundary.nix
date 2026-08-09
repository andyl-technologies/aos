{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.licenseBoundary",
  taskIds ? ["BOUND-1" "BOUND-2" "BOUND-3" "BOUND-4" "BOUND-5" "BOUND-6" "BOUND-7" "BOUND-8" "BOUND-9" "BOUND-10" "BOUND-11" "BOUND-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-license-boundary";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.grep
      pkgs.nix
      pkgs.patch
      pkgs.rust
      pkgs.sed
      pkgs.tar
      pkgs.xz
      pkgs.crucible-controller
      pkgs.qemu-crucible-source
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          export CRUCIBLE_GATE_SOURCE="$PWD"
          mkdir -p "$CARGO_HOME" .cargo
          printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
            > .cargo/config.toml
        '';
      }
      {
        name = "check-packaging-boundary";
        script = ''
          set -eu

          controller=${pkgs.crucible-controller}
          controller_info="$controller/nix-support/crucible-build-info"
          test -x "$controller/bin/crucible"
          test -f "$controller_info"
          grep -Fxq 'package=crucible-controller' "$controller_info"
          grep -Fxq 'component=controller' "$controller_info"
          grep -Fxq 'component_license=Apache-2.0' "$controller_info"
          grep -Fxq 'qemu_package=none' "$controller_info"
          grep -Fxq 'plugin_package=none' "$controller_info"
          test -f "$controller/share/licenses/crucible-controller/Apache-2.0.txt"
          test ! -e "$controller/share/licenses/crucible-controller/GPL-2.0-only.txt"
          test ! -e "$controller/share/licenses/crucible-controller/GPL-2.0-or-later.txt"

          source_package=${pkgs.qemu-crucible-source}
          source_root="$source_package/share/aos/qemu-crucible-source"
          source_manifest="$source_root/SOURCE-MANIFEST.env"
          source_info="$source_package/nix-support/qemu-crucible-source-build-info"
          test -f "$source_manifest"
          test -f "$source_info"
          grep -Fxq 'package=qemu-crucible-source' "$source_manifest"
          grep -Fxq 'qemu_package=qemu-crucible' "$source_manifest"
          grep -Fxq 'qemu_build_id=${pkgs.qemu-crucible-source.passthru.qemuBuildIdentity}' "$source_manifest"
          grep -Fxq 'qemu_build_id=${pkgs.qemu-crucible-source.passthru.qemuBuildIdentity}' "$source_info"
          grep -Fxq 'qemu_source_hash=${pkgs.qemu-crucible-source.passthru.qemuSourceHash}' "$source_manifest"
          grep -Fxq 'qemu_patch_series_hash=${pkgs.qemu-crucible-source.passthru.patchSeriesHash}' "$source_manifest"
          grep -Fxq 'qemu_patch_branch_bundle_hash=${pkgs.qemu-crucible-source.passthru.patchBranchBundleHash}' "$source_manifest"
          grep -Fxq 'shmem_header_hash=${pkgs.qemu-crucible-source.passthru.shmemHeaderHash}' "$source_manifest"
          grep -Fxq 'plugin_cargo_deps_hash=${pkgs.qemu-crucible-source.passthru.cargoDepsHash}' "$source_manifest"
          grep -Fxq 'corresponding_source_scope=qemu-crucible,crucible-qemu-plugin' "$source_manifest"
          grep -Fxq 'licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later' "$source_manifest"
          grep -Fxq 'qemu_combined_work_license=GPL-2.0-only' "$source_manifest"
          grep -Fxq 'qemu_created_source_license=GPL-2.0-or-later' "$source_manifest"

          qemu_source_file=$(sed -n 's/^qemu_source_file=//p' "$source_manifest")
          patch_count=$(sed -n 's/^qemu_patch_count=//p' "$source_manifest")
          patch_bundle=$(sed -n 's/^qemu_patch_branch_bundle=//p' "$source_manifest")
          test -n "$qemu_source_file"
          test -n "$patch_count"
          test -n "$patch_bundle"
          test -s "$source_root/$qemu_source_file"
          test -s "$source_root/$patch_bundle"
          test -s "$source_root/interfaces/crucible_shmem_abi.h"
          test -s "$source_root/licenses/QEMU-COPYING.txt"
          test -s "$source_root/licenses/QEMU-LICENSE.txt"
          test -s "$source_root/licenses/Apache-2.0.txt"
          test -s "$source_root/licenses/MIT.txt"
          test -s "$source_root/licenses/GPL-2.0-only.txt"
          test -s "$source_root/licenses/GPL-2.0-or-later.txt"
          test -s "$source_root/licenses/AOS-QEMU-PATCHES.md"
          grep -Fq 'information are released under the GNU General Public License, version' \
            "$source_root/licenses/QEMU-LICENSE.txt"
          grep -Fxq 'aos_build_entrypoint=build/aos/default.nix' "$source_manifest"
          test -f "$source_root/build/aos/default.nix"
          test -f "$source_root/build/aos/lib/default.nix"
          test -f "$source_root/build/aos/stdenv/default.nix"
          test -f "$source_root/build/aos/stdenv/phases.nix"
          test -f "$source_root/build/aos/pkgs/default.nix"
          test -f "$source_root/build/aos/pkgs/emulation/qemu.nix"
          test -f "$source_root/build/aos/crates/crucible-shmem/include/crucible_shmem_abi.h"
          export NIX_STATE_DIR="$TMPDIR/nix-state"
          mkdir -p "$NIX_STATE_DIR/profiles"
          evaluated_qemu_build_id=$(nix-instantiate --eval --strict --expr '
            let
              root = builtins.toPath "'"$source_root"'/build/aos";
              lib = import (root + "/lib") { system = builtins.currentSystem; };
              qemu = import (root + "/pkgs/emulation/qemu.nix") {
                inherit lib;
                mkDerivation = args: args // (args.passthru or {});
                fetchurl = args: args;
                gnumake = null;
                pkg-config = null;
                meson = null;
                ninja = null;
                python3 = "/aos-python3";
                setuptools = null;
                distlib = null;
                glib = null;
                pixman = null;
                zlib = null;
                libslirp = null;
                dtc = null;
                pname = "qemu-crucible";
                enablePlugins = true;
                applyCruciblePatches = true;
              };
            in qemu.qemuBuildIdentity
          ')
          test "$evaluated_qemu_build_id" = '"${pkgs.qemu-crucible-source.passthru.qemuBuildIdentity}"'
          test -f "$source_root/patches/_series.nix"
          test -f "$source_root/plugin/workspace/crates/Cargo.lock"
          test -f "$source_root/plugin/workspace/crates/Cargo.toml"
          test -f "$source_root/plugin/workspace/crates/crucible-qemu-plugin/Cargo.toml"
          test -f "$source_root/plugin/workspace/pkgs/emulation/crucible-qemu-plugin.nix"
          test -n "$(find "$source_root/plugin/cargo-vendor" -mindepth 1 -maxdepth 1 -type d -print -quit)"
          actual_patch_count=$(find "$source_root/patches" -name '[0-9][0-9][0-9][0-9]-*.patch' | wc -l)
          test "$actual_patch_count" -eq "$patch_count"
          cmp "$source_root/interfaces/crucible_shmem_abi.h" \
            ${pkgs.qemu-crucible.passthru.shmemGeneratedHeader}

          reconstructed="$TMPDIR/qemu-crucible-reconstructed"
          mkdir -p "$reconstructed"
          tar -xf "$source_root/$qemu_source_file" -C "$reconstructed" --strip-components=1
          for patch_file in "$source_root"/patches/[0-9][0-9][0-9][0-9]-*.patch; do
            patch --batch -d "$reconstructed" -p1 < "$patch_file"
          done
          grep -q 'qemu_plugin_crucible_rr_switch_quantum' \
            "$reconstructed/include/qemu/qemu-plugin.h"
          grep -Fq 'SPDX-License-Identifier: GPL-2.0-or-later' \
            "$reconstructed/include/system/crucible-plugin-wake.h"
          grep -Fq 'GNU GPL, version 2 or later' \
            "$reconstructed/block/crucible-shmem.c"

          suite_nix="$CRUCIBLE_GATE_SOURCE/pkgs/tools/crucible/crucible.nix"
          release_nix="$CRUCIBLE_GATE_SOURCE/pkgs/tools/crucible/_release-manifest.nix"
          grep -Fq 'runtimeDeps = [controller qemu-crucible crucible-qemu-plugin qemu-crucible-source linux-crucible crucible-fixtures];' "$suite_nix"
          grep -Fq 'license = ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later"];' "$suite_nix"
          grep -Fq 'correspondingSource = qemu-crucible-source;' "$suite_nix"
          grep -Fq 'standalone_release=false' "$CRUCIBLE_GATE_SOURCE/pkgs/emulation/qemu.nix"
          grep -Fq 'artifact_role=aggregate-release-root' "$suite_nix"
          grep -Fq 'processBoundary = "unix-socket-control+memfd-shared-memory-data";' "$release_nix"
          grep -Fq 'scope = ["qemu-crucible" "crucible-qemu-plugin"];' "$release_nix"
          grep -Fq 'licenses = ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later"];' "$release_nix"
        '';
      }
      {
        name = "run-license-boundary";
        script = ''
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-license-boundary-target" \
            -p crucible-harness \
            --test gate_license_boundary \
            -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:license-boundary
          tasks=${builtins.concatStringsSep "," taskIds}
          rust_test=crucible-harness::gate_license_boundary
          controller_package=crucible-controller
          controller_license=Apache-2.0
          qemu_corresponding_source_package=qemu-crucible-source
          qemu_corresponding_source_build_id=${pkgs.qemu-crucible-source.passthru.qemuBuildIdentity}
          corresponding_source_reconstruction=patch-series-applied
          RESULT
        '';
      }
    ];
  }
