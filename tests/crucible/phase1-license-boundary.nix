{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.licenseBoundary",
  taskIds ? ["BOUND-1" "BOUND-2" "BOUND-3" "BOUND-4" "BOUND-5" "BOUND-6" "BOUND-7" "BOUND-8" "BOUND-9" "BOUND-10" "BOUND-11" "BOUND-12"],
  campaignComposition ? null,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  campaignMode =
    if campaignComposition == null
    then null
    else campaignComposition.mode;
  campaignSystem =
    if campaignComposition == null
    then null
    else campaignComposition.system;
  campaignToplevel =
    if campaignSystem == null
    then null
    else campaignSystem.config.system.build.toplevel;
  campaignRuntime =
    if campaignSystem == null
    then null
    else campaignSystem.config.environment.etc."crucible/campaign-runtime.env".text;
  campaignCompositionCheck = lib.optionalString (campaignComposition != null) ''
    test ${lib.escapeShellArg campaignMode} = enabled \
      -o ${lib.escapeShellArg campaignMode} = disabled
    printf '%s' ${lib.escapeShellArg campaignRuntime} > "$TMPDIR/campaign-runtime.env"
    test "$(grep -c '^schema=' "$TMPDIR/campaign-runtime.env")" -eq 1
    test "$(grep -c '^enabled=' "$TMPDIR/campaign-runtime.env")" -eq 1
    test "$(grep -c '^identity=' "$TMPDIR/campaign-runtime.env")" -eq 1
    grep -Fxq "enabled=${
      if campaignMode == "enabled"
      then "true"
      else "false"
    }" \
      "$TMPDIR/campaign-runtime.env"

    nix-store --query --requisites ${campaignToplevel} \
      > "$TMPDIR/campaign-system-closure"
    grep -Fxq ${lib.escapeShellArg (toString campaignToplevel)} \
      "$TMPDIR/campaign-system-closure"
    if test ${lib.escapeShellArg campaignMode} = enabled; then
      grep -Fxq ${lib.escapeShellArg (toString pkgs.crucible)} \
        "$TMPDIR/campaign-system-closure"
    else
      if grep -Fxq ${lib.escapeShellArg (toString pkgs.crucible)} \
          "$TMPDIR/campaign-system-closure"; then
        echo "campaign-disabled system closure contains the Crucible suite" >&2
        exit 1
      fi
    fi
  '';
  campaignCompositionResult = lib.optionalString (campaignComposition != null) ''
    cp "$TMPDIR/campaign-runtime.env" "$out/campaign-runtime.env"
    cp "$TMPDIR/campaign-system-closure" "$out/campaign-system-closure"
    cat >> "$out/result" <<RESULT
    campaign_mode=${campaignMode}
    campaign_configuration_identity=${campaignSystem.config.aos.services.crucibleCampaign._runtimeIdentity}
    campaign_toplevel=${campaignToplevel}
    campaign_runtime_identity=${builtins.hashString "sha256" campaignRuntime}
    executor_derivation=$out
    campaign_closure_authenticated=true
    RESULT
  '';
in
  pkgs.mkDerivation {
    pname = "crucible-phase1-license-boundary";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
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
      ]
      ++ lib.optional (campaignComposition != null) campaignToplevel;

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
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed 's|@vendor@|${cargoDeps}|g' \
              "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
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
          grep -Fxq 'qemu_atomic_patch_hash=${pkgs.qemu-crucible-source.passthru.atomicPatchHash}' "$source_manifest"
          grep -Fxq 'qemu_patch_branch_bundle_hash=${pkgs.qemu-crucible-source.passthru.patchBranchBundleHash}' "$source_manifest"
          grep -Fxq 'qemu_samba_smbd_version=${pkgs.qemu-crucible-source.passthru.sambaSmbdVersion}' "$source_manifest"
          grep -Fxq 'qemu_samba_smbd_source_hash_algo=${pkgs.qemu-crucible-source.passthru.sambaSmbdSourceHashAlgo}' "$source_manifest"
          grep -Fxq 'qemu_samba_smbd_source_hash=${pkgs.qemu-crucible-source.passthru.sambaSmbdSourceHash}' "$source_manifest"
          grep -Fxq 'qemu_samba_smbd_recipe_hash=${pkgs.qemu-crucible-source.passthru.sambaSmbdRecipeHash}' "$source_manifest"
          grep -Fxq 'qemu_samba_smbd_executable=${pkgs.qemu-crucible-source.passthru.sambaSmbdExecutable}' "$source_manifest"
          grep -Fxq 'shmem_header_hash=${pkgs.qemu-crucible-source.passthru.shmemHeaderHash}' "$source_manifest"
          grep -Fxq 'plugin_cargo_deps_hash=${pkgs.qemu-crucible-source.passthru.cargoDepsHash}' "$source_manifest"
          grep -Fxq 'corresponding_source_scope=qemu-crucible,crucible-qemu-plugin' "$source_manifest"
          grep -Fxq 'licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later,BSD-2-Clause,BSD-3-Clause' "$source_manifest"
          grep -Fxq 'qemu_combined_work_license=GPL-2.0-only' "$source_manifest"
          grep -Fxq 'qemu_created_source_license=GPL-2.0-or-later' "$source_manifest"

          qemu_source_file=$(sed -n 's/^qemu_source_file=//p' "$source_manifest")
          atomic_patch_file=$(sed -n 's/^qemu_atomic_patch_file=//p' "$source_manifest")
          patch_bundle=$(sed -n 's/^qemu_patch_branch_bundle=//p' "$source_manifest")
          test -n "$qemu_source_file"
          test -n "$atomic_patch_file"
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
          test -z "$(find "$source_root/build/aos" -type f -regex '.*/core[.][0-9]+' -print -quit)"
          test -f "$source_root/build/aos/crates/crucible-shmem/include/crucible_shmem_abi.h"
          samba_smbd_version=$(sed -n 's/^qemu_samba_smbd_version=//p' "$source_manifest")
          samba_smbd_source_hash_algo=$(sed -n 's/^qemu_samba_smbd_source_hash_algo=//p' "$source_manifest")
          samba_smbd_source_hash=$(sed -n 's/^qemu_samba_smbd_source_hash=//p' "$source_manifest")
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
                bash = "/aos-bash";
                perl = "/aos-perl";
                pkg-config = null;
                meson = null;
                ninja = null;
                python3 = "/aos-python3";
                stdenv = {
                  isCross = false;
                  hostPlatform = {
                    isDarwin = false;
                    isLinux = true;
                    constraints.cpu = "x86_64";
                  };
                };
                buildPackages = {};
                setuptools = null;
                distlib = null;
                python3-pygdbmi = null;
                glib = null;
                pixman = null;
                zlib = null;
                libslirp = null;
                dtc = null;
                libcap-ng = null;
                libusb1 = null;
                libgcrypt = null;
                gnutls = null;
                fuse3 = null;
                gcc-libs = "/aos-gcc-libs";
                samba-smbd = {
                  outPath = "/aos-samba-smbd";
                  version = "'"$samba_smbd_version"'";
                  src = {
                    outputHash = "'"$samba_smbd_source_hash"'";
                    outputHashAlgo = "'"$samba_smbd_source_hash_algo"'";
                  };
                };
                pname = "qemu-crucible";
                enablePlugins = true;
                applyCruciblePatch = true;
              };
            in qemu.qemuBuildIdentity
          ')
          test "$evaluated_qemu_build_id" = '"${pkgs.qemu-crucible-source.passthru.qemuBuildIdentity}"'
          test -f "$source_root/patches/_atomic-patch.nix"
          test -f "$source_root/plugin/workspace/crates/Cargo.lock"
          test -f "$source_root/plugin/workspace/crates/Cargo.toml"
          test -f "$source_root/plugin/workspace/crates/crucible-qemu-plugin/Cargo.toml"
          test -f "$source_root/plugin/workspace/pkgs/emulation/crucible-qemu-plugin.nix"
          test -n "$(find "$source_root/plugin/cargo-vendor" -mindepth 1 -maxdepth 1 -type d -print -quit)"
          archived_workspace="$TMPDIR/archived-plugin-workspace"
          archived_cargo_home="$TMPDIR/archived-plugin-cargo-home"
          archived_target="$TMPDIR/archived-plugin-target"
          cp -R "$source_root/plugin/workspace/crates" "$archived_workspace"
          chmod -R u+w "$archived_workspace"
          mkdir -p "$archived_cargo_home" "$archived_workspace/.cargo"
          if [ -f "$source_root/plugin/cargo-vendor/.cargo/config.toml" ]; then
            sed "s|@vendor@|$source_root/plugin/cargo-vendor|g" \
              "$source_root/plugin/cargo-vendor/.cargo/config.toml" \
              > "$archived_workspace/.cargo/config.toml"
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "%s"\n\n' \
              "$source_root/plugin/cargo-vendor" \
              > "$archived_workspace/.cargo/config.toml"
          fi
          (
            cd "$archived_workspace"
            CARGO_HOME="$archived_cargo_home" cargo check --frozen --offline \
              --manifest-path Cargo.toml \
              --target-dir "$archived_target" \
              -p crucible-qemu-plugin
          )
          test -s "$source_root/$atomic_patch_file"
          cmp "$source_root/interfaces/crucible_shmem_abi.h" \
            ${pkgs.qemu-crucible.passthru.shmemGeneratedHeader}

          reconstructed="$TMPDIR/qemu-crucible-reconstructed"
          mkdir -p "$reconstructed"
          tar -xf "$source_root/$qemu_source_file" -C "$reconstructed" --strip-components=1
          patch --batch -d "$reconstructed" -p1 < "$source_root/$atomic_patch_file"
          grep -Fq 'SPDX-License-Identifier: GPL-2.0-or-later' \
            "$reconstructed/include/system/crucible-plugin-wake.h"
          grep -Fq 'GNU GPL, version 2 or later' \
            "$reconstructed/block/crucible-shmem.c"

          suite_nix="$CRUCIBLE_GATE_SOURCE/pkgs/tools/crucible/crucible.nix"
          release_nix="$CRUCIBLE_GATE_SOURCE/pkgs/tools/crucible/_release-manifest.nix"
          grep -Fq 'runtimeDeps = [controller debugGateway qemu-crucible crucible-qemu-plugin qemu-crucible-source linux-crucible crucible-fixtures gdb openssh coreutils grep sed util-linux];' "$suite_nix"
          grep -Fq 'license = ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later" "GPL-3.0-or-later" "BSD-2-Clause" "BSD-3-Clause"];' "$suite_nix"
          grep -Fq 'correspondingSource = qemu-crucible-source;' "$suite_nix"
          grep -Fq 'standalone_release=false' "$CRUCIBLE_GATE_SOURCE/pkgs/emulation/qemu.nix"
          grep -Fq 'artifact_role=aggregate-release-root' "$suite_nix"
          grep -Fq 'processBoundary = "unix-socket-control+memfd-shared-memory-data";' "$release_nix"
          grep -Fq 'scope = ["qemu-crucible" "crucible-qemu-plugin"];' "$release_nix"
          grep -Fq 'licenses = ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later" "BSD-2-Clause" "BSD-3-Clause"];' "$release_nix"

          ${campaignCompositionCheck}
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
          corresponding_source_reconstruction=atomic-patch-applied,archived-plugin-offline-checked
          RESULT
          ${campaignCompositionResult}
        '';
      }
    ];
  }
