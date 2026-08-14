##! qemu-crucible-source — complete corresponding source for qemu-crucible
{
  mkDerivation,
  fetchurl,
  fetchCargoVendor,
  lib,
  qemu-crucible,
}: let
  qemu = qemu-crucible.passthru;
  series = qemu.series;
  version = series.qemuVersion;
  patchCopyCommand = file:
    "cp ${./qemu-patches + "/${file}"} \"$source_root/patches/${file}\"";
  patchCopyCommands = builtins.concatStringsSep "\n" (map patchCopyCommand series.patchFiles);
  crucibleSource = import ../tools/crucible/_source.nix {inherit lib;};
  repoRoot = ../..;
  characterizationGoldens = "${toString repoRoot}/tests/fixtures/system-characterization-goldens";
  aosBuildSource = builtins.path {
    path = repoRoot;
    name = "aos-qemu-build-source";
    filter = path: _type: let
      base = baseNameOf path;
      pathString = toString path;
    in
      base != ".git"
      && base != ".worktrees"
      && base != "target"
      && base != "result"
      # Characterization goldens are review fixtures, not corresponding source
      # required to rebuild QEMU. Excluding them also prevents the base-lib's
      # frozen package inventory from feeding this package back into its own
      # characterization store paths.
      && !lib.hasPrefix characterizationGoldens pathString;
  };
  cargoDepsHash = "sha256-RvgGglI1TqzOmlqgt3qG+GBHEGd3ZHT9M4CueO0Q/W4=";
  crucibleCargoDeps = fetchCargoVendor {
    src = crucibleSource;
    name = "crucible-vendor-${version}";
    sourceRoot = "source/crates";
    hash = cargoDepsHash;
  };
in
  mkDerivation {
    pname = "qemu-crucible-source";
    inherit version;

    src = fetchurl {
      urls = [series.qemuSourceUrl];
      hash = series.qemuSourceHash;
    };

    runtimeDeps = [];
    propagatedDeps = [];
    # Corresponding source must remain byte-for-byte identical to its fixed
    # source inputs; reference rewriting would mutate source text.
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          set -eu
          source_root="$out/share/aos/qemu-crucible-source"
          mkdir -p "$source_root/upstream" "$source_root/patches" \
            "$source_root/build" "$source_root/interfaces" \
            "$source_root/licenses" "$source_root/plugin" "$out/nix-support"

          cp "$src" "$source_root/upstream/qemu-${version}.tar.xz"
          cp -R ${aosBuildSource} "$source_root/build/aos"
          cp ${./qemu-patches/_series.nix} "$source_root/patches/_series.nix"
          cp ${series.patchBranchBundle} "$source_root/patches/crucible-qemu-${version}.bundle"
          cp ${qemu.shmemGeneratedHeader} "$source_root/interfaces/crucible_shmem_abi.h"
          cp -R ${crucibleSource} "$source_root/plugin/workspace"
          cp -R ${crucibleCargoDeps} "$source_root/plugin/cargo-vendor"
          chmod -R u+w "$source_root/plugin"
          ${patchCopyCommands}

          tar -xOf "$src" "qemu-${version}/COPYING" > "$source_root/licenses/QEMU-COPYING.txt"
          tar -xOf "$src" "qemu-${version}/LICENSE" > "$source_root/licenses/QEMU-LICENSE.txt"
          cp ${../../LICENSES/Apache-2.0.txt} "$source_root/licenses/Apache-2.0.txt"
          cp ${../../LICENSES/MIT.txt} "$source_root/licenses/MIT.txt"
          cp ${../../LICENSES/GPL-2.0-only.txt} "$source_root/licenses/GPL-2.0-only.txt"
          cp ${../../LICENSES/GPL-2.0-or-later.txt} "$source_root/licenses/GPL-2.0-or-later.txt"
          cp ${./qemu-patches/LICENSES.md} "$source_root/licenses/AOS-QEMU-PATCHES.md"

          cat > "$source_root/SOURCE-MANIFEST.env" <<'MANIFEST'
          package=qemu-crucible-source
          qemu_package=qemu-crucible
          qemu_version=${version}
          qemu_source_file=upstream/qemu-${version}.tar.xz
          qemu_source_hash=${series.qemuSourceHash}
          aos_build_source_root=build/aos
          aos_build_entrypoint=build/aos/default.nix
          qemu_build_expression=build/aos/pkgs/emulation/qemu.nix
          qemu_patch_count=${toString (builtins.length series.patchFiles)}
          qemu_patch_series_hash=${qemu.patchSeriesHash}
          qemu_patch_branch_ref=${series.patchBranchRef}
          qemu_patch_branch_bundle=patches/crucible-qemu-${version}.bundle
          qemu_patch_branch_bundle_hash=${qemu.patchBranchBundleHash}
          qemu_patch_branch_base_commit=${series.patchBranchBaseCommit}
          qemu_patch_branch_head_commit=${series.patchBranchHeadCommit}
          qemu_build_id=${qemu.qemuBuildIdentity}
          qemu_nix_hash=${qemu.qemuNixHash}
          qemu_configure_flags_hash=${qemu.qemuConfigureFlagsHash}
          shmem_abi=${qemu.shmemAbi}
          shmem_header_file=interfaces/crucible_shmem_abi.h
          shmem_header_hash=${qemu.shmemHeaderHash}
          licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later,BSD-2-Clause,BSD-3-Clause
          qemu_license=GPL-2.0-only
          qemu_component_licenses=GPL-2.0-only,GPL-2.0-or-later,MIT,BSD-2-Clause,BSD-3-Clause
          qemu_combined_work_license=GPL-2.0-only
          qemu_created_source_license=GPL-2.0-or-later
          qemu_generated_boundary_header_license_option=MIT
          qemu_patch_license_inventory=licenses/AOS-QEMU-PATCHES.md
          plugin_source_root=plugin/workspace/crates/crucible-qemu-plugin
          plugin_workspace_root=plugin/workspace/crates
          plugin_cargo_vendor=plugin/cargo-vendor
          plugin_cargo_deps_hash=${cargoDepsHash}
          plugin_license=GPL-2.0-only
          boundary_crates_license_option=MIT
          third_party_license_metadata=plugin/cargo-vendor/*/Cargo.toml
          corresponding_source_scope=qemu-crucible,crucible-qemu-plugin
          MANIFEST

          cat > "$source_root/README" <<'README'
          This directory is the complete corresponding-source companion for the
          qemu-crucible binary identified by SOURCE-MANIFEST.env. It contains
          the exact pinned upstream tarball, the ordered patch manifest and
          patch files, the deterministic Git patch-branch bundle, the generated
          process-boundary header, and a filtered AOS source tree in its original
          relative layout containing the Nix entrypoint and transitive local
          imports that control the build. It also contains the exact filtered
          Crucible workspace and
          fixed-output Cargo vendor tree required to rebuild the GPL in-process
          crucible-qemu-plugin. The upstream COPYING file states the applicable
          QEMU combined-work terms, QEMU-LICENSE.txt defines the per-file
          default, and AOS-QEMU-PATCHES.md inventories every file created by the
          patch series. The plugin workspace carries its own SPDX declarations.

          Reconstruct the patched tree by unpacking upstream/qemu-*.tar.xz and
          applying the files named by patches/_series.nix in order with patch
          -p1. The Git bundle records the same deterministic linear patch stack.

          To rebuild the plugin offline, configure Cargo to replace crates-io
          with plugin/cargo-vendor, enter plugin/workspace/crates, and build
          package crucible-qemu-plugin against the matching qemu-crucible
          headers. Evaluate build/aos/default.nix and select
          `qemu-crucible`; the adjacent package, library, stdenv, test, and
          workspace sources preserve the hermetic AOS build configuration.

          The top-level licenses field and licenses/ directory record AOS/QEMU
          project-component scopes, including both QEMU GPL variants and the
          permissive workspace scopes. They are not an exhaustive inventory for
          vendored third-party crates. Each vendored crate retains its source,
          Cargo license metadata, and license files.
          README

          test "$(find "$source_root/patches" -name '[0-9][0-9][0-9][0-9]-*.patch' | wc -l)" \
            -eq ${toString (builtins.length series.patchFiles)}
          test -s "$source_root/licenses/QEMU-COPYING.txt"
          test -s "$source_root/licenses/QEMU-LICENSE.txt"
          test -s "$source_root/licenses/Apache-2.0.txt"
          test -s "$source_root/licenses/MIT.txt"
          test -s "$source_root/licenses/GPL-2.0-only.txt"
          test -s "$source_root/licenses/GPL-2.0-or-later.txt"
          test -s "$source_root/licenses/AOS-QEMU-PATCHES.md"
          test -s "$source_root/interfaces/crucible_shmem_abi.h"
          test -s "$source_root/patches/crucible-qemu-${version}.bundle"
          test -f "$source_root/build/aos/default.nix"
          test -f "$source_root/build/aos/lib/default.nix"
          test -f "$source_root/build/aos/stdenv/default.nix"
          test -f "$source_root/build/aos/stdenv/phases.nix"
          test -f "$source_root/build/aos/pkgs/default.nix"
          test -f "$source_root/build/aos/pkgs/emulation/qemu.nix"
          test -f "$source_root/build/aos/crates/crucible-shmem/include/crucible_shmem_abi.h"
          test -f "$source_root/build/aos/LICENSES/GPL-2.0-or-later.txt"
          test -f "$source_root/plugin/workspace/crates/Cargo.lock"
          test -f "$source_root/plugin/workspace/crates/crucible-qemu-plugin/Cargo.toml"
          test -f "$source_root/plugin/workspace/pkgs/emulation/crucible-qemu-plugin.nix"
          test -n "$(find "$source_root/plugin/cargo-vendor" -mindepth 1 -maxdepth 1 -type d -print -quit)"

          cat > "$out/nix-support/qemu-crucible-source-build-info" <<'INFO'
          package=qemu-crucible-source
          qemu_package=qemu-crucible
          qemu_build_id=${qemu.qemuBuildIdentity}
          qemu_source_hash=${series.qemuSourceHash}
          aos_build_entrypoint=build/aos/default.nix
          qemu_patch_series_hash=${qemu.patchSeriesHash}
          qemu_patch_branch_bundle_hash=${qemu.patchBranchBundleHash}
          shmem_header_hash=${qemu.shmemHeaderHash}
          plugin_cargo_deps_hash=${cargoDepsHash}
          corresponding_source_scope=qemu-crucible,crucible-qemu-plugin
          licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later,BSD-2-Clause,BSD-3-Clause
          qemu_combined_work_license=GPL-2.0-only
          qemu_created_source_license=GPL-2.0-or-later
          INFO
        '';
      }
    ];

    passthru = {
      qemuPackage = qemu-crucible;
      qemuBuildIdentity = qemu.qemuBuildIdentity;
      qemuSourceHash = series.qemuSourceHash;
      patchSeriesHash = qemu.patchSeriesHash;
      patchBranchBundleHash = qemu.patchBranchBundleHash;
      shmemHeaderHash = qemu.shmemHeaderHash;
      inherit cargoDepsHash;
    };

    meta = {
      description = "Corresponding source for qemu-crucible and its in-process plugin";
      homepage = "https://www.qemu.org";
      license = ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later" "BSD-2-Clause" "BSD-3-Clause"];
    };
  }
