# Defines a separately identified fixed diagnostic; realization needs separate approval.
# The precursor checks certify the unmutated source only; this builder never
# reports a diagnostic execution verdict or installs ordinary qualification.
{
  pkgs,
  omitNotification ? false,
}: let
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  notificationTransform = ./ram-complete-write-oracle-transform.py;
  role =
    if omitNotification
    then "notification-adversary"
    else "oracle-positive";
  transformationIdentity = builtins.hashString "sha256" (builtins.toJSON {
    base = atomicPatch.commit;
    pagedContract = "a2cbeb4e6a557524cfa2876767742eaf0201e15a51309ac9f4281e676361e470";
    notification =
      if omitNotification
      then builtins.hashFile "sha256" notificationTransform
      else null;
    recipe = builtins.hashFile "sha256" ./ram-complete-write-oracle-qemu.nix;
  });
  completeSource = import ./ram-complete-write-oracle-source.nix {
    inherit pkgs omitNotification;
  };
  precursor = pkgs.callPackage ../../pkgs/emulation/qemu.nix {
    pname = "qemu-crucible-complete-write-${role}-${transformationIdentity}";
    enablePlugins = true;
    applyCruciblePatch = true;
    testOnlyNonDistributable = true;
  };
  identity = precursor.passthru;
  diagnosticPhase = {
    name = "rebuild-fixed-diagnostic";
    script = ''
      set -eu
      test -x build/qemu-system-x86_64
      mkdir -p "$out/share/diagnostic/precursor"
      if test -d "$out/share/aos/crucible"; then
        mv "$out/share/aos/crucible" "$out/share/diagnostic/precursor/check-evidence"
      fi
      sha256sum build/qemu-system-x86_64 \
        > "$out/share/diagnostic/precursor/executable.sha256"
      cat > "$out/share/diagnostic/precursor/result" <<'RESULT'
      PASS
      source_identity=${atomicPatch.commit}
      existing_token_specific_oracle_retained=true
      source_has_notification_transform=false
      ordinary_check_phase_unchanged=true
      diagnostic_binary_qualified=false
      RESULT

      # The signed precursor already has the SAME-token no-ack comparison.
      # Preserve it byte-for-byte; only the fixed notification lane differs.
      echo 'a2cbeb4e6a557524cfa2876767742eaf0201e15a51309ac9f4281e676361e470  plugins/crucible-paged-ram.c' \
        | sha256sum -c -
      echo '4f2f7a9d720e141ad8b3f3a1cb9e155ffa6f2c4d1cbb7365bc0f0b3b748fbbd1  system/physmem.c' \
        | sha256sum -c -
      ${pkgs.lib.optionalString omitNotification ''
        cp ${completeSource}/source/system/physmem.c system/physmem.c
      ''}
      make -j$NIX_BUILD_CORES
      cmp plugins/crucible-paged-ram.c ${completeSource}/source/plugins/crucible-paged-ram.c
      cmp system/physmem.c ${completeSource}/source/system/physmem.c
    '';
  };
  installPhase = {
    name = "install-fixed-diagnostic";
    script = ''
      set -eu
      make install
      mkdir -p "$out/include/qemu" "$out/include/aos/crucible"
      install -m 644 include/plugins/qemu-plugin.h "$out/include/qemu/qemu-plugin.h"
      install -m 644 include/aos/crucible/crucible_shmem_abi.h \
        "$out/${identity.shmemHeaderInstallPath}"
      mkdir -p "$out/share/aos/crucible" "$out/share/diagnostic" "$out/nix-support"
      cat > "$out/share/aos/crucible/qemu-build-identity.env" <<'IDENTITY'
      ${identity.qemuBuildIdentityMaterial}
      qemu_build_id=${identity.qemuBuildIdentity}
      qemu_combined_work_license=GPL-2.0-only
      qemu_unmarked_source_default_license=GPL-2.0-or-later
      qemu_plugin_header_license=GPL-2.0-or-later
      qemu_shmem_header_license_option=MIT
      diagnostic_role=${role}
      diagnostic_transformation_identity=${transformationIdentity}
      diagnostic_notification_omitted=${
        if omitNotification
        then "true"
        else "false"
      }
      IDENTITY
      strings "$out/bin/qemu-system-x86_64" | grep -Fxq '${identity.qemuBuildIdentity}'
      sha256sum "$out/bin/qemu-system-x86_64" \
        > "$out/share/diagnostic/pre-fixup-executable.sha256"
      cp -r ${completeSource}/evidence "$out/share/diagnostic/source-evidence"
      ln -s ${completeSource} "$out/share/diagnostic/corresponding-source"
      # Retain the original build entry point, interface, vendored plugin and
      # library sources alongside the exact transformed native tree and tools.
      # This reference is source material, not the base binary's qualification.
      ln -s ${pkgs.qemu-crucible-source} "$out/share/diagnostic/base-rebuild-materials"
      cp ${./ram-complete-write-oracle-qemu.nix} "$out/share/diagnostic/build-recipe.nix"
      mkdir -p "$out/share/licenses/diagnostic"
      cp COPYING LICENSE "$out/share/licenses/diagnostic/"
      cp ${../../pkgs/emulation/qemu-patches/LICENSES.md} \
        "$out/share/licenses/diagnostic/AOS-PATCH-LICENSES.md"
      cat > "$out/nix-support/aos-release-policy" <<'POLICY'
      policy_version=1
      artifact_role=internal-component
      standalone_release=false
      release_via=none-test-only
      corresponding_source_required=true
      corresponding_source_identity=${identity.qemuBuildIdentity}
      publishable=false
      POLICY
      cat > "$out/share/diagnostic/result" <<'RESULT'
      PASS
      artifact_role=test-only-non-distributable-${role}-binary-build
      transformation_identity=${transformationIdentity}
      complete_transformed_corresponding_source_retained=true
      ordinary_positive_checks_apply_to_precursor_only=true
      installed_binary_hash_requires_post_fixup_read=true
      diagnostic_native_execution_qualified=false
      diagnostic_managed_admission_qualified=false
      RESULT
    '';
  };
in
  assert atomicPatch.commit == "fcf3a33f36506fd0f8418ccf9d026d9ed1f35ec0";
  assert !pkgs.stdenv.isCross && pkgs.stdenv.hostPlatform.isLinux;
    precursor.overrideAttrs (original: {
      buildDeps = original.buildDeps ++ [pkgs.coreutils pkgs.diffutils pkgs.grep completeSource];
      phases =
        builtins.concatMap
        (phase:
          if phase.name == "install"
          then [diagnosticPhase installPhase]
          else [phase])
        original.phases;
      passthru =
        original.passthru
        // {
          inherit completeSource transformationIdentity omitNotification;
          diagnosticRole = role;
        };
    })
