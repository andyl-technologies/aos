# Fixed native-host qualification of architecture-specific timer units.
{
  lib,
  enabled,
  applyCruciblePatch,
  testOnlyNonDistributable,
  fullUpstreamTestSuiteOnly,
  enableLinuxUser,
  isNativeLinux,
  ninja,
  python3,
  qemuBuildIdentity,
  qemuBuildIdentityMaterial,
}: let
  targets = [
    "hppa-softmmu"
    "loongarch64-softmmu"
    "ppc-softmmu"
    "mips64el-softmmu"
    "sparc64-softmmu"
  ];
  units = [
    "test-crucible-hppa-timer-wide-clock"
    "test-crucible-loongarch-timer-wide-clock"
    "test-crucible-ppc-wide-clock"
    "test-crucible-mips-count-wide-clock"
    "test-crucible-sparc-wide-clock"
  ];
  validator = ../../tests/crucible/phase2-qemu-cross-target-clock-units.py;
in {
  policy =
    if !enabled
    then null
    else if !applyCruciblePatch || !testOnlyNonDistributable
    then throw "clock unit qualification requires a non-distributable patched test artifact"
    else if !isNativeLinux || enableLinuxUser || fullUpstreamTestSuiteOnly
    then throw "clock unit qualification requires its fixed native Linux system-only profile"
    else null;

  targetFlag = "--target-list=${builtins.concatStringsSep "," targets}";
  identityMaterial = ''
    qualification_scope=architecture-clock-units
    qualification_helper_hash=${builtins.hashFile "sha256" ./_qemu-clock-unit-qualification.nix}
    qualification_validator_hash=${builtins.hashFile "sha256" validator}
    qualification_units=${builtins.concatStringsSep "," units}
  '';

  buildScript = ''
    ${python3}/bin/python3 ${validator} configured build
    ${ninja}/bin/ninja -C build -j$NIX_BUILD_CORES \
      ${lib.concatMapStringsSep " " (unit: "tests/unit/${unit}") units}
  '';

  checkScript = ''
    # Meson keeps each registered unit's original 30-second budget and TAP args.
    if ! build/pyvenv/bin/meson test -C build --no-rebuild \
      --num-processes 1 --print-errorlogs --logbase crucible-clock-units \
      ${builtins.concatStringsSep " " units} > clock-units.result 2>&1; then
      cat clock-units.result
      exit 1
    fi
    cat clock-units.result
    ${python3}/bin/python3 ${validator} executed \
      build/meson-logs/crucible-clock-units.json
  '';

  installScript = ''
    # Only evidence is retained; no emulator or linked unit is installed.
    evidence_dir="$out/share/aos/crucible"
    mkdir -p "$evidence_dir"
    cp clock-units.result "$evidence_dir/clock-units.result"
    cp build/meson-logs/crucible-clock-units.json \
      "$evidence_dir/clock-units.meson-log.json"
    cp build/meson-logs/crucible-clock-units.txt \
      "$evidence_dir/clock-units.meson-log.txt"
    cp build/meson-info/intro-tests.json "$evidence_dir/configured-tests.json"
    for target in ${builtins.concatStringsSep " " targets}; do
      sha256sum "build/$target-config-target.h"
    done > "$evidence_dir/generated-target-headers.sha256"
    cat > "$evidence_dir/qemu-build-identity.env" <<'IDENTITY'
    qemu_build_id=${qemuBuildIdentity}
    ${qemuBuildIdentityMaterial}
    test_only_non_distributable=true
    qualification_scope=architecture-clock-units
    IDENTITY
  '';
}
