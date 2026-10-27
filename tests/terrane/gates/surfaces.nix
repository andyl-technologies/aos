{
  pkgs,
  lib,
  sourceGateWithInputs,
  nativeSdkTestImage,
  ...
}: let
  testImage = import ../surface-test-image.nix {
    sourceGate = sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.diffutils] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    };
  };
  proof = import ../surface-contract-proof.nix {
    inherit pkgs lib testImage;
    nativeImage = nativeSdkTestImage;
  };
  presentationVm = import ../surface-presentation-ext4.nix {
    inherit pkgs lib testImage;
  };
  surfaceGate = name: suite: script:
    sourceGateWithInputs {} name ''
      test "$(cat ${proof.${suite}}/result)" = PASS
      mkdir -p "$out/nix-support"
      printf '%s\n' ${proof.${suite}} > "$out/nix-support/surface-contract-proof"
      ${script}
    '';
in {
  surface-interface = surfaceGate "surface-interface" "interface" ''
    printf 'PASS: compiled registry, exposure contract and atomic preparation\n' > "$out/result"
  '';
  surface-commit-path = surfaceGate "surface-commit-path" "commit-path" ''
    printf 'PASS: T2 read-only SDK refuses every configured write path; writable surfaces remain unavailable\n' > "$out/result"
  '';
  surface-schema = surfaceGate "surface-schema" "schema" ''
    printf 'PASS: metadata schemas refuse invalid SDK roots before presentation\n' > "$out/result"
  '';
  surface-status = surfaceGate "surface-status" "status" ''
    test "$(cat ${presentationVm}/result)" = PASS
    printf '%s\n' ${presentationVm} > "$out/nix-support/presentation-proof"
    printf 'PASS: pinned SDK identity, status and monotonic lifecycle\n' > "$out/result"
  '';
}
