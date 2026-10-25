{
  sourceGate,
  sharedDirectoryProof,
  portableSharedModes,
  initialEnrollmentProof,
  ...
}: {
  shared-dir-read-only = sourceGate "shared-dir-read-only" ''
    test "$(cat ${sharedDirectoryProof.readOnly}/result)" = PASS
    test "$(cat ${portableSharedModes}/result)" = PASS
    mkdir -p "$out/nix-support"
    printf '%s\n' ${sharedDirectoryProof.readOnly} > "$out/nix-support/shared-directory-proof"
    printf '%s\n' ${portableSharedModes} > "$out/nix-support/shared-modes-proof"
    printf 'PASS: actual existing host reads preserve encoded bytes and never write\n' > "$out/result"
  '';

  dom-host-isolation = sourceGate "dom-host-isolation" ''
    test "$(cat ${sharedDirectoryProof.isolation}/result)" = PASS
    test "$(cat ${initialEnrollmentProof.privateRelease}/result)" = PASS
    test "$(cat ${initialEnrollmentProof.coldPrivateRelease}/result)" = PASS
    test "$(cat ${initialEnrollmentProof.coldManifestRelease}/result)" = PASS
    mkdir -p "$out/nix-support"
    printf '%s\n' ${sharedDirectoryProof.isolation} > "$out/nix-support/shared-isolation-proof"
    printf '%s\n' ${initialEnrollmentProof.privateRelease} > "$out/nix-support/private-release-proof"
    printf '%s\n' ${initialEnrollmentProof.coldPrivateRelease} ${initialEnrollmentProof.coldManifestRelease} > "$out/nix-support/cold-release-proofs"
    printf 'PASS: independent scoped directory routes and private-cache refusal\n' > "$out/result"
  '';
}
