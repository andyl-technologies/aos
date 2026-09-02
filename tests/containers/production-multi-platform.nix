##! tests/containers/production-multi-platform.nix -- Production OCI qualification
##!
##! Proves that the real AOS platform artifacts compose into one exact
##! two-platform index and that a fully independent equivalent-input pipeline
##! reproduces every unsigned publication byte.
{
  lib,
  pkgs,
  name,
  primaryIndex,
  repeatIndex,
  evidence,
  evidenceRepeat,
  publicationInputs,
  publicationInputsRepeat,
  schedulerSystem,
  armExecution,
  amdExecution,
  platformChecks,
}:
pkgs.mkDerivation {
  pname = "aos-container-${name}-multi-platform-qualification";
  version = "1";
  src = null;
  buildDeps =
    [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.jq
      pkgs.tar
      primaryIndex
      repeatIndex
      evidence
      evidenceRepeat
      publicationInputs
      publicationInputsRepeat
    ]
    ++ platformChecks;
  outputChecks.out = {};
  unsafeDiscardReferences.out = true;
  phases = [
    {
      name = "qualify";
      script = ''
        set -eu
        export LC_ALL=C

        fail() {
          echo "FAIL: $1" >&2
          exit 1
        }

        diff -r ${primaryIndex} ${repeatIndex} \
          || fail "equivalent multi-platform OCI indexes differ"
        cmp ${primaryIndex}/image.oci.tar ${repeatIndex}/image.oci.tar \
          || fail "equivalent multi-platform OCI archives differ"
        diff -r ${evidence} ${evidenceRepeat} \
          || fail "equivalent multi-platform evidence differs"
        cmp ${evidence}/evidence.oci.tar ${evidenceRepeat}/evidence.oci.tar \
          || fail "equivalent multi-platform evidence archives differ"
        diff -r ${publicationInputs} ${publicationInputsRepeat} \
          || fail "equivalent external-signing input bundles differ"

        jq -e '
          .schemaVersion == 2
          and .mediaType == "application/vnd.oci.image.index.v1+json"
          and (.manifests | length) == 2
          and .manifests[0].platform == {architecture: "amd64", os: "linux"}
          and .manifests[1].platform == {architecture: "arm64", os: "linux"}
          and ([.manifests[].digest] | length) == ([.manifests[].digest] | unique | length)
        ' ${primaryIndex}/image-index.json >/dev/null \
          || fail "production index is not the exact canonical amd64+arm64 set"

        jq -e \
          --slurpfile descriptor ${primaryIndex}/index-descriptor.json \
          --slurpfile index ${primaryIndex}/image-index.json '
            .schema == "aos.container.signature-input/v1"
            and .oci.index == $descriptor[0]
            and .oci.platformManifests == $index[0].manifests
            and (.oci.platformManifests | length) == 2
            and .qualification.readyForVerifiedPublication == true
          ' ${evidence}/signature-input.json >/dev/null \
          || fail "signature input does not bind the coordinated production index"

        jq -e \
          --slurpfile input ${evidence}/signature-input.json '
            .schema == "aos.container.signing-request/v1"
            and .qualified == true
            and .unsignedRelease.oci == $input[0].oci
            and .requiredOutput.finalSidecarPath == "containers/v1/index.json"
            and .constraints.privateMaterialPermittedInNixBuild == false
            and .constraints.exactInputBytesRequired == true
          ' ${evidence}/signing-request.json >/dev/null \
          || fail "external signing request is not bound to the exact unsigned input"

        test ! -e ${publicationInputs}/container-release.json \
          || fail "pure Nix output fabricated a signed container release"
        test -f ${publicationInputs}/EXTERNAL-SIGNING-REQUIRED
        cmp ${publicationInputs}/signature-input.json ${evidence}/signature-input.json
        cmp ${publicationInputs}/signing-request.json ${evidence}/signing-request.json
        diff -r ${publicationInputs}/oci-layout ${primaryIndex}/layout
        diff -r ${publicationInputs}/evidence-layout ${evidence}/layout

        mkdir extracted-layout
        tar -xf ${publicationInputs}/image.oci.tar -C extracted-layout
        diff -r extracted-layout ${publicationInputs}/oci-layout \
          || fail "production OCI archive does not reproduce its layout"

        index_digest=$(jq -r .digest ${primaryIndex}/index-descriptor.json)
        index_hex=''${index_digest#sha256:}
        test -f ${primaryIndex}/layout/blobs/sha256/$index_hex \
          || fail "coordinated index descriptor blob is absent"
        test "$(sha256sum ${primaryIndex}/layout/blobs/sha256/$index_hex | cut -d ' ' -f 1)" = "$index_hex" \
          || fail "coordinated index descriptor blob is corrupt"

        mkdir -p "$out"
        jq -S -n \
          --arg schema 'aos.container.multi-platform-qualification/v1' \
          --arg indexDigest "$index_digest" \
          --arg indexArchiveSha256 "$(sha256sum ${primaryIndex}/image.oci.tar | cut -d ' ' -f 1)" \
          --arg evidenceArchiveSha256 "$(sha256sum ${evidence}/evidence.oci.tar | cut -d ' ' -f 1)" \
          --arg signatureInputSha256 "$(sha256sum ${evidence}/signature-input.json | cut -d ' ' -f 1)" \
          --arg schedulerSystem ${lib.escapeShellArg schedulerSystem} \
          --arg armExecution ${lib.escapeShellArg armExecution} \
          --arg amdExecution ${lib.escapeShellArg amdExecution} '
            {
              schema: $schema,
              systems: ["aarch64-linux", "x86_64-linux"],
              platforms: [
                {os: "linux", architecture: "amd64"},
                {os: "linux", architecture: "arm64"}
              ],
              builderRequirement: {
                schedulerSystem: $schedulerSystem,
                targetSystems: ["aarch64-linux", "x86_64-linux"],
                targetExecution: {
                  "aarch64-linux": $armExecution,
                  "x86_64-linux": $amdExecution
                },
                requiresConfiguredBinfmt: (
                  [
                    {system: "aarch64-linux", mode: $armExecution},
                    {system: "x86_64-linux", mode: $amdExecution}
                  ]
                  | map(select(.mode == "qemu-binfmt") | .system)
                ),
                nativeTargetBuilderRequired: false
              },
              comparisons: {
                platformArtifacts: true,
                index: true,
                evidence: true,
                publicationInputs: true
              },
              indexDigest: $indexDigest,
              sha256: {
                indexArchive: $indexArchiveSha256,
                evidenceArchive: $evidenceArchiveSha256,
                signatureInput: $signatureInputSha256
              }
            }
          ' > "$out/evidence.json"
        printf '%s\n' PASS > "$out/result"
      '';
    }
  ];
  meta.description = "Production amd64 and arm64 OCI artifact qualification";
}
