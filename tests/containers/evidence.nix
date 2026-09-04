##! tests/containers/evidence.nix -- OCI evidence graph and signing seam
{
  pkgs,
  lib,
  evidence,
  evidenceRepeat,
  image,
}: let
  mediaTypes = {
    closure = "application/vnd.aos.nix-closure.v1+json";
    sbom = "application/spdx+json";
    source = "application/vnd.aos.source-closure.v1+json";
    license = "application/vnd.aos.license-report.v1+json";
    provenance = "application/vnd.in-toto+json";
  };
  verifyArtifacts = builtins.concatStringsSep "\n" (
    map
    (role: ''
      descriptor=${evidence}/evidence/${role}.descriptor.json
      manifest=${evidence}/evidence/${role}.manifest.json
      payload=${evidence}/evidence/${role}.payload.json
      artifact_type=${lib.escapeShellArg mediaTypes.${role}}

      manifest_hex=$(sha256sum "$manifest" | cut -d ' ' -f 1)
      manifest_size=$(stat -c %s "$manifest")
      jq -e \
        --arg artifactType "$artifact_type" \
        --arg digest "sha256:$manifest_hex" \
        --argjson size "$manifest_size" '
          .mediaType == "application/vnd.oci.image.manifest.v1+json"
          and .artifactType == $artifactType
          and .digest == $digest
          and .size == $size
        ' "$descriptor" >/dev/null
      cmp "$manifest" "${evidence}/layout/blobs/sha256/$manifest_hex"

      payload_hex=$(sha256sum "$payload" | cut -d ' ' -f 1)
      payload_size=$(stat -c %s "$payload")
      jq -e \
        --arg artifactType "$artifact_type" \
        --arg subjectDigest "$index_digest" \
        --arg payloadDigest "sha256:$payload_hex" \
        --argjson payloadSize "$payload_size" \
        --slurpfile subject ${evidence}/index-descriptor.json '
          .schemaVersion == 2
          and .mediaType == "application/vnd.oci.image.manifest.v1+json"
          and .artifactType == $artifactType
          and .subject.digest == $subjectDigest
          and .subject == $subject[0]
          and .config.mediaType == "application/vnd.oci.empty.v1+json"
          and .config.digest == "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
          and .config.size == 2
          and .layers[0].mediaType == $artifactType
          and .layers[0].digest == $payloadDigest
          and .layers[0].size == $payloadSize
          and (
            if $artifactType == "application/vnd.aos.source-closure.v1+json"
            then
              (.layers | length) == 2
              and .layers[1].mediaType == "application/vnd.aos.source-closure.v1.tar+gzip"
            else (.layers | length) == 1
            end
          )
        ' "$manifest" >/dev/null
      cmp "$payload" "${evidence}/layout/blobs/sha256/$payload_hex"
    '')
    (builtins.attrNames mediaTypes)
  );
in
  pkgs.mkDerivation {
    pname = "aos-container-evidence-check";
    version = "1";
    src = null;
    buildDeps = [pkgs.aos pkgs.coreutils pkgs.diffutils pkgs.findutils pkgs.grep pkgs.gzip pkgs.jq pkgs.tar evidence evidenceRepeat image];
    outputChecks.out = {};
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"

          validate_override_fixture() {
            attrs=$1
            runtime=$2
            jq -e \
              --slurpfile runtime "$runtime" '
                .packageCatalog as $catalog
                | [$catalog[] | select(.override == true)] as $overrides
                | ([ $overrides[].output.path ] | length)
                  == ([ $overrides[].output.path ] | unique | length)
                and all(
                  $overrides[];
                  . as $override
                  | ([ $runtime[0].paths[] | select(.path == $override.output.path) ] | length) == 1
                  and ([
                    $catalog[]
                    | select(.override == false and .output.path == $override.output.path)
                  ] | length) == 0
                )
              ' "$attrs" >/dev/null
          }

          jq -n '{paths: [{path: "/nix/store/00000000000000000000000000000000-generated"}]}' > override-runtime.json
          jq -n '{packageCatalog: [{override: true, output: {path: "/nix/store/00000000000000000000000000000000-generated"}}]}' > override-positive.json
          validate_override_fixture override-positive.json override-runtime.json
          jq -n '{packageCatalog: [{override: true, output: {path: "/nix/store/11111111111111111111111111111111-unused"}}]}' > override-unused.json
          if validate_override_fixture override-unused.json override-runtime.json; then
            echo "unused evidence override was accepted" >&2
            exit 1
          fi
          jq -n '{packageCatalog: [
            {override: true, output: {path: "/nix/store/00000000000000000000000000000000-generated"}},
            {override: false, output: {path: "/nix/store/00000000000000000000000000000000-generated"}}
          ]}' > override-conflicting.json
          if validate_override_fixture override-conflicting.json override-runtime.json; then
            echo "conflicting evidence override was accepted" >&2
            exit 1
          fi

          cmp ${image}/layout/index.json ${evidence}/layout/index.json
          cmp ${image}/image-index.json ${evidence}/image-index.json
          cmp ${image}/index-descriptor.json ${evidence}/index-descriptor.json
          diff -r ${evidence} ${evidenceRepeat}
          cmp ${evidence}/evidence.oci.tar ${evidenceRepeat}/evidence.oci.tar

          index_digest=$(jq -r .digest ${evidence}/index-descriptor.json)
          ${verifyArtifacts}

          jq -e '
            .schemaVersion == 2
            and .mediaType == "application/vnd.oci.image.index.v1+json"
            and (.manifests | length) == 1
            and .manifests[0].mediaType == "application/vnd.oci.image.manifest.v1+json"
          ' ${evidence}/image-index.json >/dev/null
          platform_manifest_hex=$(jq -r '.manifests[0].digest | sub("^sha256:"; "")' ${evidence}/image-index.json)
          platform_manifest=${evidence}/layout/blobs/sha256/$platform_manifest_hex
          test -f "$platform_manifest"
          test "$(sha256sum "$platform_manifest" | cut -d ' ' -f 1)" = "$platform_manifest_hex"
          test "$(stat -c %s "$platform_manifest")" -eq "$(jq -r .manifests[0].size ${evidence}/image-index.json)"

          jq -e \
            --slurpfile subject ${evidence}/index-descriptor.json '
            .schema == "aos.container.nix-closure/v1"
            and .subject == $subject[0]
            and (.layers | length) > 0
            and (.paths | length) > 0
            and all(.paths[];
              .package != null
              and (.package.output | length) > 0
              and (.package.licenses | length) > 0
              and (.package.sources | length) > 0
            )
          ' ${evidence}/evidence/closure.payload.json >/dev/null
          jq -e \
            --slurpfile closure ${evidence}/evidence/closure.payload.json '
              .layers[0:($closure[0].layers | length)] == $closure[0].layers
            ' "$platform_manifest" >/dev/null
          jq -e '
            .spdxVersion == "SPDX-2.3"
            and .dataLicense == "CC0-1.0"
            and (.packages | length) > 0
            and all(.packages[];
              .licenseDeclared == "NOASSERTION"
              and (.comment | contains("AOS package metadata license:"))
            )
          ' ${evidence}/evidence/sbom.payload.json >/dev/null

          source_archive=${evidence}/evidence/source.archive.tar.gz
          source_archive_hex=$(sha256sum "$source_archive" | cut -d ' ' -f 1)
          source_archive_size=$(stat -c %s "$source_archive")
          gzip -t "$source_archive"
          tar -tzf "$source_archive" > source-members
          tar -tvzf "$source_archive" > source-members.verbose
          if grep -q '^h' source-members.verbose; then
            echo "source archive contains a hardlink member" >&2
            exit 1
          fi
          if grep -E '^(/|\.\.(/|$)|.*/\.\.(/|$))' source-members; then
            echo "source archive contains an absolute or traversing member" >&2
            exit 1
          fi
          jq -e \
            --arg digest "sha256:$source_archive_hex" \
            --argjson size "$source_archive_size" '
              .mediaType == "application/vnd.aos.source-closure.v1.tar+gzip"
              and .digest == $digest
              and .size == $size
            ' ${evidence}/evidence/source.archive-descriptor.json >/dev/null
          cmp "$source_archive" "${evidence}/layout/blobs/sha256/$source_archive_hex"
          jq -e \
            --slurpfile descriptor ${evidence}/evidence/source.archive-descriptor.json '
              .schema == "aos.container.source-closure/v1"
              and .archive == $descriptor[0]
              and (.retainedPaths | length) > 0
              and ([.retainedPaths[].path] == ([.retainedPaths[].path] | sort | unique))
              and ([.paths[].sources[].path] | sort | unique) == .sourceRoots
              and (
                . as $payload
                | all($payload.sourceRoots[]; . as $root | any($payload.retainedPaths[]; .path == $root))
              )
            ' ${evidence}/evidence/source.payload.json >/dev/null
          jq -e \
            --slurpfile descriptor ${evidence}/evidence/source.archive-descriptor.json '
              (.layers | length) == 2
              and .layers[1] == $descriptor[0]
            ' ${evidence}/evidence/source.manifest.json >/dev/null

          jq -e '
            .schema == "aos.container.evidence-qualification/v1"
            and (.mapping.complete == ((.mapping.unknownPaths | length) == 0))
            and (.correspondingSource.complete == ((.correspondingSource.unknownPaths | length) == 0))
            and (.licensing.complete == ((.licensing.unknownPaths | length) == 0))
            and (
              .readyForVerifiedPublication
              == (.mapping.complete and .correspondingSource.complete and .licensing.complete)
            )
            and .readyForVerifiedPublication == true
            and ([.mapping.unknownPaths[].path] == ([.mapping.unknownPaths[].path] | sort | unique))
            and ([.correspondingSource.unknownPaths[].path] == ([.correspondingSource.unknownPaths[].path] | sort | unique))
            and ([.licensing.unknownPaths[].path] == ([.licensing.unknownPaths[].path] | sort | unique))
          ' ${evidence}/qualification.json >/dev/null

          jq -e \
            --slurpfile qualification ${evidence}/qualification.json '
              .schema == "aos.container.signature-input/v1"
              and .qualification == $qualification[0]
              and .qualification.readyForVerifiedPublication == true
              and .nix.definition.attribute == "systems.server.build.containers.aos"
              and (.nix.definition.derivationPath | test("^/nix/store/[0-9a-z]{32}-.*[.]drv$"))
              and .nix.output.name == "out"
              and (.nix.output.storePath | test("^/nix/store/[0-9a-z]{32}-"))
              and (.evidence | has("signature") | not)
            ' ${evidence}/signature-input.json >/dev/null
          input_hex=$(sha256sum ${evidence}/signature-input.json | cut -d ' ' -f 1)
          input_size=$(stat -c %s ${evidence}/signature-input.json)
          test "$input_size" -le 4194304
          jq -e \
            --arg digest "sha256:$input_hex" \
            --argjson size "$input_size" \
            --slurpfile input ${evidence}/signature-input.json '
              .schema == "aos.container.signing-request/v1"
              and .input.digest == $digest
              and .input.size == $size
              and .qualified == $input[0].qualification.readyForVerifiedPublication
              and .qualified == true
              and .unsignedRelease.qualification == $input[0].qualification
              and .constraints.privateMaterialPermittedInNixBuild == false
              and .constraints.finalizerMustRejectUnqualifiedInput == true
              and (.unsignedRelease.evidence | has("signature") | not)
            ' ${evidence}/signing-request.json >/dev/null

          jq -cS '
            del(.schema)
            | .schemaVersion = 1
            | .mediaType = "application/vnd.aos.container-release.v1+json"
            | .evidence.signature = {
                mediaType: "application/vnd.oci.image.manifest.v1+json",
                artifactType: "application/vnd.dsse.envelope.v1+json",
                digest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                size: 1
              }
          ' ${evidence}/signature-input.json > signed-sidecar.with-newline.json
          sidecar_size=$(stat -c %s signed-sidecar.with-newline.json)
          truncate -s "$((sidecar_size - 1))" signed-sidecar.with-newline.json
          mv signed-sidecar.with-newline.json signed-sidecar.json
          if ${pkgs.aos}/bin/aos container publish \
            aos example.invalid/team/aos:latest \
            --release signed-sidecar.json \
            --release-layout "$PWD/missing-release-layout" \
            --signature-input ${evidence}/signature-input.json \
            --registry test \
            --idempotency-key evidence-wire-contract \
            --stage-only \
            --registry-token unused \
            >cli-parser.stdout 2>cli-parser.stderr; then
            echo "wire-contract parser unexpectedly reached publication" >&2
            exit 1
          fi
          grep -q 'signed release layout does not exist' cli-parser.stderr

          test ! -e ${evidence}/containers/v1/index.json
          jq -e '
            .schema == "aos.container.publication-roots/v1"
            and (.referrers | length) == 5
            and ([.referrers[].artifactType] == ([.referrers[].artifactType] | sort | unique))
          ' ${evidence}/publication-roots.json >/dev/null
          jq -e \
            --slurpfile roots ${evidence}/publication-roots.json '
            .schemaVersion == 2
            and .mediaType == "application/vnd.oci.image.index.v1+json"
            and (.manifests | length) == 5
            and .manifests == $roots[0].referrers
          ' ${evidence}/referrers/index.json >/dev/null
          jq -e \
            --slurpfile descriptor ${evidence}/index-descriptor.json '
              .image == $descriptor[0]
            ' ${evidence}/publication-roots.json >/dev/null

          find ${evidence}/layout/blobs/sha256 -type f -print | while IFS= read -r blob; do
            expected=''${blob##*/}
            actual=$(sha256sum "$blob" | cut -d ' ' -f 1)
            test "$actual" = "$expected"
          done

          printf '%s\n' PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Deterministic unsigned OCI container evidence check";
  }
