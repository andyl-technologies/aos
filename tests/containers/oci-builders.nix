##! tests/containers/oci-builders.nix -- focused hermetic OCI builder checks.
##!
##! This check is intentionally standalone until the container evaluator owns
##! the repository-wide check wiring.  It builds a real reference-graph delta,
##! two equivalent layers under different derivation names, typed metadata, two
##! platform manifests, and a multi-platform layout.
{
  pkgs,
  lib,
}: let
  oci = import ../../lib/build/oci {
    inherit lib;
    inherit (pkgs) mkDerivation coreutils findutils gzip jq tar;
  };

  base = pkgs.runCommand "oci-builder-fixture-base" {} ''
    mkdir -p "$out/bin" "$out/share"
    printf '%s\n' 'base payload' > "$out/bin/base-tool"
    chmod 0555 "$out/bin/base-tool"
    printf '%s\n' 'not executable' > "$out/share/non-executable"
    chmod 0444 "$out/share/non-executable"
  '';
  application = pkgs.runCommand "oci-builder-fixture-application" {BASE = base;} ''
    mkdir -p "$out/bin" "$out/share"
    printf '%s\n' 'application payload' > "$out/bin/application"
    chmod 0555 "$out/bin/application"
    printf '%s' "$BASE" > "$out/share/base-reference"
  '';
  changedApplication = pkgs.runCommand "oci-builder-fixture-application-changed" {BASE = base;} ''
    mkdir -p "$out/bin" "$out/share"
    printf '%s\n' 'changed application payload' > "$out/bin/application"
    chmod 0555 "$out/bin/application"
    printf '%s' "$BASE" > "$out/share/base-reference"
  '';
  generatedRegistration = pkgs.runCommand "oci-builder-generated-registration" {} ''
    rmdir "$out"
    printf '%s\n' 'generated registration bytes' > "$out"
  '';

  baseLayerA = oci.mkClosureLayer {
    roots = [base];
    pname = "oci-fixture-base-layer-a";
    layerName = "fixture-base";
  };
  baseLayerB = oci.mkClosureLayer {
    roots = [base];
    pname = "oci-fixture-base-layer-b";
    layerName = "fixture-base";
  };
  applicationDelta = oci.mkClosureLayer {
    roots = [application];
    subtractRoots = [base];
    pname = "oci-fixture-application-delta";
    layerName = "fixture-application";
  };
  changedApplicationDelta = oci.mkClosureLayer {
    roots = [changedApplication];
    subtractRoots = [base];
    pname = "oci-fixture-application-changed-delta";
    layerName = "fixture-application";
  };
  metadata = oci.mkRootMetadataLayer {
    pname = "oci-fixture-metadata";
    layerName = "fixture-metadata";
    directories = [
      {
        path = "/tmp";
        mode = "1777";
      }
      {
        path = "/work";
        mode = "0755";
      }
    ];
    files = [
      {
        path = "/etc/os-release";
        mode = "0644";
        text = "ID=aos\nNAME=AOS\n";
      }
      {
        path = "/usr/libexec/aos-container-init";
        mode = "0555";
        text = "fixture init\n";
      }
      {
        path = "/aos-registration";
        mode = "0444";
        source = generatedRegistration;
      }
    ];
    symlinks = [
      {
        path = "/bin/base-tool";
        target = "${base}/bin/base-tool";
        requireExecutable = true;
      }
    ];
    storeLayers = [baseLayerA applicationDelta];
  };
  runtimeAudit = import ../../lib/build/runtime-closure-audit.nix {
    inherit pkgs lib;
    name = "oci-builder-fixture";
    roots = [application];
    maxClosureMiB = 32;
    maxDevelopmentPayloadMiB = 1;
    allowTestArtifacts = true;
  };
  changedRuntimeAudit = import ../../lib/build/runtime-closure-audit.nix {
    inherit pkgs lib;
    name = "oci-builder-changed-fixture";
    roots = [changedApplication];
    maxClosureMiB = 32;
    maxDevelopmentPayloadMiB = 1;
    allowTestArtifacts = true;
  };

  mkPlatformImage = {
    architecture,
    pname ? "oci-fixture-${architecture}-image",
    applicationLayer ? applicationDelta,
    audit ? runtimeAudit,
  }:
    oci.mkImageLayout {
      inherit pname;
      layers = [baseLayerA applicationLayer metadata];
      runtimeAudit = audit;
      platform = {
        inherit architecture;
        os = "linux";
      };
      referenceName = "aos-fixture:latest";
      annotations = {
        "org.opencontainers.image.title" = "AOS OCI builder fixture";
      };
      config = {
        entrypoint = ["/bin/base-tool"];
        cmd = ["--version"];
        env = {
          HOME = "/root";
          PATH = "/bin:/usr/bin";
        };
        user = "0:0";
        workingDir = "/work";
        stopSignal = "SIGTERM";
        exposedPorts = ["8080/tcp"];
        labels = {
          "org.opencontainers.image.vendor" = "Andyl, Inc.";
        };
      };
    };
  amd64Image = mkPlatformImage {architecture = "amd64";};
  equivalentAmd64Image = mkPlatformImage {
    architecture = "amd64";
    pname = "oci-fixture-amd64-image-equivalent-name";
  };
  changedAmd64Image = mkPlatformImage {
    architecture = "amd64";
    pname = "oci-fixture-amd64-image-changed-app";
    applicationLayer = changedApplicationDelta;
    audit = changedRuntimeAudit;
  };
  arm64Image = mkPlatformImage {architecture = "arm64";};
  multiPlatform = oci.mkMultiPlatformIndex {
    pname = "oci-fixture-multi-platform";
    images = [arm64Image amd64Image];
    referenceName = "aos-fixture:latest";
    annotations = {
      "org.opencontainers.image.title" = "AOS multi-platform fixture";
    };
  };
  dockerArchive = oci.mkDockerArchive {
    pname = "oci-fixture-docker-archive";
    image = amd64Image;
    references = ["aos-fixture:latest"];
  };

  validStickyMode = builtins.tryEval (oci.mkRootMetadataLayer {
    pname = "oci-valid-sticky-mode-eval";
    directories = [
      {
        path = "/tmp";
        mode = "1777";
      }
    ];
  });
  invalidMode = builtins.tryEval (oci.mkRootMetadataLayer {
    pname = "oci-invalid-mode-eval";
    directories = [
      {
        path = "/tmp";
        mode = "8888";
      }
    ];
  });
  unsafePath = builtins.tryEval (oci.mkRootMetadataLayer {
    pname = "oci-unsafe-path-eval";
    files = [
      {
        path = "/etc/../escape";
        text = "bad";
      }
    ];
  });
  symlinkParent = builtins.tryEval (oci.mkRootMetadataLayer {
    pname = "oci-symlink-parent-eval";
    files = [
      {
        path = "/redirect/file";
        text = "bad";
      }
    ];
    symlinks = [
      {
        path = "/redirect";
        target = "/tmp";
      }
    ];
  });
  missingFilePayload = builtins.tryEval (oci.mkRootMetadataLayer {
    pname = "oci-missing-file-payload-eval";
    files = [{path = "/missing";}];
  });
  ambiguousFilePayload = builtins.tryEval (oci.mkRootMetadataLayer {
    pname = "oci-ambiguous-file-payload-eval";
    files = [
      {
        path = "/ambiguous";
        text = "inline";
        source = generatedRegistration;
      }
    ];
  });
  hostFileSource = builtins.tryEval (oci.mkRootMetadataLayer {
    pname = "oci-host-file-source-eval";
    files = [
      {
        path = "/host";
        source = "/etc/passwd";
      }
    ];
  });
  referenceVectors = builtins.fromJSON (
    builtins.readFile ../../crates/aos-oci-types/tests/reference-vectors.json
  );
  accepts = validator: value: (builtins.tryEval (validator "test vector" value)).success;
  evalContracts = assert validStickyMode.success;
  assert !invalidMode.success;
  assert !unsafePath.success;
  assert !symlinkParent.success;
  assert !missingFilePayload.success;
  assert !ambiguousFilePayload.success;
  assert !hostFileSource.success;
  assert lib.all (accepts oci.common.validateRepository) referenceVectors.repositories.valid;
  assert lib.all (value: !accepts oci.common.validateRepository value) referenceVectors.repositories.invalid;
  assert lib.all (accepts oci.common.validateTag) referenceVectors.tags.valid;
  assert lib.all (value: !accepts oci.common.validateTag value) referenceVectors.tags.invalid;
  assert lib.all (accepts oci.common.validateTaggedReference) referenceVectors.taggedReferences.valid;
  assert lib.all (value: !accepts oci.common.validateTaggedReference value) referenceVectors.taggedReferences.invalid; true;
in
  builtins.deepSeq evalContracts (pkgs.mkDerivation {
    pname = "aos-oci-builder-check";
    version = "1";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.gzip
      pkgs.grep
      pkgs.jq
      pkgs.tar
      baseLayerA
      baseLayerB
      applicationDelta
      changedApplicationDelta
      metadata
      runtimeAudit
      changedRuntimeAudit
      amd64Image
      equivalentAmd64Image
      changedAmd64Image
      arm64Image
      multiPlatform
      dockerArchive
    ];
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "check";
        script = ''
          set -eu
          export LC_ALL=C

          fail() {
            echo "FAIL: $1" >&2
            exit 1
          }

          ${oci.common.realizedStorePolicyScript}

          validate_disjoint_layer_inventories \
            policy-valid \
            ${baseLayerA} ${applicationDelta}
          if validate_disjoint_layer_inventories \
            policy-overlap \
            ${baseLayerA} ${baseLayerA} 2>/dev/null; then
            fail "realized store-path overlap was accepted"
          fi
          if validate_store_symlink_target \
            policy-valid.allowed \
            /nix/store/00000000000000000000000000000000-missing/bin/tool \
            1 2>/dev/null; then
            fail "facade target absent from the image closure was accepted"
          fi
          if validate_store_symlink_target \
            policy-valid.allowed \
            ${base}/share/non-executable \
            1 2>/dev/null; then
            fail "non-executable facade target was accepted"
          fi
          validate_store_symlink_target \
            policy-valid.allowed \
            ${base}/bin/base-tool \
            1

          assert_compact_sorted_json() {
            json_path="$1"
            jq -cS . "$json_path" > canonical.with-newline
            canonical_size=$(stat -c %s canonical.with-newline)
            truncate -s "$((canonical_size - 1))" canonical.with-newline
            cmp canonical.with-newline "$json_path" \
              || fail "$json_path is not compact sorted JSON"
          }

          verify_descriptor_blob() {
            descriptor="$1"
            blob="$2"
            expected_digest=$(jq -r .digest "$descriptor")
            expected_size=$(jq -r .size "$descriptor")
            actual_digest="sha256:$(sha256sum "$blob" | cut -d ' ' -f 1)"
            actual_size=$(stat -c %s "$blob")
            test "$expected_digest" = "$actual_digest" \
              || fail "descriptor digest mismatch for $blob"
            test "$expected_size" -eq "$actual_size" \
              || fail "descriptor size mismatch for $blob"
          }

          # Derivation names do not enter layer identity or companion metadata.
          diff -r ${baseLayerA} ${baseLayerB} \
            || fail "equivalent closure layers differ by derivation name"
          diff -r ${amd64Image} ${equivalentAmd64Image} \
            || fail "equivalent images differ by derivation name"
          assert_compact_sorted_json ${baseLayerA}/descriptor.json
          assert_compact_sorted_json ${baseLayerA}/closure.json
          verify_descriptor_blob ${baseLayerA}/descriptor.json ${baseLayerA}/blob

          jq -e --arg base ${lib.escapeShellArg (builtins.toString base)} '
            (.paths | length) == 1 and .paths[0].path == $base
          ' ${baseLayerA}/closure.json >/dev/null \
            || fail "base closure inventory is incorrect"
          jq -e --arg app ${lib.escapeShellArg (builtins.toString application)} --arg base ${lib.escapeShellArg (builtins.toString base)} '
            (.paths | length) == 1
            and .paths[0].path == $app
            and ([.paths[].path] | index($base) | not)
          ' ${applicationDelta}/closure.json >/dev/null \
            || fail "closure subtraction did not produce the exact delta"

          original_base_digest=$(jq -r '.layers[0].digest' ${amd64Image}/manifest.json)
          changed_base_digest=$(jq -r '.layers[0].digest' ${changedAmd64Image}/manifest.json)
          original_app_digest=$(jq -r '.layers[1].digest' ${amd64Image}/manifest.json)
          changed_app_digest=$(jq -r '.layers[1].digest' ${changedAmd64Image}/manifest.json)
          test "$original_base_digest" = "$changed_base_digest" \
            || fail "changed application invalidated the canonical base layer"
          test "$original_app_digest" != "$changed_app_digest" \
            || fail "changed application did not produce a changed delta layer"

          mkdir metadata-root
          gzip -dc ${metadata}/blob | tar --same-permissions --no-same-owner -xf - -C metadata-root
          test "$(stat -c %a metadata-root/tmp)" = 1777 \
            || fail "metadata layer lost sticky /tmp mode"
          test "$(readlink metadata-root/bin/base-tool)" = ${lib.escapeShellArg "${base}/bin/base-tool"} \
            || fail "metadata layer changed an authored symlink"
          test -f metadata-root/etc/os-release
          grep -Fx 'generated registration bytes' metadata-root/aos-registration >/dev/null \
            || fail "store-backed metadata source bytes changed"
          test ! -e metadata-root/etc/hosts
          test ! -e metadata-root/etc/resolv.conf

          for image in ${amd64Image} ${arm64Image}; do
            test -f "$image/layout/oci-layout"
            test -f "$image/layout/index.json"
            test -f "$image/image.oci.tar"
            test -z "$(find "$image/layout" -type l -print -quit)" \
              || fail "OCI layout contains a symlink"
            assert_compact_sorted_json "$image/config.json"
            assert_compact_sorted_json "$image/manifest.json"
            assert_compact_sorted_json "$image/layout/index.json"
            jq -e '
              .rootfs.type == "layers"
              and (.rootfs.diff_ids | length) == 3
              and .config.Entrypoint == ["/bin/base-tool"]
              and .config.ExposedPorts == {"8080/tcp": {}}
            ' "$image/config.json" >/dev/null \
              || fail "image config contract is incorrect"
            jq -e '(.layers | length) == 3' "$image/manifest.json" >/dev/null \
              || fail "platform manifest layer count is incorrect"

            for blob in "$image/layout/blobs/sha256/"*; do
              test "$(sha256sum "$blob" | cut -d ' ' -f 1)" = "''${blob##*/}" \
                || fail "layout blob filename does not equal its digest"
            done

            mkdir extracted-layout
            tar -xf "$image/image.oci.tar" -C extracted-layout
            diff -r "$image/layout" extracted-layout \
              || fail "OCI archive does not reproduce its layout"
            rm -rf extracted-layout
          done

          assert_compact_sorted_json ${multiPlatform}/image-index.json
          assert_compact_sorted_json ${multiPlatform}/layout/index.json
          jq -e '
            (.manifests | length) == 2
            and .manifests[0].platform.architecture == "amd64"
            and .manifests[1].platform.architecture == "arm64"
          ' ${multiPlatform}/image-index.json >/dev/null \
            || fail "multi-platform descriptors are missing or not canonical"
          jq -e '
            (.manifests | length) == 1
            and .manifests[0].mediaType == "application/vnd.oci.image.index.v1+json"
          ' ${multiPlatform}/layout/index.json >/dev/null \
            || fail "layout root does not point at the multi-platform index"
          index_digest=$(jq -r .digest ${multiPlatform}/index-descriptor.json)
          index_hex=''${index_digest#sha256:}
          verify_descriptor_blob \
            ${multiPlatform}/index-descriptor.json \
            ${multiPlatform}/layout/blobs/sha256/$index_hex

          base_digest=$(jq -r .digest ${baseLayerA}/descriptor.json)
          base_hex=''${base_digest#sha256:}
          test -f ${multiPlatform}/layout/blobs/sha256/$base_hex \
            || fail "shared base layer is absent from the composed layout"
          test "$(find ${multiPlatform}/layout/blobs/sha256 -name "$base_hex" | wc -l)" -eq 1 \
            || fail "shared base layer was copied more than once"

          mkdir docker-root
          tar -xf ${dockerArchive}/image.docker.tar -C docker-root
          assert_compact_sorted_json docker-root/manifest.json
          jq -e '
            length == 1
            and .[0].RepoTags == ["aos-fixture:latest"]
            and (.[0].Layers | length) == 3
          ' docker-root/manifest.json >/dev/null \
            || fail "Docker archive manifest is incorrect"
          jq -r '.[0].Layers[]' docker-root/manifest.json | while IFS= read -r layer; do
            test -f "docker-root/$layer" \
              || fail "Docker archive layer is missing: $layer"
          done
          test -f ${amd64Image}/runtime-closure-audit.json \
            || fail "image did not retain its required runtime audit report"

          mkdir -p "$out"
          cp ${multiPlatform}/index-descriptor.json "$out/index-descriptor.json"
          printf '%s\n' ok > "$out/result"
        '';
      }
    ];

    meta.description = "Focused deterministic AOS OCI builder conformance check";
  })
