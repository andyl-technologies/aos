##! tests/containers/oci-builders.nix -- focused hermetic OCI builder checks.
##!
##! The container.oci-builders check builds a real reference-graph delta,
##! two equivalent layers under different derivation names, typed metadata, two
##! platform manifests, and a multi-platform layout.
{
  pkgs,
  lib,
}: let
  oci = pkgs.ociTools;
  originResolution = import ./package-origin-resolution.nix {inherit pkgs lib;};
  nativeBackend =
    (lib.evalPackageModules {
      packages = [pkgs.aos-oci-backend];
      scope = ["profile" "system"];
    })
    .config
    .aos
    .artifacts
    .backend;
  malformedBackend = builtins.tryEval (builtins.deepSeq
    ((lib.evalModules {
        inherit lib;
        modules = [
          ../../pkgs/containers/_aos-oci-backend/backend-option.nix
          {
            config.aos.artifacts.backend = {
              _type = "aos-package-artifact-backend";
              name = "partial";
              package = "/nix/store/00000000000000000000000000000000-partial";
              buildDeploymentArtifact = _: {};
            };
          }
        ];
      })
      .config
      .aos
      .artifacts
      .backend)
    true);

  nativeHandler = pkgs.mkDerivation {
    pname = "oci-native-fixture";
    version = "1";
    src = null;
    module = ./_native-fixture;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' 'fixture handler' > "$out/bin/fixture-handler"
          chmod 0555 "$out/bin/fixture-handler"
        '';
      }
    ];
    meta = {
      mainProgram = "fixture-handler";
      license = "Apache-2.0";
    };
  };
  namedOutputFixture = pkgs.mkDerivation {
    pname = "oci-profile-output-fixture";
    version = "1";
    outputs = ["out" "dev"];
    src = null;
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The selected payload and development header.";
        operation = "Read both exact retained output files.";
        expected = "Both files contain their declared fixture bytes.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@python@" "-c" "from pathlib import Path; assert Path('@out@/share/payload').read_text() == 'payload\\n'; assert Path('@output:dev@/include/header').read_text() == 'header\\n'"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A missing payload file.";
        operation = "Attempt to read an undeclared fixture member.";
        expected = "Opening the missing member fails.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@python@" "-c" "from pathlib import Path; Path('@out@/share/missing').read_bytes()"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
      };
    };
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share" "$dev/include"
          printf '%s\n' payload > "$out/share/payload"
          printf '%s\n' header > "$dev/include/header"
        '';
      }
    ];
    meta.license = "Apache-2.0";
  };
  base = pkgs.runCommand "oci-builder-fixture-base" {} ''
    mkdir -p "$out/bin" "$out/share/nested"
    printf '%s\n' 'base payload' > "$out/bin/base-tool"
    chmod 0555 "$out/bin/base-tool"
    printf '%s\n' 'not executable' > "$out/share/non-executable"
    chmod 0444 "$out/share/non-executable"
    ln -s share "$out/share-link"
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
  abilityLayer = oci.mkClosureLayer {
    roots = [nativeHandler];
    pname = "oci-fixture-ability-layer";
    layerName = "fixture-ability";
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
        path = "/usr/lib/aos/nix-registration";
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
      {
        path = "/usr/lib/base-runtime";
        target = builtins.toString base;
        targetType = "directory";
      }
    ];
    storeLayers = [baseLayerA applicationDelta abilityLayer];
  };
  runtimeAudit = lib.build.runtimeClosureAudit {
    inherit pkgs;
    name = "oci-builder-fixture";
    roots = [application nativeHandler];
    maxClosureMiB = 32;
    maxDevelopmentPayloadMiB = 1;
    allowTestArtifacts = true;
  };
  changedRuntimeAudit = lib.build.runtimeClosureAudit {
    inherit pkgs;
    name = "oci-builder-changed-fixture";
    roots = [changedApplication nativeHandler];
    maxClosureMiB = 32;
    maxDevelopmentPayloadMiB = 1;
    allowTestArtifacts = true;
  };
  profileScope = ["profile" "system"];
  profilePackages = [application nativeHandler namedOutputFixture.dev];
  profileDescriptor = lib.build.evaluationInput {
    inherit lib pkgs;
    packages = profilePackages;
    scope = profileScope;
    system = lib.platform.system;
  };
  profileEvaluation = lib.evalPackageModules {
    scope = profileScope;
    packages = profilePackages;
    evaluationInput = profileDescriptor;
    evaluationInputs = [lib.packageModuleLibrary profileDescriptor];
  };
  profileBundle = import ../../pkgs/containers/_aos-oci-backend/deployment-bundle.nix {
    inherit lib pkgs;
    packages = profilePackages;
    scope = profileScope;
    inherit (profileEvaluation.deployment) graph system inputs;
    evaluationInput = profileDescriptor;
    withProfileRecords = true;
  };
  artifactFor = architecture: applicationRoot:
    oci.mkDeploymentArtifact {
      inherit pkgs;
      pname = "oci-fixture-${architecture}-deployment";
      platform = {
        inherit architecture;
        os = "linux";
      };
      scope = ["container" "oci-fixture"];
      packages = [applicationRoot nativeHandler];
    };
  amd64Deployment = artifactFor "amd64" application;
  arm64Deployment = artifactFor "arm64" application;
  changedDeployment = artifactFor "amd64" changedApplication;
  aggregateDeployment = oci.mkDeploymentArtifact {
    pname = "oci-fixture-aggregate-deployment";
    contracts = [arm64Deployment amd64Deployment];
  };
  mkPlatformImage = architecture: pname: applicationLayer: audit: deploymentArtifact:
    oci.mkImageLayout {
      inherit pname deploymentArtifact;
      layers = [baseLayerA applicationLayer abilityLayer metadata];
      runtimeAudit = audit;
      referenceName = "aos-fixture:latest";
      config = {
        entrypoint = ["/bin/base-tool"];
        cmd = ["--version"];
        env = {
          HOME = "/root";
          PATH = "/bin:/usr/bin";
        };
        user = "0:0";
        workingDir = "/work";
        exposedPorts = ["8080/tcp"];
      };
    };
  amd64Image = mkPlatformImage "amd64" "oci-fixture-amd64-image" applicationDelta runtimeAudit amd64Deployment;
  equivalentAmd64Image = mkPlatformImage "amd64" "oci-fixture-equivalent-image" applicationDelta runtimeAudit amd64Deployment;
  changedAmd64Image = mkPlatformImage "amd64" "oci-fixture-changed-image" changedApplicationDelta changedRuntimeAudit changedDeployment;
  arm64Image = mkPlatformImage "arm64" "oci-fixture-arm64-image" applicationDelta runtimeAudit arm64Deployment;
  multiPlatform = oci.mkMultiPlatformIndex {
    images = [arm64Image amd64Image];
    deploymentArtifact = aggregateDeployment;
    referenceName = "aos-fixture:latest";
    pname = "oci-fixture-multi-platform";
  };
  singlePlatform = oci.mkMultiPlatformIndex {
    images = [amd64Image];
    deploymentArtifact = amd64Deployment;
    referenceName = "aos-fixture:latest";
    pname = "oci-fixture-single-platform";
  };
  dockerArchive = oci.mkDockerArchive {
    image = amd64Image;
    references = ["aos-fixture:latest"];
    pname = "oci-fixture-docker-archive";
  };
  tryBuilder = value: builtins.tryEval (builtins.deepSeq value true);
  aggregateContractMismatch = tryBuilder (oci.mkMultiPlatformIndex {
    images = [arm64Image amd64Image];
    deploymentArtifact = amd64Deployment;
  });
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
  openPlatform = oci.common.validatePlatform {
    os = "otheros";
    architecture = "riscv64";
  };
  tryPlatform = platform:
    builtins.tryEval (builtins.deepSeq (oci.common.validatePlatform platform) true);
  missingPlatformOs = tryPlatform {
    architecture = "riscv64";
  };
  inventedPlatformField = tryPlatform {
    os = "otheros";
    architecture = "riscv64";
    vendor = "forged";
  };
  evalContracts = assert originResolution;
  assert nativeBackend.name == "oci";
  assert builtins.toString nativeBackend.artifact == builtins.toString pkgs.aos-oci-backend;
  assert !malformedBackend.success;
  assert validStickyMode.success;
  assert !invalidMode.success;
  assert !unsafePath.success;
  assert !symlinkParent.success;
  assert !missingFilePayload.success;
  assert !ambiguousFilePayload.success;
  assert !hostFileSource.success;
  assert !missingPlatformOs.success;
  assert !inventedPlatformField.success;
  assert !aggregateContractMismatch.success;
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
    outputChecks.out = {};
    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.findutils
      pkgs.gzip
      pkgs.grep
      pkgs.jq
      pkgs.tar
      pkgs.aos-deployment-check
      profileBundle
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
      singlePlatform
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
          fail() { echo "FAIL: $1" >&2; exit 1; }
          ${builtins.readFile ../../pkgs/containers/_aos-oci-backend/oci/deployment-validation.sh}
          validate_deployment_artifact ${amd64Deployment.artifact}/deployment.json ${pkgs.aos-deployment-check}/bin/aos-deployment-check ${pkgs.jq}/bin/jq
          for mutation in \
            '.platforms += [.platforms[0]]' \
            '.platforms[0].transaction.graph.order += [.platforms[0].transaction.graph.order[0]]' \
            '.platforms[0].packages.artifacts[0].version = "forged"'; do
            jq "$mutation" ${amd64Deployment.artifact}/deployment.json > mutated-deployment.json
            if validate_deployment_artifact mutated-deployment.json ${pkgs.aos-deployment-check}/bin/aos-deployment-check ${pkgs.jq}/bin/jq; then
              fail "native deployment accepted mutation: $mutation"
            fi
          done
          test -f ${profileBundle}/transaction.json
          test -f ${profileBundle}/packages.json
          test -f ${profileBundle}/evaluation.json
          jq -e '.schema == "aos.package.evaluation-input" and .scope == ["profile","system"]
            and (.libraryNarHash | test("^sha256:[0-9a-f]{64}$"))' \
            ${profileBundle}/evaluation.json >/dev/null
          jq -e --arg selectedOutput ${lib.escapeShellArg (builtins.toString namedOutputFixture.dev)} \
            'length == 3 and ([.[] | select(.apm.explicit)] | length) == 3
            and ([.[] | select(.apm.name == "oci-profile-output-fixture")] | length) == 1
            and any(.[]; .store_path == $selectedOutput)
            and all(.[];
            .apm.registry == "image"
            and .apm.qualification == null
            and (.apm.deployment.store_path | startswith("/nix/store/"))
            and (.apm.deployment.document_sha256 | test("^sha256:[0-9a-f]{64}$")))' \
            ${profileBundle}/installed.json >/dev/null
          jq -c '.[] | .apm.deployment, (.apm.module_documentation // empty), (.apm.qualification // empty)' ${profileBundle}/installed.json |
          while IFS= read -r locator; do
            root=$(printf '%s\n' "$locator" | jq -r .store_path)
            expected=$(printf '%s\n' "$locator" | jq -r .document_sha256)
            document="$root/deployment.json"
            if [ ! -f "$document" ]; then document="$root/options.json"; fi
            if [ ! -f "$document" ]; then document="$root/qualification.json"; fi
            test "$expected" = "sha256:$(sha256sum "$document" | cut -d ' ' -f 1)"
            printf '%s\n' "$locator" > locator.json
            jq -e --slurpfile locator locator.json '
              any(.roots[]; .storePath == $locator[0].store_path
                and .narHash == $locator[0].nar_hash and .narSize == $locator[0].nar_size
                and .references == $locator[0].references)
            ' ${profileBundle}/admission.json >/dev/null
          done
          jq -n --slurpfile packages ${profileBundle}/packages.json \
            --slurpfile transaction ${profileBundle}/transaction.json \
            '{packages:$packages[0],transaction:$transaction[0]}' |
            ${pkgs.aos-deployment-check}/bin/aos-deployment-check

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
                validate_store_directory_target policy-valid.allowed ${base}
                validate_store_directory_target policy-valid.allowed ${base}/share
                for directory_target in \
                  /nix/store/00000000000000000000000000000000-missing \
                  ${nativeHandler} \
                  ${base}/share-link \
                  ${base}/share-link/nested \
                  ${base}/share-link/../share \
                  ${base}/share/../share \
                  ${base}/bin/base-tool; do
                  if validate_store_directory_target \
                    policy-valid.allowed "$directory_target" 2>/dev/null; then
                    fail "invalid directory target was accepted: $directory_target"
                  fi
                done
                if validate_store_symlink_target \
                  policy-valid.allowed ${base} 0 2>/dev/null; then
                  fail "file target validation accepted a directory"
                fi

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

                # Derivation names do not enter layer or package-document identity.
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
                test "$(readlink metadata-root/usr/lib/base-runtime)" = ${lib.escapeShellArg (builtins.toString base)} \
                  || fail "metadata layer changed its admitted directory target"
                test -f metadata-root/etc/os-release
                grep -Fx 'generated registration bytes' metadata-root/usr/lib/aos/nix-registration >/dev/null \
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
                    and (.rootfs.diff_ids | length) == 4
                    and .config.Entrypoint == ["/bin/base-tool"]
                    and .config.ExposedPorts == {"8080/tcp": {}}
                  ' "$image/config.json" >/dev/null \
                    || fail "image config contract is incorrect"
                  jq -e '(.layers | length) == 4' "$image/manifest.json" >/dev/null \
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

                manifest_hex=$(jq -r '.digest | sub("^sha256:"; "")' ${amd64Image}/manifest-descriptor.json)
                cp ${amd64Image}/manifest.json mismatched-manifest-sidecar.json
                jq -cS '.annotations."dev.andyl.aos.deployment.digest" = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
                  mismatched-manifest-sidecar.json > mismatched-manifest-sidecar.next.json
                mv mismatched-manifest-sidecar.next.json mismatched-manifest-sidecar.json
                if cmp mismatched-manifest-sidecar.json ${amd64Image}/layout/blobs/sha256/$manifest_hex; then
                  fail "mismatched platform manifest sidecar/blob fixture was accepted"
                fi

                assert_compact_sorted_json ${multiPlatform}/image-index.json
                assert_compact_sorted_json ${multiPlatform}/layout/index.json
                deployment_hex=$(sha256sum ${multiPlatform}/deployment.json | cut -d ' ' -f 1)
                jq -e --arg handler ${lib.escapeShellArg (builtins.toString nativeHandler)} '
                  .schema == "aos.artifact.deployment/v1"
                  and (.platforms | length) == 2
                  and all(.platforms[];
                    .transaction.artifacts == .packages.artifacts
                    and (.transaction.graph.nodes | length) == 1
                    and any(.transaction.artifacts[]; .path == $handler)
                  )
                ' ${multiPlatform}/deployment.json >/dev/null || fail "native graph identities were lost"
                jq -e --arg abilityDigest "sha256:$deployment_hex" '
                  (.manifests | length) == 2
                  and .manifests[0].platform.architecture == "amd64"
                  and .manifests[1].platform.architecture == "arm64"
                  and .annotations."dev.andyl.aos.deployment.digest" == $abilityDigest
                ' ${multiPlatform}/image-index.json >/dev/null \
                  || fail "multi-platform descriptors are missing or not canonical"
                jq -e '
                  (.manifests | length) == 1
                  and .manifests[0].mediaType == "application/vnd.oci.image.index.v1+json"
                ' ${multiPlatform}/layout/index.json >/dev/null \
                  || fail "layout root does not point at the multi-platform index"
                jq -e \
                  --slurpfile descriptor ${multiPlatform}/index-descriptor.json \
                  --slurpfile index ${multiPlatform}/image-index.json '
                    .manifests == [$descriptor[0]]
                    and $descriptor[0].annotations == $index[0].annotations
                    and $descriptor[0].annotations."org.opencontainers.image.ref.name"
                      == "aos-fixture:latest"
                  ' ${multiPlatform}/layout/index.json >/dev/null \
                  || fail "layout root descriptor annotations diverge from the image index"
                index_digest=$(jq -r .digest ${multiPlatform}/index-descriptor.json)
                index_hex=''${index_digest#sha256:}
                verify_descriptor_blob \
                  ${multiPlatform}/index-descriptor.json \
                  ${multiPlatform}/layout/blobs/sha256/$index_hex

                single_index_digest=$(jq -r .digest ${singlePlatform}/index-descriptor.json)
                single_index_hex=''${single_index_digest#sha256:}
                verify_descriptor_blob \
                  ${singlePlatform}/index-descriptor.json \
                  ${singlePlatform}/layout/blobs/sha256/$single_index_hex
                test "$(find ${singlePlatform}/layout/blobs/sha256 -name "$single_index_hex" | wc -l)" -eq 1 \
                  || fail "single-platform index did not reuse its identical input blob"

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
                  and (.[0].Layers | length) == 4
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
    meta.description = "Deterministic OCI builders with native deployment preflight";
  })
