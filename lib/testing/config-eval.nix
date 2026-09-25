# lib/testing/config-eval.nix — off-host config-eval preflight gate.
#
# operability.md §Off-host CI preflight: a pure-eval derivation that exercises
# the production config-eval path the host consumes, with the same
# deterministic evaluation discipline as the production path:
#
#   1. the module set EVALUATES (else fail with the module-system error);
#   2. the rendered config inputs are SCHEMA-VALID; and
#   3. they are DETERMINISTIC — eval twice, assert byte-identical output.
#
# It also covers trust-anchor rendering (`aos.apm.configKeys` ->
# /etc/apm/trusted-config-keys.d/<op>.pub) and the platform-versus-signed
# host-configuration policy.
#
# Runs via `nix-build -A checks.config-eval`.
{
  pkgs,
  lib,
  mkSystem,
}: let
  frozenPackageChecks = import ./frozen-pkgs.nix {inherit lib;};

  opKey = "ops:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIJiuCf/fX/rsn5ODyT5ebEVtabAmZceKi2aD+cBWjWKL";

  # A well-formed system declaring one operator config key.
  mkConfigSystem = keys:
    mkSystem {
      modules = [
        ../../systems/server.nix
        {aos.apm.configKeys.ops = keys;}
      ];
    };

  systemA = mkConfigSystem [opKey];
  anchorPath = "apm/trusted-config-keys.d/ops.pub";
  anchorA = systemA.config.environment.etc.${anchorPath}.text;

  # Invalid-input cases exercise the real domain modules without constructing
  # several full server fixed points. The check phase independently evaluates
  # the production host manifest twice and compares both results.
  focusedTrustEvaluation = module:
    lib.evalModules {
      inherit pkgs lib;
      modules = [
        ../../modules/base/build.nix
        ../../modules/base/apm-registries.nix
        ../../modules/base/config-eval.nix
        module
      ];
    };
  rejectsAssertion = message: evaluation:
    builtins.any
    (entry: !entry.assertion && lib.hasInfix message entry.message)
    evaluation.config.assertions;
  signedTrustEvaluation = focusedTrustEvaluation {
    aos.apm.configKeys.ops = [opKey];
    aos.config.evalAtBoot.trust = "signed";
  };

  hostSource = pkgs.runCommand "source" {} ''
    mkdir -p "$out"
    cat > "$out/host.nix" <<'EOF'
    {
      aos.networking.hostName = "config-eval-preflight";
      environment.etc."config-eval/preflight" = {
        text = "enabled\n";
        mode = "0644";
      };
      aos.security.pki.certificates = [ "-----BEGIN CERTIFICATE-----\nMAgwADAAAwIAAA==\n-----END CERTIFICATE-----\n" ];
    }
    EOF
  '';
  hostFixture = "${hostSource}/host.nix";
  factsFixture = builtins.toFile "config-eval-preflight-facts.json" "{}\n";
  baseLib = systemA.config.aos.config.evalAtBoot.baseLib;
  hostStaticContract = systemA.config.system.build.staticAbilityContract;
  moduleAbi = systemA.config.aos.system.moduleAbi;
  evalInputClosure = import ../build/closure-info.nix {inherit pkgs lib;} {
    pname = "config-eval-input-closure";
    rootPaths = [baseLib hostStaticContract hostSource factsFixture];
  };

  # (1) eval succeeds; the build phase checks deterministic repeated evaluation.
  evalSucceeds = builtins.isString anchorA;

  # (2) schema-valid: every line is `<op>:Ed25519:<base64>`.
  anchorLines = builtins.filter (l: l != "") (lib.splitString "\n" anchorA);
  lineWellFormed = line: builtins.match "ops:Ed25519:[A-Za-z0-9+/]+=*" line != null;
  schemaValid = anchorLines != [] && builtins.all lineWellFormed anchorLines;

  brokenKeyRejected =
    rejectsAssertion
    "config key 'ops:RSA:not-a-real-key'"
    (focusedTrustEvaluation {aos.apm.configKeys.ops = ["ops:RSA:not-a-real-key"];});
  mismatchRejected =
    rejectsAssertion
    "config key 'other:Ed25519:AAAA'"
    (focusedTrustEvaluation {aos.apm.configKeys.ops = ["other:Ed25519:AAAA"];});

  defaultTrustsPlatform =
    systemA.config.aos.config.evalAtBoot.trust == "platform";
  metadataProviderRoots =
    builtins.filter
    (root:
      builtins.match
      "/nix/store/[a-z0-9]+-aos-initrd-runtime-files-aos-metadata-provider"
      root
      != null)
    systemA.config.aos.boot.initrd.runtimeRoots;
  evalServices =
    builtins.filter
    (resource:
      resource.kind
      == "aos.service.instance"
      && (resource.value.manager_identity.name or resource.value.service) == "aos-eval")
    (builtins.attrValues systemA.config.aos.abilities.resolvedResources);
  evalService =
    if builtins.length evalServices == 1
    then builtins.head evalServices
    else throw "config-eval: the server fixed point must contain one package-owned evaluation service";
  stage2Arguments =
    (builtins.head evalService.value.lifecycle.start).executable.arguments;
  signedModeRequiresSignature =
    signedTrustEvaluation.config.aos.config.evalAtBoot.trust
    == "signed"
    && signedTrustEvaluation.config.environment.etc.${anchorPath}.text == anchorA
    && builtins.length metadataProviderRoots == 1;
  stage2UsesRetainedManifest =
    builtins.elem "__eval-service" stage2Arguments
    && !(builtins.any
      (argument:
        builtins.isString argument
        && lib.hasInfix "/run/aos-metadata" argument)
      stage2Arguments)
    && !(builtins.elem "--host-nix" stage2Arguments);
  signedModeWithoutKeyThrows =
    rejectsAssertion
    "requires at least one aos.apm.configKeys trust anchor"
    (focusedTrustEvaluation {aos.config.evalAtBoot.trust = "signed";});

  evalAssertions =
    lib.throwIfNot evalSucceeds
    "config-eval: the config module set must evaluate"
    (lib.throwIfNot schemaValid
      "config-eval: rendered trusted-config-keys.d must be schema-valid '<op>:Ed25519:<base64>' lines"
      (lib.throwIfNot brokenKeyRejected
        "config-eval: a malformed operator config key must fire a fail-closed assertion"
        (lib.throwIfNot mismatchRejected
          "config-eval: an operator-prefix mismatch must be rejected"
          (lib.throwIfNot defaultTrustsPlatform
            "config-eval: the stock image must trust platform-authorized provisioning input"
            (lib.throwIfNot signedModeRequiresSignature
              "config-eval: signed policy must retain the configured trust anchor and metadata provider"
              (lib.throwIfNot stage2UsesRetainedManifest
                "config-eval: stage 2 must consume retained manifest inputs without an ambient metadata path"
                (lib.throwIfNot signedModeWithoutKeyThrows
                  "config-eval: signed policy without a trust anchor must fail evaluation"
                  true)))))));
in
  pkgs.mkDerivation {
    pname = "config-eval-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.aos pkgs.coreutils pkgs.diffutils pkgs.jq pkgs.nix baseLib evalInputClosure];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString evalAssertions}
          : ${builtins.toString frozenPackageChecks}
          mkdir -p "$out"
          eval_state="$TMPDIR/aos-root"
          profile_root="$TMPDIR/profiles"
          config_root="$TMPDIR/apm-config"
          cache_root="$TMPDIR/native-cache"
          first_root="$TMPDIR/eval-first"
          second_root="$TMPDIR/eval-second"
          mkdir -p \
            "$eval_state/var/lib/apm/config/registries.d" \
            "$profile_root/system" \
            "$config_root/registries.d" \
            "$cache_root" \
            "$first_root" \
            "$second_root"

          eval_store_root="$TMPDIR/nix-eval-store"
          eval_store="local?root=$eval_store_root"
          eval_base_lib=${baseLib}
          eval_host_source=${hostSource}
          eval_facts=${factsFixture}

          mkdir -p "$eval_store_root/nix/store"
          while IFS= read -r store_path; do
            cp -a --no-preserve=ownership \
              "$store_path" "$eval_store_root/nix/store/"
          done < ${evalInputClosure}/store-paths

          ${pkgs.nix}/bin/nix-store --store "$eval_store" --init
          ${pkgs.nix}/bin/nix-store --store "$eval_store" \
            --load-db < ${evalInputClosure}/registration
          for eval_input in "$eval_base_lib" ${hostStaticContract} "$eval_host_source" "$eval_facts"; do
            ${pkgs.nix}/bin/nix-store --store "$eval_store" \
              --check-validity "$eval_input"
          done

          export AOS_ROOT="$eval_state"
          export AOS_PROFILE_ROOT="$profile_root"
          export APM_SYSTEM_CONFIG_DIR="$config_root"
          export AOS_NIX_EVAL_CACHE_ROOT="$cache_root"
          export AOS_NIX_EVAL_STORE="$eval_store"
          export NIX_REMOTE="$eval_store"

          store_view=$(${pkgs.jq}/bin/jq -cnS \
            --arg readRoot "$eval_store_root/nix/store" \
            --arg staticContract "${hostStaticContract}/contract.json" \
            '{
              identity_root: "/nix/store",
              read_root: $readRoot,
              schema: "aos.package-store.read-view-locator/v1",
              static_contract: $staticContract
            }')
          ${pkgs.aos.packageRuntime}/bin/aos-package-runtime __eval \
            --store-view "$store_view" \
            --host-nix ${hostFixture} \
            --base-lib ${baseLib} \
            --facts ${factsFixture} \
            --module-abi ${toString moduleAbi} \
            --out "$first_root/manifest.json" \
            --eval-root "$first_root"
          ${pkgs.aos.packageRuntime}/bin/aos-package-runtime __eval \
            --store-view "$store_view" \
            --host-nix ${hostFixture} \
            --base-lib ${baseLib} \
            --facts ${factsFixture} \
            --module-abi ${toString moduleAbi} \
            --out "$second_root/manifest.json" \
            --eval-root "$second_root"

          ${pkgs.diffutils}/bin/cmp \
            "$first_root/manifest.json" "$second_root/manifest.json"
          ${pkgs.diffutils}/bin/cmp \
            "$first_root/graph.json" "$second_root/graph.json"
          ${pkgs.jq}/bin/jq -e \
            --arg baseLib ${lib.escapeShellArg (toString baseLib)} \
            --argjson storeView "$store_view" '
            .schema == "aos.config-manifest/v1"
            and (.etc | type == "object")
            and (.jobScripts | type == "object")
            and (.inputs | type == "object")
            and .inputs.base_lib.store_path == $baseLib
            and .inputs.store_view == $storeView
            and (.users | type == "array")
            and (.packages | type == "array")
            and .etc.hostname.text == "config-eval-preflight\n"
            and .etc."config-eval/preflight".text == "enabled\n"
            and .etc."ssl/certs/ca-certificates.crt".kind == "certificate-bundle"
            and .etc."ssl/certs/ca-certificates.crt".mode == "0644"
            and (.etc."ssl/certs/ca-certificates.crt".parts | length == 2)
            and .etc."ssl/certs/ca-certificates.crt".parts[0].kind == "store-file"
            and .etc."ssl/certs/ca-certificates.crt".parts[1].kind == "text"
            and (.etc."ssl/certs/ca-certificates.crt".parts[1].text
              | contains("MAgwADAAAwIAAA=="))
            and .ownership.etc."ssl/certs/ca-certificates.crt" == "@host"
          ' "$first_root/manifest.json" >/dev/null
          ${pkgs.jq}/bin/jq -e '
            (keys == ["edges"])
            and (.edges | type == "object")
          ' "$first_root/graph.json" >/dev/null

          echo "==> config-eval preflight gate" | ${pkgs.coreutils}/bin/tee "$out/result"
          echo "  module set evaluates: OK"
          echo "  production host.nix manifest + graph schema: OK"
          echo "  manifest + graph deterministic (eval-twice byte-identical): OK"
          echo "  inline runtime CA bundle is pure manifest data: OK"
          echo "  trusted-config-keys.d schema-valid: OK"
          echo "  malformed/ mismatched config key fails closed: OK"
          echo "  platform trust default and signed policy wiring: OK"
        '';
      }
    ];
  }
