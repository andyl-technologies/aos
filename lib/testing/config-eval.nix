# lib/testing/config-eval.nix — off-host config-eval preflight gate.
#
# operability.md §Off-host CI preflight: a pure-eval derivation that exercises
# the production config-eval path the host consumes, with the same determinism
# same deterministic evaluation discipline as the production path:
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
  systemB = mkConfigSystem [opKey];
  signedSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {
        aos.apm.configKeys.ops = [opKey];
        aos.config.evalAtBoot.trust = "signed";
      }
    ];
  };
  signedWithoutKeySystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.config.evalAtBoot.trust = "signed";}
    ];
  };

  anchorPath = "apm/trusted-config-keys.d/ops.pub";
  anchorA = systemA.config.environment.etc.${anchorPath}.text;
  anchorB = systemB.config.environment.etc.${anchorPath}.text;

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
  moduleAbi = systemA.config.aos.system.moduleAbi;
  evalInputClosure = import ../build/closure-info.nix {inherit pkgs lib;} {
    pname = "config-eval-input-closure";
    rootPaths = [baseLib hostSource factsFixture];
  };

  # (1) eval succeeds + (3) determinism: two independent evals are byte-identical.
  evalSucceeds = builtins.isString anchorA;
  deterministic = anchorA == anchorB;

  # (2) schema-valid: every line is `<op>:Ed25519:<base64>`.
  anchorLines = builtins.filter (l: l != "") (lib.splitString "\n" anchorA);
  lineWellFormed = line: builtins.match "ops:Ed25519:[A-Za-z0-9+/]+=*" line != null;
  schemaValid = anchorLines != [] && builtins.all lineWellFormed anchorLines;

  # Fail-closed: a malformed config key fires the apm-registries assertion, so
  # forcing the toplevel throws (mirrors module-enforcement's brokenBuildThrows).
  brokenSystem = mkConfigSystem ["ops:RSA:not-a-real-key"];
  brokenBuildThrows =
    !(builtins.tryEval brokenSystem.config.system.build.toplevel.name).success;

  # Fail-closed: an operator-prefix mismatch is also rejected.
  mismatchSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.apm.configKeys.ops = ["other:Ed25519:AAAA"];}
    ];
  };
  mismatchBuildThrows =
    !(builtins.tryEval mismatchSystem.config.system.build.toplevel.name).success;

  defaultTrustsPlatform =
    systemA.config.aos.config.evalAtBoot.trust == "platform";
  signedTrustAnchors =
    builtins.filter
    (root:
      builtins.match
      "/nix/store/[a-z0-9]+-aos-initrd-runtime-files-aos-metadata-provider"
      root
      != null)
    signedSystem.config.aos.boot.initrd.runtimeRoots;
  signedEvalServices =
    builtins.filter
    (resource:
      resource.kind
      == "aos.service.instance"
      && (resource.value.manager_identity.name or resource.value.service) == "aos-eval")
    (builtins.attrValues signedSystem.config.aos.abilities.resolvedResources);
  signedEvalService =
    if builtins.length signedEvalServices == 1
    then builtins.head signedEvalServices
    else throw "config-eval: the signed fixed point must contain one package-owned evaluation service";
  stage2Arguments =
    (builtins.head signedEvalService.value.lifecycle.start).executable.arguments;
  signedModeRequiresSignature =
    signedSystem.config.aos.config.evalAtBoot.trust
    == "signed"
    && builtins.length signedTrustAnchors == 1;
  stage2UsesRetainedManifest =
    builtins.elem "__eval-service" stage2Arguments
    && !(builtins.any
      (argument:
        builtins.isString argument
        && lib.hasInfix "/run/aos-metadata" argument)
      stage2Arguments)
    && !(builtins.elem "--host-nix" stage2Arguments);
  signedModeWithoutKeyThrows =
    !(builtins.tryEval signedWithoutKeySystem.config.system.build.toplevel.name).success;

  evalAssertions =
    lib.throwIfNot evalSucceeds
    "config-eval: the config module set must evaluate"
    (lib.throwIfNot deterministic
      "config-eval: two evals of identical inputs must be byte-identical (determinism)"
      (lib.throwIfNot schemaValid
        "config-eval: rendered trusted-config-keys.d must be schema-valid '<op>:Ed25519:<base64>' lines"
        (lib.throwIfNot brokenBuildThrows
          "config-eval: a malformed operator config key must fire a fail-closed assertion"
          (lib.throwIfNot mismatchBuildThrows
            "config-eval: an operator-prefix mismatch must be rejected"
            (lib.throwIfNot defaultTrustsPlatform
              "config-eval: the stock image must trust platform-authorized provisioning input"
              (lib.throwIfNot signedModeRequiresSignature
                "config-eval: signed policy must project exact trust anchors into the typed authorization request"
                (lib.throwIfNot stage2UsesRetainedManifest
                  "config-eval: stage 2 must consume retained manifest inputs without an ambient metadata path"
                  (lib.throwIfNot signedModeWithoutKeyThrows
                    "config-eval: signed policy without a trust anchor must fail evaluation"
                    true))))))));
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
          for eval_input in "$eval_base_lib" "$eval_host_source" "$eval_facts"; do
            ${pkgs.nix}/bin/nix-store --store "$eval_store" \
              --check-validity "$eval_input"
          done

          export AOS_ROOT="$eval_state"
          export AOS_PROFILE_ROOT="$profile_root"
          export APM_SYSTEM_CONFIG_DIR="$config_root"
          export AOS_NIX_EVAL_CACHE_ROOT="$cache_root"
          export AOS_NIX_EVAL_STORE="$eval_store"
          export NIX_REMOTE="$eval_store"

          ${pkgs.aos.packageRuntime}/bin/aos-package-runtime __eval \
            --host-nix ${hostFixture} \
            --base-lib ${baseLib} \
            --facts ${factsFixture} \
            --module-abi ${toString moduleAbi} \
            --out "$first_root/manifest.json" \
            --eval-root "$first_root"
          ${pkgs.aos.packageRuntime}/bin/aos-package-runtime __eval \
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
            --arg baseLib ${lib.escapeShellArg (toString baseLib)} '
            .schema == "aos.config-manifest/v1"
            and (.etc | type == "object")
            and (.jobScripts | type == "object")
            and (.inputs | type == "object")
            and .inputs.base_lib.store_path == $baseLib
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
