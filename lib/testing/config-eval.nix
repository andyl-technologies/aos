# lib/testing/config-eval.nix — off-host config-eval preflight gate.
#
# operability.md §Off-host CI preflight: a pure-eval derivation that exercises
# the config-eval inputs the on-host evaluator consumes, with the same
# determinism discipline as the aos-nix `.drv` parity gate:
#
#   1. the module set EVALUATES (else fail with the module-system error);
#   2. the rendered config inputs are SCHEMA-VALID; and
#   3. they are DETERMINISTIC — eval twice, assert byte-identical output.
#
# The full host.nix -> manifest fixpoint runs stock Nix on-host (builder-gated,
# `apm switch --dry-run`); this pure gate covers the trust-anchor rendering
# (`aos.apm.configKeys` -> /etc/apm/trusted-config-keys.d/<op>.pub) and the
# platform-versus-signed host-configuration policy.
#
# Runs via `nix-build -A checks.config-eval`.
{
  pkgs,
  lib,
}: let
  aos = import ../../. {};

  opKey = "ops:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIJiuCf/fX/rsn5ODyT5ebEVtabAmZceKi2aD+cBWjWKL";

  # A well-formed system declaring one operator config key.
  mkConfigSystem = keys:
    aos.mkSystem {
      modules = [
        ../../systems/server.nix
        {aos.apm.configKeys.ops = keys;}
      ];
    };

  systemA = mkConfigSystem [opKey];
  systemB = mkConfigSystem [opKey];
  signedSystem = aos.mkSystem {
    modules = [
      ../../systems/server.nix
      {
        aos.apm.configKeys.ops = [opKey];
        aos.config.evalAtBoot.trust = "signed";
      }
    ];
  };
  signedWithoutKeySystem = aos.mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.config.evalAtBoot.trust = "signed";}
    ];
  };

  anchorPath = "apm/trusted-config-keys.d/ops.pub";
  anchorA = systemA.config.environment.etc.${anchorPath}.text;
  anchorB = systemB.config.environment.etc.${anchorPath}.text;

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
  mismatchSystem = aos.mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.apm.configKeys.ops = ["other:Ed25519:AAAA"];}
    ];
  };
  mismatchBuildThrows =
    !(builtins.tryEval mismatchSystem.config.system.build.toplevel.name).success;

  defaultTrustsPlatform =
    systemA.config.aos.config.evalAtBoot.trust == "platform"
    && systemA.config.aos.config.evalAtBoot.hostNix == "/run/aos-metadata/host.nix";
  signedModeRequiresSignature =
    builtins.match
    ".*--require-signed-host-nix.*"
    signedSystem.config.systemd.services.aos-eval.script
    != null;
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
              "config-eval: the stock image must trust the metadata-agent stash"
              (lib.throwIfNot signedModeRequiresSignature
                "config-eval: signed policy must require host.nix signature verification"
                (lib.throwIfNot signedModeWithoutKeyThrows
                  "config-eval: signed policy without a trust anchor must fail evaluation"
                  true)))))));
in
  pkgs.mkDerivation {
    pname = "config-eval-check";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString evalAssertions}
          mkdir -p $out
          echo "==> config-eval preflight gate" | tee $out/result
          echo "  module set evaluates: OK"
          echo "  manifest inputs deterministic (eval-twice byte-identical): OK"
          echo "  trusted-config-keys.d schema-valid: OK"
          echo "  malformed/ mismatched config key fails closed: OK"
          echo "  platform trust default and signed policy wiring: OK"
        '';
      }
    ];
  }
