##! Checks retained CA inputs, native aliases, and host-only session policy.
{
  lib,
  pkgs,
}: let
  lower = {
    type = "derivation";
    outPath = builtins.toString (import ./_fixture-payload.nix "pki-lower");
    meta.mainProgram = "aos-configuration-lower";
  };
  ca = import ./_fixture-payload.nix "pki-ca";
  extra = import ./_fixture-payload.nix "pki-extra";
  evaluate = stage: enabled:
    lib.evalModules {
      inherit lib;
      specialArgs = {
        package = lower;
        dependencies.ca-certificates = ca;
      };
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/boot/_aos-configuration-lower/module.nix
        ../../pkgs/system/_aos-host-policy/session-environment.nix
        ../../pkgs/system/_aos-host-policy/pki.nix
        ({lib, ...}: {
          options.aos.boot.stage = lib.mkOption {
            type = lib.types.str;
            default = stage;
          };
          aos.security.pki = {
            enable = enabled;
            certificateFiles = ["${extra}/certificate.pem"];
            certificates = ["exact inline PEM"];
          };
        })
      ];
    };
  host = evaluate "host" true;
  disabled = evaluate "host" false;
  initrd = evaluate "initrd" true;
  nodes = builtins.attrValues host.config.aos.activation.graph.nodes;
  ensure = builtins.head (builtins.filter (node: (node.handler.executable or null) == "${lower.outPath}/bin/aos-configuration-lower") nodes);
  files = ensure.input.files;
  canonical = files."ssl/certs/ca-certificates.crt";
in {
  exactOrderedSources = assert canonical.parts
  == [
    {
      kind = "store-file";
      path = "${ca}/etc/ssl/certs/ca-certificates.crt";
    }
    {
      kind = "store-file";
      path = "${extra}/certificate.pem";
    }
    {
      kind = "text";
      text = "exact inline PEM\n";
    }
  ]; true;
  aliases = assert files."ssl/certs/ca-bundle.crt".target == "ca-certificates.crt";
  assert files."pki/tls/certs/ca-bundle.crt".target == "../../../ssl/certs/ca-certificates.crt"; true;
  retainedSources = assert builtins.elem (builtins.toString ca) ensure.input.storePaths;
  assert builtins.elem (builtins.toString extra) ensure.input.storePaths; true;
  exactOwnership = assert builtins.attrNames files == builtins.attrNames ensure.input.ownership.files; true;
  nativeInstallation = assert builtins.length nodes == 3; true;
  stableEnvironment = assert host.config.environment.sessionVariables
  == {
    SSL_CERT_FILE = host.config.aos.security.pki.caBundle;
    NIX_SSL_CERT_FILE = host.config.aos.security.pki.caBundle;
  }; true;
  disabledHasNoEffects = assert disabled.config.aos.activation.graph.nodes == {};
  assert disabled.config.environment.sessionVariables == {}; true;
  initrdHasNoTrustEffects = assert initrd.config.aos.activation.graph.nodes == {};
  assert initrd.config.environment.sessionVariables == {}; true;
}
