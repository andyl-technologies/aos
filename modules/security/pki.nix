##! Projects retained PKI bundle inputs into the initial image trust store.
{
  config,
  lib,
  pkgs,
  packageModulesAvailable ? false,
  ...
}: let
  cfg = config.aos.security.pki;
  enabled = cfg.enable && (config.aos.boot.stage or "host") == "host";
  parts = config.aos.configurationLower.files."ssl/certs/ca-certificates.crt".parts;
  helper = pkgs.buildPackages.aos-configuration-lower;
  bundle = pkgs.mkDerivation {
    pname = "aos-ca-certificates";
    version = "1";
    src = null;
    buildDeps = [helper];
    inputsJSON = builtins.toJSON parts;
    passAsFile = ["inputsJSON"];
    phases = [
      {
        name = "assemble-certificates";
        script = ''
          mkdir -p "$out/etc/ssl/certs"
          ${helper}/bin/aos-certificate-bundle < "$inputsJSONPath" > "$out/etc/ssl/certs/ca-certificates.crt"
        '';
      }
    ];
  };
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/system/_aos-host-policy/pki.nix];
  config = lib.mkIf enabled {
    environment.etc = lib.genAttrs ["ssl/certs/ca-certificates.crt" "ssl/certs/ca-bundle.crt" "pki/tls/certs/ca-bundle.crt"] (_: {
      source = "${bundle}/etc/ssl/certs/ca-certificates.crt";
    });
  };
}
